"""
network_core.py - Ryu controller foundation (Member 2).

Run:   ryu-manager network_core.py                 (diamond topology)
       NETCORE_TOPO=tree ryu-manager network_core.py
       ryu-manager network_core.py member3_policy.py   (with Member 3's module)

What it does
------------
1. Base rules on every switch when it connects:
     prio 0  table-miss          -> controller
     prio 1  IPv6 / LLDP         -> drop   (never loops, never spams us)
     prio 5  ARP                 -> controller (proxy ARP, never flooded)
2. Proxy ARP: answers ARP requests from the fixed host table, so even without
   Mininet's static ARP no broadcast ever enters the loop.
3. Reactive forwarding: the first packet of an IPv4 connection arrives as a
   packet-in. The controller picks a path from the path dictionary in
   netcore_config.py, installs a rule on every switch of that path in BOTH
   directions (match: IP proto, src/dst IP, TCP/UDP ports), tags all of them
   with one cookie, then delivers the first packet itself.
4. Link failure: a port-status message for a switch-switch port marks the
   link down; every flow whose path used it is moved to the first backup path
   that is fully up (make-before-break, then old rules removed by cookie).
   Failover time is logged to failover_log.csv.
5. Recovery: configurable (REVERT_ON_RECOVERY), default stays on backup.
6. API for Member 3 (Python methods below + REST on :8080 + Ryu events).

Cookie layout: [16-bit tag | 48-bit install sequence]. A flow keeps its id for
life; its cookie changes on every (re)install so stale rules can be deleted
precisely.
"""
import json
import os
import sys
import threading
import time

from ryu.app.wsgi import ControllerBase, Response, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib.packet import arp, ether_types, ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netcore_config as cfg  # noqa: E402
from netcore_events import (EventFlowInstalled, EventLinkState,  # noqa: E402
                            EventPathChanged)

REST_INSTANCE = 'netcore_app'
IP_PROTO_NAMES = {1: 'icmp', 6: 'tcp', 17: 'udp'}


class NetworkCore(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    _EVENTS = [EventPathChanged, EventLinkState, EventFlowInstalled]

    def __init__(self, *args, **kwargs):
        super(NetworkCore, self).__init__(*args, **kwargs)
        self.topo = os.environ.get('NETCORE_TOPO', cfg.DEFAULT_TOPO)
        if self.topo not in cfg.TOPOLOGIES:
            raise ValueError('unknown NETCORE_TOPO %r' % self.topo)

        self.port_map, self.next_hop = cfg.port_map(self.topo)
        self.hosts = cfg.hosts_on(self.topo)
        self.ip_to_host = {h['ip']: n for n, h in self.hosts.items()}
        self.switch_ids = set(cfg.TOPOLOGIES[self.topo]['switches'])

        self.datapaths = {}                       # dpid -> datapath
        self.link_up = {cfg.link_id(a, b): True
                        for a, _, b, _ in cfg.TOPOLOGIES[self.topo]['links']}
        self.port_down = {}                       # (dpid, port) -> bool
        self.flows = {}                           # flow_id -> record (dict)
        self.match_index = {}                     # match key -> flow_id
        self.cookie_index = {}                    # current cookie -> flow_id
        self._next_flow_id = 1
        self._next_cookie_seq = 1
        self.lock = threading.RLock()

        self.path_selector = None                 # Member 3 hook, see set_path_selector
        self.stats = {'packet_in': 0, 'packet_in_ipv4': 0, 'arp_replies': 0,
                      'flows_installed': 0, 'flow_mods_sent': 0, 'reroutes': 0,
                      'link_down_events': 0, 'link_up_events': 0, 'flows_expired': 0}
        self.failover_history = []

        self._init_failover_log()
        kwargs['wsgi'].register(NetCoreRest, {REST_INSTANCE: self})
        self.logger.info('NetworkCore up: topology=%s switches=%s hosts=%s',
                         self.topo, sorted(self.switch_ids), sorted(self.hosts))

    # ==================================================================
    # Switch connection and base rules
    # ==================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        with self.lock:
            self.datapaths[dp.id] = dp
            # A (re)connecting switch starts clean: forget flows that used it
            for fid in [f for f, r in self.flows.items() if dp.id in r['path']]:
                self._remove_flow_locked(fid, send_delete=True)

        # wipe whatever was left in the table from an earlier run
        dp.send_msg(parser.OFPFlowMod(dp, command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=parser.OFPMatch()))
        to_ctrl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, cfg.PRIO_TABLE_MISS, parser.OFPMatch(), to_ctrl)
        self._add_flow(dp, cfg.PRIO_DROP_NOISE, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6), [])
        self._add_flow(dp, cfg.PRIO_DROP_NOISE, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP), [])
        self._add_flow(dp, cfg.PRIO_ARP_TO_CTRL, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP), to_ctrl)

        # learn real port states (a link may already be down)
        dp.send_msg(parser.OFPPortDescStatsRequest(dp, 0))
        self.logger.info('switch s%d connected (%s)', dp.id,
                         'known' if dp.id in self.switch_ids else 'NOT IN CONFIG')

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == DEAD_DISPATCHER and dp.id is not None:
            with self.lock:
                if self.datapaths.get(dp.id) is dp:
                    del self.datapaths[dp.id]
            self.logger.warning('switch s%s disconnected', dp.id)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_handler(self, ev):
        dp = ev.msg.datapath
        for p in ev.msg.body:
            self._update_port(dp, p.port_no, self._port_is_down(dp, p), initial=True)

    # ==================================================================
    # Packet-in: ARP and IPv4
    # ==================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        self.stats['packet_in'] += 1

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(dp, in_port, eth, pkt.get_protocol(arp.arp))
            return
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return  # anything else: drop silently (never flood on a loop)

        ip = pkt.get_protocol(ipv4.ipv4)
        self.stats['packet_in_ipv4'] += 1
        src_name = self.ip_to_host.get(ip.src)
        dst_name = self.ip_to_host.get(ip.dst)
        if not src_name or not dst_name:
            self.logger.debug('drop IPv4 %s -> %s (unknown host)', ip.src, ip.dst)
            return

        match = {'eth_type': ether_types.ETH_TYPE_IP, 'ip_proto': ip.proto,
                 'ipv4_src': ip.src, 'ipv4_dst': ip.dst}
        t = pkt.get_protocol(tcp.tcp)
        u = pkt.get_protocol(udp.udp)
        if t:
            match.update(tcp_src=t.src_port, tcp_dst=t.dst_port)
        elif u:
            match.update(udp_src=u.src_port, udp_dst=u.dst_port)

        with self.lock:
            fid = self.match_index.get(self._match_key(match))
            if fid is None:
                fid = self._install_flow_locked(match, path=None, priority=cfg.PRIO_REACTIVE,
                                                tag=0, idle_timeout=cfg.REACTIVE_IDLE_TIMEOUT,
                                                bidirectional=True, origin='reactive')
        if fid is None:
            self.logger.warning('no usable path for %s -> %s', src_name, dst_name)
            return
        # Deliver the first packet straight out of the destination edge switch
        # (avoids racing the rules we just sent).
        self._deliver_to_host(dst_name, msg.data)

    def _handle_arp(self, dp, in_port, eth, a):
        if a is None or a.opcode != arp.ARP_REQUEST:
            return
        name = self.ip_to_host.get(a.dst_ip)
        if name is None:
            return
        target_mac = self.hosts[name]['mac']
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                             dst=eth.src, src=target_mac))
        reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=target_mac, src_ip=a.dst_ip,
                                   dst_mac=a.src_mac, dst_ip=a.src_ip))
        reply.serialize()
        self._packet_out(dp, in_port_out=in_port, data=reply.data)
        self.stats['arp_replies'] += 1
        self.logger.debug('proxy ARP: %s is-at %s (asked by %s)', a.dst_ip, target_mac, a.src_ip)

    # ==================================================================
    # Port status / link failure and recovery
    # ==================================================================
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        down = msg.reason == dp.ofproto.OFPPR_DELETE or self._port_is_down(dp, msg.desc)
        self._update_port(dp, msg.desc.port_no, down, initial=False)

    def _port_is_down(self, dp, desc):
        ofp = dp.ofproto
        return bool(desc.state & ofp.OFPPS_LINK_DOWN) or bool(desc.config & ofp.OFPPC_PORT_DOWN)

    def _update_port(self, dp, port_no, down, initial):
        t0 = time.time()
        peer = self.port_map.get(dp.id, {}).get(port_no)
        if peer is None:
            return
        if peer[0] == 'host':
            if not initial:
                self.logger.warning('host port s%d:%d (%s) is %s', dp.id, port_no, peer[1],
                                    'DOWN' if down else 'UP')
            return
        lid = cfg.link_id(dp.id, peer[1])
        with self.lock:
            # a link is up only when BOTH of its ports are up; this stops one
            # end's late "up" report from flapping the link while the other
            # end is still down
            self.port_down[(dp.id, port_no)] = down
            now_up = not (self.port_down.get((dp.id, port_no), False) or
                          self.port_down.get((peer[1], peer[2]), False))
            if self.link_up[lid] == now_up:
                return  # no change (the other end already reported it)
            self.link_up[lid] = now_up
            down = not now_up
        self.send_event_to_observers(EventLinkState(lid, not down))
        if down:
            self.stats['link_down_events'] += 1
            self.logger.warning('LINK DOWN s%d-s%d (reported by s%d port %d)',
                                lid[0], lid[1], dp.id, port_no)
            self._on_link_down(lid, t0)
        else:
            self.stats['link_up_events'] += 1
            self.logger.info('LINK UP   s%d-s%d', lid[0], lid[1])
            self._on_link_up(lid, t0)

    def _on_link_down(self, lid, t0):
        moved, lost = [], []
        with self.lock:
            for fid, rec in list(self.flows.items()):
                if lid not in self._path_links(rec['path']):
                    continue
                new = self._choose_path(rec, exclude_current=True)
                if new is None:
                    lost.append(fid)
                    self._remove_flow_locked(fid, send_delete=True)
                else:
                    self._move_flow_locked(fid, new, reason='failover', t0=t0)
                    moved.append(fid)
        ms = (time.time() - t0) * 1000.0
        self.logger.warning('failover for s%d-s%d: %d flow(s) rerouted, %d without path, %.2f ms',
                            lid[0], lid[1], len(moved), len(lost), ms)
        self._log_failover('link_down', lid, len(moved), len(lost), ms)

    def _on_link_up(self, lid, t0):
        if not cfg.REVERT_ON_RECOVERY:
            self.logger.info('recovery policy: stay on current paths (new flows use primary)')
            self._log_failover('link_up_stay', lid, 0, 0, (time.time() - t0) * 1000.0)
            return
        moved = 0
        with self.lock:
            for fid, rec in list(self.flows.items()):
                best = self._choose_path(rec)
                if best and best != rec['path']:
                    self._move_flow_locked(fid, best, reason='recovery', t0=t0)
                    moved += 1
        ms = (time.time() - t0) * 1000.0
        self.logger.info('recovery for s%d-s%d: %d flow(s) moved back, %.2f ms', lid[0], lid[1], moved, ms)
        self._log_failover('link_up_revert', lid, moved, 0, ms)

    # ==================================================================
    # Flow removed (idle timeout) -> remove whole flow everywhere
    # ==================================================================
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        if msg.reason not in (ofp.OFPRR_IDLE_TIMEOUT, ofp.OFPRR_HARD_TIMEOUT):
            return
        with self.lock:
            fid = self.cookie_index.get(msg.cookie)
            if fid is not None:
                self.stats['flows_expired'] += 1
                self._remove_flow_locked(fid, send_delete=True)
                self.logger.debug('flow #%d expired', fid)

    # ==================================================================
    # Core internals
    # ==================================================================
    def _match_key(self, match):
        return tuple(sorted(match.items()))

    @staticmethod
    def _reverse_match(match):
        r = dict(match)
        r['ipv4_src'], r['ipv4_dst'] = match['ipv4_dst'], match['ipv4_src']
        for a, b in (('tcp_src', 'tcp_dst'), ('udp_src', 'udp_dst')):
            if a in match or b in match:
                r.pop(a, None)
                r.pop(b, None)
                if b in match:
                    r[a] = match[b]
                if a in match:
                    r[b] = match[a]
        return r

    @staticmethod
    def _path_links(path):
        return {cfg.link_id(path[i], path[i + 1]) for i in range(len(path) - 1)}

    def _path_usable(self, path):
        if any(s not in self.datapaths for s in path):
            return False
        return all(self.link_up.get(l, False) for l in self._path_links(path))

    def _endpoints(self, match):
        src = self.ip_to_host.get(match['ipv4_src'])
        dst = self.ip_to_host.get(match['ipv4_dst'])
        return src, dst

    def _candidates(self, src_name, dst_name):
        return cfg.candidate_paths(self.topo, self.hosts[src_name]['switch'],
                                   self.hosts[dst_name]['switch'])

    def _choose_path(self, rec, exclude_current=False):
        cands = [p for p in self._candidates(rec['src'], rec['dst']) if self._path_usable(p)]
        if exclude_current:
            cands = [p for p in cands if p != rec['path']] or cands
        if not cands:
            return None
        if self.path_selector is not None:
            try:
                choice = self.path_selector(self._public(rec), [list(p) for p in cands])
                if choice and list(choice) in cands:
                    return list(choice)
            except Exception as e:  # never let a policy bug break forwarding
                self.logger.error('path_selector raised %r, using default', e)
        return list(cands[0])

    def _new_cookie(self, tag):
        seq = self._next_cookie_seq
        self._next_cookie_seq += 1
        return ((tag & 0xFFFF) << cfg.COOKIE_TAG_SHIFT) | (seq & cfg.COOKIE_ID_MASK)

    def _install_flow_locked(self, match, path, priority, tag, idle_timeout,
                             bidirectional, origin):
        src, dst = self._endpoints(match)
        if not src or not dst:
            raise ValueError('ipv4_src/ipv4_dst must be known hosts')
        fid = self._next_flow_id
        self._next_flow_id += 1
        rec = {'id': fid, 'src': src, 'dst': dst, 'match': dict(match),
               'priority': priority, 'tag': tag, 'idle_timeout': idle_timeout,
               'bidirectional': bidirectional, 'origin': origin, 'path': None,
               'cookie': None, 'created': time.time(), 'moves': 0}
        if path is None:
            path = self._choose_path(rec)
            if path is None:
                return None
        else:
            self._validate_path(rec, path)
        rec['path'] = list(path)
        rec['primary'] = list(self._candidates(src, dst)[0])
        rec['cookie'] = self._new_cookie(tag)
        self.flows[fid] = rec
        self.cookie_index[rec['cookie']] = fid
        self.match_index[self._match_key(match)] = fid
        if bidirectional:
            self.match_index[self._match_key(self._reverse_match(match))] = fid
        self._push_rules(rec)
        self.stats['flows_installed'] += 1
        self.logger.info('flow #%d %s installed on path %s (cookie 0x%x)',
                         fid, self._describe(rec), self._fmt_path(rec['path']), rec['cookie'])
        self.send_event_to_observers(EventFlowInstalled(fid, self._public(rec)))
        return fid

    def _validate_path(self, rec, path):
        path = list(path)
        if path[0] != self.hosts[rec['src']]['switch'] or path[-1] != self.hosts[rec['dst']]['switch']:
            raise ValueError('path must start at s%d and end at s%d' %
                             (self.hosts[rec['src']]['switch'], self.hosts[rec['dst']]['switch']))
        for i in range(len(path) - 1):
            if (path[i], path[i + 1]) not in self.next_hop:
                raise ValueError('s%d and s%d are not linked' % (path[i], path[i + 1]))

    def _push_rules(self, rec):
        """Install the flow's rules along rec['path'] (egress switch first)."""
        flags_rem = rec['idle_timeout'] > 0
        dirs = [(rec['match'], rec['path'], rec['dst'])]
        if rec['bidirectional']:
            dirs.append((self._reverse_match(rec['match']), list(reversed(rec['path'])), rec['src']))
        for match, path, dst_host in dirs:
            for i in reversed(range(len(path))):
                sw = path[i]
                out = self.hosts[dst_host]['port'] if i == len(path) - 1 else self.next_hop[(sw, path[i + 1])]
                dp = self.datapaths.get(sw)
                if dp is None:
                    continue
                parser = dp.ofproto_parser
                self._add_flow(dp, rec['priority'], parser.OFPMatch(**match),
                               [parser.OFPActionOutput(out)], cookie=rec['cookie'],
                               idle_timeout=rec['idle_timeout'], send_rem=flags_rem)
        # barrier so the switches finish processing before we report success
        for sw in set(rec['path']):
            dp = self.datapaths.get(sw)
            if dp is not None:
                dp.send_msg(dp.ofproto_parser.OFPBarrierRequest(dp))

    def _delete_cookie(self, cookie, switches=None):
        for sw in (switches or list(self.datapaths)):
            dp = self.datapaths.get(sw)
            if dp is None:
                continue
            ofp, parser = dp.ofproto, dp.ofproto_parser
            dp.send_msg(parser.OFPFlowMod(dp, cookie=cookie, cookie_mask=cfg.COOKIE_FULL_MASK,
                                          command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                                          out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                          match=parser.OFPMatch()))
            self.stats['flow_mods_sent'] += 1

    def _move_flow_locked(self, fid, new_path, reason, t0=None):
        t0 = t0 or time.time()
        rec = self.flows[fid]
        self._validate_path(rec, new_path)
        old_path, old_cookie = list(rec['path']), rec['cookie']
        # make-before-break: the new rules overwrite identical matches on shared
        # switches (same match + priority = replace), then leftovers are deleted
        rec['path'] = list(new_path)
        rec['cookie'] = self._new_cookie(rec['tag'])
        self.cookie_index.pop(old_cookie, None)
        self.cookie_index[rec['cookie']] = fid
        self._push_rules(rec)
        self._delete_cookie(old_cookie, switches=old_path)
        rec['moves'] += 1
        self.stats['reroutes'] += 1
        ms = (time.time() - t0) * 1000.0
        self.failover_history.append({'time': time.time(), 'flow': fid, 'reason': reason,
                                      'old': old_path, 'new': list(new_path), 'ms': round(ms, 3)})
        self.logger.warning('flow #%d %s moved %s -> %s (%s, %.2f ms)', fid, self._describe(rec),
                            self._fmt_path(old_path), self._fmt_path(new_path), reason, ms)
        self.send_event_to_observers(EventPathChanged(fid, old_path, list(new_path), reason, ms))
        return True

    def _remove_flow_locked(self, fid, send_delete=True):
        rec = self.flows.pop(fid, None)
        if rec is None:
            return False
        self.cookie_index.pop(rec['cookie'], None)
        for m in (rec['match'], self._reverse_match(rec['match'])):
            if self.match_index.get(self._match_key(m)) == fid:
                del self.match_index[self._match_key(m)]
        if send_delete:
            self._delete_cookie(rec['cookie'])
        return True

    def _add_flow(self, dp, priority, match, actions, cookie=0, idle_timeout=0,
                  hard_timeout=0, send_rem=False):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        flags = ofp.OFPFF_SEND_FLOW_REM if send_rem else 0
        dp.send_msg(parser.OFPFlowMod(datapath=dp, cookie=cookie, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle_timeout,
                                      hard_timeout=hard_timeout, flags=flags))
        self.stats['flow_mods_sent'] += 1

    def _packet_out(self, dp, in_port_out, data):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=ofp.OFPP_CONTROLLER,
                                        actions=[parser.OFPActionOutput(in_port_out)], data=data))

    def _deliver_to_host(self, host_name, data):
        h = self.hosts[host_name]
        dp = self.datapaths.get(h['switch'])
        if dp is not None:
            self._packet_out(dp, h['port'], data)

    # ---------- formatting / logging ----------
    @staticmethod
    def _fmt_path(path):
        return '-'.join('s%d' % s for s in path) if path else '(none)'

    def _describe(self, rec):
        m = rec['match']
        proto = IP_PROTO_NAMES.get(m.get('ip_proto'), str(m.get('ip_proto', 'ip')))
        sp = m.get('tcp_src', m.get('udp_src', '*'))
        dp_ = m.get('tcp_dst', m.get('udp_dst', '*'))
        if proto in ('tcp', 'udp'):
            return '%s %s:%s->%s:%s' % (proto, rec['src'], sp, rec['dst'], dp_)
        return '%s %s->%s' % (proto, rec['src'], rec['dst'])

    def _public(self, rec):
        out = {k: (list(v) if isinstance(v, list) else v) for k, v in rec.items()}
        out['match'] = dict(rec['match'])
        out['description'] = self._describe(rec)
        out['on_primary'] = rec['path'] == rec.get('primary')
        return out

    def _init_failover_log(self):
        try:
            new = not os.path.exists(cfg.FAILOVER_LOG)
            with open(cfg.FAILOVER_LOG, 'a') as f:
                if new:
                    f.write('timestamp,event,link,flows_moved,flows_without_path,control_plane_ms\n')
        except OSError as e:
            self.logger.error('cannot open %s: %s', cfg.FAILOVER_LOG, e)

    def _log_failover(self, event, lid, moved, lost, ms):
        try:
            with open(cfg.FAILOVER_LOG, 'a') as f:
                f.write('%.6f,%s,s%d-s%d,%d,%d,%.3f\n' % (time.time(), event, lid[0], lid[1], moved, lost, ms))
        except OSError:
            pass

    # ==================================================================
    # PUBLIC API for Member 3 (call these; do not touch the internals)
    # Get the app from another Ryu app with:
    #     from ryu.base import app_manager
    #     core = app_manager.lookup_service_brick('NetworkCore')
    # ==================================================================
    def install_flow(self, match, path=None, priority=cfg.PRIO_POLICY_MIN, tag=0,
                     idle_timeout=0, bidirectional=True):
        """
        Install a flow along a path. Returns the flow id, or None if no path.

        match: dict of OpenFlow 1.3 match fields. Must contain ipv4_src and
               ipv4_dst of known hosts. eth_type=0x0800 is added for you.
               Example (topic 'sports' from h3 to the broker):
                 {'ipv4_src': '10.0.0.3', 'ipv4_dst': '10.0.0.1',
                  'ip_proto': 6, 'tcp_dst': 5001}
               With bidirectional=True the reverse rule is derived
               automatically (IPs swapped, tcp_dst becomes tcp_src).
        path:  list of switch ids, 'primary', 'backup', or None (= best usable).
        priority: use >= PRIO_POLICY_MIN so policy beats reactive rules.
        tag:   0..65535, stored in the top 16 bits of the cookie (e.g. topic id),
               lets you find / delete all flows of one topic.
        """
        m = dict(match)
        m.setdefault('eth_type', ether_types.ETH_TYPE_IP)
        if 'tcp_src' in m or 'tcp_dst' in m:
            m.setdefault('ip_proto', 6)
        if 'udp_src' in m or 'udp_dst' in m:
            m.setdefault('ip_proto', 17)
        with self.lock:
            existing = self.match_index.get(self._match_key(m))
            if existing is not None and self.flows[existing]['priority'] == priority:
                self._remove_flow_locked(existing, send_delete=True)
            resolved = self._resolve_path_arg(m, path)
            return self._install_flow_locked(m, resolved, priority, tag, idle_timeout,
                                             bidirectional, origin='api')

    def get_flow_path(self, flow_id):
        """Current path (list of switch ids) of a flow, or None."""
        rec = self.flows.get(flow_id)
        return list(rec['path']) if rec else None

    def find_flows(self, **criteria):
        """
        Flows whose match contains all given fields, plus optional 'tag' or
        'src'/'dst' host names. E.g. find_flows(tcp_dst=5001) or find_flows(tag=2).
        Each result is a dict with id, src, dst, match, path, primary, cookie...
        """
        out = []
        with self.lock:
            for rec in self.flows.values():
                ok = True
                for k, v in criteria.items():
                    if k in ('tag', 'src', 'dst', 'origin'):
                        ok = ok and rec[k] == v
                    else:
                        rm, rev = rec['match'], self._reverse_match(rec['match'])
                        ok = ok and (rm.get(k) == v or (rec['bidirectional'] and rev.get(k) == v))
                if ok:
                    out.append(self._public(rec))
        return out

    def lookup_path(self, src_ip, dst_ip, ip_proto=None, src_port=None, dst_port=None):
        """'What path does this traffic use?' Returns list of switch ids or None."""
        with self.lock:
            for rec in self.flows.values():
                for m, path in ((rec['match'], rec['path']),
                                (self._reverse_match(rec['match']), list(reversed(rec['path'])))):
                    if m['ipv4_src'] != src_ip or m['ipv4_dst'] != dst_ip:
                        continue
                    if ip_proto is not None and m.get('ip_proto') != ip_proto:
                        continue
                    if src_port is not None and src_port not in (m.get('tcp_src'), m.get('udp_src')):
                        continue
                    if dst_port is not None and dst_port not in (m.get('tcp_dst'), m.get('udp_dst')):
                        continue
                    return list(path)
        return None

    def move_flow(self, flow_id, path):
        """Move a flow to another path (list of switch ids, 'primary' or 'backup')."""
        with self.lock:
            rec = self.flows.get(flow_id)
            if rec is None:
                raise KeyError('no flow %s' % flow_id)
            new = self._resolve_path_arg(rec['match'], path)
            if new is None:
                raise ValueError('no usable path')
            if not self._path_usable(new):
                raise ValueError('path %s uses a down link or disconnected switch' % self._fmt_path(new))
            if new == rec['path']:
                return False
            return self._move_flow_locked(flow_id, new, reason='api')

    def move_flows(self, path, **criteria):
        """Move every flow matching find_flows(**criteria). Returns moved ids."""
        moved = []
        for f in self.find_flows(**criteria):
            try:
                if self.move_flow(f['id'], path):
                    moved.append(f['id'])
            except (ValueError, KeyError) as e:
                self.logger.warning('move_flows: flow #%d not moved: %s', f['id'], e)
        return moved

    def remove_flow(self, flow_id):
        with self.lock:
            return self._remove_flow_locked(flow_id, send_delete=True)

    def remove_flows_by_tag(self, tag):
        """Delete every flow carrying this cookie tag (e.g. a whole topic)."""
        with self.lock:
            ids = [f for f, r in self.flows.items() if r['tag'] == tag]
            for fid in ids:
                self._remove_flow_locked(fid, send_delete=False)
            for dp in self.datapaths.values():
                ofp, parser = dp.ofproto, dp.ofproto_parser
                dp.send_msg(parser.OFPFlowMod(dp, cookie=(tag & 0xFFFF) << cfg.COOKIE_TAG_SHIFT,
                                              cookie_mask=cfg.COOKIE_TAG_MASK,
                                              command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                                              out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                              match=parser.OFPMatch()))
        return ids

    def candidate_paths(self, src_ip, dst_ip):
        """All candidate paths between two hosts with a 'usable' flag (primary first)."""
        s, d = self.ip_to_host.get(src_ip), self.ip_to_host.get(dst_ip)
        if not s or not d:
            return []
        return [{'path': p, 'usable': self._path_usable(p), 'primary': i == 0}
                for i, p in enumerate(self._candidates(s, d))]

    def get_links(self):
        """{(a, b): {'up': bool, 'ports': {a: port, b: port}, 'capacity_mbps': N}}"""
        return {lid: {'up': up, 'ports': {lid[0]: self.next_hop[(lid[0], lid[1])],
                                          lid[1]: self.next_hop[(lid[1], lid[0])]},
                      'capacity_mbps': cfg.CORE_LINK['bw']}
                for lid, up in self.link_up.items()}

    def link_for_port(self, dpid, port_no):
        """Map a switch port to its link (for Member 3's port stats). None for host ports."""
        peer = self.port_map.get(dpid, {}).get(port_no)
        if peer and peer[0] == 'switch':
            return cfg.link_id(dpid, peer[1])
        return None

    def flow_for_cookie(self, cookie):
        """Flow record for a rule cookie seen in flow stats (or None)."""
        fid = self.cookie_index.get(cookie)
        return self._public(self.flows[fid]) if fid is not None else None

    def set_path_selector(self, fn):
        """
        Let Member 3 choose paths for NEW reactive flows and failovers.
        fn(flow_info: dict, usable_paths: list[list[int]]) -> chosen path or None.
        Returning None (or an invalid path) falls back to the default (primary first).
        """
        self.path_selector = fn

    def get_stats(self):
        s = dict(self.stats)
        s['active_flows'] = len(self.flows)
        s['links_down'] = ['s%d-s%d' % l for l, up in self.link_up.items() if not up]
        return s

    def _resolve_path_arg(self, match, path):
        if path is None or isinstance(path, (list, tuple)):
            return list(path) if path else None
        s, d = self.ip_to_host.get(match['ipv4_src']), self.ip_to_host.get(match['ipv4_dst'])
        cands = self._candidates(s, d)
        if path == 'primary':
            return list(cands[0])
        if path == 'backup':
            if len(cands) < 2:
                raise ValueError('no backup path between %s and %s' % (s, d))
            return list(cands[1])
        raise ValueError('path must be a list, "primary", "backup" or None')


# ======================================================================
# REST API (port 8080) - handy for demos and for Member 3 from outside Ryu
#   curl localhost:8080/netcore/flows
#   curl localhost:8080/netcore/links
#   curl localhost:8080/netcore/stats
#   curl localhost:8080/netcore/paths/10.0.0.2/10.0.0.3
#   curl "localhost:8080/netcore/lookup?src=10.0.0.2&dst=10.0.0.3"
#   curl -X POST -d '{"path":"backup"}' localhost:8080/netcore/flows/3/move
#   curl -X POST -d '{"match":{"ipv4_src":"10.0.0.3","ipv4_dst":"10.0.0.1","tcp_dst":5002},
#                     "path":[4,3,1],"priority":20,"tag":2}' localhost:8080/netcore/flows
#   curl -X DELETE localhost:8080/netcore/flows/3
# ======================================================================
def _json(obj, status=200):
    return Response(status=status, content_type='application/json',
                    body=json.dumps(obj, indent=2, default=str).encode('utf-8'))


class NetCoreRest(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(NetCoreRest, self).__init__(req, link, data, **config)
        self.core = data[REST_INSTANCE]

    @route('netcore', '/netcore/flows', methods=['GET'])
    def list_flows(self, req, **kw):
        return _json(self.core.find_flows())

    @route('netcore', '/netcore/flows', methods=['POST'])
    def add_flow(self, req, **kw):
        try:
            body = json.loads(req.body.decode('utf-8') or '{}')
            fid = self.core.install_flow(body['match'], path=body.get('path'),
                                         priority=int(body.get('priority', cfg.PRIO_POLICY_MIN)),
                                         tag=int(body.get('tag', 0)),
                                         idle_timeout=int(body.get('idle_timeout', 0)),
                                         bidirectional=bool(body.get('bidirectional', True)))
            return _json({'flow_id': fid, 'path': self.core.get_flow_path(fid)})
        except (KeyError, ValueError) as e:
            return _json({'error': str(e)}, 400)

    @route('netcore', '/netcore/flows/{fid}/move', methods=['POST'])
    def move(self, req, fid, **kw):
        try:
            body = json.loads(req.body.decode('utf-8') or '{}')
            changed = self.core.move_flow(int(fid), body.get('path'))
            return _json({'flow_id': int(fid), 'moved': changed, 'path': self.core.get_flow_path(int(fid))})
        except (KeyError, ValueError) as e:
            return _json({'error': str(e)}, 400)

    @route('netcore', '/netcore/flows/{fid}', methods=['DELETE'])
    def delete(self, req, fid, **kw):
        return _json({'flow_id': int(fid), 'removed': self.core.remove_flow(int(fid))})

    @route('netcore', '/netcore/links', methods=['GET'])
    def links(self, req, **kw):
        return _json({'s%d-s%d' % k: v for k, v in self.core.get_links().items()})

    @route('netcore', '/netcore/paths/{src}/{dst}', methods=['GET'])
    def paths(self, req, src, dst, **kw):
        return _json(self.core.candidate_paths(src, dst))

    @route('netcore', '/netcore/lookup', methods=['GET'])
    def lookup(self, req, **kw):
        q = req.GET
        def _int(k):
            return int(q[k]) if k in q else None
        return _json({'path': self.core.lookup_path(q.get('src'), q.get('dst'), _int('proto'),
                                                    _int('sport'), _int('dport'))})

    @route('netcore', '/netcore/stats', methods=['GET'])
    def stats(self, req, **kw):
        return _json(self.core.get_stats())

    @route('netcore', '/netcore/failovers', methods=['GET'])
    def failovers(self, req, **kw):
        return _json(self.core.failover_history[-100:])
