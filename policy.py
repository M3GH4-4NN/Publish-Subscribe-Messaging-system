"""
policy.py - Member 3: per-topic monitoring and adaptive path policy, built on
Member 2's network core. Run both together (from the netcore folder):

    ryu-manager network_core.py policy.py

What it does
  * every POLL_INTERVAL seconds asks switch s1 (where the broker is) for its
    flow stats and turns them into packets/second per topic
  * writes the numbers to stats.json (the dashboard reads this file)
  * if a topic goes over THRESHOLD_PPS, moves that topic's flows to the backup
    path (and keeps new flows of that topic on the backup path for HOLD_SECONDS)
"""
import json
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

from netcore_events import EventPathChanged

try:
    import config                      # your shared topic map, if it is in this folder
    TOPICS = dict(config.TOPICS)
except ImportError:
    TOPICS = {5001: "sports", 5002: "weather", 5003: "news"}

HERE = os.path.dirname(os.path.abspath(__file__))
STATS_FILE = os.path.join(HERE, "stats.json")
MONITOR_DPID = 1       # s1: the broker (h1) is attached here, so every topic flow crosses it
POLL_INTERVAL = 2      # seconds between stats requests
THRESHOLD_PPS = 100    # a topic above this many packets/s gets rerouted
HOLD_SECONDS = 30      # how long a rerouted topic stays on the backup path
PORT_OF = {name: port for port, name in TOPICS.items()}


def topic_of(match):
    """Topic name from a flow's TCP ports (either direction), or None."""
    for port, name in TOPICS.items():
        if port in (match.get("tcp_dst"), match.get("tcp_src")):
            return name
    return None


def topic_deltas(prev, stats, flow_lookup, first):
    """Packets seen per topic since the previous poll.

    stats:       list of (cookie, match_text, packet_count) read from the switch
    flow_lookup: cookie -> flow dict (from the network core) or None
    prev:        {(cookie, match_text): count} from the last poll, updated in place
    first:       True on the very first poll (only sets the baseline)
    """
    deltas = {name: 0 for name in TOPICS.values()}
    seen = {}
    for cookie, key, count in stats:
        flow = flow_lookup(cookie)
        if flow is None:
            continue
        topic = topic_of(flow["match"])
        if topic is None:
            continue
        k = (cookie, key)
        seen[k] = count
        old = prev.get(k)
        if old is None:
            d = 0 if first else count      # a new rule: everything it counted is new
        else:
            d = max(0, count - old)
        deltas[topic] += d
    prev.clear()
    prev.update(seen)
    return deltas


class TopicPolicy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopicPolicy, self).__init__(*args, **kwargs)
        self.core = None
        self.datapaths = {}
        self.prev = {}
        self.totals = {name: 0 for name in TOPICS.values()}
        self.rerouted = {}          # topic -> time its hold period ends
        self.first = True
        self.last_time = None
        self.settling = False      # True for one poll after a failover/recovery
        hub.spawn(self._attach)
        hub.spawn(self._monitor)

    # ---- connect to Member 2's core --------------------------------------
    def _attach(self):
        while self.core is None:
            self.core = app_manager.lookup_service_brick('NetworkCore')
            hub.sleep(0.5)
        self.core.set_path_selector(self.select_path)
        self.logger.info('[policy] attached to NetworkCore')

    def select_path(self, flow, usable_paths):
        """Called by the core for each NEW flow and on failover."""
        topic = topic_of(flow['match'])
        if topic in self.rerouted and self.rerouted[topic] > time.time() and len(usable_paths) > 1:
            return usable_paths[1]
        return None                      # default: primary first

    @set_ev_cls(EventPathChanged)
    def _on_path_changed(self, ev):
        """A failover or recovery restarts the rule counters, so the next reading
        is not trustworthy: take it as a new baseline and do not react to it."""
        if ev.reason in ('failover', 'recovery'):
            self.settling = True

    # ---- keep track of connected switches ---------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    # ---- poll ---------------------------------------------------------------
    def _monitor(self):
        while True:
            dp = self.datapaths.get(MONITOR_DPID)
            if dp is not None and self.core is not None:
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        if ev.msg.datapath.id != MONITOR_DPID or self.core is None:
            return
        now = time.time()
        stats = [(s.cookie, str(s.match), s.packet_count)
                 for s in ev.msg.body if s.priority >= 10]
        settling = self.settling
        self.settling = False
        deltas = topic_deltas(self.prev, stats, self.core.flow_for_cookie, self.first or settling)
        dt = (now - self.last_time) if self.last_time else None
        self.first = False
        self.last_time = now

        result = {}
        for topic, d in deltas.items():
            self.totals[topic] += d
            pps = (d / dt) if (dt and not settling) else 0.0
            result[topic] = {"packets": self.totals[topic], "pps": round(pps, 2)}

        # ---- adaptive rule -------------------------------------------------
        for topic in list(self.rerouted):
            if self.rerouted[topic] <= now:
                del self.rerouted[topic]
        for topic, r in result.items():
            if not settling and r["pps"] > THRESHOLD_PPS:
                if topic not in self.rerouted:
                    try:
                        moved = self.core.move_flows('backup', tcp_dst=PORT_OF[topic])
                    except Exception as e:           # never let policy break monitoring
                        moved = []
                        self.logger.error('[policy] move failed: %r', e)
                    self.logger.warning('[policy] REROUTING %s: %.1f pps > %d, moved flows %s to the backup path',
                                        topic, r["pps"], THRESHOLD_PPS, moved)
                self.rerouted[topic] = now + HOLD_SECONDS

        paths = {}
        for topic, port in PORT_OF.items():
            flows = self.core.find_flows(tcp_dst=port)
            paths[topic] = sorted({"-".join("s%d" % s for s in f["path"]) for f in flows})

        data = {"time": int(now), "topics": result,
                "actions": {t: "REROUTED" for t in self.rerouted}, "paths": paths}
        tmp = STATS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, STATS_FILE)
        self.logger.info('[policy] %s', {t: r["pps"] for t, r in result.items()})
