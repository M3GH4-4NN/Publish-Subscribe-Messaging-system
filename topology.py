#!/usr/bin/env python3
"""
topology.py - Mininet topology for the pub-sub project (Member 2).

Builds the diamond (or loop-free tree) topology from netcore_config.py with:
  * fixed host names, IPs and MACs
  * fixed switch port numbers (so the controller's port map is always right)
  * TCLink on every link (bandwidth / delay / loss configurable)
  * OpenFlow 1.3 forced on every switch
  * a RemoteController (start Ryu first: ryu-manager network_core.py)
  * static ARP on all hosts, so no ARP broadcast ever circles the loop

Usage (inside the Mininet VM, as root):
  sudo python3 topology.py                      # diamond, CLI
  sudo python3 topology.py --topo tree          # loop-free, for first tests
  sudo python3 topology.py --bw 5 --delay 5ms --loss 1
  sudo python3 topology.py --no-static-arp      # rely on the controller's proxy ARP
  sudo python3 topology.py --userspace          # OVS userspace datapath (no OVS kernel module)

Useful CLI commands once it is running:
  mininet> pingall
  mininet> link s1 s2 down        # trigger failover
  mininet> link s1 s2 up
  mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
  mininet> h3 iperf -s &  ;  h2 iperf -c 10.0.0.3 -t 5
"""
import argparse
import os
import sys
from functools import partial

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netcore_config as cfg  # noqa: E402


class PubSubTopo(Topo):
    """Topology built entirely from netcore_config."""

    def build(self, topo_name='diamond', core=None, host_link=None):
        core = core or {}
        host_link = host_link or {}
        spec = cfg.TOPOLOGIES[topo_name]

        for dpid in spec['switches']:
            self.addSwitch('s%d' % dpid, dpid='%016x' % dpid, protocols='OpenFlow13')

        for name, h in sorted(cfg.hosts_on(topo_name).items()):
            self.addHost(name, ip='%s/%d' % (h['ip'], cfg.SUBNET_PREFIX), mac=h['mac'])
            # port1 = host side (eth0), port2 = the fixed switch port from the config
            self.addLink(name, 's%d' % h['switch'], port1=0, port2=h['port'], **host_link)

        for a, pa, b, pb in spec['links']:
            self.addLink('s%d' % a, 's%d' % b, port1=pa, port2=pb, **core)


def link_params(bw, delay, loss, queue):
    p = {}
    if bw:
        p['bw'] = bw
    if delay and delay not in ('0', '0ms'):
        p['delay'] = delay
    if loss:
        p['loss'] = loss
    if queue:
        p['max_queue_size'] = queue
    return p


def build_net(topo_name=cfg.DEFAULT_TOPO, bw=None, delay=None, loss=None,
              static_arp=True, userspace=False, ctrl_ip=cfg.CONTROLLER_IP,
              ctrl_port=cfg.CONTROLLER_PORT, shape=True, queue=None):
    """Create (but do not start) the Mininet network. Used by the tests too."""
    if shape:
        core = link_params(bw if bw is not None else cfg.CORE_LINK['bw'],
                           delay if delay is not None else cfg.CORE_LINK['delay'],
                           loss if loss is not None else cfg.CORE_LINK['loss'],
                           cfg.CORE_LINK.get('max_queue_size') if queue is None else queue)
        hostp = link_params(cfg.HOST_LINK['bw'], cfg.HOST_LINK['delay'], cfg.HOST_LINK['loss'], None)
    else:
        core, hostp = {}, {}

    switch = partial(OVSSwitch, protocols='OpenFlow13', failMode='secure',
                     datapath='user' if userspace else 'kernel')
    net = Mininet(topo=PubSubTopo(topo_name=topo_name, core=core, host_link=hostp),
                  switch=switch, link=TCLink,
                  controller=partial(RemoteController, ip=ctrl_ip, port=ctrl_port),
                  autoSetMacs=False, build=True)
    net._static_arp_wanted = static_arp
    net._userspace = userspace
    return net


def start_net(net):
    net.start()
    if getattr(net, '_static_arp_wanted', True):
        net.staticArp()   # pre-fill every host's ARP table: no ARP broadcasts at all
    # Disable IPv6 on hosts so router/neighbour solicitations don't add noise
    for h in net.hosts:
        h.cmd('sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null')
        if getattr(net, '_userspace', False):
            # userspace OVS does not fill in offloaded TCP/UDP checksums on veth
            h.cmd('ethtool -K %s tx off >/dev/null 2>&1' % h.defaultIntf())
    return net


def print_port_map(topo_name):
    pm, _ = cfg.port_map(topo_name)
    info('*** Port map (from netcore_config.py)\n')
    for dpid in sorted(pm):
        for port in sorted(pm[dpid]):
            kind = pm[dpid][port]
            dest = kind[1] if kind[0] == 'host' else 's%d (port %d)' % (kind[1], kind[2])
            info('    s%d port %d -> %s\n' % (dpid, port, dest))


def main():
    ap = argparse.ArgumentParser(description='Pub-sub SDN topology (Member 2)')
    ap.add_argument('--topo', choices=sorted(cfg.TOPOLOGIES), default=cfg.DEFAULT_TOPO)
    ap.add_argument('--bw', type=float, help='core link bandwidth Mbit/s (default %s)' % cfg.CORE_LINK['bw'])
    ap.add_argument('--delay', help='core link delay, e.g. 5ms (default %s)' % cfg.CORE_LINK['delay'])
    ap.add_argument('--loss', type=float, help='core link loss %% (default %s)' % cfg.CORE_LINK['loss'])
    ap.add_argument('--no-shaping', action='store_true', help='plain links, no tc (debugging)')
    ap.add_argument('--no-static-arp', action='store_true', help='use controller proxy ARP instead')
    ap.add_argument('--userspace', action='store_true', help='OVS userspace datapath')
    ap.add_argument('--controller-ip', default=cfg.CONTROLLER_IP)
    ap.add_argument('--controller-port', type=int, default=cfg.CONTROLLER_PORT)
    args = ap.parse_args()

    setLogLevel('info')
    net = build_net(args.topo, args.bw, args.delay, args.loss,
                    static_arp=not args.no_static_arp, userspace=args.userspace,
                    ctrl_ip=args.controller_ip, ctrl_port=args.controller_port,
                    shape=not args.no_shaping)
    start_net(net)
    print_port_map(args.topo)
    info('*** Broker host: %s (%s)\n' % (cfg.BROKER_HOST, cfg.HOSTS[cfg.BROKER_HOST]['ip']))
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()
