"""
netcore_config.py - single source of truth for the network core (Member 2).

Both the Mininet topology script and the Ryu controller import this file,
so host addresses, port numbers and links are defined exactly once.
Change things HERE, never in the other files.

Port map (diamond topology)
---------------------------

            port3   +----+   port2
         +----------| s2 |----------+
         |  (s2 p1) +----+  (s4 p1) |
  h1 -p1-+                          +-p3- h3
       [s1]                        [s4]-p4- h4
  h2 -p2-+                          +-p5- h5
         |  (s3 p1) +----+  (s4 p2) |
         +----------| s3 |----------+
            port4   +----+   port2

  Primary path s1 <-> s4 : s1 - s2 - s4   (upper branch)
  Backup  path s1 <-> s4 : s1 - s3 - s4   (lower branch)

The "tree" topology is the same picture without s3 (no loop); use it first to
prove the forwarding rules work, then switch to "diamond".
"""
import os

# --------------------------------------------------------------------------
# Hosts: fixed names, IPs and MACs. 'switch'/'port' = where the host plugs in.
# h1 is the broker by default (Member 1's broker should bind on 10.0.0.1).
# --------------------------------------------------------------------------
HOSTS = {
    'h1': {'ip': '10.0.0.1', 'mac': '00:00:00:00:00:01', 'switch': 1, 'port': 1, 'role': 'broker'},
    'h2': {'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02', 'switch': 1, 'port': 2, 'role': 'client'},
    'h3': {'ip': '10.0.0.3', 'mac': '00:00:00:00:00:03', 'switch': 4, 'port': 3, 'role': 'client'},
    'h4': {'ip': '10.0.0.4', 'mac': '00:00:00:00:00:04', 'switch': 4, 'port': 4, 'role': 'client'},
    'h5': {'ip': '10.0.0.5', 'mac': '00:00:00:00:00:05', 'switch': 4, 'port': 5, 'role': 'client'},
}

BROKER_HOST = 'h1'
SUBNET_PREFIX = 8  # hosts are 10.0.0.x/8

# --------------------------------------------------------------------------
# Switch-to-switch links: (switch_a, port_on_a, switch_b, port_on_b)
# --------------------------------------------------------------------------
TOPOLOGIES = {
    'tree': {
        'switches': [1, 2, 4],
        'links': [
            (1, 3, 2, 1),
            (2, 2, 4, 1),
        ],
    },
    'diamond': {
        'switches': [1, 2, 3, 4],
        'links': [
            (1, 3, 2, 1),   # s1-s2  (primary, upper)
            (2, 2, 4, 1),   # s2-s4  (primary, upper)
            (1, 4, 3, 1),   # s1-s3  (backup, lower)
            (3, 2, 4, 2),   # s3-s4  (backup, lower)
        ],
    },
}

DEFAULT_TOPO = 'diamond'

# --------------------------------------------------------------------------
# Explicit path definitions (ASSUMPTION documented in README: for this project
# paths are a fixed dictionary, not computed by a routing protocol).
# Key = (src_switch, dst_switch); value = ordered list of candidate paths,
# first entry is the primary, the rest are backups in order of preference.
# Reverse direction is derived automatically by reversing each path.
# Any switch pair NOT listed here falls back to all loop-free paths found by a
# simple search over the link table, sorted shortest first.
# --------------------------------------------------------------------------
PATHS = {
    'tree': {
        (1, 4): [[1, 2, 4]],
    },
    'diamond': {
        (1, 4): [[1, 2, 4], [1, 3, 4]],
    },
}

# --------------------------------------------------------------------------
# Link shaping defaults for TCLink (Member 3's congestion tests rely on these).
# Capacities are also what Member 3 divides by for link utilisation.
# --------------------------------------------------------------------------
CORE_LINK = {'bw': 10, 'delay': '2ms', 'loss': 0, 'max_queue_size': 1000}   # Mbit/s
HOST_LINK = {'bw': 100, 'delay': '0ms', 'loss': 0}

# --------------------------------------------------------------------------
# Controller settings
# --------------------------------------------------------------------------
CONTROLLER_IP = '127.0.0.1'
CONTROLLER_PORT = 6633

# Rule priorities (higher wins when matches overlap)
PRIO_TABLE_MISS = 0      # send to controller
PRIO_DROP_NOISE = 1      # drop IPv6 / LLDP so they never loop or spam the controller
PRIO_ARP_TO_CTRL = 5     # ARP goes to controller (proxy ARP), never flooded
PRIO_REACTIVE = 10       # per-connection rules installed on packet-in
PRIO_POLICY_MIN = 20     # Member 3 policy rules should use >= this

# Reactive rules expire after this many idle seconds (0 = never). When any
# rule of a flow expires, the controller removes the whole flow everywhere so
# the next packet re-triggers a clean install.
REACTIVE_IDLE_TIMEOUT = 30

# Recovery policy when a failed link comes back up:
#   False -> stay on the backup path (non-revertive, default: avoids a second
#            disruption; new flows will use the primary again automatically)
#   True  -> move flows back to their primary path (revertive)
# Override without editing: NETCORE_REVERT=1 ryu-manager network_core.py
REVERT_ON_RECOVERY = os.environ.get('NETCORE_REVERT', '0') == '1'

# Cookie layout: top 16 bits = tag (e.g. topic id chosen by Member 3, 0 = none),
# low 48 bits = unique flow id. Lets us delete one flow, or a whole topic.
COOKIE_TAG_SHIFT = 48
COOKIE_ID_MASK = (1 << 48) - 1
COOKIE_FULL_MASK = (1 << 64) - 1
COOKIE_TAG_MASK = ((1 << 16) - 1) << 48

# Log file for failover timing (one CSV line per reroute)
FAILOVER_LOG = 'failover_log.csv'


# --------------------------------------------------------------------------
# Helper functions (used by both topology and controller)
# --------------------------------------------------------------------------
def host_by_ip(ip):
    for name, h in HOSTS.items():
        if h['ip'] == ip:
            return name, h
    return None, None


def host_by_mac(mac):
    for name, h in HOSTS.items():
        if h['mac'] == mac:
            return name, h
    return None, None


def hosts_on(topo):
    """Hosts whose access switch exists in this topology."""
    sw = set(TOPOLOGIES[topo]['switches'])
    return {n: h for n, h in HOSTS.items() if h['switch'] in sw}


def port_map(topo):
    """
    {dpid: {port_no: ('switch', neighbour_dpid, neighbour_port) or ('host', name)}}
    and next-hop lookup {(dpid, neighbour_dpid): out_port}.
    """
    pm = {s: {} for s in TOPOLOGIES[topo]['switches']}
    nh = {}
    for a, pa, b, pb in TOPOLOGIES[topo]['links']:
        pm[a][pa] = ('switch', b, pb)
        pm[b][pb] = ('switch', a, pa)
        nh[(a, b)] = pa
        nh[(b, a)] = pb
    for name, h in hosts_on(topo).items():
        pm[h['switch']][h['port']] = ('host', name)
    return pm, nh


def link_id(a, b):
    """Canonical, direction-independent id for a switch-switch link."""
    return (min(a, b), max(a, b))


def _search_paths(topo, src, dst):
    adj = {}
    for a, _, b, _ in TOPOLOGIES[topo]['links']:
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)
    out, stack = [], [(src, [src])]
    while stack:
        node, path = stack.pop()
        if node == dst:
            out.append(path)
            continue
        for n in sorted(adj.get(node, ())):
            if n not in path:
                stack.append((n, path + [n]))
    return sorted(out, key=lambda p: (len(p), p))


def candidate_paths(topo, src_sw, dst_sw):
    """Ordered candidate switch paths src_sw -> dst_sw (primary first)."""
    if src_sw == dst_sw:
        return [[src_sw]]
    table = PATHS.get(topo, {})
    if (src_sw, dst_sw) in table:
        return [list(p) for p in table[(src_sw, dst_sw)]]
    if (dst_sw, src_sw) in table:
        return [list(reversed(p)) for p in table[(dst_sw, src_sw)]]
    return _search_paths(topo, src_sw, dst_sw)
