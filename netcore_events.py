"""
netcore_events.py - Ryu events raised by the network core so other apps
(Member 3's policy/monitoring module) can react without polling.

Usage in another Ryu app:

    from ryu.controller.handler import set_ev_cls
    from netcore_events import EventPathChanged, EventLinkState

    @set_ev_cls(EventPathChanged)
    def on_path_changed(self, ev):
        print(ev.flow_id, ev.old_path, ev.new_path, ev.reason)
"""
from ryu.controller import event


class EventPathChanged(event.EventBase):
    """A flow was moved to another path. reason: 'failover', 'recovery', 'api'."""

    def __init__(self, flow_id, old_path, new_path, reason, elapsed_ms):
        super(EventPathChanged, self).__init__()
        self.flow_id = flow_id
        self.old_path = old_path
        self.new_path = new_path
        self.reason = reason
        self.elapsed_ms = elapsed_ms


class EventLinkState(event.EventBase):
    """A switch-to-switch link went up or down. link = (dpid_a, dpid_b), a < b."""

    def __init__(self, link, up):
        super(EventLinkState, self).__init__()
        self.link = link
        self.up = up


class EventFlowInstalled(event.EventBase):
    """A new flow (reactive or via the API) was installed along a path."""

    def __init__(self, flow_id, info):
        super(EventFlowInstalled, self).__init__()
        self.flow_id = flow_id
        self.info = info
