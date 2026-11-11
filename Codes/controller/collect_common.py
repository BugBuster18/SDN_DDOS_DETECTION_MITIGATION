"""Shared Ryu flow-stat collector. Labels are assigned by the selected collector app."""
from __future__ import annotations

import csv
import os
from pathlib import Path
from datetime import datetime

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub

import switch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = Path(os.environ.get("DDOS_FLOW_CSV", PROJECT_ROOT / "data/raw/sdn_flows.csv"))
FIELDS = [
    "timestamp", "datapath_id", "flow_id", "ip_src", "tp_src", "ip_dst", "tp_dst",
    "ip_proto", "icmp_code", "icmp_type", "flow_duration_sec", "flow_duration_nsec",
    "idle_timeout", "hard_timeout", "flags", "packet_count", "byte_count",
    "packet_count_per_second", "packet_count_per_nsecond", "byte_count_per_second",
    "byte_count_per_nsecond", "label",
]


class FlowCollector(switch.SimpleSwitch13):
    LABEL = 0
    def __init__(self, *args, **kwargs):
        super(FlowCollector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not DATA_PATH.exists() or DATA_PATH.stat().st_size == 0:
            with DATA_PATH.open("w", newline="", encoding="utf-8") as handle:
                csv.writer(handle).writerow(FIELDS)
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("Collecting label=%s flows into %s", self.LABEL, DATA_PATH)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                datapath.send_msg(datapath.ofproto_parser.OFPFlowStatsRequest(datapath))
            hub.sleep(10)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        rows = []
        datapath_id = ev.msg.datapath.id
        for stat in ev.msg.body:
            match = stat.match
            if stat.priority != 1 or not all(k in match for k in ("ipv4_src", "ipv4_dst", "ip_proto")):
                continue
            proto = int(match.get("ip_proto", -1))
            src_port = match.get("tcp_src", match.get("udp_src", 0)) or 0
            dst_port = match.get("tcp_dst", match.get("udp_dst", 0)) or 0
            icmp_code = match.get("icmpv4_code", -1)
            icmp_type = match.get("icmpv4_type", -1)
            duration = float(stat.duration_sec) + float(stat.duration_nsec) / 1_000_000_000.0
            safe_duration = max(duration, 1e-9)
            flow_id = f"{match.get('ipv4_src')}:{src_port}>{match.get('ipv4_dst')}:{dst_port}/{proto}"
            rows.append([
                datetime.now().timestamp(), datapath_id, flow_id,
                match.get("ipv4_src"), src_port, match.get("ipv4_dst"), dst_port,
                proto, icmp_code, icmp_type, stat.duration_sec, stat.duration_nsec,
                stat.idle_timeout, stat.hard_timeout, stat.flags, stat.packet_count,
                stat.byte_count, stat.packet_count / safe_duration,
                stat.packet_count / max(float(stat.duration_nsec), 1.0),
                stat.byte_count / safe_duration,
                stat.byte_count / max(float(stat.duration_nsec), 1.0), self.LABEL,
            ])
        if rows:
            with DATA_PATH.open("a", newline="", encoding="utf-8") as handle:
                csv.writer(handle).writerows(rows)
            self.logger.info("Appended %d flow records with label=%d", len(rows), self.LABEL)


class BenignFlowCollector(FlowCollector):
    LABEL = 0


class AttackFlowCollector(FlowCollector):
    LABEL = 1
