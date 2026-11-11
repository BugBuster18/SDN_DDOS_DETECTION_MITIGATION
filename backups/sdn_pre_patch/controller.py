"""Ryu OpenFlow 1.3 monitor using the shared, pre-trained DDoS model."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub

import switch
from ddos_ml.runtime import load_model, live_feature_frame

POLL_SECONDS = float(os.environ.get("DDOS_POLL_SECONDS", "10"))


class SimpleMonitor13(switch.SimpleSwitch13):
    """Collect flow counters, score them, and report likely attack flows."""

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_model, self.model_metadata = load_model(PROJECT_ROOT / os.environ.get("DDOS_MODEL_DIR", "artifacts/production"))
        self._cycle_flows = []
        self.logger.info("Loaded DDoS model trained from %s", self.model_metadata.get("training_source", "unknown"))
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Registered switch %016x", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.logger.info("Unregistered switch %016x", datapath.id)

    def _monitor(self):
        while True:
            # Start a fresh polling window; OFPFlowStatsReply events append to it.
            self._cycle_flows = []
            for datapath in list(self.datapaths.values()):
                self._request_stats(datapath)
            hub.sleep(POLL_SECONDS)
            rows = self._cycle_flows
            self._cycle_flows = []
            if rows:
                self._process_rows(rows)
            else:
                self.logger.info("Monitoring network: no IPv4 data flows in this poll window")

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        for stat in ev.msg.body:
            match = stat.match
            if stat.priority != 1 or "ipv4_src" not in match or "ipv4_dst" not in match or "ip_proto" not in match:
                continue
            ip_proto = int(match.get("ip_proto", -1))
            tp_src = match.get("tcp_src", match.get("udp_src", 0))
            tp_dst = match.get("tcp_dst", match.get("udp_dst", 0))
            match_fields = {}
            for key in ("in_port", "eth_type", "ipv4_src", "ipv4_dst", "ip_proto",
                        "tcp_src", "tcp_dst", "udp_src", "udp_dst", "icmpv4_code", "icmpv4_type"):
                try:
                    value = match.get(key)
                except Exception:
                    value = None
                if value is not None:
                    match_fields[key] = value
            self._cycle_flows.append({
                "timestamp": datetime.now().timestamp(),
                "datapath_id": datapath.id,
                "datapath": datapath,
                "ip_src": match.get("ipv4_src"),
                "ip_dst": match.get("ipv4_dst"),
                "ip_proto": ip_proto,
                "tp_src": tp_src or 0,
                "tp_dst": tp_dst or 0,
                "duration_sec": stat.duration_sec,
                "duration_nsec": stat.duration_nsec,
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "in_port": match.get("in_port"),
                "match_fields": match_fields,
            })

    def _process_rows(self, rows):
        features = live_feature_frame(rows)
        predictions = self.flow_model.predict(features)
        probabilities = self.flow_model.predict_proba(features)[:, 1]
        attacks = []
        for row, prediction, probability in zip(rows, predictions, probabilities):
            is_attack = int(prediction) == 1
            self._on_prediction(row, is_attack, float(probability))
            if is_attack:
                attacks.append(row)
        if attacks:
            destination_counts = {}
            for row in attacks:
                destination_counts[row.get("ip_dst", "unknown")] = destination_counts.get(row.get("ip_dst", "unknown"), 0) + 1
            victim = max(destination_counts, key=destination_counts.get)
            self.logger.warning("Potential DDoS: %d/%d flows classified as attack; most frequent destination=%s",
                                len(attacks), len(rows), victim)
        else:
            self.logger.info("Traffic classified as benign: %d/%d flows", len(rows), len(rows))

    def _on_prediction(self, row, is_attack, probability):
        self.logger.debug("flow %s -> %s proto=%s attack=%s probability=%.3f",
                          row.get("ip_src"), row.get("ip_dst"), row.get("ip_proto"),
                          is_attack, probability)
