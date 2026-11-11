"""Ryu OpenFlow 1.3 monitor using the seven-feature CICFlowMeter model.

This version aligns live OpenFlow observations with the bidirectional feature
semantics used during CICFlowMeter training and handles multipart stats replies.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import time
from urllib.request import Request, urlopen
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub

import switch
from ddos_ml.sdn_runtime import aggregate_bidirectional_rows

POLL_SECONDS = max(float(os.environ.get("DDOS_POLL_SECONDS", "10")), 1.0)
REPLY_TIMEOUT_SECONDS = max(
    float(os.environ.get("DDOS_REPLY_TIMEOUT_SECONDS", "3")), 0.25
)
ML_API_URL = os.environ.get(
    "DDOS_ML_API_URL", "http://127.0.0.1:8765/predict"
)
ML_API_TIMEOUT_SECONDS = max(
    float(os.environ.get("DDOS_ML_API_TIMEOUT_SECONDS", "5")), 1.0
)


class SimpleMonitor13(switch.SimpleSwitch13):
    """Collect stats, aggregate bidirectional conversations, and classify."""

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self._active_cycle = None
        self._configure_capture()
        self.logger.info("ML prediction endpoint: %s", ML_API_URL)
        self.logger.info(
            "Monitoring with bidirectional aggregation; poll=%ss reply_timeout=%ss",
            POLL_SECONDS,
            REPLY_TIMEOUT_SECONDS,
        )
        self.monitor_thread = hub.spawn(self._monitor)

    def _configure_capture(self):
        raw_label = os.environ.get("DDOS_CAPTURE_LABEL")
        self.capture_label = None

        if raw_label is None:
            self.logger.info("SDN traffic capture is disabled")
            return

        if raw_label not in ("0", "1"):
            raise ValueError("DDOS_CAPTURE_LABEL must be 0 or 1")

        self.capture_label = int(raw_label)
        self.capture_path = Path(os.environ.get(
            "DDOS_CAPTURE_CSV",
            str(PROJECT_ROOT / "data/raw/mininet_capture.csv"),
        ))

        self.capture_path.parent.mkdir(parents=True, exist_ok=True)

        self.capture_fields = [
            "timestamp", "ip_src", "tp_src", "ip_dst", "tp_dst",
            "ip_proto", "flow_duration_sec", "flow_duration_nsec",
            "packet_count", "byte_count", "label",
        ]

        if not self.capture_path.exists() or self.capture_path.stat().st_size == 0:
            with self.capture_path.open("w", newline="", encoding="utf-8") as handle:
                csv.writer(handle).writerow(self.capture_fields)

        self.logger.warning(
            "SDN traffic capture enabled: label=%d file=%s",
            self.capture_label,
            self.capture_path,
        )

    def _capture_rows(self, rows):
        if self.capture_label is None or not rows:
            return

        with self.capture_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)

            for row in rows:
                writer.writerow([
                    time.time(),
                    row.get("ip_src", ""),
                    row.get("tp_src", 0),
                    row.get("ip_dst", ""),
                    row.get("tp_dst", 0),
                    row.get("ip_proto", -1),
                    row.get("duration_sec", 0),
                    row.get("duration_nsec", 0),
                    row.get("packet_count", 0),
                    row.get("byte_count", 0),
                    self.capture_label,
                ])

        self.logger.info(
            "Captured %d aggregated flow snapshots with label=%d",
            len(rows),
            self.capture_label,
        )

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
            cycle_started = time.monotonic()
            cycle = {"rows": [], "pending": set()}
            self._active_cycle = cycle

            for datapath in list(self.datapaths.values()):
                request = datapath.ofproto_parser.OFPFlowStatsRequest(datapath)
                # Assign XID before sending so the reply can be tied to this poll.
                if getattr(request, "xid", None) is None:
                    datapath.set_xid(request)
                key = (datapath.id, request.xid)
                cycle["pending"].add(key)
                try:
                    datapath.send_msg(request)
                except Exception:
                    cycle["pending"].discard(key)
                    self.logger.exception(
                        "Could not request flow statistics from switch %016x",
                        datapath.id,
                    )

            deadline = time.monotonic() + REPLY_TIMEOUT_SECONDS
            while cycle["pending"] and time.monotonic() < deadline:
                hub.sleep(0.05)

            # Close the cycle before scoring. Late replies are discarded instead
            # of accidentally contaminating the next polling window.
            if self._active_cycle is cycle:
                self._active_cycle = None

            raw_rows = cycle["rows"]
            rows = aggregate_bidirectional_rows(raw_rows)
            missing_replies = len(cycle["pending"])
            if missing_replies:
                self.logger.warning(
                    "Flow-stat poll timed out waiting for %d switch reply(s); processing received data",
                    missing_replies,
                )

            if rows:
                self.logger.info(
                    "Scoring %d bidirectional conversations from %d raw switch-flow observations",
                    len(rows),
                    len(raw_rows),
                )
                self._process_rows(rows)
            else:
                self.logger.info(
                    "Monitoring network: no IPv4 flow observations in this poll window"
                )

            elapsed = time.monotonic() - cycle_started
            hub.sleep(max(POLL_SECONDS - elapsed, 0.1))

    def _request_stats(self, datapath):
        """Compatibility helper for manual requests; normal polling is in _monitor."""
        request = datapath.ofproto_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(request)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        cycle = self._active_cycle
        if cycle is None:
            return

        request_key = (datapath.id, ev.msg.xid)
        if request_key not in cycle["pending"]:
            return

        for stat in ev.msg.body:
            match = stat.match
            if (
                stat.priority != 1
                or "ipv4_src" not in match
                or "ipv4_dst" not in match
                or "ip_proto" not in match
            ):
                continue

            ip_proto = int(match.get("ip_proto", -1))
            tcp_src = match.get("tcp_src")
            udp_src = match.get("udp_src")
            tcp_dst = match.get("tcp_dst")
            udp_dst = match.get("udp_dst")
            tp_src = tcp_src if tcp_src is not None else (udp_src or 0)
            tp_dst = tcp_dst if tcp_dst is not None else (udp_dst or 0)

            match_fields = {}
            for key in (
                "in_port", "eth_type", "ipv4_src", "ipv4_dst", "ip_proto",
                "tcp_src", "tcp_dst", "udp_src", "udp_dst",
                "icmpv4_code", "icmpv4_type",
            ):
                value = match.get(key)
                if value is not None:
                    match_fields[key] = value

            cycle["rows"].append(
                {
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
                }
            )

        # OpenFlow may split large flow-stat replies across multiple messages.
        more_flag = getattr(datapath.ofproto, "OFPMPF_REPLY_MORE", 1)
        if not (getattr(ev.msg, "flags", 0) & more_flag):
            cycle["pending"].discard(request_key)

    def _process_rows(self, rows):
        self._capture_rows(rows)
        # Send only the traffic statistics required by the ML feature adapter.
        flows = []

        for row in rows:
            flows.append({
                "ip_proto": int(row.get("ip_proto", -1)),
                "duration_sec": int(row.get("duration_sec", 0)),
                "duration_nsec": int(row.get("duration_nsec", 0)),
                "packet_count": int(row.get("packet_count", 0)),
                "byte_count": int(row.get("byte_count", 0)),
            })

        body = json.dumps({"flows": flows}).encode("utf-8")
        request = Request(
            ML_API_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=ML_API_TIMEOUT_SECONDS) as response:
                result = json.loads(response.read().decode("utf-8"))

            predictions = result.get("predictions")
            if not isinstance(predictions, list) or len(predictions) != len(rows):
                raise ValueError("Invalid prediction count returned by ML API")

            parsed = []
            for item in predictions:
                prediction = int(item["prediction"])
                probability = float(item["attack_probability"])

                if prediction not in (0, 1):
                    raise ValueError("Invalid prediction label")
                if not 0.0 <= probability <= 1.0:
                    raise ValueError("Invalid attack probability")

                parsed.append((prediction, probability))

        except Exception as exc:
            self.logger.error("ML prediction request failed: %s", exc)
            return

        attacks = []

        for row, (prediction, probability) in zip(rows, parsed):
            is_attack = prediction == 1
            self._on_prediction(row, is_attack, probability)

            if is_attack:
                attacks.append(row)

        if attacks:
            destination_counts = {}

            for row in attacks:
                destination = row.get("ip_dst", "unknown")
                destination_counts[destination] = (
                    destination_counts.get(destination, 0) + 1
                )

            victim = max(destination_counts, key=destination_counts.get)

            self.logger.warning(
                "Potential DDoS: %d/%d bidirectional conversations classified as attack; "
                "most frequent observed destination=%s",
                len(attacks),
                len(rows),
                victim,
            )
        else:
            self.logger.info(
                "Traffic classified as benign: %d/%d bidirectional conversations",
                len(rows),
                len(rows),
            )

    def _on_prediction(self, row, is_attack, probability):
        self.logger.info(
            "flow %s:%s <-> %s:%s proto=%s attack=%s probability=%.3f datapath=%s",
            row.get("ip_src"), row.get("tp_src"),
            row.get("ip_dst"), row.get("tp_dst"),
            row.get("ip_proto"), is_attack, probability,
            row.get("datapath_id"),
        )
