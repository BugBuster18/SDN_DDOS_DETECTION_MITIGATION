"""Hybrid destination-centric DDoS detector and staged mitigator (Ryu, OF1.3).

Level 1: flow-level ML (existing seven-feature model via the localhost API).
Level 2: counter-delta, destination-centric window features.
Level 3: transparent decision engine + state machine + scoped, reversible
         mitigation.

Mitigation modes (see ddos_ml/mitigation.py):
    DETECTION_ONLY (default) | DRY_RUN | MITIGATION_ENABLED
The startup mode comes from DDOS_MITIGATION_MODE or the config file; it can be
changed at runtime through the localhost REST API (only to MITIGATION_ENABLED
when the config says detection.mode: enforce).

REST API (start ryu-manager with --wsapi-host 127.0.0.1 --wsapi-port 8080):
    GET    /ddos/status                 mode, switches, per-destination state + evidence
    GET    /ddos/rules                  active drop rules (with drop counters)
    DELETE /ddos/rules                  remove ALL drop rules
    DELETE /ddos/rules/{cookie}         remove one drop rule
    GET    /ddos/mode                   current mode
    POST   /ddos/mode  {"mode": "..."}  change mode
    GET    /ddos/events?since=N         alert / mitigation event log

Run:
    DDOS_CONFIG=experiments/configs/demo.yaml ryu-manager --ofp-tcp-listen-port 6653 \
        --wsapi-host 127.0.0.1 --wsapi-port 8080 hybrid_controller.py

The original controller.py is left unchanged (baseline / capture tool).
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import deque
from pathlib import Path
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ipv4, arp
from webob import Response

import switch
from ddos_ml.config import load_config
from ddos_ml.decision_engine import DecisionEngine, CONFIRMED, MITIGATING, NORMAL
from ddos_ml.mitigation import (
    DROP_COOKIE_MASK, DROP_COOKIE_TAG, DETECTION_ONLY, DRY_RUN, MITIGATION_ENABLED,
    DropRule, DropRuleTable, DryRunLedger, flags_from_mode, format_cookie, normalize_mode,
    parse_cookie, proto_name, status_label,
)
from ddos_ml.sdn_runtime import aggregate_bidirectional_rows
from ddos_ml.temporal_features import (
    DestinationWindowAnalyzer, FlowCounterTracker, merge_path_observations,
)

REST_INSTANCE = "ddos_app"
SUMMARY_FEATURES = ("n_sources", "n_active_flows", "n_new_flows", "pps", "bps", "avg_pkt_size",
                    "udp_share", "tcp_share", "icmp_share", "response_ratio", "top_source_share",
                    "ml_max_prob", "ml_mean_prob", "ml_flow_frac", "ml_pps_share")


class HybridDetector(switch.SimpleSwitch13):
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(HybridDetector, self).__init__(*args, **kwargs)
        self.cfg = load_config()
        mon, det, mit = self.cfg["monitoring"], self.cfg["detection"], self.cfg["mitigation"]
        self.poll = max(float(mon["polling_interval_seconds"]), 0.5)
        self.reply_timeout = min(float(mon["reply_timeout_seconds"]), self.poll * 0.8)
        self.ml_url = mon["ml_api_url"]
        self.ml_timeout = float(mon["ml_api_timeout_seconds"])
        self.ml_batch = int(mon["ml_batch_size"])
        self.ml_max = int(mon["max_ml_flows_per_poll"])
        self.ml_threshold = float(det["ml_threshold"])
        self.tracker = FlowCounterTracker(expire_after_seconds=float(mon["flow_expire_seconds"]))
        self.analyzer = DestinationWindowAnalyzer()
        self.engine = DecisionEngine.from_config(self.cfg, PROJECT_ROOT) if det["enabled"] else None
        self.mode = mit["mode"]
        self.datapaths = {}
        self.host_location = {}          # ip -> dpid of first switch that saw it (ingress)
        self.packet_in_by_dst = {}
        self.counters = {"packet_in": 0, "flow_mod": 0, "stats_req": 0, "stats_reply_msgs": 0}
        self.rules = DropRuleTable()
        self.dry_ledger = DryRunLedger()
        self._cycle = None
        self.poll_id = 0
        self.ml_status = "unknown"
        self.alert_log = deque(maxlen=2000)
        self._event_seq = 0
        self.last_window = {"ts": None, "poll": 0, "dst": {}}
        log_path = mon.get("log_jsonl") or os.environ.get("DDOS_TELEMETRY_JSONL")
        self.log_fh = None
        if log_path:
            p = Path(log_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self.log_fh = p.open("a", encoding="utf-8")
        self.kill_switch = PROJECT_ROOT / mit["kill_switch_file"]
        # Source-address validation (anti-spoofing). A host-facing edge port is bound to the IP
        # of the host behind it (read from the lab's state file). Packets entering that port
        # with another source address are spoofed; when a port emits >= min_packets of them
        # towards one destination in a window, the port is quarantined for that destination.
        asp = mit.get("anti_spoofing") or {}
        self.asp_enabled = bool(asp.get("enabled", False))
        self.asp_min = int(asp.get("min_packets", 20))
        self.asp_file = Path(asp["bindings_file"]) if asp.get("bindings_file") else None
        if self.asp_file is not None and not self.asp_file.is_absolute():
            self.asp_file = PROJECT_ROOT / self.asp_file
        self.port_binding = {}           # (dpid, port_no) -> bound ip
        self.spoof_evidence = {}         # (dpid, port_no, dst) -> spoofed packet-ins this window
        kwargs["wsgi"].register(DdosRestController, {REST_INSTANCE: self})
        self.logger.warning(
            "HybridDetector: method=%s poll=%.1fs confirm=%s/%s MODE=%s (detection.mode=%s)",
            det["method"], self.poll, det["confirm_k"], det["confirm_n"], self.mode, det["mode"])
        self._emit({"event": "start", "config": self.cfg})
        self._event("start", mode=self.mode)
        self.monitor_thread = hub.spawn(self._monitor)

    # ------------------------------------------------------------ utilities
    def _emit(self, record):
        if self.log_fh is None:
            return
        record.setdefault("ts", time.time())
        self.log_fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
        self.log_fh.flush()

    def _event(self, kind, **fields):
        self._event_seq += 1
        rec = {"seq": self._event_seq, "ts": round(time.time(), 3), "type": kind}
        rec.update(fields)
        self.alert_log.append(rec)
        return rec

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        self.counters["flow_mod"] += 1
        super(HybridDetector, self).add_flow(datapath, priority, match, actions, buffer_id, idle, hard)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.counters["packet_in"] += 1
        try:
            pkt = packet.Packet(ev.msg.data)
            ip = pkt.get_protocol(ipv4.ipv4)
            src = dst = None
            if ip is not None:
                src, dst = ip.src, ip.dst
                self.packet_in_by_dst[dst] = self.packet_in_by_dst.get(dst, 0) + 1
                if self.asp_enabled and self.port_binding:
                    k = (ev.msg.datapath.id, ev.msg.match["in_port"])
                    bound = self.port_binding.get(k)
                    if bound is not None and src != bound:
                        kk = k + (dst,)
                        self.spoof_evidence[kk] = self.spoof_evidence.get(kk, 0) + 1
                        src = None  # never learn a spoofed address as a host location
            else:
                a = pkt.get_protocol(arp.arp)
                if a is not None:
                    src = a.src_ip
            if src and src not in self.host_location:
                # The first switch to report a host's packet is its ingress switch.
                self.host_location[src] = ev.msg.datapath.id
        except Exception:  # never let telemetry break forwarding
            pass
        super(HybridDetector, self)._packet_in_handler(ev)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Registered switch %016x (s%d) - %d switch(es) connected",
                             dp.id, dp.id, len(self.datapaths))
            self._event("switch_connected", dpid=dp.id, n_switches=len(self.datapaths))
        elif ev.state == DEAD_DISPATCHER and dp.id is not None:
            self.datapaths.pop(dp.id, None)
            self.tracker.forget_datapath(dp.id)
            self.logger.warning("Switch %016x disconnected; counter state discarded", dp.id)
            self._event("switch_disconnected", dpid=dp.id, n_switches=len(self.datapaths))

    # ------------------------------------------------------------- polling
    def _monitor(self):
        while True:
            started = time.monotonic()
            try:
                self._poll_once()
            except Exception:
                self.logger.exception("Detection cycle failed (continuing)")
            hub.sleep(max(self.poll - (time.monotonic() - started), 0.05))

    def _poll_once(self):
        cycle = {"rows": {}, "drops": [], "pending": set(), "reply_ts": {}}
        self._cycle = cycle
        for dp in list(self.datapaths.values()):
            req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
            dp.set_xid(req)
            key = (dp.id, req.xid)
            cycle["pending"].add(key)
            cycle["rows"][dp.id] = []
            try:
                dp.send_msg(req)
                self.counters["stats_req"] += 1
            except Exception:
                cycle["pending"].discard(key)
        deadline = time.monotonic() + self.reply_timeout
        while cycle["pending"] and time.monotonic() < deadline:
            hub.sleep(0.02)
        self._cycle = None
        missing = sorted({k[0] for k in cycle["pending"]})
        t_proc = time.monotonic()
        self.poll_id += 1
        self._process(cycle, missing)
        self._emit({"event": "ctrl", "poll": self.poll_id,
                    "cycle_seconds": round(time.monotonic() - t_proc, 4),
                    "counters": dict(self.counters), "tracked": len(self.tracker),
                    "drop_rules": len(self.rules)})

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        cycle = self._cycle
        dp = ev.msg.datapath
        if cycle is None or (dp.id, ev.msg.xid) not in cycle["pending"]:
            return
        self.counters["stats_reply_msgs"] += 1
        now = time.time()
        for stat in ev.msg.body:
            m = stat.match
            if (stat.cookie & DROP_COOKIE_MASK) == DROP_COOKIE_TAG:
                cycle["drops"].append((stat.cookie, stat.packet_count, m.get("ipv4_dst")))
                continue
            if stat.priority != 1 or "ipv4_src" not in m or "ipv4_dst" not in m:
                continue
            proto = int(m.get("ip_proto", -1))
            sp = m.get("tcp_src") if m.get("tcp_src") is not None else m.get("udp_src")
            dpt = m.get("tcp_dst") if m.get("tcp_dst") is not None else m.get("udp_dst")
            cycle["rows"][dp.id].append({
                "ip_src": m.get("ipv4_src"), "ip_dst": m.get("ipv4_dst"), "ip_proto": proto,
                "tp_src": sp or 0, "tp_dst": dpt or 0,
                "icmp_type": m.get("icmpv4_type", -1) if proto == 1 else -1,
                "duration_sec": stat.duration_sec, "duration_nsec": stat.duration_nsec,
                "packet_count": stat.packet_count, "byte_count": stat.byte_count,
            })
        cycle["reply_ts"][dp.id] = now
        more = getattr(dp.ofproto, "OFPMPF_REPLY_MORE", 1)
        if not (getattr(ev.msg, "flags", 0) & more):
            cycle["pending"].discard((dp.id, ev.msg.xid))

    # ------------------------------------------------------------ pipeline
    def _process(self, cycle, missing):
        ts = time.time()
        deltas = []
        for dpid, rows in cycle["rows"].items():
            if dpid in missing:
                continue  # keep previous counters; never fabricate zero deltas
            deltas.extend(self.tracker.update(dpid, rows, cycle["reply_ts"].get(dpid, ts)))
        flows = merge_path_observations(deltas)
        interval = max([d.elapsed for d in deltas if d.status == "ok"] or [self.poll])
        ml_ms = self._score_ml(flows)
        drop_hits = self.rules.update_counters(cycle["drops"], interval)
        pin = self.packet_in_by_dst
        self.packet_in_by_dst = {}
        dst_feats, src_feats = self.analyzer.compute(flows, interval, pin, self.ml_threshold)
        decisions = self.engine.step(ts, dst_feats, src_feats, drop_hits) if self.engine else []

        self._update_last_window(ts, dst_feats, src_feats, decisions, drop_hits, missing)
        self._log_window(dst_feats, decisions)
        for d in decisions:
            if d.state != d.previous_state or d.actions:
                self.logger.warning("dst=%s %s->%s score=%.3f sources=%s actions=%s",
                                    d.dst, d.previous_state, d.state, d.score, d.attributed_sources, d.actions)
            if d.state != d.previous_state:
                self._on_transition(d)
            self._apply_actions(d, flows)
        self._anti_spoofing()
        if self.kill_switch.exists() and len(self.rules):
            self.logger.warning("Kill-switch file present: rolling back all drop rules")
            self._rollback(None, reason="kill_switch")

        self._emit({
            "event": "window", "poll": self.poll_id, "interval": round(interval, 4), "mode": self.mode,
            "missing_dpids": missing, "n_dpids": len(cycle["rows"]), "ml_ms": ml_ms,
            "flows": [[r.src, r.key[1], r.dst, r.key[3], r.proto, r.key[5], r.status, r.delta_packets,
                       r.delta_bytes, r.packets, r.bytes, round(r.duration, 3),
                       None if r.ml_prob is None else round(r.ml_prob, 4)] for r in flows.values()],
            "packet_in_by_dst": pin, "drop_hits_pps": drop_hits,
            "dst": dst_feats,
            "src": {f"{s}->{d}": {"src_pps": round(v.get("src_pps", 0), 1),
                                   "src_share": round(v.get("src_share", 0), 3)}
                    for (s, d), v in src_feats.items()},
            "decisions": [d.__dict__ for d in decisions],
        })

    def _score_ml(self, flows):
        """Level 1: lifetime-counter features per bidirectional conversation."""
        candidates = [r for r in flows.values() if r.status != "no_baseline" and (r.delta_packets > 0 or r.status == "new")]
        candidates.sort(key=lambda r: -r.delta_packets)
        candidates = candidates[: self.ml_max]
        if not candidates:
            return 0.0
        rows = [{"ip_src": r.src, "tp_src": r.key[1], "ip_dst": r.dst, "tp_dst": r.key[3], "ip_proto": r.proto,
                 "datapath_id": 0, "packet_count": r.packets, "byte_count": r.bytes,
                 "duration_sec": int(r.duration), "duration_nsec": int((r.duration % 1) * 1e9)}
                for r in candidates]
        convs = aggregate_bidirectional_rows(rows)
        t0 = time.monotonic()
        probs = []
        try:
            for i in range(0, len(convs), self.ml_batch):
                chunk = convs[i:i + self.ml_batch]
                body = json.dumps({"flows": [{k: c[k] for k in ("ip_proto", "duration_sec", "duration_nsec",
                                                                "packet_count", "byte_count")} for c in chunk]})
                req = Request(self.ml_url, data=body.encode(), headers={"Content-Type": "application/json"},
                              method="POST")
                with urlopen(req, timeout=self.ml_timeout) as resp:
                    preds = json.loads(resp.read().decode())["predictions"]
                if len(preds) != len(chunk):
                    raise ValueError("prediction count mismatch")
                probs.extend(float(p["attack_probability"]) for p in preds)
                hub.sleep(0)
        except Exception as exc:
            if self.ml_status != "unavailable":
                self._event("ml_api_unavailable", error=str(exc))
            self.ml_status = "unavailable"
            self.logger.error("ML API unavailable (%s); continuing without Level-1 evidence", exc)
            return -1.0
        if self.ml_status != "ok":
            self._event("ml_api_ok")
        self.ml_status = "ok"
        conv_prob = {}
        for c, p in zip(convs, probs):
            for dr in c["direction_rows"]:
                conv_prob[(dr["ip_src"], int(dr["tp_src"]), dr["ip_dst"], int(dr["tp_dst"]), int(dr["ip_proto"]))] = p
        for r in candidates:
            r.ml_prob = conv_prob.get((r.src, r.key[1], r.dst, r.key[3], r.proto))
        return round((time.monotonic() - t0) * 1000.0, 2)

    # ------------------------------------------------------- human output
    def _source_score(self, feats):
        if self.engine is None or self.engine.source_scorer is None:
            return None
        try:
            return self.engine.source_scorer.score(feats)
        except Exception:
            return None

    def _update_last_window(self, ts, dst_feats, src_feats, decisions, drop_hits, missing):
        by_dst = {}
        dec_by_dst = {d.dst: d for d in decisions}
        for dst in set(dst_feats) | set(dec_by_dst):
            feats = dst_feats.get(dst, {})
            d = dec_by_dst.get(dst)
            srcs = []
            for (s, dd), v in src_feats.items():
                if dd != dst:
                    continue
                sc = self._source_score(v)
                srcs.append({"src": s, "pps": round(v.get("src_pps", 0.0), 1),
                             "share": round(v.get("src_share", 0.0), 3),
                             "flows": int(v.get("src_n_flows", 0)),
                             "ml_max_prob": round(v.get("src_ml_max_prob", 0.0), 4),
                             "source_score": None if sc is None else round(sc, 4),
                             "blocked": any(r.src == s and r.dst == dst for r in self.rules.rules())})
            srcs.sort(key=lambda x: -x["pps"])
            by_dst[dst] = {
                "features": {k: round(float(feats.get(k, 0.0)), 4) for k in SUMMARY_FEATURES} if feats else {},
                "score": d.score if d else 0.0,
                "threshold": getattr(self.engine.window_scorer, "threshold", 0.5) if self.engine else None,
                "state": d.state if d else NORMAL,
                "label": status_label(d.state if d else NORMAL),
                "attributed": d.attributed_sources if d else [],
                "evidence": dict(sorted((d.evidence if d else {}).items(), key=lambda kv: -abs(kv[1]))[:6]),
                "sources": srcs[:20],
                "dropped_pps": round(drop_hits.get(dst, 0.0), 1),
            }
        self.last_window = {"ts": round(ts, 3), "poll": self.poll_id, "missing_dpids": missing, "dst": by_dst}

    def _log_window(self, dst_feats, decisions):
        dec_by_dst = {d.dst: d for d in decisions}
        rows = []
        for dst, f in dst_feats.items():
            d = dec_by_dst.get(dst)
            state = d.state if d else NORMAL
            if state == NORMAL and f.get("pps", 0.0) < 20 and (d is None or d.score < 0.1):
                continue
            rows.append((f.get("pps", 0.0), dst, f, d, state))
        for _, dst, f, d, state in sorted(rows, key=lambda r: -r[0])[:6]:
            thr = getattr(self.engine.window_scorer, "threshold", 0.5) if self.engine else 0.5
            self.logger.info(
                "[poll %d] dst=%-10s %-18s score=%.3f (thr %.3f) sources=%d flows=%d pps=%.0f rate=%.2fMbps "
                "avg_pkt=%.0fB | flow-ML max_p=%.2f flagged=%.0f%%",
                self.poll_id, dst, status_label(state), d.score if d else 0.0, thr, int(f.get("n_sources", 0)),
                int(f.get("n_active_flows", 0)), f.get("pps", 0.0), f.get("bps", 0.0) / 1e6,
                f.get("avg_pkt_size", 0.0), f.get("ml_max_prob", 0.0), 100.0 * f.get("ml_flow_frac", 0.0))

    def _on_transition(self, d):
        info = self.last_window["dst"].get(d.dst, {})
        feats = info.get("features", {})
        self._event("state", dst=d.dst, previous=d.previous_state, state=d.state, label=status_label(d.state),
                    score=d.score, attributed=d.attributed_sources, features=feats, mode=self.mode)
        if d.state in (CONFIRMED, MITIGATING) and d.previous_state not in (CONFIRMED, MITIGATING):
            top = ", ".join(f"{k} {v:+.2f}" for k, v in list(info.get("evidence", {}).items())[:4])
            susp = ", ".join(f"{s['src']}({s['pps']:.0f}pps)" for s in info.get("sources", [])[:8])
            lines = [
                "=" * 78,
                "DDoS ALERT  victim=%s  ATTACK CONFIRMED  window score=%.3f (threshold %.3f)" % (
                    d.dst, d.score, info.get("threshold") or 0.0),
                "  sources=%d  active flows=%d  aggregate=%.0f pps / %.2f Mbps  avg pkt=%.0f B" % (
                    feats.get("n_sources", 0), feats.get("n_active_flows", 0), feats.get("pps", 0),
                    feats.get("bps", 0) / 1e6, feats.get("avg_pkt_size", 0)),
                "  protocol mix: UDP %.0f%%  TCP %.0f%%  ICMP %.0f%%" % (
                    100 * feats.get("udp_share", 0), 100 * feats.get("tcp_share", 0),
                    100 * feats.get("icmp_share", 0)),
                "  flow-level ML (CIC-DDoS2019 model): max attack prob=%.2f, %.0f%% of flows flagged" % (
                    feats.get("ml_max_prob", 0), 100 * feats.get("ml_flow_frac", 0)),
                "  strongest evidence: %s" % (top or "n/a"),
                "  top senders: %s" % (susp or "n/a"),
                "  mitigation mode: %s%s" % (self.mode, "" if self.mode == MITIGATION_ENABLED else
                                             "  (no OpenFlow rule will be installed)"),
                "=" * 78,
            ]
            for line in lines:
                self.logger.warning(line)
        elif d.state == NORMAL and d.previous_state != NORMAL:
            self.logger.warning("dst=%s back to NORMAL TRAFFIC", d.dst)

    # ----------------------------------------------------------- mitigation
    def _load_bindings(self):
        if self.port_binding or self.asp_file is None or not self.asp_file.exists():
            return
        try:
            st = json.loads(self.asp_file.read_text())
            for h in st["hosts"].values():
                sw, port = h["switch_port"].split("-eth")
                self.port_binding[(int(sw.lstrip("s")), int(port))] = h["ip"]
            self.logger.warning("Anti-spoofing: %d host ports bound to their IPs", len(self.port_binding))
        except Exception as exc:
            self.logger.error("Anti-spoofing: cannot read %s (%s)", self.asp_file, exc)

    def _anti_spoofing(self):
        if not self.asp_enabled:
            return
        self._load_bindings()
        ev, self.spoof_evidence = self.spoof_evidence, {}
        for (dpid, port, dst), n in sorted(ev.items()):
            if n < self.asp_min:
                continue
            label = "spoof@s%d-eth%d" % (dpid, port)
            key = (label, dst, 0)
            if key in self.rules:
                continue
            self._emit({"event": "spoofing", "dpid": dpid, "port": port, "dst": dst, "packets": n,
                        "bound_ip": self.port_binding.get((dpid, port))})
            self._event("spoofing_detected", switch="s%d" % dpid, port=port, dst=dst, spoofed_packet_ins=n,
                        bound_ip=self.port_binding.get((dpid, port)))
            self.logger.warning("SPOOFING: s%d port %d sent %d packets to %s with foreign source IPs",
                                dpid, port, n, dst)
            if self.mode != MITIGATION_ENABLED or dpid not in self.datapaths:
                continue
            dp = self.datapaths[dpid]
            parser, ofp = dp.ofproto_parser, dp.ofproto
            mit = self.cfg["mitigation"]
            cookie = self.rules.next_cookie()
            match = parser.OFPMatch(in_port=port, eth_type=0x0800, ipv4_dst=dst)
            dp.send_msg(parser.OFPFlowMod(datapath=dp, cookie=cookie, command=ofp.OFPFC_ADD,
                                          priority=int(mit["priority"]) + 5, match=match, instructions=[],
                                          hard_timeout=int(mit["hard_timeout_seconds"]),
                                          flags=ofp.OFPFF_SEND_FLOW_REM))
            self.counters["flow_mod"] += 1
            rule = DropRule(label, dst, 0, cookie, [dpid], time.time(), int(mit["hard_timeout_seconds"]),
                            int(mit["priority"]) + 5, "spoofed_source_port", 1.0)
            self.rules.add(rule)
            self._emit({"event": "mitigation", "action": "install", "src": label, "dst": dst, "proto": 0,
                        "dpids": [dpid], "cookie": cookie, "kind": "port_quarantine"})
            self._event("rule_installed", **rule.to_dict())
            self.logger.warning("MITIGATION INSTALLED: QUARANTINE s%d port %d -> %s (spoofed sources)",
                                dpid, port, dst)

    def _apply_actions(self, d, flows):
        mit = self.cfg["mitigation"]
        if "rollback" in d.actions:
            self._rollback(d.dst, reason="recovered")
        if "block" not in d.actions and "block_dry_run" not in d.actions:
            return
        dry = "block_dry_run" in d.actions
        installed = 0
        any_proto = mit.get("rule_scope", "src_dst_proto") == "src_dst"
        for src in d.attributed_sources:
            if src in mit["allowlist"]:
                continue
            if any_proto:   # one rule per (src, dst): switching protocol does not bypass it
                protos = [0]
            else:
                protos = sorted({r.proto for r in flows.values() if r.src == src and r.dst == d.dst})
            for proto in protos:
                key = (src, d.dst, proto)
                if key in self.rules or installed >= int(mit["max_rules_per_window"]):
                    continue
                dpid = self.host_location.get(src)
                targets = [dpid] if dpid in self.datapaths else sorted(self.datapaths)
                if dry:
                    if self.dry_ledger.first_time(key, time.time()):
                        self._emit({"event": "mitigation", "action": "would_block", "src": src, "dst": d.dst,
                                    "proto": proto, "dpids": targets, "score": d.score})
                        self._event("would_block", src=src, dst=d.dst, proto=proto, proto_name=proto_name(proto),
                                    switches=["s%d" % t for t in targets])
                        self.logger.warning("[DRY-RUN] would install DROP %s -> %s %s at %s (no rule installed)",
                                            src, d.dst, proto_name(proto), ["s%d" % t for t in targets])
                    continue
                self._install_drop(src, d.dst, proto, targets, d.score, reason="attributed_attacker")
                installed += 1

    def _install_drop(self, src, dst, proto, targets, score, reason):
        mit = self.cfg["mitigation"]
        cookie = self.rules.next_cookie()
        for t in targets:
            dp = self.datapaths[t]
            parser, ofp = dp.ofproto_parser, dp.ofproto
            if int(proto):
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src, ipv4_dst=dst, ip_proto=int(proto))
            else:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src, ipv4_dst=dst)
            # Empty instruction list = drop. Higher priority than forwarding (1).
            dp.send_msg(parser.OFPFlowMod(datapath=dp, cookie=cookie, command=ofp.OFPFC_ADD,
                                          priority=int(mit["priority"]), match=match, instructions=[],
                                          hard_timeout=int(mit["hard_timeout_seconds"]),
                                          flags=ofp.OFPFF_SEND_FLOW_REM))
            self.counters["flow_mod"] += 1
        rule = DropRule(src, dst, int(proto), cookie, list(targets), time.time(),
                        int(mit["hard_timeout_seconds"]), int(mit["priority"]), reason, float(score))
        self.rules.add(rule)
        self._emit({"event": "mitigation", "action": "install", "src": src, "dst": dst, "proto": proto,
                    "dpids": targets, "cookie": cookie, "score": score,
                    "hard_timeout": int(mit["hard_timeout_seconds"])})
        self._event("rule_installed", **rule.to_dict())
        self.logger.warning("MITIGATION INSTALLED: DROP %s -> %s %s at %s priority=%d hard_timeout=%ds cookie=%s",
                            src, dst, proto_name(proto), ["s%d" % t for t in targets], int(mit["priority"]),
                            int(mit["hard_timeout_seconds"]), format_cookie(cookie))

    def _delete_rule(self, rule, reason):
        for t in rule.dpids:
            dp = self.datapaths.get(t)
            if dp is None:
                continue
            parser, ofp = dp.ofproto_parser, dp.ofproto
            dp.send_msg(parser.OFPFlowMod(datapath=dp, cookie=rule.cookie, cookie_mask=0xFFFFFFFFFFFFFFFF,
                                          command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                                          out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                          match=parser.OFPMatch()))
            self.counters["flow_mod"] += 1
        self.rules.remove_key(rule.key)
        age = round(time.time() - rule.installed, 2)
        self._emit({"event": "mitigation", "action": "remove", "src": rule.src, "dst": rule.dst,
                    "proto": rule.proto, "reason": reason, "age_s": age})
        self._event("rule_removed", cookie=format_cookie(rule.cookie), src=rule.src, dst=rule.dst,
                    proto=rule.proto, proto_name=proto_name(rule.proto), reason=reason, age_s=age,
                    dropped_packets=rule.dropped_packets)
        self.logger.warning("MITIGATION REMOVED: DROP %s -> %s %s (%s, active %.1fs, %d packets dropped)",
                            rule.src, rule.dst, proto_name(rule.proto), reason, age, rule.dropped_packets)

    def _rollback(self, dst, reason):
        removed = 0
        for rule in self.rules.select(dst):
            self._delete_rule(rule, reason)
            removed += 1
        self.dry_ledger.clear(dst)
        return removed

    def _delete_all_tagged(self):
        """Belt and braces: delete every controller drop rule by cookie mask on every switch."""
        for dp in list(self.datapaths.values()):
            parser, ofp = dp.ofproto_parser, dp.ofproto
            dp.send_msg(parser.OFPFlowMod(datapath=dp, cookie=DROP_COOKIE_TAG, cookie_mask=DROP_COOKIE_MASK,
                                          command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                                          out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=parser.OFPMatch()))

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        if (msg.cookie & DROP_COOKIE_MASK) != DROP_COOKIE_TAG:
            return
        rule = self.rules.by_cookie(msg.cookie)
        if rule is None:
            return
        reason = {0: "idle_timeout", 1: "hard_timeout", 2: "deleted"}.get(int(msg.reason), str(msg.reason))
        if reason == "deleted":
            return  # our own delete; already logged
        self.rules.remove_key(rule.key)
        self._emit({"event": "mitigation", "action": "expired", "src": rule.src, "dst": rule.dst,
                    "proto": rule.proto, "reason": int(msg.reason)})
        self._event("rule_expired", cookie=format_cookie(rule.cookie), src=rule.src, dst=rule.dst,
                    proto=rule.proto, reason=reason, dropped_packets=int(msg.packet_count))
        self.logger.warning("MITIGATION EXPIRED: DROP %s -> %s %s (%s, %d packets dropped)", rule.src, rule.dst,
                            proto_name(rule.proto), reason, int(msg.packet_count))

    # ------------------------------------------------------------- REST ops
    def rest_status(self):
        states = {}
        if self.engine is not None:
            for dst, st in self.engine.states.items():
                states[dst] = {"state": st.state, "label": status_label(st.state), "since": round(st.since, 3)}
        return {
            "mode": self.mode, "detection_mode": self.cfg["detection"]["mode"],
            "switches": sorted(self.datapaths), "n_switches": len(self.datapaths),
            "poll": self.poll_id, "poll_interval": self.poll, "ml_api": self.ml_status,
            "n_rules": len(self.rules), "counters": dict(self.counters),
            "states": states, "window": self.last_window, "last_event_seq": self._event_seq,
            "kill_switch": self.kill_switch.exists(),
        }

    def rest_rules(self):
        now = time.time()
        return {"mode": self.mode, "n_rules": len(self.rules), "rules": [r.to_dict(now) for r in self.rules.rules()]}

    def rest_remove(self, cookie=None):
        if cookie is None:
            n = self._rollback(None, reason="operator_remove_all")
            self._delete_all_tagged()
            self._event("rules_cleared", removed=n)
            self.logger.warning("Operator removed ALL mitigation rules (%d)", n)
            return {"removed": n, "n_rules": len(self.rules)}
        rule = self.rules.by_cookie(cookie)
        if rule is None:
            return None
        self._delete_rule(rule, reason="operator_remove")
        return {"removed": 1, "rule": rule.to_dict(), "n_rules": len(self.rules)}

    def rest_set_mode(self, mode):
        mode = normalize_mode(mode)
        if mode == MITIGATION_ENABLED and self.cfg["detection"]["mode"] != "enforce":
            raise PermissionError("MITIGATION_ENABLED requires detection.mode: enforce in the controller config")
        old = self.mode
        enabled, dry = flags_from_mode(mode)
        self.cfg["mitigation"].update({"mode": mode, "enabled": enabled, "dry_run": dry})
        demoted = self.engine.set_mitigation(enabled, dry) if self.engine else []
        removed = 0
        if mode != MITIGATION_ENABLED and len(self.rules):
            removed = self._rollback(None, reason="mode_%s" % mode.lower())
        self.dry_ledger.clear()
        self.mode = mode
        self._event("mode", previous=old, mode=mode, removed_rules=removed, demoted=demoted)
        self.logger.warning("MODE CHANGE %s -> %s (removed %d rules, demoted %s)", old, mode, removed, demoted)
        return {"previous": old, "mode": mode, "removed_rules": removed}


class DdosRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(DdosRestController, self).__init__(req, link, data, **config)
        self.app = data[REST_INSTANCE]

    @staticmethod
    def _json(obj, status=200):
        return Response(status=status, content_type="application/json", charset="utf-8",
                        body=(json.dumps(obj, indent=1, default=str) + "\n").encode("utf-8"))

    @route("ddos", "/ddos/status", methods=["GET"])
    def status(self, req, **kwargs):
        return self._json(self.app.rest_status())

    @route("ddos", "/ddos/rules", methods=["GET"])
    def list_rules(self, req, **kwargs):
        return self._json(self.app.rest_rules())

    @route("ddos", "/ddos/rules", methods=["DELETE"])
    def delete_rules(self, req, **kwargs):
        return self._json(self.app.rest_remove(None))

    @route("ddos", "/ddos/rules/{cookie}", methods=["DELETE"])
    def delete_rule(self, req, cookie, **kwargs):
        try:
            out = self.app.rest_remove(parse_cookie(cookie))
        except ValueError:
            return self._json({"error": "bad cookie %r" % cookie}, 400)
        if out is None:
            return self._json({"error": "no active rule with cookie %s" % cookie}, 404)
        return self._json(out)

    @route("ddos", "/ddos/mode", methods=["GET"])
    def get_mode(self, req, **kwargs):
        return self._json({"mode": self.app.mode, "detection_mode": self.app.cfg["detection"]["mode"]})

    @route("ddos", "/ddos/mode", methods=["POST", "PUT"])
    def set_mode(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode("utf-8") or "{}") if req.body else {}
            mode = body.get("mode") or req.params.get("mode")
            return self._json(self.app.rest_set_mode(mode))
        except PermissionError as exc:
            return self._json({"error": str(exc)}, 403)
        except (ValueError, AttributeError) as exc:
            return self._json({"error": str(exc)}, 400)

    @route("ddos", "/ddos/events", methods=["GET"])
    def events(self, req, **kwargs):
        try:
            since = int(req.params.get("since", 0))
        except ValueError:
            since = 0
        return self._json({"last_seq": self.app._event_seq,
                           "events": [e for e in self.app.alert_log if e["seq"] > since]})
