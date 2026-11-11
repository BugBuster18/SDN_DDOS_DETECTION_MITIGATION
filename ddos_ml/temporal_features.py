"""Counter-delta tracking and destination-centric window features.

Pure Python (no NumPy/Pandas) so it can run inside the Ryu Python 3.9
environment as well as in offline replay/evaluation in the ML environment.

Why counter deltas
------------------
OpenFlow flow counters are cumulative over the lifetime of a flow entry, so
``byte_count / duration`` is a lifetime average, not the traffic rate in the
last polling interval. :class:`FlowCounterTracker` keeps the previous counters
for every (datapath, directed flow identity) and returns per-interval deltas.

Handled conditions
------------------
* new flow entries (installed during the interval)            -> status "new"
* first sight of an old entry (controller restart / missed polls) -> "no_baseline"
  (excluded from rate sums, because the interval delta is unknowable)
* counter decrease or duration decrease (entry re-installed / wrap) -> "reset"
* duplicate observations of the same entry in one poll          -> max kept
* entries that disappear (idle/hard timeout)                     -> expired
* switch disconnects                                             -> forget_datapath()
* missing statistics replies                                     -> state kept,
  no fake zero deltas; window coverage is reported
* the same directed flow seen on several switches of a path      -> the
  per-window delta is the maximum over datapaths (not the sum)
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

DirectedKey = Tuple[str, int, str, int, int, int]  # src, sport, dst, dport, proto, icmp_type


def _int(value, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        out = float(value)
        if math.isnan(out) or math.isinf(out):
            return default
        return out
    except (TypeError, ValueError):
        return default


def directed_key(row: dict) -> Optional[DirectedKey]:
    src = row.get("ip_src")
    dst = row.get("ip_dst")
    if not src or not dst:
        return None
    return (
        str(src), _int(row.get("tp_src")), str(dst), _int(row.get("tp_dst")),
        _int(row.get("ip_proto"), -1), _int(row.get("icmp_type"), -1),
    )


def row_duration(row: dict) -> float:
    return max(_float(row.get("duration_sec")) + _float(row.get("duration_nsec")) / 1e9, 0.0)


@dataclass
class FlowDelta:
    key: DirectedKey
    dpid: int
    status: str            # "ok" | "new" | "reset" | "no_baseline"
    delta_packets: int
    delta_bytes: int
    elapsed: float
    packets: int           # cumulative (lifetime) counters, for the flow-level ML
    bytes: int
    duration: float

    @property
    def usable(self) -> bool:
        return self.status != "no_baseline"


@dataclass
class _EntryState:
    packets: int
    bytes: int
    duration: float
    ts: float
    last_seen: float


class FlowCounterTracker:
    """Track cumulative OpenFlow counters and produce per-interval deltas."""

    def __init__(self, expire_after_seconds: float = 30.0, new_flow_slack_seconds: float = 1.0):
        self.expire_after = float(expire_after_seconds)
        self.slack = float(new_flow_slack_seconds)
        self._state: Dict[Tuple[int, DirectedKey], _EntryState] = {}
        self._last_poll_ts: Dict[int, float] = {}

    def forget_datapath(self, dpid: int) -> None:
        for k in [k for k in self._state if k[0] == dpid]:
            del self._state[k]
        self._last_poll_ts.pop(dpid, None)

    def __len__(self) -> int:
        return len(self._state)

    def update(self, dpid: int, rows: Iterable[dict], ts: float) -> List[FlowDelta]:
        """Process one complete flow-stats reply from one datapath."""
        dpid = _int(dpid, -1)
        prev_poll = self._last_poll_ts.get(dpid)
        since_prev_poll = (ts - prev_poll) if prev_poll is not None else None

        # De-duplicate identical entries in one reply (keep the largest counters).
        latest: Dict[DirectedKey, dict] = {}
        for row in rows:
            key = directed_key(row)
            if key is None:
                continue
            cur = latest.get(key)
            if cur is None or (_int(row.get("packet_count")), _int(row.get("byte_count"))) > (
                _int(cur.get("packet_count")), _int(cur.get("byte_count"))
            ):
                latest[key] = row

        out: List[FlowDelta] = []
        for key, row in latest.items():
            pk = max(_int(row.get("packet_count")), 0)
            by = max(_int(row.get("byte_count")), 0)
            dur = row_duration(row)
            sk = (dpid, key)
            prev = self._state.get(sk)
            if prev is not None:
                elapsed = max(ts - prev.ts, 1e-6)
                if pk < prev.packets or by < prev.bytes or dur + 0.5 < prev.duration:
                    # Entry was re-installed (timeout + new packet) or counter wrapped:
                    # everything counted now accumulated since re-installation.
                    status, dp, db, el = "reset", pk, by, max(min(dur, elapsed), 1e-6)
                else:
                    status, dp, db, el = "ok", pk - prev.packets, by - prev.bytes, elapsed
            else:
                window = since_prev_poll if since_prev_poll is not None else None
                if window is not None and dur <= window + self.slack:
                    status, dp, db, el = "new", pk, by, max(window, 1e-6)
                else:
                    status, dp, db, el = "no_baseline", 0, 0, max(window or dur, 1e-6)
            self._state[sk] = _EntryState(pk, by, dur, ts, ts)
            out.append(FlowDelta(key, dpid, status, dp, db, el, pk, by, dur))

        # Expire entries of this datapath that were not reported for a while.
        for sk in [k for k, v in self._state.items() if k[0] == dpid and ts - v.last_seen > self.expire_after]:
            del self._state[sk]
        self._last_poll_ts[dpid] = ts
        return out


# --------------------------------------------------------------------------
# Destination-centric window features
# --------------------------------------------------------------------------

WINDOW_FEATURES = [
    "n_sources", "n_active_flows", "n_new_flows", "new_flow_rate",
    "pps", "bps", "avg_pkt_size", "top_source_share", "source_entropy",
    "udp_share", "tcp_share", "icmp_share", "response_ratio",
    "log_pps_change", "packet_in_rate",
    "ml_flow_frac", "ml_pps_share", "ml_max_prob", "ml_mean_prob",
]

SOURCE_FEATURES = [
    "src_pps", "src_share", "src_n_flows", "src_new_flows", "src_pkts_per_flow",
    "src_ml_max_prob", "src_ml_mean_prob", "src_response_ratio", "src_log_rate_jump",
    "src_active_windows",
]


@dataclass
class FlowWindowRecord:
    """Per directed flow, merged across datapaths for one window."""
    key: DirectedKey
    delta_packets: int
    delta_bytes: int
    elapsed: float
    status: str
    packets: int
    bytes: int
    duration: float
    dpids: List[int] = field(default_factory=list)
    ml_prob: Optional[float] = None

    @property
    def src(self) -> str:
        return self.key[0]

    @property
    def dst(self) -> str:
        return self.key[2]

    @property
    def proto(self) -> int:
        return self.key[4]


def merge_path_observations(deltas: Iterable[FlowDelta]) -> Dict[DirectedKey, FlowWindowRecord]:
    """Collapse the same directed flow seen on several switches (max, not sum)."""
    merged: Dict[DirectedKey, FlowWindowRecord] = {}
    status_rank = {"no_baseline": 0, "ok": 1, "reset": 2, "new": 3}
    for d in deltas:
        rec = merged.get(d.key)
        if rec is None:
            merged[d.key] = FlowWindowRecord(d.key, d.delta_packets, d.delta_bytes, d.elapsed, d.status,
                                             d.packets, d.bytes, d.duration, [d.dpid])
            continue
        rec.dpids.append(d.dpid)
        if d.usable and (d.delta_packets, d.delta_bytes) > (rec.delta_packets, rec.delta_bytes):
            rec.delta_packets, rec.delta_bytes, rec.elapsed = d.delta_packets, d.delta_bytes, d.elapsed
        if (d.packets, d.bytes) > (rec.packets, rec.bytes):
            rec.packets, rec.bytes, rec.duration = d.packets, d.bytes, d.duration
        # A flow is "new" in this window if any on-path switch installed it now.
        if status_rank.get(d.status, 0) > status_rank.get(rec.status, 0):
            rec.status = d.status
    return merged


def _entropy_norm(values: List[float]) -> float:
    total = sum(values)
    n = len([v for v in values if v > 0])
    if total <= 0 or n <= 1:
        return 0.0
    h = -sum((v / total) * math.log(v / total) for v in values if v > 0)
    return h / math.log(n)


class DestinationWindowAnalyzer:
    """Compute destination-level and per-(source, destination) features per window."""

    def __init__(self, ewma_alpha: float = 0.3):
        self.alpha = float(ewma_alpha)
        self._dst_ewma_pps: Dict[str, float] = {}
        self._src_prev_pps: Dict[Tuple[str, str], float] = {}
        self._src_active: Dict[Tuple[str, str], int] = defaultdict(int)

    def compute(
        self,
        flows: Dict[DirectedKey, FlowWindowRecord],
        interval: float,
        packet_in_by_dst: Optional[Dict[str, int]] = None,
        ml_threshold: float = 0.5,
    ) -> Tuple[Dict[str, dict], Dict[Tuple[str, str], dict]]:
        interval = max(float(interval), 1e-3)
        packet_in_by_dst = packet_in_by_dst or {}
        by_dst: Dict[str, List[FlowWindowRecord]] = defaultdict(list)
        for rec in flows.values():
            by_dst[rec.dst].append(rec)

        # Reverse-direction bytes (dst -> src) for request/response detection.
        reverse_bytes: Dict[Tuple[str, str], int] = defaultdict(int)
        for rec in flows.values():
            if rec.status != "no_baseline":
                reverse_bytes[(rec.dst, rec.src)] += rec.delta_bytes  # keyed (victim, client) reversed below

        dst_feats: Dict[str, dict] = {}
        src_feats: Dict[Tuple[str, str], dict] = {}
        seen_pairs = set()
        for dst, recs in by_dst.items():
            usable = [r for r in recs if r.status != "no_baseline"]
            active = [r for r in usable if r.delta_packets > 0 or r.status in ("new", "reset")]
            pkts = sum(r.delta_packets for r in usable)
            byts = sum(r.delta_bytes for r in usable)
            new_flows = sum(1 for r in recs if r.status in ("new", "reset"))
            per_src_pk: Dict[str, int] = defaultdict(int)
            per_src_by: Dict[str, int] = defaultdict(int)
            per_src_flows: Dict[str, int] = defaultdict(int)
            per_src_new: Dict[str, int] = defaultdict(int)
            per_src_probs: Dict[str, List[float]] = defaultdict(list)
            proto_pk = {6: 0, 17: 0, 1: 0}
            for r in active:
                per_src_pk[r.src] += r.delta_packets
                per_src_by[r.src] += r.delta_bytes
                per_src_flows[r.src] += 1
                if r.status in ("new", "reset"):
                    per_src_new[r.src] += 1
                if r.ml_prob is not None:
                    per_src_probs[r.src].append(r.ml_prob)
                if r.proto in proto_pk:
                    proto_pk[r.proto] += r.delta_packets
            sources = sorted(per_src_flows)
            if not sources:
                continue
            fwd_bytes_total = max(byts, 1)
            rev_total = sum(reverse_bytes.get((s, dst), 0) for s in sources)
            probs = [r.ml_prob for r in active if r.ml_prob is not None]
            ml_pos = [r for r in active if r.ml_prob is not None and r.ml_prob >= ml_threshold]
            pps = pkts / interval
            prev = self._dst_ewma_pps.get(dst)
            log_change = math.log((pps + 1.0) / (prev + 1.0)) if prev is not None else 0.0
            self._dst_ewma_pps[dst] = pps if prev is None else self.alpha * pps + (1 - self.alpha) * prev
            share_vals = [float(per_src_pk[s]) for s in sources]
            dst_feats[dst] = {
                "n_sources": float(len(sources)),
                "n_active_flows": float(len(active)),
                "n_new_flows": float(new_flows),
                "new_flow_rate": new_flows / interval,
                "pps": pps,
                "bps": byts * 8.0 / interval,
                "avg_pkt_size": (byts / pkts) if pkts > 0 else 0.0,
                "top_source_share": (max(share_vals) / pkts) if pkts > 0 else 0.0,
                "source_entropy": _entropy_norm(share_vals),
                "udp_share": proto_pk[17] / pkts if pkts else 0.0,
                "tcp_share": proto_pk[6] / pkts if pkts else 0.0,
                "icmp_share": proto_pk[1] / pkts if pkts else 0.0,
                "response_ratio": min(rev_total / fwd_bytes_total, 10.0),
                "log_pps_change": log_change,
                "packet_in_rate": float(packet_in_by_dst.get(dst, 0)) / interval,
                "ml_flow_frac": (len(ml_pos) / len(probs)) if probs else 0.0,
                "ml_pps_share": (sum(r.delta_packets for r in ml_pos) / pkts) if pkts else 0.0,
                "ml_max_prob": max(probs) if probs else 0.0,
                "ml_mean_prob": (sum(probs) / len(probs)) if probs else 0.0,
            }
            for s in sources:
                pair = (s, dst)
                seen_pairs.add(pair)
                s_pps = per_src_pk[s] / interval
                prev_s = self._src_prev_pps.get(pair, 0.0)
                self._src_active[pair] += 1
                sp = per_src_probs.get(s, [])
                src_feats[pair] = {
                    "src_pps": s_pps,
                    "src_share": per_src_pk[s] / pkts if pkts else 0.0,
                    "src_n_flows": float(per_src_flows[s]),
                    "src_new_flows": float(per_src_new[s]),
                    "src_pkts_per_flow": per_src_pk[s] / max(per_src_flows[s], 1),
                    "src_ml_max_prob": max(sp) if sp else 0.0,
                    "src_ml_mean_prob": (sum(sp) / len(sp)) if sp else 0.0,
                    "src_response_ratio": min(reverse_bytes.get((s, dst), 0) / max(per_src_by[s], 1), 10.0),
                    "src_log_rate_jump": math.log((s_pps + 1.0) / (prev_s + 1.0)),
                    "src_active_windows": float(self._src_active[pair]),
                }
                self._src_prev_pps[pair] = s_pps
        # Pairs that went silent: reset their history.
        for pair in [p for p in self._src_prev_pps if p not in seen_pairs]:
            self._src_prev_pps[pair] = 0.0
            self._src_active.pop(pair, None)
        return dst_feats, src_feats
