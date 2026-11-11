"""OpenFlow-to-CICFlowMeter feature alignment helpers.

The seven-feature CICFlowMeter model is trained on bidirectional flows. OpenFlow
1.3 exposes directional match counters, often at more than one switch along a
path. This module combines the two directions and selects one datapath's view
per bidirectional 5-tuple before calling the existing live feature adapter.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any


def _port(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _duration(row: dict) -> float:
    try:
        sec = float(row.get("duration_sec", 0) or 0)
        nsec = float(row.get("duration_nsec", 0) or 0)
        value = sec + nsec / 1_000_000_000.0
        return max(value, 0.0)
    except (TypeError, ValueError):
        return 0.0


def _counter(row: dict, key: str) -> int:
    try:
        return max(int(row.get(key, 0) or 0), 0)
    except (TypeError, ValueError):
        return 0


def _conversation_key(row: dict) -> tuple:
    """Return a direction-independent IPv4 5-tuple key."""
    src = (str(row.get("ip_src") or ""), _port(row.get("tp_src")))
    dst = (str(row.get("ip_dst") or ""), _port(row.get("tp_dst")))
    endpoints = tuple(sorted((src, dst)))
    try:
        proto = int(row.get("ip_proto", -1))
    except (TypeError, ValueError):
        proto = -1
    return proto, endpoints[0], endpoints[1]


def _directed_key(row: dict) -> tuple:
    return (
        str(row.get("ip_src") or ""),
        _port(row.get("tp_src")),
        str(row.get("ip_dst") or ""),
        _port(row.get("tp_dst")),
    )


def aggregate_bidirectional_rows(flow_rows: list[dict]) -> list[dict]:
    """Combine forward/reverse counters and de-duplicate the same flow at switches.

    The same 5-tuple can be visible at multiple switches in a multi-hop Mininet
    topology. We first build candidates per conversation and datapath, retain
    only the datapath view with the greatest packet count (then bytes), and
    combine distinct directions from that datapath. This avoids multiplying
    counters simply because a flow traverses several switches.

    Rows without IPv4 endpoints are ignored because the controller's current
    model is trained on IPv4 CICFlowMeter flows.
    """
    by_conversation: dict[tuple, dict[int, dict[tuple, dict]]] = defaultdict(
        lambda: defaultdict(dict)
    )

    for row in flow_rows:
        if not row.get("ip_src") or not row.get("ip_dst"):
            continue
        conversation = _conversation_key(row)
        try:
            dpid = int(row.get("datapath_id", -1))
        except (TypeError, ValueError):
            dpid = -1
        direction = _directed_key(row)
        existing = by_conversation[conversation][dpid].get(direction)
        score = (_counter(row, "packet_count"), _counter(row, "byte_count"), _duration(row))
        if existing is None:
            by_conversation[conversation][dpid][direction] = dict(row)
        else:
            old_score = (
                _counter(existing, "packet_count"),
                _counter(existing, "byte_count"),
                _duration(existing),
            )
            if score > old_score:
                by_conversation[conversation][dpid][direction] = dict(row)

    aggregated: list[dict] = []
    for _conversation, per_datapath in by_conversation.items():
        # A conversation observed on several switches is counted only once.
        selected_dpid, directions = max(
            per_datapath.items(),
            key=lambda item: (
                sum(_counter(r, "packet_count") for r in item[1].values()),
                sum(_counter(r, "byte_count") for r in item[1].values()),
                len(item[1]),
            ),
        )
        direction_rows = list(directions.values())
        representative = dict(
            max(
                direction_rows,
                key=lambda r: (
                    _counter(r, "packet_count"),
                    _counter(r, "byte_count"),
                ),
            )
        )
        total_packets = sum(_counter(r, "packet_count") for r in direction_rows)
        total_bytes = sum(_counter(r, "byte_count") for r in direction_rows)
        duration = max((_duration(r) for r in direction_rows), default=0.0)
        duration_sec = int(duration)
        duration_nsec = int(round((duration - duration_sec) * 1_000_000_000))
        if duration_nsec >= 1_000_000_000:
            duration_sec += 1
            duration_nsec -= 1_000_000_000

        representative.update(
            {
                "datapath_id": selected_dpid,
                "packet_count": total_packets,
                "byte_count": total_bytes,
                "duration_sec": duration_sec,
                "duration_nsec": duration_nsec,
                # Kept for future exact-direction mitigation; current mitigation
                # remains disabled by default and uses representative match_fields.
                "direction_rows": direction_rows,
            }
        )
        aggregated.append(representative)

    return aggregated
