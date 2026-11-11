"""Mitigation modes, operator-facing status labels and the drop-rule table.

Pure Python (no Ryu, no NumPy) so it runs inside the Python 3.9 Ryu
environment and is unit-testable from the Python 3.12 ML environment.

Mitigation modes
----------------
DETECTION_ONLY      detect + alert, never touch the data plane (DEFAULT)
DRY_RUN             detect + log the exact rules that WOULD be installed
MITIGATION_ENABLED  install real, scoped OpenFlow drop rules (lab only)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

DETECTION_ONLY = "DETECTION_ONLY"
DRY_RUN = "DRY_RUN"
MITIGATION_ENABLED = "MITIGATION_ENABLED"
MODES = (DETECTION_ONLY, DRY_RUN, MITIGATION_ENABLED)

# Cookie layout of controller-installed drop rules: top 16 bits tag, low bits sequence.
DROP_COOKIE_TAG = 0xDD05 << 48
DROP_COOKIE_MASK = 0xFFFF << 48

# Destination state -> what the operator sees.
STATUS_LABELS = {
    "NORMAL": "NORMAL TRAFFIC",
    "SUSPECTED": "SUSPICIOUS TRAFFIC",
    "CONFIRMED": "ATTACK CONFIRMED",
    "MITIGATING": "MITIGATION ACTIVE",
    "RECOVERING": "RECOVERING",
}

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def status_label(state: str) -> str:
    return STATUS_LABELS.get(state, state)


def proto_name(proto) -> str:
    try:
        return PROTO_NAMES.get(int(proto), str(proto))
    except (TypeError, ValueError):
        return str(proto)


def normalize_mode(value) -> str:
    """Accept common spellings ('mitigation_enabled', 'enforce', 'dry-run', ...)."""
    if value is None:
        raise ValueError("mode is required")
    v = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "DETECT": DETECTION_ONLY, "DETECTION": DETECTION_ONLY, "DETECT_ONLY": DETECTION_ONLY,
        "OFF": DETECTION_ONLY, "DISABLED": DETECTION_ONLY, "OBSERVATION": DETECTION_ONLY,
        "DRYRUN": DRY_RUN,
        "ENFORCE": MITIGATION_ENABLED, "MITIGATE": MITIGATION_ENABLED, "ENABLED": MITIGATION_ENABLED,
        "ON": MITIGATION_ENABLED, "MITIGATION": MITIGATION_ENABLED,
    }
    v = aliases.get(v, v)
    if v not in MODES:
        raise ValueError(f"unknown mitigation mode {value!r}; expected one of {', '.join(MODES)}")
    return v


def mode_from_flags(enabled: bool, dry_run: bool) -> str:
    if not enabled:
        return DETECTION_ONLY
    return DRY_RUN if dry_run else MITIGATION_ENABLED


def flags_from_mode(mode: str) -> Tuple[bool, bool]:
    """mode -> (mitigation_enabled, dry_run) as used by the DecisionEngine."""
    mode = normalize_mode(mode)
    return mode != DETECTION_ONLY, mode == DRY_RUN


def format_cookie(cookie: int) -> str:
    return f"0x{int(cookie):016x}"


def parse_cookie(text) -> int:
    s = str(text).strip().lower()
    return int(s, 16) if s.startswith("0x") or any(c in "abcdef" for c in s) else int(s)


@dataclass
class DropRule:
    src: str
    dst: str
    proto: int
    cookie: int
    dpids: List[int]
    installed: float
    hard_timeout: int
    priority: int
    reason: str = ""
    score: float = 0.0
    dropped_packets: int = 0
    dropped_pps: float = 0.0

    @property
    def key(self) -> Tuple[str, str, int]:
        return (self.src, self.dst, self.proto)

    def to_dict(self, now: Optional[float] = None) -> dict:
        now = time.time() if now is None else now
        return {
            "cookie": format_cookie(self.cookie), "src": self.src, "dst": self.dst,
            "proto": self.proto, "proto_name": proto_name(self.proto), "dpids": list(self.dpids),
            "switches": [f"s{d}" for d in self.dpids], "priority": self.priority,
            "hard_timeout": self.hard_timeout, "installed": round(self.installed, 3),
            "age_s": round(now - self.installed, 1), "reason": self.reason, "score": round(self.score, 4),
            "dropped_packets": self.dropped_packets, "dropped_pps": round(self.dropped_pps, 1),
            "match": f"eth_type=0x0800,ipv4_src={self.src},ipv4_dst={self.dst},ip_proto={self.proto}",
            "action": "drop",
        }


class DropRuleTable:
    """Bookkeeping for installed drop rules, keyed by (src, dst, proto) and cookie.

    The controller sends the OpenFlow messages; this class only decides cookies,
    remembers what is installed, and tracks drop counters reported by switches.
    """

    def __init__(self, start_seq: int = 1):
        self._seq = int(start_seq)
        self._rules: Dict[Tuple[str, str, int], DropRule] = {}
        self._prev_counts: Dict[int, int] = {}

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, key) -> bool:
        return key in self._rules

    def next_cookie(self) -> int:
        cookie = DROP_COOKIE_TAG | (self._seq & ((1 << 48) - 1))
        self._seq += 1
        return cookie

    @staticmethod
    def is_drop_cookie(cookie: int) -> bool:
        return (int(cookie) & DROP_COOKIE_MASK) == DROP_COOKIE_TAG

    def add(self, rule: DropRule) -> None:
        if rule.key in self._rules:
            raise KeyError(f"rule for {rule.key} already installed")
        self._rules[rule.key] = rule

    def get(self, key) -> Optional[DropRule]:
        return self._rules.get(key)

    def by_cookie(self, cookie: int) -> Optional[DropRule]:
        for r in self._rules.values():
            if r.cookie == int(cookie):
                return r
        return None

    def remove_key(self, key) -> Optional[DropRule]:
        rule = self._rules.pop(key, None)
        if rule is not None:
            self._prev_counts.pop(rule.cookie, None)
        return rule

    def remove_cookie(self, cookie: int) -> Optional[DropRule]:
        rule = self.by_cookie(cookie)
        return self.remove_key(rule.key) if rule else None

    def select(self, dst: Optional[str] = None) -> List[DropRule]:
        return [r for r in self._rules.values() if dst is None or r.dst == dst]

    def rules(self) -> List[DropRule]:
        return sorted(self._rules.values(), key=lambda r: r.cookie)

    def update_counters(self, drops, interval: float) -> Dict[str, float]:
        """drops: iterable of (cookie, packet_count, ipv4_dst) from flow-stats replies.

        A rule installed on several switches reports several entries; the max
        is used (the same packets are not dropped twice). Returns dropped pps
        per destination for the decision engine.
        """
        interval = max(float(interval), 1e-3)
        per_cookie: Dict[int, Tuple[int, Optional[str]]] = {}
        for cookie, pkts, dst in drops:
            c = int(cookie)
            prev = per_cookie.get(c)
            if prev is None or int(pkts) > prev[0]:
                per_cookie[c] = (int(pkts), dst)
        rates: Dict[str, float] = {}
        for cookie, (pkts, dst) in per_cookie.items():
            rule = self.by_cookie(cookie)
            prev = self._prev_counts.get(cookie)
            rate = 0.0
            if prev is not None and pkts >= prev:
                rate = (pkts - prev) / interval
                if dst:
                    rates[dst] = rates.get(dst, 0.0) + rate
            self._prev_counts[cookie] = pkts
            if rule is not None:
                rule.dropped_packets = pkts
                rule.dropped_pps = rate
        return rates


@dataclass
class DryRunLedger:
    """Remembers which would-block rules were already reported, so a dry run
    logs each (src, dst, proto) once per attack episode instead of every window."""
    seen: Dict[Tuple[str, str, int], float] = field(default_factory=dict)

    def first_time(self, key, ts: float) -> bool:
        if key in self.seen:
            return False
        self.seen[key] = ts
        return True

    def clear(self, dst: Optional[str] = None) -> None:
        for k in [k for k in self.seen if dst is None or k[1] == dst]:
            del self.seen[k]
