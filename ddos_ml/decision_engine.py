"""Transparent decision policy: window scoring, source attribution, state machine.

Pure Python so it runs inside Ryu. Models are linear (logistic) scorers stored
as JSON: every decision can be explained as a sum of per-feature contributions,
which are logged as alert evidence.

States per destination::

    NORMAL -> SUSPECTED -> CONFIRMED -> MITIGATING -> RECOVERING -> NORMAL

* SUSPECTED: window score >= threshold once.
* CONFIRMED: >= k of the last n windows over threshold (k-of-n confirmation).
* MITIGATING: entered only when mitigation is enabled (or dry_run for logging).
* RECOVERING: attack evidence (scores AND drop-rule hit rate) below threshold
  for `recovery_windows` consecutive windows -> rules are rolled back and the
  destination is watched for `cooldown_windows`; renewed evidence returns it
  straight to CONFIRMED.
"""
from __future__ import annotations

import json
import math
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Sequence, Tuple

NORMAL, SUSPECTED, CONFIRMED, MITIGATING, RECOVERING = (
    "NORMAL", "SUSPECTED", "CONFIRMED", "MITIGATING", "RECOVERING")


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


# Features with heavy tails are log1p-transformed before standardisation.
LOG_FEATURES = {
    "n_sources", "n_active_flows", "n_new_flows", "new_flow_rate", "pps", "bps",
    "avg_pkt_size", "packet_in_rate", "src_pps", "src_n_flows", "src_new_flows",
    "src_pkts_per_flow", "src_active_windows",
}


def transform(name: str, value: float) -> float:
    v = float(value or 0.0)
    if name in LOG_FEATURES:
        return math.log1p(max(v, 0.0))
    return v


@dataclass
class LinearScorer:
    """Logistic model on (transformed, standardised) features."""
    features: List[str]
    coef: List[float]
    intercept: float
    mean: List[float]
    scale: List[float]
    threshold: float = 0.5
    name: str = "linear"

    @classmethod
    def from_dict(cls, d: dict) -> "LinearScorer":
        return cls(list(d["features"]), [float(x) for x in d["coef"]], float(d["intercept"]),
                   [float(x) for x in d["mean"]], [float(x) for x in d["scale"]],
                   float(d.get("threshold", 0.5)), str(d.get("name", "linear")))

    @classmethod
    def load(cls, path: str | Path) -> "LinearScorer":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def contributions(self, feats: dict) -> Dict[str, float]:
        out = {}
        for f, c, m, s in zip(self.features, self.coef, self.mean, self.scale):
            z = (transform(f, feats.get(f, 0.0)) - m) / (s if s > 0 else 1.0)
            out[f] = c * z
        return out

    def score(self, feats: dict) -> float:
        return _sigmoid(self.intercept + sum(self.contributions(feats).values()))


@dataclass
class RuleScorer:
    """Non-ML statistical baseline: thresholds on aggregate rate and sources."""
    min_pps: float
    min_sources: float = 1.0
    min_new_flow_rate: Optional[float] = None
    name: str = "rule"
    threshold: float = 0.5

    def score(self, feats: dict) -> float:
        rate_ok = feats.get("pps", 0.0) >= self.min_pps
        if self.min_new_flow_rate is not None:
            rate_ok = rate_ok or feats.get("new_flow_rate", 0.0) >= self.min_new_flow_rate
        return 1.0 if rate_ok and feats.get("n_sources", 0.0) >= self.min_sources else 0.0

    def contributions(self, feats: dict) -> Dict[str, float]:
        return {"pps": feats.get("pps", 0.0), "n_sources": feats.get("n_sources", 0.0),
                "new_flow_rate": feats.get("new_flow_rate", 0.0)}


@dataclass
class DestinationState:
    state: str = NORMAL
    history: Deque[bool] = field(default_factory=lambda: deque(maxlen=8))
    quiet_windows: int = 0
    cooldown_left: int = 0
    since: float = 0.0
    attributed: Dict[str, float] = field(default_factory=dict)  # source -> last score


@dataclass
class Decision:
    dst: str
    ts: float
    score: float
    over: bool
    state: str
    previous_state: str
    attributed_sources: List[str]
    evidence: Dict[str, float]
    actions: List[str]


class DecisionEngine:
    def __init__(
        self,
        window_scorer,
        source_scorer: Optional[LinearScorer] = None,
        *,
        confirm_k: int = 2,
        confirm_n: int = 3,
        recovery_windows: int = 3,
        cooldown_windows: int = 3,
        mitigation_enabled: bool = False,
        dry_run: bool = True,
        min_source_pps: float = 0.0,
        allowlist: Sequence[str] = (),
        max_sources_per_destination: int = 32,
        drop_rate_threshold_pps: float = 50.0,
        source_min_attribute_pps: Optional[float] = None,
        rate_requires_corroboration: bool = False,
        corroboration_ml_prob: float = 0.5,
        corroboration_new_flows: float = 10.0,
        min_source_pps_strict: bool = False,
        fast_confirm_score: Optional[float] = None,
        offender_memory_seconds: float = 0.0,
        recovery_backoff: bool = False,
        max_backoff_exponent: int = 3,
        baseline_factor: Optional[float] = None,
        new_source_corroborates: bool = False,
        source_confirm_windows: int = 1,
    ):
        self.window_scorer = window_scorer
        self.source_scorer = source_scorer
        self.k = int(confirm_k)
        self.n = int(confirm_n)
        if not 1 <= self.k <= self.n:
            raise ValueError("Need 1 <= confirm_k <= confirm_n")
        self.recovery_windows = int(recovery_windows)
        self.cooldown_windows = int(cooldown_windows)
        self.mitigation_enabled = bool(mitigation_enabled)
        self.dry_run = bool(dry_run)
        self.min_source_pps = float(min_source_pps)
        # Strict: the per-source rate floor applies even to sources that open new flows (e.g. a
        # DNS-like client using a new port per query). Non-strict keeps the original behaviour.
        self.min_source_pps_strict = bool(min_source_pps_strict)
        self.allowlist = set(allowlist)
        self.max_sources = int(max_sources_per_destination)
        self.drop_rate_threshold = float(drop_rate_threshold_pps)
        # Rate-based attribution fallback: at a confirmed victim, a source whose
        # interval rate exceeds this is attributed even if the ML source score is
        # marginal. None disables it (ML score only). This is an explainable,
        # conservative safety net so a clear flood is never left unattributed.
        self.source_min_attribute_pps = (
            float(source_min_attribute_pps) if source_min_attribute_pps is not None else None)
        # A high rate alone is not evidence of maliciousness (a legitimate bulk transfer is also
        # fast). When enabled, the rate fallback additionally needs one independent per-source
        # indicator: the flow-level ML flags this source's flows, OR the source churns many new
        # flows per window (random-port / SYN-flood signature).
        self.rate_requires_corroboration = bool(rate_requires_corroboration)
        self.corroboration_ml_prob = float(corroboration_ml_prob)
        self.corroboration_new_flows = float(corroboration_new_flows)
        # Latency: a single window whose score is at least this is confirmed at once
        # (k-of-n still applies to scores between threshold and this value). None = off.
        self.fast_confirm_score = None if fast_confirm_score is None else float(fast_confirm_score)
        # Re-attack / pulsing: sources blocked at a destination are remembered for this long.
        # If one of them reappears while the destination is over threshold, the destination is
        # confirmed in that window (no k-of-n wait). 0 disables.
        self.offender_memory = float(offender_memory_seconds)
        # Each further attack episode on a destination doubles the quiet windows needed
        # before its rules are removed (capped at 2**max_backoff_exponent).
        self.recovery_backoff = bool(recovery_backoff)
        self.max_backoff_exponent = int(max_backoff_exponent)
        self.offenders: Dict[str, Dict[str, float]] = {}
        self.episodes: Dict[str, int] = {}
        # Baseline-aware attribution: per (source, destination) EWMA of the rate, learned ONLY in
        # windows where the destination is NORMAL and under threshold. At a confirmed victim, a
        # source that already sent at a similar rate before the attack (a video stream, a bulk
        # transfer) is attributed only if its rate rose by at least this factor. None = off.
        self.baseline_factor = None if baseline_factor is None else float(baseline_factor)
        self.src_baseline: Dict[Tuple[str, str], float] = {}
        # A source never seen sending to d in normal windows that appears at >= the rate threshold
        # during a confirmed attack counts as corroborated (ICMP / fixed-port floods give no flow
        # churn and the flow model does not flag ICMP). Known steady clients are excluded.
        self.new_source_corroborates = bool(new_source_corroborates)
        self.source_confirm_windows = max(int(source_confirm_windows), 1)
        self.src_hits: Dict[Tuple[str, str], int] = {}
        self.states: Dict[str, DestinationState] = {}

    def _learn_baseline(self, dst: str, src_feats: Dict[Tuple[str, str], dict]) -> None:
        for (s, d), f in src_feats.items():
            if d == dst:
                prev = self.src_baseline.get((s, d))
                v = float(f.get("src_pps", 0.0))
                # peak-hold with slow decay (half-life ~23 windows): a stall caused by congestion
                # does not erase what the source normally sends
                self.src_baseline[(s, d)] = v if prev is None else max(v, 0.97 * prev)

    def above_baseline(self, src: str, dst: str, feats: dict) -> bool:
        if self.baseline_factor is None:
            return True
        base = self.src_baseline.get((src, dst), 0.0)
        return base <= 0.0 or feats.get("src_pps", 0.0) >= self.baseline_factor * base

    def repeat_offenders(self, dst: str, src_feats: Dict[Tuple[str, str], dict], ts: float) -> List[str]:
        if self.offender_memory <= 0:
            return []
        known = self.offenders.get(dst, {})
        return sorted(s for (s, d), f in src_feats.items()
                      if d == dst and s in known and ts - known[s] <= self.offender_memory
                      and f.get("src_pps", 0.0) >= self.min_source_pps)

    def recovery_needed(self, dst: str) -> int:
        if not self.recovery_backoff:
            return self.recovery_windows
        e = max(self.episodes.get(dst, 1) - 1, 0)
        return self.recovery_windows * (2 ** min(e, self.max_backoff_exponent))

    def _rate_corroborated(self, feats: dict) -> bool:
        if not self.rate_requires_corroboration:
            return True
        return (feats.get("src_ml_max_prob", 0.0) >= self.corroboration_ml_prob
                or feats.get("src_new_flows", 0.0) >= self.corroboration_new_flows)

    # ---------------------------------------------------------------- sources
    def attribute_sources(self, dst: str, src_feats: Dict[Tuple[str, str], dict]) -> Dict[str, float]:
        scored = {}
        for (src, d), feats in src_feats.items():
            if d != dst or src in self.allowlist:
                continue
            if feats.get("src_pps", 0.0) < self.min_source_pps and (
                    self.min_source_pps_strict or feats.get("src_new_flows", 0.0) < 1):
                continue  # not a material contributor to the load on this destination
            if not self.above_baseline(src, dst, feats):
                continue  # was already sending like this before the attack: not an attacker
            if self.source_scorer is None:
                s = 1.0 if feats.get("src_share", 0.0) >= 0.5 / max(len(src_feats), 1) else 0.0
                thr = 0.5
            else:
                s = self.source_scorer.score(feats)
                thr = self.source_scorer.threshold
            new_heavy = (self.baseline_factor is not None and self.new_source_corroborates
                         and (src, dst) not in self.src_baseline)
            rate_hit = (self.source_min_attribute_pps is not None
                        and feats.get("src_pps", 0.0) >= self.source_min_attribute_pps
                        and (self._rate_corroborated(feats) or new_heavy))
            if s >= thr or rate_hit:
                scored[src] = max(s, 1.0 if rate_hit else s)
        if self.source_confirm_windows > 1:
            # Persistence: a source must qualify in consecutive windows (counter artefacts and
            # short bursts of legitimate senders last one window; floods do not). Known repeat
            # offenders at this destination are exempt (re-blocked at once).
            known = self.offenders.get(dst, {})
            for (s_, d_) in [k for k in self.src_hits if k[1] == dst and k[0] not in scored]:
                del self.src_hits[(s_, d_)]
            confirmed = {}
            for src, sc in scored.items():
                self.src_hits[(src, dst)] = self.src_hits.get((src, dst), 0) + 1
                if self.src_hits[(src, dst)] >= self.source_confirm_windows or src in known:
                    confirmed[src] = sc
            scored = confirmed
        top = sorted(scored.items(), key=lambda kv: -kv[1])[: self.max_sources]
        return dict(top)

    # ------------------------------------------------------------------ step
    def step(
        self,
        ts: float,
        dst_feats: Dict[str, dict],
        src_feats: Dict[Tuple[str, str], dict],
        drop_hits_pps: Optional[Dict[str, float]] = None,
    ) -> List[Decision]:
        """Advance every destination by one window. Returns decisions for
        destinations that were scored or are not NORMAL."""
        drop_hits_pps = drop_hits_pps or {}
        decisions: List[Decision] = []
        for dst in set(dst_feats) | {d for d, s in self.states.items() if s.state != NORMAL}:
            feats = dst_feats.get(dst, {})
            st = self.states.setdefault(dst, DestinationState(since=ts))
            score = self.window_scorer.score(feats) if feats else 0.0
            thr = getattr(self.window_scorer, "threshold", 0.5)
            dropped = drop_hits_pps.get(dst, 0.0)
            over = score >= thr or (st.state == MITIGATING and dropped >= self.drop_rate_threshold)
            st.history.append(over)
            recent = list(st.history)[-self.n:]
            prev_state = st.state
            actions: List[str] = []
            attributed: Dict[str, float] = {}

            fast = self.fast_confirm_score is not None and score >= self.fast_confirm_score
            repeat = self.repeat_offenders(dst, src_feats, ts) if over and st.state not in (
                CONFIRMED, MITIGATING) else []
            if dropped >= self.drop_rate_threshold and dst in self.offenders:
                for s in self.offenders[dst]:  # still sending into the drop rule: keep remembering
                    self.offenders[dst][s] = ts
            if self.baseline_factor is not None and st.state == NORMAL and not over and feats:
                self._learn_baseline(dst, src_feats)
            if st.state in (NORMAL, SUSPECTED):
                if sum(recent) >= self.k or (over and (fast or repeat)):
                    st.state = CONFIRMED
                elif over:
                    st.state = SUSPECTED
                else:
                    st.state = NORMAL
            elif st.state == RECOVERING:
                if over:
                    st.state = CONFIRMED  # renewed evidence during cooldown
                else:
                    st.cooldown_left -= 1
                    if st.cooldown_left <= 0:
                        st.state = NORMAL
                        st.history.clear()
            elif st.state in (CONFIRMED, MITIGATING):
                st.quiet_windows = 0 if over else st.quiet_windows + 1
                if st.quiet_windows >= self.recovery_needed(dst):
                    if st.state == MITIGATING or st.attributed:
                        actions.append("rollback")
                    st.state = RECOVERING
                    st.cooldown_left = self.cooldown_windows
                    st.quiet_windows = 0
                    st.attributed = {}

            if st.state in (CONFIRMED, MITIGATING) and over and feats:
                attributed = self.attribute_sources(dst, src_feats)
                if attributed:
                    st.attributed.update(attributed)
                    if self.mitigation_enabled:
                        actions.append("block" if not self.dry_run else "block_dry_run")
                        if not self.dry_run:
                            if prev_state != MITIGATING:
                                self.episodes[dst] = self.episodes.get(dst, 0) + 1
                            st.state = MITIGATING
                        mem = self.offenders.setdefault(dst, {})
                        for s in attributed:
                            mem[s] = ts
            if st.state != prev_state:
                st.since = ts
            evidence = {}
            if feats:
                try:
                    evidence = {k: round(v, 4) for k, v in self.window_scorer.contributions(feats).items()}
                except Exception:  # pragma: no cover - evidence must never break detection
                    evidence = {}
            if feats or st.state != NORMAL or prev_state != NORMAL:
                decisions.append(Decision(dst, ts, round(score, 4), over, st.state, prev_state,
                                          sorted(attributed), evidence, actions))
        return decisions

    # ------------------------------------------------------------- runtime mode
    def set_mitigation(self, enabled: bool, dry_run: bool) -> List[str]:
        """Change the mitigation mode at runtime.

        When real blocking is switched off, destinations in MITIGATING are
        demoted to CONFIRMED (the attack evidence is unchanged, but nothing is
        being enforced any more). Returns the demoted destinations.
        """
        self.mitigation_enabled = bool(enabled)
        self.dry_run = bool(dry_run)
        demoted = []
        if not self.mitigation_enabled or self.dry_run:
            for dst, st in self.states.items():
                if st.state == MITIGATING:
                    st.state = CONFIRMED
                    demoted.append(dst)
        return demoted

    @classmethod
    def from_config(cls, cfg: dict, base_dir: Path) -> "DecisionEngine":
        det = cfg.get("detection", {})
        mit = cfg.get("mitigation", {})
        method = det.get("method", "hybrid")
        if method == "rule":
            r = det.get("rule", {})
            scorer = RuleScorer(float(r.get("min_pps", 1e9)), float(r.get("min_sources", 1)),
                                r.get("min_new_flow_rate"))
        else:
            scorer = LinearScorer.load(base_dir / det["window_model"])
        src_scorer = LinearScorer.load(base_dir / det["source_model"]) if det.get("source_model") else None
        return cls(
            scorer, src_scorer,
            confirm_k=det.get("confirm_k", 2), confirm_n=det.get("confirm_n", 3),
            recovery_windows=det.get("recovery_windows", 3), cooldown_windows=det.get("cooldown_windows", 3),
            mitigation_enabled=bool(mit.get("enabled", False)), dry_run=bool(mit.get("dry_run", True)),
            min_source_pps=det.get("min_source_pps", 0.0), allowlist=mit.get("allowlist", []),
            max_sources_per_destination=mit.get("max_sources_per_destination", 32),
            drop_rate_threshold_pps=mit.get("drop_rate_threshold_pps", 50.0),
            source_min_attribute_pps=det.get("source_min_attribute_pps"),
            rate_requires_corroboration=bool(det.get("rate_requires_corroboration", False)),
            corroboration_ml_prob=det.get("corroboration_ml_prob", 0.5),
            corroboration_new_flows=det.get("corroboration_new_flows", 10.0),
            min_source_pps_strict=bool(det.get("min_source_pps_strict", False)),
            fast_confirm_score=det.get("fast_confirm_score"),
            offender_memory_seconds=float(det.get("offender_memory_seconds", 0.0) or 0.0),
            recovery_backoff=bool(det.get("recovery_backoff", False)),
            max_backoff_exponent=int(det.get("max_backoff_exponent", 3)),
            baseline_factor=det.get("attribution_baseline_factor"),
            new_source_corroborates=bool(det.get("new_source_corroborates", False)),
            source_confirm_windows=int(det.get("source_confirm_windows", 1)),
        )
