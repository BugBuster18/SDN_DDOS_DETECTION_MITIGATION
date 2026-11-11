"""Unit tests for the decision engine: scoring, state machine, attribution."""
from ddos_ml.decision_engine import (
    CONFIRMED, MITIGATING, NORMAL, RECOVERING, SUSPECTED,
    DecisionEngine, LinearScorer, RuleScorer,
)


def _const_scorer(threshold=0.5):
    # score == feats["x"] (after identity transform); mean0 scale1, coef1
    return LinearScorer(["response_ratio"], [-1.0], 0.0, [0.0], [1.0], threshold, "test")


class ToggleScorer:
    threshold = 0.5

    def score(self, feats):
        return feats.get("attack", 0.0)

    def contributions(self, feats):
        return {"attack": feats.get("attack", 0.0)}


def _feats(attack):
    return {"attack": attack}


def test_k_of_n_confirmation_requires_persistence():
    eng = DecisionEngine(ToggleScorer(), confirm_k=2, confirm_n=3)
    d = eng.step(1.0, {"v": _feats(1.0)}, {})[0]
    assert d.state == SUSPECTED  # one window over threshold -> suspected only
    d = eng.step(2.0, {"v": _feats(1.0)}, {})[0]
    assert d.state == CONFIRMED  # 2 of last 3 -> confirmed


def test_single_window_does_not_confirm_with_k2():
    eng = DecisionEngine(ToggleScorer(), confirm_k=2, confirm_n=3)
    eng.step(1.0, {"v": _feats(1.0)}, {})
    d = eng.step(2.0, {"v": _feats(0.0)}, {})[0]
    assert d.state in (SUSPECTED, NORMAL) and d.state != CONFIRMED


def test_benign_never_confirms():
    eng = DecisionEngine(ToggleScorer(), confirm_k=2, confirm_n=3)
    states = [eng.step(float(i), {"v": _feats(0.0)}, {})[0].state for i in range(5)]
    assert set(states) == {NORMAL}


def test_recovery_and_cooldown_cycle():
    eng = DecisionEngine(ToggleScorer(), confirm_k=1, confirm_n=1, recovery_windows=2, cooldown_windows=2)
    eng.step(1.0, {"v": _feats(1.0)}, {})  # CONFIRMED
    eng.step(2.0, {"v": _feats(0.0)}, {})  # quiet 1
    d = eng.step(3.0, {"v": _feats(0.0)}, {})[0]  # quiet 2 -> RECOVERING
    assert d.state == RECOVERING
    eng.step(4.0, {"v": _feats(0.0)}, {})  # cooldown 1
    d = eng.step(5.0, {"v": _feats(0.0)}, {})[0]  # cooldown 2 -> NORMAL
    assert d.state == NORMAL


def test_renewed_attack_during_recovery_returns_to_confirmed():
    eng = DecisionEngine(ToggleScorer(), confirm_k=1, confirm_n=1, recovery_windows=1, cooldown_windows=3)
    eng.step(1.0, {"v": _feats(1.0)}, {})
    d = eng.step(2.0, {"v": _feats(0.0)}, {})[0]
    assert d.state == RECOVERING
    d = eng.step(3.0, {"v": _feats(1.0)}, {})[0]
    assert d.state == CONFIRMED


def test_source_attribution_filters_allowlist_and_low_rate():
    src_scorer = LinearScorer(["src_pps"], [1.0], -5.0, [0.0], [1.0], 0.5, "src")
    eng = DecisionEngine(ToggleScorer(), src_scorer, confirm_k=1, confirm_n=1, allowlist=["10.0.0.7"])
    src = {
        ("10.0.0.1", "v"): {"src_pps": 1000.0, "src_share": 0.4, "src_new_flows": 0, "src_log_rate_jump": 0,
                            "src_active_windows": 1, "src_pkts_per_flow": 1, "src_n_flows": 1,
                            "src_ml_max_prob": 1, "src_ml_mean_prob": 1, "src_response_ratio": 0},
        ("10.0.0.7", "v"): {"src_pps": 2000.0, "src_share": 0.4, "src_new_flows": 0, "src_log_rate_jump": 0,
                            "src_active_windows": 1, "src_pkts_per_flow": 1, "src_n_flows": 1,
                            "src_ml_max_prob": 1, "src_ml_mean_prob": 1, "src_response_ratio": 0},
    }
    d = eng.step(1.0, {"v": _feats(1.0)}, src)[0]
    assert "10.0.0.1" in d.attributed_sources
    assert "10.0.0.7" not in d.attributed_sources  # allowlisted


def test_evidence_contributions_are_reported():
    eng = DecisionEngine(ToggleScorer(), confirm_k=1, confirm_n=1)
    d = eng.step(1.0, {"v": _feats(1.0)}, {})[0]
    assert "attack" in d.evidence


def test_mitigation_disabled_never_emits_block():
    eng = DecisionEngine(ToggleScorer(), confirm_k=1, confirm_n=1, mitigation_enabled=False)
    d = eng.step(1.0, {"v": _feats(1.0)}, {("10.0.0.1", "v"): {"src_pps": 1e4, "src_share": 1.0,
                 "src_new_flows": 0, "src_log_rate_jump": 0, "src_active_windows": 1, "src_pkts_per_flow": 1,
                 "src_n_flows": 1, "src_ml_max_prob": 1, "src_ml_mean_prob": 1, "src_response_ratio": 0}})[0]
    assert "block" not in d.actions and "block_dry_run" not in d.actions


def test_dry_run_emits_only_dry_run_action():
    eng = DecisionEngine(ToggleScorer(), confirm_k=1, confirm_n=1, mitigation_enabled=True, dry_run=True)
    src = {("10.0.0.1", "v"): {"src_pps": 1e4, "src_share": 1.0, "src_new_flows": 0, "src_log_rate_jump": 0,
           "src_active_windows": 1, "src_pkts_per_flow": 1, "src_n_flows": 1, "src_ml_max_prob": 1,
           "src_ml_mean_prob": 1, "src_response_ratio": 0}}
    d = eng.step(1.0, {"v": _feats(1.0)}, src)[0]
    assert "block_dry_run" in d.actions and "block" not in d.actions


def test_rule_scorer_threshold_behaviour():
    r = RuleScorer(min_pps=5000, min_sources=3)
    assert r.score({"pps": 6000, "n_sources": 4}) == 1.0
    assert r.score({"pps": 6000, "n_sources": 2}) == 0.0
    assert r.score({"pps": 100, "n_sources": 10}) == 0.0
