"""Decision-engine features added in the review revision."""
from ddos_ml.decision_engine import CONFIRMED, MITIGATING, NORMAL, SUSPECTED, DecisionEngine
from ddos_ml.mitigation import DropRule, proto_name


class FeatScorer:
    """Window score = feats['s'] (threshold 0.5)."""
    threshold = 0.5

    def score(self, f):
        return float(f.get("s", 0.0))

    def contributions(self, f):
        return {}


def eng(**kw):
    base = dict(confirm_k=2, confirm_n=3, recovery_windows=1, cooldown_windows=1, mitigation_enabled=True,
                dry_run=False, min_source_pps=10, source_min_attribute_pps=100)
    base.update(kw)
    return DecisionEngine(FeatScorer(), None, **base)


def src(pps):
    return {"src_pps": pps, "src_share": 0.5, "src_ml_max_prob": 1.0}


def test_fast_confirm_skips_k_of_n():
    e = eng(fast_confirm_score=0.9)
    d = e.step(0, {"v": {"s": 0.95}}, {})[0]
    assert d.state == CONFIRMED
    e2 = eng()
    assert e2.step(0, {"v": {"s": 0.95}}, {})[0].state == SUSPECTED


def test_repeat_offender_reblocked_in_first_window_and_backoff():
    e = eng(offender_memory_seconds=300, recovery_backoff=True)
    sf = {("a", "v"): src(500)}
    e.step(0, {"v": {"s": 1}}, sf)
    d = e.step(2, {"v": {"s": 1}}, sf)[0]
    assert d.state == MITIGATING and "block" in d.actions
    # attack stops: one quiet window (episode 1) -> rollback
    d = e.step(4, {"v": {"s": 0}}, {})[0]
    assert "rollback" in d.actions
    e.step(6, {"v": {"s": 0}}, {})
    assert e.states["v"].state == NORMAL
    # same attacker comes back: confirmed in the FIRST window over threshold
    d = e.step(8, {"v": {"s": 1}}, sf)[0]
    assert d.state == MITIGATING and "block" in d.actions
    # second episode needs 2 quiet windows before rollback
    assert "rollback" not in e.step(10, {"v": {"s": 0}}, {})[0].actions
    assert "rollback" in e.step(12, {"v": {"s": 0}}, {})[0].actions


def test_baseline_aware_attribution_spares_preexisting_sender():
    e = eng(baseline_factor=3.0)
    legit = {("L", "v"): src(120)}
    for t in range(5):                       # benign period: L streams at 120 pps
        e.step(t, {"v": {"s": 0}}, legit)
    attack = {("L", "v"): src(130), ("A", "v"): src(400)}
    e.step(10, {"v": {"s": 1}}, attack)
    d = e.step(12, {"v": {"s": 1}}, attack)[0]
    assert d.attributed_sources == ["A"]
    # without the baseline rule the steady sender is blocked too
    e2 = eng()
    for t in range(5):
        e2.step(t, {"v": {"s": 0}}, legit)
    e2.step(10, {"v": {"s": 1}}, attack)
    assert set(e2.step(12, {"v": {"s": 1}}, attack)[0].attributed_sources) == {"A", "L"}


def test_any_protocol_rule_match():
    r = DropRule("10.0.0.1", "10.0.0.200", 0, 1, [6], 0.0, 300, 200)
    assert "ip_proto" not in r.to_dict()["match"] and proto_name(0) == "ANY"


def test_reinstalled_entry_has_no_fake_rate_spike():
    from ddos_ml.temporal_features import FlowCounterTracker
    tr = FlowCounterTracker()
    row = dict(ip_src="a", ip_dst="v", ip_proto=17, tp_src=1, tp_dst=2)
    tr.update(1, [dict(row, packet_count=10000, byte_count=10**7, duration_sec=100)], 0.0)
    # entry hard-timed-out and was re-installed 12 s ago at 100 pps -> 1200 packets
    d = tr.update(1, [dict(row, packet_count=1200, byte_count=1.2e6, duration_sec=12)], 2.0)[0]
    assert d.status == "reset" and abs(d.delta_packets / d.elapsed - 100) < 1
    # same match re-added: counters continue, duration restarts
    d = tr.update(1, [dict(row, packet_count=1400, byte_count=1.4e6, duration_sec=0.3)], 4.0)[0]
    assert d.status == "ok" and d.delta_packets == 200


def test_source_persistence_ignores_one_window_spike():
    e = eng(source_confirm_windows=2)
    e.step(0, {"v": {"s": 1}}, {})
    spike = {("L", "v"): src(900)}
    d = e.step(2, {"v": {"s": 1}}, spike)[0]          # confirmed, but L qualified in 1 window only
    assert d.state == CONFIRMED and d.attributed_sources == []
    d = e.step(4, {"v": {"s": 1}}, {("L", "v"): src(5), ("A", "v"): src(500)})[0]
    assert d.attributed_sources == []                  # A: first window
    d = e.step(6, {"v": {"s": 1}}, {("A", "v"): src(500)})[0]
    assert d.attributed_sources == ["A"]
