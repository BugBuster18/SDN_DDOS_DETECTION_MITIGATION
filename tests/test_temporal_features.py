"""Unit tests for counter-delta tracking and destination window features."""
from ddos_ml.temporal_features import (
    DestinationWindowAnalyzer, FlowCounterTracker, merge_path_observations,
)


def _row(src, dst, proto, pk, by, dur, sport=1, dport=2):
    return {"ip_src": src, "ip_dst": dst, "ip_proto": proto, "tp_src": sport, "tp_dst": dport,
            "packet_count": pk, "byte_count": by, "duration_sec": int(dur),
            "duration_nsec": int((dur % 1) * 1e9)}


def test_counter_delta_basic_interval_rate():
    t = FlowCounterTracker()
    t.update(1, [_row("a", "b", 17, 100, 10000, 5.0)], ts=100.0)
    d = t.update(1, [_row("a", "b", 17, 300, 30000, 7.0)], ts=102.0)
    assert len(d) == 1
    assert d[0].status == "ok"
    assert d[0].delta_packets == 200 and d[0].delta_bytes == 20000
    assert abs(d[0].elapsed - 2.0) < 1e-6
    # interval rate, not lifetime average
    assert abs(d[0].delta_packets / d[0].elapsed - 100.0) < 1e-6


def test_new_flow_counts_full_counters_once():
    t = FlowCounterTracker()
    t.update(1, [], ts=100.0)  # establishes a poll baseline time
    d = t.update(1, [_row("a", "b", 17, 50, 5000, 0.3)], ts=105.0)
    assert d[0].status == "new" and d[0].delta_packets == 50


def test_first_sight_without_baseline_is_excluded():
    t = FlowCounterTracker()
    # very first poll, a long-lived flow we never saw before -> no interval known
    d = t.update(1, [_row("a", "b", 17, 1000, 100000, 50.0)], ts=100.0)
    assert d[0].status == "no_baseline" and d[0].delta_packets == 0 and not d[0].usable


def test_counter_reset_uses_current_counters():
    t = FlowCounterTracker()
    t.update(1, [_row("a", "b", 17, 1000, 100000, 20.0)], ts=100.0)
    d = t.update(1, [_row("a", "b", 17, 30, 3000, 1.0)], ts=105.0)  # re-installed entry
    assert d[0].status == "reset" and d[0].delta_packets == 30


def test_duplicate_entries_in_one_reply_keep_max():
    t = FlowCounterTracker()
    t.update(1, [_row("a", "b", 17, 10, 1000, 1.0)], ts=100.0)
    d = t.update(1, [_row("a", "b", 17, 20, 2000, 2.0), _row("a", "b", 17, 40, 4000, 3.0)], ts=102.0)
    assert len(d) == 1 and d[0].delta_packets == 30


def test_missing_reply_keeps_state_no_phantom_delta():
    t = FlowCounterTracker()
    t.update(1, [_row("a", "b", 17, 10, 1000, 1.0)], ts=100.0)
    # datapath 1 produced no reply this poll -> we simply do not call update(1, ...)
    d = t.update(1, [_row("a", "b", 17, 210, 21000, 11.0)], ts=110.0)
    assert d[0].status == "ok" and d[0].delta_packets == 200


def test_switch_disconnect_forgets_state():
    t = FlowCounterTracker()
    t.update(1, [_row("a", "b", 17, 10, 1000, 1.0)], ts=100.0)
    t.forget_datapath(1)
    d = t.update(1, [_row("a", "b", 17, 20, 2000, 2.0)], ts=102.0)
    assert d[0].status == "no_baseline"


def test_expiry_removes_stale_entries():
    t = FlowCounterTracker(expire_after_seconds=5.0)
    t.update(1, [_row("a", "b", 17, 10, 1000, 1.0)], ts=100.0)
    t.update(1, [_row("c", "d", 17, 5, 500, 1.0)], ts=110.0)  # a->b not seen, >5s stale
    assert all(k[1][0] != "a" for k in t._state)


def test_merge_path_observations_takes_max_not_sum():
    t = FlowCounterTracker()
    t.update(1, [_row("a", "b", 17, 0, 0, 0.0)], ts=100.0)
    t.update(2, [_row("a", "b", 17, 0, 0, 0.0)], ts=100.0)
    d1 = t.update(1, [_row("a", "b", 17, 100, 10000, 2.0)], ts=102.0)
    d2 = t.update(2, [_row("a", "b", 17, 100, 10000, 2.0)], ts=102.0)
    merged = merge_path_observations(d1 + d2)
    assert len(merged) == 1
    rec = next(iter(merged.values()))
    assert rec.delta_packets == 100  # same flow on two switches counted once


def test_window_features_distinguish_distributed_flood():
    an = DestinationWindowAnalyzer()
    # six sources, one-directional high-rate UDP to the victim
    deltas = []
    t = FlowCounterTracker()
    rows0 = [_row(f"10.0.0.{i}", "10.0.0.18", 17, 0, 0, 0.0, sport=i) for i in range(1, 7)]
    t.update(1, rows0, ts=100.0)
    rows1 = [_row(f"10.0.0.{i}", "10.0.0.18", 17, 5000, 2_500_000, 2.0, sport=i) for i in range(1, 7)]
    deltas = t.update(1, rows1, ts=102.0)
    flows = merge_path_observations(deltas)
    for r in flows.values():
        r.ml_prob = 0.9
    dst, src = an.compute(flows, interval=2.0, ml_threshold=0.5)
    f = dst["10.0.0.18"]
    assert f["n_sources"] == 6
    assert f["pps"] > 10000
    assert f["response_ratio"] == 0.0  # no reverse traffic
    assert len(src) == 6
    assert all(v["src_response_ratio"] == 0.0 for v in src.values())
