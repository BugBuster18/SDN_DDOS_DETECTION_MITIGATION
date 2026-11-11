"""Tests for mitigation modes, the drop-rule table, config mode resolution and
runtime mode changes of the decision engine."""
import copy

import pytest

from ddos_ml.config import DEFAULTS, resolve_mitigation_mode
from ddos_ml.decision_engine import CONFIRMED, MITIGATING, NORMAL, DecisionEngine, RuleScorer
from ddos_ml.mitigation import (
    DETECTION_ONLY, DROP_COOKIE_TAG, DRY_RUN, MITIGATION_ENABLED, DropRule, DropRuleTable, DryRunLedger,
    flags_from_mode, format_cookie, mode_from_flags, normalize_mode, parse_cookie, status_label,
)

VICTIM = "10.0.0.18"


def test_normalize_mode_aliases():
    assert normalize_mode("detection_only") == DETECTION_ONLY
    assert normalize_mode("dry-run") == DRY_RUN
    assert normalize_mode("enforce") == MITIGATION_ENABLED
    assert normalize_mode(" Mitigation_Enabled ") == MITIGATION_ENABLED
    with pytest.raises(ValueError):
        normalize_mode("block-everything")
    with pytest.raises(ValueError):
        normalize_mode(None)


def test_flags_roundtrip():
    for m in (DETECTION_ONLY, DRY_RUN, MITIGATION_ENABLED):
        assert mode_from_flags(*flags_from_mode(m)) == m
    assert flags_from_mode(DETECTION_ONLY) == (False, False)
    assert flags_from_mode(DRY_RUN) == (True, True)
    assert flags_from_mode(MITIGATION_ENABLED) == (True, False)


def test_status_labels():
    assert status_label("NORMAL") == "NORMAL TRAFFIC"
    assert status_label("SUSPECTED") == "SUSPICIOUS TRAFFIC"
    assert status_label("CONFIRMED") == "ATTACK CONFIRMED"
    assert status_label("MITIGATING") == "MITIGATION ACTIVE"


def test_cookie_format_parse():
    c = DROP_COOKIE_TAG | 7
    assert parse_cookie(format_cookie(c)) == c
    assert parse_cookie(str(c)) == c


# ---------------------------------------------------------------- config
def _cfg(**mit):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["mitigation"].update(mit)
    return cfg


def test_default_mode_is_detection_only():
    cfg = _cfg()
    assert resolve_mitigation_mode(cfg) == DETECTION_ONLY
    assert cfg["mitigation"]["enabled"] is False


def test_legacy_flags_still_work():
    cfg = _cfg(enabled=True, dry_run=True)
    assert resolve_mitigation_mode(cfg) == DRY_RUN


def test_enabled_requires_enforce():
    cfg = _cfg(mode="MITIGATION_ENABLED")
    with pytest.raises(ValueError):
        resolve_mitigation_mode(cfg)
    cfg["detection"]["mode"] = "enforce"
    assert resolve_mitigation_mode(cfg) == MITIGATION_ENABLED
    assert (cfg["mitigation"]["enabled"], cfg["mitigation"]["dry_run"]) == (True, False)


def test_env_mode_overrides_config():
    cfg = _cfg(mode="MITIGATION_ENABLED")
    cfg["detection"]["mode"] = "enforce"
    assert resolve_mitigation_mode(cfg, "DRY_RUN") == DRY_RUN


# ---------------------------------------------------------------- rule table
def _rule(table, src, proto=17, dst=VICTIM):
    r = DropRule(src, dst, proto, table.next_cookie(), [1], 100.0, 120, 200)
    table.add(r)
    return r


def test_rule_table_add_lookup_remove():
    t = DropRuleTable()
    r1 = _rule(t, "10.0.0.1")
    r2 = _rule(t, "10.0.0.2")
    assert len(t) == 2 and ("10.0.0.1", VICTIM, 17) in t
    assert r1.cookie != r2.cookie and DropRuleTable.is_drop_cookie(r1.cookie)
    assert not DropRuleTable.is_drop_cookie(0x1234)
    with pytest.raises(KeyError):
        t.add(DropRule("10.0.0.1", VICTIM, 17, t.next_cookie(), [1], 0.0, 1, 1))
    assert t.by_cookie(r2.cookie) is r2
    assert t.remove_cookie(r2.cookie) is r2 and len(t) == 1
    assert t.remove_cookie(r2.cookie) is None


def test_rule_table_select_by_destination():
    t = DropRuleTable()
    _rule(t, "10.0.0.1")
    _rule(t, "10.0.0.2", dst="10.0.0.17")
    assert [r.src for r in t.select(VICTIM)] == ["10.0.0.1"]
    assert len(t.select(None)) == 2


def test_rule_counters_use_max_across_switches_and_deltas():
    t = DropRuleTable()
    r = _rule(t, "10.0.0.1")
    r.dpids = [1, 2]
    # same rule seen on two switches: max is used, not the sum
    assert t.update_counters([(r.cookie, 100, VICTIM), (r.cookie, 90, VICTIM)], 5.0) == {}
    rates = t.update_counters([(r.cookie, 600, VICTIM), (r.cookie, 580, VICTIM)], 5.0)
    assert rates == {VICTIM: pytest.approx(100.0)}
    assert r.dropped_packets == 600 and r.dropped_pps == pytest.approx(100.0)


def test_rule_to_dict_describes_match_and_action():
    t = DropRuleTable()
    d = _rule(t, "10.0.0.3", proto=1).to_dict(now=110.0)
    assert d["proto_name"] == "ICMP" and d["action"] == "drop" and d["switches"] == ["s1"]
    assert "ipv4_src=10.0.0.3" in d["match"] and "ipv4_dst=10.0.0.18" in d["match"]
    assert d["age_s"] == 10.0


def test_dry_run_ledger_reports_once_per_episode():
    led = DryRunLedger()
    k = ("10.0.0.1", VICTIM, 17)
    assert led.first_time(k, 1.0) and not led.first_time(k, 2.0)
    led.clear(VICTIM)
    assert led.first_time(k, 3.0)


# ---------------------------------------------------------------- engine runtime mode
def _engine(enabled, dry):
    return DecisionEngine(RuleScorer(min_pps=1000, min_sources=2), confirm_k=2, confirm_n=3,
                          recovery_windows=2, cooldown_windows=1, mitigation_enabled=enabled, dry_run=dry)


ATTACK = {VICTIM: {"pps": 5000.0, "n_sources": 6.0}}
SRC = {(f"10.0.0.{i}", VICTIM): {"src_pps": 900.0, "src_share": 1 / 6} for i in range(1, 7)}


def test_detection_only_never_blocks():
    eng = _engine(False, False)
    for t in range(4):
        decs = eng.step(float(t), ATTACK, SRC)
    assert decs[0].state == CONFIRMED
    assert all("block" not in d.actions and "block_dry_run" not in d.actions for d in decs)


def test_enabling_mitigation_at_runtime_blocks_next_window():
    eng = _engine(False, False)
    for t in range(3):
        eng.step(float(t), ATTACK, SRC)
    assert eng.states[VICTIM].state == CONFIRMED
    eng.set_mitigation(*flags_from_mode(MITIGATION_ENABLED))
    d = eng.step(3.0, ATTACK, SRC)[0]
    assert d.state == MITIGATING and "block" in d.actions and len(d.attributed_sources) == 6


def test_disabling_mitigation_demotes_mitigating_state():
    eng = _engine(True, False)
    for t in range(3):
        eng.step(float(t), ATTACK, SRC)
    assert eng.states[VICTIM].state == MITIGATING
    demoted = eng.set_mitigation(*flags_from_mode(DETECTION_ONLY))
    assert demoted == [VICTIM] and eng.states[VICTIM].state == CONFIRMED
    d = eng.step(5.0, ATTACK, SRC)[0]
    assert "block" not in d.actions


def test_dry_run_reports_but_does_not_enter_mitigating():
    eng = _engine(True, True)
    for t in range(3):
        decs = eng.step(float(t), ATTACK, SRC)
    assert decs[0].state == CONFIRMED and "block_dry_run" in decs[0].actions


class _NeverScorer:
    """Source model that never attributes, so only the rate fallback can."""
    threshold = 0.9

    def score(self, feats):
        return 0.1


def _rate_engine(corroborate):
    return DecisionEngine(RuleScorer(min_pps=1000, min_sources=2), _NeverScorer(), confirm_k=1, confirm_n=1,
                          mitigation_enabled=True, dry_run=False, source_min_attribute_pps=800.0,
                          rate_requires_corroboration=corroborate)


LEGIT_BULK = {"src_pps": 900.0, "src_ml_max_prob": 0.0, "src_new_flows": 0.0}      # fast but benign-looking
FLAGGED_FLOOD = {"src_pps": 2000.0, "src_ml_max_prob": 0.99, "src_new_flows": 0.0}  # flow ML agrees
SYN_CHURN = {"src_pps": 900.0, "src_ml_max_prob": 0.0, "src_new_flows": 400.0}      # random-port churn


def test_rate_fallback_without_corroboration_blocks_any_fast_source():
    eng = _rate_engine(False)
    got = eng.attribute_sources(VICTIM, {("10.0.0.7", VICTIM): LEGIT_BULK})
    assert "10.0.0.7" in got


def test_rate_fallback_with_corroboration_spares_fast_legit_source():
    eng = _rate_engine(True)
    src = {("10.0.0.7", VICTIM): LEGIT_BULK, ("10.0.0.1", VICTIM): FLAGGED_FLOOD,
           ("10.0.0.2", VICTIM): SYN_CHURN}
    got = eng.attribute_sources(VICTIM, src)
    assert set(got) == {"10.0.0.1", "10.0.0.2"}


class _AlwaysScorer:
    threshold = 0.9

    def score(self, feats):
        return 0.99


def test_strict_rate_floor_protects_low_rate_new_flow_sources():
    # A DNS-like client: almost no traffic but many new flows; the source model says "attack".
    dns_like = {("10.0.0.10", VICTIM): {"src_pps": 0.1, "src_new_flows": 100.0}}
    lax = DecisionEngine(RuleScorer(min_pps=1), _AlwaysScorer(), min_source_pps=50.0)
    strict = DecisionEngine(RuleScorer(min_pps=1), _AlwaysScorer(), min_source_pps=50.0,
                            min_source_pps_strict=True)
    assert "10.0.0.10" in lax.attribute_sources(VICTIM, dns_like)
    assert strict.attribute_sources(VICTIM, dns_like) == {}
    flood = {("10.0.0.1", VICTIM): {"src_pps": 2000.0, "src_new_flows": 0.0}}
    assert "10.0.0.1" in strict.attribute_sources(VICTIM, flood)


def test_recovery_rolls_back_after_quiet_windows():
    eng = _engine(True, False)
    for t in range(3):
        eng.step(float(t), ATTACK, SRC)
    quiet = {VICTIM: {"pps": 10.0, "n_sources": 1.0}}
    actions = []
    for t in range(3, 8):
        for d in eng.step(float(t), quiet, {}):
            actions += d.actions
    assert "rollback" in actions
    assert eng.states[VICTIM].state == NORMAL
