"""Diagnose live attribution per attack segment (review round 1: live ICMP 1/40 vs offline 38/40).

python experiments/large/diagnose_attribution.py test_mit [kind]
For each segment: (a) rules already active at onset for that segment's attackers (carry-over),
(b) stepping the live engine configuration through the session's own telemetry, which condition of
Eq. (7) fails for each attacker in the windows where the victim is confirmed and over threshold.
"""
import json
import os
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ddos_ml.config import load_config  # noqa: E402
from ddos_ml.decision_engine import CONFIRMED, MITIGATING, DecisionEngine  # noqa: E402
from ddos_ml.temporal_features import SOURCE_FEATURES, WINDOW_FEATURES  # noqa: E402

ses_name = sys.argv[1]
only = sys.argv[2] if len(sys.argv) > 2 else None
L = ROOT / "experiments/results/large" / ses_name
ses = json.loads((L / "session.json").read_text())
ev = json.loads((L / "events.json").read_text())["events"]
victim = ses["victim_ip"]

# (a) carry-over: intervals during which each source had an active rule for the victim
active = {}
for e in ev:
    if e["type"] == "rule_installed" and e.get("dst") == victim:
        active.setdefault(e["src"], []).append([e["installed"], None])
for e in ev:
    if e["type"] in ("rule_removed", "rule_expired") and e.get("dst") == victim and e.get("src") in active:
        for iv in active[e["src"]]:
            if iv[1] is None:
                iv[1] = e["ts"]
                break


def blocked_at(src, t):
    return any(a <= t and (b is None or b > t) for a, b in active.get(src, []))


os.environ.pop("DDOS_MITIGATION_MODE", None)
cfg = load_config(L / "config.yaml")
cfg["mitigation"].update({"enabled": True, "dry_run": True})
eng = DecisionEngine.from_config(cfg, ROOT)
t = ROOT / "experiments/results/raw" / ("large_" + ses_name) / "tables"
dst = pd.read_csv(t / "dst_windows.csv")
src = pd.read_csv(t / "src_windows.csv")
src_g = {k: g for k, g in src.groupby("ts")}
seg_of = lambda ts: next((g for g in ses["segments"] if g["start"] - 1 <= ts <= g["end"] + 2), None)  # noqa: E731
reasons = {}
for ts, w in dst.sort_values("ts").groupby("ts", sort=True):
    df = {r["dst"]: {f: r[f] for f in WINDOW_FEATURES} for r in w.to_dict("records")}
    sw = src_g.get(ts)
    sf = {} if sw is None else {(r["src"], r["dst"]): {f: r[f] for f in SOURCE_FEATURES} for r in sw.to_dict("records")}
    seg = seg_of(ts)
    st_before = eng.states.get(victim)
    eng.step(ts, df, sf)
    st = eng.states.get(victim)
    if seg is None or not seg["events"] or (only and seg["kind"] != only):
        continue
    score = eng.window_scorer.score(df.get(victim, {})) if victim in df else 0.0
    if st is None or st.state not in (CONFIRMED, MITIGATING) or score < eng.window_scorer.threshold:
        continue
    atk = {e["src_ip"] for e in seg["events"]}
    for a in atk:
        f = sf.get((a, victim))
        key = (seg["kind"], a)
        if blocked_at(a, ts):
            r = "already blocked (rule active)"
        elif f is None:
            r = "no traffic seen to victim this window"
        elif f["src_pps"] < eng.min_source_pps:
            r = "below rate floor"
        elif not eng.above_baseline(a, victim, f):
            r = "below beta*baseline"
        else:
            s = eng.source_scorer.score(f)
            rate = f["src_pps"] >= eng.source_min_attribute_pps
            corr = eng._rate_corroborated(f) or (a, victim) not in eng.src_baseline
            if s >= eng.source_scorer.threshold or (rate and corr):
                r = "qualifies"
            elif not rate:
                r = "score<eta_s and rate<150pps"
            else:
                r = "score<eta_s and not corroborated (seen before, ML low, no churn)"
        reasons.setdefault(key, Counter())[r] += 1

rows = []
for (kind, a), c in reasons.items():
    rows.append({"kind": kind, "src": a, "main_reason": c.most_common(1)[0][0], "windows": sum(c.values())})
df = pd.DataFrame(rows)
if len(df):
    print(df.groupby(["kind", "main_reason"]).src.count().rename("attackers").to_string())
for g in ses["segments"]:
    if g["events"] and (not only or g["kind"] == only):
        atk = {e["src_ip"] for e in g["events"]}
        print(g["kind"], "attackers already blocked at onset:", sum(blocked_at(a, g["start"]) for a in atk), "/", len(atk))
