"""Large-testbed pipeline: split sessions, fit on calibration, evaluate against standard SDN baselines.

  split SESSION                       session telemetry -> experiments/results/raw/large_<SESSION>/<idx>_<kind>/
                                      (manifest.json + telemetry.jsonl), then run replay.py on it
  fit   CALIB_CAMPAIGN OUT_DIR        window + source logistic models; threshold = calibration-only
                                      leave-one-segment-out CV at window FPR <= 1 %
  eval  CALIB_CAMPAIGN TEST_CAMPAIGN MODEL_DIR NAME [--poll S]
        methods (thresholds fixed on CALIBRATION benign windows at FPR <= 1 %, never on test):
          pps_threshold     per-destination packet rate                       (classic volumetric rule)
          src_entropy       Shannon entropy (bits) of the source-IP distribution per destination
          dst_entropy       Mousavi & St-Hilaire (2015): entropy of the destination-IP distribution of
                            all traffic in a window; low entropy -> alarm on the dominant destination
          flow_ml_only      max flow-level ML probability at the destination
          hybrid            proposed window model (+ k-of-n, + fast confirmation)
        outputs experiments/results/processed/<NAME>/{window_metrics,event_metrics,event_summary}.csv
"""
from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments" / "scripts"))
from ddos_ml.decision_engine import DecisionEngine, LinearScorer, LOG_FEATURES  # noqa: E402
from ddos_ml.temporal_features import SOURCE_FEATURES, WINDOW_FEATURES  # noqa: E402

RAW = ROOT / "experiments" / "results" / "raw"
TARGET_FPR = float(__import__("os").environ.get("DDOS_TARGET_FPR", "0.01"))


# ------------------------------------------------------------------------- split
def split(session):
    sdir = ROOT / "experiments" / "results" / "large" / session
    ses = json.loads((sdir / "session.json").read_text())
    segs = ses["segments"]
    camp = RAW / ("large_" + session)
    camp.mkdir(parents=True, exist_ok=True)
    bounds = []
    for i, s in enumerate(segs):
        lo = s["start"] - (8 if i else 0)
        hi = segs[i + 1]["start"] - 8 if i + 1 < len(segs) else ses.get("finished", s["end"] + 60)
        bounds.append((lo, hi))
    fhs = []
    for i, s in enumerate(segs):
        d = camp / ("%02d_%s" % (i, s["kind"]))
        d.mkdir(exist_ok=True)
        ev = [dict(e, start=e["epoch_start"] - s["start"]) for e in s["events"]]
        man = {"scenario": s["kind"], "seed": ses["seed"] * 100 + i, "victim_ip": ses["victim_ip"],
               "epoch0": s["start"], "events": ev, "session": session, "segment": i,
               "duration": s["duration"], "kind": s["kind"]}
        (d / "manifest.json").write_text(json.dumps(man, indent=1))
        fhs.append(open(d / "telemetry.jsonl", "w"))
    with open(sdir / "telemetry.jsonl") as fh:
        for line in fh:
            if '"event":"window"' not in line[:40]:
                continue
            ts = json.loads(line)["ts"]
            for (lo, hi), out in zip(bounds, fhs):
                if lo <= ts < hi:
                    out.write(line)
                    break
    for f in fhs:
        f.close()
    subprocess.run([sys.executable, str(ROOT / "experiments" / "scripts" / "replay.py"), "--campaign",
                    "large_" + session], check=True)


# --------------------------------------------------------------------- features
def design(df, feats, mean=None, scale=None):
    X = np.column_stack([np.log1p(np.clip(df[f].to_numpy(float), 0, None)) if f in LOG_FEATURES
                         else df[f].to_numpy(float) for f in feats])
    if mean is None:
        mean, scale = X.mean(0), X.std(0)
        scale[scale == 0] = 1.0
    return (X - mean) / scale, mean, scale


def thr_at_fpr(neg_scores, target=None):
    target = TARGET_FPR if target is None else target
    s = np.sort(np.asarray(neg_scores, float))
    if len(s) == 0:
        return 0.5
    k = int(math.ceil((1 - target) * len(s))) - 1
    return float(s[min(max(k, 0), len(s) - 1)]) + 1e-9


def fit_one(df, feats, groups, C=1.0):
    Xs, mean, scale = design(df, feats)
    y = df["label"].to_numpy(int)
    # leave-one-segment-out probabilities for an honest calibration threshold
    oof = np.zeros(len(df))
    for g in np.unique(groups):
        m = groups == g
        if y[~m].min() == y[~m].max():
            oof[m] = 0.0
            continue
        clf = LogisticRegression(max_iter=3000, class_weight="balanced", C=C).fit(Xs[~m], y[~m])
        oof[m] = clf.predict_proba(Xs[m])[:, 1]
    clf = LogisticRegression(max_iter=3000, class_weight="balanced", C=C).fit(Xs, y)
    thr = thr_at_fpr(oof[y == 0])
    tpr = float((oof[y == 1] >= thr).mean()) if (y == 1).any() else None
    return {"features": feats, "coef": clf.coef_[0].tolist(), "intercept": float(clf.intercept_[0]),
            "mean": mean.tolist(), "scale": scale.tolist(), "threshold": thr, "target_fpr": TARGET_FPR,
            "calibration": {"n_rows": int(len(df)), "n_positive": int(y.sum()), "oof_tpr_at_thr": tpr},
            "coef_importance": sorted([(f, abs(float(c))) for f, c in zip(feats, clf.coef_[0])], key=lambda x: -x[1])}


def fit(calib, out_dir):
    t = RAW / calib / "tables"
    dst = pd.read_csv(t / "dst_windows.csv")
    src = pd.read_csv(t / "src_windows.csv")
    out = ROOT / out_dir
    out.mkdir(parents=True, exist_ok=True)
    wm = fit_one(dst, WINDOW_FEATURES, (dst["scenario"] + dst["seed"].astype(str)).to_numpy())
    wm["name"] = "window_logistic_large"
    sv = src[(src["is_victim_dst"] == 1) & (src["scenario"] != "spoof")].reset_index(drop=True)
    sm = fit_one(sv, SOURCE_FEATURES, (sv["scenario"] + sv["seed"].astype(str)).to_numpy())
    sm["name"] = "source_logistic_large"
    (out / "window_model.json").write_text(json.dumps(wm, indent=2))
    (out / "source_model.json").write_text(json.dumps(sm, indent=2))
    print("window thr %.4f oof-TPR %s top %s" % (wm["threshold"], wm["calibration"]["oof_tpr_at_thr"],
                                                 wm["coef_importance"][:6]))
    print("source thr %.4f oof-TPR %s top %s" % (sm["threshold"], sm["calibration"]["oof_tpr_at_thr"],
                                                 sm["coef_importance"][:6]))


# --------------------------------------------------------------------- baselines
def add_baseline_scores(dst, src, model):
    key = ["scenario", "seed", "ts"]
    s = src.copy()
    s["tot"] = s.groupby(key + ["dst"])["src_pps"].transform("sum")
    p = (s["src_pps"] / s["tot"].replace(0, np.nan)).fillna(0).to_numpy()
    s["plogp"] = np.where(p > 0, -p * np.log2(np.where(p > 0, p, 1)), 0.0)
    h = s.groupby(key + ["dst"])["plogp"].sum().rename("src_entropy_bits").reset_index()
    d = dst.merge(h, on=key + ["dst"], how="left")
    d["src_entropy_bits"] = d["src_entropy_bits"].fillna(0.0)
    # destination entropy of the whole window (normalised), alarm assigned to the dominant destination
    d["tot"] = d.groupby(key)["pps"].transform("sum")
    q = (d["pps"] / d["tot"].replace(0, np.nan)).fillna(0).to_numpy()
    d["qlogq"] = np.where(q > 0, -q * np.log(np.where(q > 0, q, 1)), 0.0)
    n = d.groupby(key)["dst"].transform("count").clip(lower=2)
    hd = d.groupby(key)["qlogq"].transform("sum") / np.log(n)
    top = d["pps"] == d.groupby(key)["pps"].transform("max")
    d["dst_entropy_drop"] = np.where(top, 1.0 - hd, 0.0)
    ws = LinearScorer.from_dict(model)
    Xs = np.column_stack([np.log1p(np.clip(d[f].to_numpy(float), 0, None)) if f in LOG_FEATURES
                          else d[f].to_numpy(float) for f in ws.features])
    z = ws.intercept + ((Xs - np.array(ws.mean)) / np.where(np.array(ws.scale) > 0, ws.scale, 1)) @ np.array(ws.coef)
    d["hybrid"] = 1 / (1 + np.exp(-z))
    return d.drop(columns=["tot", "qlogq"])


METHODS = {"pps_threshold": "pps", "src_entropy": "src_entropy_bits", "dst_entropy": "dst_entropy_drop",
           "flow_ml_only": "ml_max_prob", "hybrid": "hybrid"}


class Pass:
    def __init__(self, col, thr):
        self.col, self.threshold = col, thr

    def score(self, f):
        return float(f.get(self.col, 0.0))

    def contributions(self, f):
        return {}


def window_metrics(d, thr):
    rows = []
    for m, col in METHODS.items():
        for part, sub in [("all", d)] + [(k, g) for k, g in d.groupby("scenario")]:
            y = sub["label"].to_numpy(int)
            p = sub[col].to_numpy(float) >= thr[m]
            tp, fp = int((p & (y == 1)).sum()), int((p & (y == 0)).sum())
            fn, tn = int((~p & (y == 1)).sum()), int((~p & (y == 0)).sum())
            prec = tp / (tp + fp) if tp + fp else float("nan")
            rec = tp / (tp + fn) if tp + fn else float("nan")
            rows.append({"method": m, "part": part, "threshold": thr[m], "n": len(y), "n_attack": int(y.sum()),
                         "recall": rec, "fpr": fp / (fp + tn) if fp + tn else float("nan"), "precision": prec,
                         "f1": 2 * prec * rec / (prec + rec) if prec and rec and prec + rec else float("nan"),
                         "fp": fp, "tp": tp})
    return pd.DataFrame(rows)


def event_metrics(d, thr, manifests, configs):
    rows = []
    for (scn, seed), g in d.groupby(["scenario", "seed"]):
        man = manifests[(scn, seed)]
        atk = [(e.get("epoch_start", man.get("epoch0", 0) + e.get("start", 0)),
                e.get("epoch_start", man.get("epoch0", 0) + e.get("start", 0)) + e["duration"])
               for e in man["events"] if e.get("role") == "attack"]
        a0 = min(a for a, _ in atk) if atk else None
        a1 = max(b for _, b in atk) if atk else None
        victim = man["victim_ip"]
        g = g.sort_values("ts")
        for cname, (m, k, n, fast) in configs.items():
            eng = DecisionEngine(Pass(METHODS[m], thr[m]), None, confirm_k=k, confirm_n=n, recovery_windows=3,
                                 cooldown_windows=3, fast_confirm_score=fast)
            first = None
            false_eps = 0
            for ts, w in g.groupby("ts", sort=True):
                feats = {r["dst"]: r for r in w.to_dict("records")}
                for dcn in eng.step(ts, feats, {}):
                    under = bool(atk) and dcn.dst == victim and a0 - 0.1 <= ts <= a1 + 4
                    if dcn.state == "CONFIRMED" and under and first is None:
                        first = ts
                    if dcn.state == "CONFIRMED" and dcn.previous_state not in ("CONFIRMED", "MITIGATING"):
                        if not (dcn.dst == victim and atk and a0 - 0.1 <= ts <= a1 + 12):
                            false_eps += 1
            dur_h = (g["ts"].max() - g["ts"].min() + 2) / 3600.0
            rows.append({"config": cname, "method": m, "scenario": scn, "seed": seed, "has_attack": int(bool(atk)),
                         "detected": int(first is not None) if atk else None,
                         "latency_s": (first - a0) if first is not None else None,
                         "false_alarm_episodes": false_eps, "hours": dur_h})
    return pd.DataFrame(rows)


def evaluate(calib, test, model_dir, name):
    model = json.loads((ROOT / model_dir / "window_model.json").read_text())
    tc, tt = RAW / calib / "tables", RAW / test / "tables"
    cd = add_baseline_scores(pd.read_csv(tc / "dst_windows.csv"), pd.read_csv(tc / "src_windows.csv"), model)
    td = add_baseline_scores(pd.read_csv(tt / "dst_windows.csv"), pd.read_csv(tt / "src_windows.csv"), model)
    thr = {m: thr_at_fpr(cd.loc[cd["label"] == 0, col]) for m, col in METHODS.items()}
    thr["hybrid"] = model["threshold"]
    out = ROOT / "experiments" / "results" / "processed" / name
    out.mkdir(parents=True, exist_ok=True)
    wm = window_metrics(td, thr)
    wm.to_csv(out / "window_metrics.csv", index=False)
    manifests = {}
    for dd in (RAW / test).iterdir():
        if (dd / "manifest.json").exists():
            mm = json.loads((dd / "manifest.json").read_text())
            manifests[(mm["scenario"], mm["seed"])] = mm
    configs = {"pps_threshold k2/3": ("pps_threshold", 2, 3, None), "src_entropy k2/3": ("src_entropy", 2, 3, None),
               "dst_entropy k2/3": ("dst_entropy", 2, 3, None), "flow_ml_only k2/3": ("flow_ml_only", 2, 3, None),
               "hybrid k2/3": ("hybrid", 2, 3, None), "hybrid k2/3+fast": ("hybrid", 2, 3, 0.97),
               "hybrid k1/1": ("hybrid", 1, 1, None)}
    ev = event_metrics(td, thr, manifests, configs)
    ev.to_csv(out / "event_metrics.csv", index=False)
    summ = []
    for c, g in ev.groupby("config", sort=False):
        a = g[g.has_attack == 1]
        summ.append({"config": c, "attack_segments": len(a), "detected": int(a.detected.sum()),
                     "detection_rate": a.detected.mean(), "mean_latency_s": a.latency_s.mean(),
                     "median_latency_s": a.latency_s.median(),
                     "false_alarm_episodes": int(g.false_alarm_episodes.sum()),
                     "false_alarms_per_hour": g.false_alarm_episodes.sum() / g.hours.sum(),
                     "benign_dst_windows": int((td.label == 0).sum())})
    summ = pd.DataFrame(summ)
    summ.to_csv(out / "event_summary.csv", index=False)
    lat = ev.pivot_table(index="scenario", columns="config", values="latency_s", aggfunc="mean")
    lat.to_csv(out / "latency_by_scenario.csv")
    pd.set_option("display.width", 200)
    print(wm[wm.part == "all"].round(4).to_string(index=False))
    print(summ.round(3).to_string(index=False))
    print(ev[ev.has_attack == 1].pivot_table(index="scenario", columns="config", values="detected").to_string())
    json.dump(thr, open(out / "thresholds.json", "w"), indent=1)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "split":
        split(sys.argv[2])
    elif cmd == "fit":
        fit(sys.argv[2], sys.argv[3])
    elif cmd == "eval":
        evaluate(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
