"""Evaluate detection: baselines, ablation, window-level + event-level metrics.

Fits every method on the CALIBRATION tables and scores the held-out TEST
tables. Nothing from the test campaign is used for fitting or thresholding.

Methods / ablation (all share the same features + decision engine machinery):
  flow_ml_only_raw   Baseline 1  : threshold on the flow model's ml_max_prob
  rule_statistical   Baseline 2  : pps & source-count thresholds, no ML
  abl_ml             logistic on ML-only features
  abl_ml_src         + unique-source / entropy features
  abl_ml_rate        + aggregate interval rate features
  abl_ml_src_rate    + both
  full_temporal      Baseline 3  : logistic on all window features (single window)
  proposed           full temporal + k-of-n confirmation + source attribution

Outputs under experiments/results/processed/<test_campaign>/:
  window_metrics.csv        one row per method (overall) + per-protocol/-scenario
  event_metrics.csv         per (method, run): detection latency, false alerts, recovery
  event_summary.csv         per method: mean/std latency, FP-alert rate, recovery
  predictions_<method>.csv  per-window scores (for ROC/PR plots)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ddos_ml.decision_engine import DecisionEngine, LinearScorer, RuleScorer  # noqa: E402
from ddos_ml.temporal_features import WINDOW_FEATURES, SOURCE_FEATURES  # noqa: E402
from fit_models import fit_scorer, choose_threshold, _design  # noqa: E402

class PassthroughScorer:
    """Returns a single feature directly (no sigmoid) — for the raw flow-ML baseline."""
    def __init__(self, feature, threshold):
        self.feature = feature
        self.threshold = float(threshold)

    def score(self, feats):
        return float(feats.get(self.feature, 0.0))

    def contributions(self, feats):
        return {self.feature: float(feats.get(self.feature, 0.0))}


ML_FEATS = ["ml_max_prob", "ml_mean_prob", "ml_flow_frac", "ml_pps_share"]
SRC_FEATS = ["n_sources", "source_entropy", "top_source_share", "n_new_flows", "new_flow_rate"]
RATE_FEATS = ["pps", "bps", "avg_pkt_size", "packet_in_rate"]
CTX_FEATS = ["udp_share", "tcp_share", "icmp_share", "response_ratio", "log_pps_change"]

ABLATION = {
    "abl_ml": ML_FEATS,
    "abl_ml_src": ML_FEATS + SRC_FEATS,
    "abl_ml_rate": ML_FEATS + RATE_FEATS,
    "abl_ml_src_rate": ML_FEATS + SRC_FEATS + RATE_FEATS,
    "full_temporal": WINDOW_FEATURES,
}


def clf_metrics(y, pred, prob):
    y = np.asarray(y); pred = np.asarray(pred)
    tp = int(((y == 1) & (pred == 1)).sum()); tn = int(((y == 0) & (pred == 0)).sum())
    fp = int(((y == 0) & (pred == 1)).sum()); fn = int(((y == 1) & (pred == 0)).sum())
    P = tp + fn or 1; N = tn + fp or 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / P; spec = tn / N
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    benign_f1 = 2 * spec * (tn / (tn + fn) if tn + fn else 0) / ((spec + (tn / (tn + fn) if tn + fn else 0)) or 1)
    out = {"n": len(y), "pos": int((y == 1).sum()), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
           "accuracy": (tp + tn) / (len(y) or 1), "precision": prec, "recall": rec, "specificity": spec,
           "f1": f1, "balanced_accuracy": 0.5 * (rec + spec), "fpr": fp / N, "fnr": fn / P,
           "macro_f1": 0.5 * (f1 + benign_f1)}
    try:
        from sklearn.metrics import roc_auc_score, average_precision_score
        if len(set(y)) > 1:
            out["roc_auc"] = float(roc_auc_score(y, prob))
            out["pr_auc"] = float(average_precision_score(y, prob))
    except Exception:
        pass
    return out


def dominant_proto(row):
    shares = {"udp": row["udp_share"], "tcp": row["tcp_share"], "icmp": row["icmp_share"]}
    k = max(shares, key=shares.get)
    return k if shares[k] > 0 else "none"


def score_rows(scorer, df, feats):
    """Vectorised scoring over a dataframe from a fitted-scorer dict."""
    X = _design(df, feats)
    mean = np.asarray(scorer["mean"]); scale = np.asarray(scorer["scale"])
    Xs = (X - mean) / np.where(scale == 0, 1, scale)
    z = scorer["intercept"] + Xs @ np.asarray(scorer["coef"])
    return 1.0 / (1.0 + np.exp(-z))


def build_methods(calib_dst, calib_src):
    methods = {}
    # Baseline 1: raw flow-ML probability (threshold tuned on calibration windows)
    thr = choose_threshold(calib_dst["label"].to_numpy(), calib_dst["ml_max_prob"].to_numpy(), 0.05)
    methods["flow_ml_only_raw"] = ("raw", "ml_max_prob", thr)
    # Baseline 2: statistical rule (grid over pps & sources, max F1 s.t. FPR<=5%)
    best = (0.5, 1e9, 2)
    y = calib_dst["label"].to_numpy()
    for pps_t in [1000, 2000, 4000, 8000, 12000, 20000]:
        for ns in [1, 2, 3, 4]:
            pred = ((calib_dst["pps"] >= pps_t) & (calib_dst["n_sources"] >= ns)).to_numpy().astype(int)
            m = clf_metrics(y, pred, pred)
            if m["fpr"] <= 0.05 and m["f1"] > best[0]:
                best = (m["f1"], pps_t, ns)
    methods["rule_statistical"] = ("rule", best[1], best[2])
    # Ablation + Baseline 3 (logistic on feature subsets)
    for name, feats in ABLATION.items():
        methods[name] = ("logistic", fit_scorer(calib_dst, feats, name, "seed", 0.02, 1.0), feats)
    # Proposed uses the full_temporal scorer + confirmation + source model
    methods["proposed"] = methods["full_temporal"]
    return methods


def window_eval(methods, test_dst, out_dir):
    rows = []
    test_dst = test_dst.copy()
    test_dst["proto"] = test_dst.apply(dominant_proto, axis=1)
    for name, spec in methods.items():
        kind = spec[0]
        if kind == "raw":
            prob = test_dst[spec[1]].to_numpy(); pred = (prob >= spec[2]).astype(int); thr = spec[2]
        elif kind == "rule":
            prob = ((test_dst["pps"] >= spec[1]) & (test_dst["n_sources"] >= spec[2])).to_numpy().astype(float)
            pred = prob.astype(int); thr = 0.5
        else:
            scorer = spec[1]; prob = score_rows(scorer, test_dst, spec[2])
            thr = float(scorer["threshold"]); pred = (prob >= thr).astype(int)
        y = test_dst["label"].to_numpy()
        base = {"method": name, "scope": "overall", "threshold": round(float(thr), 4), **clf_metrics(y, pred, prob)}
        rows.append(base)
        for proto in ["udp", "tcp", "icmp"]:
            m = test_dst["proto"] == proto
            if m.sum() and test_dst.loc[m, "label"].nunique() >= 1:
                rows.append({"method": name, "scope": f"proto:{proto}",
                             **clf_metrics(y[m], pred[m], prob[m])})
        for scn, g in test_dst.groupby("scenario"):
            idx = g.index.to_numpy()
            rows.append({"method": name, "scope": f"scenario:{scn}",
                         **clf_metrics(y[idx], pred[idx], prob[idx])})
        if name in ("flow_ml_only_raw", "full_temporal", "proposed", "rule_statistical"):
            pd.DataFrame({"scenario": test_dst["scenario"], "seed": test_dst["seed"], "ts": test_dst["ts"],
                          "is_victim": test_dst["is_victim"], "label": y, "prob": prob}).to_csv(
                out_dir / f"predictions_{name}.csv", index=False)
    return pd.DataFrame(rows)


def event_eval(methods, test_dst, test_src, raw_base, out_dir):
    """Chronological state-machine replay per run; latency & false alerts."""
    manifests = {}
    for d in (raw_base).iterdir():
        mf = d / "manifest.json"
        if mf.exists():
            m = json.loads(mf.read_text())
            manifests[(m["scenario"], m["seed"])] = m
    src_by_run = {k: g for k, g in test_src.groupby(["scenario", "seed"])}
    rows = []
    for name in ["flow_ml_only_raw", "rule_statistical", "full_temporal", "proposed"]:
        spec = methods[name]
        confirm = (1, 1) if name != "proposed" else (2, 3)
        for (scn, seed), g in test_dst.groupby(["scenario", "seed"]):
            g = g.sort_values("ts")
            m = manifests.get((scn, seed))
            if m is None:
                continue
            victim = m["victim_ip"]; a_start = m.get("attack_start_epoch")
            atk = [(e.get("epoch_start"), e.get("epoch_start", 0) + e["duration"]) for e in m["events"] if e["role"] == "attack"]
            attack_start = min((a[0] for a in atk), default=None)
            attack_end = max((a[1] for a in atk), default=None)
            # scorer
            if spec[0] == "logistic":
                ws = LinearScorer.from_dict(spec[1])
            elif spec[0] == "rule":
                ws = RuleScorer(spec[1], spec[2])
            else:  # raw flow-ML probability, thresholded directly
                ws = PassthroughScorer(spec[1], spec[2])
            src_model = None
            spath = ROOT / "artifacts/experiments/temporal/source_model.json"
            if name == "proposed" and spath.exists():
                src_model = LinearScorer.load(spath)
            eng = DecisionEngine(ws, src_model, confirm_k=confirm[0], confirm_n=confirm[1],
                                 recovery_windows=2, cooldown_windows=2, mitigation_enabled=False)
            gsrc = src_by_run.get((scn, seed))
            srows = {round(t, 3): sg for t, sg in gsrc.groupby("ts")} if gsrc is not None else {}
            confirm_ts = None; recover_ts = None; false_alerts = 0; confirmed_any = False
            for _, w in g.iterrows():
                ts = w["ts"]
                dfe = {w["dst"]: {k: w[k] for k in WINDOW_FEATURES}}
                sg = srows.get(round(ts, 3))
                sfe = {}
                if sg is not None:
                    for _, sr in sg.iterrows():
                        sfe[(sr["src"], sr["dst"])] = {k: sr[k] for k in SOURCE_FEATURES}
                decs = eng.step(ts, dfe, sfe)
                for dcn in decs:
                    if dcn.state in ("CONFIRMED", "MITIGATING"):
                        if dcn.dst == victim and attack_start and ts >= attack_start - 1e-6:
                            if confirm_ts is None:
                                confirm_ts = ts
                            confirmed_any = True
                        elif attack_start is None or dcn.dst != victim or (attack_end and ts > attack_end + 10):
                            false_alerts += 1
                    if (dcn.dst == victim and confirm_ts and dcn.state in ("RECOVERING", "NORMAL")
                            and recover_ts is None and attack_end and ts > attack_end):
                        recover_ts = ts
            has_attack = attack_start is not None
            rows.append({
                "method": name, "scenario": scn, "seed": seed, "has_attack": int(has_attack),
                "detected": int(confirmed_any) if has_attack else None,
                "detection_latency": (confirm_ts - attack_start) if (confirmed_any and has_attack) else None,
                "false_alerts": false_alerts,
                "recovery_after_end": (recover_ts - attack_end) if (recover_ts and attack_end) else None,
            })
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--calib", default="calibration")
    ap.add_argument("--test", default="test")
    args = ap.parse_args()
    raw = ROOT / "experiments" / "results" / "raw"
    cdir = raw / args.calib / "tables"; tdir = raw / args.test / "tables"
    out = ROOT / "experiments" / "results" / "processed" / args.test
    out.mkdir(parents=True, exist_ok=True)
    calib_dst = pd.read_csv(cdir / "dst_windows.csv"); calib_src = pd.read_csv(cdir / "src_windows.csv")
    test_dst = pd.read_csv(tdir / "dst_windows.csv"); test_src = pd.read_csv(tdir / "src_windows.csv")

    methods = build_methods(calib_dst, calib_src[calib_src.is_victim_dst == 1].reset_index(drop=True))
    wm = window_eval(methods, test_dst, out)
    wm.to_csv(out / "window_metrics.csv", index=False)
    ev = event_eval(methods, test_dst, test_src, raw / args.test, out)
    ev.to_csv(out / "event_metrics.csv", index=False)
    # event summary
    summ = []
    for name, g in ev.groupby("method"):
        atk = g[g.has_attack == 1]; ben = g[g.has_attack == 0]
        det = atk[atk.detected == 1]
        summ.append({"method": name, "n_attack_runs": len(atk), "detection_rate": atk.detected.mean(),
                     "mean_latency_s": det.detection_latency.mean(), "std_latency_s": det.detection_latency.std(),
                     "mean_false_alerts_benign_run": ben.false_alerts.mean() if len(ben) else None,
                     "total_false_alerts": int(g.false_alerts.sum()),
                     "mean_recovery_s": g.recovery_after_end.dropna().mean()})
    pd.DataFrame(summ).to_csv(out / "event_summary.csv", index=False)

    ov = wm[wm.scope == "overall"].set_index("method")
    print("\n=== WINDOW-LEVEL (overall, held-out test) ===")
    print(ov[["recall", "specificity", "fpr", "f1", "balanced_accuracy", "roc_auc", "pr_auc"]].round(3).to_string())
    print("\n=== EVENT-LEVEL ===")
    print(pd.DataFrame(summ).round(3).to_string(index=False))
    print("\nwrote", out)


if __name__ == "__main__":
    main()
