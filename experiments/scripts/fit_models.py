"""Fit the Level-2 window and source logistic scorers on CALIBRATION runs only.

Input : experiments/results/raw/calibration/tables/{dst_windows,src_windows}.csv
Output: artifacts/experiments/temporal/{window_model,source_model}.json
        (+ a standardisation report and a threshold chosen on a calibration
        validation split by maximising F1 subject to FPR<=target.)

The exported JSON is exactly what ddos_ml.decision_engine.LinearScorer.load
reads, so the same coefficients run inside the Ryu controller with no sklearn.

Only calibration data is used here. Test runs are never read.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[2]
import sys  # noqa: E402
sys.path.insert(0, str(ROOT))
from ddos_ml.decision_engine import transform  # noqa: E402
from ddos_ml.temporal_features import WINDOW_FEATURES, SOURCE_FEATURES  # noqa: E402


def _design(df: pd.DataFrame, feats: list[str]) -> np.ndarray:
    X = np.empty((len(df), len(feats)), dtype="float64")
    for j, f in enumerate(feats):
        col = df[f].to_numpy(dtype="float64")
        if f in __import__("ddos_ml.decision_engine", fromlist=["LOG_FEATURES"]).LOG_FEATURES:
            col = np.log1p(np.clip(col, 0, None))
        X[:, j] = col
    return X


def choose_threshold(y: np.ndarray, p: np.ndarray, target_fpr: float = 0.02) -> float:
    order = np.argsort(-p)
    ys = y[order]
    ps = p[order]
    P = max(int(y.sum()), 1)
    N = max(int((y == 0).sum()), 1)
    best_t, best_f1 = 0.5, -1.0
    tp = fp = 0
    for i in range(len(ps)):
        tp += ys[i] == 1
        fp += ys[i] == 0
        fpr = fp / N
        prec = tp / (tp + fp)
        rec = tp / P
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        if fpr <= target_fpr and f1 > best_f1:
            best_f1, best_t = f1, float(ps[i])
    if best_f1 < 0:  # target FPR unreachable; fall back to max-F1 (any FPR)
        tp = fp = 0
        for i in range(len(ps)):
            tp += ys[i] == 1
            fp += ys[i] == 0
            prec = tp / (tp + fp)
            rec = tp / P
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            if f1 > best_f1:
                best_f1, best_t = f1, float(ps[i])
    return best_t


def fit_scorer(df: pd.DataFrame, feats: list[str], name: str, group_col: str, target_fpr: float, C: float):
    # group-disjoint calibration/validation split by run (scenario+seed) so the
    # threshold is not tuned on windows from a training run.
    groups = (df["scenario"].astype(str) + ":" + df["seed"].astype(str)).to_numpy()
    uniq = np.array(sorted(set(groups)))
    rng = np.random.default_rng(42)
    rng.shuffle(uniq)
    val = set(uniq[: max(1, len(uniq) // 4)])
    is_val = np.array([g in val for g in groups])
    X = _design(df, feats)
    y = df["label"].to_numpy(dtype="int")
    mean = X[~is_val].mean(axis=0)
    scale = X[~is_val].std(axis=0)
    scale[scale == 0] = 1.0
    Xs = (X - mean) / scale
    clf = LogisticRegression(max_iter=2000, class_weight="balanced", C=C)
    clf.fit(Xs[~is_val], y[~is_val])
    p_val = clf.predict_proba(Xs[is_val])[:, 1]
    thr = choose_threshold(y[is_val], p_val, target_fpr)
    p_all = clf.predict_proba(Xs)[:, 1]
    model = {
        "name": name,
        "features": feats,
        "coef": clf.coef_[0].tolist(),
        "intercept": float(clf.intercept_[0]),
        "mean": mean.tolist(),
        "scale": scale.tolist(),
        "threshold": thr,
        "target_fpr": target_fpr,
        "calibration": {
            "n_rows": int(len(df)), "n_positive": int(y.sum()),
            "train_runs": sorted(set(uniq) - val), "val_runs": sorted(val),
            "val_roc_auc": float(roc_auc_score(y[is_val], p_val)) if len(set(y[is_val])) > 1 else None,
            "val_pr_auc": float(average_precision_score(y[is_val], p_val)) if y[is_val].sum() else None,
        },
        "coef_importance": sorted(
            [(f, float(abs(c))) for f, c in zip(feats, clf.coef_[0])], key=lambda x: -x[1]),
    }
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", default="calibration")
    ap.add_argument("--out", default="artifacts/experiments/temporal")
    ap.add_argument("--window-fpr", type=float, default=0.02)
    ap.add_argument("--source-fpr", type=float, default=0.01)
    ap.add_argument("--window-C", type=float, default=1.0)
    ap.add_argument("--source-C", type=float, default=1.0)
    args = ap.parse_args()
    tables = ROOT / "experiments" / "results" / "raw" / args.campaign / "tables"
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)

    dst = pd.read_csv(tables / "dst_windows.csv")
    # window model is trained on ALL destinations (victim + benign) so it learns
    # to keep benign high-volume UDP destinations below threshold.
    wm = fit_scorer(dst, WINDOW_FEATURES, "window_logistic", "seed", args.window_fpr, args.window_C)
    (out / "window_model.json").write_text(json.dumps(wm, indent=2))

    src = pd.read_csv(tables / "src_windows.csv")
    # source model is trained only on (source -> victim) rows; the question is
    # "is this source contributing to the flood?", which only matters at a victim.
    src_v = src[src["is_victim_dst"] == 1].reset_index(drop=True)
    sm = fit_scorer(src_v, SOURCE_FEATURES, "source_logistic", "seed", args.source_fpr, args.source_C)
    (out / "source_model.json").write_text(json.dumps(sm, indent=2))

    print("window model threshold=%.3f  top=%s" % (wm["threshold"], wm["coef_importance"][:5]))
    print("source model threshold=%.3f  top=%s" % (sm["threshold"], sm["coef_importance"][:5]))
    print("wrote", out / "window_model.json", out / "source_model.json")


if __name__ == "__main__":
    main()
