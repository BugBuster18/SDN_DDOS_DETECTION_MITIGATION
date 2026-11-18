#!/usr/bin/env python3
"""Run-level (cluster) bootstrap confidence intervals for the held-out test results.

Windows from the same run are correlated, so the unit that is resampled is the RUN
(scenario, seed), not the window. Thresholds are the ones fixed on the calibration
campaign (read from window_metrics.csv); nothing is re-tuned on the test data.

Inputs : experiments/results/processed/test/{predictions_*.csv, window_metrics.csv, event_metrics.csv}
Outputs: experiments/results/processed/test/ci_window.csv, ci_event.csv, ci_paired.csv

    python experiments/scripts/confidence_intervals.py [--n-boot 10000] [--seed 0]
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
TEST = ROOT / "experiments/results/processed/test"
METHODS = ["flow_ml_only_raw", "rule_statistical", "proposed"]


def counts(d, thr):
    pred = d["prob"].to_numpy() >= thr
    y = d["label"].to_numpy() == 1
    return np.array([(pred & y).sum(), (~pred & ~y).sum(), (pred & ~y).sum(), (~pred & y).sum()])


def metrics(c):
    tp, tn, fp, fn = c
    rec = tp / (tp + fn) if tp + fn else np.nan
    fpr = fp / (fp + tn) if fp + tn else np.nan
    prec = tp / (tp + fp) if tp + fp else np.nan
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else np.nan
    return {"recall": rec, "fpr": fpr, "precision": prec, "f1": f1}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-boot", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)

    wm = pd.read_csv(TEST / "window_metrics.csv")
    thr = wm[wm.scope == "overall"].set_index("method")["threshold"].to_dict()

    # per-run confusion counts for each method -> bootstrap by summing resampled runs
    per_run = {}
    runs = None
    for m in METHODS:
        d = pd.read_csv(TEST / f"predictions_{m}.csv")
        g = {k: counts(x, thr[m]) for k, x in d.groupby(["scenario", "seed"])}
        runs = sorted(g) if runs is None else runs
        per_run[m] = np.stack([g[r] for r in runs])
    n = len(runs)
    idx = rng.integers(0, n, size=(a.n_boot, n))

    rows, boots = [], {}
    for m in METHODS:
        point = metrics(per_run[m].sum(0))
        bs = per_run[m][idx].sum(1)                     # (n_boot, 4)
        bm = pd.DataFrame([metrics(c) for c in bs])
        boots[m] = bm
        for k in ["recall", "fpr", "precision", "f1"]:
            lo, hi = np.nanpercentile(bm[k], [2.5, 97.5])
            rows.append({"method": m, "metric": k, "value": point[k], "ci_low": lo, "ci_high": hi,
                         "n_runs": n, "n_windows": int(per_run[m].sum())})
    pd.DataFrame(rows).to_csv(TEST / "ci_window.csv", index=False)

    # paired differences: same resampled runs for both methods
    paired = []
    for base in ["flow_ml_only_raw", "rule_statistical"]:
        for k in ["fpr", "recall", "f1"]:
            diff = boots["proposed"][k] - boots[base][k]
            point = metrics(per_run["proposed"].sum(0))[k] - metrics(per_run[base].sum(0))[k]
            lo, hi = np.nanpercentile(diff, [2.5, 97.5])
            better = (diff < 0).mean() if k == "fpr" else (diff > 0).mean()
            paired.append({"comparison": f"proposed - {base}", "metric": k, "difference": point,
                           "ci_low": lo, "ci_high": hi, "share_of_resamples_proposed_better": better})
    pd.DataFrame(paired).to_csv(TEST / "ci_paired.csv", index=False)

    # event level: detection rate & latency over attack runs, false alerts over benign runs
    ev = pd.read_csv(TEST / "event_metrics.csv")
    erows = []
    for m in ["flow_ml_only_raw", "rule_statistical", "proposed"]:
        e = ev[ev.method == m]
        att, ben = e[e.has_attack == 1], e[e.has_attack == 0]
        for name, vals in [("detection_rate", att["detected"].astype(float).to_numpy()),
                           ("latency_s", att["detection_latency"].dropna().to_numpy()),
                           ("false_alerts_per_benign_run", ben["false_alerts"].astype(float).to_numpy())]:
            if len(vals) == 0:
                continue
            b = vals[rng.integers(0, len(vals), size=(a.n_boot, len(vals)))].mean(1)
            lo, hi = np.percentile(b, [2.5, 97.5])
            erows.append({"method": m, "metric": name, "value": vals.mean(), "ci_low": lo, "ci_high": hi,
                          "n_runs": len(vals)})
    pd.DataFrame(erows).to_csv(TEST / "ci_event.csv", index=False)

    pd.set_option("display.width", 160)
    print(pd.DataFrame(rows).round(4).to_string(index=False))
    print(pd.DataFrame(paired).round(4).to_string(index=False))
    print(pd.DataFrame(erows).round(3).to_string(index=False))


if __name__ == "__main__":
    main()
