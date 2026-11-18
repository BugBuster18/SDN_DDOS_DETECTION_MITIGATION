#!/usr/bin/env python3
"""Publication-style figures with readable labels and 95 % confidence intervals.

Reads the processed test results (+ confidence_intervals.py output), the flow-model
metrics and, if present, the repeated live runs summary (report/evidence/repeats/summary.csv).
Writes PNGs to experiments/results/figures/pub_*.png and report/figures/.

    python experiments/scripts/publication_figures.py
"""
import shutil
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import auc, roc_curve

ROOT = Path(__file__).resolve().parents[2]
TEST = ROOT / "experiments/results/processed/test"
OUT = ROOT / "experiments/results/figures"
REP = ROOT / "report/figures"

ACCENT, GREY, LIGHT = "#2a78d6", "#898781", "#c3c2b7"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e1e0d9"
NAMES = {"flow_ml_only_raw": "Flow-level ML only", "rule_statistical": "Statistical rules",
         "proposed": "Proposed hybrid", "full_temporal": "Proposed hybrid",
         "abl_ml": "ML features only", "abl_ml_src": "ML + source features",
         "abl_ml_rate": "ML + rate features", "abl_ml_src_rate": "ML + source + rate",
         }
ORDER = ["flow_ml_only_raw", "rule_statistical", "proposed"]

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 10, "axes.edgecolor": LIGHT, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.titlesize": 10.5, "axes.titleweight": "bold", "axes.titlecolor": INK, "axes.titlelocation": "left",
    "figure.dpi": 100, "savefig.dpi": 200, "savefig.bbox": "tight", "legend.frameon": False,
})


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True); REP.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / name, facecolor="white")
    shutil.copy(OUT / name, REP / name)
    plt.close(fig)
    print("wrote", name)


def color(m):
    return ACCENT if m in ("proposed", "full_temporal") else GREY


def ci_panel(ax, df, metric, scale, fmt, xlabel, order=ORDER):
    d = df[df.metric == metric].set_index("method")
    ys = np.arange(len(order))[::-1]
    for y, m in zip(ys, order):
        r = d.loc[m]
        v, lo, hi = r.value * scale, r.ci_low * scale, r.ci_high * scale
        ax.plot([lo, hi], [y, y], color=color(m), lw=2, solid_capstyle="round")
        ax.plot([lo, lo], [y - 0.12, y + 0.12], color=color(m), lw=1.5)
        ax.plot([hi, hi], [y - 0.12, y + 0.12], color=color(m), lw=1.5)
        ax.scatter([v], [y], s=64, color=color(m), zorder=3, edgecolor="white", linewidth=1.5)
        ax.text(v, y + 0.22, fmt.format(v), ha="center", va="bottom", fontsize=9, color=INK,
                fontweight="bold" if m == "proposed" else "normal")
    ax.set_yticks(ys, [NAMES[m] for m in order])
    ax.set_ylim(-0.6, len(order) - 0.3)
    ax.set_xlabel(xlabel)
    ax.grid(axis="x", color=GRID, lw=0.8); ax.set_axisbelow(True)
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    sub = df[df.metric == metric]
    ax.set_xlim(left=min(sub.ci_low.min() * scale, 0) - 0.04 * sub.ci_high.max() * scale)


def fig_window():
    ci = pd.read_csv(TEST / "ci_window.csv")
    fig, ax = plt.subplots(1, 2, figsize=(9.5, 2.9), sharey=True)
    ci_panel(ax[0], ci, "fpr", 100, "{:.1f} %", "False-positive rate (% of benign windows)")
    ci_panel(ax[1], ci, "recall", 100, "{:.0f} %", "Recall (% of attack windows detected)")
    ax[1].set_xlim(0, 102)
    ax[0].set_title("Fewer false alarms ...")
    ax[1].set_title("... and more attacks detected")
    fig.suptitle("Window-level results on 21 held-out test runs (dot = estimate, bar = 95 % CI)",
                 x=0.01, ha="left", fontsize=11.5, fontweight="bold", color=INK, y=1.04)
    save(fig, "pub_window_ci.png")


def fig_event():
    ci = pd.read_csv(TEST / "ci_event.csv")
    fig, ax = plt.subplots(1, 3, figsize=(11, 2.9), sharey=True)
    ci_panel(ax[0], ci, "false_alerts_per_benign_run", 1, "{:.1f}", "False alerts per benign run (3 runs)")
    ci_panel(ax[1], ci, "detection_rate", 100, "{:.0f} %", "Attack runs detected (18 runs)")
    ci_panel(ax[2], ci, "latency_s", 1, "{:.1f} s", "Detection latency, detected runs (s)")
    ax[1].set_xlim(0, 102)
    ax[0].set_title("False alerts"); ax[1].set_title("Detection rate"); ax[2].set_title("Latency")
    fig.suptitle("Event-level results: the hybrid trades about 5 s of latency for ~95 % fewer false alerts",
                 x=0.01, ha="left", fontsize=11.5, fontweight="bold", color=INK, y=1.04)
    save(fig, "pub_event_ci.png")


def fig_roc():
    fig, ax = plt.subplots(figsize=(5.6, 4.6))
    styles = {"flow_ml_only_raw": (LIGHT, "--"), "rule_statistical": (GREY, ":"), "proposed": (ACCENT, "-")}
    for m in ORDER:
        d = pd.read_csv(TEST / f"predictions_{m}.csv")
        f, t, _ = roc_curve(d["label"], d["prob"])
        c, ls = styles[m]
        ax.plot(f, t, color=c, ls=ls, lw=2.2 if m == "proposed" else 1.8,
                label=f"{NAMES[m]} (AUC {auc(f, t):.3f})")
    ax.plot([0, 1], [0, 1], color=GRID, lw=1)
    ax.set(xlabel="False-positive rate", ylabel="True-positive rate", xlim=(0, 1), ylim=(0, 1.01))
    ax.set_title("ROC on held-out test windows (2,805 windows, 21 runs)")
    ax.grid(color=GRID, lw=0.6); ax.set_axisbelow(True)
    ax.legend(loc="lower right", fontsize=9)
    save(fig, "pub_roc.png")


def fig_ablation():
    wm = pd.read_csv(TEST / "window_metrics.csv")
    w = wm[wm.scope == "overall"].set_index("method")
    order = ["flow_ml_only_raw", "rule_statistical", "abl_ml", "abl_ml_rate", "abl_ml_src", "abl_ml_src_rate", "proposed"]
    labels = [NAMES[m] if m != "proposed" else "All features (proposed)" for m in order]
    fig, ax = plt.subplots(1, 2, figsize=(9.5, 3.4), sharey=True)
    ys = np.arange(len(order))[::-1]
    for a, (col, scale, lab, fmt) in zip(ax, [("f1", 1, "F1 score", "{:.2f}"), ("fpr", 100, "False-positive rate (%)", "{:.1f}")]):
        vals = [w.loc[m, col] * scale for m in order]
        a.barh(ys, vals, height=0.62, color=[color(m) for m in order])
        for y, v in zip(ys, vals):
            a.text(v + max(vals) * 0.015, y, fmt.format(v), va="center", fontsize=9, color=INK)
        a.set_xlabel(lab); a.grid(axis="x", color=GRID, lw=0.8); a.set_axisbelow(True)
        a.spines["left"].set_visible(False); a.tick_params(axis="y", length=0)
        a.set_xlim(0, max(vals) * 1.18)
    ax[0].set_yticks(ys, labels)
    ax[0].axhline(4.5, color=GRID, lw=1)
    ax[1].axhline(4.5, color=GRID, lw=1)
    fig.suptitle("Ablation: adding feature groups raises F1; all groups together score best (top two rows = baselines)",
                 x=0.01, ha="left", fontsize=11.5, fontweight="bold", color=INK, y=1.02)
    save(fig, "pub_ablation.png")


def fig_models():
    mm = pd.read_csv(ROOT / "artifacts/production/metrics.csv").set_index("model")
    mm = mm.sort_values("macro_f1")
    fig, ax = plt.subplots(1, 2, figsize=(9.5, 3.3), sharey=True)
    ys = np.arange(len(mm))
    sel = "Hist Gradient Boosting"
    for a, (col, scale, lab, fmt, log) in zip(ax, [("macro_f1", 1, "Macro F1", "{:.3f}", False),
                                                  ("false_positive_rate", 100, "False-positive rate on benign flows (%, log scale)", "{:.2f} %", True)]):
        vals = mm[col] * scale
        cs = [ACCENT if m == sel else GREY for m in mm.index]
        a.scatter(vals, ys, s=56, color=cs, zorder=3, edgecolor="white", linewidth=1.2)
        for y, v, m in zip(ys, vals, mm.index):
            a.text(v * (1.15 if log else 1) + (0 if log else 0.02), y, fmt.format(v), va="center", fontsize=9,
                   color=INK, fontweight="bold" if m == sel else "normal")
        if log:
            a.set_xscale("log"); a.set_xlim(0.2, 200)
        else:
            a.set_xlim(0.3, 1.05)
        a.set_xlabel(lab); a.grid(axis="x", color=GRID, lw=0.8); a.set_axisbelow(True)
        a.spines["left"].set_visible(False); a.tick_params(axis="y", length=0)
    ax[0].set_yticks(ys, mm.index)
    fig.suptitle("Flow-level models on the CIC-DDoS2019 grouped test set: HistGradientBoosting has the best macro F1 and ties for the lowest FPR",
                 x=0.01, ha="left", fontsize=11.5, fontweight="bold", color=INK, y=1.02)
    save(fig, "pub_model_comparison.png")


def fig_repeats():
    p = ROOT / "report/evidence/repeats/summary.csv"
    if not p.exists():
        print("no repeats summary yet"); return
    s = pd.read_csv(p)
    s = s[s.completed == 1]
    panels = [("t_confirm_s", "Attack confirmed and blocked (s after start)", "{:.1f} s"),
              ("reduction_pct", "Attack traffic removed at the victim (%)", "{:.1f} %"),
              ("t_normal_after_stop_s", "Back to NORMAL (s after attack stop)", "{:.1f} s")]
    fig, ax = plt.subplots(1, 3, figsize=(11, 2.4))
    rng = np.random.default_rng(1)
    for a, (col, lab, fmt) in zip(ax, panels):
        v = s[col].to_numpy(dtype=float)
        jit = rng.uniform(-0.12, 0.12, len(v))
        a.scatter(v, jit, s=40, color=GREY, alpha=0.9, zorder=3, edgecolor="white", linewidth=1)
        b = v[rng.integers(0, len(v), size=(10000, len(v)))].mean(1)
        lo, hi = np.percentile(b, [2.5, 97.5])
        a.plot([lo, hi], [-0.38, -0.38], color=ACCENT, lw=2.4, solid_capstyle="round")
        a.scatter([v.mean()], [-0.38], s=70, color=ACCENT, zorder=4, edgecolor="white", linewidth=1.5)
        a.text(v.mean(), -0.62, f"mean {fmt.format(v.mean())}", ha="center", va="top", fontsize=9, color=INK, fontweight="bold")
        a.set_ylim(-0.85, 0.35); a.set_yticks([])
        a.spines["left"].set_visible(False)
        a.set_xlabel(lab); a.grid(axis="x", color=GRID, lw=0.8); a.set_axisbelow(True)
        span = max(v.max() - v.min(), 1e-6)
        if col == "reduction_pct":
            a.set_xlim(min(v.min(), lo) - 1, 100.5)
        else:
            a.set_xlim(min(v.min(), lo) - span * 0.35 - 0.5, max(v.max(), hi) + span * 0.35 + 0.5)
    fig.suptitle(f"{len(s)} repeated live mitigation runs (grey = each run, blue = mean with 95 % CI)",
                 x=0.01, ha="left", fontsize=11.5, fontweight="bold", color=INK, y=1.04)
    save(fig, "pub_live_repeats.png")


if __name__ == "__main__":
    fig_window(); fig_event(); fig_roc(); fig_ablation(); fig_models(); fig_repeats()
