"""Generate publication-quality figures from PROCESSED experiment outputs only.

Every figure is drawn from a real results CSV; nothing is illustrative. If an
input is missing the corresponding figure is skipped with a printed note.

Outputs: experiments/results/figures/*.png (+ a few .csv tables for the paper).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
plt.rcParams.update({"font.size": 11, "figure.dpi": 150, "axes.grid": True, "grid.alpha": 0.3})


def savefig(fig, path):
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print("wrote", path)


def roc_pr(pred_dir: Path, fig_dir: Path):
    from sklearn.metrics import roc_curve, precision_recall_curve, auc
    files = sorted(pred_dir.glob("predictions_*.csv"))
    if not files:
        return
    fig1, ax1 = plt.subplots(figsize=(5, 4))
    fig2, ax2 = plt.subplots(figsize=(5, 4))
    for f in files:
        name = f.stem.replace("predictions_", "")
        d = pd.read_csv(f)
        if d["label"].nunique() < 2:
            continue
        fpr, tpr, _ = roc_curve(d["label"], d["prob"])
        pr, rc, _ = precision_recall_curve(d["label"], d["prob"])
        ax1.plot(fpr, tpr, label=f"{name} (AUC={auc(fpr,tpr):.3f})")
        ax2.plot(rc, pr, label=f"{name} (AP={auc(rc,pr):.3f})")
    ax1.plot([0, 1], [0, 1], "k--", lw=0.8)
    ax1.set(xlabel="False positive rate", ylabel="True positive rate", title="ROC — destination windows (test)")
    ax2.set(xlabel="Recall", ylabel="Precision", title="Precision–Recall — destination windows (test)")
    ax1.legend(fontsize=8); ax2.legend(fontsize=8)
    savefig(fig1, fig_dir / "roc_curves.png")
    savefig(fig2, fig_dir / "pr_curves.png")


def ablation_bars(window_csv: Path, fig_dir: Path):
    d = pd.read_csv(window_csv)
    ov = d[d.scope == "overall"].set_index("method")
    order = ["flow_ml_only_raw", "rule_statistical", "abl_ml", "abl_ml_src", "abl_ml_rate",
             "abl_ml_src_rate", "full_temporal", "proposed"]
    order = [m for m in order if m in ov.index]
    metrics = ["recall", "specificity", "f1", "balanced_accuracy"]
    x = np.arange(len(order)); w = 0.2
    fig, ax = plt.subplots(figsize=(11, 5))
    for i, m in enumerate(metrics):
        ax.bar(x + (i - 1.5) * w, ov.loc[order, m], w, label=m.replace("_", " "))
    ax.set_xticks(x); ax.set_xticklabels(order, rotation=20, ha="right")
    ax.set_ylim(0, 1.02); ax.set_ylabel("score")
    ax.set_title("Ablation / baselines — window-level (held-out test)")
    ax.legend(ncol=4, fontsize=9)
    savefig(fig, fig_dir / "ablation_window.png")
    # FPR separately (small numbers)
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(np.arange(len(order)), ov.loc[order, "fpr"], color="#c44")
    ax.set_xticks(np.arange(len(order))); ax.set_xticklabels(order, rotation=20, ha="right")
    ax.set_ylabel("false positive rate")
    ax.set_title("False-positive rate by method (lower is better)")
    savefig(fig, fig_dir / "fpr_by_method.png")


def confusion(window_csv: Path, fig_dir: Path):
    d = pd.read_csv(window_csv)
    ov = d[(d.scope == "overall")].set_index("method")
    for name in [m for m in ("flow_ml_only_raw", "proposed") if m in ov.index]:
        r = ov.loc[name]
        cm = np.array([[r.tn, r.fp], [r.fn, r.tp]], dtype=int)
        fig, ax = plt.subplots(figsize=(4, 3.4))
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks([0, 1], ["Benign", "Attack"]); ax.set_yticks([0, 1], ["Benign", "Attack"])
        ax.set_xlabel("Predicted"); ax.set_ylabel("True"); ax.set_title(f"{name} — window confusion")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, f"{v}", ha="center", va="center",
                    color="white" if v > cm.max() / 2 else "black")
        fig.colorbar(im, ax=ax, fraction=0.046)
        savefig(fig, fig_dir / f"confusion_{name}.png")


def latency(event_summary: Path, fig_dir: Path):
    d = pd.read_csv(event_summary)
    d = d.dropna(subset=["mean_latency_s"])
    if d.empty:
        return
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(np.arange(len(d)), d.mean_latency_s, yerr=d.std_latency_s.fillna(0), capsize=4, color="#48c")
    ax.set_ylabel("detection latency (s)"); ax.set_title("Detection latency by method (test, mean±sd)")
    ax.set_xticks(np.arange(len(d))); ax.set_xticklabels(d.method, rotation=15, ha="right")
    savefig(fig, fig_dir / "detection_latency.png")


def timeseries(raw_campaign: Path, fig_dir: Path, scenario="C"):
    """One representative run: victim pps/sources over time with attack span."""
    runs = sorted((raw_campaign).glob(f"{scenario}_*"))
    if not runs:
        return
    run = runs[0]
    tele = run / "telemetry.jsonl"
    man = json.loads((run / "manifest.json").read_text())
    e0 = man["epoch0"]; vip = man["victim_ip"]
    ts, pps, srcs, resp, mlshare = [], [], [], [], []
    for line in tele.open():
        r = json.loads(line)
        if r.get("event") != "window":
            continue
        f = r["dst"].get(vip)
        if not f:
            continue
        ts.append(r["ts"] - e0); pps.append(f["pps"]); srcs.append(f["n_sources"])
        resp.append(f["response_ratio"]); mlshare.append(f["ml_pps_share"])
    if not ts:
        return
    a0 = man.get("attack_start"); a1 = man.get("attack_end")
    fig, axes = plt.subplots(2, 1, figsize=(9, 6), sharex=True)
    axes[0].plot(ts, pps, "-o", ms=3, label="interval pps")
    axes[0].set_ylabel("packets/s"); axes[0].legend(loc="upper left")
    ax0b = axes[0].twinx(); ax0b.plot(ts, srcs, "-s", ms=3, color="#c60", label="sources"); ax0b.set_ylabel("sources")
    ax0b.legend(loc="upper right")
    axes[1].plot(ts, resp, "-o", ms=3, label="response ratio")
    axes[1].plot(ts, mlshare, "-^", ms=3, label="ML pps share")
    axes[1].set_ylabel("ratio / share"); axes[1].set_xlabel("time (s)"); axes[1].legend()
    for ax in axes:
        if a0 and a1:
            ax.axvspan(a0, a1, color="red", alpha=0.12)
    axes[0].set_title(f"Scenario {scenario} victim {vip} — counter-delta features ({run.name})")
    savefig(fig, fig_dir / f"timeseries_{scenario}.png")


def overhead(raw_campaign: Path, fig_dir: Path):
    rows = []
    for run in sorted(raw_campaign.glob("*_*")):
        rc = run / "resources.csv"
        man = run / "manifest.json"
        if not rc.exists() or not man.exists():
            continue
        m = json.loads(man.read_text())
        d = pd.read_csv(rc)
        for proc, g in d.groupby("proc"):
            rows.append({"scenario": m["scenario"], "proc": proc,
                         "cpu_mean": g.cpu_percent.mean(), "cpu_p95": g.cpu_percent.quantile(.95),
                         "rss_mb": g.rss_kb.max() / 1024})
    if not rows:
        return
    df = pd.DataFrame(rows)
    df.to_csv(fig_dir / "overhead_summary.csv", index=False)
    piv = df.groupby(["scenario", "proc"]).cpu_mean.mean().unstack()
    fig, ax = plt.subplots(figsize=(8, 4))
    piv.plot(kind="bar", ax=ax)
    ax.set_ylabel("mean CPU %"); ax.set_title("Controller / ML-API CPU by scenario")
    savefig(fig, fig_dir / "overhead_cpu.png")


def mitigation_effect(mit_dir: Path, fig_dir: Path):
    """Probe goodput/RTT with vs without mitigation, if a comparison table exists."""
    f = mit_dir / "mitigation_effect.csv"
    if not f.exists():
        return
    d = pd.read_csv(f)
    fig, ax = plt.subplots(figsize=(8, 4))
    d.set_index("condition")[["probe_udp_goodput_mbps", "probe_loss_pct"]].plot(kind="bar", ax=ax, secondary_y="probe_loss_pct")
    ax.set_title("Legitimate probe under attack: no-mitigation vs mitigation")
    savefig(fig, fig_dir / "mitigation_effect.png")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", default="test")
    ap.add_argument("--calib", default="calibration")
    args = ap.parse_args()
    proc = ROOT / "experiments/results/processed" / args.test
    raw = ROOT / "experiments/results/raw" / args.test
    fig_dir = ROOT / "experiments/results/figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    if (proc / "window_metrics.csv").exists():
        ablation_bars(proc / "window_metrics.csv", fig_dir)
        confusion(proc / "window_metrics.csv", fig_dir)
        roc_pr(proc, fig_dir)
    else:
        print("no window_metrics yet:", proc)
    if (proc / "event_summary.csv").exists():
        latency(proc / "event_summary.csv", fig_dir)
    for scn in ["C", "F", "G", "B"]:
        timeseries(raw if raw.exists() else ROOT / "experiments/results/raw" / args.calib, fig_dir, scn)
    overhead(raw if raw.exists() else ROOT / "experiments/results/raw" / args.calib, fig_dir)
    mitigation_effect(proc, fig_dir)
    print("figures in", fig_dir)


if __name__ == "__main__":
    main()
