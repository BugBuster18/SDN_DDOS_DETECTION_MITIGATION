"""Figures for the revised report (report/v2/figures)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "report" / "v2" / "figures"
OUT.mkdir(parents=True, exist_ok=True)
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
plt.rcParams.update({"font.size": 10, "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2,
                     "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.7, "figure.facecolor": SURF,
                     "axes.facecolor": SURF, "savefig.dpi": 160, "savefig.bbox": "tight"})


def fig_cross_dataset():
    d = pd.read_csv(ROOT / "experiments/results/flow_multidataset_v2/cross_dataset_metrics.csv")
    h = d[d.model == "Hist Gradient Boosting"].pivot(index="train", columns="test", values="balanced_accuracy")
    h = h.loc[["CIC-DDoS2019", "CSE-CIC-IDS2018", "Combined"], ["CIC-DDoS2019", "CSE-CIC-IDS2018"]]
    fig, ax = plt.subplots(figsize=(6.2, 3.0))
    x = np.arange(len(h.index))
    w = 0.36
    for j, col in enumerate(h.columns):
        b = ax.bar(x + (j - 0.5) * (w + 0.02), h[col], w, color=C[j], label="tested on " + col)
        for r, v in zip(b, h[col]):
            ax.text(r.get_x() + r.get_width() / 2, v + 0.015, "%.3f" % v, ha="center", fontsize=8, color=INK)
    ax.axhline(0.5, color=INK2, lw=1, ls="--")
    ax.text(-0.55, 0.515, "chance", fontsize=8, color=INK2, ha="left")
    ax.set_xticks(x, ["trained on\nCIC-DDoS2019", "trained on\nCSE-CIC-IDS2018", "trained on\nboth (deployed)"])
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("balanced accuracy")
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=2)
    ax.grid(axis="x", visible=False)
    fig.savefig(OUT / "fig_cross_dataset.png")
    plt.close(fig)


def fig_timeline(kind="udp"):
    fig, axes = plt.subplots(2, 1, figsize=(7.2, 4.6), sharex=True)
    for col, (ses, lab) in enumerate([("test_det2", "no mitigation"), ("test_mit", "with mitigation")]):
        sd = ROOT / "experiments/results/large" / ses
        if not (sd / "legit_timeseries.csv").exists():
            continue
        s = json.loads((sd / "session.json").read_text())
        seg = [g for g in s["segments"] if g["kind"] == kind][0]
        seg_events = sorted({(round(e["epoch_start"] - seg["start"], 1), round(e["epoch_start"] - seg["start"] + e["duration"], 1)) for e in seg["events"]})
        ts = pd.read_csv(sd / "legit_timeseries.csv")
        ts["t"] = ts["sec"] - seg["start"]
        ts = ts[(ts.t >= -15) & (ts.t <= seg["duration"] + 25)]
        axes[0].plot(ts.t, ts.victim_mbps, color=C[col], lw=2, label=lab)
        http = ts.http_success.rolling(3, min_periods=1).mean()
        axes[1].plot(ts.t, 100 * http, color=C[col], lw=2, label=lab)
        if ses == "test_mit" and (sd / "events.json").exists():
            ev = json.loads((sd / "events.json").read_text())["events"]
            r = [e["installed"] - seg["start"] for e in ev if e["type"] == "rule_installed"
                 and seg["start"] - 1 <= e["installed"] <= seg["end"]]
            if r:
                for a in axes:
                    a.axvline(min(r), color=C[1], lw=1, ls=":")
                axes[0].text(min(r) + 0.5, 2, "first drop rules", color=INK2, fontsize=8)
    for a in axes:
        for e in seg_events:
            a.axvspan(e[0], e[1], color=GRID, alpha=0.5, lw=0)
    cap = json.loads((ROOT / "experiments/results/large/test_det2/session.json").read_text()).get("victim_bw_mbps", 25)
    axes[0].axhline(cap, color=INK2, lw=1, ls="--")
    axes[0].text(-14, cap + 1, "victim link capacity %g Mbit/s" % cap, fontsize=8, color=INK2)
    axes[0].set_ylabel("delivered to victim\n(Mbit/s)")
    axes[1].set_ylabel("legitimate HTTP\nsuccess (%)")
    axes[1].set_xlabel("seconds from attack start (shaded = attack active)")
    axes[1].set_ylim(-5, 105)
    axes[0].legend(frameon=False, fontsize=8, loc="upper right")
    fig.savefig(OUT / ("fig_timeline_%s.png" % kind))
    plt.close(fig)


def fig_legit_bars():
    rows = []
    for ses, lab in [("test_det2", "no mitigation"), ("test_mit", "with mitigation")]:
        f = ROOT / "experiments/results/large" / ses / "legit_phases.csv"
        if f.exists():
            d = pd.read_csv(f)
            d["cond"] = lab
            rows.append(d)
    if not rows:
        return
    d = pd.concat(rows)
    base = d[d.phase == "baseline"].http_success.mean()
    a = d[d.phase.isin(["attack"])]
    p = a.pivot_table(index="kind", columns="cond", values="http_success")
    order = [k for k in ["udp", "syn", "icmp", "lowrate", "pulsing", "spoof", "mixed", "protoswitch", "reattack"] if k in p.index]
    p = p.loc[order]
    fig, ax = plt.subplots(figsize=(7.4, 3.0))
    x = np.arange(len(p))
    w = 0.38
    for j, col in enumerate(["no mitigation", "with mitigation"]):
        if col in p:
            ax.bar(x + (j - 0.5) * (w + 0.02), 100 * p[col], w, color=C[j], label=col)
    ax.axhline(100 * base, color=INK2, lw=1, ls="--", label="benign baseline (%.0f%%)" % (100 * base))
    nice = {"lowrate": "low-rate", "protoswitch": "protocol\nswitch", "reattack": "re-attack", "mixed": "mixed\nUDP+SYN"}
    ax.set_xticks(x, [nice.get(k, k.upper() if k in ("udp", "syn", "icmp") else k) for k in order], fontsize=8)
    ax.set_ylabel("legitimate HTTP success\nduring attack (%)")
    ax.set_ylim(0, 112)
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=3)
    ax.grid(axis="x", visible=False)
    fig.savefig(OUT / "fig_legit_http.png")
    plt.close(fig)


def fig_methods(name="large_test"):
    f = ROOT / "experiments/results/processed" / name / "window_metrics.csv"
    if not f.exists():
        return
    d = pd.read_csv(f)
    d = d[d.part == "all"].set_index("method")
    order = ["pps_threshold", "src_entropy", "dst_entropy", "flow_ml_only", "hybrid"]
    lab = ["pps per\ndestination", "source-IP\nentropy", "destination-IP\nentropy", "flow-ML\nonly", "proposed\nhybrid"]
    fig, ax = plt.subplots(figsize=(7.0, 2.9))
    x = np.arange(len(order))
    w = 0.38
    ax.bar(x - 0.2, d.loc[order, "recall"], w, color=C[0], label="recall")
    ax.bar(x + 0.2, d.loc[order, "f1"].fillna(0), w, color=C[2], label="F1")
    lab = ["%s\nFPR %.1f%%" % (l, 100 * d.loc[m, "fpr"]) for l, m in zip(lab, order)]
    ax.set_xticks(x, lab, fontsize=8)
    ax.set_ylim(0, 1.05)
    ax.legend(frameon=False, fontsize=8, loc="upper left", ncol=2)
    ax.grid(axis="x", visible=False)
    fig.savefig(OUT / ("fig_methods_%s.png" % name))
    plt.close(fig)


if __name__ == "__main__":
    fig_cross_dataset()
    fig_methods("chain_baselines")
    fig_methods("large_test")
    for k in ("udp", "pulsing", "reattack"):
        try:
            fig_timeline(k)
        except Exception as e:
            print("timeline", k, e)
    fig_legit_bars()
    print("figures in", OUT)
