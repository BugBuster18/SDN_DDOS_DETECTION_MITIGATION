"""Quantify mitigation effect on the LEGITIMATE probe (goodput / loss / RTT).

Reads matched runs from two campaigns of the same scenario+seed:
  --nomit  (attack, detection only, no blocking)   e.g. mit_nomit
  --enforce(attack, scoped mitigation enabled)      e.g. mit_enforce
and the benign-only baseline runs from the calibration/test A scenario.

Per run it segments the iperf3 UDP probe (h7) into pre / during / post attack
using manifest epochs, and the ping probe (h13) RTT likewise, then writes
<processed>/<enforce>/mitigation_effect.csv consumed by plots.py.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]


def probe_intervals(run: Path):
    f = run / "probe_iperf.json"
    if not f.exists():
        return []
    try:
        data = json.loads(f.read_text())
    except Exception:
        return []
    start = data.get("start", {}).get("timestamp", {}).get("timesecs")
    # Receiver-side intervals (loss/jitter) come from the server output when
    # --get-server-output was used; fall back to client intervals for goodput.
    server = data.get("server_output_json") or {}
    recv = {round(iv.get("sum", {}).get("start", -1)): iv.get("sum", {}) for iv in server.get("intervals", [])}
    out = []
    for iv in data.get("intervals", []):
        s = iv.get("sum", {})
        r = recv.get(round(s.get("start", -1)), {})
        out.append({"t": s.get("start"), "mbps": r.get("bits_per_second", s.get("bits_per_second", 0)) / 1e6,
                    "loss_pct": r.get("lost_percent", s.get("lost_percent", 0.0)),
                    "jitter_ms": r.get("jitter_ms", s.get("jitter_ms", 0.0))})
    return out, start


def ping_rtts(run: Path):
    f = run / "hosts"
    rtts = []
    if f.exists():
        for log in f.glob("*probe_ping*"):
            for line in log.read_text(errors="ignore").splitlines():
                m = re.search(r"time=([\d.]+) ms", line)
                t = re.search(r"\[(\d+\.\d+)\]", line)
                if m:
                    rtts.append((float(t.group(1)) if t else None, float(m.group(1))))
    return rtts


def segment(run: Path, condition: str):
    man = json.loads((run / "manifest.json").read_text())
    e0 = man["epoch0"]
    atk = [(e.get("epoch_start"), e.get("epoch_start", 0) + e["duration"]) for e in man["events"] if e["role"] == "attack"]
    a0 = min((a[0] for a in atk), default=None)
    a1 = max((a[1] for a in atk), default=None)
    rows = []
    pr = probe_intervals(run)
    if pr:
        intervals, pstart = pr
        for iv in intervals:
            if iv["t"] is None or pstart is None:
                continue
            abs_t = pstart + iv["t"]
            phase = "during" if (a0 and a1 and a0 <= abs_t <= a1) else ("post" if (a1 and abs_t > a1) else "pre")
            rows.append({"scenario": man["scenario"], "seed": man["seed"], "condition": condition,
                         "phase": phase, "metric": "probe", **iv})
    for t, rtt in ping_rtts(run):
        phase = "during" if (t and a0 and a1 and a0 <= t <= a1) else ("post" if (t and a1 and t > a1) else "pre")
        rows.append({"scenario": man["scenario"], "seed": man["seed"], "condition": condition,
                     "phase": phase, "metric": "ping", "rtt_ms": rtt})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nomit", default="mit_nomit")
    ap.add_argument("--enforce", default="mit_enforce")
    args = ap.parse_args()
    raw = ROOT / "experiments/results/raw"
    rows = []
    for camp, cond in [(args.nomit, "no_mitigation"), (args.enforce, "mitigation")]:
        base = raw / camp
        if not base.exists():
            print("missing campaign", base); continue
        for run in sorted(base.glob("*_*")):
            if (run / "manifest.json").exists():
                rows += segment(run, cond)
    if not rows:
        print("no probe data found"); return
    df = pd.DataFrame(rows)
    out = ROOT / "experiments/results/processed" / args.enforce
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "mitigation_effect_raw.csv", index=False)
    # summary: probe goodput/loss during attack, and ping RTT during attack, per condition
    summ = []
    for cond, g in df.groupby("condition"):
        pg = g[(g.metric == "probe") & (g.phase == "during")]
        pr = g[(g.metric == "ping") & (g.phase == "during")]
        summ.append({"condition": cond,
                     "probe_udp_goodput_mbps": pg["mbps"].mean(),
                     "probe_loss_pct": pg["loss_pct"].mean(),
                     "probe_jitter_ms": pg["jitter_ms"].mean(),
                     "ping_rtt_ms_during": pr["rtt_ms"].mean(),
                     "ping_rtt_ms_p95": pr["rtt_ms"].quantile(0.95) if len(pr) else np.nan})
    s = pd.DataFrame(summ)
    s.to_csv(out / "mitigation_effect.csv", index=False)
    print(s.round(3).to_string(index=False))
    print("wrote", out / "mitigation_effect.csv")


if __name__ == "__main__":
    main()
