"""Offline, deterministic replay of logged telemetry into labelled feature tables.

Reads each run's telemetry.jsonl (per-poll per-flow counter deltas, already
computed live by the controller) and manifest.json (seeded ground truth), then
re-derives destination-window and (source,destination)-window features with the
exact same :class:`DestinationWindowAnalyzer` used live. Ground-truth labels
come only from the seeded schedule, never from the model.

Outputs two long CSVs under <results>/<campaign>/tables/:
  dst_windows.csv   one row per (run, poll, destination)
  src_windows.csv   one row per (run, poll, source, destination)

These tables are the single input to model fitting (fit_models.py) and to the
detection/ablation evaluation (evaluate.py). Re-running replay never touches
Mininet, so features and ablations are reproducible from raw telemetry.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ddos_ml.temporal_features import (  # noqa: E402
    DestinationWindowAnalyzer, FlowWindowRecord, WINDOW_FEATURES, SOURCE_FEATURES,
)

# telemetry flow-row column order (see hybrid_controller._process)
F_SRC, F_SPORT, F_DST, F_DPORT, F_PROTO, F_ICMP, F_STATUS, F_DPKT, F_DBYTE, \
    F_PKT, F_BYTE, F_DUR, F_MLP = range(13)


def attack_intervals(manifest: dict):
    """Return (victim_ip, [(src_ip, start_epoch, end_epoch)]) for attack events."""
    e0 = manifest["epoch0"]
    victim_ip = manifest["victim_ip"]
    out = []
    for e in manifest["events"]:
        if e["role"] != "attack":
            continue
        start = e.get("epoch_start", e0 + e["start"])
        out.append((e["src_ip"], start, start + e["duration"]))
    return victim_ip, out


def record_from_row(row) -> FlowWindowRecord:
    key = (row[F_SRC], int(row[F_SPORT]), row[F_DST], int(row[F_DPORT]), int(row[F_PROTO]), int(row[F_ICMP]))
    rec = FlowWindowRecord(key, int(row[F_DPKT]), int(row[F_DBYTE]), 0.0, row[F_STATUS],
                           int(row[F_PKT]), int(row[F_BYTE]), float(row[F_DUR]))
    rec.ml_prob = row[F_MLP]
    return rec


def replay_run(run_dir: Path, ml_threshold: float = 0.5):
    manifest = json.loads((run_dir / "manifest.json").read_text())
    victim_ip, atk = attack_intervals(manifest)
    scn, seed = manifest["scenario"], manifest["seed"]
    attacker_ips = sorted({a[0] for a in atk})
    analyzer = DestinationWindowAnalyzer()
    dst_rows, src_rows = [], []
    with (run_dir / "telemetry.jsonl").open() as fh:
        for line in fh:
            r = json.loads(line)
            if r.get("event") != "window":
                continue
            ts = r["ts"]
            interval = r["interval"]
            flows = {}
            for frow in r["flows"]:
                rec = record_from_row(frow)
                flows[rec.key] = rec
            dst_feats, src_feats = analyzer.compute(flows, interval, r.get("packet_in_by_dst", {}), ml_threshold)
            # dst-window label: this destination is the victim AND the window
            # overlaps any attack interval (window covers [ts-interval, ts]).
            for dst, feats in dst_feats.items():
                under = dst == victim_ip and any(s < ts and e > ts - interval for _, s, e in atk)
                dst_rows.append({"scenario": scn, "seed": seed, "ts": round(ts, 3), "interval": round(interval, 3),
                                 "dst": dst, "is_victim": int(dst == victim_ip), "label": int(under),
                                 **{k: feats.get(k, 0.0) for k in WINDOW_FEATURES}})
            for (src, dst), feats in src_feats.items():
                is_atk = (dst == victim_ip and any(a_src == src and s < ts and e > ts - interval
                                                   for a_src, s, e in atk))
                src_rows.append({"scenario": scn, "seed": seed, "ts": round(ts, 3), "interval": round(interval, 3),
                                 "src": src, "dst": dst, "is_victim_dst": int(dst == victim_ip),
                                 "is_attacker": int(src in attacker_ips), "label": int(is_atk),
                                 **{k: feats.get(k, 0.0) for k in SOURCE_FEATURES}})
    return dst_rows, src_rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--ml-threshold", type=float, default=0.5)
    args = ap.parse_args()
    base = ROOT / "experiments" / "results" / "raw" / args.campaign
    runs = sorted([d for d in base.iterdir() if (d / "telemetry.jsonl").exists()])
    all_dst, all_src = [], []
    for d in runs:
        try:
            dr, sr = replay_run(d, args.ml_threshold)
            all_dst += dr
            all_src += sr
            print(f"replayed {d.name}: {len(dr)} dst-windows, {len(sr)} src-windows")
        except Exception as exc:
            print(f"FAILED {d.name}: {exc!r}")
    out = base / "tables"
    out.mkdir(exist_ok=True)
    for name, rows in (("dst_windows.csv", all_dst), ("src_windows.csv", all_src)):
        if not rows:
            continue
        with (out / name).open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {out/name}: {len(rows)} rows")


if __name__ == "__main__":
    main()
