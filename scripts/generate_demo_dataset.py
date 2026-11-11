#!/usr/bin/env python3
"""Create a synthetic dataset for pipeline smoke tests only (not research metrics)."""
from pathlib import Path
import argparse
import numpy as np
import pandas as pd


def generate(rows=10_000, seed=42):
    rng = np.random.default_rng(seed)
    labels = rng.integers(0, 2, size=rows)
    protocol = rng.choice([1, 6, 17], p=[0.12, 0.53, 0.35], size=rows)
    duration = rng.lognormal(mean=-0.1, sigma=1.1, size=rows)
    packet_count = np.where(labels == 1,
                            rng.lognormal(3.6, 1.0, rows),
                            rng.lognormal(2.7, 1.05, rows)).astype(int) + 1
    # Add slow floods and benign CDN bursts so the synthetic data is not trivially separable.
    attack_slow = (labels == 1) & (rng.random(rows) < 0.22)
    benign_burst = (labels == 0) & (rng.random(rows) < 0.16)
    packet_count[attack_slow] = rng.integers(4, 45, attack_slow.sum())
    packet_count[benign_burst] = rng.integers(80, 600, benign_burst.sum())
    duration[attack_slow] = rng.uniform(1.0, 20.0, attack_slow.sum())
    duration[benign_burst] = rng.uniform(0.05, 0.8, benign_burst.sum())
    avg_size = np.clip(rng.lognormal(5.2, 0.55, rows), 40, 1400)
    byte_count = (packet_count * avg_size).astype(int)
    packet_rate = packet_count / np.maximum(duration, 1e-6)
    byte_rate = byte_count / np.maximum(duration, 1e-6)
    # Label noise represents imperfect labelling only for software tests.
    flip = rng.random(rows) < 0.035
    labels[flip] = 1 - labels[flip]
    flow_id = [f"demo-flow-{i:07d}" for i in range(rows)]
    frame = pd.DataFrame({
        "timestamp": 1_700_000_000 + np.arange(rows),
        "flow_id": flow_id,
        "ip_src": [f"10.0.{(i // 250) % 200}.{(i % 250) + 1}" for i in range(rows)],
        "ip_dst": [f"10.1.{(i // 250) % 200}.{(i % 250) + 1}" for i in range(rows)],
        "tp_src": rng.integers(1024, 65535, rows),
        "tp_dst": rng.choice([53, 80, 443, 8080, 5001], size=rows),
        "ip_proto": protocol,
        "flow_duration_sec": duration,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "packet_count_per_second": packet_rate,
        "byte_count_per_second": byte_rate,
        "label": labels,
    })
    return frame


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="data/demo/demo_flows_raw.csv")
    args = parser.parse_args()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    frame = generate(args.rows, args.seed)
    frame.to_csv(out, index=False)
    print(f"Wrote {len(frame):,} synthetic rows to {out}")
    print("This dataset is only for smoke testing; it is not a captured/public benchmark dataset.")


if __name__ == "__main__":
    main()
