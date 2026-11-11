"""Chunked CSV preprocessing for CIC-DDoS2019, CICIDS2017, and SDN flow logs."""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import pandas as pd

from .features import OUTPUT_COLUMNS, canonicalize_frame


def preprocess_paths(inputs: list[Path], output: Path, *, chunksize: int, numeric_label_meaning: str) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    summary = {"input_files": [], "rows_read": 0, "rows_kept": 0, "class_counts": {"benign_0": 0, "attack_1": 0}, "errors": []}
    wrote_header = False

    for source in inputs:
        if source.is_dir():
            files = sorted(p for p in source.rglob("*.csv") if p.resolve() != output.resolve())
        else:
            files = [source]
        for csv_path in files:
            if not csv_path.exists() or csv_path.stat().st_size == 0:
                summary["errors"].append({"file": str(csv_path), "error": "empty or missing file"})
                continue
            file_kept = 0
            try:
                reader = pd.read_csv(csv_path, chunksize=chunksize, low_memory=False, encoding_errors="replace")
                for chunk in reader:
                    summary["rows_read"] += len(chunk)
                    clean = canonicalize_frame(chunk, numeric_label_meaning=numeric_label_meaning)
                    if clean.empty:
                        continue
                    clean.to_csv(output, mode="a", header=not wrote_header, index=False)
                    wrote_header = True
                    file_kept += len(clean)
                    summary["rows_kept"] += len(clean)
                    counts = clean["label"].value_counts().to_dict()
                    summary["class_counts"]["benign_0"] += int(counts.get(0, 0))
                    summary["class_counts"]["attack_1"] += int(counts.get(1, 0))
                summary["input_files"].append({"file": str(csv_path), "rows_kept": file_kept})
            except Exception as exc:
                summary["errors"].append({"file": str(csv_path), "error": str(exc)})

    if not wrote_header:
        raise RuntimeError(
            "No labelled flow rows were produced. Check that the CSV has a Label column, "
            "packet/byte counters, and recognised BENIGN/DoS/DDoS labels. "
            "For numeric labels from SNT-ddos, pass --numeric-label-meaning one_is_benign."
        )
    summary_path = output.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Preprocess CICFlowMeter or SDN flow CSV files.")
    parser.add_argument("--input", required=True, help="CSV file or directory containing CSV files")
    parser.add_argument("--output", default="data/processed/flows.csv")
    parser.add_argument("--chunksize", type=int, default=100_000)
    parser.add_argument("--numeric-label-meaning", choices=["zero_is_benign", "one_is_benign"], default="zero_is_benign")
    args = parser.parse_args()
    summary = preprocess_paths([Path(args.input)], Path(args.output), chunksize=args.chunksize,
                               numeric_label_meaning=args.numeric_label_meaning)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
