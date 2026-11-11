#!/usr/bin/env python3
"""Chunked CICFlowMeter preprocessing for the extended offline experiment."""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.extended_common import OUTPUT_COLUMNS, canonicalize_extended_chunk, resolve_raw_columns


def main() -> None:
    parser = argparse.ArgumentParser(description="Preprocess CIC-DDoS2019 into extended CICFlowMeter features.")
    parser.add_argument("--input", required=True, help="Raw CSV file or directory containing CSVs")
    parser.add_argument("--output", default="data/processed/cicddos2019_extended.csv.gz")
    parser.add_argument("--chunksize", type=int, default=100_000)
    parser.add_argument("--compresslevel", type=int, default=1)
    args = parser.parse_args()

    input_path = Path(args.input)
    files = [input_path] if input_path.is_file() else sorted(input_path.glob("*.csv"))
    if not files:
        raise SystemExit(f"No CSV files found at: {input_path}")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise SystemExit(f"Output already exists: {output}. Remove or rename it before running to avoid accidental overwrite.")

    summary = {
        "input_files": [],
        "rows_read": 0,
        "rows_kept": 0,
        "class_counts": {"benign_0": 0, "attack_1": 0},
        "attack_family_counts": {},
        "missing_by_feature": {},
        "features": [],
        "excluded_identifiers": ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp", "SimillarHTTP", "Inbound"],
        "notes": [
            "Identifier fields are used only for group_id and are not model inputs.",
            "Attack family labels are retained for per-family evaluation.",
            "Duration, IAT, Active and Idle values are converted from microseconds to seconds.",
            "Exact duplicate source columns are omitted from the model schema.",
        ],
    }
    first_write = True

    for file in files:
        header = pd.read_csv(file, nrows=0, low_memory=False)
        resolved = resolve_raw_columns(header.columns)
        missing = [feature for feature, raw_col in resolved.items() if feature in OUTPUT_COLUMNS and raw_col is None]
        # A few optional features may be absent in a variant; required core fields may not.
        core = ["protocol", "flow_duration_sec", "total_fwd_packets", "total_backward_packets", "total_length_fwd_packets", "total_length_bwd_packets"]
        absent_core = [c for c in core if resolved.get(c) is None]
        if absent_core:
            raise ValueError(f"{file.name} is missing required core CICFlowMeter fields: {absent_core}")
        usecols = [c for c in header.columns if str(c).strip() in set(resolved.values()) and resolved.get(str(c).strip(), "__not_a_key__") is not None]
        # resolved maps canonical output names to source names; select all mapped source fields.
        usecols = sorted({v for v in resolved.values() if v is not None})
        print(f"Processing {file.name} in chunks of {args.chunksize:,} ...", flush=True)
        file_read = 0
        file_kept = 0
        for chunk in pd.read_csv(file, usecols=usecols, chunksize=args.chunksize, low_memory=False):
            file_read += len(chunk)
            converted = canonicalize_extended_chunk(chunk, source_file=file.name)
            file_kept += len(converted)
            summary["rows_read"] += len(chunk)
            summary["rows_kept"] += len(converted)
            if not converted.empty:
                summary["class_counts"]["benign_0"] += int((converted.label == 0).sum())
                summary["class_counts"]["attack_1"] += int((converted.label == 1).sum())
                families = converted["attack_family"].value_counts(dropna=False)
                for family, count in families.items():
                    summary["attack_family_counts"][str(family)] = summary["attack_family_counts"].get(str(family), 0) + int(count)
                converted.to_csv(
                    output,
                    index=False,
                    mode="w" if first_write else "a",
                    header=first_write,
                    compression={"method": "gzip", "compresslevel": args.compresslevel} if output.suffix == ".gz" else None,
                )
                first_write = False
        summary["input_files"].append({"file": str(file), "rows_read": file_read, "rows_kept": file_kept})
        print(f"  rows read={file_read:,}; kept={file_kept:,}", flush=True)

    if first_write:
        raise SystemExit("No labelled rows were retained; check source CSV labels.")
    summary["features"] = [c for c in OUTPUT_COLUMNS if c not in {"label", "attack_family", "group_id", "source_file"}]
    # Re-read only the output features in chunks to get accurate null counts.
    missing_counts = {c: 0 for c in summary["features"]}
    for chunk in pd.read_csv(output, usecols=summary["features"], chunksize=args.chunksize, low_memory=False):
        missing_counts.update({c: missing_counts[c] + int(chunk[c].isna().sum()) for c in summary["features"]})
    summary["missing_by_feature"] = missing_counts
    summary_path = output.with_suffix(output.suffix + ".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ["rows_read", "rows_kept", "class_counts", "attack_family_counts"]}, indent=2))
    print(f"Saved extended dataset: {output}")
    print(f"Saved summary: {summary_path}")


if __name__ == "__main__":
    main()
