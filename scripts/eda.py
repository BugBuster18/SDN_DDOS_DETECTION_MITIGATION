#!/usr/bin/env python3
"""Basic data quality report for preprocessed flow datasets."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
import json
import numpy as np
import pandas as pd
from ddos_ml.features import FEATURE_COLUMNS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/processed/flows.csv")
    parser.add_argument("--output-dir", default="results/eda")
    args = parser.parse_args()
    df = pd.read_csv(args.input)
    out = Path(args.output_dir); out.mkdir(parents=True, exist_ok=True)
    report = {
        "rows": int(len(df)),
        "columns": list(df.columns),
        "class_counts": {str(k): int(v) for k, v in df["label"].value_counts(dropna=False).to_dict().items()},
        "duplicate_feature_rows": int(df.duplicated(subset=FEATURE_COLUMNS).sum()),
        "missing_by_feature": {c: int(df[c].isna().sum()) for c in FEATURE_COLUMNS},
        "infinite_by_feature": {c: int(np.isinf(pd.to_numeric(df[c], errors="coerce")).sum()) for c in FEATURE_COLUMNS},
        "summary": df[FEATURE_COLUMNS].describe().replace({np.nan: None}).to_dict(),
    }
    (out / "eda_summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    df["label"].value_counts().sort_index().rename(index={0: "BENIGN", 1: "DoS/DDoS"}).to_csv(out / "class_distribution.csv", header=["rows"])
    print(json.dumps({k: report[k] for k in ["rows", "class_counts", "duplicate_feature_rows", "missing_by_feature"]}, indent=2))

if __name__ == "__main__":
    main()
