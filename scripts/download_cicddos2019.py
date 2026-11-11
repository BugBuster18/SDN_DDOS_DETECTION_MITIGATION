#!/usr/bin/env python3
"""Download original CIC-DDoS2019 flow CSVs from a public Hugging Face mirror.

The official UNB page remains the canonical source. This script uses a public
mirror of the published per-attack CSVs because the official download portal may
require a form. The downloaded files are large; choose a small subset first.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

REPO_ID = "baalajimaestro/CICDDoS2019"
REPO_SUBDIR = "01-12/"
ALL_FILES = [
    "DrDoS_DNS.csv",
    "DrDoS_LDAP.csv",
    "DrDoS_MSSQL.csv",
    "DrDoS_NTP.csv",
    "DrDoS_NetBIOS.csv",
    "DrDoS_SNMP.csv",
    "DrDoS_SSDP.csv",
    "DrDoS_UDP.csv",
    "Syn.csv",
    "TFTP.csv",
    "UDPLag.csv",
]
# A starter subset that is materially smaller than downloading all attack families.
DEFAULT_FILES = ["UDPLag.csv", "Syn.csv", "DrDoS_NTP.csv"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download CIC-DDoS2019 per-attack CSVs from a public Hugging Face mirror."
    )
    parser.add_argument(
        "--files", nargs="+", default=None,
        help="CSV filenames to download (default: UDPLag.csv Syn.csv DrDoS_NTP.csv).",
    )
    parser.add_argument("--all", action="store_true", help="Download all 11 flow CSVs (about 22.3 GB).")
    parser.add_argument(
        "--output-dir", default="data/raw/CICDDoS2019/01-12",
        help="Destination directory (default: data/raw/CICDDoS2019/01-12).",
    )
    parser.add_argument("--list", action="store_true", help="List filenames without downloading.")
    args = parser.parse_args()

    selected = ALL_FILES if args.all else (args.files or DEFAULT_FILES)
    unknown = sorted(set(selected) - set(ALL_FILES))
    if unknown:
        parser.error(f"Unknown filename(s): {', '.join(unknown)}. Choose from: {', '.join(ALL_FILES)}")

    print(f"Dataset repository: {REPO_ID} (public mirror of CIC-DDoS2019 CSV files)")
    print(f"Files selected ({len(selected)}):")
    for name in selected:
        print(f"  - {name}")
    print(f"Destination: {Path(args.output_dir).resolve()}")
    if args.list:
        return 0

    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("Missing optional dependency. Install it with: pip install -r requirements-download.txt", file=sys.stderr)
        return 2

    target = Path(args.output_dir)
    target.mkdir(parents=True, exist_ok=True)
    failures = []
    for name in selected:
        remote_name = REPO_SUBDIR + name
        try:
            path = hf_hub_download(
                repo_id=REPO_ID,
                repo_type="dataset",
                filename=remote_name,
                local_dir=str(target.parent),
            )
            print(f"Downloaded: {path}")
        except Exception as exc:  # network, storage, or hub errors are shown per file
            failures.append((name, str(exc)))
            print(f"FAILED: {name}: {exc}", file=sys.stderr)

    if failures:
        print("\nSome files could not be downloaded:", file=sys.stderr)
        for name, error in failures:
            print(f"- {name}: {error}", file=sys.stderr)
        print("Retry when network access is available. Partial downloads are kept in the Hub cache.", file=sys.stderr)
        return 1

    print("\nDownload complete. Next run:")
    print(
        "python scripts/preprocess_dataset.py "
        f"--input {target.parent} --output data/processed/cicddos2019_flows.csv"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
