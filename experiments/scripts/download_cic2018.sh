#!/usr/bin/env bash
# Download selected CSE-CIC-IDS2018 CICFlowMeter CSVs (public AWS Open Data bucket, no credentials).
# Only four day-files (~1.42 GB total) are downloaded; the 4 GB Tuesday file and raw PCAPs are not.
set -euo pipefail
OUT="${1:-data/raw/cic2018}"
mkdir -p "$OUT"
BASE="https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms"
for day in Wednesday-21-02-2018 Friday-16-02-2018 Thursday-15-02-2018 Thursday-22-02-2018; do
  f="${day}_TrafficForML_CICFlowMeter.csv"
  if [ -s "$OUT/$f" ]; then echo "exists: $f"; continue; fi
  echo "downloading $f"
  curl -sS --fail -o "$OUT/$f.part" "$BASE/$f"
  mv "$OUT/$f.part" "$OUT/$f"
done
(cd "$OUT" && sha256sum *.csv > SHA256SUMS && ls -la)
