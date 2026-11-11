#!/usr/bin/env bash
# Terminal 4: EXPLICITLY enable real OpenFlow blocking (isolated Mininet lab only).
# Usage: scripts/demo/10_enable_mitigation.sh [MITIGATION_ENABLED|DRY_RUN]
source "$(dirname "$0")/_common.sh"
MODE="${1:-MITIGATION_ENABLED}"
echo "Switching controller to $MODE ..."
curl -sf -X POST -H 'Content-Type: application/json' -d "{\"mode\": \"$MODE\"}" "$REST/mode" \
  || { echo "FAILED (is the controller running? does the config say detection.mode: enforce?)"; exit 1; }
echo "Current:"; curl -s "$REST/mode"
