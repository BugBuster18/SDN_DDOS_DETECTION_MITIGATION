#!/usr/bin/env bash
# Terminal 4: Scenario A2 - "flash crowd": 9 legitimate clients hit h18 at once (~37 Mbps).
# KNOWN LIMITATION: the window model weights the number of concurrent sources heavily and
# CONFIRMS an attack here (false alarm). Run in DETECTION_ONLY to show the limitation safely.
source "$(dirname "$0")/_common.sh"; need_root; run_py crowd "$@"
