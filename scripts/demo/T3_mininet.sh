#!/usr/bin/env bash
# 3-TERMINAL INTERACTIVE DEMO - TERMINAL 3: start the Mininet lab and open the mininet> prompt.
#   sudo scripts/demo/T3_mininet.sh
# Start it after Terminal 1 (sudo scripts/demo/T1_start_system.sh --no-lab) says SYSTEM READY.
# Then type the commands from docs/LIVE_DEMO_SCRIPT.md. `exit` at mininet> stops the lab.
source "$(dirname "$0")/_common.sh"; need_root
cd "$PROJECT"
exec python3 "$DEMO_DIR/mininet_lab.py" "$@"
