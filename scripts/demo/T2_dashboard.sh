#!/usr/bin/env bash
# 3-TERMINAL PRESENTATION DEMO  -  TERMINAL 2: live dashboard (refreshes every 2 s, no sudo needed)
#   scripts/demo/T2_dashboard.sh
# Shows the victim's state and score, every source sending to it (pps, ML probability, BLOCKED or not)
# and the active drop rules. Start it any time after Terminal 1 says SYSTEM READY. Ctrl-C to stop.
source "$(dirname "$0")/_common.sh"
exec python3 "$DEMO_DIR/ctl.py" watch "$@"
