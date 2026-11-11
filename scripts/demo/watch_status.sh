#!/usr/bin/env bash
# Terminal 5: live dashboard of the controller (refreshes every 2 s). Ctrl-C to stop.
source "$(dirname "$0")/_common.sh"
exec python3 "$DEMO_DIR/ctl.py" watch "$@"
