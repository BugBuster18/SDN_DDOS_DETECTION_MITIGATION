#!/usr/bin/env bash
# Terminal 3: start the 6-switch / 18-host Mininet lab and open the mininet> prompt.
# Start this AFTER Terminal 2 (controller). Type `exit` at mininet> to stop the lab.
source "$(dirname "$0")/_common.sh"; need_root
cd "$PROJECT"
exec python3 "$DEMO_DIR/mininet_lab.py" "$@"
