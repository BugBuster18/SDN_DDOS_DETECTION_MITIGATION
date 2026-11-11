#!/usr/bin/env bash
# Terminal 2: start the Ryu hybrid controller (OpenFlow 6653, REST API 127.0.0.1:8080).
# Usage: sudo scripts/demo/02_start_controller.sh [DETECTION_ONLY|DRY_RUN|MITIGATION_ENABLED]
# Default DETECTION_ONLY: nothing is ever blocked until you run 10_enable_mitigation.sh.
# Logs: experiments/results/demo/logs/ryu.log and per-window telemetry .../logs/telemetry.jsonl
source "$(dirname "$0")/_common.sh"; need_root
MODE="${1:-DETECTION_ONLY}"
cd "$PROJECT"; mkdir -p "$LOG_DIR"
if pgrep -f '[r]yu-manager' >/dev/null; then
  echo "A ryu-manager is already running:"; pgrep -af '[r]yu-manager'; echo "Stop it first (Ctrl-C there)."; exit 1
fi
export DDOS_CONFIG="$PROJECT/experiments/configs/demo.yaml"
export DDOS_MITIGATION_MODE="$MODE"
export DDOS_TELEMETRY_JSONL="$LOG_DIR/telemetry.jsonl"
export DDOS_FLOW_IDLE_TIMEOUT=10 PYTHONUNBUFFERED=1
: > "$DDOS_TELEMETRY_JSONL"
chown -R "${SUDO_USER:-enkatesh}:${SUDO_USER:-enkatesh}" "$LOG_DIR"
echo "Starting Ryu hybrid controller  mode=$MODE  config=$DDOS_CONFIG"
cd Codes/controller
"$PROJECT/.venv-ryu39/bin/ryu-manager" --ofp-tcp-listen-port 6653 \
    --wsapi-host 127.0.0.1 --wsapi-port 8080 hybrid_controller.py 2>&1 | tee "$LOG_DIR/ryu.log"
