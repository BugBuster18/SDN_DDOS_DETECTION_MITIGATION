#!/usr/bin/env bash
# Terminal 1: start the ML prediction API (flow-level HistGradientBoosting model) on 127.0.0.1:8765.
# Runs in the foreground; stop with Ctrl-C. Also logged to experiments/results/demo/logs/ml_api.log
# No sudo needed.
source "$(dirname "$0")/_common.sh"
cd "$PROJECT"; mkdir -p "$LOG_DIR"
source .venv/bin/activate
export DDOS_MODEL_DIR=artifacts/production PYTHONUNBUFFERED=1
echo "Starting ML API (model dir $DDOS_MODEL_DIR). Test with: curl http://127.0.0.1:8765/health"
python -m ddos_ml.predict_api 2>&1 | tee "$LOG_DIR/ml_api.log"
