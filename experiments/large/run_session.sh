#!/usr/bin/env bash
# One large-testbed session:  sudo experiments/large/run_session.sh SESSION MODE SEED PLAN [MODEL_DIR]
#   MODE  DETECTION_ONLY | MITIGATION_ENABLED
#   PLAN  calib | test | smoke
#   MODEL_DIR  directory with window_model.json + source_model.json (default artifacts/experiments/temporal)
set -u
SESSION=$1; MODE=$2; SEED=$3; PLAN=$4; MODEL_DIR=${5:-artifacts/experiments/temporal}
PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT"
OUT="$PROJECT/experiments/results/large/$SESSION"
rm -rf "$OUT"; mkdir -p "$OUT"
echo "=== session $SESSION mode=$MODE seed=$SEED plan=$PLAN models=$MODEL_DIR  $(date)"

pkill -f '[l]arge_lab.py'; pkill -INT -f '[r]yu-manager'; pkill -f '[d]dos_ml.predict_api'; pkill -f '[h]ping3'
sleep 2; pkill -KILL -f '[r]yu-manager'; mn -c >/dev/null 2>&1
rm -f "$PROJECT/experiments/results/large/current_lab_state.json"

sed -e "s#WINDOW_MODEL#$MODEL_DIR/window_model.json#" -e "s#SOURCE_MODEL#$MODEL_DIR/source_model.json#" \
    experiments/configs/large.yaml > "$OUT/config.yaml"

( cd "$PROJECT" && DDOS_MODEL_DIR=${FLOW_MODEL_DIR:-artifacts/production} OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 PYTHONUNBUFFERED=1 \
  setsid nohup sudo -u enkatesh .venv/bin/python -m ddos_ml.predict_api > "$OUT/ml_api.log" 2>&1 < /dev/null & )
for i in $(seq 1 60); do curl -s http://127.0.0.1:8765/health >/dev/null && break; sleep 0.5; done

( cd "$PROJECT/Codes/controller" && DDOS_CONFIG="$OUT/config.yaml" DDOS_MITIGATION_MODE="$MODE" \
  DDOS_TELEMETRY_JSONL="$OUT/telemetry.jsonl" DDOS_FLOW_IDLE_TIMEOUT=15 DDOS_FLOW_GRANULARITY=pair PYTHONUNBUFFERED=1 \
  setsid nohup "$PROJECT/.venv-ryu39/bin/ryu-manager" --ofp-tcp-listen-port 6653 \
     --wsapi-host 127.0.0.1 --wsapi-port 8080 hybrid_controller.py > "$OUT/ryu.log" 2>&1 < /dev/null & )
for i in $(seq 1 60); do curl -s http://127.0.0.1:8080/ddos/mode >/dev/null && break; sleep 0.5; done
curl -s http://127.0.0.1:8080/ddos/mode || { echo "controller failed"; tail -30 "$OUT/ryu.log"; exit 1; }

python3 experiments/large/large_lab.py --session "$SESSION" --seed "$SEED" --plan "$PLAN" 2>&1 | tee "$OUT/lab.log"

curl -s "http://127.0.0.1:8080/ddos/events?since=0" > "$OUT/events.json"
pkill -INT -f '[r]yu-manager'; pkill -f '[d]dos_ml.predict_api'; sleep 2; pkill -KILL -f '[r]yu-manager'
mn -c >/dev/null 2>&1
chown -R enkatesh:enkatesh "$OUT"
echo "=== done $SESSION $(date)"
