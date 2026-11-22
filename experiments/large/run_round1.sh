#!/usr/bin/env bash
# Deep Review round 1 experiments (run as root). Frozen final configuration and models.
#  test3_det : seed 3, shuffled attack order, 60 s gaps, detection only
#  test3_mit : same schedule, mitigation enabled
#  calib25   : calibration schedule (seed 1) at the 25 Mbit/s test capacity (sensitivity analysis)
set -u
PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT"
export FLOW_MODEL_DIR=artifacts/multidataset
PY="sudo -u enkatesh $PROJECT/.venv/bin/python"
LM=artifacts/experiments/large
bash experiments/large/run_session.sh test3_det DETECTION_ONLY 3 test3 $LM
$PY experiments/large/large_eval.py split test3_det
bash experiments/large/run_session.sh test3_mit MITIGATION_ENABLED 3 test3 $LM
$PY experiments/large/large_eval.py split test3_mit
bash experiments/large/run_session.sh calib25 DETECTION_ONLY 1 calib $LM
$PY experiments/large/large_eval.py split calib25
echo "=== ROUND1 DONE $(date)"
