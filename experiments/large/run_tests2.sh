#!/usr/bin/env bash
# Re-run of the paired test sessions after adding baseline-aware attribution (run as root).
set -u
PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT"
export FLOW_MODEL_DIR=artifacts/multidataset
PY="sudo -u enkatesh $PROJECT/.venv/bin/python"
LM=artifacts/experiments/large
bash experiments/large/run_session.sh test_mit MITIGATION_ENABLED 2 test $LM
$PY experiments/large/large_eval.py split test_mit
bash experiments/large/run_session.sh test_det2 DETECTION_ONLY 2 test $LM
$PY experiments/large/large_eval.py split test_det2
echo "=== TESTS2 DONE $(date)"
