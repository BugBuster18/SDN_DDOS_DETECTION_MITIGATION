#!/usr/bin/env bash
# Full large-testbed campaign (run as root):  experiments/large/run_campaign.sh
#  1. calib   : DETECTION_ONLY, seed 1, calibration schedule      -> refit window/source models
#  2. test_det: DETECTION_ONLY, seed 2, test schedule (held out)   -> detection metrics + attack impact
#  3. test_mit: MITIGATION_ENABLED, seed 2, same test schedule     -> mitigation effect (paired with 2)
set -u
PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT"
export FLOW_MODEL_DIR=artifacts/multidataset
PY="sudo -u enkatesh $PROJECT/.venv/bin/python"
LM=artifacts/experiments/large
if [ "${SKIP_CALIB:-0}" != 1 ]; then
  bash experiments/large/run_session.sh calib DETECTION_ONLY 1 calib artifacts/experiments/temporal
  $PY experiments/large/large_eval.py split calib
  $PY experiments/large/large_eval.py fit large_calib $LM
fi
bash experiments/large/run_session.sh test_det DETECTION_ONLY 2 test $LM
$PY experiments/large/large_eval.py split test_det
bash experiments/large/run_session.sh test_mit MITIGATION_ENABLED 2 test $LM
$PY experiments/large/large_eval.py split test_mit
echo "=== CAMPAIGN DONE $(date)"
