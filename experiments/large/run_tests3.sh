#!/usr/bin/env bash
# Final mitigation session (after the counter-tracker fix). Waits for run_tests2.sh to finish (run as root).
set -u
PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT"
until grep -q "TESTS2 DONE" /var/tmp/large_tests2.out; do sleep 10; done
L=experiments/results/large
rm -rf $L/test_mit_v2 experiments/results/raw/large_test_mit_v2
mv $L/test_mit $L/test_mit_v2
[ -d experiments/results/raw/large_test_mit ] && mv experiments/results/raw/large_test_mit experiments/results/raw/large_test_mit_v2
export FLOW_MODEL_DIR=artifacts/multidataset
bash experiments/large/run_session.sh test_mit MITIGATION_ENABLED 2 test artifacts/experiments/large
sudo -u enkatesh "$PROJECT/.venv/bin/python" experiments/large/large_eval.py split test_mit
echo "=== TESTS3 DONE $(date)"
