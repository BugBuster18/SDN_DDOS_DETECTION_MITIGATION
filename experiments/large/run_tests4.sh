#!/usr/bin/env bash
# Final mitigation session with source persistence. Waits for run_tests3.sh (run as root).
set -u
PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT"
until grep -q "TESTS3 DONE" /var/tmp/large_tests3.out; do sleep 10; done
L=experiments/results/large
rm -rf $L/test_mit_v3 experiments/results/raw/large_test_mit_v3
mv $L/test_mit $L/test_mit_v3
[ -d experiments/results/raw/large_test_mit ] && mv experiments/results/raw/large_test_mit experiments/results/raw/large_test_mit_v3
export FLOW_MODEL_DIR=artifacts/multidataset
bash experiments/large/run_session.sh test_mit MITIGATION_ENABLED 2 test artifacts/experiments/large
sudo -u enkatesh "$PROJECT/.venv/bin/python" experiments/large/large_eval.py split test_mit
echo "=== TESTS4 DONE $(date)"
