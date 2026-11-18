#!/usr/bin/env bash
# Post-campaign analysis (run as enkatesh): metrics, legitimate-traffic impact, mitigation effect, figures.
set -u
cd "$(dirname "$0")/../.."
PY=.venv/bin/python
export DDOS_TARGET_FPR=0.003   # same false-positive budget for every method (window model was fitted with it)
$PY experiments/large/large_eval.py eval large_calib large_test_det artifacts/experiments/large large_test
$PY experiments/large/large_eval.py eval large_calib large_test_det2 artifacts/experiments/large large_test2
$PY experiments/large/large_legit.py test_det2 test_mit
$PY experiments/large/large_mitigation.py test_det2 test_mit
$PY experiments/large/report_figures.py
