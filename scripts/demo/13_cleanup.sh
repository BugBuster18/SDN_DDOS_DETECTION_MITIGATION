#!/usr/bin/env bash
# Any terminal: stop EVERYTHING (traffic, Mininet, Ryu, ML API) and clean Mininet state.
source "$(dirname "$0")/_common.sh"; need_root
python3 "$DEMO_DIR/demo_runner.py" stop 2>/dev/null
pkill -f '[m]ininet_lab.py'; sleep 1
pkill -INT -f '[r]yu-manager'; pkill -INT -f '[d]dos_ml.predict_api'; sleep 2
pkill -KILL -f '[r]yu-manager'; pkill -KILL -f '[d]dos_ml.predict_api'
pkill -f '[u]dp_sink.py'; pkill -f '[u]dp_rr.py'; pkill -f '[h]ttp.server 80'; pkill -f '[i]perf3 -s'; pkill -f '[i]perf -s'
mn -c >/dev/null 2>&1
rm -f "$PROJECT/experiments/results/demo/run/lab_state.json" "$PROJECT/experiments/MITIGATION_DISABLE"
echo "Cleanup done. Remaining related processes:"
pgrep -af '[r]yu-manager|[p]redict_api|[m]ininet:|[h]ping3' || echo "  none"
