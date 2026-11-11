#!/usr/bin/env bash
# Terminal 4 (once, BEFORE starting anything): check environments and clean old Mininet state.
# Runs `mn -c` HERE, before Ryu starts, because `mn -c` also kills ryu-manager.
source "$(dirname "$0")/_common.sh"; need_root
cd "$PROJECT"; ok=1
chk() { if eval "$2" >/dev/null 2>&1; then echo "  [OK]   $1"; else echo "  [FAIL] $1"; ok=0; fi; }
echo "== Preflight checks ($PROJECT)"
chk "ML venv (.venv, Python 3.12) imports sklearn/joblib" ".venv/bin/python -c 'import sklearn, joblib'"
chk "Ryu venv (.venv-ryu39, Python 3.9) imports ryu"       ".venv-ryu39/bin/python -c 'import ryu'"
chk "production model present"      "test -f artifacts/production/hist_gradient_boosting.joblib"
chk "temporal window model present" "test -f artifacts/experiments/temporal/window_model.json"
chk "temporal source model present" "test -f artifacts/experiments/temporal/source_model.json"
for t in mn mnexec ovs-vsctl ovs-ofctl hping3 iperf iperf3 curl ethtool; do chk "tool: $t" "command -v $t"; done
service openvswitch-switch start >/dev/null 2>&1
chk "Open vSwitch running" "ovs-vsctl show"
if pgrep -f '[r]yu-manager' >/dev/null || pgrep -f '[d]dos_ml.predict_api' >/dev/null; then
  echo "  [INFO] Ryu and/or ML API already running:"
  pgrep -af '[r]yu-manager|[d]dos_ml.predict_api' | sed 's/^/         /'
  echo "         Stop them (Ctrl-C in their terminals) or run 13_cleanup.sh for a fresh start."
else
  echo "== Cleaning old Mininet state (mn -c) - safe now because Ryu is not running"
  mn -c >/dev/null 2>&1; echo "  [OK]   mn -c done"
fi
rm -f "$PROJECT/experiments/MITIGATION_DISABLE"
mkdir -p "$LOG_DIR"; chown -R "${SUDO_USER:-enkatesh}:${SUDO_USER:-enkatesh}" "$PROJECT/experiments/results/demo"
if [ $ok = 1 ]; then echo "== PREFLIGHT PASSED"; else echo "== PREFLIGHT FAILED (see [FAIL] lines)"; exit 1; fi
