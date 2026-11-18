#!/usr/bin/env bash
# ============================================================================================
#  3-TERMINAL PRESENTATION DEMO  -  TERMINAL 1: start the whole system, then show live decisions
#
#      sudo scripts/demo/T1_start_system.sh
#
#  One command replaces the old Terminals 1-3 (+ preflight):
#    * cleans old Mininet state, runs the preflight checks
#    * starts the ML API, the Ryu hybrid controller (MITIGATION_ENABLED = protection armed)
#      and the 6-switch / 18-host Mininet lab, all in the background (logs in
#      experiments/results/demo/logs/)
#    * then shows the controller's decisions live: NORMAL / SUSPECTED / CONFIRMED / BLOCK / UNBLOCK
#  Ctrl-C here stops EVERYTHING and cleans up.
#
#  Optional: sudo scripts/demo/T1_start_system.sh DETECTION_ONLY   (alert only, never block)
# ============================================================================================
#  Interactive variant (you type the Mininet commands yourself, see docs/LIVE_DEMO_SCRIPT.md):
#        sudo scripts/demo/T1_start_system.sh --no-lab      then in Terminal 3: sudo scripts/demo/T3_mininet.sh
source "$(dirname "$0")/_common.sh"; need_root
NOLAB=0; MODE=MITIGATION_ENABLED
for a in "$@"; do case "$a" in --no-lab) NOLAB=1 ;; *) MODE="$a" ;; esac; done
cd "$PROJECT"
B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; N=$'\033[0m'
die() { echo "${R}${B}FAILED: $*${N}"; echo "Logs: $LOG_DIR"; bash "$DEMO_DIR/13_cleanup.sh" >/dev/null 2>&1; exit 1; }

clear
echo "${B}[1/5] Cleaning old state + preflight checks${N}"
bash "$DEMO_DIR/13_cleanup.sh" >/dev/null 2>&1
mkdir -p "$LOG_DIR"
bash "$DEMO_DIR/00_preflight.sh" > "$LOG_DIR/preflight.out" 2>&1 || { cat "$LOG_DIR/preflight.out"; die "preflight"; }
echo "      ${G}OK${N}"

echo "${B}[2/5] Starting ML prediction API (flow model, 127.0.0.1:8765)${N}"
setsid nohup sudo -u "${SUDO_USER:-enkatesh}" bash "$DEMO_DIR/01_start_ml_api.sh" > "$LOG_DIR/terminal1.out" 2>&1 < /dev/null &
for i in $(seq 1 60); do curl -s http://127.0.0.1:8765/health >/dev/null && break; sleep 0.5; done
curl -s http://127.0.0.1:8765/health >/dev/null || die "ML API did not start (see $LOG_DIR/terminal1.out)"
echo "      ${G}OK${N}"

echo "${B}[3/5] Starting Ryu hybrid controller (mode $MODE)${N}"
setsid nohup bash "$DEMO_DIR/02_start_controller.sh" "$MODE" > "$LOG_DIR/terminal2.out" 2>&1 < /dev/null &
for i in $(seq 1 60); do curl -s "$REST/mode" >/dev/null && break; sleep 0.5; done
curl -s "$REST/mode" >/dev/null || die "controller did not start (see $LOG_DIR/terminal2.out)"
echo "      ${G}OK${N}"

if [ $NOLAB = 0 ]; then
echo "${B}[4/5] Starting Mininet lab (6 switches, 18 hosts, victim h18)${N}"
setsid nohup bash "$DEMO_DIR/03_start_mininet.sh" --no-cli > "$LOG_DIR/terminal3.out" 2>&1 < /dev/null &
for i in $(seq 1 120); do test -f "$PROJECT/experiments/results/demo/run/lab_state.json" && break; sleep 0.5; done
test -f "$PROJECT/experiments/results/demo/run/lab_state.json" || die "Mininet lab did not start (see $LOG_DIR/terminal3.out)"
echo "      ${G}OK${N}"

echo "${B}[5/5] Checking switches${N}"
sw=0
for i in $(seq 1 30); do
  sw=$(curl -s "$REST/status" | python3 -c 'import sys,json; print(json.load(sys.stdin)["n_switches"])' 2>/dev/null || echo 0)
  [ "$sw" -ge 6 ] 2>/dev/null && break; sleep 1
done
[ "$sw" -ge 6 ] 2>/dev/null || die "only $sw/6 switches connected"
echo "      ${G}OK - 6/6 switches connected${N}"
T3="sudo scripts/demo/T3_run_demo.sh"
else
echo "${B}[4/5] Mininet NOT started here (--no-lab): start it in Terminal 3${N}"
T3="sudo scripts/demo/T3_mininet.sh   (gives you the mininet> prompt)"
fi

echo
echo "${G}${B}=====================================================================${N}"
echo "${G}${B} SYSTEM READY   (mode: $MODE)${N}"
echo "   Network: s1..s6 chain, 18 hosts, victim h18 = 10.0.0.18"
echo "   Attackers in the demo: h1-h6      Legitimate users: h7 h8 h9 h10 h13"
echo "   Terminal 2:  scripts/demo/T2_dashboard.sh"
echo "   Terminal 3:  $T3"
echo "   Ctrl-C here = stop everything"
echo "${G}${B}=====================================================================${N}"
echo

trap 'true' INT TERM            # let Ctrl-C end the feed, then fall through to the cleanup below
python3 "$DEMO_DIR/live_feed.py"
trap - INT TERM
echo; echo "${B}Stopping everything ...${N}"
bash "$DEMO_DIR/13_cleanup.sh"
