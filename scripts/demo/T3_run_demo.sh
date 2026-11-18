#!/usr/bin/env bash
# ============================================================================================
#  3-TERMINAL PRESENTATION DEMO  -  TERMINAL 3: the guided demo (start after Terminal 1 = READY)
#
#      sudo scripts/demo/T3_run_demo.sh            (pauses for Enter between steps)
#      sudo scripts/demo/T3_run_demo.sh --auto     (no pauses)
#
#  STEP 1  every host can reach the victim h18                                    (~15 s)
#  STEP 2  normal traffic only: h7 TCP, h8 UDP, h9 HTTP, h10 DNS-like, h13 ping   (25 s)
#          -> victim stays NORMAL, nothing is blocked although protection is armed
#  STEP 3  DDoS: h1-h6 flood h18 with UDP WHILE the legitimate users keep going   (40 s)
#          -> CONFIRMED -> drop rules for h1-h6 only -> legitimate traffic preserved
#  STEP 4  attack stops -> rules removed automatically -> back to NORMAL           (40 s)
#  STEP 5  check: no rules left, former attackers can reach h18 again
#  Results are also saved in experiments/results/demo/<time>_mitigation/
# ============================================================================================
source "$(dirname "$0")/_common.sh"; need_root
AUTO=0; [ "$1" = "--auto" ] && AUTO=1
B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; N=$'\033[0m'
pause() { [ $AUTO = 1 ] && return; echo; read -r -p "${Y}${B}>>> Press Enter to $1 ...${N}" _; }
step()  { echo; echo "${C}${B}############################################################################${N}";
          echo "${C}${B}  $*${N}"; echo "${C}${B}############################################################################${N}"; }

test -f "$PROJECT/experiments/results/demo/run/lab_state.json" \
  || { echo "${R}The lab is not running. Start Terminal 1 first: sudo scripts/demo/T1_start_system.sh${N}"; exit 1; }
mode=$(curl -s "$REST/mode" | python3 -c 'import sys,json; print(json.load(sys.stdin)["mode"])' 2>/dev/null)
[ -n "$mode" ] || { echo "${R}Controller not reachable. Is Terminal 1 running?${N}"; exit 1; }
if [ "$mode" != "MITIGATION_ENABLED" ]; then
  echo "Controller is in $mode - arming protection (MITIGATION_ENABLED) ..."
  bash "$DEMO_DIR/10_enable_mitigation.sh" >/dev/null || exit 1
fi

clear
echo "${B}DDoS detection + mitigation with SDN and ML - live demo${N}"
echo "  victim: h18 (10.0.0.18)   attackers: h1-h6   legitimate users: h7 h8 h9 h10 h13"
echo "  protection: ${G}${B}ARMED${N} (controller will install real OpenFlow drop rules)"

pause "check connectivity"
step "STEP 1 - Every host can reach the victim h18"
run_py connectivity || { echo "${R}Connectivity problem - see above.${N}"; exit 1; }

pause "start NORMAL traffic, then the ATTACK"
step "STEP 2-4 - Normal traffic (25 s)  ->  DDoS attack from h1-h6 (40 s)  ->  recovery (40 s)"
echo "  Watch Terminal 1 (decisions) and Terminal 2 (who is sending / who is BLOCKED)."
echo "  Timeline below: [time] controller state, score, traffic seen by the controller, rules."
echo
run_py mitigation --warmup 25 --attack-duration 40 --recovery-wait 40

pause "verify the network is fully restored"
step "STEP 5 - Recovery: rules removed, former attackers reach h18 again"
run_py recovery

echo
echo "${G}${B}DEMO COMPLETE.${N}  Run this script again for another round, or Ctrl-C Terminal 1 to stop everything."
