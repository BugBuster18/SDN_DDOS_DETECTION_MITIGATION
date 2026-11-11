#!/usr/bin/env bash
# Unattended end-to-end verification of the whole demo (~20 min), from a clean state.
# Starts ML API, controller (DETECTION_ONLY) and the lab in the background, runs every scenario
# in the order of docs/DEMO_GUIDE.md, then stops everything. Output: experiments/results/demo/
# Logs of the background services: experiments/results/demo/logs/
#   sudo scripts/demo/run_full_verification.sh
source "$(dirname "$0")/_common.sh"; need_root
cd "$PROJECT"
step() { echo; echo "################ $*"; }
step "cleanup + preflight"
bash "$DEMO_DIR/13_cleanup.sh" >/dev/null
bash "$DEMO_DIR/00_preflight.sh" || exit 1
step "start ML API, controller (DETECTION_ONLY), Mininet lab (background)"
setsid nohup sudo -u "${SUDO_USER:-enkatesh}" bash "$DEMO_DIR/01_start_ml_api.sh" > "$LOG_DIR/terminal1.out" 2>&1 < /dev/null &
for i in $(seq 1 60); do curl -s http://127.0.0.1:8765/health >/dev/null && break; sleep 0.5; done
setsid nohup bash "$DEMO_DIR/02_start_controller.sh" DETECTION_ONLY > "$LOG_DIR/terminal2.out" 2>&1 < /dev/null &
for i in $(seq 1 60); do curl -s "$REST/mode" >/dev/null && break; sleep 0.5; done
setsid nohup bash "$DEMO_DIR/03_start_mininet.sh" --no-cli > "$LOG_DIR/terminal3.out" 2>&1 < /dev/null &
for i in $(seq 1 120); do test -f "$PROJECT/experiments/results/demo/run/lab_state.json" && break; sleep 0.5; done
sleep 5
step "04 connectivity";                 bash "$DEMO_DIR/04_test_connectivity.sh"
step "05 benign (DETECTION_ONLY)";      bash "$DEMO_DIR/05_test_benign_traffic.sh" | sed -n '/RESULT/,$p'
step "05b flash crowd (DETECTION_ONLY)"; bash "$DEMO_DIR/05b_test_flash_crowd.sh" | sed -n '/RESULT/,$p'
step "06 UDP flood (DETECTION_ONLY)";   bash "$DEMO_DIR/06_test_udp_attack.sh" | sed -n '/RESULT/,$p'
step "08 ICMP flood (DETECTION_ONLY)";  bash "$DEMO_DIR/08_test_icmp_attack.sh" | sed -n '/RESULT/,$p'
step "07 SYN flood random ports";       bash "$DEMO_DIR/07_test_tcp_attack.sh" | sed -n '/RESULT/,$p'
sleep 20
step "07 SYN flood fixed ports";        bash "$DEMO_DIR/07_test_tcp_attack.sh" --syn-mode fixed | sed -n '/RESULT/,$p'
step "09 mixed (DETECTION_ONLY)";       bash "$DEMO_DIR/09_test_mixed_traffic.sh" | sed -n '/RESULT/,$p'
step "10 enable mitigation";            bash "$DEMO_DIR/10_enable_mitigation.sh"
step "11 mitigation demo (UDP)";        bash "$DEMO_DIR/11_verify_mitigation.sh" | sed -n '/RESULT/,$p'
step "11 mitigation demo (ICMP)";       bash "$DEMO_DIR/11_verify_mitigation.sh" --attack icmp | sed -n '/RESULT/,$p'
step "12 disable mitigation + recovery"; bash "$DEMO_DIR/12_disable_mitigation.sh"
step "stop everything";                 bash "$DEMO_DIR/13_cleanup.sh"
chown -R "${SUDO_USER:-enkatesh}:${SUDO_USER:-enkatesh}" "$PROJECT/experiments/results/demo"
echo "VERIFICATION FINISHED"
