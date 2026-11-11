#!/usr/bin/env bash
# Terminal 4: Scenario E - legit h7 TCP, h8 UDP, h9 HTTP, h10 DNS-like, h13 ping WHILE h1..h6 attack h18.
# Optional: --attack udp|icmp|syn (default udp). Works in any mode; with MITIGATION_ENABLED it also
# measures blocking and legit preservation.
source "$(dirname "$0")/_common.sh"; need_root; run_py mixed "$@"
