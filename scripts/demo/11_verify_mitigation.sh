#!/usr/bin/env bash
# Terminal 4: full mitigation demonstration (run 10_enable_mitigation.sh first):
# legit clients + attack -> detect -> install drop rules -> attack blocked -> legit preserved -> recovery.
# Optional: --attack udp|icmp|syn (default udp)
source "$(dirname "$0")/_common.sh"; need_root; run_py mitigation "$@"
