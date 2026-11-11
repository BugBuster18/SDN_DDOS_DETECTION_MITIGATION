#!/usr/bin/env bash
# Terminal 4: Scenario C - TCP SYN flood from h1..h4 to h18:80 + legit probes (EXPERIMENTAL).
#   default            : random source port per SYN (realistic SYN-flood shape). In this reactive
#                        controller every SYN becomes a new flow + packet-in, so the attack mostly
#                        hits the CONTROL PLANE; measured result: NOT detected (see DEMO_GUIDE.md).
#   --syn-mode fixed   : same SYN packets with a fixed source port per attacker (one flow each,
#                        2000 pps), so the flood reaches the victim's data plane.
source "$(dirname "$0")/_common.sh"; need_root; run_py syn --attackers h1,h2,h3,h4 "$@"
