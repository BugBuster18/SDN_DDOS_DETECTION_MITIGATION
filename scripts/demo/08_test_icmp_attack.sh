#!/usr/bin/env bash
# Terminal 4: Scenario D - ICMP flood from h1..h6 to h18 + legit probes.
source "$(dirname "$0")/_common.sh"; need_root; run_py icmp "$@"
