#!/usr/bin/env bash
# Terminal 4: Scenario B - UDP flood from h1..h6 to h18 (different sizes/rates/ports) + legit probes h7/h13.
# ~95 s: 15 s normal, 40 s attack, 40 s recovery. Results: experiments/results/demo/<time>_udp/
source "$(dirname "$0")/_common.sh"; need_root; run_py udp "$@"
