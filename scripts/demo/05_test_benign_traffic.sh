#!/usr/bin/env bash
# Terminal 4: Scenario A - legitimate traffic only (TCP, UDP of several sizes/rates, ICMP, HTTP,
# DNS-like) from 9 hosts to h18 for ~65 s. Results: experiments/results/demo/<time>_benign/
source "$(dirname "$0")/_common.sh"; need_root; run_py benign "$@"
