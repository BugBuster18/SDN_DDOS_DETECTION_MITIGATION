#!/usr/bin/env bash
# Terminal 4: verify controller, ML API, 6 switches and host -> h18 connectivity.
source "$(dirname "$0")/_common.sh"; need_root; run_py connectivity "$@"
