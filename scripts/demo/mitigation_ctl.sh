#!/usr/bin/env bash
# Operator control of the mitigation rules (talks to the controller REST API; `ovs` needs sudo).
#   mitigation_ctl.sh status            mode + per-destination state
#   mitigation_ctl.sh list              rules as the controller knows them
#   mitigation_ctl.sh ovs               rules as the SWITCHES actually hold them (ground truth, sudo)
#   mitigation_ctl.sh remove <cookie>   remove one rule (cookie from `list`, e.g. 0xdd05000000000003)
#   mitigation_ctl.sh remove-all        remove every rule
#   mitigation_ctl.sh mode [MODE]       show / set DETECTION_ONLY | DRY_RUN | MITIGATION_ENABLED
#   mitigation_ctl.sh events            recent alert / mitigation events
source "$(dirname "$0")/_common.sh"
exec python3 "$DEMO_DIR/ctl.py" "$@"
