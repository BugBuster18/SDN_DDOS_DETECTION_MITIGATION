#!/usr/bin/env bash
# Terminal 4: back to DETECTION_ONLY, remove every mitigation rule, verify connectivity is restored.
source "$(dirname "$0")/_common.sh"; need_root
echo "== Switching controller to DETECTION_ONLY (this also removes its drop rules)"
curl -sf -X POST -H 'Content-Type: application/json' -d '{"mode": "DETECTION_ONLY"}' "$REST/mode" \
  || echo "controller not reachable"
curl -sf -X DELETE "$REST/rules" >/dev/null || true
left=0
for s in 1 2 3 4 5 6; do
  n=$(ovs-ofctl -O OpenFlow13 dump-flows s$s cookie=0xdd05000000000000/0xffff000000000000 2>/dev/null | grep -c cookie=)
  left=$((left + n))
done
if [ "$left" -gt 0 ]; then
  echo "== $left drop rule(s) still on the switches - deleting directly with ovs-ofctl"
  for s in 1 2 3 4 5 6; do ovs-ofctl -O OpenFlow13 del-flows s$s cookie=0xdd05000000000000/0xffff000000000000; done
fi
run_py stop >/dev/null
run_py recovery
