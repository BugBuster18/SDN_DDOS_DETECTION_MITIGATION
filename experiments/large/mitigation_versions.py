"""Collateral and coverage of each mitigation run (attribution ablation).

python experiments/large/mitigation_versions.py test_mit_v1 test_mit_v2 test_mit_v3 test_mit
"""
import json
import sys
from pathlib import Path

import pandas as pd

L = Path(__file__).resolve().parents[2] / "experiments/results/large"
rows = []
for name in sys.argv[1:]:
    d = L / name
    if not (d / "events.json").exists():
        continue
    s = json.loads((d / "session.json").read_text())
    ev = json.loads((d / "events.json").read_text())["events"]
    inst = [e for e in ev if e["type"] == "rule_installed"]
    legit = {c["ip"]: c for c in s["clients"].values()}
    atk_segs = [g for g in s["segments"] if g["events"]]
    covered = []
    for g in atk_segs:
        atk = {e["src_ip"] for e in g["events"] if e["src_ip"] != "spoofed"}
        if not atk:
            continue
        # an attacker is covered if a rule for it is active at any time in the segment
        active = {e["src"] for e in inst if e["installed"] <= g["end"] and e["installed"] + e.get("hard_timeout", 300) >= g["start"]}
        covered.append(len(atk & active) / len(atk))
    lb = sorted({e["src"] for e in inst if e["src"] in legit})
    rows.append({"run": name, "segments_run": len(s["segments"]), "rules": len(inst),
                 "attackers_ever_blocked": len({e["src"] for e in inst if e["src"] in set(s["attacker_ips"])}),
                 "mean_attacker_coverage": round(sum(covered) / max(len(covered), 1), 3),
                 "spoof_ports": len([e for e in inst if str(e["src"]).startswith("spoof")]),
                 "legit_blocked": len(lb),
                 "legit_roles": ",".join(sorted({legit[i]["role"] for i in lb}))})
print(pd.DataFrame(rows).to_string(index=False))
