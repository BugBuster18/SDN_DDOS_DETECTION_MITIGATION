"""Mitigation effect per attack segment: test_mit (mitigation) paired with test_det (same schedule, no mitigation).

python experiments/large/large_mitigation.py test_det test_mit
-> experiments/results/large/mitigation_summary.csv
"""
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
L = ROOT / "experiments" / "results" / "large"


def main(det, mit):
    sm = json.loads((L / mit / "session.json").read_text())
    ev = json.loads((L / mit / "events.json").read_text())["events"]
    attackers = set(sm["attacker_ips"])
    legit_ips = {c["ip"] for c in sm["clients"].values()}
    pd_det = pd.read_csv(L / det / "legit_phases.csv")
    pd_mit = pd.read_csv(L / mit / "legit_phases.csv")
    base_det = pd_det[pd_det.phase == "baseline"].iloc[0]
    rows = []
    for s in sm["segments"]:
        if not s["events"]:
            continue
        a0 = min(e["epoch_start"] for e in s["events"])
        seg_atk = {e["src_ip"] for e in s["events"] if e["src_ip"] != "spoofed"}
        rules = [e for e in ev if e["type"] == "rule_installed" and s["start"] - 1 <= e["installed"] <= s["end"] + 15]
        srcs = [r["src"] for r in rules]
        first = min((r["installed"] for r in rules), default=None)
        spoof_rules = [r for r in rules if str(r["src"]).startswith("spoof")]
        # rules that are already active from an earlier segment also protect this one
        d = pd_det[(pd_det.segment == s["idx"]) & (pd_det.phase == "attack")]
        m = pd_mit[(pd_mit.segment == s["idx"]) & (pd_mit.phase == "attack")]
        ma = pd_mit[(pd_mit.segment == s["idx"]) & (pd_mit.phase == "after_rules")]
        g = lambda df, c: float(df[c].iloc[0]) if len(df) and c in df else float("nan")  # noqa: E731
        rows.append({
            "kind": s["kind"], "attackers": len(seg_atk) if seg_atk else len(spoof_rules),
            "first_rule_s": round(first - a0, 1) if first else None,
            "attackers_blocked": len({x for x in srcs if x in seg_atk}),
            "spoof_ports_quarantined": len(spoof_rules),
            "legit_blocked": len({x for x in srcs if x in legit_ips}),
            "other_blocked": len({x for x in srcs if x not in attackers and x not in legit_ips and not str(x).startswith("spoof")}),
            "offered_pps": round(g(d, "attack_offered_pps")),
            "victim_mbps_nomit": round(g(d, "victim_mbps"), 1), "victim_mbps_mit": round(g(m, "victim_mbps"), 1),
            "victim_mbps_after_rules": round(g(ma, "victim_mbps"), 1),
            "http_nomit": round(g(d, "http_success"), 3), "http_mit": round(g(m, "http_success"), 3),
            "http_after_rules": round(g(ma, "http_success"), 3),
            "udp_nomit": round(g(d, "udp_rr_success"), 3), "udp_mit": round(g(m, "udp_rr_success"), 3),
            "ping_nomit": round(g(d, "ping_delivery"), 3), "ping_mit": round(g(m, "ping_delivery"), 3),
            "bulk_nomit": round(g(d, "bulk_tcp_mbps"), 2), "bulk_mit": round(g(m, "bulk_tcp_mbps"), 2),
        })
    out = pd.DataFrame(rows)
    out.to_csv(L / "mitigation_summary.csv", index=False)
    pd.set_option("display.width", 250)
    print("baseline (benign, no attack):", base_det[["http_success", "udp_rr_success", "ping_delivery",
                                                      "bulk_tcp_mbps", "victim_mbps"]].astype(float).round(3).to_dict())
    print(out.to_string(index=False))
    all_rules = [e for e in ev if e["type"] == "rule_installed"]
    print("total rules", len(all_rules), "on legit clients:",
          sorted({r["src"] for r in all_rules if r["src"] in legit_ips}))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
