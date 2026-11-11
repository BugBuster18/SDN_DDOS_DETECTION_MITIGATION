#!/usr/bin/env python3
"""Build a Markdown table of all demo experiments from their result.json files.

    python3 scripts/demo/summarize_results.py            # prints Markdown
    python3 scripts/demo/summarize_results.py --out experiments/results/demo/SUMMARY.md
"""
import argparse
import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[2] / "experiments" / "results" / "demo"


def fmt(v, suffix=""):
    return "–" if v in (None, "") else f"{v}{suffix}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(RESULTS))
    ap.add_argument("--out")
    a = ap.parse_args()
    rows = []
    for rj in sorted(Path(a.dir).glob("2*/result.json")):
        r = json.loads(rj.read_text())
        row = r["row"]
        legit = r.get("legit", {})
        legit_txt = "; ".join(
            f"{h} {e['kind'].replace('_iperf3', '').replace('udp_request_response', 'dns')}: "
            + ("BLOCKED" if e["blocked_by_rule"] else ("ok" if e["preserved"] else "degraded"))
            for h, e in legit.items())
        rows.append(
            f"| `{row['run_id']}` | {row['traffic_type']} | {row['mode']} | {row['n_attack_sources'] or '–'} | "
            f"{row['max_state']} | {fmt(row['max_window_score'])} | {fmt(row['flow_ml_max_prob'])} | "
            f"{fmt(row['detection_latency_s'], ' s')} | {fmt(row['mitigation_latency_s'], ' s')} | "
            f"{row['n_rules_installed']} | {fmt(row['offered_attack_pps'])} | "
            f"{fmt(row['delivered_attack_pps_before_mitigation'])} → {fmt(row['delivered_attack_pps_after_mitigation'])} "
            f"({fmt(row['attack_reduction_pct'], '%')}) | {legit_txt} | {fmt(row['recovery_time_s'], ' s')} | "
            f"{'<br>'.join(r['statuses'])} |")
    head = ("| run | traffic | mode | attackers | max state | max score | flow-ML max p | detect latency | "
            "first rule | rules | offered attack pps | delivered attack pps before → after (reduction) | "
            "legitimate clients | recovery | statuses |\n|" + "---|" * 15)
    md = head + "\n" + "\n".join(rows) + "\n"
    if a.out:
        Path(a.out).write_text(md)
    print(md)


if __name__ == "__main__":
    main()
