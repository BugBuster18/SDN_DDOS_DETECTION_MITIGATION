#!/usr/bin/env python3
"""Summarise repeated live mitigation runs (direct host commands, one fresh system start per run).

Each run folder (report/evidence/repeats/run_NN/) holds phases.csv, port_counters.csv (1 Hz switch-port
counters), telemetry.jsonl (controller windows), and the legitimate clients' own outputs.
Attack rates are measured on switch ports, not taken from the controller:
  offered   = packets entering s1/s2 from h1..h6
  delivered = packets leaving s6-eth3 towards the victim, minus the legitimate baseline before the attack

Writes report/evidence/repeats/summary.csv and summary_stats.csv (mean, sd, 95 % bootstrap CI).

    python experiments/scripts/summarize_live_repeats.py
"""
import csv
import json
import re
import statistics as st
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "report/evidence/repeats"
ATT = ("h1", "h2", "h3", "h4", "h5", "h6")


def mean(T, xs, lo, hi):
    v = [x for t, x in zip(T, xs) if lo <= t < hi]
    return st.mean(v) if v else float("nan")


def analyse(E: Path) -> dict:
    ph = {r["phase"]: float(r["ts"]) for r in csv.DictReader(open(E / "phases.csv"))}
    t0 = ph["attack_start"]
    rows = [{k: float(v) for k, v in r.items()} for r in csv.DictReader(open(E / "port_counters.csv"))]
    T, victim, attack = [], [], []
    for a, b in zip(rows, rows[1:]):
        dt = b["ts"] - a["ts"]
        if dt <= 0:
            continue
        T.append((a["ts"] + b["ts"]) / 2 - t0)
        victim.append((b["victim_tx_pkts"] - a["victim_tx_pkts"]) / dt)
        attack.append(sum(b[h] - a[h] for h in ATT) / dt)
    t_susp = t_mit = t_rec = t_norm = None
    blocked, legit_blocked = set(), set()
    for l in open(E / "telemetry.jsonl"):
        d = json.loads(l)
        if d.get("event") != "window" or d["ts"] < ph["normal_start"] - 6:
            continue
        for x in d["decisions"]:
            if x["dst"] != "10.0.0.18":
                continue
            s, pv, t = x["state"], x["previous_state"], d["ts"] - t0
            if s == "SUSPECTED" and t_susp is None and t > -1: t_susp = t
            if s in ("CONFIRMED", "MITIGATING") and t_mit is None and t > -1: t_mit = t
            if s == "RECOVERING" and t_rec is None and t_mit is not None: t_rec = t
            if s == "NORMAL" and pv == "RECOVERING" and t_norm is None: t_norm = t
            for src in x.get("attributed_sources") or []:
                (blocked if src in {f"10.0.0.{i}" for i in range(1, 7)} else legit_blocked).add(src)
    t_stop = ph["attack_stop"] - t0
    base = mean(T, victim, ph["normal_start"] - t0 + 4, -1)
    unmit = mean(T, victim, 2, t_mit - 0.5) - base if t_mit else float("nan")
    mit = mean(T, victim, t_mit + 2, t_stop - 1) - base if t_mit else float("nan")
    # legitimate clients
    http = [l.split() for l in open(E / "legit_h9_http.txt") if len(l.split()) == 3]
    http_mit = [h for h in http if t_mit and t_mit <= float(h[0]) - t0 < t_stop]
    http_all = [h for h in http]
    udp_lost = None
    m = re.search(r"(\d+)/(\d+) \([\d.]+%\)\s+receiver", (E / "legit_h8_udp.txt").read_text())
    if m: udp_lost = int(m.group(1))
    m = re.search(r"([\d.]+) Mbits/sec\s+\d*\s*receiver", (E / "legit_h7_tcp.txt").read_text())
    tcp = float(m.group(1)) if m else float("nan")
    pings = len(re.findall(r"icmp_seq=", (E / "legit_h13_ping.txt").read_text()))
    return {
        "run": E.name, "completed": int(t_mit is not None and t_norm is not None),
        "attack_offered_pps": round(mean(T, attack, 2, t_stop - 1)),
        "t_suspected_s": t_susp, "t_confirm_s": t_mit,
        "attack_delivered_before_pps": round(unmit), "attack_delivered_after_pps": round(max(mit, 0)),
        "reduction_pct": 100 * (1 - max(mit, 0) / unmit) if unmit and unmit > 0 else float("nan"),
        "attackers_blocked": len(blocked), "legit_hosts_blocked": len(legit_blocked),
        "t_rules_removed_after_stop_s": (t_rec - t_stop) if t_rec else None,
        "t_normal_after_stop_s": (t_norm - t_stop) if t_norm else None,
        "tcp_h7_mbps": tcp, "udp_h8_lost": udp_lost, "ping_h13_received": pings,
        "http_failed_while_blocked": sum(1 for h in http_mit if h[1] != "200"),
        "http_requests_while_blocked": len(http_mit),
        "http_failed_total": sum(1 for h in http_all if h[1] != "200"), "http_total": len(http_all),
    }


def main():
    runs = sorted(p for p in REP.iterdir() if p.is_dir() and (p / "phases.csv").exists())
    out = []
    for r in runs:
        try:
            out.append(analyse(r))
        except Exception as e:  # a run that did not finish is reported, not dropped silently
            out.append({"run": r.name, "completed": 0, "error": str(e)})
            print("run", r.name, "could not be analysed:", e)
    keys = list(dict.fromkeys(k for o in out for k in o))
    with open(REP / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, keys); w.writeheader(); w.writerows(out)
    ok = [o for o in out if o.get("completed")]
    rng = np.random.default_rng(0)
    stats = []
    for k in ["t_suspected_s", "t_confirm_s", "attack_offered_pps", "attack_delivered_before_pps",
              "attack_delivered_after_pps", "reduction_pct", "t_rules_removed_after_stop_s",
              "t_normal_after_stop_s", "tcp_h7_mbps"]:
        v = np.array([o[k] for o in ok if o.get(k) is not None], dtype=float)
        if len(v) == 0:
            continue
        b = v[rng.integers(0, len(v), size=(10000, len(v)))].mean(1)
        lo, hi = np.percentile(b, [2.5, 97.5])
        stats.append({"metric": k, "n": len(v), "mean": v.mean(), "sd": v.std(ddof=1) if len(v) > 1 else 0,
                      "min": v.min(), "max": v.max(), "ci_low": lo, "ci_high": hi})
    with open(REP / "summary_stats.csv", "w", newline="") as f:
        w = csv.DictWriter(f, list(stats[0])); w.writeheader(); w.writerows(stats)
    print(f"{len(ok)} of {len(out)} runs completed")
    for o in out:
        print({k: (round(v, 2) if isinstance(v, float) else v) for k, v in o.items()})
    for s in stats:
        print({k: (round(v, 2) if isinstance(v, float) else v) for k, v in s.items()})


if __name__ == "__main__":
    main()
