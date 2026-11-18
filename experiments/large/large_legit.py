"""Effect of attacks (and of mitigation) on legitimate users in the large testbed.

python experiments/large/large_legit.py SESSION [SESSION ...]

Per session and segment, for legitimate clients whose server is the VICTIM:
  http_success      share of HTTP GETs answered within 2 s       (web clients, per request)
  http_p95_s        95th percentile latency of answered GETs
  udp_rr_success    share of DNS-like UDP queries answered within 1 s
  ping_delivery     ICMP echo replies received / expected (0.5 s interval)
  bulk_tcp_mbps     mean throughput of the bulk TCP clients (their edge-port rx rate)
  victim_mbps       traffic delivered on the victim's 50 Mbit/s access link
  attack_offered_pps  packets/s entering the network from attacker ports
Phases: "baseline" = all benign segments; for each attack segment "attack" = [start+3 s, end];
with mitigation the attack phase is split at the first drop-rule installation ("before_rules"/"after_rules").
Writes experiments/results/large/<SESSION>/legit_phases.csv and legit_timeseries.csv
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
LARGE = ROOT / "experiments" / "results" / "large"


def load_requests(sdir, clients, role):
    rows = []
    for h, c in clients.items():
        if c["role"] != role:
            continue
        f = sdir / "legit" / f"{h}_{role}.csv"
        if not f.exists():
            continue
        try:
            d = pd.read_csv(f, header=None, names=["ts", "ok", "lat", "target"])
        except Exception:
            continue
        d["host"], d["victim_client"] = h, int(c["target"] == "h200")
        rows.append(d)
    return pd.concat(rows) if rows else pd.DataFrame(columns=["ts", "ok", "lat", "target", "host", "victim_client"])


def load_ping(sdir, clients):
    rows = []
    for h, c in clients.items():
        if c["role"] != "ping":
            continue
        f = sdir / "legit" / f"{h}_ping.txt"
        if not f.exists():
            continue
        for line in f.read_text(errors="ignore").splitlines():
            m = re.match(r"\[(\d+\.\d+)\].*time=([\d.]+)", line)
            if m:
                rows.append((float(m.group(1)), float(m.group(2)) / 1000, h, int(c["target"] == "h200")))
    return pd.DataFrame(rows, columns=["ts", "rtt", "host", "victim_client"])


def port_rates(sdir, lab):
    pc = pd.read_csv(sdir / "port_counters.csv")
    pc["key"] = pc["switch"] + "-eth" + pc["port"].astype(str)
    pc = pc.sort_values(["key", "ts"])
    for c in ("rx_pkts", "rx_bytes", "tx_pkts", "tx_bytes"):
        pc["d_" + c] = pc.groupby("key")[c].diff()
    pc["dt"] = pc.groupby("key")["ts"].diff()
    pc = pc.dropna()
    pc["sec"] = pc["ts"].round().astype(int)
    port_of = {h: v["switch_port"] for h, v in lab["hosts"].items()}
    return pc, port_of


def analyse(session):
    sdir = LARGE / session
    ses = json.loads((sdir / "session.json").read_text())
    lab = json.loads((sdir / "lab_state.json").read_text()) if (sdir / "lab_state.json").exists() else \
        json.loads((LARGE / "current_lab_state.json").read_text())
    clients = ses["clients"]
    web = load_requests(sdir, clients, "web")
    rr = load_requests(sdir, clients, "rr")
    ping = load_ping(sdir, clients)
    pc, port_of = port_rates(sdir, lab)
    vport = port_of["h200"]
    atk_ports = {port_of[a] for a in ses["attackers"]}
    bulk_ports = {port_of[h] for h, c in clients.items() if c["role"] == "bulk" and c["target"] == "h200"}
    n_ping_v = sum(1 for c in clients.values() if c["role"] == "ping" and c["target"] == "h200")

    first_rule = {}
    evf = sdir / "events.json"
    if evf.exists():
        try:
            evs = json.loads(evf.read_text())["events"]
            for e in evs:
                if e["type"] == "rule_installed" and e.get("dst") == ses["victim_ip"]:
                    for s in ses["segments"]:
                        if s["start"] - 1 <= e["installed"] <= s["end"] + 1 and s["idx"] not in first_rule:
                            first_rule[s["idx"]] = e["installed"]
        except Exception:
            pass

    def phase_row(seg, phase, lo, hi):
        if hi - lo < 1:
            return None
        w = web[(web.victim_client == 1) & (web.ts >= lo) & (web.ts < hi)]
        r = rr[(rr.victim_client == 1) & (rr.ts >= lo) & (rr.ts < hi)]
        p = ping[(ping.victim_client == 1) & (ping.ts >= lo) & (ping.ts < hi)]
        sl = pc[(pc.ts >= lo) & (pc.ts < hi)]
        v = sl[sl.key == vport]
        a = sl[sl.key.isin(atk_ports)]
        b = sl[sl.key.isin(bulk_ports)]
        dur = hi - lo
        return {"session": session, "segment": seg["idx"] if seg else -1, "kind": seg["kind"] if seg else "benign",
                "phase": phase, "seconds": round(dur, 1),
                "http_requests": len(w), "http_success": w.ok.mean() if len(w) else np.nan,
                "http_p95_s": w[w.ok == 1].lat.quantile(0.95) if (w.ok == 1).any() else np.nan,
                "udp_rr_queries": len(r), "udp_rr_success": r.ok.mean() if len(r) else np.nan,
                "ping_delivery": min(len(p) / max(n_ping_v * dur / 0.5, 1), 1.0),
                "ping_p95_ms": 1000 * p.rtt.quantile(0.95) if len(p) else np.nan,
                "bulk_tcp_mbps": (b.d_rx_bytes.sum() * 8 / dur / 1e6 / max(len(bulk_ports), 1)) if len(b) else np.nan,
                "victim_mbps": v.d_tx_bytes.sum() * 8 / dur / 1e6 if len(v) else np.nan,
                "attack_offered_pps": a.d_rx_pkts.sum() / dur if len(a) else 0.0}

    rows = []
    benign = [s for s in ses["segments"] if not s["events"] and s["kind"] in ("benign",)]
    base = [phase_row(s, "baseline", s["start"] + 3, s["end"]) for s in benign]
    base = [b for b in base if b]
    if base:
        bdf = pd.DataFrame(base)
        agg = bdf.drop(columns=["session", "segment", "kind", "phase"]).mean(numeric_only=True).to_dict()
        rows.append({"session": session, "segment": -1, "kind": "benign(all)", "phase": "baseline", **agg})
    for s in ses["segments"]:
        if not s["events"]:
            continue
        lo, hi = s["start"] + 3, s["end"]
        rows.append(phase_row(s, "attack", lo, hi))
        if s["idx"] in first_rule:
            fr = first_rule[s["idx"]]
            rows.append(phase_row(s, "before_rules", lo, fr))
            rows.append(phase_row(s, "after_rules", fr + 2, hi))
    out = pd.DataFrame([r for r in rows if r])
    out.to_csv(sdir / "legit_phases.csv", index=False)

    # per-second time series (for plots)
    t0 = ses["segments"][0]["start"]
    secs = np.arange(int(t0) - 20, int(ses.get("finished", t0 + 2000)))
    v = pc[pc.key == vport].groupby("sec").d_tx_bytes.sum() * 8 / 1e6
    a = pc[pc.key.isin(atk_ports)].groupby("sec").d_rx_pkts.sum()
    wv = web[web.victim_client == 1].assign(sec=lambda d: d.ts.round().astype(int)).groupby("sec").ok.mean()
    rv = rr[rr.victim_client == 1].assign(sec=lambda d: d.ts.round().astype(int)).groupby("sec").ok.mean()
    ts = pd.DataFrame({"sec": secs}).set_index("sec")
    ts["victim_mbps"], ts["attack_pps"], ts["http_success"], ts["udp_rr_success"] = v, a, wv, rv
    ts["t"] = ts.index - t0
    ts.reset_index().to_csv(sdir / "legit_timeseries.csv", index=False)
    pd.set_option("display.width", 220)
    print(out.round(3).to_string(index=False))
    return out


if __name__ == "__main__":
    for s in sys.argv[1:]:
        analyse(s)
