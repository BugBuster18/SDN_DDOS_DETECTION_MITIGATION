#!/usr/bin/env python3
"""Demo workload orchestrator + experiment recorder (run as root from Terminal 4).

Runs traffic INSIDE the Mininet hosts of the running lab (mininet_lab.py) using
mnexec, follows the controller through its REST API, measures what actually
happened on the switches, and writes a result folder per experiment:

    experiments/results/demo/<timestamp>_<scenario>/
        plan.json      traffic generators (host, role, command, parameters, PIDs, times)
        timeline.csv   1 Hz: controller state/score/features + measured offered/delivered pps
        events.json    controller events (state changes, rules installed/removed)
        rules_at_peak.json / ovs_drop_rules.txt   the rules as the controller AND the switches report them
        hosts/*.log    raw output of every traffic generator (iperf3 JSON, ping, ...)
        result.json    all metrics       summary.md   human-readable report
    experiments/results/demo/demo_results.csv   one row per experiment (appended)

Scenarios:
    connectivity   ping checks (h1, h7, h13 -> h18 and every host -> h18)
    benign         legitimate traffic only (ICMP, TCP, UDP of several sizes/rates, HTTP, DNS-like)
    udp            multi-source UDP flood h1-h6 -> h18 (+ legitimate probes)
    syn            multi-source TCP SYN flood -> h18 (+ legitimate probes)
    icmp           multi-source ICMP flood h1-h6 -> h18 (+ legitimate probes)
    mixed          legitimate clients (h7 TCP, h8 UDP, h9 HTTP, h10 DNS-like, h13 ping) during an attack
    mitigation     = mixed, but requires MITIGATION_ENABLED and checks blocking + preservation + recovery
    recovery       verify no mitigation rule is left and every attacker can reach h18 again
    stop           kill every traffic generator in the lab

All traffic stays inside the isolated Mininet network (10.0.0.0/24).
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demolib import (  # noqa: E402
    HERE, RESULTS, ROOT, DemoError, HostProc, Sampler, chown_results, dump_drop_rules, ip_of,
    kill_lab_traffic, load_lab, ml_health, rest, rest_or_none, run_in_host,
)

VICTIM_IP = "10.0.0.18"
ATTACKERS = ["h1", "h2", "h3", "h4", "h5", "h6"]

# Per-attacker parameters: different packet sizes, rates and destination ports.
UDP_ATTACK = {"h1": (1024, 3000, 9999), "h2": (512, 3000, 53), "h3": (1400, 2000, 123),
              "h4": (1024, 3000, 1900), "h5": (256, 4000, 8080), "h6": (768, 2500, 9999)}
ICMP_ATTACK = {"h1": (512, 1500), "h2": (256, 2000), "h3": (1000, 1000),
               "h4": (512, 1500), "h5": (128, 2000), "h6": (768, 1200)}
SYN_RATE_PPS = 100   # per source; random source ports => one new flow per SYN (see guide)
SYN_FIXED_PPS = 2000  # per source; fixed source port => one flow per attacker

PRESERVE_TCP_RATIO = 0.70      # legit TCP keeps >= 70 % of its pre-attack throughput
PRESERVE_MAX_LOSS = 5.0        # legit UDP / ping / DNS-like loss <= 5 %
BLOCKED_MIN_REDUCTION = 90.0   # delivered attack pps reduced by >= 90 %


def hping_interval(pps):
    return f"u{max(int(1_000_000 / max(pps, 1)), 20)}"


# ===================================================================== traffic
def attack_cmds(kind, hosts, duration):
    out = []
    for i, h in enumerate(hosts):
        if kind == "udp":
            size, pps, dport = UDP_ATTACK.get(h, (1024, 3000, 9999))
            sport = 40001 + i
            # -k -s: fixed source port => one flow per attacker (a random-port flood creates one
            # OpenFlow rule + packet-in per packet in this reactive controller).
            cmd = f"timeout -s INT {duration} hping3 --udp -d {size} -i {hping_interval(pps)} -k -s {sport} -p {dport} -q {VICTIM_IP}"
            out.append((h, cmd, {"proto": "UDP", "pkt_size": size, "rate_pps": pps, "dport": dport, "sport": sport}))
        elif kind == "icmp":
            size, pps = ICMP_ATTACK.get(h, (512, 1500))
            cmd = f"timeout -s INT {duration} hping3 --icmp -d {size} -i {hping_interval(pps)} -q {VICTIM_IP}"
            out.append((h, cmd, {"proto": "ICMP", "pkt_size": size, "rate_pps": pps}))
        elif kind == "syn":
            # random source port per SYN (realistic shape; each SYN is a new flow / packet-in here)
            cmd = f"timeout -s INT {duration} hping3 -S -p 80 -i {hping_interval(SYN_RATE_PPS)} -q {VICTIM_IP}"
            out.append((h, cmd, {"proto": "TCP-SYN", "pkt_size": 0, "rate_pps": SYN_RATE_PPS, "dport": 80,
                                 "sport": "random"}))
        elif kind == "synfixed":
            # same SYN packets but a fixed source port: one flow per attacker, data-plane volume
            sport = 41001 + i
            cmd = (f"timeout -s INT {duration} hping3 -S -p 80 -i {hping_interval(SYN_FIXED_PPS)} -k -s {sport} "
                   f"-q {VICTIM_IP}")
            out.append((h, cmd, {"proto": "TCP-SYN", "pkt_size": 0, "rate_pps": SYN_FIXED_PPS, "dport": 80,
                                 "sport": sport}))
        else:
            raise DemoError(f"unknown attack kind {kind}")
    return out


def legit_specs(kind, total):
    """Legitimate traffic generators: (host, kind, cmd, params). `total` = seconds to run."""
    T = int(total)
    # `timeout`, not `ping -w`: iputils ping with a deadline exits on the first ICMP error.
    ping = lambda h, iv=0.2: (h, "icmp_ping", f"timeout -s INT {T} ping -D -i {iv} {VICTIM_IP}", {"interval_s": iv})
    udp = lambda h, port, mbps, size: (h, "udp_iperf3",
                                       f"iperf3 -u -c {VICTIM_IP} -p {port} -b {mbps}M -l {size} -t {T} -i 1 -J "
                                       f"--get-server-output", {"mbps": mbps, "pkt_size": size, "port": port})
    tcp = lambda h, port, mbps: (h, "tcp_iperf3",
                                 f"iperf3 -c {VICTIM_IP} -p {port} {'-b %sM' % mbps if mbps else ''} -t {T} -i 1 -J",
                                 {"mbps_cap": mbps, "port": port})
    http = lambda h: (h, "http", "end=$((SECONDS+%d)); while [ $SECONDS -lt $end ]; do "
                                 "echo \"$(date +%%s.%%N) $(curl -s -o /dev/null --max-time 3 -w '%%{http_code} %%{time_total}' "
                                 "http://%s/medium.bin)\"; sleep 1; done" % (T, VICTIM_IP), {"object": "medium.bin (1 MB)"})
    dns = lambda h, qps, size: (h, "udp_request_response",
                                f"python3 {HERE}/udp_probe.py {VICTIM_IP} --port 5353 --qps {qps} --size {size} --duration {T}",
                                {"qps": qps, "pkt_size": size})
    if kind == "probes":
        return [udp("h7", 5201, 2, 1000), ping("h13")]
    if kind == "mixed":
        return [tcp("h7", 5202, 10), udp("h8", 5203, 2, 1000), http("h9"), dns("h10", 20, 128), ping("h13")]
    if kind == "benign":
        # 6 concurrent clients covering TCP, UDP (3 sizes/rates), ICMP and HTTP.
        return [tcp("h11", 5204, 20), udp("h12", 5205, 1, 200), udp("h14", 5206, 8, 1400),
                udp("h15", 5207, 4, 512), http("h9"), ping("h10")]
    if kind == "crowd":
        # 9 concurrent clients ("flash crowd"): KNOWN false-alarm case of the window model,
        # which weights the number of concurrent sources heavily (see docs/DEMO_GUIDE.md).
        return [tcp("h11", 5204, 20), udp("h12", 5205, 1, 200), udp("h14", 5206, 8, 1400),
                udp("h15", 5207, 4, 512), udp("h17", 5208, 2, 1024), dns("h16", 20, 256),
                http("h9"), ping("h10"), ping("h8", 0.5)]
    raise DemoError(kind)


# ===================================================================== parsing legit logs
_IPERF_SRV = re.compile(r"\]\s+([\d.]+)-([\d.]+)\s+sec\s+\S+\s+\S+\s+([\d.]+)\s+([KMG]?)bits/sec\s+\S+\s+ms\s+"
                        r"(\d+)/(\d+)")


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def legit_series(proc):
    """-> list of (abs_time, metric dict) per second for a legitimate generator."""
    out = []
    if proc.kind in ("udp_iperf3", "tcp_iperf3"):
        d = _load_json(proc.log)
        if not d or "intervals" not in d:
            return out
        t0 = d.get("start", {}).get("timestamp", {}).get("timesecs", proc.t_start)
        t0 = max(t0, proc.t_start)
        if proc.kind == "tcp_iperf3":
            for iv in d["intervals"]:
                s = iv["sum"]
                out.append((t0 + s["start"], {"mbps": s["bits_per_second"] / 1e6}))
        else:
            srv = d.get("server_output_json") or {}
            for iv in srv.get("intervals", []):
                s = iv["sum"]
                out.append((t0 + s["start"], {"mbps": s["bits_per_second"] / 1e6, "lost": s.get("lost_packets", 0),
                                              "packets": s.get("packets", 0)}))
            # Victim servers run without -J, so the server report arrives as text lines like
            # "[  5]   3.00-4.00   sec   122 KBytes  1000 Kbits/sec  0.195 ms  0/625 (0%)"
            for line in (d.get("server_output_text") or "").splitlines():
                m = _IPERF_SRV.search(line)
                if not m:
                    continue
                a, b = float(m.group(1)), float(m.group(2))
                if b - a > 1.5:
                    continue  # the final summary line
                rate = float(m.group(3)) * {"": 1e-6, "K": 1e-3, "M": 1.0, "G": 1e3}[m.group(4)]
                out.append((t0 + a, {"mbps": rate, "lost": int(m.group(5)), "packets": int(m.group(6))}))
    elif proc.kind == "icmp_ping":
        iv = proc.params["interval_s"]
        replies = {}
        for line in Path(proc.log).read_text(errors="replace").splitlines():
            if "icmp_seq=" in line and "time=" in line and line.startswith("["):
                ts = float(line[1:line.index("]")])
                seq = int(line.split("icmp_seq=")[1].split()[0])
                rtt = float(line.split("time=")[1].split()[0])
                replies[seq] = (ts, rtt)
        if not replies:
            return out
        last = max(replies)
        for seq in range(1, last + 1):
            t = proc.t_start + (seq - 1) * iv
            r = replies.get(seq)
            out.append((t, {"sent": 1, "answered": 1 if r else 0, "rtt_ms": r[1] if r else None}))
    elif proc.kind == "udp_request_response":
        for line in Path(proc.log).read_text(errors="replace").splitlines():
            try:
                j = json.loads(line)
            except ValueError:
                continue
            if "t" in j:
                out.append((j["t"], {"sent": j["sent"], "answered": j["answered"], "rtt_ms": j["rtt_ms_avg"]}))
    elif proc.kind == "http":
        for line in Path(proc.log).read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    out.append((float(parts[0]), {"sent": 1, "answered": 1 if parts[1] == "200" else 0,
                                                  "rtt_ms": float(parts[2]) * 1000}))
                except ValueError:
                    pass
    return out


def summarize_phase(proc, series, t_a, t_b):
    pts = [m for t, m in series if t_a <= t < t_b]
    if not pts:
        return None
    if proc.kind == "tcp_iperf3":
        return {"mbps": round(sum(p["mbps"] for p in pts) / len(pts), 2), "n": len(pts)}
    if proc.kind == "udp_iperf3":
        pk = sum(p["packets"] for p in pts)
        lost = sum(p["lost"] for p in pts)
        return {"mbps": round(sum(p["mbps"] for p in pts) / len(pts), 2),
                "loss_pct": round(100.0 * lost / pk, 2) if pk else None, "n": len(pts)}
    sent = sum(p["sent"] for p in pts)
    ans = sum(p["answered"] for p in pts)
    rtts = [p["rtt_ms"] for p in pts if p.get("rtt_ms") is not None]
    return {"loss_pct": round(100.0 * (sent - ans) / sent, 2) if sent else None,
            "rtt_ms": round(sum(rtts) / len(rtts), 3) if rtts else None, "n": sent}


def phase_ok(proc, pre, ph):
    if ph is None:
        return None
    if proc.kind == "tcp_iperf3":
        if not pre or not pre.get("mbps"):
            return ph["mbps"] > 0
        return ph["mbps"] >= PRESERVE_TCP_RATIO * pre["mbps"]
    loss = ph.get("loss_pct")
    return loss is not None and loss <= PRESERVE_MAX_LOSS


# ===================================================================== helpers
def say(msg=""):
    print(msg, flush=True)


def banner(text, ch="="):
    say(ch * 78)
    say(" " + text)
    say(ch * 78)


def preflight(lab, need_mode=None):
    st = rest("GET", "/status")
    if st["n_switches"] < 6:
        raise DemoError(f"only {st['n_switches']}/6 switches connected to the controller")
    if ml_health() is None:
        say("WARNING: ML API (127.0.0.1:8765) not reachable - flow-level ML evidence will be missing.")
    if need_mode and st["mode"] != need_mode:
        raise DemoError(f"controller mode is {st['mode']}; this step needs {need_mode}. "
                        f"Run scripts/demo/10_enable_mitigation.sh first.")
    return st


def wait_for_quiet(timeout=60):
    """Wait until the victim is NORMAL and no rule is installed (previous test fully recovered)."""
    t_end = time.time() + timeout
    while time.time() < t_end:
        st = rest_or_none("GET", "/status")
        if st and st["states"].get(VICTIM_IP, {}).get("state", "NORMAL") == "NORMAL" and st["n_rules"] == 0:
            return True
        time.sleep(1)
    return False


def new_run_dir(name):
    d = RESULTS / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_{name}"
    (d / "hosts").mkdir(parents=True, exist_ok=True)
    return d


def write_timeline(run_dir, rows):
    cols = ["t", "rel_s", "mode", "poll", "state", "label", "score", "threshold", "n_rules", "ctl_pps",
            "ctl_mbps", "ctl_n_sources", "ctl_n_flows", "ctl_avg_pkt", "ctl_ml_max_prob", "ctl_ml_flagged",
            "victim_recv_pps", "victim_recv_mbps", "attack_sent_pps", "attack_delivered_pps",
            "legit_delivered_pps", "controller_ok"]
    t0 = rows[0]["t"] if rows else 0
    with open(run_dir / "timeline.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in rows:
            r = dict(r, rel_s=round(r["t"] - t0, 1))
            w.writerow([("" if r.get(c) is None else (round(r[c], 4) if isinstance(r.get(c), float) else r[c]))
                        for c in cols])


def append_results_csv(row):
    path = RESULTS / "demo_results.csv"
    cols = ["run_id", "scenario", "start", "end", "mode", "traffic_type", "n_attack_sources", "attack_hosts",
            "victim_ip", "attack_pkt_sizes", "per_source_rate_pps", "offered_attack_pps",
            "delivered_attack_pps_before_mitigation", "delivered_attack_pps_after_mitigation",
            "attack_reduction_pct", "detected", "max_state", "max_window_score", "flow_ml_max_prob",
            "flow_ml_flagged_pct", "detection_latency_s", "suspicious_latency_s", "mitigation_latency_s",
            "n_rules_installed", "rules_on_legit_hosts", "legit_tcp_mbps_before", "legit_tcp_mbps_during",
            "legit_tcp_mbps_after", "legit_udp_loss_before", "legit_udp_loss_during", "legit_udp_loss_after",
            "legit_ping_loss_during", "legit_status", "recovered", "recovery_time_s", "false_alarm",
            "statuses", "result_dir"]
    new = not path.exists()
    with open(path, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        if new:
            w.writeheader()
        w.writerow({c: row.get(c, "") for c in cols})


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def r1(x, nd=1):
    return None if x is None else round(x, nd)


# ===================================================================== scenarios
def scenario_connectivity(lab, args):
    banner("CONNECTIVITY TEST")
    st = rest_or_none("GET", "/status")
    say(f"controller: {'OK' if st else 'NOT REACHABLE'}"
        + (f"  switches={st['n_switches']}/6 {['s%d' % d for d in st['switches']]}  mode={st['mode']}" if st else ""))
    mh = ml_health()
    say(f"ML API:     {'OK ' + str(mh) if mh else 'NOT REACHABLE'}")
    results = {}
    for src in ("h1", "h7", "h13"):
        r = run_in_host(lab, src, f"ping -c 5 -i 0.2 -W 1 {VICTIM_IP}", timeout=20)
        line = [l for l in r.stdout.splitlines() if "packet loss" in l or "rtt" in l]
        results[src] = r.returncode == 0
        say(f"  {src:>4} -> h18 : {'OK  ' if r.returncode == 0 else 'FAIL'} {' | '.join(line)}")
    fails = []
    for h in sorted(lab["hosts"], key=lambda x: int(x[1:])):
        if h == lab["victim"]:
            continue
        r = run_in_host(lab, h, f"ping -c 2 -i 0.2 -W 1 {VICTIM_IP}", timeout=10)
        if r.returncode != 0:
            fails.append(h)
    say(f"  all 17 hosts -> h18 : {'OK' if not fails else 'FAILED from ' + ','.join(fails)}")
    ok = bool(st) and st["n_switches"] >= 6 and all(results.values()) and not fails
    say("\nRESULT: " + ("CONNECTIVITY OK" if ok else "CONNECTIVITY PROBLEM"))
    return 0 if ok else 1


def scenario_recovery(lab, args):
    banner("RECOVERY CHECK")
    st = rest("GET", "/status")
    rules = rest("GET", "/rules")
    ovs = dump_drop_rules()
    say(f"controller mode={st['mode']}  rules (controller)={rules['n_rules']}  drop rules on switches (OVS)={len(ovs)}")
    for f in ovs:
        say("   " + f["raw"])
    vs = st["states"].get(VICTIM_IP, {}).get("label", "NORMAL TRAFFIC")
    say(f"victim state: {vs}")
    fails = []
    for h in ATTACKERS:
        ping = run_in_host(lab, h, f"ping -c 3 -i 0.2 -W 1 {VICTIM_IP}", timeout=10).returncode == 0
        udp = run_in_host(lab, h, f"python3 {HERE}/udp_probe.py {VICTIM_IP} --qps 10 --duration 1.5",
                          timeout=10).returncode == 0
        tcp = run_in_host(lab, h, f"curl -s -o /dev/null --max-time 3 -w '%{{http_code}}' http://{VICTIM_IP}/small.bin",
                          timeout=10).stdout.strip() == "200"
        say(f"  {h} -> h18  ICMP {'OK' if ping else 'FAIL'}   UDP {'OK' if udp else 'FAIL'}   TCP/HTTP {'OK' if tcp else 'FAIL'}")
        if not (ping and udp and tcp):
            fails.append(h)
    ok = rules["n_rules"] == 0 and not ovs and not fails
    say("\nRESULT: " + ("NETWORK RECOVERED" if ok else "NOT FULLY RECOVERED"))
    if not ok and (rules["n_rules"] or ovs):
        say("  -> remove rules with: sudo scripts/demo/mitigation_ctl.sh remove-all")
    return 0 if ok else 1


def run_traffic_experiment(lab, args, scenario, attack_kind, legit_kind):
    st0 = preflight(lab, need_mode="MITIGATION_ENABLED" if scenario == "mitigation" else None)
    mode = st0["mode"]
    attack_hosts = [] if attack_kind is None else args.attackers
    warm, A, R = args.warmup, args.attack_duration, args.recovery_wait
    total = warm + (A + R if attack_kind else 0) + (0 if attack_kind else args.benign_duration)
    run_dir = new_run_dir(attack_kind if scenario == "syn" else scenario)
    title = {"benign": "SCENARIO A - NORMAL TRAFFIC ONLY",
             "crowd": "SCENARIO A2 - FLASH CROWD (9 legitimate clients, known false-alarm case)","udp": "SCENARIO B - MULTI-SOURCE UDP FLOOD",
             "syn": "SCENARIO C - TCP SYN FLOOD", "icmp": "SCENARIO D - ICMP FLOOD",
             "mixed": "SCENARIO E - MIXED LEGITIMATE + ATTACK TRAFFIC",
             "mitigation": "MITIGATION DEMO - DETECT, BLOCK, PRESERVE, RECOVER"}[scenario]
    banner(f"{title}   (controller mode: {mode})")
    if not wait_for_quiet(timeout=45):
        say("WARNING: victim was not NORMAL / rules still present before the test started.")
    ev0 = rest("GET", "/events?since=0")["last_seq"]
    legit = legit_specs(legit_kind, total) if legit_kind else []
    legit_hosts = [h for h, *_ in legit]
    sampler = Sampler(lab, attack_hosts, legit_hosts)
    procs, attack_procs = [], []
    t_start = time.time()
    sampler.start()
    t_attack = t_attack_end = None
    try:
        for i, (h, kind, cmd, params) in enumerate(legit):
            procs.append(HostProc(lab, h, cmd, run_dir / "hosts" / f"legit_{h}_{kind}.log", "legit", kind, params,
                                  VICTIM_IP))
        say(f"[{0:5.1f}s] legitimate traffic started: " + ", ".join(f"{p.host}({p.kind})" for p in procs) if procs
            else "[  0.0s] no legitimate traffic")
        say(f"         watching the victim for {warm:.0f}s before any attack ...")
        _watch(sampler, t_start, warm)
        if attack_kind:
            specs = attack_cmds(attack_kind, attack_hosts, A)
            t_attack = time.time()
            for h, cmd, params in specs:
                attack_procs.append(HostProc(lab, h, cmd, run_dir / "hosts" / f"attack_{h}_{attack_kind}.log",
                                             "attack", f"{attack_kind}_flood", params, VICTIM_IP))
            say(f"[{t_attack - t_start:5.1f}s] ATTACK STARTED ({attack_kind.upper()}): "
                + ", ".join(f"{h}->{VICTIM_IP} {p['proto']} {p['pkt_size']}B@{p['rate_pps']}pps" for h, _, p in specs))
            _watch(sampler, t_start, A)
            for p in attack_procs:
                p.stop()
            kill_lab_traffic_attack()
            t_attack_end = time.time()
            say(f"[{t_attack_end - t_start:5.1f}s] ATTACK STOPPED. Watching recovery for up to {R:.0f}s ...")
            _watch(sampler, t_start, R)
        else:
            _watch(sampler, t_start, args.benign_duration)
        for p in procs:
            p.wait(timeout=8)
    finally:
        for p in attack_procs + procs:
            p.stop()
        sampler.stop()
    t_end = time.time()
    events = rest("GET", f"/events?since={ev0}")["events"]
    res = analyze(lab, scenario, attack_kind, mode, run_dir, t_start, t_end, t_attack, t_attack_end, procs,
                  attack_procs, sampler, events)
    (run_dir / "plan.json").write_text(json.dumps({
        "scenario": scenario, "attack_kind": attack_kind, "mode_at_start": mode, "victim_ip": VICTIM_IP,
        "timeline_s": {"warmup": warm, "attack": A if attack_kind else 0, "recovery_wait": R if attack_kind else 0},
        "t_start": t_start, "t_attack": t_attack, "t_attack_end": t_attack_end, "t_end": t_end,
        "generators": [p.describe() for p in procs + attack_procs]}, indent=1))
    (run_dir / "events.json").write_text(json.dumps(events, indent=1))
    if sampler.max_rules_snapshot:
        (run_dir / "rules_at_peak.json").write_text(json.dumps(sampler.max_rules_snapshot["rest"], indent=1))
        (run_dir / "ovs_drop_rules.txt").write_text("\n".join(sampler.max_rules_snapshot["ovs"]) + "\n")
    write_timeline(run_dir, sampler.rows)
    (run_dir / "result.json").write_text(json.dumps(res, indent=1, default=str))
    (run_dir / "summary.md").write_text(render_summary(res))
    append_results_csv(res["row"])
    chown_results(RESULTS)
    say("")
    say(render_summary(res, console=True))
    say(f"Results saved in: {run_dir}")
    return 0


def kill_lab_traffic_attack():
    import subprocess
    subprocess.run(["pkill", "-KILL", "-f", "[h]ping3"], capture_output=True)


def _watch(sampler, t_start, seconds):
    t_end = time.time() + seconds
    last_key = None
    while time.time() < t_end:
        time.sleep(min(1.0, max(t_end - time.time(), 0)))
        if not sampler.rows:
            continue
        r = sampler.rows[-1]
        key = (r.get("poll"), r.get("label"), r.get("n_rules"))
        if key == last_key:
            continue
        last_key = key
        if not r.get("controller_ok"):
            say(f"[{r['t'] - t_start:5.1f}s] controller not responding")
            continue
        say(f"[{r['t'] - t_start:5.1f}s] poll {r.get('poll'):>4}  {r.get('label', ''):<20} score={_f(r.get('score'), 3)} "
            f"src={_f(r.get('ctl_n_sources'), 0)} flows={_f(r.get('ctl_n_flows'), 0)} "
            f"pps={_f(r.get('ctl_pps'), 0)} ({_f(r.get('ctl_mbps'), 1)} Mbps) "
            f"flowML max_p={_f(r.get('ctl_ml_max_prob'), 2)}  rules={r.get('n_rules')}  "
            f"| measured: attack delivered={_f(r.get('attack_delivered_pps'), 0)} pps")


def _f(x, nd):
    return "-" if x is None else f"{x:.{nd}f}"


# ===================================================================== analysis
def analyze(lab, scenario, attack_kind, mode, run_dir, t_start, t_end, t_attack, t_attack_end, procs,
            attack_procs, sampler, events):
    rows = sampler.rows
    vic = [e for e in events if e.get("dst") == VICTIM_IP]
    state_ev = [e for e in vic if e["type"] == "state"]
    installs = [e for e in events if e["type"] == "rule_installed"]
    removals = [e for e in events if e["type"] in ("rule_removed", "rule_expired")]
    would = [e for e in events if e["type"] == "would_block"]
    attack_ips = {p.src_ip for p in attack_procs}
    legit_ips = {p.src_ip for p in procs}

    def first(evs, states, after):
        for e in evs:
            if e.get("state") in states and (after is None or e["ts"] >= after - 1.0):
                return e
        return None

    ref = t_attack if t_attack else t_start
    e_susp = first(state_ev, ("SUSPECTED",), ref)
    e_conf = first(state_ev, ("CONFIRMED", "MITIGATING"), ref)
    e_rule = next((e for e in installs if e["ts"] >= ref - 1.0), None)
    t_rule = e_rule["ts"] if e_rule else None
    order = ["NORMAL", "SUSPECTED", "RECOVERING", "CONFIRMED", "MITIGATING"]
    seen = {r.get("state") for r in rows if r.get("state")} | {e["state"] for e in state_ev}
    max_state = max(seen or {"NORMAL"}, key=lambda s: order.index(s) if s in order else 0)
    scores = [r.get("score") for r in rows if r.get("score") is not None]
    peak = max(rows, key=lambda r: r.get("score") or 0) if rows else {}
    rules_on_legit = sorted({e["src"] for e in installs if e["src"] in legit_ips})
    rules_on_attackers = sorted({e["src"] for e in installs if e["src"] in attack_ips})

    # ----- attack traffic measured on the switches
    att = {}
    if t_attack:
        a0, a1 = t_attack + 3, t_attack_end
        pre_mit_end = (t_rule if t_rule and t_rule < a1 else a1)
        before = [r for r in rows if a0 <= r["t"] < pre_mit_end]
        after = [r for r in rows if t_rule and t_rule + 3 <= r["t"] < a1]
        att = {
            "offered_pps": r1(mean([r["attack_sent_pps"] for r in rows if a0 <= r["t"] < a1]), 0),
            "delivered_before_pps": r1(mean([r["attack_delivered_pps"] for r in before]), 0),
            "delivered_after_pps": r1(mean([r["attack_delivered_pps"] for r in after]), 0) if after else None,
            "per_attacker": {},
        }
        for p in attack_procs:
            h = p.host
            att["per_attacker"][h] = {
                "ip": p.src_ip, "params": p.params,
                "sent_pps": r1(mean([r["per_attacker"][h]["sent_pps"] for r in rows if a0 <= r["t"] < a1]), 0),
                "delivered_before_pps": r1(mean([r["per_attacker"][h]["delivered_pps"] for r in before]), 0),
                "delivered_after_pps": r1(mean([r["per_attacker"][h]["delivered_pps"] for r in after]), 0)
                if after else None,
                "rule_installed": p.src_ip in rules_on_attackers,
            }
        b, a = att["delivered_before_pps"], att["delivered_after_pps"]
        att["reduction_pct"] = r1(100.0 * (1 - a / b), 1) if (b and a is not None) else None

    # ----- legitimate traffic, per phase
    if t_attack:
        mit_start = (t_rule + 3) if (t_rule and t_rule + 3 < t_attack_end) else None
        phases = {"before": (t_start + 3, t_attack),
                  "attack_unmitigated": (t_attack + 1, t_rule if mit_start else t_attack_end),
                  "mitigated": (mit_start, t_attack_end) if mit_start else None,
                  "after": (t_attack_end + 5, t_end)}
    else:
        phases = {"whole": (t_start + 3, t_end)}
    legit = {}
    for p in procs:
        series = legit_series(p)
        ent = {"host": p.host, "ip": p.src_ip, "kind": p.kind, "params": p.params, "phases": {},
               "blocked_by_rule": p.src_ip in rules_on_legit}
        for name, rng in phases.items():
            ent["phases"][name] = summarize_phase(p, series, *rng) if rng else None
        pre = ent["phases"].get("before") or ent["phases"].get("whole")
        check = ent["phases"].get("mitigated") if t_attack else ent["phases"].get("whole")
        if t_attack and check is None:
            check = ent["phases"].get("attack_unmitigated")
        ent["preserved"] = (not ent["blocked_by_rule"]) and bool(phase_ok(p, pre, check))
        legit[p.host] = ent

    # ----- recovery
    recovered, rec_time = None, None
    if t_attack_end:
        for r in rows:
            if r["t"] >= t_attack_end and r.get("state") == "NORMAL" and r.get("n_rules") == 0:
                recovered, rec_time = True, round(r["t"] - t_attack_end, 1)
                break
        recovered = bool(recovered)
    reach_ok = None
    if t_attack_end and recovered:
        reach_ok = all(run_in_host(lab, h, f"ping -c 2 -i 0.2 -W 1 {VICTIM_IP}", timeout=10).returncode == 0
                       for h in [p.host for p in attack_procs])

    # ----- statuses (only what the measurements support)
    statuses = []
    false_alarm = False
    if attack_kind is None:
        if max_state == "NORMAL":
            statuses.append("NORMAL TRAFFIC")
        elif max_state in ("SUSPECTED", "RECOVERING"):
            statuses.append("SUSPICIOUS TRAFFIC (false alarm on benign traffic - never confirmed)")
            false_alarm = True
        else:
            statuses.append("FALSE ALARM: ATTACK CONFIRMED ON BENIGN TRAFFIC")
            false_alarm = True
    else:
        if any(r.get("state") == "NORMAL" for r in rows if r["t"] < t_attack):
            statuses.append("NORMAL TRAFFIC")
        if e_susp:
            statuses.append("SUSPICIOUS TRAFFIC")
        if e_conf:
            statuses.append("ATTACK CONFIRMED")
        else:
            statuses.append("ATTACK NOT DETECTED")
        verified_ovs = bool(sampler.max_rules_snapshot and sampler.max_rules_snapshot["ovs"])
        if installs and verified_ovs:
            statuses.append("MITIGATION INSTALLED")
        elif would:
            statuses.append("DRY RUN: RULES WOULD HAVE BEEN INSTALLED (none installed)")
        elif mode == "DETECTION_ONLY" and e_conf:
            statuses.append("DETECTION ONLY: NO MITIGATION (mode DETECTION_ONLY)")
        if installs:
            red = att.get("reduction_pct")
            all_blocked = attack_ips <= set(rules_on_attackers)
            if red is not None and red >= BLOCKED_MIN_REDUCTION and all_blocked:
                statuses.append("ATTACK TRAFFIC BLOCKED")
            elif red is not None and red > 0:
                statuses.append(f"ATTACK TRAFFIC REDUCED ({red:.0f}%, {len(rules_on_attackers)}/{len(attack_ips)} sources blocked)")
            else:
                statuses.append("ATTACK TRAFFIC NOT REDUCED")
    if procs:
        if rules_on_legit:
            statuses.append("LEGITIMATE TRAFFIC BLOCKED: rule installed on " + ",".join(rules_on_legit))
        elif all(e["preserved"] for e in legit.values()):
            if attack_kind is None or installs:
                statuses.append("LEGITIMATE TRAFFIC PRESERVED")
            else:
                statuses.append("LEGITIMATE TRAFFIC OK (no rule touched it)")
        else:
            bad = [h for h, e in legit.items() if not e["preserved"]]
            statuses.append("LEGITIMATE TRAFFIC DEGRADED: " + ",".join(f"{h}({legit[h]['kind']})" for h in bad))
    if t_attack_end:
        if recovered and reach_ok:
            statuses.append("NETWORK RECOVERED")
        elif recovered:
            statuses.append("CONTROLLER RECOVERED BUT CONNECTIVITY CHECK FAILED")
        else:
            statuses.append("NOT RECOVERED WITHIN WAIT")

    # ----- flat CSV row
    def legit_pick(kind, phase, field):
        vals = [e["phases"].get(phase, {}) and e["phases"][phase].get(field) for e in legit.values()
                if e["kind"] == kind and e["phases"].get(phase)]
        return vals[0] if vals else ""
    during = "mitigated" if (t_attack and t_rule and t_rule + 3 < t_attack_end) else "attack_unmitigated"
    row = {
        "run_id": run_dir.name, "scenario": scenario,
        "start": datetime.fromtimestamp(t_start).isoformat(timespec="seconds"),
        "end": datetime.fromtimestamp(t_end).isoformat(timespec="seconds"), "mode": mode,
        "traffic_type": attack_kind.upper() if attack_kind else "BENIGN",
        "n_attack_sources": len(attack_procs), "attack_hosts": " ".join(p.host for p in attack_procs),
        "victim_ip": VICTIM_IP,
        "attack_pkt_sizes": " ".join(str(p.params.get("pkt_size")) for p in attack_procs),
        "per_source_rate_pps": " ".join(str(p.params.get("rate_pps")) for p in attack_procs),
        "offered_attack_pps": att.get("offered_pps", ""),
        "delivered_attack_pps_before_mitigation": att.get("delivered_before_pps", ""),
        "delivered_attack_pps_after_mitigation": "" if att.get("delivered_after_pps") is None else att["delivered_after_pps"],
        "attack_reduction_pct": "" if att.get("reduction_pct") is None else att["reduction_pct"],
        "detected": bool(e_conf) if attack_kind else "",
        "max_state": max_state, "max_window_score": r1(max(scores), 4) if scores else "",
        "flow_ml_max_prob": r1(peak.get("ctl_ml_max_prob"), 3) if peak else "",
        "flow_ml_flagged_pct": r1(100 * (peak.get("ctl_ml_flagged") or 0), 1) if peak else "",
        "detection_latency_s": r1(e_conf["ts"] - t_attack, 1) if (e_conf and t_attack) else "",
        "suspicious_latency_s": r1(e_susp["ts"] - t_attack, 1) if (e_susp and t_attack) else "",
        "mitigation_latency_s": r1(t_rule - t_attack, 1) if (t_rule and t_attack) else "",
        "n_rules_installed": len(installs), "rules_on_legit_hosts": " ".join(rules_on_legit),
        "legit_tcp_mbps_before": legit_pick("tcp_iperf3", "before", "mbps"),
        "legit_tcp_mbps_during": legit_pick("tcp_iperf3", during, "mbps") if t_attack else legit_pick("tcp_iperf3", "whole", "mbps"),
        "legit_tcp_mbps_after": legit_pick("tcp_iperf3", "after", "mbps"),
        "legit_udp_loss_before": legit_pick("udp_iperf3", "before", "loss_pct"),
        "legit_udp_loss_during": legit_pick("udp_iperf3", during, "loss_pct") if t_attack else legit_pick("udp_iperf3", "whole", "loss_pct"),
        "legit_udp_loss_after": legit_pick("udp_iperf3", "after", "loss_pct"),
        "legit_ping_loss_during": legit_pick("icmp_ping", during, "loss_pct") if t_attack else legit_pick("icmp_ping", "whole", "loss_pct"),
        "legit_status": ("blocked" if rules_on_legit else ("preserved" if all(e["preserved"] for e in legit.values())
                                                          else "degraded")) if legit else "",
        "recovered": "" if recovered is None else (recovered and bool(reach_ok)),
        "recovery_time_s": "" if rec_time is None else rec_time, "false_alarm": false_alarm,
        "statuses": " | ".join(statuses), "result_dir": str(run_dir.relative_to(ROOT)),
    }
    return {
        "scenario": scenario, "attack_kind": attack_kind, "mode": mode, "run_dir": str(run_dir),
        "times": {"start": t_start, "attack_start": t_attack, "attack_end": t_attack_end, "end": t_end,
                  "first_suspected": e_susp["ts"] if e_susp else None,
                  "first_confirmed": e_conf["ts"] if e_conf else None, "first_rule": t_rule},
        "phases": {k: (None if v is None else [round(v[0] - t_start, 1), round(v[1] - t_start, 1)])
                   for k, v in phases.items()},
        "detection": {"max_state": max_state, "max_score": max(scores) if scores else None,
                      "threshold": peak.get("threshold"), "peak_window": {k: peak.get(k) for k in (
                          "ctl_n_sources", "ctl_n_flows", "ctl_pps", "ctl_mbps", "ctl_avg_pkt",
                          "ctl_ml_max_prob", "ctl_ml_flagged", "score", "label")},
                      "peak_sources": peak.get("window_sources", []),
                      "n_state_events": len(state_ev)},
        "mitigation": {"installed": installs, "removed": removals, "would_block": would,
                       "rules_on_attackers": rules_on_attackers, "rules_on_legit": rules_on_legit,
                       "ovs_rules_at_peak": sampler.max_rules_snapshot["ovs"] if sampler.max_rules_snapshot else []},
        "attack_traffic": att, "legit": legit,
        "recovery": {"recovered": recovered, "recovery_time_s": rec_time, "attackers_reach_victim": reach_ok},
        "statuses": statuses, "row": row,
    }


def render_summary(res, console=False):
    row, det, att = res["row"], res["detection"], res["attack_traffic"]
    L = []
    L.append(f"# Demo result: {row['run_id']}\n" if not console else "=" * 78)
    if console:
        L.append(f" RESULT  {row['scenario']}  ({row['traffic_type']}, controller mode {row['mode']})")
        L.append("=" * 78)
    else:
        L.append(f"- scenario: **{row['scenario']}**  traffic: **{row['traffic_type']}**  mode: **{row['mode']}**")
        L.append(f"- start {row['start']}  end {row['end']}  victim {row['victim_ip']}\n")
    pw = det["peak_window"]
    L.append("Detection (controller view at the highest-scoring window):")
    L.append(f"  max state: {det['max_state']}   max window score: {_f(det['max_score'], 3)} "
             f"(threshold {_f(det['threshold'], 3)})")
    L.append(f"  sources={_f(pw.get('ctl_n_sources'), 0)}  active flows={_f(pw.get('ctl_n_flows'), 0)}  "
             f"aggregate={_f(pw.get('ctl_pps'), 0)} pps / {_f(pw.get('ctl_mbps'), 2)} Mbps  "
             f"avg pkt={_f(pw.get('ctl_avg_pkt'), 0)} B")
    L.append(f"  flow-level ML (CIC-DDoS2019 model): max attack probability={_f(pw.get('ctl_ml_max_prob'), 3)}, "
             f"{_f(100 * (pw.get('ctl_ml_flagged') or 0), 0)}% of flows flagged")
    if det["peak_sources"]:
        L.append("  per-source view at that window (pps | flow-ML max prob | source score | blocked):")
        for s in det["peak_sources"][:10]:
            L.append(f"    {s['src']:<10} {s['pps']:>8.0f} pps | {s['ml_max_prob']:.2f} | "
                     f"{_f(s.get('source_score'), 2)} | {'yes' if s.get('blocked') else 'no'}")
    if res["attack_kind"]:
        L.append(f"  latency from attack start: suspicious={row['suspicious_latency_s'] or '-'} s, "
                 f"confirmed={row['detection_latency_s'] or '-'} s, first rule={row['mitigation_latency_s'] or '-'} s")
        L.append("")
        L.append("Attack traffic (measured on the switches, packets/s):")
        L.append(f"  offered by attackers: {att.get('offered_pps')}   delivered to victim switch before mitigation: "
                 f"{att.get('delivered_before_pps')}   after mitigation: {att.get('delivered_after_pps')}   "
                 f"reduction: {att.get('reduction_pct')}%")
        for h, a in att.get("per_attacker", {}).items():
            L.append(f"    {h} ({a['ip']}) {a['params'].get('proto')} {a['params'].get('pkt_size')}B "
                     f"@{a['params'].get('rate_pps')}pps: sent {a['sent_pps']}  delivered before {a['delivered_before_pps']}"
                     f"  after {a['delivered_after_pps']}  rule={'yes' if a['rule_installed'] else 'no'}")
        mit = res["mitigation"]
        L.append("")
        L.append(f"Mitigation: {len(mit['installed'])} rule(s) installed, {len(mit['removed'])} removed/expired, "
                 f"{len(mit['would_block'])} dry-run would-block")
        for e in mit["installed"]:
            L.append(f"    INSTALLED {e['cookie']} DROP {e['src']} -> {e['dst']} {e['proto_name']} at {e['switches']}")
        if mit["ovs_rules_at_peak"]:
            L.append("  rules as reported by Open vSwitch (ovs-ofctl dump-flows):")
            for r in mit["ovs_rules_at_peak"]:
                L.append("    " + r)
    if res["legit"]:
        L.append("")
        L.append("Legitimate traffic (per phase):")
        for h, e in res["legit"].items():
            ph = "  ".join(f"{k}: {_fmt_phase(v)}" for k, v in e["phases"].items() if v)
            L.append(f"  {h} {e['kind']:<21} {ph}   -> {'preserved' if e['preserved'] else 'NOT preserved'}"
                     f"{' (BLOCKED BY RULE)' if e['blocked_by_rule'] else ''}")
    if res["attack_kind"]:
        rc = res["recovery"]
        L.append("")
        L.append(f"Recovery: {'yes' if rc['recovered'] else 'no'}"
                 f"{' after %ss' % rc['recovery_time_s'] if rc['recovery_time_s'] is not None else ''}; "
                 f"attackers reach victim again: {rc['attackers_reach_victim']}")
    L.append("")
    L.append("STATUS:")
    for s in res["statuses"]:
        L.append(f"  >>> {s}")
    L.append("")
    return "\n".join(L)


def _fmt_phase(v):
    parts = []
    if v.get("mbps") is not None:
        parts.append(f"{v['mbps']}Mbps")
    if v.get("loss_pct") is not None:
        parts.append(f"loss {v['loss_pct']}%")
    if v.get("rtt_ms") is not None:
        parts.append(f"rtt {v['rtt_ms']}ms")
    return "/".join(parts) or "-"


# ===================================================================== main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", choices=["connectivity", "benign", "crowd", "udp", "syn", "icmp", "mixed", "mitigation",
                                         "recovery", "stop"])
    ap.add_argument("--syn-mode", choices=["random", "fixed"], default="random",
                    help="syn scenario: random source port per SYN (default) or fixed port per attacker")
    ap.add_argument("--attack", choices=["udp", "syn", "synfixed", "icmp"], default="udp",
                    help="attack type for 'mixed' / 'mitigation' (default udp)")
    ap.add_argument("--attackers", default=",".join(ATTACKERS), help="comma-separated attacker hosts (default h1-h6)")
    ap.add_argument("--warmup", type=float, default=15.0, help="seconds of legit-only traffic before the attack")
    ap.add_argument("--attack-duration", type=float, default=40.0)
    ap.add_argument("--recovery-wait", type=float, default=40.0)
    ap.add_argument("--benign-duration", type=float, default=50.0)
    args = ap.parse_args()
    args.attackers = [h.strip() for h in args.attackers.split(",") if h.strip()]
    import os
    if os.geteuid() != 0:
        sys.exit("Run as root (needs mnexec / ovs-ofctl):  sudo scripts/demo/<script>.sh")
    try:
        if args.scenario == "stop":
            kill_lab_traffic()
            say("All lab traffic generators stopped.")
            return 0
        lab = load_lab()
        bad = [h for h in args.attackers if h not in lab["hosts"] or h == lab["victim"]]
        if bad:
            raise DemoError(f"invalid attacker host(s): {bad}")
        if args.scenario == "connectivity":
            return scenario_connectivity(lab, args)
        if args.scenario == "recovery":
            return scenario_recovery(lab, args)
        if args.scenario in ("benign", "crowd"):
            return run_traffic_experiment(lab, args, args.scenario, None, args.scenario)
        if args.scenario in ("udp", "syn", "icmp"):
            kind = "synfixed" if (args.scenario == "syn" and args.syn_mode == "fixed") else args.scenario
            return run_traffic_experiment(lab, args, args.scenario, kind, "probes")
        return run_traffic_experiment(lab, args, args.scenario, args.attack, "mixed")
    except DemoError as e:
        say(f"ERROR: {e}")
        return 2
    except KeyboardInterrupt:
        kill_lab_traffic()
        say("Interrupted - lab traffic stopped.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
