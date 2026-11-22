#!/usr/bin/env python3
"""Large SDN testbed (25 OpenFlow switches, 200 hosts) and one scheduled traffic session.

Topology (3-tier tree, no loops):
    core s1  --  aggregation s2..s5  --  edge s6..s25 (10 hosts each)  =  200 hosts h1..h200
    host links 100 Mbit/s, edge-agg 200 Mbit/s, agg-core 400 Mbit/s
    victim server  h200 = 10.0.0.200, access link VICTIM_BW (default 50 Mbit/s = bottleneck)
    other servers  h199 = 10.0.0.199, h198 = 10.0.0.198 (benign destinations only)

Roles (seeded): 40 attackers (2 per edge switch, sharing switches with legitimate users)
and 157 legitimate clients: web (HTTP), rr (DNS-like UDP), stream (UDP video-like),
bulk (TCP), ping. Legitimate traffic runs during the whole session.

The schedule is a list of segments (benign periods and attacks). Ground truth (attacker
IPs and exact epoch intervals) is written to session.json; experiments/large/split_session.py
cuts the controller telemetry into per-segment run directories for replay/evaluation.

Run as root, after the controller is up:  python3 experiments/large/large_lab.py --session S --seed N --plan test
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import threading
import time
from pathlib import Path

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
N_AGG, N_EDGE, PER_EDGE = 4, 20, 10
VICTIM, S2, S3 = "h200", "h199", "h198"
SERVERS = (VICTIM, S2, S3)
BINDINGS = ROOT / "experiments" / "results" / "large" / "current_lab_state.json"


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


class TreeTopo(Topo):
    def build(self, victim_bw=50.0):
        core = self.addSwitch("s1", protocols="OpenFlow13")
        aggs = [self.addSwitch("s%d" % (2 + i), protocols="OpenFlow13") for i in range(N_AGG)]
        for a in aggs:
            self.addLink(a, core, bw=400)
        h = 0
        for e in range(N_EDGE):
            es = self.addSwitch("s%d" % (6 + e), protocols="OpenFlow13")
            self.addLink(es, aggs[e % N_AGG], bw=200)
            for _ in range(PER_EDGE):
                h += 1
                name = "h%d" % h
                host = self.addHost(name, ip="10.0.0.%d/24" % h, mac="00:00:00:00:%02x:%02x" % (h // 256, h % 256))
                self.addLink(host, es, bw=victim_bw if name == VICTIM else 100)


def assign_roles(seed):
    rng = random.Random(1000 + seed)
    attackers = []
    for e in range(N_EDGE):
        hosts = ["h%d" % (e * PER_EDGE + j + 1) for j in range(PER_EDGE)]
        hosts = [x for x in hosts if x not in SERVERS]
        attackers += rng.sample(hosts, 2)
    clients = [("h%d" % i) for i in range(1, 201) if "h%d" % i not in SERVERS and "h%d" % i not in attackers]
    rng.shuffle(clients)
    roles = {}
    counts = [("web", 95), ("rr", 25), ("stream", 12), ("bulk", 10), ("ping", 15)]
    i = 0
    for role, n in counts:
        for h in clients[i:i + n]:
            roles[h] = role
        i += n
    return attackers, roles


def ip(h):
    return "10.0.0.%d" % int(h[1:])


# ------------------------------------------------------------------ attack commands
def attack_cmd(kind, target, rng, rate, size, sport):
    iv = max(int(1e6 / max(rate, 1)), 50)
    if kind == "udp":
        return "hping3 --udp -k -s %d -p 9999 -d %d -i u%d -q %s" % (sport, size, iv, target)
    if kind == "syn":
        return "hping3 -S -k -s %d -p 80 -i u%d -q %s" % (sport, iv, target)
    if kind == "icmp":
        return "hping3 --icmp -d %d -i u%d -q %s" % (size, iv, target)
    if kind == "spoof":
        return "hping3 --udp --rand-source -p 9999 -d %d -i u%d -q %s" % (size, iv, target)
    raise ValueError(kind)


def build_plan(plan, seed, attackers):
    """Return list of segments: dict(kind, duration, gap_after, attacks=[(host, proto, rate, size, [(t0,dur)...])])."""
    rng = random.Random(seed)

    def flood(proto, hosts, rate_lo, rate_hi, pulses):
        return [(h, proto, rng.uniform(rate_lo, rate_hi), rng.randint(200, 1200) if proto != "syn" else 0,
                 pulses) for h in hosts]

    A = list(attackers)
    segs = [dict(kind="benign", duration=60, gap_after=0, attacks=[])]
    segs.append(dict(kind="flash", duration=20, gap_after=40, attacks=[]))
    segs.append(dict(kind="udp", duration=30, gap_after=40, attacks=flood("udp", rng.sample(A, 40), 220, 380, [(0, 30)])))
    segs.append(dict(kind="syn", duration=30, gap_after=40, attacks=flood("syn", rng.sample(A, 40), 220, 380, [(0, 30)])))
    segs.append(dict(kind="icmp", duration=30, gap_after=40, attacks=flood("icmp", rng.sample(A, 40), 220, 380, [(0, 30)])))
    segs.append(dict(kind="lowrate", duration=40, gap_after=40, attacks=flood("udp", rng.sample(A, 40), 25, 45, [(0, 40)])))
    pul = [(i * 16, 6) for i in range(4)]
    segs.append(dict(kind="pulsing", duration=58, gap_after=40, attacks=flood("udp", rng.sample(A, 40), 250, 380, pul)))
    segs.append(dict(kind="spoof", duration=30, gap_after=40, attacks=[(h, "spoof", rng.uniform(120, 180), 512, [(0, 30)])
                                                                  for h in rng.sample(A, 4)]))
    half = rng.sample(A, 40)
    segs.append(dict(kind="mixed", duration=30, gap_after=40,
                     attacks=flood("udp", half[:20], 220, 380, [(0, 30)]) + flood("syn", half[20:], 220, 380, [(0, 30)])))
    if plan in ("test", "test3"):
        sw = rng.sample(A, 24)
        atk = []
        for h in sw:  # each attacker: UDP 20 s -> ICMP 20 s -> TCP SYN 20 s
            r, s = rng.uniform(250, 380), rng.randint(200, 1200)
            atk += [(h, "udp", r, s, [(0, 20)]), (h, "icmp", r, s, [(20, 20)]), (h, "syn", r, 0, [(40, 20)])]
        segs.append(dict(kind="protoswitch", duration=60, gap_after=40, attacks=atk))
        ra = rng.sample(A, 30)
        segs.append(dict(kind="reattack", duration=105, gap_after=40,
                         attacks=flood("udp", ra, 250, 380, [(0, 25), (40, 25), (80, 25)])))
        segs.append(dict(kind="benign", duration=60, gap_after=0, attacks=[]))
        segs.append(dict(kind="flash", duration=20, gap_after=40, attacks=[]))
    segs.append(dict(kind="benign", duration=60, gap_after=0, attacks=[]))
    if plan == "test3":
        # Fresh-seed validation (review round 1): same attack types, attack ORDER shuffled by the seed,
        # and 60 s benign gaps (> the 48 s maximum hold-down) to reduce carry-over between episodes.
        attacks = [s for s in segs if s["attacks"]]
        rng.shuffle(attacks)
        for s in attacks:
            s["gap_after"] = 60
        head = segs[:2]
        tail = [s for s in segs[2:] if not s["attacks"]]
        segs = head + attacks[:5] + tail[:2] + attacks[5:] + tail[2:]
    return segs


# --------------------------------------------------------------------- monitoring
class PortSampler(threading.Thread):
    """Every second: per-port rx/tx packet and byte counters of all edge switches."""

    def __init__(self, out):
        super().__init__(daemon=True)
        self.out = open(out, "w", buffering=1)
        self.out.write("ts,switch,port,rx_pkts,rx_bytes,tx_pkts,tx_bytes,tx_drop\n")
        self.stop = False

    def run(self):
        names = " ".join("s%d" % (6 + e) for e in range(N_EDGE))
        while not self.stop:
            t = time.time()
            txt = sh("for s in %s; do echo SW $s; ovs-ofctl -O OpenFlow13 dump-ports $s; done" % names)
            sw = None
            cur = None
            for line in txt.splitlines():
                line = line.strip()
                if line.startswith("SW "):
                    sw = line[3:]
                elif line.startswith("port") and "rx pkts" in line:
                    p = line.split(":")[0].split()[1]
                    kv = dict(x.split("=") for x in line.split(":", 1)[1].replace("rx", "").replace(" ", "").split(","))
                    cur = [p, kv.get("pkts", "0"), kv.get("bytes", "0")]
                elif line.startswith("tx pkts") and cur is not None:
                    kv = dict(x.split("=") for x in line.replace("tx", "").replace(" ", "").split(","))
                    if cur[0] != "LOCAL":
                        self.out.write("%.3f,%s,%s,%s,%s,%s,%s,%s\n" % (t, sw, cur[0], cur[1], cur[2], kv.get("pkts", 0),
                                                                    kv.get("bytes", 0), kv.get("drop", 0)))
                    cur = None
            time.sleep(max(0.0, 1.0 - (time.time() - t)))


def peer_name(host):
    intf = host.defaultIntf()
    link = intf.link
    return (link.intf2 if link.intf1 == intf else link.intf1).name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--plan", choices=["calib", "test", "test3", "smoke"], default="test")
    ap.add_argument("--victim-bw", type=float, default=25.0)
    ap.add_argument("--pktin-limit", type=int, default=400)
    args = ap.parse_args()
    out = ROOT / "experiments" / "results" / "large" / args.session
    (out / "legit").mkdir(parents=True, exist_ok=True)
    setLogLevel("warning")
    os.chdir(ROOT)
    for k, v in (("net.ipv4.neigh.default.gc_thresh1", 2048), ("net.ipv4.neigh.default.gc_thresh2", 4096),
                 ("net.ipv4.neigh.default.gc_thresh3", 8192)):
        sh("sysctl -w %s=%d" % (k, v))

    attackers, roles = assign_roles(args.seed)
    segs = build_plan(args.plan, args.seed, attackers)
    if args.plan == "smoke":
        segs = [dict(kind="benign", duration=30, gap_after=0, attacks=[]),
                dict(kind="udp", duration=20, gap_after=20,
                     attacks=[(h, "udp", 300, 800, [(0, 20)]) for h in attackers]),
                dict(kind="spoof", duration=15, gap_after=15,
                     attacks=[(h, "spoof", 150, 512, [(0, 15)]) for h in attackers[:4]])]

    print("*** building 25-switch / 200-host network", flush=True)
    t_build = time.time()
    net = Mininet(topo=TreeTopo(victim_bw=args.victim_bw), link=TCLink, controller=None, autoSetMacs=False,
                  autoStaticArp=False)
    net.addController(RemoteController("c0", ip="127.0.0.1", port=6653))
    sampler = None
    try:
        net.start()
        print("*** network up in %.0f s; disabling offloads" % (time.time() - t_build), flush=True)
        cmds = []
        for h in net.hosts:
            for intf in h.intfList():
                h.cmd("ethtool -K %s tx off tso off gso off gro off >/dev/null 2>&1" % intf)
        for s in net.switches:
            for intf in s.intfList():
                if intf.name != "lo":
                    cmds.append("ethtool -K %s tso off gso off gro off >/dev/null 2>&1" % intf.name)
        sh(" ; ".join(cmds))
        for uuid in sh("ovs-vsctl --bare --columns=_uuid list controller").split():
            sh("ovs-vsctl set controller %s controller_rate_limit=%d controller_burst_limit=200" % (uuid, args.pktin_limit))
        for _ in range(120):
            if sh("ovs-vsctl --columns=is_connected list controller").count("true") >= 25:
                break
            time.sleep(1)
        print("*** switches connected: %d/25" % sh("ovs-vsctl --columns=is_connected list controller").count("true"),
              flush=True)

        state = {"started": time.time(), "victim": VICTIM, "victim_ip": ip(VICTIM),
                 "hosts": {h.name: {"pid": h.pid, "ip": h.IP(), "switch_port": peer_name(h)} for h in net.hosts}}
        BINDINGS.parent.mkdir(parents=True, exist_ok=True)
        BINDINGS.write_text(json.dumps(state))
        os.chmod(BINDINGS, 0o644)
        (out / "lab_state.json").write_text(json.dumps(state))

        print("*** starting server services", flush=True)
        web = Path("/var/tmp/ddos_web_large")
        web.mkdir(exist_ok=True)
        (web / "small.bin").write_bytes(os.urandom(10_000))
        (web / "page.bin").write_bytes(os.urandom(100_000))
        for sname in SERVERS:
            s = net.get(sname)
            s.cmd("python3 %s/webserver.py %s >/dev/null 2>&1 &" % (HERE, web))
            s.cmd("python3 %s/agent.py tcpsink 5201 >/dev/null 2>&1 &" % HERE)
            s.cmd("python3 %s/experiments/scripts/udp_rr.py server 5353 >/dev/null 2>&1 &" % ROOT)
            s.cmd("python3 %s/scripts/demo/udp_sink.py 9999 9998 >/dev/null 2>&1 &" % ROOT)
            s.cmd("cd %s" % ROOT)

        print("*** static ARP on all hosts (no ARP broadcast storms)", flush=True)
        neigh = [(h.IP(), h.MAC()) for h in net.hosts]
        for h in net.hosts:
            f = Path("/var/tmp/arp_%s" % h.name)
            f.write_text("".join("neigh replace %s lladdr %s dev %s nud permanent\n" % (a, m, h.defaultIntf().name)
                                 for a, m in neigh if a != h.IP()))
            h.cmd("ip -batch %s" % f)
        print("*** warm-up: staggered broadcast from every host (all switches learn every host)", flush=True)
        for h in net.hosts:
            h.cmd("ping -b -c1 -W1 10.0.0.255 >/dev/null 2>&1 &")
            time.sleep(0.08)
        time.sleep(3)
        for h in net.hosts:   # one unicast round trip per client to its servers (installs nothing permanent)
            if h.name not in SERVERS:
                h.cmd("ping -c1 -W1 %s >/dev/null 2>&1 &" % ip(VICTIM))
                time.sleep(0.02)
        time.sleep(4)

        print("*** starting %d legitimate clients" % len(roles), flush=True)
        rng = random.Random(7 + args.seed)
        port_next = {VICTIM: 5201, S2: 5201}
        client_info = {}
        lg = out / "legit"
        for hname, role in sorted(roles.items(), key=lambda kv: int(kv[0][1:])):
            h = net.get(hname)
            if role == "web":
                tgt = rng.choices([VICTIM, S2, S3], weights=[0.6, 0.25, 0.15])[0]
                urls = ",".join("http://%s/%s" % (ip(tgt), f) for f in ("small.bin",) * 9 + ("page.bin",))
                cmd = "python3 %s/agent.py web %s 1.5 %d %s/%s_web.csv" % (HERE, urls, rng.randint(0, 1 << 30), lg, hname)
            elif role == "rr":
                tgt = rng.choices([VICTIM, S2], weights=[0.6, 0.4])[0]
                cmd = "python3 %s/agent.py rr %s 5353 4 %d %s/%s_rr.csv" % (HERE, ip(tgt), rng.randint(0, 1 << 30), lg, hname)
            elif role in ("stream", "bulk"):
                tgt = VICTIM if len([1 for v in client_info.values() if v["role"] == role]) % 2 == 0 else S2
                if role == "stream":   # 1 Mbit/s CBR UDP, 1200-byte datagrams (video-like)
                    cmd = "python3 %s/agent.py udpstream %s 9998 1000000 1200" % (HERE, ip(tgt))
                else:                  # 2 Mbit/s paced TCP bulk transfer
                    cmd = "python3 %s/agent.py tcpbulk %s 5201 2000000" % (HERE, ip(tgt))
            else:
                tgt = VICTIM if rng.random() < 0.67 else S2
                cmd = "ping -D -i 0.5 -W 1 %s > %s/%s_ping.txt 2>&1" % (ip(tgt), lg, hname)
            client_info[hname] = {"role": role, "target": tgt, "target_ip": ip(tgt), "ip": ip(hname)}
            h.cmd(cmd + " &")
            time.sleep(0.02)
        sampler = PortSampler(out / "port_counters.csv")
        sampler.start()
        print("*** benign traffic settling 25 s", flush=True)
        time.sleep(25)

        # --------------------------------------------------------- the schedule
        session = {"session": args.session, "seed": args.seed, "plan": args.plan, "victim": VICTIM,
                   "victim_ip": ip(VICTIM), "victim_bw_mbps": args.victim_bw, "attackers": attackers,
                   "attacker_ips": [ip(a) for a in attackers], "clients": client_info,
                   "victim_port": peer_name(net.get(VICTIM)), "segments": []}
        web_clients = [h for h, r in roles.items() if r == "web"]
        for i, seg in enumerate(segs):
            t0 = time.time()
            rec = {"idx": i, "kind": seg["kind"], "start": t0, "duration": seg["duration"],
                   "end": t0 + seg["duration"], "events": []}
            print("*** [%s] segment %d %-11s %3d s (+%d s gap)" % (time.strftime("%H:%M:%S"), i, seg["kind"],
                                                                 seg["duration"], seg["gap_after"]), flush=True)
            if seg["kind"] == "flash":
                # benign surge: every web client fetches the large page 6 times in the segment
                for hname in web_clients:
                    tgt = client_info[hname]["target_ip"]
                    net.get(hname).cmd("(for k in 1 2 3 4 5 6; do curl -s -o /dev/null --max-time 3 "
                                       "http://%s/page.bin; sleep $((RANDOM %% 3)); done) &" % tgt)
            sp = 20000
            for (hname, proto, rate, size, pulses) in seg["attacks"]:
                sp += 1
                cmd = attack_cmd(proto, ip(VICTIM), rng, rate, size, sp)
                parts = []
                last = 0.0
                for (ps, pd) in pulses:
                    parts.append("sleep %.2f; timeout %d %s >/dev/null 2>&1" % (ps - last, pd, cmd))
                    last = ps + pd
                    rec["events"].append({"host": hname, "src_ip": ip(hname) if proto != "spoof" else "spoofed",
                                          "proto": proto, "rate_pps": round(rate, 1), "size": size,
                                          "epoch_start": t0 + ps, "duration": pd, "role": "attack"})
                net.get(hname).cmd("(%s) &" % " ; ".join(parts))
            session["segments"].append(rec)
            (out / "session.json").write_text(json.dumps(session, indent=1))
            time.sleep(max(0.0, t0 + seg["duration"] + seg["gap_after"] - time.time()))
        session["finished"] = time.time()
        (out / "session.json").write_text(json.dumps(session, indent=1))
        print("*** session complete", flush=True)
    finally:
        if sampler is not None:
            sampler.stop = True
        sh("pkill -f '[h]ping3'; pkill -f '[a]gent.py'; pkill -f '[i]perf3 -'; pkill -f '[u]dp_rr.py';"
           " pkill -f '[u]dp_sink.py'; pkill -f '[w]ebserver.py'; pkill -f '[p]ing -D'")
        try:
            net.stop()
        except Exception as exc:
            print("net.stop failed:", exc)


if __name__ == "__main__":
    main()
