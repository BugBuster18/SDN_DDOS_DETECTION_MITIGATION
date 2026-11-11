#!/usr/bin/env python3
"""Start the 6-switch / 18-host Mininet lab for the demo and open the Mininet CLI.

Uses the project's unchanged topology class (Codes/mininet/topology.py: MyTopo)
with the settings the detector needs:
  * hosts NOT CPU-capped (the original default cap of 5 % CPU throttles traffic),
  * 100 Mbit/s TCLinks,
  * NIC offloads off, so OpenFlow packet counters count real packets,
  * victim (h18) services: iperf3 servers 5201-5220, iperf2 servers (TCP+UDP 5001),
    UDP sinks on 53/123/1900/8080/9999, a UDP request/response server on 5353,
    an HTTP server on port 80.

It writes experiments/results/demo/run/lab_state.json (host PIDs, IPs and switch
ports) so the scripts in scripts/demo/ can run traffic inside the hosts from
another terminal.

IMPORTANT: this script never runs `mn -c` (that command also kills ryu-manager).
Run it as root AFTER the controller is up:   sudo python3 scripts/demo/mininet_lab.py
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Codes" / "mininet"))
HERE = Path(__file__).resolve().parent

from mininet.cli import CLI  # noqa: E402
from mininet.link import TCLink  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402
from mininet.net import Mininet  # noqa: E402
from mininet.node import RemoteController  # noqa: E402

from topology import MyTopo  # noqa: E402

STATE_DIR = ROOT / "experiments" / "results" / "demo" / "run"
STATE_FILE = STATE_DIR / "lab_state.json"
VICTIM = "h18"
IPERF3_PORTS = list(range(5201, 5221))
SINK_PORTS = [53, 123, 1900, 8080, 9999]
REST = "http://127.0.0.1:8080/ddos/status"


def sh(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def controller_status():
    try:
        with urllib.request.urlopen(REST, timeout=2) as r:
            return json.loads(r.read())
    except Exception:
        return None


def targeted_cleanup():
    """Remove leftovers of a previous lab WITHOUT `mn -c` (which kills ryu-manager)."""
    sh("pkill -f '[m]ininet:' ; pkill -f '[h]ping3' ; pkill -f '[i]perf3 -' ; pkill -f '[i]perf -' ;"
       " pkill -f '[u]dp_sink.py' ; pkill -f '[u]dp_rr.py' ; pkill -f '[h]ttp.server 80'")
    for i in range(1, 7):
        sh(f"ovs-vsctl --if-exists del-br s{i}")
    for line in sh("ip -o link show").splitlines():
        try:
            name = line.split(":")[1].strip().split("@")[0]
        except IndexError:
            continue
        if (name.startswith("s") or name.startswith("h")) and "-eth" in name:
            sh(f"ip link del {name} 2>/dev/null")


def peer_name(host) -> str:
    intf = host.defaultIntf()
    link = intf.link
    return (link.intf2 if link.intf1 == intf else link.intf1).name


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--controller-ip", default="127.0.0.1")
    ap.add_argument("--bw", type=float, default=100.0, help="link capacity Mbit/s (0 = unlimited)")
    ap.add_argument("--pktin-limit", type=int, default=500,
                    help="OVS packet-in rate limit per switch, pps (0 = unlimited, OVS minimum 100)")
    ap.add_argument("--pktin-burst", type=int, default=100)
    ap.add_argument("--no-cli", action="store_true", help="start the lab and wait (Ctrl-C to stop) without a CLI")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Run as root:  sudo python3 scripts/demo/mininet_lab.py")

    st = controller_status()
    if st is None:
        print("WARNING: controller REST API (127.0.0.1:8080) not reachable. Is Terminal 2 running?\n"
              "         Continuing; switches will connect when the controller starts.")
    targeted_cleanup()
    setLogLevel("info")
    os.chdir(ROOT)
    net = Mininet(topo=MyTopo(bw=args.bw or None, cpu=None), link=TCLink, controller=None,
                  autoSetMacs=False)
    net.addController(RemoteController("c0", ip=args.controller_ip, port=6653))
    try:
        net.start()
        print("*** Disabling NIC offloads (real per-packet counters)")
        for h in net.hosts:
            for intf in h.intfList():
                h.cmd(f"ethtool -K {intf} tx off tso off gso off gro off >/dev/null 2>&1")
        for sw in net.switches:
            for intf in sw.intfList():
                if intf.name != "lo":
                    sh(f"ethtool -K {intf} tso off gso off gro off >/dev/null 2>&1")

        if args.pktin_limit > 0:
            # Control-plane protection: OVS forwards at most N table-miss packets/s per switch to
            # the controller (fair-queued per input port), dropping the excess instead of queueing
            # it. Without this, a flood's first packets build a packet-in backlog that the Python
            # controller needs ~1 min to drain, starving ARP and legitimate flow setup.
            print(f"*** Packet-in rate limit: {args.pktin_limit} pps per switch (burst {args.pktin_burst})")
            for uuid in sh("ovs-vsctl --bare --columns=_uuid list controller").split():
                sh(f"ovs-vsctl set controller {uuid} controller_rate_limit={args.pktin_limit} "
                   f"controller_burst_limit={args.pktin_burst}")
        print("*** Waiting for the 6 switches to connect to the controller")
        n = 0
        for _ in range(60):
            st = controller_status()
            if st:
                n = st["n_switches"]
            else:  # REST down: ask OVS directly
                n = sh("ovs-vsctl --columns=is_connected list controller").count("true")
            if n >= 6:
                break
            time.sleep(0.5)
        print(f"*** Controller reports {n}/6 switches connected")

        print("*** Starting victim services on h18 (10.0.0.18)")
        v = net.get(VICTIM)
        web = Path("/tmp/ddos_web")
        web.mkdir(exist_ok=True)
        (web / "small.bin").write_bytes(os.urandom(10_000))
        (web / "medium.bin").write_bytes(os.urandom(1_000_000))
        v.cmd(f"cd {web} && python3 -m http.server 80 >/dev/null 2>&1 &")
        v.cmd(f"cd {ROOT}")
        for p in IPERF3_PORTS:
            v.cmd(f"iperf3 -s -p {p} -D")
        v.cmd("iperf -s -D >/dev/null 2>&1")
        v.cmd("iperf -s -u -D >/dev/null 2>&1")
        v.cmd(f"python3 {HERE}/udp_sink.py {' '.join(map(str, SINK_PORTS))} >/dev/null 2>&1 &")
        v.cmd(f"python3 {ROOT}/experiments/scripts/udp_rr.py server 5353 >/dev/null 2>&1 &")
        for other in ("h9", "h12"):
            net.get(other).cmd("iperf3 -s -p 5201 -D")

        print("*** Warm-up: every host pings the victim once (ARP + host location learning)")
        for h in net.hosts:
            if h.name != VICTIM:
                h.cmd(f"ping -c1 -W1 10.0.0.18 >/dev/null 2>&1 &")
        time.sleep(2)

        STATE_DIR.mkdir(parents=True, exist_ok=True)
        state = {
            "started": time.time(), "controller": f"{args.controller_ip}:6653", "bw_mbps": args.bw,
            "pktin_limit_pps": args.pktin_limit,
            "victim": VICTIM, "victim_ip": v.IP(), "victim_switch_port": peer_name(v),
            "iperf3_ports": IPERF3_PORTS, "sink_ports": SINK_PORTS,
            "hosts": {h.name: {"pid": h.pid, "ip": h.IP(), "mac": h.MAC(), "switch_port": peer_name(h),
                               "switch": peer_name(h).split("-")[0]} for h in net.hosts},
        }
        STATE_FILE.write_text(json.dumps(state, indent=1))
        os.chmod(STATE_FILE, 0o644)

        print("\n" + "=" * 72)
        print(" LAB READY: 6 switches (s1..s6 chain), 18 hosts, victim h18 = 10.0.0.18")
        print("   s1: h1 h2 h3 | s2: h4 h5 h6 | s3: h7 h8 h9 | s4: h10 h11 h12")
        print("   s5: h13 h14 h15 | s6: h16 h17 h18(victim)")
        print(" Try:   mininet> h1 ping -c 3 h18")
        print(" Traffic scenarios run from Terminal 4:  sudo scripts/demo/05_test_benign_traffic.sh ...")
        print(" Lab state: " + str(STATE_FILE))
        print("=" * 72 + "\n")
        if args.no_cli:
            while True:
                time.sleep(3600)
        else:
            CLI(net)
    except KeyboardInterrupt:
        pass
    finally:
        print("*** Stopping lab traffic and victim services")
        sh("pkill -f '[h]ping3' ; pkill -f '[i]perf3 -' ; pkill -f '[i]perf -' ; pkill -f '[u]dp_sink.py' ;"
           " pkill -f '[u]dp_rr.py' ; pkill -f '[h]ttp.server 80'")
        try:
            STATE_FILE.unlink()
        except FileNotFoundError:
            pass
        net.stop()


if __name__ == "__main__":
    main()
