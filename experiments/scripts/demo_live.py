#!/usr/bin/env python3
"""Headless reproduction of the INTERACTIVE demo, to verify the exact commands.

Starts Ryu (enforce) + the real 6-switch/18-host topology, disables NIC offloads,
puts a UDP sink on the victim, runs benign UDP + a fixed-source-port flood from
h4/h5, and prints what the controller logged. Mirrors what a presenter types.
"""
import os, re, signal, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Codes" / "mininet"))
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel
from topology import MyTopo

RYU = ROOT / ".venv-ryu39" / "bin" / "ryu-manager"
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout

def main():
    setLogLevel("warning")
    os.chdir(ROOT)
    sh("pkill -f hybrid_controller; pkill -f hping3; pkill -f iperf3; mn -c >/dev/null 2>&1")
    time.sleep(2)
    log = open("/tmp/demo_live_ryu.log", "w")
    env = dict(os.environ, DDOS_CONFIG=str(ROOT/"experiments/configs/hybrid_enforce.yaml"),
               DDOS_TELEMETRY_JSONL="/tmp/demo_live.jsonl", PYTHONUNBUFFERED="1")
    ryu = subprocess.Popen([str(RYU), "--ofp-tcp-listen-port", "6653", "hybrid_controller.py"],
                           cwd=ROOT/"Codes/controller", env=env, stdout=log, stderr=subprocess.STDOUT,
                           start_new_session=True)
    for _ in range(100):
        if sh("ss -ltn 2>/dev/null | grep -c 6653").strip() not in ("","0"): break
        time.sleep(0.2)
    net = Mininet(topo=MyTopo(bw=100, cpu=None), link=TCLink, controller=None)
    net.addController(RemoteController("c0", ip="127.0.0.1", port=6653))
    try:
        net.start()
        # disable offloads so OpenFlow packet counters are real packets
        for h in net.hosts:
            for i in h.intfList():
                h.cmd(f"ethtool -K {i} tx off tso off gso off gro off >/dev/null 2>&1")
        time.sleep(8)
        v = net.get("h18")
        v.cmd("python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',53));\nwhile 1: s.recvfrom(65535)\" &")
        net.pingAll(timeout="1")
        h7 = net.get("h7")
        h7.cmd("iperf -u -c 10.0.0.18 -b 2M -t 40 &")    # benign (allowlisted)
        print(">>> starting fixed-port flood h4,h5 -> h18", flush=True)
        t0 = time.time()
        net.get("h4").cmd("hping3 --udp -d 512 -i u200 -k -s 40001 -p 53 -q 10.0.0.18 &")
        net.get("h5").cmd("hping3 --udp -d 512 -i u200 -k -s 40002 -p 53 -q 10.0.0.18 &")
        # let it run ~30s, sampling flow counts
        for k in range(6):
            time.sleep(5)
            n = sh("ovs-ofctl -O OpenFlow13 dump-aggregate s2 2>/dev/null")
            fc = re.search(r"flow_count=(\d+)", n)
            print(f"  t+{int(time.time()-t0):2d}s  s2 flow_count={fc.group(1) if fc else '?'}", flush=True)
        net.get("h4").cmd("pkill -f hping3")
        net.get("h5").cmd("pkill -f hping3")
        print(">>> attack stopped; waiting for recovery", flush=True)
        time.sleep(15)
    finally:
        sh("pkill -f hping3; pkill -f iperf3")
        try: net.stop()
        except Exception: pass
        try: os.killpg(ryu.pid, signal.SIGINT); ryu.wait(timeout=5)
        except Exception: os.killpg(ryu.pid, signal.SIGKILL)
        log.close()
    print("\n===== CONTROLLER DECISION LOG =====", flush=True)
    print(sh("grep -iE 'SUSPECTED|CONFIRMED|MITIGATING|BLOCK|UNBLOCK|RECOVERING|unavailable' /tmp/demo_live_ryu.log | head -25"))

if __name__ == "__main__":
    main()
