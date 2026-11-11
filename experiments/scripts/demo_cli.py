#!/usr/bin/env python3
"""One-command INTERACTIVE demo: controller + topology + victim sink + Mininet CLI.

Fixes the three things that make a raw `topology.py` launch silent:
  * hosts are UNCAPPED (cpu=None) so attackers can actually flood,
  * NIC offloads are disabled so OpenFlow packet counters are real,
  * the victim runs UDP sinks so a flood is one-way (no ICMP-unreachable noise).

Usage (as root):
    sudo python3 experiments/scripts/demo_cli.py            # opens Mininet CLI
    sudo python3 experiments/scripts/demo_cli.py --selftest # scripted check, no CLI

In the CLI, start a benign flow and a FIXED-PORT flood (note -k -s):
    mininet> h7 iperf -u -c 10.0.0.18 -b 2M -t 60 &
    mininet> h4 hping3 --udp -d 1024 -i u250 -k -s 40001 -p 9999 -q 10.0.0.18 &
    mininet> h5 hping3 --udp -d 1024 -i u250 -k -s 40002 -p 9999 -q 10.0.0.18 &
Watch the controller log (other terminal):  tail -f /tmp/demo_cli_ryu.log
Stop the attack (Ctrl-C the hping in the prompt or):  mininet> h4 pkill hping3
"""
import os, signal, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Codes" / "mininet"))
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from topology import MyTopo

RYU = ROOT / ".venv-ryu39" / "bin" / "ryu-manager"
MLPY = ROOT / ".venv" / "bin" / "python"
LOG = "/tmp/demo_cli_ryu.log"
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout

def main(selftest=False):
    setLogLevel("warning")
    os.chdir(ROOT)
    sh("pkill -f '[h]ybrid_controller'; pkill -f '[h]ping3'; pkill -f '[i]perf'; mn -c >/dev/null 2>&1")
    time.sleep(2)
    # ML API
    if "ok" not in sh("curl -s http://127.0.0.1:8765/health"):
        subprocess.Popen([str(MLPY), "-m", "ddos_ml.predict_api"], cwd=ROOT,
                         env=dict(os.environ, DDOS_MODEL_DIR="artifacts/production"),
                         stdout=open("/tmp/demo_cli_mlapi.log", "w"), stderr=subprocess.STDOUT,
                         start_new_session=True)
        for _ in range(50):
            if "ok" in sh("curl -s http://127.0.0.1:8765/health"): break
            time.sleep(0.2)
    # Controller (enforce = real scoped mitigation; swap to observation.yaml for detect-only)
    env = dict(os.environ, DDOS_CONFIG=str(ROOT/"experiments/configs/hybrid_enforce.yaml"),
               DDOS_TELEMETRY_JSONL="/tmp/demo_cli.jsonl", PYTHONUNBUFFERED="1")
    ryu = subprocess.Popen([str(RYU), "--ofp-tcp-listen-port", "6653", "hybrid_controller.py"],
                           cwd=ROOT/"Codes/controller", env=env,
                           stdout=open(LOG, "w"), stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(100):
        if sh("ss -ltn 2>/dev/null | grep -c :6653").strip() not in ("", "0"): break
        time.sleep(0.2)
    net = Mininet(topo=MyTopo(bw=100, cpu=None), link=TCLink, controller=None)
    net.addController(RemoteController("c0", ip="127.0.0.1", port=6653))
    net.start()
    for h in net.hosts:
        for i in h.intfList():
            h.cmd(f"ethtool -K {i} tx off tso off gso off gro off >/dev/null 2>&1")
    # victim UDP sinks on the ports the demo attacks (so floods are one-way)
    v = net.get("h18")
    for p in (53, 123, 1900, 8080, 9999):
        v.cmd(f"python3 -c \"import socket;s=socket.socket(2,2);s.bind(('0.0.0.0',{p}));\nwhile 1: s.recvfrom(65535)\" &")
    net.get("h18").cmd("iperf -s -u -p 5201 -D")
    time.sleep(6)
    print("\n" + "="*64)
    print("READY. Controller log:  tail -f " + LOG)
    print("Benign:  h7 iperf -u -c 10.0.0.18 -b 2M -t 60 &")
    print("Attack:  h4 hping3 --udp -d 1024 -i u250 -k -s 40001 -p 9999 -q 10.0.0.18 &")
    print("         h5 hping3 --udp -d 1024 -i u250 -k -s 40002 -p 9999 -q 10.0.0.18 &")
    print("="*64 + "\n")
    try:
        if selftest:
            net.pingAll(timeout="1")
            net.get("h7").cmd("iperf -u -c 10.0.0.18 -b 2M -t 50 &")
            for i, h in enumerate(["h1", "h2", "h3", "h4", "h5", "h6"], start=40001):
                net.get(h).cmd(f"hping3 --udp -d 1024 -i u300 -k -s {i} -p 9999 -q 10.0.0.18 &")
            time.sleep(30)
            for h in ["h1", "h2", "h3", "h4", "h5", "h6"]:
                net.get(h).cmd("pkill -f hping3")
            time.sleep(14)
            print("=== SELFTEST controller decisions ===")
            print(sh(f"grep -iE 'CONFIRMED|MITIGATING|BLOCK|UNBLOCK|RECOVERING|unavailable' {LOG} | head -20"))
        else:
            CLI(net)
    finally:
        sh("pkill -f '[h]ping3'; pkill -f '[i]perf'")
        try: net.stop()
        except Exception: pass
        try: os.killpg(ryu.pid, signal.SIGINT); ryu.wait(timeout=5)
        except Exception: os.killpg(ryu.pid, signal.SIGKILL)

if __name__ == "__main__":
    main(selftest="--selftest" in sys.argv)
