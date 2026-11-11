#!/usr/bin/env python3
"""Run reproducible Mininet/Ryu experiment campaigns (must run as root).

Per run:  mn -c  ->  start Ryu (hybrid_controller.py)  ->  start Mininet
(6-switch chain, 18 hosts, optional link bw)  ->  disable NIC offloads (so
OpenFlow packet counters are real packets, not TSO/GSO super-segments)  ->
start servers on the victim  ->  play the seeded schedule  ->  sample
controller/ML-API CPU+RSS and flow-table size  ->  stop everything.

Example:
  sudo python3 experiments/scripts/run_experiment.py --campaign detection \
      --scenarios A B C --seeds 0-4 --config experiments/configs/observation.yaml
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Codes" / "mininet"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mininet.link import TCLink  # noqa: E402
from mininet.log import setLogLevel  # noqa: E402
from mininet.net import Mininet  # noqa: E402
from mininet.node import RemoteController  # noqa: E402

from scenarios import scenario  # noqa: E402
from topology import MyTopo  # noqa: E402

RYU = ROOT / ".venv-ryu39" / "bin" / "ryu-manager"
ML_PY = ROOT / ".venv" / "bin" / "python"
SCRIPTS = Path(__file__).resolve().parent
OWNER = os.environ.get("DDOS_RESULTS_OWNER", "enkatesh")


def sh(cmd: str, **kw) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw).stdout


def port_open(port: int, host="127.0.0.1") -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def ensure_ml_api(model_dir: str) -> int | None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8765/health", timeout=2) as r:
            info = json.loads(r.read())
            print("ML API already running:", info)
            return None
    except Exception:
        pass
    log = open("/tmp/ddos_ml_api.log", "a")
    env = dict(os.environ, DDOS_MODEL_DIR=model_dir)
    p = subprocess.Popen([str(ML_PY), "-m", "ddos_ml.predict_api"], cwd=ROOT, env=env, stdout=log, stderr=log,
                         start_new_session=True)
    for _ in range(100):
        if port_open(8765):
            print("ML API started pid", p.pid)
            return p.pid
        time.sleep(0.2)
    raise RuntimeError("ML API did not start; see /tmp/ddos_ml_api.log")


def find_pid(pattern: str) -> int | None:
    out = sh(f"pgrep -f '{pattern}'").split()
    return int(out[0]) if out else None


class Sampler(threading.Thread):
    """1 Hz CPU (from /proc tick deltas) + RSS for controller and ML API; flow-table size."""

    def __init__(self, pids: dict, out: Path, epoch0_ref: dict):
        super().__init__(daemon=True)
        self.pids, self.out, self.stop_evt = pids, out, threading.Event()
        self.hz = os.sysconf("SC_CLK_TCK")

    def _ticks(self, pid):
        try:
            f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
            rss = int([l for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")][0].split()[1])
            return int(f[11]) + int(f[12]), rss
        except Exception:
            return None, None

    def run(self):
        prev = {k: self._ticks(p)[0] for k, p in self.pids.items() if p}
        t_prev = time.time()
        with open(self.out / "resources.csv", "w") as fh, open(self.out / "flowtable.csv", "w") as ft:
            fh.write("ts,proc,cpu_percent,rss_kb\n")
            ft.write("ts,switch,flow_count\n")
            i = 0
            while not self.stop_evt.wait(1.0):
                now = time.time()
                for k, pid in self.pids.items():
                    if not pid:
                        continue
                    ticks, rss = self._ticks(pid)
                    if ticks is None or prev.get(k) is None:
                        continue
                    cpu = 100.0 * (ticks - prev[k]) / self.hz / max(now - t_prev, 1e-3)
                    prev[k] = ticks
                    fh.write(f"{now:.3f},{k},{cpu:.2f},{rss}\n")
                t_prev = now
                i += 1
                if i % 5 == 0:
                    for s in range(1, 7):
                        o = sh(f"ovs-ofctl -O OpenFlow13 dump-aggregate s{s}")
                        n = o.split("flow_count=")[1].split()[0] if "flow_count=" in o else ""
                        ft.write(f"{now:.3f},s{s},{n}\n")
                fh.flush()
                ft.flush()


def run_one(scn: str, seed: int, cfg_path: Path, out_root: Path, *, T: float, bw: float | None,
            poll: float | None, idle_timeout: int, cpu: float | None) -> Path:
    plan = scenario(scn, seed, T)
    run_dir = out_root / f"{scn}_{seed:03d}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)

    # Clean Mininet BEFORE starting Ryu (mn -c has killed ryu-manager in this env before).
    sh("pkill -f '[h]ybrid_controller.py'; mn -c >/dev/null 2>&1; pkill -f '[h]ping3'; pkill -f '[i]perf3'")
    time.sleep(1)

    cfg_text = cfg_path.read_text()
    if poll:
        import yaml
        cfg = yaml.safe_load(cfg_text)
        cfg.setdefault("monitoring", {})["polling_interval_seconds"] = poll
        cfg_text = yaml.safe_dump(cfg)
    (run_dir / "config.yaml").write_text(cfg_text)
    env = dict(os.environ, DDOS_CONFIG=str(run_dir / "config.yaml"),
               DDOS_TELEMETRY_JSONL=str(run_dir / "telemetry.jsonl"),
               DDOS_FLOW_IDLE_TIMEOUT=str(idle_timeout), PYTHONUNBUFFERED="1")
    ryu_log = open(run_dir / "ryu.log", "w")
    ryu = subprocess.Popen([str(RYU), "--ofp-tcp-listen-port", "6653", "hybrid_controller.py"],
                           cwd=ROOT / "Codes" / "controller", env=env, stdout=ryu_log, stderr=subprocess.STDOUT,
                           start_new_session=True)
    for _ in range(150):
        if port_open(6653):
            break
        if ryu.poll() is not None:
            raise RuntimeError(f"Ryu exited early; see {run_dir/'ryu.log'}")
        time.sleep(0.2)

    net = Mininet(topo=MyTopo(bw=bw, cpu=cpu), link=TCLink, controller=None, autoSetMacs=False)
    net.addController(RemoteController("c0", ip="127.0.0.1", port=6653))
    procs = []
    sampler = None
    try:
        net.start()
        for h in net.hosts:
            for intf in h.intfList():
                h.cmd(f"ethtool -K {intf} tx off tso off gso off gro off >/dev/null 2>&1")
        for sw in net.switches:
            for intf in sw.intfList():
                if intf.name != "lo":
                    sh(f"ethtool -K {intf} tso off gso off gro off >/dev/null 2>&1")
        t_wait = time.time()
        while time.time() - t_wait < 20:
            if (run_dir / "ryu.log").read_text().count("Registered switch") >= 6:
                break
            time.sleep(0.3)

        victim = net.get(plan["victim"])
        web = Path("/tmp/ddos_web")
        web.mkdir(exist_ok=True)
        (web / "small.bin").write_bytes(os.urandom(10_000))
        (web / "medium.bin").write_bytes(os.urandom(1_000_000))
        victim.cmd(f"cd {web} && python3 -m http.server 80 >/dev/null 2>&1 &")
        victim.cmd(f"python3 {SCRIPTS}/udp_rr.py server 5353 >/dev/null 2>&1 &")
        for p in plan["iperf_server_ports"]:
            victim.cmd(f"iperf3 -s -p {p} -D")
        for other in ("h9", "h12"):
            net.get(other).cmd("iperf3 -s -p 5201 -D")
        # ARP/forwarding warm-up (excluded from evaluation: before traffic_start)
        for h in net.hosts:
            h.cmd(f"ping -c1 -W1 {plan['victim_ip']} >/dev/null 2>&1 &")
        time.sleep(1.0)

        pids = {"ryu": ryu.pid, "ml_api": find_pid("ddos_ml.predict_api")}
        sampler = Sampler(pids, run_dir, {})
        sampler.start()
        epoch0 = time.time()
        plan["epoch0"] = epoch0
        events = sorted(plan["events"], key=lambda e: e["start"])
        logs = run_dir / "hosts"
        logs.mkdir()
        for i, e in enumerate(events):
            delay = epoch0 + e["start"] - time.time()
            if delay > 0:
                time.sleep(delay)
            cmd = e["cmd"].replace("{SCRIPTS}", str(SCRIPTS)).replace("{RUN}", str(run_dir))
            outf = open(logs / f"{i:02d}_{e['host']}_{e['kind']}.log", "w")
            e["epoch_start"] = time.time()
            p = net.get(e["host"]).popen(["timeout", "-s", "INT", str(int(e["duration"]) + 1), "bash", "-c", cmd],
                                         stdout=outf, stderr=subprocess.STDOUT, start_new_session=True)
            procs.append(p)
        remaining = epoch0 + T - time.time()
        if remaining > 0:
            time.sleep(remaining)
        plan["epoch_end"] = time.time()
    finally:
        for p in procs:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except Exception:
                pass
        if sampler:
            sampler.stop_evt.set()
            sampler.join(timeout=3)
        sh("pkill -f '[h]ping3'; pkill -f '[i]perf3'; pkill -f '[u]dp_rr.py'; pkill -f '[h]ttp.server 80'")
        try:
            net.stop()
        except Exception as exc:
            print("net.stop failed:", exc)
        try:
            os.killpg(ryu.pid, signal.SIGINT)
            ryu.wait(timeout=5)
        except Exception:
            os.killpg(ryu.pid, signal.SIGKILL)
        ryu_log.close()
        plan.update({"bw_mbps": bw, "cpu_cap": cpu, "idle_timeout": idle_timeout, "config_file": str(cfg_path),
                     "code_version": sh(f"cd {ROOT} && (git rev-parse HEAD 2>/dev/null || echo no-git)").strip(),
                     "model_dir": os.environ.get("DDOS_MODEL_DIR", "artifacts/production")})
        (run_dir / "manifest.json").write_text(json.dumps(plan, indent=1))
    return run_dir


def parse_seeds(text: str):
    out = []
    for part in text.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--scenarios", nargs="+", default=["A", "B", "C", "D", "E", "F", "G"])
    ap.add_argument("--seeds", default="0-4")
    ap.add_argument("--config", default="experiments/configs/observation.yaml")
    ap.add_argument("--duration", type=float, default=80.0)
    ap.add_argument("--bw", type=float, default=100.0, help="link capacity Mbit/s (0 = unlimited)")
    ap.add_argument("--poll", type=float, default=None, help="override polling interval")
    ap.add_argument("--idle-timeout", type=int, default=10)
    ap.add_argument("--cpu", type=float, default=0.0,
                    help="per-host CPU fraction cap (0 = uncapped, lets attackers actually flood)")
    ap.add_argument("--model-dir", default="artifacts/production")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Must run as root (Mininet).")
    setLogLevel("warning")
    os.chdir(ROOT)
    ensure_ml_api(args.model_dir)
    out_root = ROOT / "experiments" / "results" / "raw" / args.campaign
    out_root.mkdir(parents=True, exist_ok=True)
    status = []
    for seed in parse_seeds(args.seeds):
        for scn in args.scenarios:
            t = time.time()
            try:
                d = run_one(scn, seed, ROOT / args.config, out_root, T=args.duration, bw=args.bw or None,
                            poll=args.poll, idle_timeout=args.idle_timeout, cpu=args.cpu or None)
                status.append({"scenario": scn, "seed": seed, "ok": True, "dir": str(d)})
                print(f"[{args.campaign}] {scn} seed={seed} done in {time.time()-t:.0f}s", flush=True)
            except Exception as exc:
                status.append({"scenario": scn, "seed": seed, "ok": False, "error": repr(exc)})
                print(f"[{args.campaign}] {scn} seed={seed} FAILED: {exc!r}", flush=True)
            with open(out_root / "campaign_status.jsonl", "a") as fh:
                fh.write(json.dumps(status[-1]) + "\n")
    sh(f"mn -c >/dev/null 2>&1; chown -R {OWNER}:{OWNER} {out_root}")


if __name__ == "__main__":
    main()
