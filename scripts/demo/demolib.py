"""Shared helpers for the demo scripts (stdlib only; run with system python3 as root).

* REST client for the controller API (127.0.0.1:8080/ddos/...)
* Mininet lab state (written by mininet_lab.py) and running commands INSIDE a
  Mininet host from another terminal (mnexec -a <host shell pid>)
* OVS ground truth: port counters (/sys/class/net) and flow tables (ovs-ofctl)
* a 1 Hz Sampler that records controller state + measured traffic
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RESULTS = ROOT / "experiments" / "results" / "demo"
STATE_FILE = RESULTS / "run" / "lab_state.json"
REST = os.environ.get("DDOS_REST", "http://127.0.0.1:8080/ddos")
ML_HEALTH = os.environ.get("DDOS_ML_HEALTH", "http://127.0.0.1:8765/health")
OWNER = os.environ.get("SUDO_USER") or os.environ.get("DDOS_RESULTS_OWNER") or "enkatesh"
DROP_COOKIE_FILTER = "cookie=0xdd05000000000000/0xffff000000000000"


class DemoError(RuntimeError):
    pass


# ----------------------------------------------------------------- REST
def rest(method: str, path: str, body: dict | None = None, timeout: float = 3.0) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(REST + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read().decode()).get("error")
        except Exception:
            msg = str(e)
        raise DemoError(f"controller REST {method} {path}: HTTP {e.code}: {msg}")
    except Exception as e:
        raise DemoError(f"controller REST API not reachable at {REST} ({e}). Is Terminal 2 (Ryu) running?")


def rest_or_none(method, path, body=None, timeout=2.0):
    try:
        return rest(method, path, body, timeout)
    except DemoError:
        return None


def ml_health():
    try:
        with urllib.request.urlopen(ML_HEALTH, timeout=2) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


# ----------------------------------------------------------------- lab
def load_lab() -> dict:
    if not STATE_FILE.exists():
        raise DemoError(f"{STATE_FILE} not found. Start the Mininet lab first (Terminal 3: "
                        "sudo scripts/demo/03_start_mininet.sh).")
    lab = json.loads(STATE_FILE.read_text())
    for name, h in lab["hosts"].items():
        try:
            cmdline = Path(f"/proc/{h['pid']}/cmdline").read_bytes().decode(errors="replace")
        except FileNotFoundError:
            cmdline = ""
        if f"mininet:{name}" not in cmdline:
            raise DemoError(f"Mininet host {name} (pid {h['pid']}) is gone. Is the lab (Terminal 3) still running?")
    return lab


def ip_of(lab, host):
    return lab["hosts"][host]["ip"]


def host_cmd(lab, host, cmd: str) -> list:
    return ["mnexec", "-a", str(lab["hosts"][host]["pid"]), "bash", "-c", cmd]


def run_in_host(lab, host, cmd: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(host_cmd(lab, host, cmd), capture_output=True, text=True, timeout=timeout)


class HostProc:
    """A background process running inside a Mininet host, with its own log file."""

    def __init__(self, lab, host, cmd, log: Path, role: str, kind: str, params: dict | None = None,
                 dst: str | None = None):
        self.host, self.cmd, self.log, self.role, self.kind = host, cmd, log, role, kind
        self.params = params or {}
        self.src_ip = ip_of(lab, host)
        self.dst = dst
        log.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(log, "w")
        self.t_start = time.time()
        self.p = subprocess.Popen(host_cmd(lab, host, cmd), stdout=self._fh, stderr=subprocess.STDOUT,
                                  start_new_session=True)
        self.t_stop = None

    @property
    def pid(self):
        return self.p.pid

    def running(self):
        return self.p.poll() is None

    def stop(self, sig=signal.SIGINT, wait=3.0):
        if self.running():
            try:
                os.killpg(self.p.pid, sig)
            except ProcessLookupError:
                pass
            try:
                self.p.wait(timeout=wait)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.p.wait(timeout=2)
        if self.t_stop is None:
            self.t_stop = time.time()
        self._fh.close()

    def wait(self, timeout=None):
        try:
            self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        if self.t_stop is None:
            self.t_stop = time.time()
        return True

    def describe(self):
        return {"host": self.host, "src_ip": self.src_ip, "role": self.role, "kind": self.kind,
                "cmd": self.cmd, "params": self.params, "dst": self.dst, "pid": self.pid,
                "start": round(self.t_start, 3), "stop": round(self.t_stop, 3) if self.t_stop else None,
                "log": self.log.name}


def kill_lab_traffic():
    """Stop every traffic generator started in the lab (never touches Ryu / ML API / victim servers)."""
    for pat in ("[h]ping3", "[i]perf3 -c", "[i]perf3 -u -c", "[i]perf -c", "[u]dp_probe.py", "[p]ing -D"):
        subprocess.run(["pkill", "-INT", "-f", pat], capture_output=True)
    time.sleep(0.5)
    for pat in ("[h]ping3", "[i]perf3 -c", "[i]perf3 -u -c", "[i]perf -c", "[u]dp_probe.py", "[p]ing -D"):
        subprocess.run(["pkill", "-KILL", "-f", pat], capture_output=True)


# ----------------------------------------------------------------- OVS ground truth
def port_counters(ifname: str) -> dict:
    base = Path("/sys/class/net") / ifname / "statistics"
    out = {}
    for k in ("rx_packets", "rx_bytes", "tx_packets", "tx_bytes"):
        try:
            out[k] = int((base / k).read_text())
        except (FileNotFoundError, ValueError):
            out[k] = None
    return out


_KV = re.compile(r"([a-z_0-9]+)=([^,\s]+)")


def dump_flows(switch: str, filt: str = "") -> list:
    out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch] + ([filt] if filt else []),
                         capture_output=True, text=True).stdout
    flows = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("cookie="):
            continue
        match_part, _, actions = line.partition(" actions=")
        d = dict(_KV.findall(match_part))
        toks = [t.strip() for t in match_part.split(",")]
        proto = next((t for t in toks if t in ("udp", "tcp", "icmp", "ip", "arp")), None)
        d.update({"proto": proto, "actions": actions, "raw": line, "switch": switch})
        for k in ("n_packets", "n_bytes", "priority"):
            if k in d:
                d[k] = int(d[k])
        if "duration" in d:
            d["duration"] = float(d["duration"].rstrip("s"))
        d["key"] = re.sub(r"(duration|n_packets|n_bytes|idle_age|hard_age)=[^,\s]+,?\s*", "", match_part)
        flows.append(d)
    return flows


def dump_drop_rules(switches=("s1", "s2", "s3", "s4", "s5", "s6")) -> list:
    rules = []
    for s in switches:
        rules.extend(dump_flows(s, DROP_COOKIE_FILTER))
    return rules


class FlowDeltaCounter:
    """Per-source packets forwarded by one switch towards one destination (from flow counters)."""

    def __init__(self, switch: str, dst_ip: str):
        self.switch, self.dst_ip = switch, dst_ip
        self.prev = {}
        self.t_prev = None

    def sample(self) -> dict:
        now = time.time()
        cur = {}
        per_src = {}
        for f in dump_flows(self.switch):
            if f.get("priority") != 1 or f.get("nw_dst") != self.dst_ip or "nw_src" not in f:
                continue
            k = f["key"]
            cur[k] = (f["n_packets"], f["duration"])
            prev = self.prev.get(k)
            if prev is not None and f["n_packets"] >= prev[0]:
                d = f["n_packets"] - prev[0]
            elif self.t_prev is not None and f["duration"] <= (now - self.t_prev) + 1.0:
                d = f["n_packets"]  # entry installed since the last sample
            else:
                d = 0
            per_src[f["nw_src"]] = per_src.get(f["nw_src"], 0) + d
        dt = (now - self.t_prev) if self.t_prev else None
        self.prev, self.t_prev = cur, now
        if not dt:
            return {}
        return {s: v / dt for s, v in per_src.items()}


# ----------------------------------------------------------------- sampler
class Sampler(threading.Thread):
    """1 Hz: controller state for the victim + measured offered / delivered traffic."""

    def __init__(self, lab, attackers, legit_hosts, interval=1.0):
        super().__init__(daemon=True)
        self.lab, self.attackers, self.legit = lab, list(attackers), list(legit_hosts)
        self.victim_ip = lab["victim_ip"]
        self.interval = interval
        self.rows = []
        self.stop_evt = threading.Event()
        self.flowctr = FlowDeltaCounter(lab["victim_switch_port"].split("-")[0], self.victim_ip)
        self._prev_ports = {}
        self.max_rules_snapshot = None

    def _port_rates(self, now):
        rates = {}
        names = {h: self.lab["hosts"][h]["switch_port"] for h in self.attackers + self.legit}
        names["victim"] = self.lab["victim_switch_port"]
        for h, ifn in names.items():
            c = port_counters(ifn)
            prev = self._prev_ports.get(h)
            self._prev_ports[h] = (now, c)
            if prev and c["rx_packets"] is not None and prev[1]["rx_packets"] is not None:
                dt = max(now - prev[0], 1e-3)
                # switch-side port: rx = what the host SENT into the network, tx = what was delivered TO the host
                rates[h] = {"sent_pps": (c["rx_packets"] - prev[1]["rx_packets"]) / dt,
                            "recv_pps": (c["tx_packets"] - prev[1]["tx_packets"]) / dt,
                            "recv_mbps": 8 * (c["tx_bytes"] - prev[1]["tx_bytes"]) / dt / 1e6}
        return rates

    def run(self):
        while not self.stop_evt.is_set():
            t0 = time.time()
            st = rest_or_none("GET", "/status", timeout=1.5)
            ports = self._port_rates(t0)
            delivered = self.flowctr.sample()
            row = {"t": round(t0, 3), "controller_ok": st is not None}
            if st:
                vstate = st["states"].get(self.victim_ip, {})
                w = st["window"]["dst"].get(self.victim_ip, {})
                f = w.get("features", {})
                row.update({
                    "mode": st["mode"], "poll": st["poll"], "state": vstate.get("state", "NORMAL"),
                    "label": vstate.get("label", "NORMAL TRAFFIC"), "score": w.get("score"),
                    "threshold": w.get("threshold"), "n_rules": st["n_rules"],
                    "ctl_pps": f.get("pps"), "ctl_mbps": (f.get("bps") or 0) / 1e6 if f else None,
                    "ctl_n_sources": f.get("n_sources"), "ctl_n_flows": f.get("n_active_flows"),
                    "ctl_avg_pkt": f.get("avg_pkt_size"), "ctl_ml_max_prob": f.get("ml_max_prob"),
                    "ctl_ml_flagged": f.get("ml_flow_frac"), "ml_api": st.get("ml_api"),
                    "window_sources": w.get("sources", []), "attributed": w.get("attributed", []),
                })
                if st["n_rules"] and (self.max_rules_snapshot is None
                                      or st["n_rules"] > self.max_rules_snapshot["n_rules"]):
                    self.max_rules_snapshot = {"t": t0, "n_rules": st["n_rules"],
                                               "rest": rest_or_none("GET", "/rules"),
                                               "ovs": [f["raw"] for f in dump_drop_rules()]}
            row["victim_recv_pps"] = ports.get("victim", {}).get("recv_pps")
            row["victim_recv_mbps"] = ports.get("victim", {}).get("recv_mbps")
            row["attack_sent_pps"] = sum(ports.get(h, {}).get("sent_pps", 0) for h in self.attackers)
            row["attack_delivered_pps"] = sum(delivered.get(ip_of(self.lab, h), 0) for h in self.attackers)
            row["legit_delivered_pps"] = sum(delivered.get(ip_of(self.lab, h), 0) for h in self.legit)
            row["per_attacker"] = {h: {"sent_pps": round(ports.get(h, {}).get("sent_pps", 0), 1),
                                       "delivered_pps": round(delivered.get(ip_of(self.lab, h), 0), 1)}
                                   for h in self.attackers}
            self.rows.append(row)
            self.stop_evt.wait(max(self.interval - (time.time() - t0), 0.05))

    def stop(self):
        self.stop_evt.set()
        self.join(timeout=5)


def chown_results(path: Path):
    subprocess.run(["chown", "-R", f"{OWNER}:{OWNER}", str(path)], capture_output=True)
