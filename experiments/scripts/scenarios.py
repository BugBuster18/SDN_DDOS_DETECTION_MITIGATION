"""Seeded, reproducible traffic schedules for the Mininet testbed.

Each scenario returns a list of events. An event is a command run on one
Mininet host from ``start`` seconds (relative to traffic start) for
``duration`` seconds, plus ground-truth metadata (role, src, dst, proto).
All attack traffic targets only the isolated 10.0.0.0/24 Mininet network.

Scenarios
  A  benign only (ICMP, TCP bulk, HTTP, UDP streams of varied size/rate,
     UDP request/response, multiple concurrent legit clients; rates overlap attacks)
  B  single-source UDP flood (fixed 5-tuple)
  C  multi-source UDP DDoS (2-6 of h1-h6; fixed-port or port-scattering)
  D  TCP SYN flood (port-scattering, the normal SYN-flood shape)
  E  ICMP flood
  F  mixed: scenario-A benign workload + C-type attack concurrently
  G  low-rate / bursty / join-leave / multi-destination-port UDP attacks
"""
from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

VICTIM = "h18"
ATTACK_POOL = ["h1", "h2", "h3", "h4", "h5", "h6"]
PROBE_UDP_HOST = "h7"   # legit iperf3 UDP probe (goodput / loss / jitter)
PROBE_PING_HOST = "h13"  # legit ICMP probe (RTT)
LEGIT_POOL = [f"h{i}" for i in range(1, 18) if f"h{i}" not in (PROBE_UDP_HOST, PROBE_PING_HOST)]
UDP, TCP, ICMP = 17, 6, 1


def ip(host: str) -> str:
    return "10.0.0." + host[1:]


@dataclass
class Event:
    host: str
    start: float
    duration: float
    cmd: str
    role: str                 # benign | attack | probe | server
    dst: Optional[str] = None
    proto: Optional[int] = None
    kind: str = ""
    params: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["src_ip"] = ip(self.host)
        d["dst_ip"] = ip(self.dst) if self.dst else None
        return d


class PortAlloc:
    """Unique iperf3 server ports on the victim (one client per server)."""
    def __init__(self, base=5201):
        self.next = base
        self.used: List[int] = []

    def take(self) -> int:
        p = self.next
        self.next += 1
        self.used.append(p)
        return p


def _hping(rate_pps: float) -> str:
    interval_us = max(int(1_000_000 / max(rate_pps, 1)), 20)
    return f"-i u{interval_us}"


# --------------------------------------------------------------- benign parts
def benign_workload(rng: random.Random, ports: PortAlloc, t0: float, t1: float, level: str,
                    exclude: List[str]) -> List[Event]:
    ev: List[Event] = []
    pool = [h for h in LEGIT_POOL if h not in exclude and h != VICTIM]
    rng.shuffle(pool)
    take = lambda: pool.pop() if pool else rng.choice([h for h in LEGIT_POOL if h not in exclude])

    # ICMP pings (to victim and to other hosts)
    for _ in range(rng.randint(2, 4)):
        h = take()
        dst = VICTIM if rng.random() < 0.6 else rng.choice([x for x in ("h9", "h12", "h15") if x != h])
        iv = rng.choice([0.2, 0.5, 1.0])
        ev.append(Event(h, t0 + rng.uniform(0, 5), t1 - t0, f"ping -i {iv} {ip(dst)}", "benign", dst, ICMP,
                        "icmp_ping", {"interval": iv}))
    # HTTP-like downloads from the victim web server
    for _ in range(rng.randint(1, 3)):
        h = take()
        obj = rng.choice(["small.bin", "medium.bin"])
        gap = rng.choice([0.5, 1.0, 2.0])
        cmd = (f"bash -c 'while true; do curl -s -o /dev/null --max-time 5 http://{ip(VICTIM)}/{obj}; "
               f"sleep {gap}; done'")
        ev.append(Event(h, t0 + rng.uniform(0, 5), t1 - t0, cmd, "benign", VICTIM, TCP, "http", {"object": obj}))
    # TCP bulk transfer (rate-capped)
    for _ in range(rng.randint(1, 2)):
        h = take()
        rate = rng.choice([2, 5, 10, 20])
        dur = rng.uniform(15, t1 - t0 - 5)
        p = ports.take()
        ev.append(Event(h, t0 + rng.uniform(0, (t1 - t0) - dur), dur,
                        f"iperf3 -c {ip(VICTIM)} -p {p} -b {rate}M -t {int(dur)}", "benign", VICTIM, TCP,
                        "tcp_bulk", {"mbps": rate, "port": p}))
    # UDP streams: several legitimate clients to the same server, varied size and rate.
    n_udp = {"low": rng.randint(1, 2), "medium": rng.randint(2, 4), "high": rng.randint(4, 6)}[level]
    rate_choices = {"low": [0.5, 1, 2], "medium": [2, 5, 10], "high": [8, 12, 15, 20]}[level]
    for _ in range(n_udp):
        h = take()
        rate = rng.choice(rate_choices)
        size = rng.choice([200, 512, 1024, 1400])
        dur = rng.uniform(20, t1 - t0)
        p = ports.take()
        ev.append(Event(h, t0 + rng.uniform(0, (t1 - t0) - dur), dur,
                        f"iperf3 -u -c {ip(VICTIM)} -p {p} -b {rate}M -l {size} -t {int(dur)}", "benign",
                        VICTIM, UDP, "udp_stream", {"mbps": rate, "size": size, "port": p}))
    # UDP request/response (DNS-like; new source port per query, server replies)
    for _ in range(rng.randint(1, 2)):
        h = take()
        qps = rng.choice([5, 20, 50]) if level != "low" else rng.choice([2, 5])
        size = rng.choice([64, 256, 512])
        ev.append(Event(h, t0 + rng.uniform(0, 5), t1 - t0,
                        f"python3 {{SCRIPTS}}/udp_rr.py client {ip(VICTIM)} 5353 {qps} {size}",
                        "benign", VICTIM, UDP, "udp_request_response", {"qps": qps, "size": size}))
    # Some benign traffic between other hosts (not involving the victim)
    h, dst = take(), rng.choice(["h9", "h12"])
    ev.append(Event(h, t0 + rng.uniform(0, 5), t1 - t0 - 6,
                    f"iperf3 -u -c {ip(dst)} -p 5201 -b {rng.choice([1, 5])}M -l 1000 -t {int(t1 - t0 - 6)}",
                    "benign", dst, UDP, "udp_stream_other", {}))
    return ev


def probes(t0: float, t1: float, ports: PortAlloc) -> List[Event]:
    p = ports.take()
    return [
        Event(PROBE_UDP_HOST, t0, t1 - t0,
              f"iperf3 -u -c {ip(VICTIM)} -p {p} -b 2M -l 1000 -t {int(t1 - t0)} -i 1 --json "
              f"--get-server-output --logfile {{RUN}}/probe_iperf.json", "probe", VICTIM, UDP, "probe_udp",
              {"port": p}),
        Event(PROBE_PING_HOST, t0, t1 - t0, f"ping -D -i 0.2 {ip(VICTIM)}", "probe", VICTIM, ICMP, "probe_ping",
              {"logfile": "probe_ping.txt"}),
    ]


# --------------------------------------------------------------- attack parts
def udp_flood(rng, host, start, dur, *, pps, size, fixed_port=True, multi_port=False, kind="udp_flood"):
    sport, dport = rng.randint(1024, 65000), rng.choice([53, 123, 161, 1900, 8080, 9999])
    opts = f"--udp -d {size} {_hping(pps)}"
    if fixed_port:
        opts += f" -k -s {sport}"
    opts += f" -p ++{dport}" if multi_port else f" -p {dport}"
    return Event(host, start, dur, f"hping3 {opts} -q {ip(VICTIM)}", "attack", VICTIM, UDP, kind,
                 {"pps": pps, "size": size, "fixed_port": fixed_port, "multi_port": multi_port, "dport": dport})


def bursty(ev: Event, on: float, off: float) -> Event:
    inner = ev.cmd
    ev.cmd = f"bash -c 'while true; do timeout {on} {inner}; sleep {off}; done'"
    ev.kind = ev.kind + "_bursty"
    ev.params.update({"on": on, "off": off})
    return ev


def attack_window(rng, T):
    a0 = rng.uniform(25, 32)
    return a0, rng.uniform(25, 32)


def scenario(name: str, seed: int, T: float = 80.0) -> dict:
    rng = random.Random(f"{name}-{seed}")
    ports = PortAlloc()
    t0, t1 = 8.0, T - 2.0
    events: List[Event] = []
    level = rng.choice(["low", "medium", "high"])
    if name in ("A", "F"):
        events += benign_workload(rng, ports, t0, t1, level if name == "A" else rng.choice(["medium", "high"]),
                                  exclude=ATTACK_POOL if name == "F" else [])
    else:
        # light benign background so the victim is never otherwise silent
        events += benign_workload(rng, ports, t0, t1, "low", exclude=ATTACK_POOL)
    events += probes(t0, t1, ports)
    a0, ad = attack_window(rng, T)
    if name == "B":
        h = rng.choice(ATTACK_POOL)
        events.append(udp_flood(rng, h, a0, ad, pps=rng.choice([2000, 4000, 8000]),
                                size=rng.choice([64, 512, 1024, 1400])))
    elif name in ("C", "F"):
        n = rng.randint(2, 6)
        scatter = rng.random() < 0.3
        for h in rng.sample(ATTACK_POOL, n):
            pps = rng.choice([150, 250]) if scatter else rng.choice([1000, 2000, 4000])
            events.append(udp_flood(rng, h, a0 + rng.uniform(0, 2), ad, pps=pps,
                                    size=rng.choice([64, 512, 1024, 1400]), fixed_port=not scatter,
                                    kind="udp_ddos_scatter" if scatter else "udp_ddos"))
    elif name == "D":
        for h in rng.sample(ATTACK_POOL, rng.randint(2, 4)):
            pps = rng.choice([100, 200, 300])
            events.append(Event(h, a0 + rng.uniform(0, 2), ad, f"hping3 -S -p 80 {_hping(pps)} -q {ip(VICTIM)}",
                                "attack", VICTIM, TCP, "syn_flood", {"pps": pps}))
    elif name == "E":
        for h in rng.sample(ATTACK_POOL, rng.randint(1, 6)):
            pps, size = rng.choice([500, 1000, 3000]), rng.choice([64, 512, 1000])
            events.append(Event(h, a0 + rng.uniform(0, 2), ad, f"hping3 --icmp -d {size} {_hping(pps)} -q {ip(VICTIM)}",
                                "attack", VICTIM, ICMP, "icmp_flood", {"pps": pps, "size": size}))
    elif name == "G":
        variant = rng.choice(["low_rate", "bursty", "join_leave", "multi_port"])
        hosts = rng.sample(ATTACK_POOL, rng.randint(3, 6))
        for i, h in enumerate(hosts):
            if variant == "low_rate":
                e = udp_flood(rng, h, a0, ad, pps=rng.choice([50, 100, 200]), size=rng.choice([64, 512]),
                              kind="udp_lowrate")
            elif variant == "bursty":
                e = bursty(udp_flood(rng, h, a0, ad, pps=rng.choice([2000, 4000]), size=rng.choice([512, 1024])),
                           on=rng.choice([2, 3]), off=rng.choice([3, 5]))
            elif variant == "join_leave":
                s = a0 + i * rng.uniform(2, 5)
                e = udp_flood(rng, h, s, max(8.0, ad - i * rng.uniform(1, 4)), pps=rng.choice([1000, 2000]),
                              size=rng.choice([512, 1024]), kind="udp_join_leave")
            else:
                e = udp_flood(rng, h, a0, ad, pps=rng.choice([300, 600]), size=rng.choice([256, 1024]),
                              fixed_port=True, multi_port=True, kind="udp_multiport")
            events.append(e)
    elif name != "A":
        raise ValueError(f"unknown scenario {name}")
    attacks = [e for e in events if e.role == "attack"]
    return {
        "scenario": name, "seed": seed, "duration": T, "traffic_start": t0, "benign_level": level,
        "victim": VICTIM, "victim_ip": ip(VICTIM),
        "attack_start": min((e.start for e in attacks), default=None),
        "attack_end": max((e.start + e.duration for e in attacks), default=None),
        "iperf_server_ports": ports.used,
        "events": [e.to_dict() for e in events],
    }


SCENARIOS = ["A", "B", "C", "D", "E", "F", "G"]

if __name__ == "__main__":
    import json, sys
    print(json.dumps(scenario(sys.argv[1], int(sys.argv[2])), indent=1))
