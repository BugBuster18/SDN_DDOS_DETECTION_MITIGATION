#!/usr/bin/env python3
"""Presentation-friendly live feed of the controller's DECISIONS (Terminal 1 of the 3-terminal demo).

Prints one coloured line per decision taken by the controller (state changes, drop rules installed /
removed, mode changes) from the REST API /ddos/events, instead of the raw Ryu log.

    python3 scripts/demo/live_feed.py          (Ctrl-C to stop)
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demolib import DemoError, rest  # noqa: E402

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN, MAGENTA = "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[35m"
STATE_COLOR = {"NORMAL": GREEN, "SUSPECTED": YELLOW, "CONFIRMED": RED, "MITIGATING": MAGENTA, "RECOVERING": CYAN}


def host(ip):
    """10.0.0.7 -> 'h7 (10.0.0.7)' (Mininet host hN has IP 10.0.0.N)."""
    try:
        return f"h{int(ip.rsplit('.', 1)[1])} ({ip})"
    except (ValueError, IndexError, AttributeError):
        return str(ip)


def line(ts, color, tag, text):
    t = time.strftime("%H:%M:%S", time.localtime(ts))
    print(f"{DIM}{t}{RESET}  {color}{BOLD}{tag:<10}{RESET} {text}", flush=True)


def show(ev):
    k, ts = ev["type"], ev["ts"]
    if k == "state":
        new, old = ev["state"], ev["previous"]
        f = ev.get("features") or {}
        traffic = (f"  [{f.get('pps', 0):.0f} pps, {(f.get('bps') or 0) / 1e6:.1f} Mbps, "
                   f"{f.get('n_sources', 0):.0f} sources]") if f else ""
        c = STATE_COLOR.get(new, "")
        line(ts, c, new, f"victim {host(ev['dst'])}: {old} -> {new}  score={ev.get('score', 0):.2f}{traffic}")
        if new == "CONFIRMED" or (new == "MITIGATING" and old not in ("CONFIRMED", "MITIGATING")):
            att = ev.get("attributed") or []
            print(f"{RED}{BOLD}          >>> DDoS ATTACK CONFIRMED on {host(ev['dst'])}"
                  f"{' - attackers identified: ' + ', '.join(host(a) for a in att) if att else ''}{RESET}", flush=True)
        elif new == "NORMAL" and old != "NORMAL":
            print(f"{GREEN}{BOLD}          >>> {host(ev['dst'])} back to NORMAL{RESET}", flush=True)
    elif k == "rule_installed":
        line(ts, RED, "BLOCK", f"DROP {host(ev['src'])} -> {host(ev['dst'])} {ev.get('proto_name', '')} "
                               f"at switch {','.join(ev.get('switches', []))}  (attacker's ingress switch)")
    elif k == "would_block":
        line(ts, YELLOW, "DRY-RUN", f"would DROP {host(ev['src'])} -> {host(ev['dst'])} {ev.get('proto_name', '')}")
    elif k in ("rule_removed", "rule_expired"):
        line(ts, GREEN, "UNBLOCK", f"{host(ev['src'])} -> {host(ev['dst'])} rule removed ({ev.get('reason', '')})")
    elif k == "rules_cleared":
        line(ts, GREEN, "UNBLOCK", f"all rules removed ({ev.get('removed', 0)})")
    elif k == "mode":
        line(ts, CYAN, "MODE", f"{ev.get('previous')} -> {ev.get('mode')}")
    elif k == "switch_connected":
        line(ts, DIM, "SWITCH", f"s{ev.get('dpid')} connected ({ev.get('n_switches')}/6)")
    elif k in ("ml_api_unavailable", "ml_api_ok"):
        line(ts, YELLOW if k.endswith("unavailable") else GREEN, "ML-API", k.replace("_", " "))


def main():
    print(f"{BOLD}Controller decisions (live){RESET}  - legend: "
          f"{GREEN}NORMAL{RESET} {YELLOW}SUSPECTED{RESET} {RED}CONFIRMED/BLOCK{RESET} "
          f"{MAGENTA}MITIGATING{RESET} {CYAN}RECOVERING{RESET}\n", flush=True)
    seq, waiting = None, False
    while True:
        try:
            if seq is None:
                seq = rest("GET", "/status")["last_event_seq"]
                st = rest("GET", "/status")
                print(f"{DIM}connected: mode={st['mode']}  switches={st['n_switches']}/6  ML-API={st['ml_api']}{RESET}",
                      flush=True)
            r = rest("GET", f"/events?since={seq}")
            waiting = False
            for ev in r["events"]:
                if ev["seq"] > seq:
                    show(ev)
            seq = max(seq, r.get("last_seq", seq))
        except DemoError:
            if not waiting:
                print(f"{DIM}waiting for the controller REST API ...{RESET}", flush=True)
                waiting = True
            seq = None
        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
