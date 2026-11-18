#!/usr/bin/env python3
"""Operator CLI for the controller REST API (used by mitigation_ctl.sh and watch_status.sh).

    ctl.py status | list | ovs | remove <cookie> | remove-all | mode [MODE] | events | watch
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demolib import DemoError, dump_drop_rules, rest  # noqa: E402


def fmt_rules(r):
    print(f"mode={r['mode']}  active mitigation rules={r['n_rules']}")
    for x in r["rules"]:
        print(f"  {x['cookie']}  DROP {x['src']:<10} -> {x['dst']:<10} {x['proto_name']:<4} at {','.join(x['switches'])}"
              f"  priority={x['priority']} age={x['age_s']}s timeout={x['hard_timeout']}s"
              f"  dropped={x['dropped_packets']} pkts ({x['dropped_pps']:.0f} pps)")


def fmt_events(evs):
    for x in evs:
        t = time.strftime("%H:%M:%S", time.localtime(x["ts"]))
        k = x["type"]
        if k == "state":
            print(t, f"STATE  {x['dst']}  {x['previous']} -> {x['state']} ({x['label']})  score={x['score']:.3f}",
                  ("attributed=" + ",".join(x["attributed"])) if x.get("attributed") else "")
        elif k in ("rule_installed", "rule_removed", "rule_expired", "would_block"):
            print(t, f"{k.upper():<14} {x.get('cookie', '')} {x['src']} -> {x['dst']} "
                     f"{x.get('proto_name', x.get('proto', ''))} {x.get('reason', '')}")
        else:
            print(t, k.upper(), {a: b for a, b in x.items() if a not in ("seq", "ts", "type", "features")})


def watch():
    seq = None
    while True:
        try:
            s = rest("GET", "/status")
            r = rest("GET", "/rules")
            if seq is None:
                seq = max(s["last_event_seq"] - 15, 0)
            ev = rest("GET", f"/events?since={seq}")
        except DemoError as e:
            os.system("clear")
            print(e)
            time.sleep(2)
            continue
        os.system("clear")
        print(time.strftime("%H:%M:%S"), f" mode={s['mode']}  switches={s['n_switches']}/6  poll={s['poll']}"
              f"  ML-API={s['ml_api']}  rules={s['n_rules']}")
        print("-" * 100)
        win = s["window"]["dst"]
        dsts = sorted(set(win) | set(s["states"]),
                      key=lambda d: -(win.get(d, {}).get("features", {}).get("pps") or 0))[:6]
        for d in dsts:
            w = win.get(d, {})
            f = w.get("features", {})
            label = s["states"].get(d, {}).get("label", w.get("label", "NORMAL TRAFFIC"))
            if not f and label == "NORMAL TRAFFIC":
                continue
            print(f"{d:<11} {label:<19} score={w.get('score', 0):.3f}/{(w.get('threshold') or 0):.3f} "
                  f"sources={f.get('n_sources', 0):.0f} flows={f.get('n_active_flows', 0):.0f} "
                  f"pps={f.get('pps', 0):.0f} Mbps={(f.get('bps', 0) or 0) / 1e6:.1f} "
                  f"flowML max_p={f.get('ml_max_prob', 0):.2f}")
            for src in w.get("sources", [])[:10]:
                ip = src["src"]
                name = f"h{ip.rsplit('.', 1)[1]}" if ip.count(".") == 3 else ""
                verdict = ("\033[31;1mBLOCKED (dropped at its switch)\033[0m" if src["blocked"]
                           else "\033[32mACCEPTED\033[0m")
                sc = src["source_score"]
                print(f"     from {name:>4} {ip:<10} {src['pps']:>8.0f} pps  flowML={src['ml_max_prob']:.2f} "
                      f"src_score={'%.2f' % sc if sc is not None else '-':<5} {verdict}")
        print("-" * 100)
        if r["rules"]:
            fmt_rules(r)
            print("-" * 100)
        print("recent events:")
        fmt_events(ev["events"][-12:])
        sys.stdout.flush()
        time.sleep(2)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    arg = sys.argv[2] if len(sys.argv) > 2 else None
    if cmd == "status":
        s = rest("GET", "/status")
        print(f"mode={s['mode']}  switches={s['n_switches']}/6 {['s%d' % d for d in s['switches']]}  "
              f"poll={s['poll']}  ML-API={s['ml_api']}  rules={s['n_rules']}")
        for d, v in sorted(s["states"].items()):
            print(f"  {d:<12} {v['label']}")
    elif cmd == "list":
        fmt_rules(rest("GET", "/rules"))
    elif cmd == "ovs":
        if os.geteuid() != 0:
            sys.exit("needs sudo (ovs-ofctl)")
        rules = dump_drop_rules()
        for f in rules:
            print(f"{f['switch']}: {f['raw']}")
        print(f"({len(rules)} drop rule(s) on the switches)")
    elif cmd == "remove":
        if not arg:
            sys.exit("usage: mitigation_ctl.sh remove <cookie>")
        print(rest("DELETE", f"/rules/{arg}"))
    elif cmd == "remove-all":
        print(rest("DELETE", "/rules"))
    elif cmd == "mode":
        print(rest("POST", "/mode", {"mode": arg}) if arg else rest("GET", "/mode"))
    elif cmd == "events":
        fmt_events(rest("GET", f"/events?since={arg or 0}")["events"][-50:])
    elif cmd == "watch":
        watch()
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DemoError as e:
        sys.exit(f"ERROR: {e}")
    except KeyboardInterrupt:
        pass
