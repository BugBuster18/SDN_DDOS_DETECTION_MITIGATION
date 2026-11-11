#!/usr/bin/env python3
"""Measuring UDP request/response client (DNS-like) for the victim's udp_rr server.

Each query uses a new source port (like a real resolver) and waits up to
--timeout for the answer. Prints one JSON line per second and a final summary:
    {"t": <unix>, "sent": n, "answered": m, "rtt_ms_avg": x}
    {"summary": true, "sent": N, "answered": M, "loss_pct": L, "rtt_ms_avg": R}

    python3 udp_probe.py 10.0.0.18 --port 5353 --qps 20 --duration 30 --size 128
"""
import argparse
import json
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=5353)
    ap.add_argument("--qps", type=float, default=10.0)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--size", type=int, default=128)
    ap.add_argument("--timeout", type=float, default=0.5)
    a = ap.parse_args()
    gap = 1.0 / max(a.qps, 0.1)
    payload = b"q" * a.size
    t_end = time.time() + a.duration
    nxt = time.monotonic()
    tot_s = tot_a = 0
    tot_rtt = 0.0
    sec = int(time.time())
    s_cnt = a_cnt = 0
    s_rtt = 0.0
    while time.time() < t_end:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.settimeout(a.timeout)
        t0 = time.monotonic()
        ok = False
        try:
            sk.sendto(payload, (a.host, a.port))
            sk.recvfrom(65535)
            ok = True
        except OSError:
            pass
        finally:
            sk.close()
        rtt = (time.monotonic() - t0) * 1000.0
        tot_s += 1
        s_cnt += 1
        if ok:
            tot_a += 1
            a_cnt += 1
            tot_rtt += rtt
            s_rtt += rtt
        now = int(time.time())
        if now != sec:
            print(json.dumps({"t": sec, "sent": s_cnt, "answered": a_cnt,
                              "rtt_ms_avg": round(s_rtt / a_cnt, 3) if a_cnt else None}), flush=True)
            sec, s_cnt, a_cnt, s_rtt = now, 0, 0, 0.0
        nxt += gap
        time.sleep(max(0.0, nxt - time.monotonic()))
    print(json.dumps({"summary": True, "sent": tot_s, "answered": tot_a,
                      "loss_pct": round(100.0 * (tot_s - tot_a) / tot_s, 2) if tot_s else None,
                      "rtt_ms_avg": round(tot_rtt / tot_a, 3) if tot_a else None}), flush=True)
    sys.exit(0 if tot_a else 1)


if __name__ == "__main__":
    main()
