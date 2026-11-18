#!/usr/bin/env python3
"""Legitimate-client agent for the large testbed. Logs every request outcome.

web  URL_LIST MEAN_GAP SEED OUT : HTTP GETs (new TCP connection each), think time ~ U(0.5, 2*MEAN_GAP)
rr   HOST PORT QPS SEED OUT     : DNS-like UDP request/response on one socket, 1 s timeout
Output CSV lines: epoch,ok,latency_s,target
"""
import random
import socket
import sys
import time
import urllib.request


def web(urls, mean_gap, seed, out):
    rng = random.Random(seed)
    urls = urls.split(",")
    with open(out, "a", buffering=1) as fh:
        time.sleep(rng.uniform(0, mean_gap * 2))
        while True:
            u = rng.choice(urls)
            t0 = time.time()
            ok = 0
            try:
                with urllib.request.urlopen(u, timeout=2.0) as r:
                    r.read()
                    ok = int(r.status == 200)
            except Exception:
                ok = 0
            fh.write("%.3f,%d,%.4f,%s\n" % (t0, ok, time.time() - t0, u.split("/")[2]))
            time.sleep(rng.uniform(0.5, 2 * mean_gap))


def rr(host, port, qps, seed, out):
    rng = random.Random(seed)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    gap = 1.0 / qps
    with open(out, "a", buffering=1) as fh:
        time.sleep(rng.uniform(0, 1))
        nxt = time.monotonic()
        while True:
            t0 = time.time()
            ok = 0
            try:
                s.sendto(b"q" * rng.randint(40, 120), (host, port))
                s.recvfrom(4096)
                ok = 1
            except OSError:
                ok = 0
            fh.write("%.3f,%d,%.4f,%s\n" % (t0, ok, time.time() - t0, host))
            nxt += gap
            time.sleep(max(0.0, nxt - time.monotonic()))


def tcpbulk(host, port, rate_bps):
    """Paced TCP sender (bulk transfer at a target rate). Throughput is measured on switch ports."""
    chunk = b"x" * 8192
    gap = len(chunk) * 8 / rate_bps
    while True:
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.settimeout(3)
            nxt = time.monotonic()
            while True:
                s.sendall(chunk)
                nxt += gap
                if nxt < time.monotonic() - 1.0:   # no catch-up bursts after a stall
                    nxt = time.monotonic()
                time.sleep(max(0.0, nxt - time.monotonic()))
        except OSError:
            time.sleep(0.5)


def udpstream(host, port, rate_bps, size):
    """Constant-bit-rate UDP stream (video-like), paced with sleeps (low CPU)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"v" * size
    gap = size * 8 / rate_bps
    nxt = time.monotonic()
    while True:
        try:
            s.sendto(payload, (host, port))
        except OSError:
            pass
        nxt += gap
        if nxt < time.monotonic() - 1.0:   # never burst to catch up after a stall (CBR source)
            nxt = time.monotonic()
        time.sleep(max(0.0, nxt - time.monotonic()))


def tcpsink(port):
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(256)

    def drain(c):
        try:
            while c.recv(65536):
                pass
        except OSError:
            pass
        c.close()
    while True:
        c, _ = srv.accept()
        threading.Thread(target=drain, args=(c,), daemon=True).start()


if __name__ == "__main__":
    m = sys.argv[1]
    if m == "web":
        web(sys.argv[2], float(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
    elif m == "rr":
        rr(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5]), sys.argv[6])
    elif m == "tcpbulk":
        tcpbulk(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
    elif m == "udpstream":
        udpstream(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5]))
    elif m == "tcpsink":
        tcpsink(int(sys.argv[2]))
