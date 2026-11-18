#!/usr/bin/env python3
"""Send a few small UDP requests to the victim's echo service and say whether they got through.

Run INSIDE a Mininet host (from the mininet> prompt):
    mininet> h9 python3 scripts/demo/udp_check.py h18      (Mininet replaces h18 with 10.0.0.18)

The victim h18 runs a UDP request/response server on port 5353 (started by mininet_lab.py).
Prints one line per request and a verdict: ACCEPTED (answers come back) or BLOCKED (no answers).
"""
import socket
import sys
import time

GREEN, RED, BOLD, RESET = "\033[32m", "\033[31m", "\033[1m", "\033[0m"


def main():
    dst = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.18"
    port, count, gap, timeout = 5353, 10, 0.2, 0.5
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.settimeout(timeout)
    sk.connect((dst, port))
    me = sk.getsockname()[0]
    name = f"h{me.rsplit('.', 1)[1]}"
    print(f"{name} ({me}) -> {dst} UDP port {port}: sending {count} requests")
    ok, rtts = 0, []
    for i in range(1, count + 1):
        t0 = time.monotonic()
        try:
            sk.send(b"demo-request-%d" % i)
            sk.recv(2048)
            rtt = (time.monotonic() - t0) * 1000
            ok += 1
            rtts.append(rtt)
            print(f"  request {i:>2}: reply in {rtt:6.2f} ms")
        except OSError:
            print(f"  request {i:>2}: NO REPLY (timeout {timeout}s)")
        time.sleep(gap)
    loss = 100 * (count - ok) / count
    avg = f", avg reply {sum(rtts) / len(rtts):.2f} ms" if rtts else ""
    if ok == count:
        verdict = f"{GREEN}{BOLD}ACCEPTED - {name}'s traffic reaches the victim{RESET}"
    elif ok == 0:
        verdict = f"{RED}{BOLD}BLOCKED - nothing from {name} reaches the victim{RESET}"
    else:
        verdict = f"{BOLD}PARTIAL - some requests from {name} were lost{RESET}"
    print(f"  answered {ok}/{count} ({loss:.0f}% loss){avg}  =>  {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
