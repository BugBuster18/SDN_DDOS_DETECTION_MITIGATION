"""Tiny UDP request/response workload (DNS-like) for benign traffic.

server: python3 udp_rr.py server PORT
client: python3 udp_rr.py client HOST PORT QPS SIZE   (new source port per query)
"""
import socket
import sys
import time


def server(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        data, addr = s.recvfrom(65535)
        s.sendto(data[: max(64, min(len(data) * 2, 1200))] * 1, addr)


def client(host: str, port: int, qps: float, size: int) -> None:
    gap = 1.0 / max(qps, 0.1)
    payload = b"q" * size
    nxt = time.monotonic()
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        try:
            s.sendto(payload, (host, port))
            s.recvfrom(65535)
        except OSError:
            pass
        finally:
            s.close()
        nxt += gap
        time.sleep(max(0.0, nxt - time.monotonic()))


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(int(sys.argv[2]))
    else:
        client(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5]))
