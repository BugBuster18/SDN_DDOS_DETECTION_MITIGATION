#!/usr/bin/env python3
"""Silent UDP sink for the victim: bind several ports and discard datagrams.

Without a listener the victim kernel answers every flood packet with an ICMP
port-unreachable, which turns a one-way flood into two-way traffic. A sink
keeps the lab traffic realistic (servers listen on their service ports).
Usage: python3 udp_sink.py 53 123 1900 8080 9999
"""
import selectors
import socket
import sys

sel = selectors.DefaultSelector()
for p in [int(x) for x in sys.argv[1:]] or [9999]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind(("0.0.0.0", p))
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ)
while True:
    for key, _ in sel.select():
        try:
            while True:
                key.fileobj.recvfrom(65535)
        except BlockingIOError:
            pass
