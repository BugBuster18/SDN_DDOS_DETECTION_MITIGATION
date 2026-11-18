"""Threaded static web server with a large listen backlog and socket timeouts (large testbed)."""
import functools
import http.server
import socket
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    timeout = 5

    def log_message(self, *a):
        pass


class Server(http.server.ThreadingHTTPServer):
    request_queue_size = 512
    daemon_threads = True


if __name__ == "__main__":
    socket.setdefaulttimeout(10)
    Server(("0.0.0.0", 80), functools.partial(Handler, directory=sys.argv[1])).serve_forever()
