#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Loopback fixture server for tests/test-suite.sh.

Serves a directory on 127.0.0.1:8099 (never a public interface) and exposes
one extra endpoint, /slow, that stalls long enough to trip `timeout N curl`.

    srv.py [docroot]     default docroot: /srv/sxtest/in
    SXTEST_PORT=NNNN     override the port
"""
import http.server
import os
import socketserver
import sys
import time

ROOT = sys.argv[1] if len(sys.argv) > 1 else "/srv/sxtest/in"
PORT = int(os.environ.get("SXTEST_PORT", "8099"))
SLOW_SECONDS = 15  # must exceed every timeout used against /slow (currently 2s)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def do_GET(self):
        if self.path == "/slow":
            time.sleep(SLOW_SECONDS)
            try:
                self.send_response(200)
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"slow")
            except (BrokenPipeError, ConnectionResetError):
                pass  # client was killed by `timeout`: expected
            return
        super().do_GET()

    def log_message(self, *_args):
        pass  # keep test output clean


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True      # a stalled /slow must never block shutdown
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("127.0.0.1", PORT), Handler).serve_forever()
