"""Tiny HTTPS page server for the R6-4 Chrome WebTransport interop page.

Serves `index.html` from this directory over a runtime self-signed certificate
(the same certificate `run-chrome.sh` hands to the harness), and exposes two
small endpoints so the run script can collect machine-readable evidence:

- `GET /params.json` reads the harness log and returns the values the page
  needs *after* the QUIC handshake (`peer_max_datagram_frame_size` and the
  harness' own `max_datagram_frame_size_advertised`). The page cannot know
  these before Chrome connects, so it polls this endpoint with a bounded
  timeout after `WebTransport.ready` resolves.
- `POST /result` stores the page's final `window.__rtx_result` JSON verbatim,
  so the script does not have to reconstruct it from console summaries.

Usage: page_server.py <port> <cert.pem> <key.pem> <result.json> <server.log>
"""

import http.server
import json
import os
import re
import ssl
import sys
import tempfile

port = int(sys.argv[1])
cert = sys.argv[2]
key = sys.argv[3]
result_path = sys.argv[4]
server_log_path = sys.argv[5]

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)

PEER_RE = re.compile(r"peer_max_datagram_frame_size=([0-9]+|absent)")
ADVERTISED_RE = re.compile(r"max_datagram_frame_size_advertised=([0-9]+)")


def harness_params():
    """Returns the last observed handshake values, or nulls when not yet logged."""
    peer = None
    advertised = None
    try:
        with open(server_log_path, "r", encoding="utf-8") as handle:
            for line in handle:
                match = ADVERTISED_RE.search(line)
                if match:
                    advertised = int(match.group(1))
                match = PEER_RE.search(line)
                if match and match.group(1) != "absent":
                    peer = int(match.group(1))
    except FileNotFoundError:
        pass
    return {
        "peer_max_datagram_frame_size": peer,
        "max_datagram_frame_size_advertised": advertised,
    }


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        if self.path.split("?")[0] == "/params.json":
            body = json.dumps(harness_params()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self):  # noqa: N802 - http.server API
        if self.path != "/result":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        directory = os.path.dirname(result_path)
        os.makedirs(directory, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=directory, prefix=".result-")
        try:
            with os.fdopen(handle, "wb") as out:
                out.write(body)
            os.replace(temporary, result_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        self.send_response(204)
        self.end_headers()

    def log_message(self, message, *args):
        sys.stderr.write("page_server: " + (message % args) + "\n")


server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("serving on", port, flush=True)
server.serve_forever()
