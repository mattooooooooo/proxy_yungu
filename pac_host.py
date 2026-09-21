#!/usr/bin/env python3
"""Serve proxy.pac on the always-on server."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAC = ROOT / "proxy.pac"


class PacHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path not in {"/", "/proxy.pac", "/wpad.dat"}:
            self.send_error(404)
            return
        data = PAC.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5008)
    args = parser.parse_args()
    server = HTTPServer((args.listen, args.port), PacHandler)
    print(f"PAC http://{args.listen}:{args.port}/proxy.pac", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
