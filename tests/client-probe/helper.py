#!/usr/bin/env python3
"""Temporary local evidence helper; starting a live LAN listener needs approval."""
import argparse
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

STATIC = {"/": ("index.html", "text/html"), "/probe.mjs": ("probe.mjs", "text/javascript")}


def validated_bind(value):
    address = ipaddress.ip_address(value)
    if getattr(address, "ipv4_mapped", None):
        validated_bind(str(address.ipv4_mapped))
    if address.is_unspecified or address.is_multicast or address.is_link_local:
        raise ValueError("Use one explicit loopback or LAN unicast address")
    if not address.is_loopback and not address.is_private:
        raise ValueError("Public listener addresses are outside this probe")
    return str(address)


class ProbeServer(HTTPServer):
    def __init__(self, address, log_path, lifetime=90):
        host = validated_bind(address[0])
        if not 90 <= lifetime <= 180:
            raise ValueError("Lifetime must be 90..180 seconds")
        if not Path(log_path).is_absolute():
            raise ValueError("Provide an explicit absolute private log path")
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        super().__init__((host, address[1]), Handler)
        try:
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fchmod(fd, 0o600)
            self.journal = os.fdopen(fd, "w", encoding="utf-8")
        except Exception:
            self.server_close()
            raise
        self.cap = secrets.token_urlsafe(32)
        self.deadline = time.monotonic() + lifetime
        self.requests = self.written = 0
        self.timeout = 0.2

    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(max(0.001, min(1, self.deadline - time.monotonic())))
        def expire():
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        watchdog = threading.Timer(max(0.001, min(1, self.deadline - time.monotonic())), expire)
        watchdog.daemon = True
        watchdog.start()  # Absolute connection bound also stops slow byte-at-a-time bodies.
        self.watchdog = watchdog
        return conn, address

    def shutdown_request(self, request):
        self.watchdog.cancel()
        super().shutdown_request(request)

    def handle_error(self, *_):
        pass  # Do not print request metadata or private source addresses.

    def record(self, value):
        row = json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n"
        if self.written + len(row.encode()) > 262144:
            raise ValueError("Private log limit reached")
        self.journal.write(row)
        self.journal.flush()
        self.written += len(row.encode())

    def run(self):
        try:
            while time.monotonic() < self.deadline and self.requests < 1000:
                self.handle_request()
        finally:
            self.journal.close()
            self.server_close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # No URL, headers, capabilities or household source addresses on stdout.

    def reply(self, status, body, mime="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def allowed(self):
        self.server.requests += 1
        if time.monotonic() >= self.server.deadline or self.server.requests > 1000:
            self.reply(410, {"error": "Probe window ended"})
            return False
        if self.path not in (*STATIC, "/clock", "/heartbeat"):
            self.reply(404, {"error": "Unknown path"})
            return False
        if self.path not in STATIC and not secrets.compare_digest(self.headers.get("X-Probe-Cap", ""), self.server.cap):
            self.reply(403, {"error": "Capability required"})
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        if self.path in STATIC:
            name, mime = STATIC[self.path]
            self.reply(200, Path(__file__).with_name(name).read_bytes(), mime)
        elif self.path == "/clock":
            self.reply(200, {"serverMs": time.monotonic() * 1000, "wallMs": time.time() * 1000})
        else:
            self.reply(405, {"error": "POST required"})

    def do_POST(self):
        if not self.allowed():
            return
        if self.path != "/heartbeat":
            self.reply(405, {"error": "Wrong method"})
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                raise ValueError("One bounded content length required")
            size = int(lengths[0])
            if not 1 <= size <= 2048:
                raise ValueError("Body limit")
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("Incomplete body")
            body = json.loads(raw)
            if set(body) != {"clientMs", "nonce", "events"} or not isinstance(body["events"], list) or len(body["events"]) > 8:
                raise ValueError("Invalid heartbeat")
            if isinstance(body["clientMs"], bool) or not isinstance(body["clientMs"], (int, float)) or not math.isfinite(body["clientMs"]):
                raise ValueError("Invalid client clock")
            if not isinstance(body["nonce"], str) or len(body["nonce"]) != 32 or any(c not in "0123456789abcdef" for c in body["nonce"]):
                raise ValueError("Invalid heartbeat nonce")
            self.server.record({"serverMs": time.monotonic() * 1000, "source": self.client_address[0], "heartbeat": body})
            self.reply(200, {"nonce": body["nonce"]})
        except (ValueError, TypeError, OverflowError, RecursionError, socket.timeout):
            self.reply(400, {"error": "Invalid or exhausted bounded heartbeat"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--lifetime", type=int, default=90)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()
    server = ProbeServer((args.bind, args.port), args.log, args.lifetime)
    host = f"[{args.bind}]" if ":" in args.bind else args.bind
    print(f"Private local URL (do not share): http://{host}:{server.server_port}/#{server.cap}", flush=True)
    print("APPLICATION OBSERVATION ONLY. Packet, route, IPv6 and offload gates remain pending.", flush=True)
    server.run()
