#!/usr/bin/env python3
"""Offline fake-WebSocket and loopback-only helper verification."""
import contextlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent / "client-probe"
# The node check takes ~0.1 s here, but a 10 s limit expired on a loaded CI runner (job 123143961182). 60 s still fails a real hang.
NODE_TIMEOUT = 60
spec = importlib.util.spec_from_file_location("probe_helper", ROOT / "helper.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class ProbeTests(unittest.TestCase):
    def test_fake_socket_evidence(self):
        script = r'''
import assert from 'node:assert/strict';
import {Probe, clockBounds} from './tests/client-probe/probe.mjs';
let at = 0, id = 0, factories = 0, rows = [], messages = [];
const ws = {readyState: 1, bufferedAmount: 0, send: x => messages.push(x), close() {this.readyState = 3;}};
const p = new Probe({now: () => at, random: () => (++id).toString(16).padStart(32, '0'),
  log: x => rows.push(x), socketFactory: () => { factories++; return ws; }});
p.start(); at = 500; p.tick(); const first = messages[0];
at = 600; p.receive(first); p.receive(first);
p.receive(first.replace('"seq":1', '"seq":9'));
p.receive(JSON.stringify({nonce: 'unknown'})); p.receive('{');
assert.equal(rows.filter(x => x.event === 'fresh-echo').length, 1);
at = 1000; p.tick(); at = 1501; p.receive(messages[1]);
assert.equal(rows.filter(x => x.event === 'fresh-echo').length, 1);
at = 2000; p.tick(); assert.equal(p.stopped, true); // >750ms actual gap
assert.equal(factories, 1); assert.throws(() => p.start());
p.receive(first); assert.equal(rows.filter(x => x.event === 'fresh-echo').length, 1);
assert.deepEqual(clockBounds(10, 30, 100), [70, 90]);
const trial = () => {let t = 0; const s = {...ws, readyState: 1, bufferedAmount: 0};
  const q = new Probe({now: () => t, random: () => 'a'.repeat(32), log: () => {}, socketFactory: () => s});
  q.start(); return {q, s, advance: value => {t = value; q.tick();}};};
let x = trial(); x.s.bufferedAmount = 32768; x.advance(500); assert.equal(x.q.stopped, true);
x = trial(); for(let t = 500; t <= 60000; t += 500) x.advance(t);
assert.equal(x.q.stopped, true); assert.ok(x.q.sequence <= 120);
x = trial(); x.s.onclose(); assert.equal(x.q.stopped, true); assert.throws(() => x.q.start());
assert.ok(!first.includes('child') && !first.includes('adult'));
'''
        result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=ROOT.parents[1], capture_output=True, text=True, timeout=NODE_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr[:1000])

    def test_bind_and_lifetime_validation(self):
        for address in ("0.0.0.0", "::", "::ffff:0.0.0.0", "224.0.0.1", "example.org", "8.8.8.8", "169.254.1.1"):
            with self.assertRaises(ValueError): helper.validated_bind(address)
        self.assertEqual(helper.validated_bind("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(ValueError): helper.ProbeServer(("127.0.0.1", 0), "/tmp/unused-probe", 89)

    def test_helper_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.jsonl"
            server = helper.ProbeServer(("127.0.0.1", 0), str(path))
            thread = threading.Thread(target=server.run); thread.start()
            def request(method, target, body=None, cap=None, headers=None):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                fields = headers or {}
                if cap: fields["X-Probe-Cap"] = cap
                conn.request(method, target, body, fields); reply = conn.getresponse()
                result = (reply.status, reply.read(), reply.getheader("Access-Control-Allow-Origin"))
                conn.close(); return result
            try:
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertEqual(request("GET", "/")[0], 200)
                self.assertEqual(request("GET", "/clock")[0], 403)
                self.assertEqual(request("GET", "/clock", cap="wrong")[0], 403)
                status, body, cors = request("GET", "/clock", cap=server.cap)
                self.assertEqual(status, 200); self.assertIn("serverMs", json.loads(body)); self.assertIsNone(cors)
                for target in ("/../helper.py", "/helper.py", "/?cap=" + server.cap, "/clock?token=x"):
                    self.assertEqual(request("GET", target, cap=server.cap)[0], 404)
                data = json.dumps({"clientMs": 1, "nonce": "a" * 32, "events": []})
                self.assertEqual(request("POST", "/heartbeat", data, server.cap)[0], 200)
                self.assertEqual(request("POST", "/heartbeat", "x" * 2049, server.cap)[0], 400)
                self.assertEqual(request("POST", "/heartbeat", "{}", server.cap)[0], 400)
                self.assertEqual(request("POST", "/heartbeat", data, server.cap, {"Transfer-Encoding": "chunked"})[0], 400)
                self.assertNotIn(server.cap, path.read_text())
                server.written = 262144
                self.assertEqual(request("POST", "/heartbeat", data, server.cap)[0], 400)
                with self.assertRaises(FileExistsError): helper.ProbeServer(("127.0.0.1", 0), str(path))
            finally:
                server.deadline = time.monotonic(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_absolute_deadline_interrupts_partial_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            server = helper.ProbeServer(("127.0.0.1", 0), str(Path(directory) / "log"))
            server.deadline = time.monotonic() + 0.15
            with contextlib.redirect_stderr(io.StringIO()):
                thread = threading.Thread(target=server.run); thread.start()
                conn = socket.create_connection(("127.0.0.1", server.server_port))
                conn.sendall(b"GET / HTTP/1.1\r\nX-Slow: ")
                thread.join(timeout=1); conn.close()
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main(verbosity=2)
