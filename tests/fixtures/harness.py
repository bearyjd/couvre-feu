"""Private-root fixture harness. Networking commands cannot fall through to PATH."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]
PROTECTED = "02:00:00:00:00:aa"
KID = "02:00:00:00:00:01"
OTHER_KID = "02:00:00:00:00:02"


def policy(revision=1):
    return {"version": 1, "revision": revision,
            "people": [{"id": "alice", "macs": [KID, OTHER_KID]}],
            "pauses": [], "schedules": [], "doh": {"ipv4": [], "ipv6": []}}


class RouterFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="couvre-feu-core-", dir="/tmp")
        self.root = Path(self.tmp.name)
        self.bin = self.root / "backend-bin"
        self.bin.mkdir()
        self.state = self.root / "backend.json"
        self.log = self.root / "backend.jsonl"
        self.log.touch()
        self.state.write_text(json.dumps({
            "sets": {}, "uci": {"network.lan.ipaddr": "192.168.1.1"},
            "tables": {name: {"filter": {
                "FORWARD": [["-j", "forwarding_rule"],
                            ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]],
                "INPUT": [["-j", "input_rule"], ["-j", "GL_DNS_LEAK"]],
                "forwarding_rule": [], "input_rule": []},
                "nat": {"PREROUTING": [["-j", "prerouting_rule"], ["-j", "dns_dispatcher"]],
                        "prerouting_rule": []}}
                       for name in ("iptables", "ip6tables")},
            "neighbors": [{"ip": "192.168.1.10", "mac": PROTECTED},
                          {"ip": "2001:db8::10", "mac": PROTECTED},
                          {"ip": "192.168.1.20", "mac": KID},
                          {"ip": "192.168.1.21", "mac": KID},
                          {"ip": "2001:db8::20", "mac": KID},
                          {"ip": "2001:db8::21", "mac": KID},
                          {"ip": "192.168.1.22", "mac": OTHER_KID}],
            "addresses4": ["2: br-lan    inet 192.168.1.1/24 scope global br-lan"],
            "addresses6": [], "routes4": [], "routes6": [],
            "failures": [], "delays": [], "reload_include": True,
            "native_witness": True}))
        for command in ("ipset", "iptables", "ip6tables", "iptables-save", "ip6tables-save",
                        "conntrack", "uci", "ip", "jsonfilter", "fw3", "firewall", "sync"):
            wrapper = self.bin / command
            wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " "
                               + shlex.quote(str(REPO / "tests/fixtures/backend.py")) + " "
                               + shlex.quote(command) + ' "$@"\n')
            wrapper.chmod(0o700)
        if os.environ.get("CF_TEST_AWK"):
            awk_command = shlex.split(os.environ["CF_TEST_AWK"])
            executable = shutil.which(awk_command[0])
            if executable is None:
                raise RuntimeError("requested genuine awk runtime is unavailable")
            awk_command[0] = executable
            wrapper = self.bin / "awk"
            wrapper.write_text("#!/bin/sh\nexec " + " ".join(map(shlex.quote, awk_command)) + ' "$@"\n')
            wrapper.chmod(0o700)
        # Marker only identifies a fake backend directory. It confers no live permission.
        (self.bin / ".couvrefeu-test-backend").write_text("mock-only\n")
        protected = self.root / "etc/couvrefeu/protected"
        protected.parent.mkdir(parents=True)
        protected.parent.chmod(0o700)
        protected.write_text(PROTECTED + "\n")
        protected.chmod(0o600)
        (protected.parent / "state").write_text("V\t1\nR\t0\n")
        (protected.parent / "state").chmod(0o600)
        firewall = self.root / "etc/config/firewall"
        firewall.parent.mkdir(parents=True)
        firewall.write_text("config defaults 'defaults'\n\toption input 'REJECT'\n")
        leases = self.root / "tmp/dhcp.leases"
        leases.parent.mkdir(parents=True)
        leases.write_text(f"0 {KID} 192.168.1.20 fixture *\n0 {OTHER_KID} 192.168.1.22 fixture2 *\n")
        self.env = dict(os.environ, CF_ROOT=str(self.root), CF_TEST_MODE="1",
                        CF_BACKEND_DIR=str(self.bin), CF_BACKEND_STATE=str(self.state),
                        CF_BACKEND_LOG=str(self.log), CF_NOW="1736204400",
                        PATH=str(self.bin) + os.pathsep + os.environ.get("PATH", ""))
        self.env.pop("SSH_CONNECTION", None)
        self.env.pop("SSH_CLIENT", None)
        self.shell = shlex.split(os.environ.get("CF_TEST_SHELL", "sh"))

    def close(self):
        self.tmp.cleanup()

    # Hundreds of Python backend processes need headroom on shared CI hosts.
    # Explicit caller deadlines and router input deadlines remain independent.
    def run(self, *args, document=None, raw=None, timeout=60, env=None):
        if document is not None:
            raw = json.dumps(document, separators=(",", ":"))
        return subprocess.run(self.shell + [str(REPO / "router/cfctl"), *args],
                              env=self.env if env is None else env, input=raw,
                              capture_output=True, text=True, timeout=timeout)

    def backend(self):
        return json.loads(self.state.read_text())

    def update_backend(self, **changes):
        state = self.backend()
        state.update(changes)
        self.state.write_text(json.dumps(state))

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def durable_snapshot(self):
        directory = self.root / "etc/couvrefeu"
        return {str(path.relative_to(directory)): (path.read_bytes(), path.stat().st_mode & 0o7777)
                for path in directory.rglob("*") if path.is_file()}

    def mutation_calls(self):
        return [call for call in self.calls()
                if call["command"] == "conntrack"
                or call["command"] == "ipset" and call["argv"][0] not in ("list", "save", "test", "-L")
                or call["command"] in ("iptables", "ip6tables") and any(arg in call["argv"] for arg in ("-A", "-I", "-D", "-N", "-X", "-F"))
                or call["command"] == "uci" and any(arg in call["argv"] for arg in ("set", "delete", "commit", "add_list", "batch"))
                or call["command"] in ("fw3", "firewall") and "reload" in call["argv"]]
