"""Leg-2 pty driver of the Penn pilot (schema v2): marker watcher plus the four TTY commit legs.

Imports cleanly on its own. penn-pilot.py calls `bind(first_rehearsal_module)` right after loading it, which sets
`FR` and makes `Refusal` the same class the pilot catches. Not a script: it has no entry point. Standard library only.

Leg 1 is the single `ssh ... /bin/sh -s` payload session. Its stdout file is tailed here; a strict
`CFP_LEG2_READY <leg> <64 hex>` line starts the next planned leg once, under a pty, with the argv bound in the plan
digest. The typed confirmation (last six hex digits of the scope target MAC) is sent only when everything the leg has
printed equals the one expected text. Each leg gets its planned seconds, no retry, and is killed when leg 1 prints
STOP or CFP_LEG2_CANCEL, ends, or times out. Nothing the leg prints is kept except counts and the reply's reason codes.
This module never changes how the router is logged in to: it only reuses the pinned leg-1 ssh options."""
import hmac
import json
import os
import re
import select
import signal
import subprocess
import threading
import time
from typing import Any


class Refusal(Exception):
    """Placeholder until `bind` swaps in the first-rehearsal Refusal."""


FR: Any = None


def bind(first_rehearsal):
    """Bind the first-rehearsal module: its MAC canonicaliser and its Refusal class."""
    global FR, Refusal
    FR = first_rehearsal
    Refusal = first_rehearsal.Refusal


MARKER = re.compile(r'CFP_LEG2_READY (2[a-d]) ([0-9a-f]{64})')
CANCEL = re.compile(r'CFP_LEG2_CANCEL 2[a-d]')
PROMPT = 'Type the last 6 hex digits of the address (no colons) to confirm: '
# (leg, form, op) in the only order the plan may list them.
LEG_TABLE = (('2a', 'cfctl', 'scope-add'), ('2b', 'cfctl', 'scope-remove'),
             ('2c', 'cfctl-scope', 'scope-add'), ('2d', 'cfctl-scope', 'scope-remove'))
TEMPLATES = {'cfctl': r'/usr/sbin/cfctl (scope-add|scope-remove) \{MAC\} --base \{BASE\}',
             'cfctl-scope': r"env SSH_ORIGINAL_COMMAND='cfctl (scope-add|scope-remove) \{MAC\} --base \{BASE\}' "
                            r'/usr/sbin/cfctl-scope pilot'}
# The only ssh options a leg may carry besides the pinned known-hosts file (the leg-1 option set).
FIXED_OPTIONS = {'IdentitiesOnly=yes', 'BatchMode=yes', 'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null',
                 'ConnectTimeout=5', 'ConnectionAttempts=1', 'ForwardAgent=no', 'ClearAllForwardings=yes'}
REQUIRED_OPTIONS = {'IdentitiesOnly=yes', 'BatchMode=yes', 'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null'}
CAPTURE_BYTES = 4096
LINE_BYTES = 65536
POLL_SECONDS = 0.05
REASON = re.compile(r'[a-z0-9_]{1,64}')


def confirmation_digits(mac):
    """The last six hex digits of the canonical MAC, colons removed: all a leg ever types."""
    return mac.replace(':', '')[-6:]


def check_pinned(argv):
    """A leg argv is the leg-1 option set with `-tt` for `-T`; host-key checking and known hosts cannot be weakened."""
    if (len(argv) < 9 or argv[1:3] != ['-F', '/dev/null'] or argv[3] != '-i' or argv[-3] != '-tt'
            or not re.fullmatch(r'root@[0-9a-z.:-]+', argv[-2])):
        raise Refusal('leg ssh argv is not the pinned leg-1 shape')
    rest = argv[5:-3]
    if len(rest) % 2 or any(rest[index] != '-o' for index in range(0, len(rest), 2)):
        raise Refusal('leg ssh argv carries something other than -o options')
    options = rest[1::2]
    known = [option for option in options if option.startswith('UserKnownHostsFile=')]
    if (not REQUIRED_OPTIONS <= set(options) or len(known) != 1 or known[0] == 'UserKnownHostsFile=/dev/null'
            or [option for option in options if option not in FIXED_OPTIONS and option not in known]):
        raise Refusal('leg ssh options are not the pinned leg-1 options (host-key checking must stay strict)')


def check_leg(entry, expected, details, base):
    leg, form, op = expected
    mac = details['roles']['scope_target']['mac']
    if (entry.get('leg'), entry.get('form'), entry.get('op')) != expected:
        raise Refusal('leg table differs from the fixed one')
    if (entry.get('pty') is not True or entry.get('retry') is not False or entry.get('confirmation') != 'last6hex'
            or entry.get('scopeTargetMac') != mac or not FR.MAC.fullmatch(mac)):
        raise Refusal(f'leg {leg} flags or target differ from the fixed ones')
    seconds = entry.get('timeoutSeconds')
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= 120:
        raise Refusal(f'leg {leg} timeout is not 1-120 seconds')
    template = entry.get('commandTemplate')
    match = isinstance(template, str) and re.fullmatch(TEMPLATES[form], template)
    argv = entry.get('sshArgv')
    if not match or match.group(1) != op or not isinstance(argv, list) or argv[-1:] != [template]:
        raise Refusal(f'leg {leg} command is not the fixed text')
    if argv[:-1] != base[:-3] + ['-tt', base[-2]]:
        raise Refusal(f'leg {leg} ssh argv differs from the leg-1 argv')
    check_pinned(argv)


class Leg:
    """One commit leg under a pty. `step` is polled; every exit path goes through `finish`."""

    def __init__(self, entry, base, env, now):
        self.entry, self.leg = entry, entry['leg']
        mac = entry['scopeTargetMac']
        command = entry['commandTemplate'].replace('{MAC}', mac).replace('{BASE}', base)
        self.expected = f'{entry["op"]} {mac} --base {base}\n{PROMPT}'
        self.digits = confirmation_digits(mac)
        self.started, self.deadline = now, now + entry['timeoutSeconds']
        self.buffer, self.after, self.total, self.stderr_bytes = b'', b'', 0, 0
        self.sent, self.result, self.master, self.process = False, None, None, None
        master, slave = os.openpty()
        try:
            # The pty carries only what the remote prints; the local client's own stderr (banners, warnings, which
            # name the router) goes to a pipe that is only counted.
            self.process = subprocess.Popen(entry['sshArgv'][:-1] + [command], stdin=slave, stdout=slave,
                                            stderr=subprocess.PIPE, env=env, start_new_session=True, close_fds=True)
            self.master = master
        except OSError:
            os.close(master)
            self.finish('spawn_failed', None, now)
        finally:
            os.close(slave)

    def drain_stderr(self):
        while self.process is not None and self.process.stderr is not None and select.select([self.process.stderr], [], [], 0)[0]:
            chunk = os.read(self.process.stderr.fileno(), 4096)
            if not chunk:
                return
            self.stderr_bytes += len(chunk)

    def read(self):
        self.drain_stderr()
        while self.master is not None and select.select([self.master], [], [], 0)[0]:
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                return
            if not chunk:
                return
            self.total += len(chunk)
            if self.sent:
                self.after = (self.after + chunk)[-CAPTURE_BYTES:]
            elif len(self.buffer) <= CAPTURE_BYTES:
                self.buffer += chunk

    def check_prompt(self):
        text = self.buffer.decode('utf-8', 'replace').replace('\r\n', '\n')
        if len(self.buffer) > CAPTURE_BYTES or not self.expected.startswith(text.removesuffix('\r')):
            return False
        if text == self.expected:
            os.write(self.master, (self.digits + '\n').encode())
            self.sent = True
        return True

    def step(self, now):
        if self.result:
            return
        self.read()
        code = self.process.poll()
        if code is not None:
            self.read()
            self.finish('exited', code, now)
        elif not self.sent and self.buffer and not self.check_prompt():
            self.kill('prompt_mismatch', now)
        elif now >= self.deadline:
            self.kill('timeout', now)

    def kill(self, outcome, now):
        if self.result:
            return
        if self.process is not None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait()
        self.finish(outcome, None, now)

    def finish(self, outcome, code, now):
        if self.process is not None and self.process.stderr is not None:
            self.drain_stderr()
            self.process.stderr.close()
        if self.master is not None:
            try:
                os.close(self.master)
            finally:
                self.master = None
        reply = {}
        for line in reversed((self.buffer + self.after).decode('utf-8', 'replace').replace('\r\n', '\n').split('\n')):
            if line.startswith('{'):
                try:
                    reply = json.loads(line)
                except ValueError:
                    continue
                break
        reply = reply if isinstance(reply, dict) else {}
        errors = reply.get('errors') if isinstance(reply.get('errors'), list) else []
        # Counts and reason codes only: no line the leg printed (MAC, base, echoed digits) is ever kept.
        self.result = {'leg': self.leg, 'form': self.entry['form'], 'op': self.entry['op'], 'outcome': outcome,
                       'exit': code, 'ok': outcome == 'exited' and code == 0 and reply.get('ok') is True,
                       'errors': [e for e in errors if isinstance(e, str) and REASON.fullmatch(e)][:8],
                       'confirmationSent': self.sent, 'bytes': self.total, 'stderrBytes': self.stderr_bytes, 'seconds': int(now - self.started)}


class Tail:
    """Complete lines appended to a file since the last call; a partial last line waits for its newline."""

    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
        self.partial = b''

    def lines(self):
        found = []
        while True:
            chunk = os.read(self.fd, LINE_BYTES)
            if not chunk:
                return found
            *complete, partial = (self.partial + chunk).split(b'\n')
            self.partial = partial[-LINE_BYTES:]
            found.extend(line.decode('utf-8', 'replace').removesuffix('\r') for line in complete)

    def close(self):
        os.close(self.fd)


def feed(stream, payload):
    try:
        stream.write(payload)
    except OSError:
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


class Driver:
    """Leg 1 plus the leg-2 watcher. Built only from a plan whose digest is exactly the approved one."""

    def __init__(self, details, approved_sha, digest_fn):
        if not re.fullmatch(r'[0-9a-f]{64}', approved_sha or ''):
            raise Refusal('approved plan sha256 must be 64 lowercase hex characters')
        if not (hmac.compare_digest(str(details.get('planSha256')), approved_sha)
                and hmac.compare_digest(digest_fn(details), approved_sha)):
            raise Refusal('plan differs from the approved digest: no leg may run')
        base, legs = details['sshArgv'], details.get('legs')
        if (not isinstance(legs, list) or len(legs) != len(LEG_TABLE) or base[-3:-2] != ['-T']
                or not isinstance(base[-2], str)):
            raise Refusal('plan legs or leg-1 argv are not the fixed shape')
        for entry, expected in zip(legs, LEG_TABLE):
            check_leg(entry, expected, details, base)
        self.argv, self.legs = list(base), legs

    def run(self, payload, env, stdout_fd, stderr_fd, stdout_path, timeout):
        """Returns (leg-1 exit code, timed_out, {'legs': [...], 'ignoredMarkers': n}). Always reaps everything."""
        tail = Tail(stdout_path)
        process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=stdout_fd, stderr=stderr_fd, env=env,
                                   start_new_session=True)
        feeder = threading.Thread(target=feed, args=(process.stdin, payload), daemon=True)
        feeder.start()
        results, ignored, active, pending, locked = [], 0, None, None, False
        timed_out, aborted, begun = False, True, time.monotonic()
        try:
            while True:
                now = time.monotonic()
                lines = tail.lines()
                halts = [CANCEL.fullmatch(line) is not None for line in lines if line.startswith('STOP ') or CANCEL.fullmatch(line)]
                markers = [m.groups() for m in map(MARKER.fullmatch, lines) if m]
                if halts:
                    locked, pending = True, None
                    if active:
                        active.kill('killed_on_cancel' if halts[0] else 'killed_on_stop', now)
                if active:
                    active.step(now)
                    if active.result:
                        results.append(active.result)
                        active = None
                for leg, base in markers:
                    index = len(results) + (1 if active else 0)
                    if locked or pending or index >= len(self.legs) or self.legs[index]['leg'] != leg:
                        ignored += 1
                    elif active:
                        pending = (index, base)  # leg 1 was quicker than this leg's ssh closing: start it right after
                    else:
                        active = Leg(self.legs[index], base, env, now)
                if pending and not active and not locked:
                    active, pending = Leg(self.legs[pending[0]], pending[1], env, now), None
                if process.poll() is not None:
                    break
                if now - begun > timeout:
                    timed_out = True
                    break
                time.sleep(POLL_SECONDS)
            aborted = False
        finally:
            if active:
                active.kill('aborted' if aborted else 'killed_leg1_ended', time.monotonic())
                results.append(active.result)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            feeder.join(5)
            tail.close()
        return process.returncode, timed_out, {'legs': results, 'ignoredMarkers': ignored}
