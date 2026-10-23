"""Leg-2 pty driver of the Penn pilot (schema v2): marker watcher plus the four TTY commit legs.

Imports cleanly on its own. penn-pilot.py calls `bind(first_rehearsal_module)` right after loading it, which sets
`FR` and makes `Refusal` the same class the pilot catches. Not a script: it has no entry point. Standard library only.

Leg 1 is the single `ssh ... /bin/sh -s` payload session. Its stdout file is tailed here; a strict
`CFP_LEG2_READY <leg> <64 hex>` line starts the next planned leg once, under a pty, with the argv bound in the plan
digest. The typed confirmation (last six hex digits of the scope target MAC) is sent only when everything the leg has
printed equals the one expected text. Each leg gets its planned seconds, no retry, and is killed when leg 1 prints
STOP or CFP_LEG2_CANCEL, ends, or times out. Nothing the leg prints is kept except counts and the reply's reason codes.
This module never changes how the router is logged in to: it only reuses the pinned leg-1 ssh options. The known-hosts
and identity files are re-hashed before every leg and every ack; SIGTERM, SIGHUP and SIGINT end a run like Ctrl-C."""
import contextlib
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
# Leg 1's teardown names the router-side acknowledgement file; the only path the driver will ever write.
ACK_FILE = re.compile(r'CFP_LEG2_ACK_FILE (/tmp/couvre-feu-first\.[A-Za-z0-9]{6}/leg2-idle)')
# Created only once no cfctl or cfctl-scope process is alive on the router (a leg's `timeout` parents carry the same
# field, so a live leg is seen through its argv chain; checked as exact NUL-separated fields of
# /proc/*/cmdline, so this script's own command line never matches), never through an existing file or symlink.
ACK_SCRIPT = r"""n=0
while :; do b=0
  for p in /proc/[0-9]*; do
    [ -r "$p/cmdline" ] || continue
    if tr '\000' '\n' <"$p/cmdline" 2>/dev/null | awk '$0=="/usr/sbin/cfctl"||$0=="/usr/sbin/cfctl-scope"{f=1}END{exit !f}'; then b=1; break; fi
  done
  if [ "$b" = 0 ]; then break; fi
  n=$((n+1)); if [ "$n" -gt SCAN_ ]; then exit 3; fi
  sleep 1
done
if [ -e PATH_ ] || [ -L PATH_ ]; then exit 4; fi
set -C; : > PATH_
"""
# The router-side scan waits up to this many seconds for a live cfctl (cron `cfctl expire`, the wrapper's timeout
# watcher) to go away, then reports busy (final, no retry). It, the ssh connect (5 s) and the ssh timeout below must
# fit the shell's CFP_LEG2_CANCEL_WAIT (20 s, shared with the quiet check), so it stays a constant 15.
ACK_SCAN_SECONDS = 15
ACK_SECONDS = ACK_SCAN_SECONDS + 10
ACK_BUSY = 3
SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
PROMPT = 'Type the last 6 hex digits of the address (no colons) to confirm: '
# (leg, form, op) in the only order the plan may list them.
LEG_TABLE = (('2a', 'cfctl', 'scope-add'), ('2b', 'cfctl', 'scope-remove'),
             ('2c', 'cfctl-scope', 'scope-add'), ('2d', 'cfctl-scope', 'scope-remove'))
# The remote bound is `timeout -s KILL <seconds + grace> timeout -s TERM <seconds>`: TERM (the leg's own digest-bound
# timeoutSeconds) lets cfctl's traps release the platform lock, KILL (no -k in busybox 1.33) is the backstop. Both
# numbers are written without leading zeros.
LEG_KILL_GRACE_SECONDS = 15
BOUND_RE = r'timeout -s KILL ([1-9][0-9]{0,2}) timeout -s TERM ([1-9][0-9]{0,2}) '
TEMPLATES = {'cfctl': BOUND_RE + r'/usr/sbin/cfctl (scope-add|scope-remove) \{MAC\} --base \{BASE\}',
             'cfctl-scope': BOUND_RE + r"env SSH_ORIGINAL_COMMAND='cfctl (scope-add|scope-remove) "
                            r"\{MAC\} --base \{BASE\}' /usr/sbin/cfctl-scope pilot"}
# The only ssh options a leg may carry besides the pinned known-hosts file (the leg-1 option set).
FIXED_OPTIONS = {'IdentitiesOnly=yes', 'BatchMode=yes', 'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null',
                 'ConnectTimeout=5', 'ConnectionAttempts=1', 'ForwardAgent=no', 'ClearAllForwardings=yes'}
REQUIRED_OPTIONS = {'IdentitiesOnly=yes', 'BatchMode=yes', 'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null'}
CAPTURE_BYTES = 4096
LINE_BYTES = 65536
READ_BYTES = 65536  # most one step takes from a leg's pty or stderr: a flood cannot starve the deadline, STOP or cancel
POLL_SECONDS = 0.05
REASON = re.compile(r'[a-z0-9_]{1,64}')


def confirmation_digits(mac):
    """The last six hex digits of the canonical MAC, colons removed: all a leg ever types."""
    return mac.replace(':', '')[-6:]


def check_pinned(argv):
    """A leg argv is the leg-1 option set with `-e none -tt` for `-T`; host-key checking and known hosts cannot be weakened."""
    if (len(argv) < 11 or argv[1:3] != ['-F', '/dev/null'] or argv[3] != '-i' or argv[-5:-2] != ['-e', 'none', '-tt']
            or not re.fullmatch(r'root@[0-9a-z.:-]+', argv[-2])):
        raise Refusal('leg ssh argv is not the pinned leg-1 shape')
    rest = argv[5:-5]
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
    if (not match or match.group(3) != op or int(match.group(2)) != seconds
            or int(match.group(1)) != seconds + LEG_KILL_GRACE_SECONDS or not isinstance(argv, list)
            or argv[-1:] != [template]):
        raise Refusal(f'leg {leg} command is not the fixed text')
    if argv[:-1] != base[:-3] + ['-e', 'none', '-tt', base[-2]]:
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
        taken = 0
        while (taken < READ_BYTES and self.process is not None and self.process.stderr is not None
               and select.select([self.process.stderr], [], [], 0)[0]):
            chunk = os.read(self.process.stderr.fileno(), 4096)
            if not chunk:
                return
            taken += len(chunk)
            self.stderr_bytes += len(chunk)

    def read(self):
        self.drain_stderr()
        taken = 0
        while taken < READ_BYTES and self.master is not None and select.select([self.master], [], [], 0)[0]:
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                return
            if not chunk:
                return
            taken += len(chunk)
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
        if self.exited():
            self.read()
            self.finish('exited', self.process.wait(), now)
        elif not self.sent and self.buffer and not self.check_prompt():
            self.kill('prompt_mismatch', now)
        elif now >= self.deadline:
            self.kill('timeout', now)

    def killpg(self):
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def exited(self):
        """True once the leg's ssh has exited; its whole process group is killed BEFORE the leader is reaped, while
        the group id is still ours, so nothing it left behind outlives it."""
        try:
            done = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return self.process.poll() is not None
        if done is not None:
            self.killpg()
        return done is not None

    def kill(self, outcome, now):
        if self.result:
            return
        if self.process is not None:
            self.killpg()
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


def send_ack(argv, path, env):
    """Create the acknowledgement file on the router with ONE short ssh (the leg-1 argv, ACK_SCRIPT as the command).
    Returns 'sent', 'busy' (a cfctl process was still alive on the router: nothing written) or 'failed'. Only called
    once no leg is in flight and none can start."""
    try:
        script = ACK_SCRIPT.replace('PATH_', path).replace('SCAN_', str(ACK_SCAN_SECONDS))
        done = subprocess.run(argv[:-1] + [script], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True,
                              timeout=ACK_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return 'failed'
    return {0: 'sent', ACK_BUSY: 'busy'}.get(done.returncode, 'failed')


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


def block_signals():
    """Every helper thread calls this first: a process-wide signal goes to any thread that does not block it, and
    CPython then runs the Python handler in the main thread, so one unblocked helper defeats the main thread's mask."""
    signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)


def feed(stream, payload):
    block_signals()
    try:
        stream.write(payload)
    except OSError:
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


_DEFER = {'on': False, 'pending': False, 'stopped': False}


def stop_now(number, frame):
    """SIGTERM, SIGHUP and SIGINT end a run like Ctrl-C. Only the first one raises: signals are blocked from then on, and
    one that was already waiting (CPython runs several tripped handlers back to back) or arrives later is ignored, so
    nothing can interrupt the cleanup, and the restore of handlers and mask after it, half way."""
    signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    if _DEFER['stopped']:
        return
    if _DEFER['on']:
        _DEFER['pending'] = True
        return
    _DEFER['stopped'] = True
    raise KeyboardInterrupt


@contextlib.contextmanager
def uninterruptible():
    """A stop that arrives inside is raised as KeyboardInterrupt only when the block ends, so a child started inside
    is always assigned (and so reaped by the cleanup) before the run can be interrupted. Main thread only. Residual:
    the block is as long as the fork and exec it covers; SIGKILL and a power loss are not stoppable at all."""
    _DEFER['on'] = True
    try:
        yield
    finally:
        _DEFER['on'] = False
        if _DEFER['pending']:
            _DEFER['pending'], _DEFER['stopped'] = False, True
            raise KeyboardInterrupt


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
        known = [option[len('UserKnownHostsFile='):] for option in base if option.startswith('UserKnownHostsFile=')]
        self.pinned = ((known[0], details['knownHostsSha256']), (base[4], details['adminPublicKeySha256']))
        # Copies: nothing edited in `details` after the checks above can reach a leg.
        self.argv, self.legs = list(base), json.loads(json.dumps(legs))

    def files_unchanged(self):
        """Known hosts and the identity file still hash to the approved, digest-bound values."""
        try:
            return all(hmac.compare_digest(FR.regular_file_sha256(path, 'pinned file'), approved)
                       for path, approved in self.pinned)
        except (Refusal, OSError):
            return False

    def run(self, payload, env, stdout_fd, stderr_fd, stdout_path, timeout):
        """Returns (leg-1 exit code, timed_out, {'legs': [...], 'ignoredMarkers': n, 'ack': ..., 'pinned': ...}).
        Always reaps everything, also on SIGTERM, SIGHUP and SIGINT."""
        if not self.files_unchanged():
            raise Refusal('known hosts or identity file differs from the approved plan: nothing was sent')
        self.results, self.ignored, self.active, self.pending, self.env = [], 0, None, None, env
        self.locked = self.cancelled = False
        self.ack, self.pinned_state = 'none', 'ok'
        # The mask is captured, and the signals blocked, BEFORE any handler is installed: a signal that arrives while the
        # handlers go in waits until supervise unblocks, inside its try, and the finally below restores mask and handlers.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        _DEFER.update(on=False, pending=False, stopped=False)
        saved = {}
        try:
            try:
                for number in SIGNALS:
                    saved[number] = signal.signal(number, stop_now)
            except ValueError:  # not the main thread: the caller owns signal handling
                pass
            return self.supervise(payload, stdout_fd, stderr_fd, stdout_path, timeout, mask)
        finally:
            for number, handler in saved.items():
                signal.signal(number, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def supervise(self, payload, stdout_fd, stderr_fd, stdout_path, timeout, mask):
        tail = process = feeder = None
        timed_out, aborted, begun = False, True, time.monotonic()
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)  # a signal that waited for the handlers is delivered here
            with uninterruptible():
                tail = Tail(stdout_path)
                process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=stdout_fd, stderr=stderr_fd,
                                           env=self.env, start_new_session=True)
                feeder = threading.Thread(target=feed, args=(process.stdin, payload), daemon=True)
                feeder.start()
            while True:
                now = time.monotonic()
                self.handle(tail.lines(), now)
                if process.poll() is not None:
                    break
                if now - begun > timeout:
                    timed_out = True
                    break
                time.sleep(POLL_SECONDS)
            aborted = False
            signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
            self.cleanup(process, feeder, tail, aborted)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)  # a signal that waited is delivered here
        return process.returncode, timed_out, {'legs': self.results, 'ignoredMarkers': self.ignored, 'ack': self.ack,
                                               'pinned': self.pinned_state}

    def cleanup(self, process, feeder, tail, aborted):
        if self.active:
            self.active.kill('aborted' if aborted else 'killed_leg1_ended', time.monotonic())
            self.results.append(self.active.result)
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        if feeder is not None:
            feeder.join(5)
        if tail is not None:
            tail.close()

    def handle(self, lines, now):
        """One poll: halts first (a marker in the same read never starts a leg), then the lines in order, then the leg."""
        if any(line.startswith('STOP ') or CANCEL.fullmatch(line) for line in lines):
            self.locked, self.pending = True, None
        for line in lines:
            if CANCEL.fullmatch(line) or line.startswith('STOP '):
                self.cancelled = self.cancelled or CANCEL.fullmatch(line) is not None
                if self.active:
                    self.active.kill('killed_on_cancel' if CANCEL.fullmatch(line) else 'killed_on_stop', now)
                    self.reap()
            elif ACK_FILE.fullmatch(line):
                self.acknowledge(ACK_FILE.fullmatch(line).group(1))
            elif MARKER.fullmatch(line):
                self.marker(*MARKER.fullmatch(line).groups(), now)
        if self.active:
            self.active.step(now)
            self.reap()
        if self.pending and not self.active and not self.locked:
            index, base = self.pending
            self.pending = None
            self.start(index, base, now)

    def reap(self):
        if self.active and self.active.result:
            self.results.append(self.active.result)
            self.active = None

    def acknowledge(self, path):
        """Only the first path, only after a CANCEL (not a bare STOP), only once every leg has ended."""
        if not (self.cancelled and not self.active and self.ack == 'none'):
            self.ignored += 1
        elif not self.files_unchanged():
            self.locked, self.ack, self.pinned_state = True, 'refused', 'changed'
        else:
            self.ack = send_ack(self.argv, path, self.env)

    def marker(self, leg, base, now):
        index = len(self.results) + (1 if self.active else 0)
        if self.locked or self.pending or index >= len(self.legs) or self.legs[index]['leg'] != leg:
            self.ignored += 1
        elif self.active:
            self.pending = (index, base)  # leg 1 was quicker than this leg's ssh closing: start it right after
        else:
            self.start(index, base, now)

    def start(self, index, base, now):
        if self.files_unchanged():
            with uninterruptible():
                self.active = Leg(self.legs[index], base, self.env, now)
        else:
            self.locked, self.pending, self.pinned_state = True, None, 'changed'
