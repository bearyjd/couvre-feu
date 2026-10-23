#!/usr/bin/env python3
"""Test-only stand-in for ssh. Never connects anywhere; fictional MACs and documentation IPs only.

Leg 1 (`-T`): prints the scripted lines of spec['leg1'] ([[delay, line], ...]) after draining stdin.
Leg 2 (`-tt`): refuses unless the pinned host-key options are present and stdin is a tty, then
  mode 'scripted': plays a cfctl-like prompt itself on its own tty (spec['leg2'] knobs below), or
  mode 'fixture': runs the translated remote command under its own pty (like a remote sshd would),
  bridging the tty both ways, so the repository's cfctl and cfctl-scope read a real typed confirmation.
Every call appends its argv (and, in scripted mode, what it received) to spec['log']; that is test data only.
"""
import json
import os
import pty
import re
import select
import shlex
import signal
import subprocess
import sys
import termios
import time
import tty

PROMPT = 'Type the last 6 hex digits of the address (no colons) to confirm: '
spec = json.load(open(os.environ['FAKE_SSH_SPEC']))
argv = sys.argv[1:]
with open(spec['log'], 'a') as log:
    log.write(json.dumps(argv) + '\n')


def record(**entry):
    with open(spec['leg2']['log'], 'a') as handle:
        handle.write(json.dumps(entry) + '\n')


def leg_one():
    sys.stdin.buffer.read()
    for delay, line, *newline in spec['leg1']:
        time.sleep(delay)
        sys.stdout.write(line + ('\n' if not newline or newline[0] else ''))
        sys.stdout.flush()
    sys.exit(spec.get('leg1_exit', 0))


def pinned():
    options = [argv[i + 1] for i, item in enumerate(argv[:-1]) if item == '-o']
    return ('StrictHostKeyChecking=yes' in options and 'BatchMode=yes' in options
            and not [o for o in options if o.startswith('StrictHostKeyChecking=') and o != 'StrictHostKeyChecking=yes']
            and not [o for o in options if o.startswith('UserKnownHostsFile=') and o.endswith('/dev/null')])


def scripted(cfg, command):
    match = re.search(r'(scope-(?:add|remove)) ((?:[0-9a-f]{2}:){5}[0-9a-f]{2}) --base ([0-9a-f]{64})', command)
    if not match:
        sys.exit(2)
    op, mac, base = match.groups()
    if cfg.get('child'):
        child = subprocess.Popen(['sleep', '300'])
        open(cfg['child'], 'w').write(str(child.pid))
    if cfg.get('ignore_term'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if cfg.get('raw'):
        tty.setraw(0)  # no output post-processing: bare LF line ends, like a raw-mode ssh
    if not cfg.get('echo', True):
        attrs = termios.tcgetattr(0)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, attrs)
    time.sleep(cfg.get('delay', 0))
    if cfg.get('stderr_line'):
        sys.stderr.write(cfg['stderr_line'] + '\n')  # the local client's own warning (it names the router)
        sys.stderr.flush()
    for line in cfg.get('before', []):
        print(line.replace('{mac}', mac), flush=True)
    text = cfg.get('prompt_text') or '%s %s --base %s\n%s' % (op, mac, base, PROMPT)
    sys.stdout.write(text)
    sys.stdout.flush()
    if cfg.get('hang_before_read'):
        time.sleep(300)
    answer = sys.stdin.readline().rstrip('\r\n')
    record(received=answer, op=op, base=base)
    if cfg.get('hang_after_read'):
        time.sleep(300)
    print()
    ok = answer == mac.replace(':', '')[-6:]
    print(json.dumps({'ok': True, 'mac': mac} if ok else {'ok': False, 'errors': ['scope_confirmation_mismatch']}),
          flush=True)
    time.sleep(cfg.get('linger', 0))  # the ssh client is slow to close the channel after the remote is done
    sys.exit(0 if ok else 1)


def translate(command):
    cfctl = ' '.join(shlex.split(spec.get('shell', 'sh')) + [spec['cfctl']])
    wrapper = ' '.join(shlex.split(spec.get('shell', 'sh')) + [spec['leg2']['wrapper_scope']])
    return command.replace('/usr/sbin/cfctl-scope', wrapper).replace('/usr/sbin/cfctl', cfctl)


def bridge(cfg, command):  # noqa: C901
    env = dict(spec['env'], SSH_CONNECTION=spec['ssh_connection'])
    env.pop('SSH_ORIGINAL_COMMAND', None)
    pid, master = pty.fork()
    if pid == 0:
        os.execvpe('/bin/sh', ['sh', '-c', translate(command)], env)
    tty.setraw(0)
    wrong = cfg.get('wrong_digits_match') and re.search(cfg['wrong_digits_match'], command)
    while True:
        ready, _, _ = select.select([0, master], [], [], 1)
        try:
            if 0 in ready:
                data = os.read(0, 4096)
                if not data:
                    break
                if wrong and re.fullmatch(rb'[0-9a-f]{6}\r?\n', data):
                    data = b'000000\n'
                os.write(master, data)
            if master in ready:
                data = os.read(master, 4096)
                if not data:
                    break
                os.write(1, data)
        except OSError:
            break
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))


def leg_two():
    cfg = spec['leg2']
    if not pinned() or not os.isatty(0):
        sys.exit(255)
    command = argv[-1]
    if cfg.get('exit255') or (cfg.get('exit255_match') and re.search(cfg['exit255_match'], command)):
        sys.exit(255)
    if cfg['mode'] == 'scripted':
        scripted(cfg, command)
    bridge(cfg, command)


if '-tt' in argv:
    leg_two()
elif '-T' in argv:
    leg_one()
sys.exit(2)
