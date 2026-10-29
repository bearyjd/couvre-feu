#!/usr/bin/env python3
"""Leg-2 pty driver fixtures (T4). The driver runs against tests/fake-leg-ssh.py, never a real ssh.

Fast layer: the driver is called directly with a real v2 plan, a scripted leg 1 and a scripted leg 2 that plays a
cfctl-like prompt on its own tty. Fictional MACs and documentation IPs only. What a real router, the router's ssh
daemon and OpenSSH's own pty handling do is not exercised here.

Timing: no test depends on a sleep racing a leg. Leg 1 waits for an event the fake ssh records (or for the leg's child
to be gone) and then lingers AFTER seconds, so every assertion keeps at least that much slack.
"""
import ast
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import termios
import time
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / 'tests'))
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location('test_penn_pilot', REPO / 'tests/test-penn-pilot.py')
PP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PP)
PHONE = PP.PHONE
HELPER = REPO / 'tests/fake-leg-ssh.py'
BASE = 'ab' * 32
BASE2 = 'cd' * 32
PROMPT = 'Type the last 6 hex digits of the address (no colons) to confirm: '
LEG_KEYS = {'leg', 'form', 'op', 'outcome', 'exit', 'ok', 'errors', 'confirmationSent', 'bytes', 'stderrBytes', 'seconds'}
LEG_SECONDS = 5
AFTER = 2.0
BOUND = 'timeout -s KILL %d timeout -s TERM %d ' % (LEG_SECONDS + 15, LEG_SECONDS)
ACK_PATH = '/tmp/couvre-feu-first.Ab3dEf/leg2-idle'
# One blocking write of 8 MiB keeps the channel full until the consumer has taken all of it: a read loop that has no
# per-step bound cannot catch up with such a producer and never returns.
FLOODS = {'pty': "import os\nos.write(1, b'x' * (8 << 20))\n", 'stderr': "import os\nos.write(2, b'y' * (8 << 20))\n"}


def setUpModule():
    PP.setUpModule()


def tearDownModule():
    PP.tearDownModule()


def settled(count=1):
    """Leg 1 lines: wait until `count` legs have exited, then end."""
    return [[0, f'@wait exit {count}'], [AFTER, 'PHASE X OK']]


def gone():
    """Leg 1 lines: wait until the driver killed the leg (its child is gone), then end. Needs the `child` knob."""
    return [[0, '@wait dead'], [AFTER, 'END']]


def marker(leg='2a', base=BASE):
    return [0.2, f'CFP_LEG2_READY {leg} {base}']


def open_fds():
    return sorted(int(name) for name in os.listdir('/proc/self/fd'))


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open(f'/proc/{pid}/stat') as handle:
            return handle.read().rsplit(') ', 1)[1][0] != 'Z'
    except OSError:
        return False


def wait_dead(pid, seconds=10):
    deadline = time.monotonic() + seconds
    while alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not alive(pid)


def mac_pattern(mac):
    return re.compile(r'(?<![0-9a-f])(%s|%s)(?![0-9a-f])' % (re.escape(mac), mac.replace(':', '')[-6:]))


class Alarm:
    """Fail (instead of hang) a test that exercises an unbounded loop."""

    def __init__(self, seconds):
        self.seconds = seconds

    def __enter__(self):
        def fire(*_):
            raise AssertionError(f'still running after {self.seconds} s (unbounded loop?)')
        self.old = signal.signal(signal.SIGALRM, fire)
        signal.alarm(self.seconds)

    def __exit__(self, *_):
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self.old)


class DriverBase(PP.PilotShellBase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(self.tool.V2, 'SCOPE_LEG_SECONDS', LEG_SECONDS)
        patcher.start()
        self.addCleanup(patcher.stop)
        shim = self.bin / 'ssh'
        shim.write_text(f'#!/bin/sh\nexec {sys.executable} -B {HELPER} "$@"\n')
        shim.chmod(0o700)
        self.legs_log, self.events_log = self.work / 'legs.jsonl', self.work / 'events.jsonl'
        self.pidfile, self.leg1_pid = self.work / 'child.pid', self.work / 'leg1.pid'
        self.config_path = self.write_config(**self.v2_changes())
        self.details = self.plan_details(self.config_path)
        self.sha = self.details['planSha256']
        self.env = {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'], 'FAKE_SSH_SPEC': str(self.spec_path),
                    'HOME': str(self.work), 'LC_ALL': 'C'}

    def spec_for(self, leg1, **leg2):
        for stale in (self.pidfile, self.events_log):
            stale.unlink(missing_ok=True)
        leg2 = dict({'mode': 'scripted', 'log': str(self.legs_log), 'events': str(self.events_log)}, **leg2)
        self.spec.update(leg1=leg1, leg2=leg2, leg1_pid=str(self.leg1_pid))
        self.spec_path.write_text(json.dumps(self.spec))

    def driver(self, details=None, sha=None):
        return self.tool.LEG2.Driver(details or self.details, sha or self.sha, self.tool.plan_digest)

    def run_driver(self, driver, timeout=30):
        out_path = self.work / 'stdout.log'
        out_fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        err_fd = os.open(self.work / 'stderr.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            self.started = time.monotonic()
            self.outcome = driver.run(b'payload\n', self.env, out_fd, err_fd, out_path, timeout)
            self.elapsed = time.monotonic() - self.started
        finally:
            os.close(out_fd)
            os.close(err_fd)
        return self.outcome

    def drive(self, leg1, details=None, sha=None, timeout=30, **leg2):
        self.spec_for(leg1, **leg2)
        return self.run_driver(self.driver(details, sha), timeout)

    def ssh_calls(self):
        return [json.loads(line) for line in self.ssh_log.read_text().splitlines()] if self.ssh_log.exists() else []

    def leg_calls(self):
        return [call for call in self.ssh_calls() if '-tt' in call]

    def ack_calls(self):
        return [call for call in self.ssh_calls() if '-tt' not in call and 'leg2-idle' in call[-1]]

    def received(self):
        if not self.legs_log.exists():
            return []
        return [json.loads(line) for line in self.legs_log.read_text().splitlines()]

    def event_times(self, name):
        lines = [json.loads(line) for line in self.events_log.read_text().splitlines()]
        return [entry['t'] for entry in lines if entry['event'] == name]

    def legs(self):
        return self.outcome[2]['legs']

    def resign(self, details):
        return dict(details, planSha256=self.tool.plan_digest(details))

    def command(self, leg, base=BASE):
        return self.details['legs'][leg]['commandTemplate'].replace('{MAC}', PHONE['mac']).replace('{BASE}', base)

    def child_dead(self):
        self.assertTrue(wait_dead(int(self.pidfile.read_text())))



class DriverTests(DriverBase):
    def test_marker_starts_a_leg_with_the_digest_bound_argv_and_types_only_the_last_six_digits(self):
        rc, timed_out, results = self.drive([marker(base=BASE)] + settled())
        self.assertEqual((rc, timed_out), (0, False))
        (leg,) = results['legs']
        self.assertEqual(set(leg), LEG_KEYS)
        self.assertEqual((leg['leg'], leg['outcome'], leg['exit'], leg['ok'], leg['confirmationSent']),
                         ('2a', 'exited', 0, True, True))
        self.assertEqual([entry.get('received') for entry in self.received()], [PHONE['mac'].replace(':', '')[-6:]])
        (call,) = self.leg_calls()
        planned = self.details['legs'][0]['sshArgv']
        self.assertEqual(call[:-1], planned[1:-1])
        self.assertEqual(call[-1], self.command(0))
        self.assertNotIn('-T', call)
        self.assertEqual(len(self.ssh_calls()), 2)

    def test_all_four_legs_run_once_each_in_order_with_their_own_bounded_command(self):
        script = [marker('2a', BASE)]
        for index, (leg, base) in enumerate((('2b', BASE2), ('2c', BASE), ('2d', BASE2)), 1):
            script += [[0, f'@wait exit {index}'], [0.5, f'CFP_LEG2_READY {leg} {base}']]
        self.drive(script + settled(4))
        self.assertEqual([(leg['leg'], leg['outcome']) for leg in self.legs()], [(l, 'exited') for l in ('2a', '2b', '2c', '2d')])
        commands = [call[-1] for call in self.leg_calls()]
        mac = PHONE['mac']
        self.assertEqual(commands, [self.command(0), self.command(1, BASE2), self.command(2), self.command(3, BASE2)])

    def test_a_leg_never_starts_without_a_valid_marker_line(self):
        bad = [f'CFP_LEG2_READY 2a {"g" * 64}', f' CFP_LEG2_READY 2a {BASE}', f'CFP_LEG2_READY 2a {BASE[:-1]}',
               f'CFP_LEG2_READY 2a {BASE.upper()}', f'CFP_LEG2_READY 2e {BASE}', f'CFP_LEG2_READY 2a {BASE} x',
               f'XCFP_LEG2_READY 2a {BASE}', f'CFP_LEG2_READY  2a {BASE}', 'CFP_LEG2_READY', 'CFP_LEG2_CANCEL 2a',
               f'INFO CFP_LEG2_READY 2a {BASE}']
        self.drive([[0.1, line] for line in bad] + [[0.1, f'CFP_LEG2_READY 2a {BASE}', False], [1.0, 'PHASE X OK']])
        # The only well-formed one is an unterminated line: it is not a marker yet, and leg 1 ends before it is.
        self.assertEqual(self.legs(), [])
        self.assertEqual(self.leg_calls(), [])
        self.assertEqual(len(self.ssh_calls()), 1)

    def test_a_marker_that_arrives_while_the_previous_leg_is_still_closing_is_held_not_lost(self):
        # Leg 1 re-reads the router and prints the next marker as soon as the scope changed; the previous leg's ssh may
        # not have exited yet. Dropping that marker would stall leg 1 for 60 s and stop the gate.
        self.drive([marker(), [0, '@wait reply 1'], [0, f'CFP_LEG2_READY 2b {BASE2}']] + settled(2), linger=3.0)
        self.assertEqual([(leg['leg'], leg['outcome'], leg['ok']) for leg in self.legs()],
                         [('2a', 'exited', True), ('2b', 'exited', True)])
        self.assertEqual(self.outcome[2]['ignoredMarkers'], 0)
        self.assertEqual(self.leg_calls()[1][-1], self.command(1, BASE2))

    def test_never_two_legs_at_once_a_held_marker_starts_only_after_the_previous_leg_exited(self):
        self.drive([marker(), [0, '@wait reply 1'], [0, f'CFP_LEG2_READY 2b {BASE2}']] + settled(2), linger=3.0)
        starts, exits = self.event_times('launch'), self.event_times('exit')
        self.assertEqual((len(starts), len(exits)), (2, 2))
        self.assertGreaterEqual(starts[1], exits[0])

    def test_a_held_marker_is_dropped_by_stop_cancel_and_the_end_of_leg_one(self):
        for name, third in (('stop', 'STOP SCOPE-ADD-1 x'), ('cancel', 'CFP_LEG2_CANCEL 2a')):
            with self.subTest(name):
                self.ssh_log.unlink(missing_ok=True)
                self.drive([marker(), [0, '@wait reply 1'], [0, f'CFP_LEG2_READY 2b {BASE}'], [0.3, third], [AFTER, 'END']],
                           linger=3.0)
                self.assertEqual(len(self.leg_calls()), 1, name)
        self.ssh_log.unlink(missing_ok=True)
        self.drive([marker(), [0, '@wait reply 1'], [0, f'CFP_LEG2_READY 2b {BASE}'], [0.3, 'END']], linger=3.0)
        self.assertEqual(len(self.leg_calls()), 1)
        self.assertEqual([leg['leg'] for leg in self.legs()], ['2a'])

    def test_the_local_clients_own_stderr_is_neither_matched_nor_kept(self):
        self.drive([marker()] + settled(), stderr_line='Connection to 192.0.2.1 closed.')
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['ok']), ('exited', True))
        self.assertGreater(leg['stderrBytes'], 0)
        self.assertNotIn('192.0.2.1', json.dumps(self.outcome[2]))

    def test_a_marker_for_another_leg_or_a_repeat_is_ignored_and_counted(self):
        self.drive([marker('2b'), [0.2, f'CFP_LEG2_READY 2a {BASE}'], [0, '@wait exit 1'], [0.5, f'CFP_LEG2_READY 2a {BASE}']]
                   + settled())
        self.assertEqual([leg['leg'] for leg in self.legs()], ['2a'])
        self.assertEqual(len(self.leg_calls()), 1)
        self.assertGreaterEqual(self.outcome[2]['ignoredMarkers'], 2)

    def test_a_prompt_that_is_not_exactly_the_expected_text_is_refused_and_nothing_is_typed(self):
        mac = PHONE['mac']
        wrong = {'other wording': {'prompt_text': f'scope-add {mac} --base {BASE}\nType the last 4 hex digits to confirm: '},
                 'different mac': {'prompt_text': f'scope-add 02:00:00:00:00:35 --base {BASE}\n{PROMPT}'},
                 'different base': {'prompt_text': f'scope-add {mac} --base {BASE2}\n{PROMPT}'},
                 'different op': {'prompt_text': f'scope-remove {mac} --base {BASE}\n{PROMPT}'},
                 'banner first': {'before': ['Welcome to {mac}']}}
        for name, knobs in wrong.items():
            with self.subTest(name):
                self.legs_log.unlink(missing_ok=True)
                self.drive([marker()] + gone(), child=str(self.pidfile), **knobs)
                (leg,) = self.legs()
                self.assertEqual(leg['outcome'], 'prompt_mismatch', name)
                self.assertFalse(leg['confirmationSent'], name)
                self.assertEqual(self.received(), [], name)

    def test_a_prompt_cut_short_is_never_answered_and_ends_at_the_deadline(self):
        mac = PHONE['mac']
        self.drive([marker()] + gone(), child=str(self.pidfile),
                   prompt_text=f'scope-add {mac} --base {BASE}\n{PROMPT.rstrip()}')
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['confirmationSent']), ('timeout', False))
        self.assertEqual(self.received(), [])

    def test_text_after_the_prompt_in_the_buffer_is_never_answered(self):
        # Deterministic: the buffer is set directly, so this does not depend on how the pty splits or joins reads.
        Leg = self.tool.LEG2.Leg
        expected = f'scope-add {PHONE["mac"]} --base {BASE}\n{PROMPT}'
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        for name, buffer, typed in (('trailing text', expected + 'yes', False), ('prefix only', expected[:-1], False),
                                    ('exact', expected, True)):
            with self.subTest(name):
                leg = Leg.__new__(Leg)
                leg.expected, leg.digits, leg.master, leg.sent = expected, '000034', master, False
                leg.buffer = buffer.replace('\n', '\r\n').encode()
                self.assertEqual(leg.check_prompt(), name != 'trailing text')
                self.assertEqual(leg.sent, typed)
        self.assertEqual(os.read(slave, 100), b'000034\n')
        self.assertFalse(select.select([slave], [], [], 0.2)[0])

    def test_silence_instead_of_a_prompt_is_never_answered(self):
        self.drive([marker()] + gone(), delay=60, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['confirmationSent']), ('timeout', False))
        self.assertEqual(self.received(), [])

    def test_crlf_and_bare_lf_line_ends_both_match(self):
        # The scripted tty is cooked (the prompt arrives with CRLF); `raw` turns post-processing off (bare LF).
        for knobs in ({}, {'raw': True}):
            with self.subTest(knobs):
                self.drive([marker()] + settled(), **knobs)
                self.assertEqual([(leg['outcome'], leg['ok']) for leg in self.legs()], [('exited', True)])

    def test_a_flood_before_the_prompt_is_capped_and_refused(self):
        self.drive([marker()] + gone(), before=['x' * 200] * 200, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['confirmationSent']), ('prompt_mismatch', False))
        self.assertEqual(self.received(), [])

    def test_one_read_of_a_flooding_leg_is_bounded_so_stderr_and_pty_cannot_starve_the_loop(self):
        for channel, code in FLOODS.items():
            with self.subTest(channel):
                entry = dict(self.details['legs'][0], sshArgv=[sys.executable, '-B', '-c', code, 'x'], timeoutSeconds=30)
                leg = self.tool.LEG2.Leg(entry, BASE, dict(os.environ), time.monotonic())
                self.addCleanup(leg.kill, 'test', time.monotonic())
                time.sleep(0.5)  # the channel is full and the producer is waiting
                with Alarm(30):
                    started = time.monotonic()
                    leg.read()
                self.assertLessEqual(leg.total, 128 * 1024)
                self.assertLessEqual(leg.stderr_bytes, 128 * 1024)
                self.assertLess(time.monotonic() - started, 5)

    def test_a_flooding_leg_still_hits_its_deadline_and_the_stop_line(self):
        for name, script in (('deadline', [marker()] + gone()), ('stop', [marker(), [0, '@wait reply 1'], [0, 'STOP A b']] + gone())):
            with self.subTest(name), Alarm(60):
                self.drive(script, flood=True, child=str(self.pidfile))
                (leg,) = self.legs()
                self.assertEqual(leg['outcome'], 'timeout' if name == 'deadline' else 'killed_on_stop')
                self.assertLess(self.elapsed, LEG_SECONDS + AFTER + 8)

    def test_a_wrong_confirmation_is_reported_as_a_refused_leg_not_an_ok_one(self):
        with mock.patch.object(self.tool.LEG2, 'confirmation_digits', lambda mac: '999999'):
            self.drive([marker()] + settled())
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['ok'], leg['errors'], leg['exit']), ('exited', False, ['scope_confirmation_mismatch'], 1))

    def test_the_confirmation_digits_are_the_last_six_hex_of_the_target_mac(self):
        digits = self.tool.LEG2.confirmation_digits
        self.assertEqual(digits('02:00:00:00:00:34'), '000034')
        self.assertEqual(digits('02:00:00:00:00:5f'), '00005f')
        self.assertEqual(digits('02:00:00:00:00:ab'), '0000ab')

    def test_a_leg_that_hangs_is_killed_at_the_deadline_with_its_children_and_never_retried(self):
        self.drive([marker()] + gone(), hang_after_read=True, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'timeout')
        self.assertTrue(leg['confirmationSent'])
        self.child_dead()
        self.assertEqual(len(self.leg_calls()), 1)

    def test_the_deadline_comes_from_the_digest_bound_plan(self):
        self.assertTrue(all(leg['timeoutSeconds'] == LEG_SECONDS for leg in self.details['legs']))
        self.drive([marker()] + gone(), hang_after_read=True, child=str(self.pidfile))
        self.assertEqual(self.legs()[0]['outcome'], 'timeout')
        self.assertGreaterEqual(self.legs()[0]['seconds'], LEG_SECONDS)
        self.assertLessEqual(self.legs()[0]['seconds'], LEG_SECONDS + 4)

    def test_a_failed_leg_is_never_retried(self):
        self.drive([marker()] + settled(), exit255=True)
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['exit'], leg['ok']), ('exited', 255, False))
        self.assertEqual(len(self.leg_calls()), 1)

    def test_a_failed_leg_is_not_retried_when_leg_one_repeats_its_marker(self):
        # Only the next planned leg may ever start: a failed 2a is over, whatever leg 1 prints afterwards.
        self.drive([marker(), [0, '@wait exit 1'], [0.3, f'CFP_LEG2_READY 2a {BASE}'], [0.3, f'CFP_LEG2_READY 2a {BASE2}']]
                   + settled(), exit255=True)
        (leg,) = self.legs()
        self.assertEqual((leg['leg'], leg['outcome'], leg['exit'], leg['ok']), ('2a', 'exited', 255, False))
        self.assertEqual(len(self.leg_calls()), 1)
        self.assertGreaterEqual(self.outcome[2]['ignoredMarkers'], 2)

    def test_a_refused_leg_is_never_retried(self):
        with mock.patch.object(self.tool.LEG2, 'confirmation_digits', lambda mac: '999999'):
            self.drive([marker()] + settled())
        self.assertEqual(len(self.leg_calls()), 1)

    def test_a_stop_line_kills_the_running_leg_and_its_children(self):
        self.drive([marker(), [0, '@wait read 1'], [0, 'STOP SCOPE-ADD-1 scope_leg_timeout']] + gone(),
                   hang_after_read=True, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'killed_on_stop')
        self.child_dead()
        self.assertLess(leg['seconds'], LEG_SECONDS)

    def test_no_leg_starts_after_a_stop_even_with_a_marker_in_the_same_read(self):
        self.drive([[0.2, 'STOP SCOPE-ADD-1 x'], [0, f'CFP_LEG2_READY 2a {BASE}'], [1.0, 'PHASE UNINSTALL OK']])
        self.assertEqual(self.legs(), [])
        self.drive([[0.2, 'STOP SCOPE-ADD-1 x'], [0.8, 'PHASE UNINSTALL OK'], [0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.8, 'END']])
        self.assertEqual(self.legs(), [])
        self.assertEqual(self.leg_calls(), [])

    def test_a_cancel_marker_ends_the_running_leg_and_blocks_later_ones(self):
        self.drive([marker(), [0, '@wait read 1'], [0, 'CFP_LEG2_CANCEL 2a'], [0.5, f'CFP_LEG2_READY 2b {BASE}']] + gone(),
                   hang_after_read=True, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'killed_on_cancel')
        self.child_dead()
        self.assertEqual(len(self.leg_calls()), 1)

    def test_the_whole_process_group_is_killed_when_the_leg_exits_normally_too(self):
        self.drive([marker()] + settled(), child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['ok']), ('exited', True))
        self.child_dead()

    def test_a_cancel_before_any_marker_blocks_the_leg(self):
        self.drive([[0.2, 'CFP_LEG2_CANCEL 2a'], [0, f'CFP_LEG2_READY 2a {BASE}'], [1.0, 'END']])
        self.assertEqual(self.legs(), [])

    def test_a_leg_does_not_outlive_leg_one(self):
        self.drive([marker(), [0, '@wait start 1'], [0.3, 'PHASE X OK']], hang_after_read=True, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'killed_leg1_ended')
        self.child_dead()

    def test_the_local_timeout_kills_leg_one_and_the_leg(self):
        rc, timed_out, results = self.drive([marker(), [30, 'never']], timeout=4, hang_after_read=True,
                                            child=str(self.pidfile))
        self.assertTrue(timed_out)
        self.assertEqual(results['legs'][0]['outcome'], 'killed_leg1_ended')
        self.child_dead()
        self.assertLess(self.elapsed, 4 + 4)


class AckTests(DriverBase):
    def cancel_then(self, *lines, **knobs):
        return self.drive([marker(), [0, '@wait read 1'], [0, 'CFP_LEG2_CANCEL 2a'], *[[0.2, line] for line in lines],
                           [AFTER, 'PHASE UNINSTALL OK']], hang_after_read=True, **knobs)

    def test_ack_is_written_over_a_pinned_ssh_only_after_the_cancelled_leg_is_dead(self):
        self.cancel_then(f'CFP_LEG2_ACK_FILE {ACK_PATH}', f'CFP_LEG2_ACK_FILE {ACK_PATH}')
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'killed_on_cancel')
        self.assertEqual(self.outcome[2]['ack'], 'sent')
        (call,) = self.ack_calls()
        self.assertIn(ACK_PATH, call[-1])
        self.assertIn('set -C', call[-1])
        self.assertEqual(call[:-1], self.details['sshArgv'][1:-1])
        self.assertIn('StrictHostKeyChecking=yes', call)

    def test_ack_without_a_cancel_or_with_a_foreign_path_is_ignored(self):
        self.drive([[0.2, f'CFP_LEG2_ACK_FILE {ACK_PATH}'], [0.2, 'CFP_LEG2_CANCEL 2a'],
                    [0, 'CFP_LEG2_ACK_FILE /etc/hosts'], [0, 'CFP_LEG2_ACK_FILE /tmp/couvre-feu-first.Ab3dEf/../x/leg2-idle'],
                    [0.5, 'END']])
        self.assertEqual(self.ack_calls(), [])
        self.assertEqual(self.outcome[2]['ack'], 'none')
        self.assertEqual(self.outcome[2]['ignoredMarkers'], 1)

    def test_a_bare_stop_does_not_enable_the_ack_only_a_cancel_does(self):
        self.drive([marker(), [0, '@wait read 1'], [0, 'STOP SCOPE-ADD-1 x'], [0.2, f'CFP_LEG2_ACK_FILE {ACK_PATH}'],
                    [AFTER, 'END']], hang_after_read=True)
        self.assertEqual((self.ack_calls(), self.outcome[2]['ack'], self.outcome[2]['ignoredMarkers']), ([], 'none', 1))
        self.cancel_then(f'CFP_LEG2_ACK_FILE {ACK_PATH}')
        self.assertEqual((len(self.ack_calls()), self.outcome[2]['ack']), (1, 'sent'))

    def test_only_the_first_ack_path_is_ever_written_even_when_it_fails(self):
        other = '/tmp/couvre-feu-first.Zz9Zz9/leg2-idle'
        self.spec.update(ack={'fail': True})
        self.cancel_then(f'CFP_LEG2_ACK_FILE {ACK_PATH}', f'CFP_LEG2_ACK_FILE {other}')
        self.assertEqual([call[-1].count(other) for call in self.ack_calls()], [0])
        self.assertEqual((len(self.ack_calls()), self.outcome[2]['ack'], self.outcome[2]['ignoredMarkers']), (1, 'failed', 1))

    def test_ack_with_no_running_leg_and_failed_or_hung_ssh_is_reported_not_fatal(self):
        patcher = mock.patch.object(self.tool.LEG2, 'ACK_SECONDS', 1)
        patcher.start()
        self.addCleanup(patcher.stop)
        for knob in ({'fail': True}, {'hang': True}):
            self.spec.update(ack=knob)
            rc, timed_out, results = self.drive([[0.2, 'CFP_LEG2_CANCEL 2a'], [0, f'CFP_LEG2_ACK_FILE {ACK_PATH}'], [0.3, 'END']])
            self.assertEqual((rc, timed_out, results['ack']), (0, False, 'failed'))


class HygieneTests(DriverBase):
    def test_descriptors_processes_and_the_terminal_are_clean_on_every_path(self):
        child = {'child': str(self.pidfile)}
        scenarios = {
            'ok': ([marker()] + settled(), {}),
            'timeout': ([marker()] + gone(), dict(child, hang_after_read=True)),
            'stop': ([marker(), [0, '@wait read 1'], [0, 'STOP A b']] + gone(), dict(child, hang_after_read=True)),
            'cancel': ([marker(), [0, '@wait read 1'], [0, 'CFP_LEG2_CANCEL 2a']] + gone(), dict(child, hang_after_read=True)),
            'leg1 ends': ([marker(), [0, '@wait read 1'], [0.1, 'END']], {'hang_after_read': True}),
            'mismatch': ([marker()] + gone(), dict(child, prompt_text='nope: ')),
            'spawn failure': ([marker()] + settled(), {'exit255': True}),
            'no marker': ([[0.2, 'END']], {})}
        # fd 0 may be closed when this runs (a daemonised runner): remember that instead of assuming it is open.
        try:
            saved = os.dup(0)
        except OSError:
            saved = None
        master, slave = os.openpty()
        os.dup2(slave, 0)
        before_attrs = termios.tcgetattr(0)
        try:
            for name, (script, knobs) in scenarios.items():
                with self.subTest(name):
                    before = open_fds()
                    self.drive(script, **knobs)
                    self.assertEqual(open_fds(), before, name)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(-1, os.WNOHANG)
                    self.assertEqual(termios.tcgetattr(0), before_attrs, name)
        finally:
            if saved is None:
                os.close(0)
            else:
                os.dup2(saved, 0)
                os.close(saved)
            os.close(master)
            os.close(slave)

    def test_descriptors_are_closed_when_the_run_is_interrupted(self):
        before = open_fds()
        self.spec_for([marker(), [20, 'END']], hang_after_read=True, child=str(self.pidfile))
        driver = self.driver()
        out = self.work / 'stdout.log'
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        original = time.sleep
        calls = []

        def interrupt(seconds):
            calls.append(seconds)
            if len(calls) > 30 and self.pidfile.exists():
                raise KeyboardInterrupt
            original(seconds)

        try:
            with mock.patch.object(self.tool.LEG2.time, 'sleep', interrupt), self.assertRaises(KeyboardInterrupt):
                driver.run(b'x\n', self.env, fd, fd, out, 30)
        finally:
            os.close(fd)
        self.child_dead()
        self.assertEqual(open_fds(), before)
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)

    def test_nothing_leaks_when_leg_one_cannot_even_be_started(self):
        before = open_fds()
        driver = self.driver()
        driver.argv = ['/nonexistent/ssh'] + driver.argv[1:]
        self.spec_for([[0.1, 'x']])
        with self.assertRaises(OSError):
            self.run_driver(driver)
        self.assertEqual(open_fds(), before)


class EvidenceTests(DriverBase):
    def test_nothing_the_driver_returns_or_prints_holds_the_confirmation_or_a_raw_mac(self):
        import contextlib
        import io
        sentinel = mac_pattern(PHONE['mac'])
        for knobs in ({}, {'echo': True, 'before': ['seen {mac} at 192.0.2.34']}, {'prompt_text': 'x {mac} ' + PHONE['mac'] + ': '}):
            with self.subTest(knobs):
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                    self.drive([marker()] + gone(), child=str(self.pidfile), **knobs)
                text = json.dumps(self.outcome[2]) + captured.getvalue()
                self.assertIsNone(sentinel.search(text), text)
                self.assertNotIn('192.0.2.34', text)
                self.assertNotIn(PHONE['mac'].replace(':', ''), text)
                for leg in self.legs():
                    self.assertEqual(set(leg), LEG_KEYS)
                    self.assertTrue(all(re.fullmatch(r'[a-z0-9_]{1,64}', code) for code in leg['errors']))


class StaticTests(unittest.TestCase):
    def test_the_driver_module_is_standalone_stdlib_and_never_weakens_ssh(self):
        path = REPO / 'tools/live/penn_pilot_leg2.py'
        code = ("import importlib.util, sys; sys.dont_write_bytecode = True; "
                "spec = importlib.util.spec_from_file_location('l2', sys.argv[1]); m = importlib.util.module_from_spec(spec); "
                "spec.loader.exec_module(m); print(m.FR is None, callable(m.bind))")
        done = subprocess.run([sys.executable, '-B', '-I', '-c', code, str(path)], capture_output=True, text=True, check=False)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, 'True True'), done.stderr)
        text = path.read_text()
        self.assertNotIn('noqa: F821', text)
        self.assertLessEqual(len(text.splitlines()), 520)  # leg + ack + pinning + signals + deferral; the project cap is 800
        self.assertIsNone(re.search(r'authorized_keys|dropbear|passwd|shadow|password|PasswordAuth|sshd', text, re.I))
        for source in ((REPO / 'tools/live/penn-pilot.py').read_text(), (REPO / 'tools/live/penn_pilot_v2.py').read_text()):
            self.assertIsNone(re.search(r'StrictHostKeyChecking=(no|accept-new|off)|UserKnownHostsFile=/dev/null|CheckHostIP', source))
        self.assertIsNone(re.search(r'StrictHostKeyChecking=(no|accept-new|off)|CheckHostIP', text))
        self.assertLessEqual(len((REPO / 'tools/live/penn-pilot.py').read_text().splitlines()), 800)
        imports = set(re.findall(r'(?m)^(?:import|from) ([a-z_]+)', text))
        self.assertLessEqual(imports, {'contextlib', 'hmac', 'json', 'os', 'pty', 're', 'select', 'signal', 'subprocess', 'threading', 'time',
                                       'typing', 'hashlib', 'shlex', 'termios'})

    def test_every_function_in_the_driver_is_at_most_fifty_lines(self):
        tree = ast.parse((REPO / 'tools/live/penn_pilot_leg2.py').read_text())
        long = [(node.name, node.end_lineno - node.lineno + 1) for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.end_lineno - node.lineno + 1 > 50]
        self.assertEqual(long, [])

    def test_the_driver_is_wired_and_the_flag_is_true(self):
        text = (REPO / 'tools/live/penn-pilot.py').read_text()
        self.assertIn('LEG2_DRIVER_IMPLEMENTED = True', text)
        self.assertNotIn('leg-2 pty driver absent', text)
        self.assertIn('driver.run(payload, env, stdout_fd, stderr_fd', text)

    def test_this_suite_is_registered_wherever_suites_are_listed(self):
        spec = importlib.util.spec_from_file_location('run_fixtures', REPO / 'tests/run-fixtures.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        matrix = re.search(r'suite: \[([^\]]+)\]', (REPO / '.github/workflows/ci.yml').read_text())
        self.assertEqual(tuple(name.strip() for name in matrix.group(1).split(',')), runner.SUITES)
        self.assertLessEqual({'test-penn-pilot-leg2.py', 'test-penn-pilot-leg2-guards.py'}, set(runner.SUITES))
        ci = (REPO / '.github/workflows/ci.yml').read_text()
        shards = sum(runner.PARTITION_COUNTS.get(name, runner.DEFAULT_PARTITIONS) for name in runner.SUITES)
        self.assertIn(f'all {shards} unique partitions', ci)
        self.assertIn(f'({shards} shards)', (REPO / 'docs/CONTRIBUTING.md').read_text())

    def test_a_version_one_summary_has_no_legs_key(self):
        text = (REPO / 'tools/live/penn-pilot.py').read_text()
        self.assertIsNone(re.search(r"'legs': leg_report", text))


if __name__ == '__main__':
    unittest.main()
