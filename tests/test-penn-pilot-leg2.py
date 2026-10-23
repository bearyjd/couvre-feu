#!/usr/bin/env python3
"""Leg-2 pty driver fixtures (T4). The driver runs against tests/fake-leg-ssh.py, never a real ssh.

Fast layer: the driver is called directly with a real v2 plan, a scripted leg 1 and a scripted leg 2 that plays a
cfctl-like prompt on its own tty. Fictional MACs and documentation IPs only. What a real router, Dropbear and
OpenSSH's own pty handling do is not exercised here.
"""
import hashlib
import json
import os
from pathlib import Path
import re
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
LEG_SECONDS = 2


def setUpModule():
    PP.setUpModule()


def tearDownModule():
    PP.tearDownModule()


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


def mac_pattern(mac):
    return re.compile(r'(?<![0-9a-f])(%s|%s)(?![0-9a-f])' % (re.escape(mac), mac.replace(':', '')[-6:]))


class DriverBase(PP.PilotShellBase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(self.tool.V2, 'SCOPE_LEG_SECONDS', LEG_SECONDS)
        patcher.start()
        self.addCleanup(patcher.stop)
        shim = self.bin / 'ssh'
        shim.write_text(f'#!/bin/sh\nexec {sys.executable} -B {HELPER} "$@"\n')
        shim.chmod(0o700)
        self.legs_log = self.work / 'legs.jsonl'
        self.pidfile = self.work / 'child.pid'
        self.config_path = self.write_config(**self.v2_changes())
        self.details = self.plan_details(self.config_path)
        self.sha = self.details['planSha256']

    def spec_for(self, leg1, **leg2):
        leg2 = dict({'mode': 'scripted', 'log': str(self.legs_log)}, **leg2)
        self.spec.update(leg1=leg1, leg2=leg2)
        self.spec_path.write_text(json.dumps(self.spec))

    def drive(self, leg1, details=None, sha=None, timeout=30, **leg2):
        self.spec_for(leg1, **leg2)
        driver = self.tool.LEG2.Driver(details or self.details, sha or self.sha, self.tool.plan_digest)
        env = {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'], 'FAKE_SSH_SPEC': str(self.spec_path),
               'HOME': str(self.work), 'LC_ALL': 'C'}
        out_path = self.work / 'stdout.log'
        out_fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        err_fd = os.open(self.work / 'stderr.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            self.started = time.monotonic()
            self.outcome = driver.run(b'payload\n', env, out_fd, err_fd, out_path, timeout)
            self.elapsed = time.monotonic() - self.started
        finally:
            os.close(out_fd)
            os.close(err_fd)
        return self.outcome

    def ssh_calls(self):
        return [json.loads(line) for line in self.ssh_log.read_text().splitlines()] if self.ssh_log.exists() else []

    def leg_calls(self):
        return [call for call in self.ssh_calls() if '-tt' in call]

    def received(self):
        if not self.legs_log.exists():
            return []
        return [json.loads(line) for line in self.legs_log.read_text().splitlines()]

    def legs(self):
        return self.outcome[2]['legs']

    def resign(self, details):
        return dict(details, planSha256=self.tool.plan_digest(details))


class DriverTests(DriverBase):
    def test_marker_starts_a_leg_with_the_digest_bound_argv_and_types_only_the_last_six_digits(self):
        rc, timed_out, results = self.drive([[0.3, f'CFP_LEG2_READY 2a {BASE}'], [1.5, 'PHASE X OK']])
        self.assertEqual((rc, timed_out), (0, False))
        (leg,) = results['legs']
        self.assertEqual(set(leg), LEG_KEYS)
        self.assertEqual((leg['leg'], leg['outcome'], leg['exit'], leg['ok'], leg['confirmationSent']),
                         ('2a', 'exited', 0, True, True))
        self.assertEqual([entry.get('received') for entry in self.received()], [PHONE['mac'].replace(':', '')[-6:]])
        (call,) = self.leg_calls()
        planned = self.details['legs'][0]['sshArgv']
        self.assertEqual(call[:-1], planned[1:-1])
        self.assertEqual(call[-1], f'/usr/sbin/cfctl scope-add {PHONE["mac"]} --base {BASE}')
        self.assertNotIn('-T', call)
        self.assertEqual(len(self.ssh_calls()), 2)

    def test_all_four_legs_run_once_each_in_order_with_their_own_command(self):
        script = []
        for index, leg in enumerate(('2a', '2b', '2c', '2d')):
            script.append([1.0 if index else 0.2, f'CFP_LEG2_READY {leg} {BASE if index % 2 == 0 else BASE2}'])
        script.append([1.2, 'PHASE Y OK'])
        self.drive(script)
        self.assertEqual([(leg['leg'], leg['outcome']) for leg in self.legs()], [(l, 'exited') for l in ('2a', '2b', '2c', '2d')])
        commands = [call[-1] for call in self.leg_calls()]
        self.assertEqual(commands[0], f'/usr/sbin/cfctl scope-add {PHONE["mac"]} --base {BASE}')
        self.assertEqual(commands[1], f'/usr/sbin/cfctl scope-remove {PHONE["mac"]} --base {BASE2}')
        self.assertEqual(commands[2],
                         f"env SSH_ORIGINAL_COMMAND='cfctl scope-add {PHONE['mac']} --base {BASE}' /usr/sbin/cfctl-scope pilot")
        self.assertEqual(commands[3],
                         f"env SSH_ORIGINAL_COMMAND='cfctl scope-remove {PHONE['mac']} --base {BASE2}' /usr/sbin/cfctl-scope pilot")

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
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.8, f'CFP_LEG2_READY 2b {BASE2}'], [5.0, 'PHASE X OK']], linger=1.5)
        self.assertEqual([(leg['leg'], leg['outcome'], leg['ok']) for leg in self.legs()],
                         [('2a', 'exited', True), ('2b', 'exited', True)])
        self.assertEqual(self.outcome[2]['ignoredMarkers'], 0)
        self.assertEqual(self.leg_calls()[1][-1], f'/usr/sbin/cfctl scope-remove {PHONE["mac"]} --base {BASE2}')

    def test_a_held_marker_is_dropped_by_stop_cancel_and_the_end_of_leg_one(self):
        for name, third in (('stop', 'STOP SCOPE-ADD-1 x'), ('cancel', 'CFP_LEG2_CANCEL 2a')):
            with self.subTest(name):
                self.ssh_log.unlink(missing_ok=True)
                self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.6, f'CFP_LEG2_READY 2b {BASE}'], [0.1, third], [4.0, 'END']],
                           linger=1.5)
                self.assertEqual(len(self.leg_calls()), 1, name)
        self.ssh_log.unlink(missing_ok=True)
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.6, f'CFP_LEG2_READY 2b {BASE}']], linger=3.0)
        self.assertEqual(len(self.leg_calls()), 1)
        self.assertEqual([leg['leg'] for leg in self.legs()], ['2a'])

    def test_the_local_clients_own_stderr_is_neither_matched_nor_kept(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.5, 'PHASE X OK']], stderr_line='Connection to 192.0.2.1 closed.')
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['ok']), ('exited', True))
        self.assertGreater(leg['stderrBytes'], 0)
        self.assertNotIn('192.0.2.1', json.dumps(self.outcome[2]))

    def test_a_marker_for_another_leg_or_a_repeat_is_ignored_and_counted(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2b {BASE}'], [0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.2, f'CFP_LEG2_READY 2a {BASE}'],
                    [1.0, 'PHASE X OK']])
        self.assertEqual([leg['leg'] for leg in self.legs()], ['2a'])
        self.assertEqual(len(self.leg_calls()), 1)
        self.assertGreaterEqual(self.outcome[2]['ignoredMarkers'], 2)

    def test_a_prompt_that_is_not_exactly_the_expected_text_is_refused_and_nothing_is_typed(self):
        mac = PHONE['mac']
        wrong = {'other wording': {'prompt_text': f'scope-add {mac} --base {BASE}\nType the last 4 hex digits to confirm: '},
                 'no trailing space': {'prompt_text': f'scope-add {mac} --base {BASE}\n{PROMPT.rstrip()}'},
                 'different mac': {'prompt_text': f'scope-add 02:00:00:00:00:35 --base {BASE}\n{PROMPT}'},
                 'different base': {'prompt_text': f'scope-add {mac} --base {BASE2}\n{PROMPT}'},
                 'different op': {'prompt_text': f'scope-remove {mac} --base {BASE}\n{PROMPT}'},
                 'banner first': {'before': ['Welcome to {mac}']},
                 'trailing text': {'prompt_text': f'scope-add {mac} --base {BASE}\n{PROMPT}yes'}}
        for name, knobs in wrong.items():
            with self.subTest(name):
                self.legs_log.unlink(missing_ok=True)
                self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [2.5, 'PHASE X OK']], **knobs)
                (leg,) = self.legs()
                self.assertIn(leg['outcome'], ('prompt_mismatch', 'timeout'), name)
                self.assertFalse(leg['confirmationSent'], name)
                self.assertEqual(self.received(), [], name)

    def test_silence_instead_of_a_prompt_is_never_answered(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [LEG_SECONDS + 2.5, 'PHASE X OK']], delay=60)
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['confirmationSent']), ('timeout', False))
        self.assertEqual(self.received(), [])

    def test_crlf_and_bare_lf_line_ends_both_match(self):
        # The scripted tty is cooked (the prompt arrives with CRLF); `raw` turns post-processing off (bare LF).
        for knobs in ({}, {'raw': True}):
            with self.subTest(knobs):
                self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.5, 'PHASE X OK']], **knobs)
                self.assertEqual([(leg['outcome'], leg['ok']) for leg in self.legs()], [('exited', True)])

    def test_a_flood_before_the_prompt_is_capped_and_refused(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [2.0, 'PHASE X OK']], before=['x' * 200] * 200)
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['confirmationSent']), ('prompt_mismatch', False))
        self.assertEqual(self.received(), [])

    def test_a_wrong_confirmation_is_reported_as_a_refused_leg_not_an_ok_one(self):
        with mock.patch.object(self.tool.LEG2, 'confirmation_digits', lambda mac: '999999'):
            self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.5, 'PHASE X OK']])
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['ok'], leg['errors'], leg['exit']), ('exited', False, ['scope_confirmation_mismatch'], 1))

    def test_the_confirmation_digits_are_the_last_six_hex_of_the_target_mac(self):
        digits = self.tool.LEG2.confirmation_digits
        self.assertEqual(digits('02:00:00:00:00:34'), '000034')
        self.assertEqual(digits('02:11:22:aa:bb:cc'), 'aabbcc')
        self.assertEqual(digits('02:11:22:33:44:5f'), '33445f')

    def test_a_leg_that_hangs_is_killed_at_the_deadline_with_its_children_and_never_retried(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [LEG_SECONDS + 3.5, 'PHASE X OK']],
                   hang_after_read=True, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'timeout')
        self.assertTrue(leg['confirmationSent'])
        self.assertTrue(self.pidfile.exists())
        time.sleep(0.3)
        self.assertFalse(alive(int(self.pidfile.read_text())))
        self.assertEqual(len(self.leg_calls()), 1)

    def test_the_deadline_comes_from_the_digest_bound_plan(self):
        self.assertTrue(all(leg['timeoutSeconds'] == LEG_SECONDS for leg in self.details['legs']))
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [LEG_SECONDS + 3.5, 'PHASE X OK']], hang_after_read=True)
        self.assertEqual(self.legs()[0]['outcome'], 'timeout')
        self.assertLess(self.elapsed, LEG_SECONDS + 4.5)
        self.assertGreaterEqual(self.legs()[0]['seconds'], LEG_SECONDS)

    def test_a_failed_leg_is_never_retried(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [2.5, 'PHASE X OK']], exit255=True)
        (leg,) = self.legs()
        self.assertEqual((leg['outcome'], leg['exit'], leg['ok']), ('exited', 255, False))
        self.assertEqual(len(self.leg_calls()), 1)

    def test_a_refused_leg_is_never_retried(self):
        with mock.patch.object(self.tool.LEG2, 'confirmation_digits', lambda mac: '999999'):
            self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [2.5, 'PHASE X OK']])
        self.assertEqual(len(self.leg_calls()), 1)

    def test_a_stop_line_kills_the_running_leg_and_its_children(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.0, 'STOP SCOPE-ADD-1 scope_leg_timeout'], [1.0, 'PHASE UNINSTALL OK']],
                   hang_after_read=True, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'killed_on_stop')
        time.sleep(0.3)
        self.assertFalse(alive(int(self.pidfile.read_text())))
        self.assertLess(leg['seconds'], LEG_SECONDS)

    def test_no_leg_starts_after_a_stop_even_with_a_marker_in_the_same_read(self):
        self.spec_for([])
        self.drive([[0.2, 'STOP SCOPE-ADD-1 x'], [0, f'CFP_LEG2_READY 2a {BASE}'], [1.0, 'PHASE UNINSTALL OK']])
        self.assertEqual(self.legs(), [])
        self.drive([[0.2, 'STOP SCOPE-ADD-1 x'], [0.8, 'PHASE UNINSTALL OK'], [0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.8, 'END']])
        self.assertEqual(self.legs(), [])
        self.assertEqual(self.leg_calls(), [])

    def test_a_cancel_marker_ends_the_running_leg_and_blocks_later_ones(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.0, 'CFP_LEG2_CANCEL 2a'], [0.5, f'CFP_LEG2_READY 2b {BASE}'],
                    [1.5, 'PHASE UNINSTALL OK']], hang_after_read=True, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'killed_on_cancel')
        time.sleep(0.3)
        self.assertFalse(alive(int(self.pidfile.read_text())))
        self.assertEqual(len(self.leg_calls()), 1)

    ACK_PATH = '/tmp/couvre-feu-first.Ab3dEf/leg2-idle'

    def ack_calls(self):
        return [call for call in self.ssh_calls() if '-tt' not in call and call[-1].startswith(': > ')]

    def test_ack_is_written_over_a_pinned_ssh_only_after_the_cancelled_leg_is_dead(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.0, 'CFP_LEG2_CANCEL 2a'], [0, f'CFP_LEG2_ACK_FILE {self.ACK_PATH}'],
                    [0.5, f'CFP_LEG2_ACK_FILE {self.ACK_PATH}'], [1.0, 'PHASE UNINSTALL OK']], hang_after_read=True)
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'killed_on_cancel')
        self.assertEqual(self.outcome[2]['ack'], 'sent')
        (call,) = self.ack_calls()
        self.assertEqual(call[-1], f': > {self.ACK_PATH}')
        self.assertEqual(call[:-1], self.details['sshArgv'][1:-1])
        self.assertIn('StrictHostKeyChecking=yes', call)

    def test_ack_without_a_cancel_or_with_a_foreign_path_is_ignored(self):
        self.drive([[0.2, f'CFP_LEG2_ACK_FILE {self.ACK_PATH}'], [0.2, 'CFP_LEG2_CANCEL 2a'],
                    [0, 'CFP_LEG2_ACK_FILE /etc/passwd'], [0, 'CFP_LEG2_ACK_FILE /tmp/couvre-feu-first.Ab3dEf/../x/leg2-idle'],
                    [0.5, 'END']])
        self.assertEqual(self.ack_calls(), [])
        self.assertEqual(self.outcome[2]['ack'], 'none')
        self.assertEqual(self.outcome[2]['ignoredMarkers'], 1)

    def test_ack_with_no_running_leg_and_failed_or_hung_ssh_is_reported_not_fatal(self):
        patcher = mock.patch.object(self.tool.LEG2, 'ACK_SECONDS', 1)
        patcher.start()
        self.addCleanup(patcher.stop)
        for knob in ({'fail': True}, {'hang': True}):
            self.spec.update(ack=knob)
            rc, timed_out, results = self.drive([[0.2, 'CFP_LEG2_CANCEL 2a'], [0, f'CFP_LEG2_ACK_FILE {self.ACK_PATH}'],
                                                 [0.3, 'END']])
            self.assertEqual((rc, timed_out, results['ack']), (0, False, 'failed'))

    def test_a_cancel_before_any_marker_blocks_the_leg(self):
        self.drive([[0.2, 'CFP_LEG2_CANCEL 2a'], [0, f'CFP_LEG2_READY 2a {BASE}'], [1.0, 'END']])
        self.assertEqual(self.legs(), [])

    def test_a_leg_does_not_outlive_leg_one(self):
        self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.8, 'PHASE X OK']], hang_after_read=True, child=str(self.pidfile))
        (leg,) = self.legs()
        self.assertEqual(leg['outcome'], 'killed_leg1_ended')
        time.sleep(0.3)
        self.assertFalse(alive(int(self.pidfile.read_text())))

    def test_the_local_timeout_kills_leg_one_and_the_leg(self):
        rc, timed_out, results = self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [30, 'never']], timeout=2,
                                            hang_after_read=True, child=str(self.pidfile))
        self.assertTrue(timed_out)
        self.assertEqual(results['legs'][0]['outcome'], 'killed_leg1_ended')
        time.sleep(0.3)
        self.assertFalse(alive(int(self.pidfile.read_text())))
        self.assertLess(self.elapsed, 6)


class BindingTests(DriverBase):
    def refused(self, details, sha=None, resigned=False):
        # A re-signed plan is approved by its own digest: only the checks behind the digest can refuse it.
        with self.assertRaises(self.tool.Refusal) as caught:
            self.drive([[0.1, 'x']], details=details, sha=sha or details['planSha256'])
        self.assertEqual('approved digest' in str(caught.exception), not resigned, str(caught.exception))
        self.assertEqual(self.ssh_calls(), [])

    def test_the_driver_refuses_a_plan_that_is_not_the_approved_digest(self):
        self.refused(self.details, sha='0' * 64)
        self.refused(self.details, sha=self.sha[:-1] + ('0' if self.sha[-1] != '0' else '1'))

    def test_changing_any_digest_bound_field_without_the_digest_is_refused(self):
        for field, value in (('payloadSha256', '0' * 64), ('phases', self.details['phases'][:-1]), ('remoteTimeoutSeconds', 1),
                             ('person', 'someone'), ('pilotPolicies', []), ('knownHostsSha256', '1' * 64)):
            with self.subTest(field):
                self.refused(dict(self.details, **{field: value}))

    def test_changing_a_leg_argv_without_the_digest_is_refused(self):
        for index in range(4):
            for position, value in ((-1, '/usr/sbin/cfctl scope-add {MAC} --base {BASE}; id'), (3, 'other.pub')):
                with self.subTest((index, position)):
                    details = json.loads(json.dumps(self.details))
                    details['legs'][index]['sshArgv'][position] = value
                    self.refused(details)
        details = json.loads(json.dumps(self.details))
        details['legs'][0]['commandTemplate'] = 'id'
        self.refused(details)
        details = json.loads(json.dumps(self.details))
        details['sshArgv'][-1] = details['sshArgv'][-1] + ' ;'
        self.refused(details)

    def test_each_leg_argv_is_bound_in_the_plan_and_shares_leg_one_prefix_exactly(self):
        base = self.details['sshArgv']
        for leg in self.details['legs']:
            self.assertEqual(leg['sshArgv'][:-1], base[:-3] + ['-tt', base[-2]])
            self.assertEqual(leg['sshArgv'][-1], leg['commandTemplate'])
        for index in range(4):
            changed = json.loads(json.dumps(self.details))
            changed['legs'][index]['sshArgv'][1] = '-x'
            self.assertNotEqual(self.tool.plan_digest(changed), self.sha)

    def test_the_host_key_options_are_never_weakened_even_in_a_resigned_plan(self):
        for leg in self.details['legs']:
            options = [item for item in leg['sshArgv'] if '=' in item]
            self.assertIn('StrictHostKeyChecking=yes', options)
            self.assertIn('BatchMode=yes', options)
            self.assertNotIn('-T', leg['sshArgv'])
            self.assertEqual(leg['sshArgv'].count('-tt'), 1)
            joined = ' '.join(leg['sshArgv'])
            for banned in ('StrictHostKeyChecking=no', 'StrictHostKeyChecking=accept-new', 'UserKnownHostsFile=/dev/null',
                           'CheckHostIP=no', 'VerifyHostKeyDNS', 'StrictHostKeyChecking=off'):
                self.assertNotIn(banned, joined)
        for old, new in (('StrictHostKeyChecking=yes', 'StrictHostKeyChecking=no'),
                         ('StrictHostKeyChecking=yes', 'StrictHostKeyChecking=accept-new'),
                         ('BatchMode=yes', 'BatchMode=no')):
            with self.subTest(new):
                # Leg 1 and every leg carry the same weakening, so only the option check can stop it.
                details = json.loads(json.dumps(self.details))
                details['sshArgv'] = [new if item == old else item for item in details['sshArgv']]
                for leg in details['legs']:
                    leg['sshArgv'] = [new if item == old else item for item in leg['sshArgv']]
                self.refused(self.resign(details), resigned=True)
        details = json.loads(json.dumps(self.details))
        for argv in [details['sshArgv']] + [leg['sshArgv'] for leg in details['legs']]:
            argv[:] = [('UserKnownHostsFile=/dev/null' if item.startswith('UserKnownHostsFile=') else item) for item in argv]
        self.refused(self.resign(details), resigned=True)
        details = json.loads(json.dumps(self.details))
        for argv in [details['sshArgv']] + [leg['sshArgv'] for leg in details['legs']]:
            argv[5:5] = ['-o', 'StrictHostKeyChecking=no']
        self.refused(self.resign(details), resigned=True)

    def test_a_resigned_plan_with_a_foreign_command_or_mac_is_refused(self):
        for index, template in ((0, '/usr/sbin/cfctl scope-add {MAC} --base {BASE} && id'),
                                (1, '/usr/sbin/cfctl scope-add {MAC} --base {BASE}'),
                                (2, "env SSH_ORIGINAL_COMMAND='cfctl scope-add {MAC} --base {BASE}' /usr/sbin/cfctl-scope root"),
                                (0, '/usr/sbin/cfctl scope-add {MAC}')):
            with self.subTest(template):
                details = json.loads(json.dumps(self.details))
                details['legs'][index]['commandTemplate'] = template
                details['legs'][index]['sshArgv'][-1] = template
                self.refused(self.resign(details), resigned=True)
        details = json.loads(json.dumps(self.details))
        details['legs'][0]['scopeTargetMac'] = '02:00:00:00:00:99'
        self.refused(self.resign(details), resigned=True)
        details = json.loads(json.dumps(self.details))
        details['legs'][0]['retry'] = True
        self.refused(self.resign(details), resigned=True)


class HygieneTests(DriverBase):
    def test_descriptors_processes_and_the_terminal_are_clean_on_every_path(self):
        scenarios = {
            'ok': ([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.5, 'PHASE X OK']], {}),
            'timeout': ([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [LEG_SECONDS + 2.5, 'END']], {'hang_after_read': True}),
            'stop': ([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.8, 'STOP A b'], [0.5, 'END']], {'hang_after_read': True}),
            'cancel': ([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.8, 'CFP_LEG2_CANCEL 2a'], [0.5, 'END']], {'hang_after_read': True}),
            'leg1 ends': ([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [0.6, 'END']], {'hang_after_read': True}),
            'mismatch': ([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.5, 'END']], {'prompt_text': 'nope: '}),
            'spawn failure': ([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.0, 'END']], {'exit255': True}),
            'no marker': ([[0.2, 'END']], {})}
        master, slave = os.openpty()
        saved = os.dup(0)
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
            os.dup2(saved, 0)
            for fd in (saved, master, slave):
                os.close(fd)

    def test_descriptors_are_closed_when_the_run_is_interrupted(self):
        before = open_fds()
        self.spec_for([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [20, 'END']], hang_after_read=True, child=str(self.pidfile))
        driver = self.tool.LEG2.Driver(self.details, self.sha, self.tool.plan_digest)
        env = {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'], 'FAKE_SSH_SPEC': str(self.spec_path), 'HOME': str(self.work)}
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
                driver.run(b'x\n', env, fd, fd, out, 30)
        finally:
            os.close(fd)
        time.sleep(0.3)
        self.assertEqual(open_fds(), before)
        self.assertFalse(alive(int(self.pidfile.read_text())))
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)


class EvidenceTests(DriverBase):
    def test_nothing_the_driver_returns_or_prints_holds_the_confirmation_or_a_raw_mac(self):
        sentinel = mac_pattern(PHONE['mac'])
        for knobs in ({}, {'echo': True, 'before': ['seen {mac} at 192.0.2.34']}, {'prompt_text': 'x {mac} ' + PHONE['mac'] + ': '}):
            with self.subTest(knobs):
                import io, contextlib
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                    self.drive([[0.2, f'CFP_LEG2_READY 2a {BASE}'], [1.5, 'PHASE X OK']], **knobs)
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
        self.assertLessEqual(len(text.splitlines()), 400)
        self.assertIsNone(re.search(r'authorized_keys|dropbear|passwd|shadow|password|PasswordAuth|sshd', text, re.I))
        for source in ((REPO / 'tools/live/penn-pilot.py').read_text(), (REPO / 'tools/live/penn_pilot_v2.py').read_text()):
            self.assertIsNone(re.search(r'StrictHostKeyChecking=(no|accept-new|off)|UserKnownHostsFile=/dev/null|CheckHostIP', source))
        self.assertIsNone(re.search(r'StrictHostKeyChecking=(no|accept-new|off)|CheckHostIP', text))
        self.assertLessEqual(len((REPO / 'tools/live/penn-pilot.py').read_text().splitlines()), 800)
        imports = set(re.findall(r'(?m)^(?:import|from) ([a-z_]+)', text))
        self.assertLessEqual(imports, {'hmac', 'json', 'os', 'pty', 're', 'select', 'signal', 'subprocess', 'threading', 'time',
                                       'typing', 'hashlib', 'shlex', 'termios'})

    def test_the_driver_is_wired_and_the_flag_is_true(self):
        text = (REPO / 'tools/live/penn-pilot.py').read_text()
        self.assertIn('LEG2_DRIVER_IMPLEMENTED = True', text)
        self.assertNotIn('leg-2 pty driver absent', text)
        self.assertIn('driver.run(payload, env, stdout_fd, stderr_fd', text)


if __name__ == '__main__':
    unittest.main()
