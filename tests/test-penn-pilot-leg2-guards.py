#!/usr/bin/env python3
"""Leg-2 pty driver guards (T4 review fixes): the digest-bound argv and plan checks, the ack command run for real
against a fake /proc, signal handling of the driver process, and re-hashing of the pinned known-hosts and identity files.
Same harness as tests/test-penn-pilot-leg2.py (fake ssh, no router). Fictional MACs and documentation IPs only."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import importlib.util

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / 'tests'))
_spec = importlib.util.spec_from_file_location('test_penn_pilot_leg2', REPO / 'tests/test-penn-pilot-leg2.py')
L2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L2)
PP, PHONE = L2.PP, L2.PHONE
BASE, BASE2, ACK_PATH, BOUND, LEG_SECONDS, AFTER = L2.BASE, L2.BASE2, L2.ACK_PATH, L2.BOUND, L2.LEG_SECONDS, L2.AFTER
marker, settled, gone, wait_dead = L2.marker, L2.settled, L2.gone, L2.wait_dead
import unittest  # noqa: E402


def setUpModule():
    PP.setUpModule()


def tearDownModule():
    PP.tearDownModule()


class AckCommandTests(L2.DriverBase):
    """The ack command itself, run by the fake ssh through /bin/sh against a fake /proc and a fake /tmp."""

    def setUp(self):
        super().setUp()
        self.proc, self.tmp = self.work / 'fake-proc', self.work / 'fake-tmp'
        self.target_dir = self.tmp / 'couvre-feu-first.Ab3dEf'
        self.target_dir.mkdir(parents=True)
        self.proc.mkdir()
        self.target = self.target_dir / 'leg2-idle'
        self.spec.update(ack={'proc': str(self.proc), 'tmp': str(self.tmp)})
        self.spec_path.write_text(json.dumps(self.spec))

    def process(self, number, *fields):
        (self.proc / str(number)).mkdir()
        (self.proc / str(number) / 'cmdline').write_bytes(b'\0'.join(f.encode() for f in fields) + b'\0')

    def ack(self):
        return self.tool.LEG2.send_ack(self.details['sshArgv'], ACK_PATH, self.env)

    def test_a_clean_router_gets_the_file(self):
        self.process(11, '/bin/sh', '-s')
        self.process(12, '/bin/sh', '-c', f': > {ACK_PATH}; /usr/sbin/cfctl-scope lookalike text in one field')
        self.process(13, '/bin/sh', '/usr/sbin/cfctl-ssh')
        self.assertEqual(self.ack(), 'sent')
        self.assertTrue(self.target.is_file())

    def test_a_live_cfctl_or_wrapper_process_blocks_the_ack_and_nothing_is_written(self):
        for fields in (('/bin/sh', '/usr/sbin/cfctl', 'scope-add', PHONE['mac']), ('/bin/sh', '/usr/sbin/cfctl-scope', 'pilot'),
                       ('timeout', '-s', 'KILL', '5', '/usr/sbin/cfctl', 'scope-add')):
            with self.subTest(fields):
                self.process(21, *fields)
                self.assertEqual(self.ack(), 'busy')
                self.assertFalse(self.target.exists())
                (self.proc / '21' / 'cmdline').unlink()
                (self.proc / '21').rmdir()

    def test_a_process_that_is_just_going_away_is_waited_for(self):
        self.process(31, '/bin/sh', '/usr/sbin/cfctl', 'scope-remove')

        def vanish():
            time.sleep(1.2)
            (self.proc / '31' / 'cmdline').unlink()
        thread = threading.Thread(target=vanish)
        thread.start()
        self.assertEqual(self.ack(), 'sent')
        thread.join()
        self.assertTrue(self.target.is_file())

    def test_an_existing_file_or_a_symlink_is_never_written_through(self):
        victim = self.work / 'victim'
        victim.write_text('keep\n')
        for name, make in (('file', lambda: self.target.write_text('x')), ('symlink', lambda: self.target.symlink_to(victim)),
                           ('dangling', lambda: self.target.symlink_to(self.work / 'nowhere'))):
            with self.subTest(name):
                self.target.unlink(missing_ok=True)
                make()
                self.assertEqual(self.ack(), 'failed')
                self.assertEqual(victim.read_text(), 'keep\n')
                self.assertFalse((self.work / 'nowhere').exists())


class SignalTests(L2.DriverBase):
    SCRIPT = '''
import importlib.util, json, os, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('penn_pilot', sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
details, env = json.load(open(sys.argv[2])), json.load(open(sys.argv[3]))
if os.environ.get('SLOW_KILL'):
    original = tool.LEG2.Leg.kill
    tool.LEG2.Leg.kill = lambda *args: (time.sleep(float(os.environ['SLOW_KILL'])), original(*args))[1]
driver = tool.LEG2.Driver(details, details['planSha256'], tool.plan_digest)
fd = os.open(sys.argv[4], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    driver.run(b'payload\\n', env, fd, fd, sys.argv[4], 60)
except KeyboardInterrupt:
    sys.exit(7)
'''

    def run_signalled(self, signals, slow='0'):
        self.spec_for([marker(), [0, '@wait read 1'], [60, 'END']], hang_after_read=True, child=str(self.pidfile))
        script = self.work / 'driver-child.py'
        script.write_text(self.SCRIPT)
        for name, value in (('details', self.details), ('env', self.env)):
            (self.work / f'{name}.json').write_text(json.dumps(value))
        child = subprocess.Popen([sys.executable, '-B', str(script), str(PP.SOURCE.tool_path), str(self.work / 'details.json'),
                                  str(self.work / 'env.json'), str(self.work / 'out.log')], start_new_session=True,
                                 env={'PATH': os.environ['PATH'], 'HOME': str(self.work), 'SLOW_KILL': slow})
        self.addCleanup(lambda: child.poll() is None and child.kill())
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (self.events_log.exists() and 'read' in self.events_log.read_text()):
            time.sleep(0.05)
        self.assertTrue(self.events_log.exists() and 'read' in self.events_log.read_text(), 'leg never read the answer')
        for index, number in enumerate(signals):
            if index:
                time.sleep(0.4)
            child.send_signal(number)
        self.assertEqual(child.wait(30), 7)

    def test_sigterm_and_sighup_kill_the_leg_leg_one_and_every_child_before_the_driver_dies(self):
        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(number.name):
                self.run_signalled([number])
                self.child_dead()
                self.assertTrue(wait_dead(int(self.leg1_pid.read_text())))

    def test_a_second_signal_during_the_cleanup_cannot_skip_the_kill_of_leg_one(self):
        self.run_signalled([signal.SIGTERM, signal.SIGTERM], slow='2')
        self.child_dead()
        self.assertTrue(wait_dead(int(self.leg1_pid.read_text())))


class BindingTests(L2.DriverBase):
    def refused(self, details, sha=None, resigned=False):
        # A re-signed plan is approved by its own digest: only the checks behind the digest can refuse it.
        with self.assertRaises(self.tool.Refusal) as caught:
            self.drive([[0.1, 'x']], details=details, sha=sha or details['planSha256'])
        self.assertEqual('approved digest' in str(caught.exception), not resigned, str(caught.exception))
        self.assertEqual(self.ssh_calls(), [])

    def fresh(self):
        return json.loads(json.dumps(self.details))

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
                    details = self.fresh()
                    details['legs'][index]['sshArgv'][position] = value
                    self.refused(details)
        details = self.fresh()
        details['legs'][0]['commandTemplate'] = 'id'
        self.refused(details)
        details = self.fresh()
        details['sshArgv'][-1] = details['sshArgv'][-1] + ' ;'
        self.refused(details)

    def test_each_leg_argv_is_bound_in_the_plan_and_shares_leg_one_prefix_exactly(self):
        base = self.details['sshArgv']
        for leg in self.details['legs']:
            self.assertEqual(leg['sshArgv'][:-1], base[:-3] + ['-e', 'none', '-tt', base[-2]])
            self.assertEqual(leg['sshArgv'][-1], leg['commandTemplate'])
            self.assertTrue(leg['commandTemplate'].startswith(BOUND))
        for index in range(4):
            changed = self.fresh()
            changed['legs'][index]['sshArgv'][1] = '-x'
            self.assertNotEqual(self.tool.plan_digest(changed), self.sha)

    def test_the_ssh_escape_character_is_disabled_on_every_leg_and_cannot_be_dropped(self):
        for leg in self.details['legs']:
            self.assertEqual(leg['sshArgv'].index('-e') + 1, leg['sshArgv'].index('none'))
            self.assertEqual(leg['sshArgv'][leg['sshArgv'].index('-e') + 2], '-tt')
        for index in range(4):
            for edit in (lambda a: a.__delitem__(slice(-5, -3)), lambda a: a.__setitem__(-4, '~')):
                details = self.fresh()
                edit(details['legs'][index]['sshArgv'])
                self.refused(self.resign(details), resigned=True)

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
                details = self.fresh()
                details['sshArgv'] = [new if item == old else item for item in details['sshArgv']]
                for leg in details['legs']:
                    leg['sshArgv'] = [new if item == old else item for item in leg['sshArgv']]
                self.refused(self.resign(details), resigned=True)
        details = self.fresh()
        for argv in [details['sshArgv']] + [leg['sshArgv'] for leg in details['legs']]:
            argv[:] = [('UserKnownHostsFile=/dev/null' if item.startswith('UserKnownHostsFile=') else item) for item in argv]
        self.refused(self.resign(details), resigned=True)
        details = self.fresh()
        for argv in [details['sshArgv']] + [leg['sshArgv'] for leg in details['legs']]:
            argv[5:5] = ['-o', 'StrictHostKeyChecking=no']
        self.refused(self.resign(details), resigned=True)

    def test_a_resigned_plan_with_a_foreign_command_bound_or_mac_is_refused(self):
        scope = "env SSH_ORIGINAL_COMMAND='cfctl scope-add {MAC} --base {BASE}' /usr/sbin/cfctl-scope"
        for index, template in ((0, BOUND + '/usr/sbin/cfctl scope-add {MAC} --base {BASE} && id'),
                                (1, BOUND + '/usr/sbin/cfctl scope-add {MAC} --base {BASE}'),
                                (2, f'{BOUND}{scope} root'),
                                (0, BOUND + '/usr/sbin/cfctl scope-add {MAC}'),
                                (0, '/usr/sbin/cfctl scope-add {MAC} --base {BASE}'),
                                (0, 'timeout -s KILL 999 /usr/sbin/cfctl scope-add {MAC} --base {BASE}'),
                                (0, 'timeout -s TERM %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % LEG_SECONDS),
                                (0, 'timeout -s KILL 0%d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % LEG_SECONDS)):
            with self.subTest(template):
                details = self.fresh()
                details['legs'][index]['commandTemplate'] = template
                details['legs'][index]['sshArgv'][-1] = template
                self.refused(self.resign(details), resigned=True)
        details = self.fresh()
        details['legs'][0]['scopeTargetMac'] = '02:00:00:00:00:99'
        self.refused(self.resign(details), resigned=True)
        details = self.fresh()
        details['legs'][0]['retry'] = True
        self.refused(self.resign(details), resigned=True)

    def test_the_legs_are_copied_at_construction_so_later_edits_change_nothing(self):
        details = self.fresh()
        driver = self.driver(details, details['planSha256'])
        evil = BOUND + '/usr/sbin/cfctl scope-add {MAC} --base {BASE}; id'
        details['legs'][0]['commandTemplate'] = evil
        details['legs'][0]['sshArgv'][-1] = evil
        details['legs'][0]['timeoutSeconds'] = 1
        self.spec_for([marker()] + settled())
        self.run_driver(driver)
        self.assertEqual(self.leg_calls()[0][-1], self.command(0))


class PinnedFileTests(L2.DriverBase):
    """Known hosts and the identity file are re-hashed against the approved digest-bound values before every use."""

    def swap(self, name):
        return str(self.work / name)

    def test_a_changed_known_hosts_file_stops_every_later_leg_and_the_ack(self):
        hosts = self.swap('known_hosts')
        self.drive([marker(), *settled(1)[:1], [0, f'@append {hosts} ssh-ed25519 AAAAevil'], [0.2, f'CFP_LEG2_READY 2b {BASE2}'],
                    [0.5, 'CFP_LEG2_CANCEL 2b'], [0.2, f'CFP_LEG2_ACK_FILE {ACK_PATH}'], [AFTER, 'END']])
        self.assertEqual([leg['leg'] for leg in self.legs()], ['2a'])
        self.assertEqual(len(self.leg_calls()), 1)
        self.assertEqual((self.ack_calls(), self.outcome[2]['ack'], self.outcome[2]['pinned']), ([], 'refused', 'changed'))

    def test_a_changed_identity_file_stops_the_first_leg(self):
        self.drive([[0, f'@append {self.swap("admin.pub")} x'], marker(), [AFTER, 'END']])
        self.assertEqual((self.legs(), self.leg_calls(), self.outcome[2]['pinned']), ([], [], 'changed'))

    def test_a_replaced_or_missing_file_counts_as_changed(self):
        driver = self.driver()
        self.assertTrue(driver.files_unchanged())
        for name in ('known_hosts', 'admin.pub'):
            with self.subTest(name):
                path = Path(self.swap(name))
                saved = path.read_bytes()
                path.unlink()
                self.assertFalse(driver.files_unchanged())
                path.symlink_to(self.work / 'authorization.txt')
                self.assertFalse(driver.files_unchanged())
                path.unlink()
                path.write_bytes(saved)
                self.assertTrue(driver.files_unchanged())

    def test_unchanged_files_run_normally_and_are_reported_ok(self):
        self.drive([marker()] + settled())
        self.assertEqual(self.outcome[2]['pinned'], 'ok')

    def test_leg_one_is_not_started_when_a_file_changed_before_the_run(self):
        Path(self.swap('known_hosts')).write_text('changed\n')
        with self.assertRaises(self.tool.Refusal):
            self.drive([[0.1, 'x']])
        self.assertEqual(self.ssh_calls(), [])


if __name__ == '__main__':
    unittest.main()
