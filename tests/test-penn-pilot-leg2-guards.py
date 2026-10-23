#!/usr/bin/env python3
"""Leg-2 pty driver guards (T4 review fixes): the digest-bound argv and plan checks, the ack command run for real
against a fake /proc, signal handling of the driver process, and re-hashing of the pinned known-hosts and identity files.
Same harness as tests/test-penn-pilot-leg2.py (fake ssh, no router). Fictional MACs and documentation IPs only."""
import json
import os
from pathlib import Path
import shlex
import shutil
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
from unittest import mock  # noqa: E402


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
            with self.subTest(fields), mock.patch.object(self.tool.LEG2, 'ACK_SCAN_SECONDS', 2):
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

    def test_a_cfctl_process_alive_for_several_seconds_is_waited_for_inside_the_cancel_wait(self):
        # cron `cfctl expire` or the wrapper's timeout watcher shows /usr/sbin/cfctl for a few seconds: the old ~3 s scan
        # gave up on it, and 'busy' is final.
        self.process(41, 'timeout', '-s', 'KILL', '75', 'timeout', '-s', 'TERM', '60', '/usr/sbin/cfctl', 'expire')

        def vanish():
            time.sleep(6)
            (self.proc / '41' / 'cmdline').unlink()
        thread = threading.Thread(target=vanish)
        thread.start()
        self.assertEqual(self.ack(), 'sent')
        thread.join()
        self.assertTrue(self.target.is_file())

    def test_the_scan_window_is_constant_and_fits_inside_the_cancel_wait_and_the_ssh_timeout(self):
        leg2 = self.tool.LEG2
        # The shell has no default for CFP_LEG2_CANCEL_WAIT since T3c: penn-pilot.py passes it as a digest-bound parameter.
        wait = self.tool.LEG2_CANCEL_WAIT_SECONDS
        self.assertGreaterEqual(leg2.ACK_SCAN_SECONDS, 15)
        self.assertLess(leg2.ACK_SCAN_SECONDS, wait)
        self.assertGreater(leg2.ACK_SECONDS, leg2.ACK_SCAN_SECONDS)
        self.assertLessEqual(leg2.ACK_SECONDS, wait)
        with mock.patch.object(leg2, 'ACK_SCAN_SECONDS', 3):
            self.process(51, '/bin/sh', '/usr/sbin/cfctl', 'expire')
            begun = time.monotonic()
            self.assertEqual(self.ack(), 'busy')
            self.assertGreaterEqual(time.monotonic() - begun, 3)
            self.assertLess(time.monotonic() - begun, 3 + 4)

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


def local_busybox():
    """The busybox CF_TEST_SHELL names, else one on PATH or in ~/.local/bin; None when there is none."""
    named = shlex.split(os.environ.get('CF_TEST_SHELL', ''))
    for candidate in (named[0] if named else None, shutil.which('busybox'), str(Path.home() / '.local/bin/busybox')):
        if candidate and shutil.which(candidate):
            return shutil.which(candidate)
    return None


@unittest.skipUnless(local_busybox(), 'no busybox available locally: the ack script was only run under the host /bin/sh')
class BusyboxAckCommandTests(AckCommandTests):
    """The same ack tests under busybox ash with busybox tr, awk and sleep only: the router's semantics (tr '\\000'
    octal escape, awk exact-field match, noclobber O_EXCL refusing dangling symlinks), not the host's."""

    def setUp(self):
        super().setUp()
        busybox, bindir = local_busybox(), self.work / 'busybox-bin'
        bindir.mkdir()
        for applet in ('tr', 'awk', 'sleep'):
            (bindir / applet).symlink_to(busybox)
        self.spec['ack'].update(busybox=busybox, bindir=str(bindir))
        self.spec_path.write_text(json.dumps(self.spec))

    def test_the_busybox_applets_are_what_ran(self):
        for applet in ('tr', 'awk', 'sleep'):
            shown = subprocess.run([str(self.work / 'busybox-bin' / applet), '--help'], capture_output=True, text=True,
                                   check=False)
            self.assertIn('BusyBox', shown.stdout + shown.stderr, applet)


class SignalTests(L2.DriverBase):
    SCRIPT = '''
import importlib.util, json, os, signal, subprocess, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('penn_pilot', sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
details, env = json.load(open(sys.argv[2])), json.load(open(sys.argv[3]))
if os.environ.get('SLOW_KILL'):
    original = tool.LEG2.Leg.kill
    tool.LEG2.Leg.kill = lambda *args: (time.sleep(float(os.environ['SLOW_KILL'])), original(*args))[1]
driver = tool.LEG2.Driver(details, details['planSha256'], tool.plan_digest)
if os.environ.get('PROBE_THREAD'):  # the pilot's own host-probe thread, started before driver.run
    probes = tool.HostProbes(lambda host: {}, 'host.invalid')
    probes.start()
inject = os.environ.get('INJECT', '')
if inject == 'mask':  # a stop that lands right after the last handler is installed
    real_signal = signal.signal
    def installing(number, handler):
        old = real_signal(number, handler)
        if number == signal.SIGINT and handler is tool.LEG2.stop_now:
            os.kill(os.getpid(), signal.SIGTERM)
        return old
    signal.signal = installing
if inject.startswith('popen:'):  # a stop that lands right after the Nth child was started, before it is assigned
    real_popen, started = subprocess.Popen, []
    def popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        started.append(child)
        if len(started) == int(inject[6:]):
            open(sys.argv[4] + '.pid', 'w').write(str(child.pid))
            os.kill(os.getpid(), signal.SIGTERM)
        return child
    subprocess.Popen = popen
originals = {number: signal.getsignal(number) for number in tool.LEG2.SIGNALS}
fd = os.open(sys.argv[4], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    driver.run(b'payload\\n' * (30000 if os.environ.get('PROBE_THREAD') else 1), env, fd, fd, sys.argv[4], 60)
except KeyboardInterrupt:
    signal.signal = real_signal if inject == 'mask' else signal.signal
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, []) & set(tool.LEG2.SIGNALS)
    restored = all(signal.getsignal(number) == handler for number, handler in originals.items())
    sys.exit(7 if not blocked and restored else 9)
'''

    def run_signalled(self, signals, slow='0', threads=None, inject=None):
        threads = dict(threads or {}, INJECT=inject or '')
        self.spec_for([marker(), [0, '@wait read 1'], [60, 'END']], hang_after_read=True, child=str(self.pidfile))
        script = self.work / 'driver-child.py'
        script.write_text(self.SCRIPT)
        for name, value in (('details', self.details), ('env', self.env)):
            (self.work / f'{name}.json').write_text(json.dumps(value))
        child = subprocess.Popen([sys.executable, '-B', str(script), str(PP.SOURCE.tool_path), str(self.work / 'details.json'),
                                  str(self.work / 'env.json'), str(self.work / 'out.log')], start_new_session=True,
                                 env={'PATH': os.environ['PATH'], 'HOME': str(self.work), 'SLOW_KILL': slow, **threads})
        self.addCleanup(lambda: child.poll() is None and child.kill())
        deadline = time.monotonic() + 30
        while not inject and time.monotonic() < deadline and not (self.events_log.exists() and 'read' in self.events_log.read_text()):
            time.sleep(0.05)
        self.assertTrue(inject or (self.events_log.exists() and 'read' in self.events_log.read_text()), 'leg never read the answer')
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

    def test_a_stop_right_after_the_handlers_go_in_leaves_the_mask_and_the_handlers_as_they_were(self):
        self.run_signalled([], inject='mask')  # exit 9 when SIGNALS stay blocked or a handler is not restored

    def test_a_stop_right_after_a_child_started_cannot_orphan_it(self):
        for nth in (1, 2):
            with self.subTest(child=nth):
                self.run_signalled([], inject=f'popen:{nth}')
                started = int((self.work / 'out.log.pid').read_text())
                self.assertTrue(wait_dead(started), f'child {nth} (pid {started}) was left running')
                self.assertTrue(wait_dead(int(self.leg1_pid.read_text())) if self.leg1_pid.exists() else True)

    @staticmethod
    def blocked_signals(thread):
        """The stop signals a thread blocks (its kernel mask), after giving it a moment to run its first action."""
        wanted = {signal.SIGTERM, signal.SIGHUP, signal.SIGINT}
        deadline = time.monotonic() + 3
        while True:
            line = next(row for row in Path(f'/proc/self/task/{thread.native_id}/status').read_text().splitlines()
                        if row.startswith('SigBlk:'))
            mask = int(line.split()[1], 16)
            found = {number for number in wanted if mask >> (number - 1) & 1}
            if found == wanted or time.monotonic() > deadline:
                return found
            time.sleep(0.05)

    def test_every_helper_thread_blocks_the_stop_signals_as_its_first_action(self):
        wanted = {signal.SIGTERM, signal.SIGHUP, signal.SIGINT}
        probes = self.tool.HostProbes(lambda host: {}, 'host.invalid')
        probes.start()
        self.addCleanup(probes.stop)
        self.assertEqual(self.blocked_signals(probes.thread), wanted, 'host-probe thread')
        read_end, write_end = os.pipe()  # nobody reads: the 1 MiB payload keeps the feeder blocked in its write
        stream = os.fdopen(write_end, 'wb')
        feeder = threading.Thread(target=self.tool.LEG2.feed, args=(stream, b'x' * (1 << 20)), daemon=True)
        feeder.start()
        self.assertEqual(self.blocked_signals(feeder), wanted, 'payload feeder thread')
        os.close(read_end)
        feeder.join(10)

    def test_a_second_signal_cannot_reach_the_cleanup_through_a_helper_thread(self):
        # A process-wide signal goes to any thread that does not block it, and CPython then runs the handler in the
        # main thread: with a host-probe thread and a payload (240 KB) bigger than the pipe, the payload feeder is
        # still writing. Neither may leave a signal for the main thread between the leg kill and the leg-1 kill.
        self.run_signalled([signal.SIGTERM, signal.SIGTERM, signal.SIGHUP], slow='2', threads={'PROBE_THREAD': '1'})
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
                                (0, 'timeout -s KILL 999 timeout -s TERM 984 /usr/sbin/cfctl scope-add {MAC} --base {BASE}'),
                                (0, 'timeout -s TERM %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % LEG_SECONDS),
                                # the pre-fix shape: a bare KILL skips cfctl's EXIT/HUP/TERM traps
                                (0, 'timeout -s KILL %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % LEG_SECONDS),
                                (0, 'timeout -s KILL %d timeout -s TERM %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % (LEG_SECONDS + 14, LEG_SECONDS)),
                                (0, 'timeout -s KILL %d timeout -s TERM %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % (LEG_SECONDS + 16, LEG_SECONDS)),
                                (0, 'timeout -s KILL %d timeout -s TERM %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % (LEG_SECONDS, LEG_SECONDS)),
                                (0, 'timeout -s TERM %d timeout -s KILL %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % (LEG_SECONDS + 15, LEG_SECONDS)),
                                (0, 'timeout -s KILL %d timeout -s KILL %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % (LEG_SECONDS + 15, LEG_SECONDS)),
                                (0, 'timeout -s KILL 0%d timeout -s TERM %d /usr/sbin/cfctl scope-add {MAC} --base {BASE}' % (LEG_SECONDS + 15, LEG_SECONDS))):
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

    def test_the_kill_grace_of_the_nested_timeouts_is_the_same_in_the_plan_and_the_driver(self):
        self.assertEqual(self.tool.V2.SCOPE_LEG_KILL_GRACE_SECONDS, self.tool.LEG2.LEG_KILL_GRACE_SECONDS)
        for leg in self.details['legs']:
            self.assertTrue(leg['commandTemplate'].startswith(BOUND), leg['commandTemplate'])

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
