#!/usr/bin/env python3
"""M4b INSTALL watchdog, end to end in the fixture (design .omc/plans/m4b-watchdog-design-20261025.md, D-W1=A).

Each row runs the real `execute` path: the host tool, the fake ssh, the real rehearsal shell with its real `cfp_run`
supervisor and the real router/install.sh in an isolated fixture root. The install is held at one transaction barrier
(a FIFO that is never released) until the watchdog fires. TERM rows let install.sh's own traps run; KILL rows make
install.sh's cleanup block in a TERM-ignoring `rm` so the watchdog has to KILL the group. Then the test plays the
operator: `cfctl recover-install-lock` and ONE ordinary uninstall.sh, and the fixture router must equal its snapshot
from before the run (files, modes, mtimes, firewall tables and sets), with no lock and no process left.

Passing proves neither target timing, BusyBox-on-router behaviour, power loss, hardware faults nor processes stuck in
uninterruptible I/O (which can defer even a KILL).
"""
import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import sys
import threading
import time
import unittest

REPO = Path(__file__).resolve().parents[1]


def _load(name, path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TLR = _load('test_live_rehearsal', REPO / 'tests/test-live-rehearsal.py')
# Short watchdog bounds for the fixture. The allowance must exceed the fixture install's time to its latest barrier
# under CI load (the hold is never released, so a longer allowance only costs wall time).
ALLOWANCE = 40
GRACE = 3
# Files the watchdog must never touch (password login and dropbear stay intact).
PASSWORD_PATHS = {'etc/shadow': b'root:$1$fixture$hash:19000:0:99999:7:::\n',
                  'etc/config/dropbear': b"config dropbear\n\toption PasswordAuth 'on'\n\toption RootPasswordAuth 'on'\n",
                  'etc/dropbear/authorized_keys': b'ssh-ed25519 AAAAfixture admin\n'}
HANG = '.hang-rm'


def setUpModule():
    TLR.setUpModule()


def tearDownModule():
    TLR.tearDownModule()


def load_tests(loader, tests, pattern):
    # Only this module's rows: the inherited rehearsal rows run in test-live-rehearsal.py.
    names = sorted(name for name in InstallWatchdogFixtureTests.__dict__ if name.startswith('test_'))
    return unittest.TestSuite(InstallWatchdogFixtureTests(name) for name in names)


class InstallWatchdogFixtureTests(TLR.LiveRehearsalTests):
    def setUp(self):
        super().setUp()
        tool = self.tool
        saved = (tool.INSTALL_ALLOWANCE_SECONDS, tool.KILL_GRACE_SECONDS)
        tool.INSTALL_ALLOWANCE_SECONDS, tool.KILL_GRACE_SECONDS = ALLOWANCE, GRACE
        self.addCleanup(setattr, tool, 'INSTALL_ALLOWANCE_SECONDS', saved[0])
        self.addCleanup(setattr, tool, 'KILL_GRACE_SECONDS', saved[1])
        for rel, content in PASSWORD_PATHS.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o600)
        self.hang_rm_stub()
        self.addCleanup(self.assert_no_fixture_process)

    def hang_rm_stub(self):
        """`rm` whose first call after arming ignores TERM and never returns. install.sh's EXIT cleanup starts with
        `rm` (journal rollback, stage files) before it releases the install lock, so a KILL row leaves the harshest
        residual of its phase: install lock, active owner and whatever the phase built."""
        real = shutil.which('rm')
        stub = self.fixture.bin / 'rm'
        # Only install.sh's own call hangs: the rehearsal shell's `rm` (its stop and cleanup) must run normally.
        stub.write_text('#!/bin/sh\nif [ -e "$CF_ROOT/' + HANG + '" ] && tr "\\0" " " < /proc/$PPID/cmdline | grep -q "/router/install\\.sh" '
                        '&& mkdir "$CF_ROOT/' + HANG + '.once" 2>/dev/null; then\n'
                        '    trap "" TERM\n    while :; do sleep 1; done\nfi\nexec ' + shlex.quote(real) + ' "$@"\n')
        stub.chmod(0o700)

    def router_snapshot(self):
        files, tables, sets = super().router_snapshot()
        return {rel: value for rel, value in files.items() if not rel.startswith(('.barrier-', HANG))}, tables, sets

    def fixture_processes(self):
        found = []
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                environ = (entry / 'environ').read_bytes().split(b'\0')
            except OSError:
                continue
            if ('CF_ROOT=' + str(self.root)).encode() in environ:
                found.append(int(entry.name))
        return found

    def assert_no_fixture_process(self):
        deadline = time.monotonic() + 5
        while self.fixture_processes() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertEqual(self.fixture_processes(), [], 'a process of the supervised install outlived the watchdog')

    def hold(self, point, kill):
        """Hold the install at `point` forever; for a KILL row arm the hanging rm once the barrier is entered."""
        streams = []
        for suffix in ('entered', 'release'):
            path = self.root / f'.barrier-{point}.{suffix}'
            os.mkfifo(path, 0o600)
            streams.append(os.fdopen(os.open(path, os.O_RDWR | os.O_NONBLOCK), 'r+b', buffering=0))
            self.addCleanup(streams[-1].close)
            self.addCleanup(path.unlink, True)
        self.spec['env']['CF_TEST_TRANSACTION_BARRIER'] = point
        self.entered = None

        def watch():
            ready, _, _ = select.select([streams[0]], [], [], ALLOWANCE + GRACE + 120)
            if ready:
                self.entered = time.monotonic()
                if kill:
                    (self.root / HANG).touch()
        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        return watcher

    def run_held(self, point, kill=False):
        before = self.router_snapshot()
        watcher = self.hold(point, kill)
        started = time.monotonic()
        code, out, err = self.execute()
        elapsed = time.monotonic() - started
        watcher.join(1)
        (self.root / HANG).unlink(missing_ok=True)
        shutil.rmtree(self.root / (HANG + '.once'), ignore_errors=True)
        self.spec['env'].pop('CF_TEST_TRANSACTION_BARRIER')
        self.assertIsNotNone(self.entered, f'the install never reached {point} before the allowance (load?)')
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertIn('MUTATION_BEGIN', stdout)
        self.assertNotIn('PHASE INSTALL OK', stdout)
        self.assertNotIn('PHASE VERIFY', stdout)
        staging = next(line.split(' ', 2)[2] for line in stdout.splitlines() if line.startswith('INFO staging '))
        self.assertFalse(Path(staging).exists(), 'the stage directory is removed on every watchdog outcome')
        return before, code, out + err, stdout, elapsed

    def recovery_env(self):
        return {k: v for k, v in self.spec['env'].items() if k != 'CF_TEST_TRANSACTION_BARRIER'}

    def router_command(self, name, *args):
        release = sorted(self.root.glob('etc/.couvrefeu-release-*'))
        source = release[0] if release and (release[0] / name).is_file() else TLR.SOURCE.root / 'router'
        shell = shlex.split(self.spec['shell'])
        return subprocess.run(shell + [str(source / name), *args], env=self.recovery_env(), stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120, check=False, start_new_session=True)

    def operator_recovers(self, before, recover=True):
        """The runbook flow from a password shell: recover-install-lock (when a lock or owner is left), then ONE
        ordinary uninstall.sh; the fixture router must then equal its snapshot from before the run."""
        if recover:
            recovered = self.router_command('cfctl', 'recover-install-lock')
            self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
            self.assertTrue(json.loads(recovered.stdout)['ok'], recovered.stdout)
        uninstalled = self.router_command('uninstall.sh')
        self.assertEqual(uninstalled.returncode, 0, uninstalled.stdout + uninstalled.stderr)
        self.assert_restored(before)

    def assert_restored(self, before):
        self.assertEqual(self.router_snapshot(), before)
        for name in ('.couvrefeu-install.lock', 'etc/couvrefeu/runtime/lock', '.couvrefeu-transaction',
                     '.couvrefeu-prepared', '.couvrefeu-recovery-required', '.couvrefeu-retirement'):
            self.assertFalse((self.root / name).exists(), name)
        for rel, content in PASSWORD_PATHS.items():
            self.assertEqual((self.root / rel).read_bytes(), content, rel)

    def assert_killed(self, code, output, stdout, elapsed):
        self.assertEqual(code, 2, output)
        self.assertIn('PHASE INSTALL FAIL install_timeout_killed', stdout)
        self.assertIn('INFO install_timeout state install_lock=', stdout)
        self.assertIn('cfctl recover-install-lock', stdout)
        self.assertNotIn('run uninstall.sh', stdout)
        self.assertEqual(stdout.splitlines()[-1], 'FAIL_AFTER_MUTATION INSTALL')
        self.assertGreaterEqual(elapsed, ALLOWANCE + GRACE)
        self.assertLess(elapsed, ALLOWANCE + GRACE + 60)

    def assert_term_honoured(self, stdout, elapsed):
        self.assertIn('PHASE INSTALL FAIL install_timeout', stdout)
        self.assertNotIn('install_timeout_killed', stdout)
        self.assertGreaterEqual(elapsed, ALLOWANCE)
        # TERM to exit of install.sh's cleanup (the grace acceptance): well inside the KILL grace.
        self.assertLess(elapsed, ALLOWANCE + GRACE + 60)

    # -- TERM honoured: install.sh's traps run -------------------------------------------------------------------
    def test_term_at_ownership_published_pre_lock(self):
        before, code, output, stdout, elapsed = self.run_held('ownership-published')
        self.report_term_row(before, code, output, stdout, elapsed)

    def test_term_with_the_lock_held_before_the_journal(self):
        before, code, output, stdout, elapsed = self.run_held('prepared')
        self.report_term_row(before, code, output, stdout, elapsed)

    def test_term_with_the_journal_ready_before_apply(self):
        before, code, output, stdout, elapsed = self.run_held('intent')
        self.report_term_row(before, code, output, stdout, elapsed)

    def test_term_after_apply_before_verify(self):
        before, code, output, stdout, elapsed = self.run_held('complete-published')
        self.report_term_row(before, code, output, stdout, elapsed)

    def report_term_row(self, before, code, output, stdout, elapsed):
        self.assert_term_honoured(stdout, elapsed)
        if 'run uninstall.sh once' in stdout:
            # Clean TERM: the single teardown ran in-session and restored the router.
            self.assertEqual(stdout.count('run uninstall.sh once'), 1)
            self.assertIn('PHASE UNINSTALL OK', stdout)
            self.assertIn('PHASE RESTORE OK', stdout)
            self.assertEqual(code, 2, output)
            self.assertEqual(stdout.splitlines()[-1], 'FAIL_AFTER_MUTATION summary')
            self.assert_restored(before)
        else:
            # TERM honoured but no installed release to tear down with: STOP, then the operator's ONE uninstall.
            self.assertEqual(code, 2, output)
            self.assertIn('no installed uninstall.sh; uninstall not attempted', stdout)
            self.assertEqual(stdout.splitlines()[-1], 'FAIL_AFTER_MUTATION INSTALL')
            self.operator_recovers(before, recover=False)

    # -- KILL: install.sh's cleanup is blocked, the group is KILLed -----------------------------------------------
    def test_kill_at_ownership_published_pre_lock(self):
        before, code, output, stdout, elapsed = self.run_held('ownership-published', kill=True)
        self.assert_killed(code, output, stdout, elapsed)
        self.assertIn('owner=active', stdout)
        self.operator_recovers(before)

    def test_kill_with_the_lock_held_before_the_journal(self):
        before, code, output, stdout, elapsed = self.run_held('prepared', kill=True)
        self.assert_killed(code, output, stdout, elapsed)
        self.assertIn('install_lock=present', stdout)
        self.assertIn('owner=active', stdout)
        self.operator_recovers(before)

    def test_kill_with_the_journal_ready_before_apply(self):
        before, code, output, stdout, elapsed = self.run_held('intent', kill=True)
        self.assert_killed(code, output, stdout, elapsed)
        self.assertIn('install_lock=present', stdout)
        self.assertIn('journal=ready', stdout)
        self.operator_recovers(before)

    def test_kill_after_apply_before_verify(self):
        before, code, output, stdout, elapsed = self.run_held('complete-published', kill=True)
        self.assert_killed(code, output, stdout, elapsed)
        self.assertIn('install_lock=present', stdout)
        self.operator_recovers(before)


    # -- the operator's recovery is itself interrupted, and the session is lost -----------------------------------
    def test_a_killed_recovery_is_retried_then_one_uninstall_restores(self):
        before, code, output, stdout, elapsed = self.run_held('prepared', kill=True)
        self.assert_killed(code, output, stdout, elapsed)
        # recover-install-lock is KILLed at its own barrier (after validation, before it retires anything).
        point = 'recovery-validated'
        streams = []
        for suffix in ('entered', 'release'):
            path = self.root / f'.barrier-{point}.{suffix}'
            os.mkfifo(path, 0o600)
            streams.append(os.fdopen(os.open(path, os.O_RDWR | os.O_NONBLOCK), 'r+b', buffering=0))
            self.addCleanup(streams[-1].close)
            self.addCleanup(path.unlink, True)
        release = sorted(self.root.glob('etc/.couvrefeu-release-*'))
        source = release[0] if release else TLR.SOURCE.root / 'router'
        env = dict(self.recovery_env(), CF_TEST_TRANSACTION_BARRIER=point)
        recovery = subprocess.Popen(shlex.split(self.spec['shell']) + [str(source / 'cfctl'), 'recover-install-lock'],
                                    env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
        ready, _, _ = select.select([streams[0]], [], [], 120)
        self.assertTrue(ready, 'recover-install-lock never reached its barrier')
        os.killpg(recovery.pid, 9)
        recovery.wait(10)
        self.operator_recovers(before)

    def test_an_unreachable_router_still_ends_bounded_and_keeps_the_unknown_rule(self):
        self.spec['hangup_after'] = 'MUTATION_BEGIN'
        before = self.router_snapshot()
        self.hold('prepared', kill=True)
        started = time.monotonic()
        code, out, err = self.execute(cleanup=False)
        self.assertEqual(code, 2, out + err)
        self.assertEqual(json.loads((self.evidence() / 'summary.json').read_text())['outcome'], 'UNKNOWN')
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        stage = Path(next(line.split(' ', 2)[2] for line in stdout if line.startswith('INFO staging ')))
        self.addCleanup(shutil.rmtree, stage, True)
        # The router side lives on (HUP ignored) and the watchdog bounds it: wait for the retained phase log.
        phase_log = stage / 'phase.log'
        deadline = started + ALLOWANCE + GRACE + 120
        while time.monotonic() < deadline and 'STAGE_RETAINED' not in (phase_log.read_text() if phase_log.exists() else ''):
            time.sleep(0.5)
        log = phase_log.read_text().splitlines()
        self.assertIn('STAGE_RETAINED ' + str(stage), log)
        self.assertTrue(any(line.startswith('PHASE INSTALL FAIL install_timeout_killed') for line in log), log)
        self.assertEqual(log[-2], 'FAIL_AFTER_MUTATION INSTALL')
        self.assertFalse(any(line.startswith('INFO run uninstall.sh') for line in log))
        (self.root / HANG).unlink(missing_ok=True)
        shutil.rmtree(self.root / (HANG + '.once'), ignore_errors=True)
        self.spec['env'].pop('CF_TEST_TRANSACTION_BARRIER')
        # Then (runbook): a separately approved read-only inspection, and the operator flow from a password shell.
        self.operator_recovers(before)


if __name__ == '__main__':
    unittest.main()
