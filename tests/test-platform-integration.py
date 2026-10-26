#!/usr/bin/env python3
"""Native ash integration fixtures. No root writes, vendor payload or live router.

Vendor adapter fixtures substitute the pinned payload/attestation boundary,
inside an independently generated private module. Direct native helper fixtures
also cover bounded comm parsing and credential classification. Other adapter
fixtures measure admission call counts, serialization and cleanup ordering;
none establish actual platform trust or router latency.
"""
import fcntl
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import tarfile
import sys
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
BB = shutil.which('busybox')
if not BB and not os.environ.get('CF_TEST_SHELL'):
    raise SystemExit('Native BusyBox ash required: set CF_TEST_SHELL to its absolute binary and ash')
SHELL = shlex.split(os.environ.get('CF_TEST_SHELL', (BB or '') + ' ash'))
PROFILE = 'gl-xe3000-4.8.3-logd-011-v1'
spec = importlib.util.spec_from_file_location('install_fixtures', REPO / 'tests/test-install.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class StrictEntryTests(unittest.TestCase):
    def setUp(self):
        self.expected_profile = 'strict'
        self.tmp = tempfile.TemporaryDirectory(prefix='couvre-feu-platform-entry-')
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ, CF_TEST_MODE='1', CF_ROOT=str(self.root))
        for key in ['SSH_CONNECTION', 'SSH_CLIENT', 'LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT']:
            self.env.pop(key, None)
        self.source = self.root / 'release'
        shutil.copytree(REPO / 'router', self.source)
        self.backend = self.root / 'backend'
        self.backend.mkdir(mode=0o700)
        (self.backend / '.couvrefeu-test-backend').touch()
        for name in ['iptables', 'ip6tables', 'ipset', 'uci', 'conntrack', 'ip', 'fw3', 'sync']:
            p = self.backend / name
            p.write_text('#!/bin/sh\nexit 0\n')
            p.chmod(0o700)
        self.env['CF_BACKEND_DIR'] = str(self.backend)

    def tearDown(self):
        self.tmp.cleanup()

    def run_entry(self, name='install.sh', args=(), env=None):
        return subprocess.run(SHELL + [str(self.source / name), *args], env=env or self.env, capture_output=True, text=True)

    def install(self):
        result = self.run_entry(args=['--protect', '02:00:00:00:00:01', '--activate'])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_strict_first_install_uses_verified_source_modules(self):
        self.assertFalse((self.root / 'usr/lib/couvrefeu').exists())
        self.install()
        self.assertEqual((self.root / 'etc/couvrefeu/platform-profile').read_bytes(), b'strict\n')
        self.assertIn(str('platform-bootstrap.sh'), (self.root / 'etc/couvrefeu/backup/usr_lib_couvrefeu_platform-bootstrap.sh.after').name)
        self.assertIn('/etc/.couvrefeu-release-', (self.root / 'etc/sysupgrade.conf').read_text())
        result = self.run_entry('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'etc/couvrefeu').exists())
        self.assertFalse((self.root / '.couvrefeu-recovery.done').exists())

    def test_actual_scoped_activation_preserves_scope_inventory_and_restoration(self):
        args=['--protect','02:00:00:00:00:aa','--rpc-allow','02:00:00:00:00:01','--activate']
        result=self.run_entry(args=args)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        private=self.root/'etc/couvrefeu'
        self.assertEqual((private/'rpc-allowed').read_bytes(),b'02:00:00:00:00:01\n')
        self.assertTrue((private/'backup/etc_couvrefeu_rpc-allowed.after').exists())
        self.assertIn(b'X\t1\nG\t',(private/'state').read_bytes())
        result=self.run_entry('uninstall.sh')
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        self.assertFalse(private.exists())

    def test_environment_cannot_supply_admission_or_pins(self):
        for key in ['CF_PLATFORM_ADMITTED', 'CF_PLATFORM_PROFILE', 'CF_PLATFORM_LOCKED', 'CF_PLATFORM_NESTED', 'CF_PLATFORM_CALLER_PID', 'CF_PLATFORM_OWNER', 'CF_PLATFORM_LIB', 'CF_RELEASE_ID', 'CF_RELEASE_MODULES', 'CF_VENDOR_PROFILE', 'CF_OS_TRUST_PROFILE', 'CF_PLATFORM_ENTRY_TICK', 'CF_PLATFORM_INITIAL_WRITE', 'vp_profile', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT']:
            with self.subTest(key=key):
                result = self.run_entry(args=['--protect', '02:00:00:00:00:01', '--activate'], env=dict(self.env, **{key:'injected'}))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'etc/couvrefeu').exists())

    def test_fixture_flags_refuse_real_root_before_platform_bootstrap(self):
        # A copied and freshly pinned inert bootstrap records any entry into the
        # vendor payload boundary. Invalid fixture flags must precede that call.
        marker = self.root / 'bootstrap-entered'
        bootstrap = self.source / 'lib/platform-bootstrap.sh'
        source = bootstrap.read_text()
        start = source.index('platform_bootstrap_vendor() {')
        stop = source.index('platform_verify_modules()', start)
        source = source[:start] + f'platform_bootstrap_vendor() {{ touch "{marker}"; exit 99; }}\n' + source[stop:]
        bootstrap.write_text(source)
        compiler = (REPO / 'tools/freeze-router-release.py').read_text().replace("Path(__file__).resolve().parent / 'strip-test-mode.py'", 'Path(' + repr(str(REPO / 'tools/strip-test-mode.py')) + ')').replace("router = Path(__file__).resolve().parents[1] / 'router'", 'router = Path(' + repr(str(self.source)) + ')')
        subprocess.run(['python3', '-c', compiler], check=True, capture_output=True)
        for mode, root in [('1', '/'), ('1', '/tmp'), ('2', str(self.root)), ('0', str(self.root))]:
            for name in ['install.sh', 'uninstall.sh']:
                args = ['--platform-profile', PROFILE] if name == 'install.sh' else []
                result = self.run_entry(name, args=args, env=dict(self.env, CF_TEST_MODE=mode, CF_ROOT=root))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())

    def test_substituted_source_refuses_before_managed_changes(self):
        (self.source / 'lib/core.sh').write_text('exit 0\n')
        result = self.run_entry(args=['--protect', '02:00:00:00:00:01', '--activate'])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'etc/couvrefeu').exists())

    def test_unknown_duplicate_and_changed_selection_refuse(self):
        for args in [['--platform-profile', 'unknown'], ['--platform-profile', 'strict', '--platform-profile', 'strict']]:
            self.assertNotEqual(self.run_entry(args=args).returncode, 0)
        self.install()
        profile = self.root / 'etc/couvrefeu/platform-profile'
        for content in [b'strict\n\n', b'strict\x00\n', b'strict\n'+b'\n'*1048576, b'strict\n'+b'\x00'*1048576, (PROFILE+'\n').encode()]:
            profile.write_bytes(content)
            self.assertNotEqual(self.run_entry('uninstall.sh').returncode, 0)
            self.assertTrue((self.root / 'etc/couvrefeu/backup').exists())

    def test_private_profile_metadata_refuses(self):
        self.install()
        profile = self.root / 'etc/couvrefeu/platform-profile'
        profile.chmod(0o640)
        self.assertNotEqual(self.run_entry('uninstall.sh').returncode, 0)
        self.assertTrue((self.root / 'etc/couvrefeu/backup').exists())

    def test_completion_fifo_and_symlink_fifo_refuse_before_attestation(self):
        done = self.root / '.couvrefeu-recovery.done'
        fifo = self.root / 'completion-pipe'
        os.mkfifo(fifo, 0o600)
        for symlink in [False, True]:
            with self.subTest(symlink=symlink):
                if symlink: done.symlink_to(fifo)
                else: os.mkfifo(done, 0o600)
                result = subprocess.run(SHELL+[str(self.source/'uninstall.sh')],
                    env=self.env, capture_output=True, text=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('regular_file', result.stderr)
                self.assertFalse((self.root/'.couvrefeu-install.lock').exists())
                self.assertTrue(done.is_symlink() or done.exists())
                done.unlink()

    def test_scoped_done3_survives_each_cleanup_delete_and_restores_exact_original(self):
        private = self.root/'etc/couvrefeu'
        private.mkdir(parents=True, mode=0o700)
        scope = private/'rpc-allowed'
        scope.write_bytes(b'02:00:00:00:00:09\n'); scope.chmod(0o600)
        original = fixtures.exact_signature(scope)
        args=['--protect','02:00:00:00:00:aa','--rpc-allow','02:00:00:00:00:01','--activate']
        # Reuse the complete deletion-boundary proof with actual scoped install.
        def scoped_install():
            result=self.run_entry(args=args)
            self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        self.install=scoped_install
        # The original private directory remains after exact restoration.
        self._cleanup_boundary_proof(expect_base=True)
        self.assertEqual(scope.read_bytes(), b'02:00:00:00:00:09\n')
        self.assertEqual(fixtures.exact_signature(scope), original)

    def test_done_binding_survives_every_cleanup_boundary(self):
        self._cleanup_boundary_proof()

    def _cleanup_boundary_proof(self, expect_base=False):
        # These are exact restoration transactions with actual source modules.
        # Every deletion position includes staged profile and both new helpers.
        self.install()
        result = self.run_entry('uninstall.sh', env=dict(self.env, CF_TEST_UNINSTALL_CLEANUP_FAIL_AFTER='1'))
        self.assertNotEqual(result.returncode, 0)
        done = self.root / '.couvrefeu-recovery.done'
        self.assertTrue(done.exists())
        self.assertEqual(done.read_text().splitlines()[:2], ['3', self.expected_profile])
        self.assertEqual(done.stat().st_mode & 0o777, 0o600)
        recovery = self.root / '.couvrefeu-recovery'
        # Resume the actual cleanup once per surviving entry. DONE must survive
        # deletion of the helper/profile records and the final journal removal.
        while recovery.exists() and list(recovery.iterdir()):
            previous = len(list(recovery.iterdir()))
            result = self.run_entry('uninstall.sh', env=dict(self.env, CF_TEST_UNINSTALL_CLEANUP_FAIL_AFTER='1'))
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertTrue(done.exists())
            self.assertLess(len(list(recovery.iterdir())), previous, result.stderr)
        result = self.run_entry('uninstall.sh', env=dict(self.env, CF_TEST_UNINSTALL_CLEANUP_FAIL_AT='journal'))
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertFalse(recovery.exists())
        self.assertTrue(done.exists())
        result = self.run_entry('uninstall.sh', env=dict(self.env, CF_TEST_UNINSTALL_CLEANUP_FAIL_AT='done'))
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertTrue(done.exists())
        self.assertFalse((self.root / '.couvrefeu-install.lock').exists())
        self.assertEqual(self.run_entry('uninstall.sh').returncode, 0)
        self.assertFalse(done.exists())
        self.assertEqual((self.root / 'etc/couvrefeu').exists(), expect_base)

    def test_completion_profile_and_release_conflict_refuse(self):
        self.install()
        self.run_entry('uninstall.sh', env=dict(self.env, CF_TEST_UNINSTALL_CLEANUP_FAIL_AT='journal'))
        done = self.root / '.couvrefeu-recovery.done'
        lines = done.read_text().splitlines()
        for tail in [b'\n'*1048576,b'\x00'*1048576]:
            done.write_bytes(('\n'.join(lines)+'\n').encode()+tail)
            self.assertNotEqual(self.run_entry('uninstall.sh').returncode,0)
            self.assertTrue(done.exists())
        for replacement in [['3', PROFILE, lines[2]], ['3', 'strict', '0'*64], ['2', 'strict', lines[2]]]:
            done.write_text('\n'.join(replacement)+'\n')
            self.assertNotEqual(self.run_entry('uninstall.sh').returncode, 0)
            self.assertTrue(done.exists())

    def _session_fds(self, sid):
        # Every fd of every process in the stalled command's session (cfctl, timeout, dd).
        targets = set()
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                if os.getsid(int(proc.name)) != sid:
                    continue
                for fd in (proc / 'fd').iterdir():
                    try:
                        info = fd.stat()
                        targets.add((info.st_dev, info.st_ino))
                    except OSError:
                        pass
            except OSError:
                pass
        return targets

    def test_open_stdin_sync_holds_no_lock_and_expire_proceeds(self):
        # Behavioural: real installed cfctl, EOF withheld, under this class's profile.
        self.install()
        tmp = self.root / 'tmp'
        tmp.mkdir(exist_ok=True)
        tmp.chmod(0o1777)  # Unconditional: a pre-existing tmp must also be the sticky stand-in.
        cfctl = str(self.root / 'usr/sbin/cfctl')
        baseline = subprocess.run(SHELL + [cfctl, 'expire'], env=self.env, capture_output=True, text=True, timeout=60)
        baseline_errors = json.loads(baseline.stdout)['errors']
        # Only lock-free work reaches this backend error: expire got past every lock.
        self.assertIn('invalid_lan_address', baseline_errors, baseline.stdout + baseline.stderr)
        mutex = (self.root / '.couvrefeu-mutex').stat()
        # Negative control: a held transaction mutex that creates none of the named lock
        # files must make expire diverge from baseline, so the equality below discriminates.
        with open(self.root / '.couvrefeu-mutex', 'rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            contended = subprocess.run(SHELL + [cfctl, 'expire'], env=self.env, capture_output=True,
                                       text=True, timeout=60)
        self.assertNotEqual((contended.returncode, contended.stdout), (baseline.returncode, baseline.stdout),
                            contended.stdout + contended.stderr)
        self.assertIn('transaction_contention', contended.stdout + contended.stderr)
        for command in ('sync', 'rpc-sync'):
            with self.subTest(command=command):
                child = subprocess.Popen(SHELL + [cfctl, command], env=self.env, stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                         start_new_session=True)
                try:
                    child.stdin.write('{"version":1')
                    child.stdin.flush()  # EOF withheld.
                    deadline = time.monotonic() + 8
                    staged = []
                    while not staged:
                        self.assertIsNone(child.poll(), 'stalled command exited before staging')
                        self.assertLess(time.monotonic(), deadline, 'stdin stage never began')
                        staged = [p for p in tmp.iterdir() if p.name.startswith('couvrefeu-input.')
                                  and (p / 'input').exists() and (p / 'input').stat().st_size]
                        time.sleep(0.01)
                    for lock in ('tmp/couvrefeu-platform.lock', 'etc/couvrefeu/runtime/lock',
                                 '.couvrefeu-install.lock'):
                        self.assertFalse((self.root / lock).exists(), lock)
                    self.assertNotIn((mutex.st_dev, mutex.st_ino), self._session_fds(child.pid),
                                     'stalled stdin holds the transaction mutex')
                    # Liveness is sampled as expire starts: the stall has only a 10s input
                    # deadline, which a loaded host may outlast during expire itself.
                    self.assertIsNone(child.poll(), 'stalled command exited before expire started')
                    expire = subprocess.run(SHELL + [cfctl, 'expire'], env=self.env, capture_output=True,
                                            text=True, timeout=60)
                    self.assertEqual(json.loads(expire.stdout)['errors'], baseline_errors, expire.stdout + expire.stderr)
                    self.assertEqual(expire.returncode, baseline.returncode)
                    if child.poll() is not None:
                        # Exited meanwhile: only the stalled stdin's own input deadline is acceptable.
                        out, err = child.communicate(timeout=10)
                        self.assertIn('input_deadline_or_read_failure', out + err)
                finally:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                    child.communicate(timeout=10)


class VendorRecoveryTests(unittest.TestCase):
    # Same actual uninstall/restoration/cleanup code, with an explicitly private
    # inert platform boundary. This also proves selection after profile removal.
    tearDown = StrictEntryTests.tearDown
    run_entry = StrictEntryTests.run_entry
    test_done_binding_survives_every_cleanup_boundary = StrictEntryTests.test_done_binding_survives_every_cleanup_boundary
    _cleanup_boundary_proof = StrictEntryTests._cleanup_boundary_proof
    test_completion_fifo_and_symlink_fifo_refuse_before_attestation = StrictEntryTests.test_completion_fifo_and_symlink_fifo_refuse_before_attestation
    _session_fds = StrictEntryTests._session_fds
    test_open_stdin_sync_holds_no_lock_and_expire_proceeds = StrictEntryTests.test_open_stdin_sync_holds_no_lock_and_expire_proceeds

    def setUp(self):
        StrictEntryTests.setUp(self)
        self.expected_profile = PROFILE
        tmp = self.root / 'tmp'
        tmp.mkdir(mode=0o1777); tmp.chmod(0o1777)
        bootstrap = self.source / 'lib/platform-bootstrap.sh'
        source = bootstrap.read_text()
        start = source.index('platform_bootstrap_vendor() {')
        stop = source.index('platform_verify_modules()', start)
        source = source[:start] + 'platform_bootstrap_vendor() { :; }\n' + source[stop:]
        source = source.replace('/tmp/couvrefeu-platform.lock', str(tmp / 'couvrefeu-platform.lock'))
        source = source.replace("'%u:%g:%a' /tmp)", "'%u:%g:%a' " + str(tmp) + ')').replace('0:0:1777', f'{os.getuid()}:{os.getgid()}:1777')
        source = source.replace('        vp_transaction_check >/dev/null', '        vp_transaction_check() { return 0; }; vp_transaction_check >/dev/null')
        bootstrap.write_text(source)
        compiler = (REPO / 'tools/freeze-router-release.py').read_text()
        compiler = compiler.replace("Path(__file__).resolve().parent / 'strip-test-mode.py'", 'Path(' + repr(str(REPO / 'tools/strip-test-mode.py')) + ')').replace("router = Path(__file__).resolve().parents[1] / 'router'", 'router = Path(' + repr(str(self.source)) + ')')
        result = subprocess.run(['python3', '-c', compiler], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def install(self):
        result = self.run_entry(args=['--platform-profile', PROFILE, '--protect', '02:00:00:00:00:01', '--activate'])
        self.assertEqual(result.returncode, 0, result.stderr)


class SyntheticLegacyDowngradeRefusalTests(unittest.TestCase):
    """A new digest-bound install cannot be rewritten into a legacy journal.

    Genuine historical byte restoration is covered separately by the pinned,
    inert test-install-legacy-recovery.py fixture. These deliberately conflicting
    states must preserve every byte and backend object on refusal.
    """
    def setUp(self):
        sys.path.insert(0, str(REPO / 'tests/fixtures'))
        from harness import RouterFixture, PROTECTED
        self.fixture = RouterFixture()
        self.root = self.fixture.root
        private = self.root / 'etc/couvrefeu'
        (private/'state').unlink(); (private/'protected').unlink(); private.rmdir()
        self.firewall = self.root / 'etc/config/firewall'
        self.original = fixtures.exact_signature(self.firewall)
        self.current = self.root / 'immutable-current-release'
        shutil.copytree(REPO/'router', self.current)
        self.current.chmod(0o700); (self.current/'lib').chmod(0o700)
        self.fixture.env['CF_TEST_INSTALL_KERNEL'] = '1'
        options=['--activate','--protect',PROTECTED]
        if self._testMethodName == 'test_scoped_downgrade_refuses_before_cleanup':
            options += ['--rpc-allow','02:00:00:00:00:01']
        result = self.command('install.sh', *options)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(self.fixture.backend()['sets'], 'owned kernel objects must exist')
        crond = self.fixture.backend()['crond']
        self.assertTrue(crond['running'])
        expiry_lines = [line for line in crond['tables']['root'].splitlines()
                        if line.startswith('* * * * * ')]
        self.assertEqual(len(expiry_lines), 1, crond['tables']['root'])
        self.assertRegex(expiry_lines[0],
                         r'^\* \* \* \* \* /etc/\.couvrefeu-release-[0-9a-f]{64}/cfctl '
                         r'--installation-generation [0-9a-f]{64} expire$')
        command = expiry_lines[0].split(' ', 5)[5]
        self.assertEqual((self.root/'etc/firewall.couvrefeu').read_text(),
                         '#!/bin/sh\nexec '+command.removesuffix(' expire')+' apply-fw\n')
        backup = private/'backup'
        archive = REPO/'tests/fixtures/legacy-router-5c45e3e.tar.gz'
        manifest = json.loads((REPO/'tests/fixtures/legacy-router-5c45e3e.json').read_text())
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), manifest['archiveSHA256'])
        with tarfile.open(archive) as tar:
            members=tar.getmembers()
            self.assertEqual({m.name for m in members}, set(manifest['files']))
            for member in members:
                self.assertTrue(member.isfile())
                content=tar.extractfile(member).read()
                self.assertEqual(hashlib.sha256(content).hexdigest(),manifest['files'][member.name])
                if member.name in ['install.sh','uninstall.sh']: continue
                rel='usr/lib/couvrefeu/'+member.name[4:] if member.name.startswith('lib/') else 'usr/sbin/'+member.name
                installed=self.root/rel
                installed.write_bytes(content); installed.chmod(member.mode)
                key=rel.replace('/','_')
                staged=backup/(key+'.staged')
                shutil.copy2(installed,staged)
                (backup/(key+'.after')).write_text(fixtures.signature(staged)+'\n')
                (backup/(key+'.after')).chmod(0o600)
        for rel in ['usr/lib/couvrefeu/platform-bootstrap.sh','usr/lib/couvrefeu/vendor-platform.sh','etc/couvrefeu/platform-profile','usr/lib/couvrefeu/activity.sh']:
            (self.root/rel).unlink()
            for suffix in ['before','after','mtime','staged','original']:
                path=backup/(rel.replace('/','_')+'.'+suffix)
                if path.exists(): path.unlink()
        self.assertNotEqual((self.root/'usr/lib/couvrefeu/core.sh').read_bytes(),(self.current/'lib/core.sh').read_bytes())
        self.assertNotEqual((self.root/'usr/lib/couvrefeu/firewall.sh').read_bytes(),(self.current/'lib/firewall.sh').read_bytes())
        self.assertFalse((private/'platform-profile').exists())

    def tearDown(self): self.fixture.close()

    def command(self, name, *args):
        return subprocess.run(SHELL+[str(self.current/name),*args], env=self.fixture.env, capture_output=True, text=True, timeout=90)

    def assert_refused_without_changes(self, expected='missing manifest: usr/lib/couvrefeu/platform-bootstrap.sh'):
        before = fixtures.full_snapshot(self.root)
        result = self.command('uninstall.sh')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stderr)
        self.assertEqual(fixtures.full_snapshot(self.root), before,
                         'contradictory new-format provenance must remain entirely unchanged')
        self.assertTrue((self.root / '.couvrefeu-prepared').is_dir())
        self.assertTrue((self.root / '.couvrefeu-transaction').is_file())
        self.assertFalse((self.root / '.couvrefeu-recovery.done').exists())

    def test_removed_manifest_records_refuse_with_new_prepared_baseline(self):
        self.assert_refused_without_changes()

    def test_scoped_downgrade_refuses_before_cleanup(self):
        self.fixture.env['CF_TEST_UNINSTALL_CLEANUP_FAIL_AFTER'] = '1'
        self.assert_refused_without_changes()

    def test_downgrade_with_module_drift_preserves_all_evidence(self):
        installed = self.root / 'usr/lib/couvrefeu/core.sh'
        installed.write_bytes(installed.read_bytes() + b'# drift\n')
        self.assert_refused_without_changes('drift at /usr/lib/couvrefeu/core.sh')

    def test_downgrade_with_invalid_record_preserves_all_evidence(self):
        record = self.root / 'etc/couvrefeu/backup/usr_lib_couvrefeu_core.sh.after'
        record.write_text('invalid\n')
        self.assert_refused_without_changes('invalid signature record: usr/lib/couvrefeu/core.sh')

    def test_downgrade_with_foreign_chain_preserves_all_evidence(self):
        state = self.fixture.backend()
        slot = self.fixture.slot()
        state['tables']['iptables']['filter'][f'cf2_{slot}_f'].append(['-j', 'ACCEPT'])
        self.fixture.update_backend(tables=state['tables'])
        self.assert_refused_without_changes()


class VendorAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='couvre-feu-platform-native-')
        self.root = Path(self.tmp.name)
        self.lib = self.root / 'lib'
        self.lib.mkdir(mode=0o700)
        shutil.copytree(REPO / 'router/lib', self.lib, dirs_exist_ok=True)
        (self.root / 'tmp').mkdir(mode=0o1777)
        (self.root / 'tmp').chmod(0o1777)
        calls_dir = tempfile.TemporaryDirectory(prefix='couvre-feu-admission-calls-')
        self.addCleanup(calls_dir.cleanup)
        self.calls = Path(calls_dir.name) / 'calls'
        self.adapter = self.root / 'independent-adapter.sh'
        source = (REPO / 'router/lib/platform-bootstrap.sh').read_text()
        # Explicit fixture boundary changes are private to this copied adapter.
        # Production has no root/path/payload/attestation override variable.
        source = source.replace('/tmp/couvrefeu-platform.lock', str(self.root/'tmp/couvrefeu-platform.lock'))
        source = source.replace("'%u:%g:%a' /tmp)", "'%u:%g:%a' " + str(self.root / 'tmp') + ")").replace('0:0:1777', f'{os.getuid()}:{os.getgid()}:1777')
        source = source.replace('. "$1/vendor-platform.sh"', '. "$1/fixture-vendor-platform.sh"')
        fixture_helper = self.lib / 'fixture-vendor-platform.sh'
        fixture_helper.write_text(f'. "{self.lib}/vendor-platform.sh"; vp_transaction_check() {{ printf "complete-two-pass-boundary\\n" >> "{self.calls}"; }}\n')
        fixture_helper.chmod(0o600)
        self.adapter.write_text(source)
        self.setup = f'umask 077; . "{self.adapter}"; platform_bootstrap_vendor() {{ :; }}; CF_TEST_MODE=1; CF_ROOT="{self.root}"; platform_entry_root_validate; '

    def tearDown(self):
        self.tmp.cleanup()

    def run_shell(self, body):
        return subprocess.run(SHELL + ['-c', self.setup + body], capture_output=True, text=True)

    def admit(self):
        return f'platform_admit {PROFILE} "{self.root}" "{self.lib}"; '

    def test_one_attestation_nested_reuse_and_fresh_external_call(self):
        result = self.run_shell(self.admit() + f'(CF_PLATFORM_LOCKED=0; platform_verify_modules "{self.lib}"); (CF_PLATFORM_LOCKED=0; platform_verify_modules "{self.lib}"); platform_lock_release')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)
        result = self.run_shell(self.admit() + 'platform_lock_release')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls.read_text().splitlines()), 2)

    def test_actual_installed_core_subshell_reuses_one_admission(self):
        installed = self.root / 'usr/lib/couvrefeu'
        shutil.copytree(REPO / 'router/lib', installed)
        installed.chmod(0o700)
        backend = self.root / 'backend'
        backend.mkdir(mode=0o700); (backend / '.couvrefeu-test-backend').touch()
        for name in ['iptables', 'ip6tables', 'ipset', 'uci', 'conntrack', 'ip', 'fw3', 'sync']:
            path = backend / name; path.write_text('#!/bin/sh\nexit 0\n'); path.chmod(0o700)
        body = self.admit() + f'CF_ROOT="{self.root}"; CF_BACKEND_DIR="{backend}"; . "{self.lib}/install-common.sh"; installed_core check; unlock_install; platform_lock_release'
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)
        self.assertFalse((self.root/'tmp/couvrefeu-platform.lock').exists())
        self.assertFalse((self.root/'.couvrefeu-install.lock').exists())

    def test_contention_allows_readonly_attestation_without_policy_mutation(self):
        lock = self.root / 'tmp/couvrefeu-platform.lock'
        lock.mkdir(mode=0o700)
        (lock / 'pid').write_text(str(os.getpid())+'\n')
        (lock / 'pid').chmod(0o600)
        before = fixtures.full_snapshot(self.root)
        result = self.run_shell(self.admit())
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('transaction_contention', result.stderr)
        self.assertEqual(self.calls.read_text().splitlines(), ['complete-two-pass-boundary'])
        self.assertEqual(fixtures.full_snapshot(self.root), before)

    def test_failed_input_stage_after_vendor_admission_releases_owned_lock(self):
        # Fallback path only: cfctl stages sync/rpc-sync before platform_admit; the real-cfctl
        # ordering is proven behaviourally by test_open_stdin_sync_holds_no_lock_and_expire_proceeds.
        timeout = SHELL[0] + ' timeout'
        for raw in ['{', ' ' * 65537]:
            with self.subTest(raw=raw[:4]):
                body = self.admit() + (f'CF_BASE="{self.root}"; CF_LOCAL_TEST=1; CF_LIB="{self.lib}"; '
                                       f'CF_TEST_TIMEOUT="{timeout}"; . "{self.lib}/core.sh"; '
                                       '[ -d "$CF_PLATFORM_LOCK" ] || exit 9; cf_sync_stage 0 || exit 1; exit 0')
                result = subprocess.run(SHELL + ['-c', self.setup + body], input=raw, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse((self.root / 'tmp/couvrefeu-platform.lock').exists())
                self.assertEqual(sorted(p.name for p in (self.root / 'tmp').iterdir()), [])

    def test_failed_attestation_releases_owned_lock(self):
        result = self.run_shell('platform_attest_vendor() { return 2; }; ' + self.admit())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'tmp/couvrefeu-platform.lock').exists())

    def test_empty_lock_left_by_kill_before_pid_publication_is_recovered(self):
        # mkdir succeeded, then KILL before the exclusive pid create: no record claims it.
        lock = self.root / 'tmp/couvrefeu-platform.lock'
        lock.mkdir(mode=0o700)
        result = self.run_shell('platform_lock_recover')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(lock.exists())
        # The next vendor admission then proceeds and releases normally.
        result = self.run_shell(self.admit() + 'platform_lock_release')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(lock.exists())

    def test_partial_or_foreign_unpublished_lock_still_refuses_recovery(self):
        lock = self.root / 'tmp/couvrefeu-platform.lock'
        for name, content in [('pid', ''), ('token', 'a' * 64 + '\n'), ('foreign', '')]:
            with self.subTest(name=name, content=content):
                lock.mkdir(mode=0o700)
                record = lock / name
                record.write_text(content); record.chmod(0o600)
                result = self.run_shell('platform_lock_recover')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(record.read_text(), content)
                record.unlink(); lock.rmdir()
        lock.mkdir(mode=0o755)
        self.assertNotEqual(self.run_shell('platform_lock_recover').returncode, 0)
        self.assertTrue(lock.is_dir())

    def test_term_after_mkdir_before_pid_releases_owned_empty_lock(self):
        lock = self.root / 'tmp/couvrefeu-platform.lock'
        body = (f'CF_PLATFORM_LOCK="{lock}"; trap "platform_lock_release" 0; trap "exit 143" TERM; '
                'mkdir -m 700 "$CF_PLATFORM_LOCK"; CF_PLATFORM_LOCKED=1; kill -TERM $$; exit 7')
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertFalse(lock.exists())

    def test_dead_owner_recovery_and_foreign_partial_refusal(self):
        lock = self.root / 'tmp/couvrefeu-platform.lock'
        lock.mkdir(mode=0o700)
        (lock / 'pid').write_text('2147483647\n'); (lock / 'pid').chmod(0o600)
        (lock / 'foreign').touch()
        self.assertNotEqual(self.run_shell('platform_lock_recover').returncode, 0)
        (lock / 'foreign').unlink()
        self.assertEqual(self.run_shell('platform_lock_recover').returncode, 0)
        self.assertFalse(lock.exists())

    def test_late_selection_drift_refuses_and_releases_lock(self):
        base = self.root / 'etc/couvrefeu'
        backup = base / 'backup'
        backup.mkdir(parents=True, mode=0o700); base.chmod(0o700)
        content = (PROFILE+'\n').encode()
        for path in [base / 'platform-profile', backup / 'etc_couvrefeu_platform-profile.staged']:
            path.write_bytes(content); path.chmod(0o600)
        after = backup / 'etc_couvrefeu_platform-profile.after'
        after.write_text(hashlib.sha256(content).hexdigest()+f':600:{os.getuid()}:{os.getgid()}\n'); after.chmod(0o600)
        fixture_helper = self.lib / 'fixture-vendor-platform.sh'
        fixture_helper.write_text(f'. "{self.lib}/vendor-platform.sh"; vp_transaction_check() {{ printf "strict\\n" > "{base}/platform-profile"; }}\n')
        fixture_helper.chmod(0o600)
        result = self.run_shell(self.admit())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'tmp/couvrefeu-platform.lock').exists())

    def test_forged_reload_token_never_grants_admission(self):
        runtime = self.root / 'etc/couvrefeu/runtime/lock'
        runtime.mkdir(parents=True, mode=0o700)
        for name, content in [('pid', str(os.getpid())), ('reload', 'a'*64)]:
            p=runtime/name;p.write_text(content+'\n');p.chmod(0o600)
        body = f'CF_BASE="{self.root}"; CF_LIB="{self.lib}"; . "{self.lib}/core.sh"; CF_RELOAD_TOKEN=forged; if cf_reentrant_include; then exit 99; fi; [ "$CF_PLATFORM_ADMITTED" = 0 ]; CF_RELOAD_TOKEN={"a"*64}; cf_reentrant_include; [ "$CF_PLATFORM_ADMITTED" = 0 ]'
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"deferred":true', result.stdout)
        self.assertFalse(self.calls.exists())


class VendorCommParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='couvre-feu-vendor-comm-')
        self.comm = Path(self.tmp.name) / 'comm'
        self.helper = REPO / 'router/lib/vendor-platform.sh'
        self.harness = '''set -eu
fail() { printf 'REFUSE=%s\n' "$1" >&2; exit 2; }
''' + 'awk() { ' + shlex.quote(SHELL[0]) + ''' awk "$@"; }
. "$1"
'''

    def tearDown(self):
        self.tmp.cleanup()

    def parse(self, value, setup=''):
        self.comm.write_bytes(value)
        return subprocess.run(SHELL + ['-c', self.harness + setup + '\nvp_comm "$2"',
                                       'comm-fixture', str(self.helper), str(self.comm)],
                              capture_output=True, timeout=10)

    def test_actual_workqueue_descriptions_remain_complete(self):
        names = ['kworker/1:2-rcu_gp', 'kworker/1:1-events', 'kworker/0:3-events',
                 'kworker/u4:2-events_power_efficient', 'kworker/0:0-events',
                 'kworker/1:2H-events_highpri', 'kworker/0:1+events',
                 'kworker/0:0H-events_highpri', 'kworker/0:1H-events_highpri',
                 'kworker/u4:1-events_power_efficient', 'kworker/u4:0-events_power_efficient']
        for name in names:
            with self.subTest(name=name):
                result = self.parse((name + '\n').encode())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, (name + '\n').encode())

    def test_linux_proc_name_bound_preserves_complete_records(self):
        for count in [15, 16, 63]:
            with self.subTest(count=count):
                value = b'a' * count + b'\n'
                result = self.parse(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, value)
        for value in [b'a' * 64 + b'\n', b'a' * 66, b'a' + b'\n' * 64]:
            with self.subTest(value=value):
                result = self.parse(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')

    def test_malformed_names_and_failed_producers_refuse(self):
        for value in [b'', b'\n', b'two\nrecords\n', b'a\x00b\n', b'a\x01b\n',
                      b'a\rb\n', b'a\x7fb\n', b'CF008_DD_END=0\n',
                      b'name\nCF008_READ_END=0\n']:
            with self.subTest(value=value):
                result = self.parse(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
        for setup, producer in [
                ('timeout() { [ "$1:$2:$3:$4" = "-s:KILL:6:dd" ] || return 99; printf "logd\\n"; return 7; };',
                 'timeout -s KILL 6 dd if="$2" bs=1 count=65'),
                ('tr() { cat; return 7; };', 'printf "logd\\n" | tr "\\000" "\\001"')]:
            with self.subTest(setup=setup):
                control = subprocess.run(SHELL + ['-c', self.harness + setup + '\n' + producer,
                                                  'producer-fixture', str(self.helper), str(self.comm)],
                                         capture_output=True, timeout=10)
                self.assertEqual(control.returncode, 7)
                self.assertEqual(control.stdout, b'logd\n')
                result = self.parse(b'logd\n', setup)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')

    def test_long_name_does_not_authorize_nonroot_gid_zero(self):
        command = self.harness + '''
creds='1 7,7,7,7 0,0,0,0 none 1'
comm='kworker/u4:2-events_power_efficient'
vp_classify
'''
        result = subprocess.run(SHELL + ['-c', command, 'classification-fixture', str(self.helper)],
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'REFUSE=unknown_nonroot_gid0', result.stderr)


if __name__ == '__main__':
    unittest.main()
