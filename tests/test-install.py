#!/usr/bin/env python3
"""Filesystem recovery fixtures; never invokes router/system backends."""
import hashlib
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import sys
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests/fixtures'))
import overlay  # noqa: E402
FILES = ('usr/lib/couvrefeu/core.sh', 'usr/lib/couvrefeu/rpc.sh', 'usr/lib/couvrefeu/state.awk', 'usr/lib/couvrefeu/firewall.sh', 'usr/lib/couvrefeu/json.awk', 'usr/lib/couvrefeu/rules.awk', 'usr/lib/couvrefeu/install-common.sh', 'usr/sbin/cfctl', 'usr/sbin/cfctl-ssh', 'etc/firewall.couvrefeu',
         'etc/config/firewall', 'etc/sysupgrade.conf', 'etc/crontabs/root',
         'etc/couvrefeu/protected', 'etc/couvrefeu/state')
DIRS = ('etc', 'usr', 'usr/sbin', 'usr/lib', 'usr/lib/couvrefeu', 'etc/config', 'etc/crontabs', 'etc/couvrefeu')


def signature(path):
    if not path.exists():
        return 'absent'
    st = path.stat()
    return f'{hashlib.sha256(path.read_bytes()).hexdigest()}:{st.st_mode & 0o7777:o}:{st.st_uid}:{st.st_gid}'


def mtime(path):
    if not path.exists():
        return 'absent'
    seconds, fraction = divmod(path.stat().st_mtime_ns, 1_000_000_000)
    return f'{seconds}:{fraction:09d}'


def exact_signature(path):
    return f'{signature(path)}:{mtime(path)}'


# Nonzero sub-microsecond digits: second and microsecond truncation both lose data.
FRACTIONAL = 1_234_567_890_123_456_789
EXISTING_ORIGINALS = {'etc/config/firewall': b"config zone 'wan'\n option input 'DROP'\n",
                      'etc/sysupgrade.conf': b'# exact no terminal newline',
                      'etc/crontabs/root': b'5 * * * * vendor-check\n'}


def full_snapshot(root):
    """Every path, with file bytes, exact metadata and inode; directories by mode/owner."""
    result = {}
    for p in sorted(root.rglob('*')):
        st = p.lstat()
        rel = str(p.relative_to(root))
        if p.is_symlink():
            result[rel] = ('symlink', os.readlink(p), st.st_uid, st.st_gid)
        elif p.is_dir():
            result[rel] = ('dir', st.st_mode & 0o7777, st.st_uid, st.st_gid)
        else:
            result[rel] = ('file', p.read_bytes(), exact_signature(p), st.st_ino)
    return result


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='couvre-feu-install-')
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ, CF_TEST_MODE='1', CF_ROOT=str(self.root))
        self.env.pop('SSH_CONNECTION', None)
        self.env.pop('SSH_CLIENT', None)

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, name, *args):
        return subprocess.run([*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')), str(REPO / 'router' / name), *args],
                              env=self.env, capture_output=True, text=True)

    def snapshot(self):
        result = {}
        for p in self.root.rglob('*'):
            if p.is_symlink():
                st = p.lstat()
                result[str(p.relative_to(self.root))] = (
                    os.readlink(p).encode(), f'symlink:{st.st_mode}:{st.st_uid}:{st.st_gid}')
            elif p.is_file():
                result[str(p.relative_to(self.root))] = (p.read_bytes(), exact_signature(p))
        return result

    def make_journal(self, absent=False, partial=False, files=FILES):
        originals = {}
        if not absent:
            for i, rel in enumerate(files):
                p = self.root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(f'original-{i}\n\x00 exact bytes\n'.encode())
                p.chmod(0o640 if i % 2 else 0o700)
                originals[rel] = (p.read_bytes(), exact_signature(p))
        modes = {rel: (f'{(self.root / rel).stat().st_mode & 0o7777:o}'
                       if (self.root / rel).exists() else 'absent') for rel in DIRS}
        backup = self.root / 'etc/couvrefeu/backup'
        backup.mkdir(parents=True, mode=0o700)
        backup.parent.chmod(0o700)
        for rel, mode in modes.items():
            (backup / ('dir_' + rel.replace('/', '_'))).write_text(mode + '\n')
        for i, rel in enumerate(files):
            p = self.root / rel
            k = rel.replace('/', '_')
            before = signature(p)
            (backup / (k + '.before')).write_text(before + '\n')
            (backup / (k + '.mtime')).write_text(mtime(p) + '\n')
            if before != 'absent':
                shutil.copy2(p, backup / (k + '.original'))
            staged = backup / (k + '.staged')
            staged.write_text('02:00:00:00:00:01\n' if rel.endswith(('/protected', '/rpc-allowed')) else f'installed-{i}\n')
            staged.chmod(0o600)
            (backup / (k + '.after')).write_text(signature(staged) + '\n')
            if not partial or i % 2 == 0:
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(staged, p)
        (backup / 'ready').write_text('1\n')
        for p in backup.iterdir():
            if not p.name.endswith(('.original', '.staged')):
                p.chmod(0o600)
        return originals

    def test_exact_recovery_and_repeat(self):
        original = self.make_journal()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), original)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), original)

    def test_legacy_done2_only_retry_preserves_exact_originals(self):
        original = self.make_journal()
        self.env['CF_TEST_UNINSTALL_CLEANUP_FAIL_AT'] = 'journal'
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        done = self.root / '.couvrefeu-recovery.done'
        self.assertEqual(done.read_bytes(), b'2\n')
        self.env.pop('CF_TEST_UNINSTALL_CLEANUP_FAIL_AT')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), original)

    def test_original_absence_restored(self):
        self.make_journal(absent=True)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_interrupted_install_restored(self):
        original = self.make_journal(partial=True)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), original)

    def test_drift_refused_without_any_mutation(self):
        self.make_journal()
        (self.root / 'etc/sysupgrade.conf').write_text('operator changed it\n')
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('drift', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_permission_drift_refused(self):
        self.make_journal()
        (self.root / 'etc/config/firewall').chmod(0o644)
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_original_backup_corruption_refused(self):
        self.make_journal()
        (self.root / 'etc/couvrefeu/backup/etc_config_firewall.original').write_text('bad')
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_symlink_refused(self):
        self.make_journal()
        target = self.root / 'etc/config/firewall'
        target.unlink()
        target.symlink_to('/etc/passwd')
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(target.is_symlink())

    def test_protected_append_allowed_but_replacement_refused(self):
        original = self.make_journal()
        protected = self.root / 'etc/couvrefeu/protected'
        with protected.open('a') as stream:
            stream.write('02:00:00:00:00:02\n')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), original)

    def test_protected_replacement_refused(self):
        self.make_journal()
        (self.root / 'etc/couvrefeu/protected').write_text('02:00:00:00:00:02\n')
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_mutable_state_restores_original(self):
        original = self.make_journal()
        (self.root / 'etc/couvrefeu/state').write_text('new policy state\n')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), original)


SCOPED_FILES = FILES + ('etc/couvrefeu/rpc-allowed',)
FLOOR_LINE = '02:00:00:00:00:01\n'


class LiveScopeRecoveryTests(unittest.TestCase):
    """The live rpc-allowed may grow past its immutable floor; uninstall must still restore."""
    setUp = RecoveryTests.setUp
    tearDown = RecoveryTests.tearDown
    run_script = RecoveryTests.run_script
    snapshot = RecoveryTests.snapshot
    make_journal = RecoveryTests.make_journal
    FLOOR = '02:00:00:00:00:01\n'

    def journal(self, **kwargs):
        return self.make_journal(files=SCOPED_FILES, **kwargs)

    def set_live(self, content, mode=0o600):
        live = self.root / 'etc/couvrefeu/rpc-allowed'
        live.write_bytes(content if isinstance(content, bytes) else content.encode())
        live.chmod(mode)

    def runtime_file(self, name):
        runtime = self.root / 'etc/couvrefeu/runtime'
        runtime.mkdir(mode=0o700, exist_ok=True)
        runtime.chmod(0o700)
        (runtime / name).write_text('stray\n')
        (runtime / name).chmod(0o600)

    def test_grown_scope_restores_exact_originals(self):
        original = self.journal()
        self.set_live(self.FLOOR + '02:00:00:00:00:02\n02:00:00:00:00:03\n')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), original)

    def test_grown_scope_with_absent_original_leaves_nothing_behind(self):
        self.journal(absent=True)
        self.set_live(self.FLOOR + '02:00:00:00:00:02\n')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_stray_scope_snapshot_is_owned_runtime_and_removed(self):
        self.journal(absent=True)
        self.set_live(self.FLOOR + '02:00:00:00:00:02\n')
        self.runtime_file('.scope.123')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_non_numeric_scope_snapshot_name_is_still_unowned(self):
        self.journal(absent=True)
        self.runtime_file('.scope.abc')
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unowned runtime file', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_or_floorless_live_scope_is_refused_without_mutation(self):
        for name, content, mode, text in (
                ('floor-missing', '02:00:00:00:00:02\n', 0o600, 'floor'),
                ('unsorted', '02:00:00:00:00:02\n' + FLOOR_LINE, 0o600, 'invalid RPC scope'),
                ('duplicate', FLOOR_LINE * 2, 0o600, 'invalid RPC scope'),
                ('no-final-newline', FLOOR_LINE + '02:00:00:00:00:02', 0o600, 'invalid RPC scope'),
                ('multicast', FLOOR_LINE + '03:00:00:00:00:01\n', 0o600, 'invalid RPC scope'),
                ('empty', '', 0o600, 'invalid RPC scope'),
                ('mode', FLOOR_LINE + '02:00:00:00:00:02\n', 0o644, 'metadata drift')):
            with self.subTest(name=name):
                self.journal(absent=True)
                self.set_live(content, mode)
                before = self.snapshot()
                result = self.run_script('uninstall.sh')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(text, result.stderr)
                self.assertEqual(self.snapshot(), before)
                shutil.rmtree(self.root)
                self.root.mkdir()

    def test_oversized_live_scope_is_refused(self):
        self.journal(absent=True)
        many = [FLOOR_LINE] + ['02:00:00:01:{:02x}:{:02x}\n'.format(i // 256, i % 256) for i in range(1, 257)]
        self.set_live(''.join(many))
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid RPC scope', result.stderr)


NEW_FILES = FILES + ('usr/lib/couvrefeu/platform-bootstrap.sh', 'usr/lib/couvrefeu/vendor-platform.sh', 'etc/couvrefeu/platform-profile', 'usr/lib/couvrefeu/activity.sh')


class InstallerTests(unittest.TestCase):
    """Complete staged/install/resume/uninstall transactions with fake sources."""
    def run_script(self, name, *args):
        if name == 'lib/install-common.sh':
            lib = REPO / 'router/lib'
            script = f'. "{lib}/platform-bootstrap.sh"; CF_PLATFORM_ADMITTED=1; . "{lib}/install-common.sh"'
            return subprocess.run([*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')), '-c', script, 'fixture-journal', *args], env=self.env, capture_output=True, text=True)
        return RecoveryTests.run_script(self, name, *args)
    snapshot = RecoveryTests.snapshot
    tearDown = RecoveryTests.tearDown

    def setUp(self):
        RecoveryTests.setUp(self)
        logs = tempfile.TemporaryDirectory(prefix='couvre-feu-cp-log-')
        self.addCleanup(logs.cleanup)
        self.cp_log = Path(logs.name) / 'cp-p.log'
        self.source = self.root / 'source'
        (self.source / 'lib').mkdir(parents=True)
        (self.source / 'cfctl').write_text('''#!/bin/sh
set -eu
case "$1" in
check) [ "${CF_TEST_CHECK_FAIL:-0}" != 1 ];;
*) exit 91;;
esac
''')
        (self.source / 'cfctl-ssh').write_text('#!/bin/sh\nexit 0\n')
        (self.source / 'cfctl-scope').write_text('#!/bin/sh\nexit 2\n')
        for lib in ('core.sh', 'rpc.sh', 'firewall.sh', 'activity.sh'):
            (self.source / 'lib' / lib).write_text(':\n')
        for lib in ('json.awk', 'state.awk', 'rules.awk'):
            (self.source / 'lib' / lib).write_text('BEGIN {exit 0}\n')
        (self.source / 'lib/core.sh').write_text('cf_check() { [ "${CF_TEST_CHECK_FAIL:-0}" != 1 ]; }\n')
        for lib in ('install-common.sh', 'platform-bootstrap.sh', 'vendor-platform.sh'):
            shutil.copy2(REPO / 'router/lib' / lib, self.source / 'lib' / lib)
        backend = self.root / 'bin'
        backend.mkdir()
        (backend / '.couvrefeu-test-backend').touch()
        (backend / 'uci').write_text('''#!/bin/sh
[ "$1" = -c ] && [ "$3" = -t ] && [ "$5" = show ] && [ "$6" = firewall ]
''')
        (backend / 'uci').chmod(0o700)
        self.env['CF_BACKEND_DIR'] = str(backend)
        # Like target BusyBox, fixture `cp -p` loses fractional mtimes by default.
        InstallerTests.install_copy_tool(self, 's')
        # Exactness never depends on touch: any invocation is logged and fails.
        self.touch_log = Path(logs.name) / 'touch.log'
        touch = backend / 'touch'
        touch.write_text(f'#!/bin/sh\nprintf "touch %s\\n" "$*" >> {shlex.quote(str(self.touch_log))}\nexit 1\n')
        touch.chmod(0o700)

    def assert_no_touch(self):
        self.assertFalse(self.touch_log.exists(), self.touch_log.read_text() if self.touch_log.exists() else '')

    def install(self, *extra, protect=True):
        args = ['--source-dir', str(self.source)]
        if protect:
            args.extend(['--protect', '02:00:00:00:00:01'])
        return self.run_script('install.sh', *args, *extra)

    def test_stage_is_no_mutation(self):
        before = self.snapshot()
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / 'etc').exists())

    def test_install_restore_original_configuration_modes_and_mtimes(self):
        originals = {'etc/config/firewall': b"config zone 'wan'\n option input 'DROP'\n",
                     'etc/sysupgrade.conf': b'# exact no terminal newline',
                     'etc/crontabs/root': b'5 * * * * vendor-check\n',
                     'etc/couvrefeu/protected': b'02:00:00:00:00:03\n',
                     'etc/couvrefeu/state': b'V\t1\nR\t0\n'}
        for rel, content in originals.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
            p.chmod(0o640)
            os.utime(p, ns=(1_234_567_890_123_456_789, 1_234_567_890_123_456_789))
        (self.root / 'etc/couvrefeu').chmod(0o750)
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        firewall = self.root / 'etc/config/firewall'
        self.assertTrue(firewall.read_bytes().startswith(originals['etc/config/firewall']))
        self.assertIn("option path '/etc/firewall.couvrefeu'", firewall.read_text())
        self.assertEqual((self.root / 'etc/couvrefeu/protected').stat().st_mode & 0o777, 0o600)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((self.root / 'etc/couvrefeu').stat().st_mode & 0o777, 0o750)

    def test_mtime_only_changes_restore_exact_originals(self):
        # An original helper with identical installed bytes and metadata used
        # to be skipped even though installation changed its timestamp.
        # Match the declared installed helper mode independently of umask.
        (self.source / 'lib/core.sh').chmod(0o644)
        target = self.root / 'usr/lib/couvrefeu/core.sh'
        target.parent.mkdir(parents=True)
        target.write_text(':\n')
        target.chmod(0o644)
        stamp = 1_234_567_890_123_456_789
        os.utime(target, ns=(stamp, stamp))
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(signature(target), signature(self.source / 'lib/core.sh'))
        os.utime(target, ns=(stamp + 999, stamp + 999))
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(target.stat().st_mtime_ns, stamp)

    def test_actual_installer_restores_original_absence(self):
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'etc/config/firewall').exists())
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / 'etc').exists())
        self.assertFalse((self.root / 'usr').exists())

    def install_copy_tool(self, precision=None):
        """`cp -p` truncating destination mtimes to seconds ('s'), microseconds ('us') or not at all."""
        wrapper = self.root / 'bin/cp'
        real_copy = shutil.which('cp')
        real_touch = shutil.which('touch')
        real_stat = shutil.which('stat')
        truncate = {None: '', 's': '"@$seconds"', 'us': '"@$seconds.${fraction%???}"'}[precision]
        script = ('#!/bin/sh\n' + shlex.quote(real_copy) + ' "$@" || exit\n')
        if truncate:
            script += ('case " $* " in *" -p "*) ;; *) exit 0;; esac\n'
                       'for destination do :; done\n'
                       '[ -f "$destination" ] || exit 0\n'
                       f'seconds=$({shlex.quote(real_stat)} -c %Y "$destination")\n'
                       f'fraction=$({shlex.quote(real_stat)} -c %y "$destination" | sed "s/.*\\.\\([0-9]*\\) .*/\\1/")\n'
                       f'{shlex.quote(real_touch)} -m -d {truncate} "$destination"\n'
                       f'printf "%s\\n" "$destination" >> {shlex.quote(str(self.cp_log))}\n')
        wrapper.write_text(script)
        wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']

    def write_originals(self):
        for rel, content in EXISTING_ORIGINALS.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
            p.chmod(0o640)
            os.utime(p, ns=(FRACTIONAL, FRACTIONAL))
        return {rel: exact_signature(self.root / rel) for rel in EXISTING_ORIGINALS}

    def originals_state(self):
        return {rel: exact_signature(self.root / rel) for rel in EXISTING_ORIGINALS}

    def test_fractional_originals_restore_exact_despite_truncating_cp(self):
        # BusyBox cp -p truncates; originals move into the journal by rename.
        originals = self.write_originals()
        for precision in ('s', 'us', None):
            with self.subTest(precision=precision):
                self.install_copy_tool(precision)
                if self.cp_log.exists():
                    self.cp_log.unlink()
                before = self.snapshot()
                result = self.install('--activate')
                self.assertEqual(result.returncode, 0, result.stderr)
                backup = self.root / 'etc/couvrefeu/backup'
                for rel, exact in originals.items():
                    key = rel.replace('/', '_')
                    self.assertEqual(exact_signature(backup / (key + '.original')), exact)
                    # Inode numbers are not identity under overlayfs; none is recorded.
                    self.assertFalse((backup / (key + '.inode')).exists())
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.originals_state(), originals)
                if precision:
                    # The wrapper really ran and really truncated a cp -p copy.
                    self.assertTrue(self.cp_log.read_text().strip())
                self.assert_no_touch()

    def copy_fail_tool(self, fail_suffix):
        """`cp` failing (as on ENOSPC) for one destination suffix; logs every refusal."""
        wrapper = self.root / 'bin/cp'
        wrapper.write_text('#!/bin/sh\nfor destination do :; done\n'
                           f'case "$destination" in *{fail_suffix}) printf "%s\\n" "$destination" >> {shlex.quote(str(self.cp_log))}; '
                           'printf "cp: %s: No space left on device\\n" "$destination" >&2; exit 1;; esac\n'
                           f'exec {shlex.quote(shutil.which("cp"))} "$@"\n')
        wrapper.chmod(0o700)

    def touch_tool(self, precision, only=''):
        """`touch -r` truncating its target mtime to seconds or microseconds (older BusyBox)."""
        wrapper = self.root / 'bin/touch'
        real_touch = shutil.which('touch')
        real_stat = shutil.which('stat')
        truncate = {'s': '"@$seconds"', 'us': '"@$seconds.${fraction%???}"'}[precision]
        wrapper.write_text('#!/bin/sh\n: > "$CF_ROOT/touch-called"\n' + shlex.quote(real_touch) + ' "$@" || exit\n'
                           'for destination do :; done\n'
                           f'case "$destination" in *{only}*) ;; *) exit 0;; esac\n'
                           f'seconds=$({shlex.quote(real_stat)} -c %Y "$destination")\n'
                           f'fraction=$({shlex.quote(real_stat)} -c %y "$destination" | sed "s/.*\\.\\([0-9]*\\) .*/\\1/")\n'
                           f'{shlex.quote(real_touch)} -m -d {truncate} "$destination"\n'
                           f'printf "%s\\n" "$destination" >> {shlex.quote(str(self.cp_log))}\n')
        wrapper.chmod(0o700)

    def enable_release(self):
        self.env['CF_TEST_RELEASE_DIR'] = '1'
        (self.root / 'etc').mkdir(mode=0o755, exist_ok=True)
        bootstrap = (REPO / 'router/lib/platform-bootstrap.sh').read_text()
        release_id = next(line.split('=', 1)[1] for line in bootstrap.splitlines() if line.startswith('CF_RELEASE_ID='))
        return self.root / ('etc/.couvrefeu-release-' + release_id)

    def assert_refused_identically(self, before, release, message):
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual(full_snapshot(self.root), before)
        self.assertFalse(release.exists())
        self.assertFalse((self.root / 'etc/couvrefeu/backup').exists())
        self.assertFalse((self.root / '.couvrefeu-install.lock').exists())
        self.assertEqual(list(self.root.glob('.couvrefeu-stage.*')), [])
        return result

    def test_preserve_failure_leaves_root_identical(self):
        release = self.enable_release()
        self.write_originals()
        (self.root / 'etc/couvrefeu').mkdir(mode=0o750)
        (self.root / 'etc/couvrefeu').chmod(0o750)
        # Fail on the last existing original: earlier recovery copies are rolled back.
        self.copy_fail_tool('etc_crontabs_root.copy')
        before = full_snapshot(self.root)
        result = self.assert_refused_identically(before, release, 'cannot copy original for manual recovery: etc/crontabs/root; no installation made')
        self.assertIn('No space left on device', result.stderr)
        self.assertTrue(self.cp_log.read_text().strip())

    def test_truncating_touch_is_never_invoked(self):
        # The live refusal (BusyBox 1.33.2 touch -r truncates) is irrelevant:
        # originals move by rename; no tool re-applies a timestamp.
        originals = self.write_originals()
        self.touch_tool('s')
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.originals_state(), originals)
        self.assertFalse((self.root / 'touch-called').exists())

    def test_every_prewrite_gate_leaves_root_identical(self):
        release = self.enable_release()
        self.write_originals()
        real_stat = shutil.which('stat')
        gates = {
            'capability': ({'CF_TEST_CHECK_FAIL': '1'}, None, 'capability gate failed'),
            'uci': ({}, ('uci', '#!/bin/sh\nexit 1\n'), 'staged UCI firewall validation failed'),
            'stat': ({}, ('stat', '#!/bin/sh\nif [ "$1" = -c ] && [ "$2" = "%Y %y" ]; then\n'
                                   '    printf "%s\\n" "1234567890 2009-02-13 23:31:30 +0000"; exit 0\nfi\n'
                                   'exec ' + shlex.quote(real_stat) + ' "$@"\n'), 'precise original mtime unavailable'),
            # A rename source that exists before any journal is never owned.
            'temp-file': ({}, None, 'temporary path collision: ' + str(self.root) + '/etc/config/firewall.couvrefeu-tmp; no installation made'),
            'temp-symlink': ({}, None, 'temporary path collision: ' + str(self.root) + '/etc/sysupgrade.conf.couvrefeu-tmp; no installation made'),
            # Live expiry requires a procd cron script that starts at boot.
            'cron-missing': ({'CF_TEST_INSTALL_KERNEL': '1'}, None,
                             'cron init script unavailable or not procd-based: ' + str(self.root) + '/bin/cron; no installation made'),
            'cron-not-procd': ({'CF_TEST_INSTALL_KERNEL': '1'}, ('cron', '#!/bin/sh\nexit 0\n'),
                               'cron init script unavailable or not procd-based: ' + str(self.root) + '/bin/cron; no installation made'),
            # A commented-out marker is not procd; only an exact USE_PROCD=1 line counts.
            'cron-procd-comment': ({'CF_TEST_INSTALL_KERNEL': '1'}, ('cron', '#!/bin/sh\n# USE_PROCD=1\nexit 0\n'),
                                   'cron init script unavailable or not procd-based: ' + str(self.root) + '/bin/cron; no installation made'),
            'cron-disabled': ({'CF_TEST_INSTALL_KERNEL': '1'}, ('cron', '#!/bin/sh\nUSE_PROCD=1\n[ "$1" != enabled ]\n'),
                              'cron service is not enabled at boot; minute expiry would stop after reboot; no installation made'),
        }
        for name, (env, tool, message) in gates.items():
            with self.subTest(gate=name):
                temp = None
                if name == 'temp-file':
                    temp = self.root / 'etc/config/firewall.couvrefeu-tmp'
                    temp.write_bytes(b'foreign\n')
                elif name == 'temp-symlink':
                    temp = self.root / 'etc/sysupgrade.conf.couvrefeu-tmp'
                    temp.symlink_to('/nonexistent-couvrefeu-target')
                saved = None
                if tool:
                    path = self.root / 'bin' / tool[0]
                    saved = path.read_bytes() if path.exists() else None
                    path.write_text(tool[1])
                    path.chmod(0o700)
                self.env.update(env)
                before = full_snapshot(self.root)
                self.assert_refused_identically(before, release, message)
                if temp:
                    result = self.run_script('uninstall.sh')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('No recorded installation; no changes made.', result.stdout)
                    self.assertEqual(full_snapshot(self.root), before)
                    temp.unlink()
                for variable in env:
                    self.env.pop(variable)
                if tool:
                    if saved is None:
                        path.unlink()
                    else:
                        path.write_bytes(saved)

    def test_in_place_append_before_install_rename_refuses_with_intact_copy(self):
        self.write_originals()
        target = self.root / 'etc/config/firewall'
        inode = target.stat().st_ino
        # The durable flush precedes the rename; the target is still the live original.
        wrapper = self.root / 'bin/sync'
        wrapper.write_text('#!/bin/sh\nfor destination do :; done\n'
                           f'case "$destination" in {shlex.quote(str(target))}.couvrefeu-tmp) '
                           f'printf "%s\\n" "# in-place append" >> {shlex.quote(str(target))};; esac\n'
                           f'exec {shlex.quote(shutil.which("sync"))} "$@"\n')
        wrapper.chmod(0o700)
        result = self.install('--activate')
        wrapper.unlink()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('original changed in place before install rename: /etc/config/firewall; installation refused, journal retained', result.stderr)
        backup = self.root / 'etc/couvrefeu/backup'
        self.assertFalse((backup / 'complete').exists())
        self.assertEqual(target.stat().st_ino, inode)
        self.assertEqual(target.read_bytes(), EXISTING_ORIGINALS['etc/config/firewall'] + b'# in-place append\n')
        before = full_snapshot(self.root)
        for rel, content in EXISTING_ORIGINALS.items():
            self.assertEqual((backup / (rel.replace('/', '_') + '.copy')).read_bytes(), content)
        for retry in ('install.sh', 'uninstall.sh'):
            with self.subTest(retry=retry):
                result = self.install('--activate') if retry == 'install.sh' else self.run_script(retry)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(full_snapshot(self.root), before)
        self.assertEqual((backup / 'etc_config_firewall.copy').read_bytes(), EXISTING_ORIGINALS['etc/config/firewall'])

    def test_in_place_append_while_copying_original_refuses_before_ready(self):
        self.write_originals()
        target = self.root / 'etc/config/firewall'
        real_copy = shutil.which('cp')
        wrapper = self.root / 'bin/cp'
        # The recovery copy reads the shared inode; a concurrent append corrupts both.
        wrapper.write_text('#!/bin/sh\nfor destination do :; done\n'
                           'case "$destination" in */etc_config_firewall.copy) '
                           f'printf "%s\\n" "# in-place append" >> {shlex.quote(str(target))};; esac\n'
                           f'exec {shlex.quote(real_copy)} "$@"\n')
        wrapper.chmod(0o700)
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('original recovery copy mismatch: etc/config/firewall; no installation made', result.stderr)
        # The append is the writer's own change to the live file; no journal remains.
        self.assertEqual(target.read_bytes(), EXISTING_ORIGINALS['etc/config/firewall'] + b'# in-place append\n')
        self.assertFalse((self.root / 'etc/couvrefeu/backup').exists())
        self.assertEqual(list(self.root.glob('.couvrefeu-stage.*')), [])

    def test_in_place_append_after_restore_rename_refuses_with_intact_copy(self):
        originals = self.write_originals()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env['CF_TEST_UNINSTALL_CRASH_AT'] = 'restored'
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.env.pop('CF_TEST_UNINSTALL_CRASH_AT')
        self.kill_lock()
        recovery = self.root / '.couvrefeu-recovery'
        target = self.root / 'etc/config/firewall'
        # The journal original itself was renamed back; it is no longer in the journal.
        self.assertEqual(exact_signature(target), originals['etc/config/firewall'])
        self.assertFalse((recovery / 'etc_config_firewall.original').exists())
        with target.open('ab') as stream:
            stream.write(b'# in-place append\n')
        before = full_snapshot(self.root)
        for _ in range(2):
            result = self.run_script('uninstall.sh')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('drift at /etc/config/firewall', result.stderr)
            self.assertEqual(full_snapshot(self.root), before)
        self.assertFalse((self.root / '.couvrefeu-recovery.done').exists())
        for rel, content in EXISTING_ORIGINALS.items():
            self.assertEqual((recovery / (rel.replace('/', '_') + '.copy')).read_bytes(), content)

    def substitute_original(self, mtime_ns):
        backup = self.root / 'etc/couvrefeu/backup'
        original = backup / 'etc_config_firewall.original'
        recorded = original.stat()
        substitute = backup / 'substitute'
        shutil.copyfile(original, substitute)
        os.chmod(substitute, recorded.st_mode & 0o7777)
        os.utime(substitute, ns=(recorded.st_atime_ns, mtime_ns))
        os.replace(substitute, original)
        replaced = original.stat()
        self.assertNotEqual(replaced.st_ino, recorded.st_ino)
        self.assertEqual(signature(original), (backup / 'etc_config_firewall.before').read_text().strip())
        return recorded

    def test_substituted_original_with_truncated_mtime_refuses_identically(self):
        # Successor of the inode-substitution test: what a cross-filesystem mv
        # fallback or cp -p leaves behind (same bytes, mode, owner; truncated
        # mtime) is not the original. Every retry refuses before any write.
        self.write_originals()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        recorded = self.root / 'etc/couvrefeu/backup/etc_config_firewall.original'
        self.substitute_original(recorded.stat().st_mtime_ns // 1000 * 1000)
        before = full_snapshot(self.root)
        for script in ('uninstall.sh', 'install.sh'):
            with self.subTest(script=script):
                result = self.install('--activate') if script == 'install.sh' else self.run_script(script)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('corrupt original backup mtime: etc/config/firewall', result.stderr)
                self.assertEqual(full_snapshot(self.root), before)
        self.assertEqual((self.root / 'etc/couvrefeu/backup/etc_config_firewall.copy').read_bytes(),
                         EXISTING_ORIGINALS['etc/config/firewall'])

    def test_stat_without_mount_point_refuses_before_first_write(self):
        # A stat that cannot report %m (BusyBox prints '?') must not make both
        # sides look like one filesystem.
        release = self.enable_release()
        self.write_originals()
        wrapper = self.root / 'bin/stat'
        wrapper.write_text('#!/bin/sh\nif [ "$1" = -c ] && [ "$2" = "%d %m" ]; then shift 2; for p do echo "19 ?"; done; exit 0; fi\n'
                           f'exec {shlex.quote(shutil.which("stat"))} "$@"\n')
        wrapper.chmod(0o700)
        before = full_snapshot(self.root)
        self.assert_refused_identically(
            before, release, 'original, journal and recovery journal are not on one filesystem: /etc/config/firewall; no installation made')
        self.assert_no_touch()

    def test_installed_content_is_proved_after_the_install_rename(self):
        # A write landing on the new file right after the second rename is
        # not the staged content: refuse with the original journaled.
        originals = self.write_originals()
        target = self.root / 'etc/config/firewall'
        flag = self.root / 'tamper-once'
        flag.touch()
        wrapper = self.root / 'bin/mv'
        wrapper.write_text(f'#!/bin/sh\n{shlex.quote(shutil.which("mv"))} "$@" || exit\n'
                           f'case "$*" in *.couvrefeu-tmp" "{target}) ;; *) exit 0;; esac\n'
                           f'if [ -f {shlex.quote(str(flag))} ]; then rm -f {shlex.quote(str(flag))}; printf "#\\n" >> {shlex.quote(str(target))}; fi\n')
        wrapper.chmod(0o700)
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'installed file mismatch after rename: {target}; original journaled, journal retained', result.stderr)
        backup = self.root / 'etc/couvrefeu/backup'
        self.assertFalse((backup / 'complete').exists())
        self.assertEqual(exact_signature(backup / 'etc_config_firewall.original'), originals['etc/config/firewall'])
        # The changed path is drift: uninstall refuses and keeps everything.
        before = full_snapshot(self.root)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('drift at /etc/config/firewall', result.stderr)
        self.assertEqual(full_snapshot(self.root), before)
        self.assert_no_touch()

    def test_inexact_journal_original_after_rename_refuses_and_rolls_back(self):
        # A rename that does not keep the original exact (e.g. a copy fallback)
        # is caught right after the pair and the original goes back in place.
        for change in ('mtime', 'bytes'):
            with self.subTest(change=change):
                self.tearDown()
                self.setUp()
                originals = self.write_originals()
                target = self.root / 'etc/config/firewall'
                alter = ({'mtime': f'{shlex.quote(shutil.which("touch"))} -m -d @1234567890 "$2"',
                          'bytes': 'printf x >> "$2"'})[change]
                wrapper = self.root / 'bin/mv'
                wrapper.write_text(f'#!/bin/sh\n{shlex.quote(shutil.which("mv"))} "$@" || exit\n'
                                   f'case "$1" in {target}) case "$2" in *.original) {alter};; esac;; esac\n')
                wrapper.chmod(0o700)
                result = self.install('--activate')
                self.assertNotEqual(result.returncode, 0)
                backup = self.root / 'etc/couvrefeu/backup'
                self.assertIn(f'journal original is not exact after rename: {target}', result.stderr)
                self.assertIn(f'manual recovery copy: {backup}/etc_config_firewall.copy', result.stderr)
                # Rolled back: the path holds the (inexact) original again, never the new content.
                self.assertFalse((backup / 'etc_config_firewall.original').exists())
                self.assertNotEqual(signature(target), signature(backup / 'etc_config_firewall.staged'))
                self.assertNotEqual(exact_signature(target), originals['etc/config/firewall'])
                self.assertFalse((backup / 'complete').exists())
                self.assert_no_touch()

    def test_tampered_journal_original_content_refuses_identically(self):
        # Same mode, owner and nanosecond mtime, other bytes: never renamed back.
        self.write_originals()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        original = self.root / 'etc/couvrefeu/backup/etc_config_firewall.original'
        stamp = original.stat().st_mtime_ns
        original.write_bytes(b"config zone 'wan'\n option input 'ACCEPT'\n")
        os.utime(original, ns=(stamp, stamp))
        installed = exact_signature(self.root / 'etc/config/firewall')
        before = full_snapshot(self.root)
        for script in ('uninstall.sh', 'install.sh'):
            with self.subTest(script=script):
                result = self.install('--activate') if script == 'install.sh' else self.run_script(script)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('corrupt original backup: etc/config/firewall', result.stderr)
                self.assertEqual(full_snapshot(self.root), before)
        self.assertEqual(exact_signature(self.root / 'etc/config/firewall'), installed)
        self.assertEqual((self.root / 'etc/couvrefeu/backup/etc_config_firewall.copy').read_bytes(),
                         EXISTING_ORIGINALS['etc/config/firewall'])

    def test_exact_substitute_original_restores_exactly(self):
        # Identity is exact bytes, mode, owner and nanosecond mtime, not an
        # inode number (overlayfs reports lower-origin inode numbers).
        originals = self.write_originals()
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        recorded = self.root / 'etc/couvrefeu/backup/etc_config_firewall.original'
        self.substitute_original(recorded.stat().st_mtime_ns)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.originals_state(), originals)

    def kill_lock(self):
        # A SIGKILLed transaction cannot run its trap; production /tmp is cleared on reboot.
        shutil.rmtree(self.root / '.couvrefeu-install.lock')

    def test_crash_after_link_before_ready_refuses_with_originals_in_place(self):
        originals = self.write_originals()
        self.env['CF_TEST_INSTALL_CRASH_AT'] = 'linked'
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.env.pop('CF_TEST_INSTALL_CRASH_AT')
        self.kill_lock()
        backup = self.root / 'etc/couvrefeu/backup'
        self.assertFalse((backup / 'ready').exists())
        self.assertEqual(self.originals_state(), originals)
        for script in ('install.sh', 'uninstall.sh'):
            result = self.install('--activate') if script == 'install.sh' else self.run_script(script)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('incomplete backup', result.stderr)
            self.assertEqual(self.originals_state(), originals)

    def test_crash_after_ready_before_install_rename_recovers(self):
        for resume in (False, True):
            with self.subTest(resume=resume):
                originals = self.write_originals()
                before = self.snapshot()
                self.env['CF_TEST_INSTALL_CRASH_AT'] = 'ready'
                result = self.install('--activate')
                self.assertNotEqual(result.returncode, 0)
                self.env.pop('CF_TEST_INSTALL_CRASH_AT')
                self.kill_lock()
                for stage in self.root.glob('.couvrefeu-stage.*'):
                    shutil.rmtree(stage)
                # Targets were never renamed: they still are the journal links.
                self.assertEqual(self.originals_state(), originals)
                if resume:
                    result = self.install('--activate')
                    self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.originals_state(), originals)

    def test_crash_after_restore_rename_before_verification_recovers(self):
        originals = self.write_originals()
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env['CF_TEST_UNINSTALL_CRASH_AT'] = 'restored'
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.env.pop('CF_TEST_UNINSTALL_CRASH_AT')
        self.kill_lock()
        recovery = self.root / '.couvrefeu-recovery'
        # Each exact original is in exactly one place: renamed back, or still journaled.
        for rel, exact in originals.items():
            original = recovery / (rel.replace('/', '_') + '.original')
            places = [p for p in (original, self.root / rel) if exact_signature(p) == exact]
            self.assertEqual(len(places), 1, rel)
        self.assertFalse((recovery / 'etc_config_firewall.original').exists())
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.originals_state(), originals)

    def test_target_drift_before_uninstall_preserves_original(self):
        originals = self.write_originals()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        target = self.root / 'etc/config/firewall'
        with target.open('ab') as stream:
            stream.write(b'# drift\n')
        before = full_snapshot(self.root)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('drift at /etc/config/firewall', result.stderr)
        self.assertEqual(full_snapshot(self.root), before)
        original = self.root / 'etc/couvrefeu/backup/etc_config_firewall.original'
        self.assertEqual(exact_signature(original), originals['etc/config/firewall'])

    def test_cleanup_never_deletes_an_unrestored_original(self):
        originals = self.write_originals()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env['CF_TEST_UNINSTALL_CLEANUP_FAIL_AFTER'] = '1'
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.env.pop('CF_TEST_UNINSTALL_CLEANUP_FAIL_AFTER')
        self.assertTrue((self.root / '.couvrefeu-recovery.done').is_file())
        # Someone replaces a restored original after completion was published.
        target = self.root / 'etc/config/firewall'
        target.unlink()
        target.write_bytes(b'replacement\n')
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('original backup is not restored at /etc/config/firewall', result.stderr)
        # The original was renamed back by the completed restore; the journal
        # and its manual recovery copy are kept.
        recovery = self.root / '.couvrefeu-recovery'
        self.assertFalse((recovery / 'etc_config_firewall.original').exists())
        self.assertEqual((recovery / 'etc_config_firewall.copy').read_bytes(), EXISTING_ORIGINALS['etc/config/firewall'])
        self.assertTrue(originals)

    def test_restore_rename_failure_retains_journal_and_retries(self):
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        target.chmod(0o640)
        os.utime(target, ns=(FRACTIONAL, FRACTIONAL))
        original = exact_signature(target)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = exact_signature(target)
        # A rename that cannot happen (as EXDEV would) restores nothing.
        wrapper = self.root / 'bin/mv'
        wrapper.write_text('#!/bin/sh\ncase "$*" in *.original" "*) printf "mv: Invalid cross-device link\\n" >&2; exit 1;; esac\n'
                           f'exec {shlex.quote(shutil.which("mv"))} "$@"\n')
        wrapper.chmod(0o700)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exact original rename failed', result.stderr)
        self.assertEqual(exact_signature(target), installed)
        backup = self.root / '.couvrefeu-recovery'
        self.assertEqual(exact_signature(backup / 'etc_config_firewall.original'), original)
        self.assertFalse((backup / 'restored').exists())
        wrapper.unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(exact_signature(target), original)
        self.assertFalse(backup.exists())
        self.assert_no_touch()

    def test_native_busybox_cp_and_mv_actual_timestamp_capability(self):
        shell = shlex.split(os.environ.get('CF_TEST_SHELL', 'sh'))
        busybox = os.environ.get('CF_TEST_BUSYBOX_CP') or (shell[0] if len(shell) == 2 and shell[1] == 'ash' else shutil.which('busybox'))
        if not busybox or subprocess.run([busybox, 'cp', '--help'], capture_output=True).returncode == 127:
            self.skipTest('native BusyBox cp unavailable; capability remains unproved')
        # This BusyBox's own cp and mv carry every copy and rename; touch is never used.
        for tool in ('cp', 'mv'):
            wrapper = self.root / 'bin' / tool
            wrapper.write_text(f'#!/bin/sh\nprintf "%s\\n" {tool} >> {shlex.quote(str(self.cp_log))}\n'
                               'exec ' + shlex.quote(busybox) + f' {tool} "$@"\n')
            wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        target.chmod(0o640)
        # Restoration no longer depends on cp precision: both stamps restore.
        for stamp in (FRACTIONAL, 1_234_567_890_000_000_000):
            with self.subTest(nanoseconds=stamp):
                os.utime(target, ns=(stamp, stamp))
                before = self.snapshot()
                result = self.install('--activate')
                self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(target.stat().st_mtime_ns, stamp)
                self.assertEqual(set(self.cp_log.read_text().split()), {'cp', 'mv'})
                self.assert_no_touch()

    def test_original_backup_mtime_corruption_refuses_all_restoration(self):
        backup = self.root / 'etc/couvrefeu/backup'
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        original = backup / 'etc_config_firewall.original'
        stamp = original.stat().st_mtime_ns + 1
        os.utime(original, ns=(stamp, stamp))
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('corrupt original backup mtime', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_missing_original_timestamp_record_preserves_installation(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / 'etc/couvrefeu/backup/etc_config_firewall.mtime').unlink()
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing/invalid original mtime record', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_stat_without_fractional_reporting_refuses_activation(self):
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        real_stat = shutil.which('stat')
        wrapper = self.root / 'bin/stat'
        wrapper.write_text('#!/bin/sh\n'
                           'if [ "$1" = -c ] && [ "$2" = "%Y %y" ]; then\n'
                           '    printf "%s\\n" "1234567890 2009-02-13 23:31:30 +0000"; exit 0\n'
                           'fi\nexec ' + shlex.quote(real_stat) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']
        before = self.snapshot()
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('precise original mtime unavailable', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_stat_valid_output_with_failure_refuses_activation(self):
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        real_stat = shutil.which('stat')
        wrapper = self.root / 'bin/stat'
        wrapper.write_text('#!/bin/sh\n'
                           'if [ "$1" = -c ] && [ "$2" = "%Y %y" ]; then\n'
                           + '    ' + shlex.quote(real_stat) + ' "$@"; exit 7\n'
                           'fi\nexec ' + shlex.quote(real_stat) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']
        before = self.snapshot()
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('precise original mtime unavailable', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_activation_gate_failure_leaves_originals(self):
        self.env['CF_TEST_CHECK_FAIL'] = '1'
        before = self.snapshot()
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / 'etc').exists())

    def test_partial_install_resume_and_uninstall(self):
        before = self.snapshot()
        self.env['CF_TEST_INSTALL_FAIL_AFTER'] = '5'
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.env.pop('CF_TEST_INSTALL_FAIL_AFTER')
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / 'etc').exists())

    def test_partial_install_direct_uninstall(self):
        before = self.snapshot()
        self.env['CF_TEST_INSTALL_FAIL_AFTER'] = '5'
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_protection_required(self):
        result = self.install('--activate', protect=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'etc').exists())

    def test_unknown_runtime_preserved(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        runtime = self.root / 'etc/couvrefeu/runtime'
        runtime.mkdir(mode=0o700)
        (runtime / 'foreign-file').write_text('preserve this')
        (runtime / 'foreign-file').chmod(0o600)
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_owned_runtime_removed(self):
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        runtime = self.root / 'etc/couvrefeu/runtime'
        runtime.mkdir(mode=0o700)
        for name in ('confirmed', 'error', 'firewall.snapshot', '.candidate.123'):
            (runtime / name).write_text('owned')
            (runtime / name).chmod(0o600)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_owned_firewall_transaction_then_uninstall(self):
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        target = self.root / 'etc/config/firewall'
        candidate = self.root / 'candidate'
        shutil.copy2(target, candidate)
        with candidate.open('a') as stream:
            stream.write("\nconfig rule 'cf_sched_child_1'\n option target 'REJECT'\n")
        helper = 'lib/install-common.sh'
        result = self.run_script(helper, 'firewall-prepare', str(candidate))
        self.assertEqual(result.returncode, 0, result.stderr)
        shutil.copy2(candidate, target)
        result = self.run_script(helper, 'firewall-commit')
        self.assertEqual(result.returncode, 0, result.stderr)
        candidate.unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_interrupted_owned_firewall_transaction_uninstall(self):
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        target = self.root / 'etc/config/firewall'
        candidate = self.root / 'candidate'
        shutil.copy2(target, candidate)
        with candidate.open('a') as stream:
            stream.write("\nconfig rule 'cf_sched_child_1'\n")
        result = self.run_script('lib/install-common.sh', 'firewall-prepare', str(candidate))
        self.assertEqual(result.returncode, 0, result.stderr)
        shutil.copy2(candidate, target)
        candidate.unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_directory_record_refuses_all_restoration(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.root / 'etc/couvrefeu/backup/dir_etc'
        record.write_text('invalid-mode\n')
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid directory record', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_unknown_backup_entry_refuses_all_restoration(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        unknown = self.root / 'etc/couvrefeu/backup/foreign'
        unknown.write_text('retain me')
        unknown.chmod(0o600)
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unexpected backup entry', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_backup_record_symlink_refuses_all_restoration(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.root / 'etc/couvrefeu/backup/dir_etc'
        record.unlink()
        record.symlink_to(self.source / 'cfctl')
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_reinstall_new_protected_identity_refused(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.snapshot()
        result = self.install('--activate', '--protect', '02:00:00:00:00:02')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot change protected identities', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_reinstall_new_ssh_client_refused(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        ip = self.root / 'bin/ip'
        ip.write_text("#!/bin/sh\nprintf '%s\\n' '192.0.2.2 dev br-lan lladdr 02:00:00:00:00:02 REACHABLE'\n")
        ip.chmod(0o700)
        self.env['SSH_CONNECTION'] = '192.0.2.2 12345 192.0.2.1 22'
        before = self.snapshot()
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot change protected identities', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_fixture_backend_traversal_refused_before_execution(self):
        with tempfile.TemporaryDirectory(prefix='couvre-feu-backend-') as outside:
            external = Path(outside)
            (external / '.couvrefeu-test-backend').touch()
            (external / 'uci').write_text('#!/bin/sh\ntouch "$CF_ROOT/backend-was-run"\n')
            (external / 'uci').chmod(0o700)
            self.env['CF_BACKEND_DIR'] = str(self.root) + '/bin/../../' + external.name
            before = self.snapshot()
            result = self.install('--activate')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('must be canonical', result.stderr)
            self.assertEqual(self.snapshot(), before)
            self.assertFalse((self.root / 'backend-was-run').exists())

    def test_fixture_backend_symlink_ancestor_refused(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root)
        self.env['CF_BACKEND_DIR'] = str(alias / 'bin')
        before = self.snapshot()
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must be canonical', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_core_lock_arriving_during_preflight_refuses_restore(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        real_hash = shutil.which('sha256sum')
        wrapper = self.root / 'bin/sha256sum'
        wrapper.write_text('''#!/bin/sh
if [ "$#" = 1 ] && [ "$1" = "$CF_ROOT/usr/lib/couvrefeu/core.sh" ] && [ -f "$CF_ROOT/block-hash" ]; then
    : > "$CF_ROOT/hash-blocked"
    while [ -f "$CF_ROOT/block-hash" ]; do sleep 0.01; done
fi
exec ''' + shlex.quote(real_hash) + ''' "$@"
''')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']
        block = self.root / 'block-hash'
        signal = self.root / 'hash-blocked'
        block.touch()
        command = [*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')),
                   str(REPO / 'router/uninstall.sh')]
        process = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 15
            while not signal.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(signal.exists(), 'preflight synchronization not reached')
            lock = self.root / 'etc/couvrefeu/runtime/lock'
            lock.mkdir(parents=True, mode=0o700)
            lock.parent.chmod(0o700)
            (lock / 'pid').write_text(str(os.getpid()) + '\n')
            (lock / 'pid').chmod(0o600)
            block.unlink()
            signal.unlink()
            expected = self.snapshot()
            # The transient installation lock is correctly removed on exit.
            expected = {k: v for k, v in expected.items() if not k.startswith('.couvrefeu-install.lock/')}
            _, stderr = process.communicate(timeout=20)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn('runtime lock', stderr)
            self.assertEqual(self.snapshot(), expected)
        finally:
            if block.exists():
                block.unlink()
            if process.poll() is None:
                process.kill()
            process.communicate()


class InterruptedRecoveryTests(unittest.TestCase):
    """Real transaction paths, with local, explicitly marked tool boundaries."""
    setUp = InstallerTests.setUp
    tearDown = InstallerTests.tearDown
    run_script = InstallerTests.run_script
    snapshot = InstallerTests.snapshot
    install = InstallerTests.install

    def tool_failure(self, tool, destination):
        real_tool = shutil.which(tool)
        wrapper = self.root / 'bin' / tool
        wrapper.write_text("#!/bin/sh\nfor argument do destination=$argument; done\n"
                           'if [ "$destination" = "$CF_TEST_FAIL_TARGET" ] && [ -f "$CF_ROOT/fail-tool" ]; then exit 73; fi\n'
                           + 'exec ' + shlex.quote(real_tool) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']
        self.env['CF_TEST_FAIL_TARGET'] = str(destination)
        (self.root / 'fail-tool').touch()

    def production_tools(self):
        self.env['CF_TEST_INSTALL_KERNEL'] = '1'
        (self.source / 'cfctl').write_text('''#!/bin/sh
set -eu
[ -f "$CF_BACKEND_DIR/.couvrefeu-test-backend" ] || exit 92
case "$1" in
check) exit 0;;
apply-fw|remove-fw)
    [ "$0" = "$CF_ROOT/usr/sbin/cfctl" ] || exit 93
    [ "$CF_INSTALL_TOKEN" = "$(cat "$CF_ROOT/.couvrefeu-install.lock/token")" ] || exit 94
    printf '%s\n' "$1" >> "$CF_ROOT/tool-log"
    [ "$1" != "${CF_TEST_CORE_FAIL:-}" ];;
*) exit 95;;
esac
''')
        (self.source / 'lib/core.sh').write_text('cf_check() { return 0; }\ncf_main() {\n    [ "$CF_INSTALL_TOKEN" = "$(cat "$CF_ROOT/.couvrefeu-install.lock/token")" ] || return 94\n    printf \'%s\\n\' "$1" >> "$CF_ROOT/tool-log"\n    [ "$1" != "${CF_TEST_CORE_FAIL:-}" ]\n}\n')
        core = self.root / 'bin/core'
        core.write_text('#!/bin/sh\n[ "$CF_INSTALL_TOKEN" = "$(cat "$CF_ROOT/.couvrefeu-install.lock/token")" ] || exit 94\nprintf \'%s\\n\' "$1" >> "$CF_ROOT/tool-log"\n[ "$1" != "${CF_TEST_CORE_FAIL:-}" ]\n')
        core.chmod(0o700)
        tool = self.root / 'bin/firewall'
        tool.write_text('''#!/bin/sh
set -eu
[ "$1" = reload ] && [ -f "$CF_BACKEND_DIR/.couvrefeu-test-backend" ] || exit 96
printf '%s\n' reload >> "$CF_ROOT/tool-log"
[ "${CF_TEST_RELOAD_FAIL:-0}" != 1 ]
''')
        tool.chmod(0o700)
        # OpenWrt 21.02 procd cron init double: reload stops crond without
        # crontabs, (re)starts it only for changed tables; `running` reports it.
        cron = self.root / 'bin/cron'
        cron.write_text('''#!/bin/sh
USE_PROCD=1
set -eu
[ -f "$CF_BACKEND_DIR/.couvrefeu-test-backend" ] || exit 96
printf '%s\\n' "$1" >> "$CF_ROOT/cron-log"
[ "$1" != "${CF_TEST_CRON_FAIL:-}" ] || exit 1
case "$1" in
reload)
    if [ -z "$(ls "$CF_ROOT/etc/crontabs" 2>/dev/null)" ]; then
        rm -f "$CF_ROOT/crond-table"; printf '%s\\n' stopped >> "$CF_ROOT/cron-log"; exit 0
    fi
    if [ -f "$CF_ROOT/crond-table" ] && cat "$CF_ROOT"/etc/crontabs/* | cmp -s - "$CF_ROOT/crond-table"; then exit 0; fi
    exec "$CF_BACKEND_DIR/crond";;
enabled) [ "${CF_TEST_CRON_DISABLED:-0}" != 1 ];;
*) exit 95;;
esac
''')
        cron.chmod(0o700)
        # procd ubus double: the cron instance runs while crond holds a table.
        ubus = self.root / 'bin/ubus'
        ubus.write_text('''#!/bin/sh
set -eu
[ "$*" = 'call service list {"name":"cron"}' ] || exit 95
printf '%s\\n' ubus >> "$CF_ROOT/cron-log"
[ "${CF_TEST_CRON_FAIL:-}" != ubus-fail ] || exit 4
running=false
if [ -f "$CF_ROOT/crond-table" ] && [ "${CF_TEST_CRON_FAIL:-}" != ubus-stopped ]; then running=true; fi
printf '{\\n\\t"cron": {\\n\\t\\t"instances": {\\n\\t\\t\\t"instance1": {\\n\\t\\t\\t\\t"running": %s,\\n\\t\\t\\t\\t"pid": 1234\\n\\t\\t\\t}\\n\\t\\t}\\n\\t}\\n}\\n' "$running"
''')
        ubus.chmod(0o700)
        # jsonfilter subset double for this one expression only.
        jsonfilter = self.root / 'bin/jsonfilter'
        jsonfilter.write_text('''#!/bin/sh
set -eu
[ "$*" = '-e @.cron.instances[*].running' ] || exit 95
grep -o -E '"running": *(true|false)' | sed 's/.*: *//'
''')
        jsonfilter.chmod(0o700)
        # crond double: records exactly the tables it loaded at (re)start.
        crond = self.root / 'bin/crond'
        crond.write_text('#!/bin/sh\nset -eu\ncat "$CF_ROOT"/etc/crontabs/* > "$CF_ROOT/crond-table"\n'
                         'printf \'%s\\n\' started >> "$CF_ROOT/cron-log"\n')
        crond.chmod(0o700)

    def assert_originals_retained(self, backup):
        self.assertTrue((backup / 'ready').is_file())
        for rel in FILES:
            key = rel.replace('/', '_')
            before = (backup / (key + '.before')).read_text().strip()
            if before != 'absent':
                self.assertEqual(signature(backup / (key + '.original')), before)
            self.assertTrue((backup / (key + '.staged')).is_file())
        for rel in DIRS:
            self.assertTrue((backup / ('dir_' + rel.replace('/', '_'))).is_file())

    def test_directory_chmod_failure_retains_originals_and_retries(self):
        base = self.root / 'etc/couvrefeu'
        base.mkdir(parents=True, mode=0o750)
        base.chmod(0o750)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.tool_failure('chmod', base)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(base.stat().st_mode & 0o777, 0o700)
        self.assert_originals_retained(self.root / '.couvrefeu-recovery')
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(base.stat().st_mode & 0o777, 0o750)
        self.assertFalse((self.root / '.couvrefeu-recovery').exists())

    def test_retry_accepts_original_base_mode_after_later_directory_failure(self):
        base = self.root / 'etc/couvrefeu'
        base.mkdir(parents=True)
        base.chmod(0o750)
        base.parent.chmod(0o750)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.tool_failure('chmod', base.parent)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(base.stat().st_mode & 0o777, 0o750)
        self.assert_originals_retained(self.root / '.couvrefeu-recovery')
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(base.stat().st_mode & 0o777, 0o750)

    def test_absent_directory_removal_failure_keeps_journal(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.tool_failure('rmdir', self.root / 'etc/couvrefeu')
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assert_originals_retained(self.root / '.couvrefeu-recovery')
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'etc').exists())

    def test_completion_rename_failure_retries_after_all_directories_removed(self):
        self.production_tools()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.tool_failure('mv', self.root / '.couvrefeu-recovery.done')
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'etc').exists())
        self.assert_originals_retained(self.root / '.couvrefeu-recovery')
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'tool-log').read_text().splitlines(),
                         ['apply-fw', 'remove-fw', 'reload'])

    def test_legacy_completion_after_truncated_restore_is_preserved(self):
        busybox = os.environ.get('CF_TEST_BUSYBOX_CP') or shutil.which('busybox')
        if not busybox or subprocess.run([busybox, 'cp', '--help'], capture_output=True).returncode == 127:
            self.skipTest('native BusyBox cp unavailable; legacy fractional replay unproved')
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        target.chmod(0o640)
        stamp = 1_234_567_890_123_456_789
        os.utime(target, ns=(stamp, stamp))
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        backup = self.root / 'etc/couvrefeu/backup'
        # Reenact the independently reproduced historical terminal state:
        # native cp -p restores original bytes/mode/owners with lost fractions;
        # the legacy journal has no timestamp records and trusts DONE=1.
        adapter_files = ('usr/lib/couvrefeu/platform-bootstrap.sh',
                         'usr/lib/couvrefeu/vendor-platform.sh',
                         'etc/couvrefeu/platform-profile',
                         'usr/lib/couvrefeu/activity.sh',
                         # A legacy journal also predates the M1d per-admin scope wrapper.
                         'usr/sbin/cfctl-scope')
        for rel in FILES + adapter_files:
            key = rel.replace('/', '_')
            original = backup / (key + '.original')
            destination = self.root / rel
            if original.exists():
                copy = subprocess.run([busybox, 'cp', '-p', str(original), str(destination)], capture_output=True)
                self.assertEqual(copy.returncode, 0, copy.stderr)
            else:
                destination.unlink()
            (backup / (key + '.mtime')).unlink()
        # A genuine pre-adapter journal has neither profile nor adapter entries.
        # Remove those records after replaying their originally absent paths.
        for rel in adapter_files:
            for entry in backup.glob(rel.replace('/', '_') + '.*'):
                entry.unlink()
        self.assertEqual(target.stat().st_mtime_ns, stamp // 1_000_000_000 * 1_000_000_000)
        recovery = self.root / '.couvrefeu-recovery'
        backup.rename(recovery)
        for rel in sorted(DIRS, key=lambda rel: rel.count('/'), reverse=True):
            mode = (recovery / ('dir_' + rel.replace('/', '_'))).read_text().strip()
            directory = self.root / rel
            if mode == 'absent':
                directory.rmdir()
            else:
                directory.chmod(int(mode, 8))
        done = self.root / '.couvrefeu-recovery.done'
        done.write_text('1\n')
        done.chmod(0o600)
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('completion_binding', result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(recovery.is_dir())

    def test_exact_completion_partial_cleanup_retries_without_timestamp_records(self):
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        stamp = 1_234_567_890_123_456_789
        os.utime(target, ns=(stamp, stamp))
        original = exact_signature(target)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        recovery = self.root / '.couvrefeu-recovery'
        self.tool_failure('rm', recovery / 'etc_config_firewall.mtime')
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        done = self.root / '.couvrefeu-recovery.done'
        self.assertEqual(done.read_text().splitlines()[:2], ['3', 'strict'])
        self.assertEqual(len(done.read_text().splitlines()[2]), 64)
        self.assertFalse((recovery / 'etc_config_firewall.before').exists())
        self.assertEqual(exact_signature(target), original)
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(exact_signature(target), original)
        self.assertFalse(recovery.exists())
        self.assertFalse(done.exists())

    def test_every_file_interruption_retries_after_removed_helpers(self):
        for count in range(1, len(NEW_FILES) + 1):
            with self.subTest(count=count):
                self.production_tools()
                result = self.install('--activate')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.env['CF_TEST_UNINSTALL_FAIL_AFTER'] = str(count)
                result = self.run_script('uninstall.sh')
                self.assertNotEqual(result.returncode, 0)
                self.assert_originals_retained(self.root / '.couvrefeu-recovery')
                result = self.install('--activate')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('recovery is pending', result.stderr)
                self.env.pop('CF_TEST_UNINSTALL_FAIL_AFTER')
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.root / 'tool-log').read_text().splitlines(),
                                 ['apply-fw', 'remove-fw', 'reload'])
                (self.root / 'tool-log').unlink()

    def test_failed_kernel_cleanup_keeps_program_and_retries(self):
        self.production_tools()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env['CF_TEST_CORE_FAIL'] = 'remove-fw'
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / 'usr/sbin/cfctl').is_file())
        self.assert_originals_retained(self.root / 'etc/couvrefeu/backup')
        self.assertFalse((self.root / 'etc/couvrefeu/backup/kernel-cleaned').exists())
        self.env.pop('CF_TEST_CORE_FAIL')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'tool-log').read_text().splitlines(),
                         ['apply-fw', 'remove-fw', 'remove-fw', 'reload'])

    def test_failed_apply_is_cleaned_on_uninstall(self):
        self.production_tools()
        self.env['CF_TEST_CORE_FAIL'] = 'apply-fw'
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assert_originals_retained(self.root / 'etc/couvrefeu/backup')
        self.env.pop('CF_TEST_CORE_FAIL')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'tool-log').read_text().splitlines(),
                         ['apply-fw', 'remove-fw', 'reload'])

    def test_failed_reload_retries_without_installed_program(self):
        self.production_tools()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env['CF_TEST_RELOAD_FAIL'] = '1'
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'usr/sbin/cfctl').exists())
        self.assert_originals_retained(self.root / '.couvrefeu-recovery')
        self.env.pop('CF_TEST_RELOAD_FAIL')
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'tool-log').read_text().splitlines(),
                         ['apply-fw', 'remove-fw', 'reload', 'reload'])

    def test_install_rename_failure_resumes_owned_temp(self):
        target = self.root / 'usr/lib/couvrefeu/core.sh'
        self.tool_failure('mv', target)
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(Path(str(target) + '.couvrefeu-tmp').exists())
        (self.root / 'fail-tool').unlink()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(Path(str(target) + '.couvrefeu-tmp').exists())
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uninstall_after_failed_install_rename_removes_owned_temp(self):
        target = self.root / 'usr/lib/couvrefeu/core.sh'
        self.tool_failure('mv', target)
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'etc').exists())
        self.assertFalse((self.root / 'usr').exists())

    def mv_shim(self, script):
        """`mv` wrapper: $script runs with the operands in "$@"; it may exit or fall through to the real mv."""
        wrapper = self.root / 'bin/mv'
        wrapper.write_text('#!/bin/sh\n' + script + '\nexec ' + shlex.quote(shutil.which('mv')) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']

    def check_recovery(self, scenario):
        """Run scenario() fresh twice; from its state, resume+uninstall and direct uninstall restore exactly."""
        for resume in (False, True):
            with self.subTest(resume=resume):
                self.tearDown()
                self.setUp()
                before, originals = scenario()
                (self.root / 'bin/mv').unlink(missing_ok=True)
                (self.root / 'fail-tool').unlink(missing_ok=True)
                if resume:
                    result = self.install('--activate')
                    self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(Path(str(self.root / 'etc/config/firewall') + '.couvrefeu-tmp').exists())
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(InstallerTests.originals_state(self), originals)
                InstallerTests.assert_no_touch(self)

    def test_install_rename_failure_rolls_the_original_back_in_place(self):
        # ENOSPC-like failure of the second rename: the original is renamed
        # straight back, so the managed path is never left absent.
        def scenario():
            originals = InstallerTests.write_originals(self)
            before = self.snapshot()
            target = self.root / 'etc/config/firewall'
            self.mv_shim(f'case "$*" in *.couvrefeu-tmp" "{target}) echo "mv: No space left on device" >&2; exit 1;; esac')
            result = self.install('--activate')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f'install rename failed: {target}; original restored in place, journal retained', result.stderr)
            backup = self.root / 'etc/couvrefeu/backup'
            self.assertEqual(exact_signature(target), originals['etc/config/firewall'])
            self.assertFalse((backup / 'etc_config_firewall.original').exists())
            self.assertFalse((backup / 'complete').exists())
            return before, originals
        self.check_recovery(scenario)

    def test_install_rename_and_rollback_failure_names_manual_copy(self):
        # Both renames onto the path fail: the journaled original and the owned
        # temporary file are the recovery state; the message names .copy.
        def scenario():
            originals = InstallerTests.write_originals(self)
            before = self.snapshot()
            target = self.root / 'etc/config/firewall'
            self.tool_failure('mv', target)
            result = self.install('--activate')
            self.assertNotEqual(result.returncode, 0)
            backup = self.root / 'etc/couvrefeu/backup'
            self.assertIn(f'install rename failed and original rollback failed: {target}; original journaled at {backup}/etc_config_firewall.original;'
                          f' manual recovery copy: {backup}/etc_config_firewall.copy', result.stderr)
            self.assertFalse(target.exists())
            self.assertEqual(exact_signature(backup / 'etc_config_firewall.original'), originals['etc/config/firewall'])
            self.assertEqual(signature(Path(str(target) + '.couvrefeu-tmp')), signature(backup / 'etc_config_firewall.staged'))
            return before, originals
        self.check_recovery(scenario)

    def test_signal_between_install_renames_completes_the_pair(self):
        # TERM/INT/HUP to the transaction while the original is journaled: the
        # pair still completes, then the installer stops with the journal kept.
        def scenario():
            originals = InstallerTests.write_originals(self)
            before = self.snapshot()
            target = self.root / 'etc/config/firewall'
            flag = self.root / 'signal-once'
            flag.touch()
            self.mv_shim(f'case "$*" in *{target}" "*.original) ;; *) exec {shlex.quote(shutil.which("mv"))} "$@";; esac\n'
                         f'{shlex.quote(shutil.which("mv"))} "$@" || exit\n'
                         f'if [ -f {shlex.quote(str(flag))} ]; then rm -f {shlex.quote(str(flag))}\n'
                         '    main=$(awk \'{print $4}\' /proc/$PPID/stat)\n'
                         '    for sig in HUP INT TERM; do kill -s $sig $PPID $main; done\nfi\nexit 0')
            result = self.install('--activate')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(flag.exists())
            backup = self.root / 'etc/couvrefeu/backup'
            self.assertEqual(signature(target), signature(backup / 'etc_config_firewall.staged'))
            self.assertEqual(exact_signature(backup / 'etc_config_firewall.original'), originals['etc/config/firewall'])
            self.assertFalse((backup / 'complete').exists())
            return before, originals
        self.check_recovery(scenario)

    def test_deleted_installed_path_is_drift_not_crash_state(self):
        # Absent path + journaled original is crash state only with the owned
        # temporary file. A user deletion after install refuses as drift.
        originals = InstallerTests.write_originals(self)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / 'etc/config/firewall').unlink()
        before = full_snapshot(self.root)
        for script in ('uninstall.sh', 'install.sh'):
            with self.subTest(script=script):
                result = self.install('--activate') if script == 'install.sh' else self.run_script(script)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('drift at /etc/config/firewall', result.stderr)
                self.assertEqual(full_snapshot(self.root), before)
        self.assertEqual(exact_signature(self.root / 'etc/couvrefeu/backup/etc_config_firewall.original'), originals['etc/config/firewall'])

    def test_restore_rename_failure_resumes_owned_original(self):
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        target.chmod(0o640)
        original = signature(target)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = signature(target)
        self.tool_failure('mv', target)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        # Restoration renames the journal original itself; nothing is staged.
        self.assertFalse(Path(str(target) + '.couvrefeu-tmp').exists())
        self.assertEqual(signature(target), installed)
        self.assert_originals_retained(self.root / '.couvrefeu-recovery')
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(signature(target), original)

    def test_foreign_or_wrong_mode_temp_refuses_before_any_restore(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        target = self.root / 'usr/lib/couvrefeu/core.sh'
        temp = Path(str(target) + '.couvrefeu-tmp')
        for content, mode in [(b'foreign', 0o644), (target.read_bytes(), 0o600)]:
            temp.write_bytes(content)
            temp.chmod(mode)
            before = self.snapshot()
            result = self.run_script('uninstall.sh')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('temporary path collision', result.stderr)
            self.assertEqual(self.snapshot(), before)
            temp.unlink()

    def test_relocation_failure_retries_without_repeat_kernel_cleanup(self):
        self.production_tools()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.tool_failure('mv', self.root / '.couvrefeu-recovery')
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assert_originals_retained(self.root / 'etc/couvrefeu/backup')
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'tool-log').read_text().splitlines(),
                         ['apply-fw', 'remove-fw', 'reload'])

    def test_final_cleanup_failure_retains_completion_and_retries(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.tool_failure('rm', self.root / '.couvrefeu-recovery/usr_sbin_cfctl.staged')
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'etc').exists())
        self.assertFalse((self.root / 'usr').exists())
        self.assertTrue((self.root / '.couvrefeu-recovery.done').is_file())
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / '.couvrefeu-recovery').exists())
        self.assertFalse((self.root / '.couvrefeu-recovery.done').exists())

    def test_recovery_collision_and_symlink_refuse(self):
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        collision = self.root / '.couvrefeu-recovery'
        collision.mkdir(mode=0o700)
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ambiguous', result.stderr)
        self.assertEqual(self.snapshot(), before)
        collision.rmdir()
        collision.symlink_to(self.root / 'source')
        before = self.snapshot()
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)
        self.assertEqual(self.snapshot(), before)


class ReleaseRetirementTests(unittest.TestCase):
    """The external recovery release is retired only when this installation created it."""
    setUp = InstallerTests.setUp
    tearDown = InstallerTests.tearDown
    run_script = InstallerTests.run_script
    snapshot = InstallerTests.snapshot
    install = InstallerTests.install

    def release(self):
        self.env['CF_TEST_RELEASE_DIR'] = '1'
        # Production /etc always exists before the release is created.
        (self.root / 'etc').mkdir(mode=0o755, exist_ok=True)
        bootstrap = (REPO / 'router/lib/platform-bootstrap.sh').read_text()
        release_id = next(line.split('=', 1)[1] for line in bootstrap.splitlines() if line.startswith('CF_RELEASE_ID='))
        return self.root / ('etc/.couvrefeu-release-' + release_id)

    def run_release_uninstall(self, release):
        return subprocess.run([*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')), str(release / 'uninstall.sh')],
                              env=self.env, capture_output=True, text=True)

    def test_created_release_removed_after_exact_uninstall(self):
        release = self.release()
        before = self.snapshot()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((release / 'uninstall.sh').is_file())
        self.assertTrue((self.root / 'etc/couvrefeu/backup/release-absent').is_file())
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Recovery release removed', result.stdout)
        self.assertFalse(release.exists())
        self.assertEqual(self.snapshot(), before)

    def test_uninstall_running_from_release_removes_itself_last(self):
        release = self.release()
        before = self.snapshot()
        self.assertEqual(self.install('--activate').returncode, 0)
        result = self.run_release_uninstall(release)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.rstrip().endswith('Recovery release removed: ' + str(release)), result.stdout)
        self.assertFalse(release.exists())
        self.assertEqual(self.snapshot(), before)

    def test_preexisting_release_is_kept(self):
        release = self.release()
        (release / 'lib').mkdir(parents=True, mode=0o700)
        release.chmod(0o700)
        emitted = self.root / 'emitted-release'
        subprocess.run([sys.executable, '-I', str(REPO / 'tools/freeze-router-release.py'), '--emit', str(emitted)],
                       check=True, capture_output=True)
        for line in (emitted / 'release.sha256').read_text().splitlines():
            name = line.split()[1]
            shutil.copyfile(emitted / name, release / name)
            (release / name).chmod(0o644 if name.startswith('lib/') else 0o755)
        shutil.copyfile(emitted / 'release.sha256', release / 'release.sha256')
        (release / 'release.sha256').chmod(0o600)
        before = self.snapshot()
        self.assertEqual(self.install('--activate').returncode, 0)
        self.assertFalse((self.root / 'etc/couvrefeu/backup/release-absent').exists())
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Recovery release removed', result.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_tampered_or_foreign_release_refused_and_kept(self):
        for label in ('tampered', 'foreign'):
            with self.subTest(label):
                release = self.release()
                before = self.snapshot()
                self.assertEqual(self.install('--activate').returncode, 0)
                target = release / ('cfctl-ssh' if label == 'tampered' else 'lib/extra')
                original = target.read_bytes() if target.exists() else None
                with open(target, 'ab') as handle:
                    handle.write(b'#')
                if label == 'foreign':
                    target.chmod(0o644)
                result = self.run_script('uninstall.sh')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('recovery release', result.stderr)
                self.assertTrue(target.exists())
                self.assertTrue((self.root / '.couvrefeu-recovery/release-absent').is_file())
                # Explicit resolution of the drift lets the retained journal finish.
                if original is None:
                    target.unlink()
                else:
                    target.write_bytes(original)
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(release.exists())
                self.assertEqual(self.snapshot(), before)

    def hold_runtime_lock(self):
        lock = self.root / 'etc/couvrefeu/runtime/lock'
        lock.mkdir(parents=True, mode=0o700)
        lock.parent.chmod(0o700)
        (lock / 'pid').write_text(f'{os.getpid()}\n')
        (lock / 'pid').chmod(0o600)
        return lock

    def test_uninstall_waits_for_concurrent_core_lock(self):
        before = self.snapshot()
        self.assertEqual(self.install('--activate').returncode, 0)
        lock = self.hold_runtime_lock()
        command = [*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')), str(REPO / 'router/uninstall.sh')]
        started = time.monotonic()
        process = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(2)
            self.assertIsNone(process.poll(), 'uninstall did not wait for the runtime lock')
            (lock / 'pid').unlink()
            lock.rmdir()
            _, stderr = process.communicate(timeout=30)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertEqual(process.returncode, 0, stderr)
        self.assertGreaterEqual(time.monotonic() - started, 2)
        self.assertEqual(self.snapshot(), before)

    def test_uninstall_lock_wait_is_bounded(self):
        self.assertEqual(self.install('--activate').returncode, 0)
        self.hold_runtime_lock()
        expected = self.snapshot()
        started = time.monotonic()
        result = subprocess.run([*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')), str(REPO / 'router/uninstall.sh')],
                                env=self.env, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('core operation is running', result.stderr)
        self.assertGreaterEqual(time.monotonic() - started, 19)
        self.assertEqual(self.snapshot(), expected)


class OverlayIdentityTests(unittest.TestCase):
    """Measured GL-XE3000 overlayfs identity (tests/fixtures/overlay.py).

    The live refusal at 7676637 install.sh:296 is reproduced for every copied-up
    or lower-only original; this code installs and restores exactly in every state.
    """
    run_script = InstallerTests.run_script
    snapshot = RecoveryTests.snapshot
    tearDown = RecoveryTests.tearDown
    setUp = InstallerTests.setUp
    install = InstallerTests.install
    install_copy_tool = InstallerTests.install_copy_tool
    write_originals = InstallerTests.write_originals
    enable_release = InstallerTests.enable_release
    assert_refused_identically = InstallerTests.assert_refused_identically
    originals_state = InstallerTests.originals_state
    # Measured lower inode of /rom/etc/sysupgrade.conf is 1072; the rest are illustrative.
    LOWER_INODES = {'etc/config/firewall': 101, 'etc/sysupgrade.conf': 1072, 'etc/crontabs/root': 2001}
    LIVE_LAYOUT = {'etc/config/firewall': 'upper', 'etc/sysupgrade.conf': 'origin', 'etc/crontabs/root': 'absent'}

    def model(self, states, mounts=None):
        self.write_originals()
        for rel, state in states.items():
            if state == 'absent':
                (self.root / rel).unlink()
        self.overlay_log = self.root.parent / (self.root.name + '-overlay.log')
        self.addCleanup(lambda: self.overlay_log.unlink(missing_ok=True))
        self.overlay_log.write_text('')
        overlay.install(self.root / 'bin', self.overlay_log,
                        {str(self.root / rel): (state, self.LOWER_INODES[rel]) for rel, state in states.items() if state != 'absent'},
                        self.root, mounts)
        # The shim is first in the scripts' PATH and reports the modeled identity.
        for rel, state in states.items():
            if state in ('lower', 'origin'):
                reported = subprocess.run(['stat', '-c', '%d:%i', str(self.root / rel)], env=self.env,
                                          capture_output=True, text=True, check=True).stdout.strip()
                self.assertEqual(reported, f'{overlay.OVERLAY_DEV}:{self.LOWER_INODES[rel]}')
        self.overlay_log.write_text('')

    def copy_ups(self):
        return [line for line in self.overlay_log.read_text().splitlines() if line.startswith('copy-up ')]

    def layouts(self):
        yield 'live', self.LIVE_LAYOUT
        for state in overlay.STATES:
            yield state, {rel: state for rel in EXISTING_ORIGINALS}

    def test_every_overlay_state_installs_and_restores_exactly(self):
        for name, states in self.layouts():
            with self.subTest(layout=name):
                self.tearDown()
                self.setUp()
                self.model(states)
                originals = {rel: exact_signature(self.root / rel) for rel in states}
                before = self.snapshot()
                result = self.install('--activate')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.root / 'etc/couvrefeu/backup/complete').exists())
                backup = self.root / 'etc/couvrefeu/backup'
                for rel, exact in originals.items():
                    original = backup / (rel.replace('/', '_') + '.original')
                    self.assertEqual(exact_signature(original), exact)
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual({rel: exact_signature(self.root / rel) for rel in states}, originals)
                self.assertFalse((self.root / '.couvrefeu-recovery').exists())
                # A lower-only original is copied up once, by the kernel, when
                # the install rename moves it into the journal; nothing earlier
                # writes it and nothing queries overlay-unstable file identity.
                self.assertEqual(self.copy_ups(), self.rename_copy_ups(states))
                self.assertNotIn('stat ', self.overlay_log.read_text())
                # Renames were preceded by directory filesystem proofs.
                self.assertIn('mount ', self.overlay_log.read_text())
                self.assert_no_touch()

    def rename_copy_ups(self, states):
        return [f'copy-up {self.root / rel} mv' for rel in EXISTING_ORIGINALS if states.get(rel) == 'lower']

    def test_copied_up_or_lower_original_matches_live_refusal_on_7676637(self):
        # Proof harness for the old hard-link design: run this class against a
        # 7676637 tree with CF_TEST_EXPECT_HARDLINK_REFUSAL=1 to reproduce the
        # live failure; against this tree the same layouts install and restore.
        old = os.environ.get('CF_TEST_EXPECT_HARDLINK_REFUSAL') == '1'
        for state in ('origin', 'lower'):
            with self.subTest(sysupgrade=state):
                self.tearDown()
                self.setUp()
                release = self.enable_release()
                self.model(dict(self.LIVE_LAYOUT, **{'etc/sysupgrade.conf': state}))
                before = full_snapshot(self.root)
                if old:
                    self.assert_refused_identically(
                        before, release, 'original hard link identity mismatch: etc/sysupgrade.conf; no installation made')
                    self.assertIn('stat ' + str(self.root / 'etc/sysupgrade.conf') + f' {overlay.OVERLAY_DEV}:1072',
                                  self.overlay_log.read_text())
                    # A lower-only original was even copied up (written) by ln.
                    self.assertEqual(self.copy_ups(), [f'copy-up {self.root}/etc/sysupgrade.conf ln'] if state == 'lower' else [])
                else:
                    result = self.install('--activate')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = self.run_script('uninstall.sh')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    after = full_snapshot(self.root)
                    # Exact bytes, mode, owner and ns mtime; a fresh inode by design.
                    strip = lambda snap: {k: v[:3] if v[0] == 'file' else v for k, v in snap.items()}  # noqa: E731
                    self.assertEqual(strip(after), strip(before))
                    self.assertEqual(self.copy_ups(), [f'copy-up {self.root}/etc/sysupgrade.conf mv'] if state == 'lower' else [])

    def test_cross_filesystem_journal_refuses_before_first_write(self):
        # BusyBox mv falls back to copy+unlink on EXDEV, which would lose the
        # exact original. Any split between an original's directory, the
        # journal and the recovery journal refuses before the first write.
        lower = {rel: 'lower' for rel in EXISTING_ORIGINALS}
        splits = {'journal': ('etc/couvrefeu', 'etc/config/firewall'),
                  'original': ('etc/crontabs', 'etc/crontabs/root'),
                  'recovery': ('etc', 'etc/config/firewall')}
        for name, (subtree, first) in splits.items():
            with self.subTest(split=name):
                self.tearDown()
                self.setUp()
                release = self.enable_release()
                (self.root / 'etc/couvrefeu').mkdir(mode=0o750)
                (self.root / 'etc/couvrefeu').chmod(0o750)
                self.model(lower, {str(self.root / subtree): (20, '/' + name)})
                before = full_snapshot(self.root)
                self.assert_refused_identically(
                    before, release, f'original, journal and recovery journal are not on one filesystem: /{first}; no installation made')
                self.assertEqual(self.copy_ups(), [])
                self.assert_no_touch()

    def test_same_device_bind_mount_refuses_before_first_write(self):
        # A bind mount shares %d and may share %m, but rename(2) across it is
        # EXDEV and BusyBox mv would copy; mountinfo mount IDs tell them apart.
        release = self.enable_release()
        (self.root / 'etc/couvrefeu').mkdir(mode=0o750)
        (self.root / 'etc/couvrefeu').chmod(0o750)
        self.model({rel: 'lower' for rel in EXISTING_ORIGINALS})
        mountinfo = self.root / 'bin/mountinfo'
        lines = {'single': ['1 0 0:2 / / rw - rootfs rootfs rw', f'30 1 0:19 / {self.root} rw - overlay overlay rw'],
                 'bind': ['1 0 0:2 / / rw - rootfs rootfs rw', f'30 1 0:19 / {self.root} rw - overlay overlay rw',
                          f'31 30 0:19 /etc/crontabs {self.root}/etc/crontabs rw - overlay overlay rw'],
                 'malformed': ['garbage line']}
        self.env['CF_TEST_MOUNTINFO'] = str(mountinfo)
        for name, rows in lines.items():
            with self.subTest(mountinfo=name):
                mountinfo.write_text('\n'.join(rows) + '\n')
                if name == 'single':
                    continue
                before = full_snapshot(self.root)
                message = ('original, journal and recovery journal are not on one filesystem: /'
                           + ('etc/crontabs/root' if name == 'bind' else 'etc/config/firewall') + '; no installation made')
                self.assert_refused_identically(before, release, message)
                self.assertEqual(self.copy_ups(), [])
        # The modeled single mount installs and restores exactly.
        mountinfo.write_text('\n'.join(lines['single']) + '\n')
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cross_filesystem_restore_refuses_before_any_write(self):
        originals = {rel: 'origin' for rel in EXISTING_ORIGINALS}
        self.model(originals)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.root / 'bin/overlay.mounts').open('a') as table:
            table.write(f'{self.root / "etc/config"} 20 /split\n')
        before = full_snapshot(self.root)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('journal original and /etc/config/firewall are not on one filesystem; no changes made', result.stderr)
        self.assertEqual(full_snapshot(self.root), before)
    assert_no_touch = InstallerTests.assert_no_touch


class CrondPickupTests(unittest.TestCase):
    """crond sees every installer/uninstaller crontab change without its mtime rescan."""
    setUp = InstallerTests.setUp
    tearDown = InstallerTests.tearDown
    run_script = InstallerTests.run_script
    snapshot = InstallerTests.snapshot
    install = InstallerTests.install
    write_originals = InstallerTests.write_originals
    kill_lock = InstallerTests.kill_lock
    production_tools = InterruptedRecoveryTests.production_tools
    LOGS = ('tool-log', 'cron-log', 'crond-table')
    EXPIRE = '* * * * * /usr/sbin/cfctl expire'

    def restorable(self):
        return {k: v for k, v in self.snapshot().items() if k not in self.LOGS}

    def cron_log(self):
        log = self.root / 'cron-log'
        return log.read_text().splitlines() if log.exists() else []

    def crond_table(self):
        table = self.root / 'crond-table'
        return table.read_text() if table.exists() else None

    def test_fresh_install_starts_crond_with_expiry_and_uninstall_stops_it(self):
        self.production_tools()
        before = self.restorable()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cron_log(), ['enabled', 'reload', 'started', 'ubus'])
        self.assertIn(self.EXPIRE, self.crond_table())
        self.assertEqual((self.root / 'etc/crontabs/root').read_text(), self.crond_table())
        self.assertEqual((self.root / 'tool-log').read_text().splitlines(), ['apply-fw'])
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cron_log(), ['enabled', 'reload', 'started', 'ubus', 'reload', 'stopped'])
        self.assertIsNone(self.crond_table())
        self.assertFalse((self.root / 'etc').exists())
        self.assertEqual(self.restorable(), before)

    def test_vendor_crontab_reloaded_on_install_and_restored_in_crond(self):
        self.production_tools()
        self.write_originals()
        vendor = EXISTING_ORIGINALS['etc/crontabs/root'].decode()
        (self.root / 'crond-table').write_text(vendor)
        before = self.restorable()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.crond_table().startswith(vendor))
        self.assertIn(self.EXPIRE, self.crond_table())
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cron_log(), ['enabled', 'reload', 'started', 'ubus', 'reload', 'started'])
        self.assertEqual(self.crond_table(), vendor)
        self.assertEqual(self.restorable(), before)

    def test_resumed_install_signals_crond_after_rename(self):
        self.production_tools()
        before = self.restorable()
        self.env['CF_TEST_INSTALL_FAIL_AFTER'] = '5'
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cron_log(), ['enabled'])
        self.env.pop('CF_TEST_INSTALL_FAIL_AFTER')
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cron_log(), ['enabled', 'enabled', 'reload', 'started', 'ubus'])
        self.assertIn(self.EXPIRE, self.crond_table())
        # A recorded reinstall renames again and re-signals; unchanged tables do not restart crond.
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cron_log(), ['enabled', 'enabled', 'reload', 'started', 'ubus', 'enabled', 'reload', 'ubus'])
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(self.crond_table())
        self.assertEqual(self.restorable(), before)

    def test_install_signalling_failure_refuses_success_and_uninstall_restores(self):
        for failing in ('reload', 'ubus-stopped', 'ubus-fail'):
            with self.subTest(failing=failing):
                self.production_tools()
                before = self.restorable()
                self.env['CF_TEST_CRON_FAIL'] = failing
                result = self.install('--activate')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('cron reload failed; expiry cron may be unseen', result.stderr)
                self.assertNotIn('Installation recorded', result.stdout)
                backup = self.root / 'etc/couvrefeu/backup'
                self.assertTrue((backup / 'activated').is_file())
                self.assertFalse((backup / 'complete').exists())
                self.assertFalse((self.root / 'tool-log').exists())
                self.env.pop('CF_TEST_CRON_FAIL')
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNone(self.crond_table())
                self.assertFalse((self.root / 'etc').exists())
                self.assertEqual(self.restorable(), before)
                for name in self.LOGS:
                    (self.root / name).unlink(missing_ok=True)

    def test_uninstall_signalling_failure_warns_and_completes_exact_restoration(self):
        self.production_tools()
        self.write_originals()
        before = self.restorable()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env['CF_TEST_CRON_FAIL'] = 'reload'
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('warning: cron reload failed', result.stderr)
        self.assertIn('/etc/init.d/cron restart', result.stderr)
        self.assertIn('Original files restored', result.stdout)
        self.assertEqual(self.cron_log(), ['enabled', 'reload', 'started', 'ubus', 'reload'])
        self.assertFalse((self.root / '.couvrefeu-recovery').exists())
        self.assertFalse((self.root / '.couvrefeu-recovery.done').exists())
        self.assertEqual(self.restorable(), before)

    def test_uninstall_retry_after_crash_signals_crond(self):
        self.production_tools()
        self.write_originals()
        vendor = EXISTING_ORIGINALS['etc/crontabs/root'].decode()
        before = self.restorable()
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env['CF_TEST_UNINSTALL_CRASH_AT'] = 'restored'
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.env.pop('CF_TEST_UNINSTALL_CRASH_AT')
        self.kill_lock()
        self.assertEqual(self.cron_log(), ['enabled', 'reload', 'started', 'ubus'])
        self.assertIn(self.EXPIRE, self.crond_table())
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cron_log(), ['enabled', 'reload', 'started', 'ubus', 'reload', 'started'])
        self.assertEqual(self.crond_table(), vendor)
        self.assertEqual(self.restorable(), before)


if __name__ == '__main__':
    unittest.main()
