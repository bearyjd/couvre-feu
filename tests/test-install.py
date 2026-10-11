#!/usr/bin/env python3
"""Filesystem recovery fixtures; never invokes router/system backends."""
import hashlib
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
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

    def make_journal(self, absent=False, partial=False):
        originals = {}
        if not absent:
            for i, rel in enumerate(FILES):
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
        for i, rel in enumerate(FILES):
            p = self.root / rel
            k = rel.replace('/', '_')
            before = signature(p)
            (backup / (k + '.before')).write_text(before + '\n')
            (backup / (k + '.mtime')).write_text(mtime(p) + '\n')
            if before != 'absent':
                shutil.copy2(p, backup / (k + '.original'))
            staged = backup / (k + '.staged')
            staged.write_text('02:00:00:00:00:01\n' if rel.endswith('/protected') else f'installed-{i}\n')
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


class InstallerTests(unittest.TestCase):
    """Complete staged/install/resume/uninstall transactions with fake sources."""
    run_script = RecoveryTests.run_script
    snapshot = RecoveryTests.snapshot
    tearDown = RecoveryTests.tearDown

    def setUp(self):
        RecoveryTests.setUp(self)
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
        for lib in ('core.sh', 'rpc.sh', 'firewall.sh'):
            (self.source / 'lib' / lib).write_text(':\n')
        for lib in ('json.awk', 'state.awk', 'rules.awk'):
            (self.source / 'lib' / lib).write_text('BEGIN {exit 0}\n')
        shutil.copy2(REPO / 'router/lib/install-common.sh', self.source / 'lib/install-common.sh')
        backend = self.root / 'bin'
        backend.mkdir()
        (backend / '.couvrefeu-test-backend').touch()
        (backend / 'uci').write_text('''#!/bin/sh
[ "$1" = -c ] && [ "$3" = -t ] && [ "$5" = show ] && [ "$6" = firewall ]
''')
        (backend / 'uci').chmod(0o700)
        self.env['CF_BACKEND_DIR'] = str(backend)

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

    def install_copy_tool(self, truncate=False):
        wrapper = self.root / 'bin/cp'
        real_copy = shutil.which('cp')
        wrapper.write_text('#!/usr/bin/env python3\n'
                           'import os, subprocess, sys\n'
                           'from pathlib import Path\n'
                           f'result = subprocess.run([{real_copy!r}, *sys.argv[1:]])\n'
                           'if result.returncode: sys.exit(result.returncode)\n'
                           'destination = Path(sys.argv[-1])\n'
                           'if destination.is_file() and (destination.name == "restore-probe" or destination.name.endswith(".couvrefeu-tmp")):\n'
                           + ('    st = destination.stat()\n    seconds = st.st_mtime_ns // 1_000_000_000\n    os.utime(destination, ns=(seconds * 1_000_000_000, seconds * 1_000_000_000))\n' if truncate else '    pass\n'))
        wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']

    def test_fractional_original_copy_refuses_before_activation(self):
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        stamp = 1_234_567_890_123_456_789
        os.utime(target, ns=(stamp, stamp))
        self.install_copy_tool(truncate=True)
        before = self.snapshot()
        result = self.install('--activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot preserve exact original', result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / 'etc/couvrefeu/backup').exists())

    def test_restore_truncation_retains_journal_and_retries(self):
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        target.chmod(0o640)
        stamp = 1_234_567_890_123_456_789
        os.utime(target, ns=(stamp, stamp))
        original = exact_signature(target)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = exact_signature(target)
        self.install_copy_tool(truncate=True)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exact original copy failed', result.stderr)
        self.assertEqual(exact_signature(target), installed)
        backup = self.root / '.couvrefeu-recovery'
        self.assertTrue((backup / 'etc_config_firewall.original').exists())
        self.assertEqual(exact_signature(backup / 'etc_config_firewall.original'), original)
        self.assertFalse((backup / 'restored').exists())
        self.install_copy_tool()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(exact_signature(target), original)
        self.assertFalse(backup.exists())

    def test_native_busybox_cp_actual_timestamp_capability(self):
        shell = shlex.split(os.environ.get('CF_TEST_SHELL', 'sh'))
        busybox = os.environ.get('CF_TEST_BUSYBOX_CP') or (shell[0] if len(shell) == 2 and shell[1] == 'ash' else shutil.which('busybox'))
        if not busybox or subprocess.run([busybox, 'cp', '--help'], capture_output=True).returncode == 127:
            self.skipTest('native BusyBox cp unavailable; capability remains unproved')
        wrapper = self.root / 'bin/cp'
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(busybox) + ' cp "$@"\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(self.root / 'bin') + ':' + os.environ['PATH']
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        target.chmod(0o640)
        for stamp, supported in ((1_234_567_890_123_456_789, False), (1_234_567_890_000_000_000, True)):
            with self.subTest(nanoseconds=stamp):
                os.utime(target, ns=(stamp, stamp))
                before = self.snapshot()
                result = self.install('--activate')
                if not supported:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('cannot preserve exact original', result.stderr)
                    self.assertEqual(self.snapshot(), before)
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(target.stat().st_mtime_ns, stamp)

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
        tool = self.root / 'bin/firewall'
        tool.write_text('''#!/bin/sh
set -eu
[ "$1" = reload ] && [ -f "$CF_BACKEND_DIR/.couvrefeu-test-backend" ] || exit 96
printf '%s\n' reload >> "$CF_ROOT/tool-log"
[ "${CF_TEST_RELOAD_FAIL:-0}" != 1 ]
''')
        tool.chmod(0o700)

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
        for rel in FILES:
            key = rel.replace('/', '_')
            original = backup / (key + '.original')
            destination = self.root / rel
            if original.exists():
                copy = subprocess.run([busybox, 'cp', '-p', str(original), str(destination)], capture_output=True)
                self.assertEqual(copy.returncode, 0, copy.stderr)
            else:
                destination.unlink()
            (backup / (key + '.mtime')).unlink()
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
        self.assertIn('legacy recovery completion record', result.stderr)
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
        self.assertEqual(done.read_text(), '2\n')
        self.assertFalse((recovery / 'etc_config_firewall.before').exists())
        self.assertEqual(exact_signature(target), original)
        (self.root / 'fail-tool').unlink()
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(exact_signature(target), original)
        self.assertFalse(recovery.exists())
        self.assertFalse(done.exists())

    def test_every_file_interruption_retries_after_removed_helpers(self):
        for count in range(1, len(FILES) + 1):
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

    def test_restore_rename_failure_resumes_owned_original(self):
        target = self.root / 'etc/config/firewall'
        target.parent.mkdir(parents=True)
        target.write_text("config zone 'wan'\n")
        target.chmod(0o640)
        original = signature(target)
        result = self.install('--activate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.tool_failure('mv', target)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(signature(Path(str(target) + '.couvrefeu-tmp')), original)
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


if __name__ == '__main__':
    unittest.main()
