#!/usr/bin/env python3
"""Captured main4ff installer compatibility; offline private roots only.

The historical installer creates its actual old-format journal. Restoration
and release retirement always execute the complete current external release.
"""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('legacy_install_support', REPO / 'tests/test-install.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
LEGACY_ID = '28b3278555e61239471497b7e806b05c8f5eed82b7cabca7ad8264d22cf6e539'
ARCHIVE_SHA = 'd355296fbd2d020a30ea3a52d8b1496c0fac965f92de6c0feeabe518d9ee20da'
BOOTSTRAP_SHA = 'c254b9b4364d5f6e252126f4e37d05312cf7cec18b81515a3004b37009ce5820'


class LegacyCompleteRecoveryTests(unittest.TestCase):
    tearDown = support.InstallerTests.tearDown
    write_originals = support.InstallerTests.write_originals
    originals_state = support.InstallerTests.originals_state

    def setUp(self):
        self.current = support.emitted_router()
        support.InstallerTests.setUp(self)
        data = (REPO / 'tests/fixtures/m4b-legacy-main4ff.tar.gz').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), ARCHIVE_SHA)
        self.legacy = self.root / 'captured-main4ff'
        self.legacy.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            archive.extractall(self.legacy, filter='data')
        for name in ('install-common.sh', 'platform-bootstrap.sh', 'vendor-platform.sh'):
            shutil.copy2(self.legacy / 'lib' / name, self.source / 'lib' / name)
        self.env['CF_TEST_RELEASE_DIR'] = '1'
        self.originals = self.write_originals()
        self.directories = {rel: ((self.root / rel).stat().st_mode & 0o7777
                                  if (self.root / rel).exists() else None)
                            for rel in support.DIRS}
        installed = subprocess.run(
            [*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')), str(self.legacy / 'install.sh'),
             '--source-dir', str(self.source), '--protect', '02:00:00:00:00:01', '--activate'],
            env=self.env, capture_output=True, text=True, timeout=45, start_new_session=True)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        self.release = self.root / 'etc' / ('.couvrefeu-release-' + LEGACY_ID)
        self.assertTrue(self.release.is_dir())
        self.assertFalse((self.root / '.couvrefeu-transaction').exists())
        self.assertFalse((self.root / '.couvrefeu-prepared').exists())
        self.backup = self.root / 'etc/couvrefeu/backup'
        recorded = (self.backup / 'usr_lib_couvrefeu_platform-bootstrap.sh.after').read_text().split(':')[0]
        self.assertEqual(recorded, BOOTSTRAP_SHA)

    def run_current(self, name, *args):
        return subprocess.run([*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')),
                               str(self.current / name), *args], env=self.env,
                              capture_output=True, text=True, timeout=45, start_new_session=True)

    def assert_restored(self):
        self.assertEqual(self.originals_state(), self.originals)
        for rel, mode in self.directories.items():
            if mode is None:
                self.assertFalse((self.root / rel).exists(), rel)
            else:
                self.assertEqual((self.root / rel).stat().st_mode & 0o7777, mode, rel)
        self.assertFalse(self.release.exists())
        for rel in ('.couvrefeu-transaction', '.couvrefeu-retirement', '.couvrefeu-recovery',
                    '.couvrefeu-recovery.done', 'etc/couvrefeu/backup'):
            self.assertFalse((self.root / rel).exists(), rel)

    def test_captured_main_complete_journal_restores_using_current_external_release(self):
        removed = self.run_current('uninstall.sh')
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assert_restored()

    def test_current_installer_cannot_resume_captured_legacy_staged_helpers(self):
        before = support.full_snapshot(self.root)
        attempted = self.run_current('install.sh', '--activate', '--source-dir', str(self.source),
                                     '--protect', '02:00:00:00:00:01')
        self.assertNotEqual(attempted.returncode, 0, attempted.stdout + attempted.stderr)
        self.assertIn('legacy_installation_resume_refused', attempted.stderr)
        self.assertFalse((self.root / '.couvrefeu-prepared').exists())
        self.assertFalse((self.root / '.couvrefeu-transaction').exists())
        self.assertEqual(support.full_snapshot(self.root), before)

    def test_killed_historical_release_retirement_resumes_through_current_recovery(self):
        real_rm = shutil.which('rm')
        wrapper = self.root / 'bin/rm'
        target = str(self.release / 'cfctl')
        wrapper.write_text('#!/bin/sh\nset -eu\n' + shlex.quote(real_rm) + ' "$@"\n'
                           + 'for operand do\nif [ "$operand" = ' + shlex.quote(target)
                           + ' ] && [ -f "$CF_ROOT/kill-legacy-retire" ]; then\n'
                           + shlex.quote(real_rm) + ' -f "$CF_ROOT/kill-legacy-retire"\n'
                           + 'kill -KILL "$PPID"; exit 0\nfi\ndone\n')
        wrapper.chmod(0o700)
        (self.root / 'kill-legacy-retire').touch()
        killed = self.run_current('uninstall.sh')
        self.assertEqual(killed.returncode, -9, killed.stdout + killed.stderr)
        self.assertTrue((self.root / '.couvrefeu-retirement').is_file())
        recovered = self.run_current('cfctl', 'recover-install-lock')
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        removed = self.run_current('uninstall.sh')
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assert_restored()

    def test_historical_manifest_tampering_refuses_before_restoration(self):
        with (self.release / 'release.sha256').open('ab') as stream:
            stream.write(b'foreign\n')
        before = support.full_snapshot(self.root)
        result = self.run_current('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(support.full_snapshot(self.root), before)

    def test_historical_bootstrap_journal_substitution_refuses_before_restoration(self):
        after = self.backup / 'usr_lib_couvrefeu_platform-bootstrap.sh.after'
        after.write_text('0' * 64 + ':' + after.read_text().split(':', 1)[1])
        before = support.full_snapshot(self.root)
        result = self.run_current('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(support.full_snapshot(self.root), before)

    def test_historical_target_substitution_refuses_before_restoration(self):
        displaced = self.release.with_name('.couvrefeu-release-' + '0' * 64)
        self.release.rename(displaced)
        self.release.symlink_to(displaced, target_is_directory=True)
        before = support.full_snapshot(self.root)
        result = self.run_current('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(support.full_snapshot(self.root), before)


if __name__ == '__main__':
    unittest.main()
