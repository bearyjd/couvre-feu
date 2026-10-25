#!/usr/bin/env python3
"""Crash/retry retirement fixtures. No network, router or packet claims."""
import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('retirement_support', REPO / 'tests/test-install.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


class RetirementRecoveryTests(unittest.TestCase):
    tearDown = support.InstallerTests.tearDown
    install = support.InstallerTests.install
    write_originals = support.InstallerTests.write_originals
    originals_state = support.InstallerTests.originals_state

    def setUp(self):
        self.frozen = support.emitted_router()
        support.InstallerTests.setUp(self)
        for name in ('install-common.sh', 'platform-bootstrap.sh', 'vendor-platform.sh'):
            shutil.copy2(self.frozen / 'lib' / name, self.source / 'lib' / name)
        self.env['CF_TEST_RELEASE_DIR'] = '1'
        self.originals = self.write_originals()
        installed = self.install('--activate')
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.release = next((self.root / 'etc').glob('.couvrefeu-release-*'))
        self.prepared = self.root / '.couvrefeu-prepared'
        self.receipt = self.root / '.couvrefeu-retirement'

    def run_script(self, name, *args):
        return subprocess.run([*shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')),
                               str(self.frozen / name), *args], env=self.env,
                              capture_output=True, text=True, timeout=45, start_new_session=True)

    def arm_delete_crash(self, target, tool='rm'):
        """Kill the actual uninstaller immediately after one exact rm operand is deleted."""
        real_rm = shutil.which(tool)
        wrapper = self.root / 'bin' / tool
        wrapper.write_text('#!/bin/sh\nset -eu\n'
                           + shlex.quote(real_rm) + ' "$@"\n'
                           + 'for operand do\n'
                           + ' if [ "$operand" = ' + shlex.quote(str(target)) + ' ] && [ ! -e '
                           + shlex.quote(str(self.root / '.crashed')) + ' ]; then\n'
                           + ': > ' + shlex.quote(str(self.root / '.crashed')) + '\n'
                           + 'kill -KILL "$PPID"; exit 137\n fi\ndone\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(wrapper.parent) + ':' + os.environ['PATH']

    def recover_and_finish(self):
        result = self.run_script('cfctl', 'recover-install-lock')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.originals_state(), self.originals)
        for name in ('.couvrefeu-prepared', '.couvrefeu-retirement', '.couvrefeu-transaction',
                     '.couvrefeu-recovery-required', '.couvrefeu-recovery.done'):
            self.assertFalse((self.root / name).exists(), name)
        self.assertFalse(self.release.exists())

    def test_partial_prepared_deletion_recovers_from_receipt(self):
        self.arm_delete_crash(self.prepared / 'inventory')
        killed = self.run_script('uninstall.sh')
        self.assertEqual(killed.returncode, -9, killed.stderr)
        self.assertFalse((self.prepared / 'inventory').exists())
        self.recover_and_finish()

    def test_partial_release_deletion_recovers_from_external_source(self):
        self.arm_delete_crash(self.release / 'install.sh')
        killed = self.run_script('uninstall.sh')
        self.assertEqual(killed.returncode, -9, killed.stderr)
        self.assertFalse((self.release / 'install.sh').exists())
        self.recover_and_finish()

    def test_removed_release_recovers_from_external_source(self):
        self.arm_delete_crash(self.release, tool='rmdir')
        killed = self.run_script('uninstall.sh')
        self.assertEqual(killed.returncode, -9, killed.stderr)
        self.assertFalse(self.release.exists())
        self.assertTrue(self.receipt.is_file())
        self.recover_and_finish()

    def test_owner_removal_before_final_receipt_unlink_is_recoverable(self):
        self.arm_delete_crash(self.root / '.couvrefeu-transaction')
        killed = self.run_script('uninstall.sh')
        self.assertEqual(killed.returncode, -9, killed.stderr)
        self.assertTrue(self.receipt.is_file())
        blocked = self.install('--activate')
        self.assertNotEqual(blocked.returncode, 0)
        self.assertEqual(self.originals_state(), self.originals)
        self.recover_and_finish()

    def test_done_removal_before_final_receipt_unlink_is_recoverable(self):
        self.arm_delete_crash(self.root / '.couvrefeu-recovery.done')
        killed = self.run_script('uninstall.sh')
        self.assertEqual(killed.returncode, -9, killed.stderr)
        self.assertTrue(self.receipt.is_file())
        self.recover_and_finish()

    def test_foreign_prepared_entry_survives_retirement_retry(self):
        self.arm_delete_crash(self.prepared / 'inventory')
        self.assertEqual(self.run_script('uninstall.sh').returncode, -9)
        foreign = self.prepared / 'foreign'
        foreign.write_bytes(b'private foreign evidence\n')
        foreign.chmod(0o600)
        before = {p.name: p.read_bytes() for p in self.prepared.iterdir()}
        result = self.run_script('cfctl', 'recover-install-lock')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual({p.name: p.read_bytes() for p in self.prepared.iterdir()}, before)
        self.assertEqual(self.originals_state(), self.originals)

    def test_foreign_release_entry_survives_retirement_retry(self):
        self.arm_delete_crash(self.release / 'install.sh')
        self.assertEqual(self.run_script('uninstall.sh').returncode, -9)
        foreign = self.release / 'lib/foreign'
        foreign.write_bytes(b'private foreign release evidence\n')
        foreign.chmod(0o644)
        before = {str(p.relative_to(self.release)): p.read_bytes() for p in self.release.rglob('*') if p.is_file()}
        recovered = self.run_script('cfctl', 'recover-install-lock')
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        result = self.run_script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual({str(p.relative_to(self.release)): p.read_bytes() for p in self.release.rglob('*') if p.is_file()}, before)
        self.assertEqual(self.originals_state(), self.originals)

    def test_changed_original_metadata_preserves_receipt_and_prepared(self):
        self.arm_delete_crash(self.prepared / 'inventory')
        self.assertEqual(self.run_script('uninstall.sh').returncode, -9)
        original = self.root / 'etc/config/firewall'
        original.chmod(0o600)
        before = {p.name: p.read_bytes() for p in self.prepared.iterdir()}
        receipt = self.receipt.read_bytes()
        result = self.run_script('cfctl', 'recover-install-lock')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.receipt.read_bytes(), receipt)
        self.assertEqual({p.name: p.read_bytes() for p in self.prepared.iterdir()}, before)
        self.assertEqual(original.stat().st_mode & 0o777, 0o600)

    def test_changed_receipt_binding_preserves_remaining_baseline(self):
        self.arm_delete_crash(self.prepared / 'inventory')
        self.assertEqual(self.run_script('uninstall.sh').returncode, -9)
        lines = self.receipt.read_bytes().splitlines(keepends=True)
        lines[4] = b'0' * 64 + b'\n'
        self.receipt.write_bytes(b''.join(lines))
        before = {p.name: p.read_bytes() for p in self.prepared.iterdir()}
        receipt = self.receipt.read_bytes()
        result = self.run_script('cfctl', 'recover-install-lock')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.receipt.read_bytes(), receipt)
        self.assertEqual({p.name: p.read_bytes() for p in self.prepared.iterdir()}, before)
        self.assertEqual(self.originals_state(), self.originals)

    def test_hardlinked_receipt_preserves_remaining_baseline(self):
        self.arm_delete_crash(self.prepared / 'inventory')
        self.assertEqual(self.run_script('uninstall.sh').returncode, -9)
        foreign = self.root / 'foreign-retirement-link'
        os.link(self.receipt, foreign)
        before = {p.name: p.read_bytes() for p in self.prepared.iterdir()}
        result = self.run_script('cfctl', 'recover-install-lock')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(foreign.read_bytes(), self.receipt.read_bytes())
        self.assertEqual(foreign.stat().st_nlink, 2)
        self.assertEqual({p.name: p.read_bytes() for p in self.prepared.iterdir()}, before)
        self.assertEqual(self.originals_state(), self.originals)

    def test_source_identity_substitution_preserves_remaining_baseline(self):
        self.arm_delete_crash(self.prepared / 'inventory')
        self.assertEqual(self.run_script('uninstall.sh').returncode, -9)
        lines = self.receipt.read_bytes().splitlines(keepends=True)
        self.assertEqual(lines[0], b'CFRETIREMENT 2\n')
        lines[10] = b'f' * 64 + b'\n'
        self.receipt.write_bytes(b''.join(lines))
        before = {p.name: p.read_bytes() for p in self.prepared.iterdir()}
        receipt = self.receipt.read_bytes()
        result = self.run_script('cfctl', 'recover-install-lock')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.receipt.read_bytes(), receipt)
        self.assertEqual({p.name: p.read_bytes() for p in self.prepared.iterdir()}, before)
        self.assertEqual(self.originals_state(), self.originals)


if __name__ == '__main__':
    unittest.main()
