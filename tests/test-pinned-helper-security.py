#!/usr/bin/env python3
"""Offline helper admission and ownership regressions; no router backend runs."""
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
HELPER = 'usr/lib/couvrefeu/busybox-static'
RETIREMENT_INVENTORY = (
    'usr/lib/couvrefeu/core.sh usr/lib/couvrefeu/rpc.sh usr/lib/couvrefeu/state.awk '
    'usr/lib/couvrefeu/firewall.sh usr/lib/couvrefeu/json.awk usr/lib/couvrefeu/rules.awk '
    'usr/lib/couvrefeu/install-common.sh usr/sbin/cfctl usr/sbin/cfctl-ssh '
    'etc/firewall.couvrefeu etc/config/firewall etc/sysupgrade.conf etc/crontabs/root '
    'etc/couvrefeu/protected etc/couvrefeu/state')


class HelperSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='couvre-feu-helper-security-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'etc').mkdir()
        self.release = self.root / 'release'
        (self.release / 'lib').mkdir(parents=True)
        self.bootstrap = self.release / 'lib/platform-bootstrap.sh'
        self.helper = self.release / 'lib/busybox-static'
        busybox = Path(os.environ.get('CF_TEST_BUSYBOX') or shutil.which('busybox') or '')
        self.assertTrue(busybox.is_file(), 'pinned host BusyBox required')
        digest = hashlib.sha256(busybox.read_bytes()).hexdigest()
        self.assertIn(digest, (
            'b9e75f97de336e3d04b7f07c2d213da779c6b2cf702ebf1935b4cd09c0b97ddb',
            'afa625460bd5f4d1db52787dfd84e6c5b8126d7ab841b65cf61e410554edb60a'))
        shutil.copyfile(busybox, self.helper)
        self.helper.chmod(0o755)
        self.bootstrap.write_text((REPO / 'router/lib/platform-bootstrap.sh').read_text().replace(
            'c25f66e5ac29ea3e373b8fb2d3549a59d058fbef9ed11b67fdaba1dc37bf75f5', digest))
        self.env = {**os.environ, 'CF_TEST_MODE': '1', 'CF_ROOT': str(self.root)}
        self.shell = shlex.split(os.environ.get('CF_TEST_SHELL', 'sh'))

    def run_sh(self, body, *, entry='fixture', env=None):
        setup = ('set -eu\nplatform_bootstrap_path=' + shlex.quote(str(self.bootstrap)) +
                 '\n. "$platform_bootstrap_path"\nplatform_entry_root_validate\n')
        return subprocess.run([*self.shell, '-c', setup + body, entry],
                              env=env or self.env, capture_output=True, text=True, timeout=12)

    def common(self, body='', **kwargs):
        return self.run_sh('CF_TRANSACTION_DEFINITIONS_ONLY=1\nplatform_transaction_paths\n. ' +
                           shlex.quote(str(REPO / 'router/lib/install-common.sh')) + '\n' + body,
                           **kwargs)

    def assert_refused(self, result, code):
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(code, result.stderr)

    def test_every_writable_ancestor_refuses_before_payload_runs(self):
        marker = self.root / 'payload-ran'
        self.helper.write_text('#!/bin/sh\ntouch ' + shlex.quote(str(marker)) + '\n')
        for parent in (self.release / 'lib', self.release, self.root):
            with self.subTest(parent=parent):
                parent.chmod(0o777)
                result = self.run_sh('platform_setsid_helper')
                parent.chmod(0o700)
                self.assert_refused(result, 'helper_missing')
                self.assertFalse(marker.exists())

    def test_symlink_ancestor_refuses_before_payload_runs(self):
        real = self.root / 'actual-lib'
        (self.release / 'lib').rename(real)
        (self.release / 'lib').symlink_to(real, target_is_directory=True)
        self.assert_refused(self.run_sh('platform_setsid_helper'), 'helper_missing')

    def test_wrong_mode_and_hardlink_refuse_before_hash(self):
        self.helper.chmod(0o777)
        self.assert_refused(self.run_sh('platform_setsid_helper'), 'helper_missing')
        self.helper.chmod(0o755)
        os.link(self.helper, self.root / 'alias')
        self.assert_refused(self.run_sh('platform_setsid_helper'), 'helper_missing')

    def test_missing_hash_and_exec_failures_have_fixed_codes(self):
        self.helper.unlink()
        self.assert_refused(self.run_sh('platform_setsid_helper'), 'helper_missing')
        self.helper.write_bytes(b'foreign')
        self.helper.chmod(0o755)
        self.assert_refused(self.run_sh('platform_setsid_helper'), 'helper_hash')
        digest = hashlib.sha256(self.helper.read_bytes()).hexdigest()
        self.assert_refused(self.run_sh('CF_SETSID_HELPER_SHA256=' + digest +
                                        '\nplatform_setsid_helper'), 'helper_exec')

    def test_private_copy_exec_survives_source_replacement_after_hash(self):
        tools = self.root / 'tools'
        tools.mkdir()
        marker = self.root / 'foreign-ran'
        sha = tools / 'sha256sum'
        sha.write_text('#!/bin/sh\n' + shlex.quote(shutil.which('sha256sum')) + ' "$@" || exit\n' +
                       'printf %s ' + shlex.quote('#!/bin/sh\ntouch ' + str(marker) + '\n') +
                       ' > ' + shlex.quote(str(self.helper)) + '\n')
        sha.chmod(0o755)
        env = {**self.env, 'PATH': str(tools) + os.pathsep + self.env['PATH']}
        result = self.run_sh('platform_setsid_helper\n'
                             '[ "$platform_helper" != "$platform_helper_source" ]\n'
                             '[ "$(stat -c %a "$platform_helper_directory")" = 700 ]\n'
                             '"$platform_helper" true\nplatform_helper_cleanup', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_session_reexec_keeps_pid_group_and_session_equal(self):
        entry = self.root / 'session.sh'
        entry.write_text('#!/bin/sh\nset -eu\n'
                         'CF_ENTRY_SESSION_PID=\n'
                         'if [ "${1:-}" = --cf-transaction-session ]; then CF_ENTRY_SESSION_PID=$2; shift 2; fi\n'
                         'platform_bootstrap_path=' + shlex.quote(str(self.bootstrap)) + '\n'
                         '. "$platform_bootstrap_path"\nplatform_entry_root_validate\n'
                         'platform_transaction_session "$@"\n'
                         'identity=$(platform_process_identity "$$")\n'
                         'case "$identity" in *:"$$":"$$") ;; *) exit 91;; esac\n'
                         'printf "%s\\n" "$$"\n')
        result = subprocess.run([*self.shell, str(entry)], env=self.env,
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip().isdigit())

    def helper_recording(self):
        record = self.root / 'private-directory'
        setup = ('mktemp() { candidate=$(command mktemp "$@") || return; '
                 'printf "%s\\n" "$candidate" > ' + shlex.quote(str(record)) +
                 '; printf "%s\\n" "$candidate"; }\n')
        return record, setup

    def assert_private_removed(self, record):
        self.assertTrue(record.exists(), 'helper private directory was allocated')
        self.assertFalse(Path(record.read_text().strip()).exists())

    def test_host_shell_substitutions_cannot_cleanup_parent_helper(self):
        record, setup = self.helper_recording()
        self.shell = ['sh']
        result = self.run_sh(setup + 'platform_setsid_helper\n'
                             'value=$(printf checked)\n[ "$value" = checked ]\n'
                             '[ -f "$platform_helper" ]\nplatform_helper_cleanup')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_private_removed(record)

    def test_noncanonical_parent_spellings_refuse(self):
        parent = str(self.release / 'lib')
        for spelling in (parent + '/', parent + '//', parent + '/.', parent + '/../lib',
                         parent.replace('/release/', '//release/')):
            with self.subTest(spelling=spelling):
                result = self.run_sh('platform_helper_parents ' + shlex.quote(spelling))
                self.assert_refused(result, 'helper_missing')

    def test_private_copy_shape_refuses_before_hash(self):
        record, setup = self.helper_recording()
        for replacement in ('ln -s "$1" "$2"', 'ln "$1" "$2"', 'mkfifo "$2"',
                            'command cp "$@"; command chmod 777 "$2"'):
            with self.subTest(replacement=replacement):
                body = setup + 'cp() { ' + replacement + '; }\n'
                if 'chmod 777' in replacement:
                    body += 'chmod() { [ "$1" = 755 ] || command chmod "$@"; }\n'
                result = self.run_sh(body + 'platform_setsid_helper')
                self.assert_refused(result, 'helper_missing')
                self.assert_private_removed(record)

    def test_private_copy_wrong_owner_or_group_refuses(self):
        record, setup = self.helper_recording()
        for metadata in ('999:0:755:1', '0:999:755:1'):
            with self.subTest(metadata=metadata):
                result = self.run_sh(setup +
                    'platform_helper_stat() { if [ "$3" = "${platform_helper:-}" ]; then '
                    'printf "%s\\n" ' + shlex.quote(metadata) +
                    '; else command stat "$@"; fi; }\nplatform_setsid_helper')
                self.assert_refused(result, 'helper_missing')
                self.assert_private_removed(record)

    def test_exit_signal_and_deadline_remove_private_directory(self):
        for body, code, refusal in (
                ('platform_setsid_helper\nexit 37', 37, None),
                ('cp() { kill -TERM "$$"; }\nplatform_setsid_helper', 143, None),
                ('CF_PLATFORM_PROFILE=$CF_OS_TRUST_PROFILE\nCF_PLATFORM_ENTRY_TICK=0\n'
                 'platform_setsid_helper', 2, 'admission_deadline')):
            with self.subTest(body=body):
                record, setup = self.helper_recording()
                result = self.run_sh(setup + body)
                self.assertEqual(result.returncode, code, result.stderr)
                if refusal:
                    self.assertIn(refusal, result.stderr)
                self.assert_private_removed(record)

    def test_failed_session_exec_cleans_and_has_fixed_code(self):
        record, setup = self.helper_recording()
        result = self.run_sh(setup +
            'platform_process_identity() { printf "1:2:3\\n"; }\n'
            'readlink() { rm -f "$platform_helper"; command readlink "$@"; }\n'
            'platform_transaction_session')
        self.assert_refused(result, 'helper_exec')
        self.assert_private_removed(record)

    def test_failed_reexec_cleans_and_has_fixed_code(self):
        record, setup = self.helper_recording()
        shell = self.root / 'one-shot-shell'
        shell.write_text('#!/bin/sh\nrm -f "$0"\nexec ' +
                         shlex.join(self.shell) + ' "$@"\n')
        shell.chmod(0o755)
        result = self.run_sh(setup +
            'platform_process_identity() { printf "1:2:3\\n"; }\n'
            'readlink() { printf "%s\\n" ' + shlex.quote(str(shell)) + '; }\n'
            'platform_transaction_session')
        self.assert_refused(result, 'helper_exec')
        self.assert_private_removed(record)

    def test_cleanup_failure_does_not_recurse_or_replace_original_refusal(self):
        for command in ('rm', 'rmdir'):
            with self.subTest(command=command):
                record, setup = self.helper_recording()
                calls = self.root / 'cleanup-calls'
                calls.write_text('')
                result = self.run_sh(setup + 'platform_setsid_helper\n' + command +
                    '() { printf "call\\n" >> ' + shlex.quote(str(calls)) +
                    '; return 1; }\nplatform_helper_fail original_refusal')
                self.assert_refused(result, 'original_refusal')
                self.assertEqual(calls.read_text().splitlines(), ['call'])
                directory = Path(record.read_text().strip())
                shutil.rmtree(directory)

    def test_sweep_removes_only_dead_owned_pid_directories(self):
        paths = []
        for pid in ('9999999999', str(os.getpid())):
            allocated = subprocess.run(['mktemp', '-d',
                '/tmp/.couvrefeu-helper.' + pid + '.XXXXXX'],
                capture_output=True, text=True, check=True)
            canonical = Path(allocated.stdout.strip())
            shutil.copyfile(self.helper, canonical / 'busybox-static')
            paths.append(canonical)
            self.addCleanup(lambda p=canonical: shutil.rmtree(p, ignore_errors=True))
        legacy = Path(tempfile.mkdtemp(prefix='.couvrefeu-helper.', dir='/tmp'))
        self.addCleanup(lambda: shutil.rmtree(legacy, ignore_errors=True))
        result = self.run_sh('set -f\nplatform_setsid_helper\nplatform_helper_cleanup\n'
                             'case $- in *f*) ;; *) exit 91;; esac')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(paths[0].exists())
        self.assertTrue(paths[1].exists())
        self.assertTrue(legacy.exists())

    def test_old_and_lookalike_inventories_refuse_before_mutex_creation(self):
        (self.root / 'etc/couvrefeu/backup').mkdir(parents=True)
        prepared = self.root / '.couvrefeu-prepared'
        prepared.mkdir()
        for fields in ('old inventory', HELPER + '.evil', 'usr/lib/couvrefeu/busybox-staticX'):
            with self.subTest(fields=fields):
                (prepared / 'inventory').write_text(fields + '\n')
                result = self.run_sh('platform_install_helper_inventory', entry='/fixture/install.sh')
                self.assert_refused(result, 'helper_inventory_upgrade_refused')
                self.assertFalse((self.root / '.couvrefeu-mutex').exists())
                self.assertFalse((self.root / '.couvrefeu-transaction').exists())

    def test_pending_recovery_or_done_refuses_before_mutex_creation(self):
        for name in ('.couvrefeu-recovery', '.couvrefeu-recovery.done'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text('legacy or modern pending recovery\n')
                result = self.run_sh('platform_install_helper_inventory', entry='/fixture/install.sh')
                self.assert_refused(result, 'helper_inventory_upgrade_refused')
                self.assertFalse((self.root / '.couvrefeu-mutex').exists())
                self.assertFalse((self.root / '.couvrefeu-transaction').exists())
                path.unlink()

    def test_done_without_helper_backup_ownership_refuses(self):
        done = self.root / '.couvrefeu-recovery.done'
        done.write_text('3\nstrict\n' + 'a' * 64 + '\n')
        result = self.common()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('helper_inventory_upgrade_refused', result.stderr)
        recovery = self.root / '.couvrefeu-recovery'
        recovery.mkdir()
        (recovery / 'usr_lib_couvrefeu_busybox-static.before').write_text('absent\n')
        result = self.common()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('helper_inventory_upgrade_refused', result.stderr)

    def test_current_receipt_rejects_15_targets_even_with_legacy_variable_set(self):
        receipt = self.root / '.couvrefeu-retirement'
        pin = 'a' * 64
        lines = ['CFRETIREMENT 2', pin, 'strict', pin, pin, '1:1', '1', '', '', pin, pin, pin,
                 ' '.join(f'item{i}:{pin}' for i in range(15))]
        lines += [f'item{i}\t{pin}\tvalue' for i in range(5)]
        receipt.write_text('\n'.join(lines) + '\n')
        receipt.chmod(0o600)
        result = self.common('platform_transaction_mutex_check() { :; }\nRETIRE_LEGACY=1\nretirement_validate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid retirement receipt', result.stderr)

    def test_receipt_rejects_malformed_line_eight_before_bindings(self):
        receipt = self.root / '.couvrefeu-retirement'
        pin = 'a' * 64
        for malformed in ('', 'usr/lib/couvrefeu/core.sh\tforeign',
                          'usr/lib/couvrefeu/core.sh;touch /tmp/foreign',
                          'usr/lib/couvrefeu/core.sh  etc/config/firewall'):
            with self.subTest(inventory=malformed):
                lines = ['CFRETIREMENT 2', pin, 'strict', pin, pin, '1:1', '1',
                         malformed, '', pin, pin, pin,
                         ' '.join(f'item{i}:{pin}' for i in range(16))]
                lines += [f'item{i}\t{pin}\tvalue' for i in range(5)]
                receipt.write_text('\n'.join(lines) + '\n')
                receipt.chmod(0o600)
                result = self.common('platform_transaction_mutex_check() { :; }\nretirement_validate')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('invalid retirement receipt', result.stderr)
                self.assertNotIn('retirement release/profile mismatch', result.stderr)

    def test_receipt_selects_legacy_target_from_receipt_before_count_check(self):
        receipt = self.root / '.couvrefeu-retirement'
        pin = 'a' * 64
        legacy = '28b3278555e61239471497b7e806b05c8f5eed82b7cabca7ad8264d22cf6e539'
        lines = ['CFRETIREMENT 2', legacy, 'strict', pin, 'none', '1:1', '1',
                 RETIREMENT_INVENTORY, '', pin, pin, pin,
                 ' '.join(f'item{i}:{pin}' for i in range(15))]
        lines += [f'item{i}\t{pin}\tvalue' for i in range(5)]
        receipt.write_text('\n'.join(lines) + '\n')
        receipt.chmod(0o600)
        result = self.common('platform_transaction_mutex_check() { :; }\nRETIRE_LEGACY=0\nretirement_validate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('retirement release/profile mismatch', result.stderr)
        self.assertNotIn('invalid retirement receipt', result.stderr)


if __name__ == '__main__':
    unittest.main()
