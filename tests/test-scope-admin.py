#!/usr/bin/env python3
"""M1d: admin-only scope-preview / scope-add / scope-remove and the per-admin cfctl-scope wrapper.

Isolated fixtures only (no SSH, Dropbear, router or packets). All MACs and admin names are fictional.
"""
import hashlib
import json
import os
from pathlib import Path
import pty
import signal
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / 'fixtures'))
from harness import KID, OTHER_KID, PROTECTED, REPO, RouterFixture, policy  # noqa: E402

NEW = '02:00:00:00:00:03'
NEW2 = '02:00:00:00:00:04'
GHOST = '02:00:00:00:00:05'
ADMIN = 'alpha'
SHA_ZERO = '0' * 64


def scope_sha(macs):
    """Independent digest: C-sorted newline-terminated list via sort(1) and hashlib."""
    listing = ''.join(mac + '\n' for mac in macs).encode()
    ordered = subprocess.run(['sort'], input=listing, capture_output=True, env=dict(os.environ, LC_ALL='C'), check=True).stdout
    return hashlib.sha256(ordered).hexdigest()


def tail6(mac):
    return mac.replace(':', '')[-6:]


def last_json(text):
    lines = [line for line in text.splitlines() if line.startswith('{')]
    if not lines:
        raise AssertionError('no JSON result line in: ' + text)
    return json.loads(lines[-1])


class ScopeCommon:
    def setUp(self):
        self.f = RouterFixture()
        self.live = self.f.root / 'etc/couvrefeu/rpc-allowed'
        self.runtime = self.f.root / 'etc/couvrefeu/runtime'
        self.install()
        self.attach(NEW, '192.168.1.40', 'phone-a')
        self.attach(NEW2, '192.168.1.41', 'tablet-b')

    def tearDown(self):
        self.f.close()

    def script(self, name, *args, env=None):
        script_env = env or self.f.env
        if name == 'uninstall.sh':
            script_env = dict(script_env, CF_TEST_INSTALL_KERNEL='1')
        return subprocess.run(self.f.shell + [str(REPO / 'router' / name), *args],
                              env=script_env, capture_output=True, text=True, timeout=120)

    def install(self, *floor, unscoped=False):
        args = ['--activate', '--protect', PROTECTED]
        if not unscoped:
            for mac in floor or (KID,):
                args += ['--rpc-allow', mac]
        result = self.script('install.sh', *args)
        self.assertEqual(result.returncode, 0, result.stderr)

    def attach(self, mac, ip, hostname='*', state='REACHABLE', lease=True, neighbour=True, expiry='0'):
        if neighbour:
            backend = self.f.backend()
            self.f.update_backend(neighbors=backend['neighbors'] + [{'ip': ip, 'mac': mac, 'state': state}])
        if lease:
            leases = self.f.root / 'tmp/dhcp.leases'
            leases.write_text(leases.read_text() + '{} {} {} {} *\n'.format(expiry, mac, ip, hostname))

    def status(self):
        result = self.f.run('rpc-status', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def base(self):
        return self.status()['scopeSha']

    def scope(self, *args, confirm=None, tty=True, env=None, timeout=120):
        """Run cfctl with a pseudo-terminal as stdin; `confirm` is typed (with a newline) before the read."""
        command = self.f.shell + [str(REPO / 'router/cfctl'), *args]
        if not tty:
            return subprocess.run(command, env=env or self.f.env, input=(confirm or '') + '\n',
                                  capture_output=True, text=True, timeout=timeout)
        master, slave = pty.openpty()
        try:
            if confirm is not None:
                os.write(master, (confirm + '\n').encode())
            return subprocess.run(command, env=env or self.f.env, stdin=slave, capture_output=True, text=True, timeout=timeout)
        finally:
            os.close(slave)
            os.close(master)

    def add(self, mac, base=None, **kwargs):
        return self.scope('scope-add', mac, '--base', base or self.base(), confirm=kwargs.pop('confirm', tail6(mac)), **kwargs)

    def remove(self, mac, base=None, **kwargs):
        return self.scope('scope-remove', mac, '--base', base or self.base(), confirm=kwargs.pop('confirm', tail6(mac)), **kwargs)

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        reply = last_json(result.stdout)
        self.assertTrue(reply['ok'], reply)
        return reply

    def logger_lines(self):
        return [' '.join(call['argv']) for call in self.f.calls() if call['command'] == 'logger']

    def refused(self, result, code, before, commits=0):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        reply = last_json(result.stdout)
        self.assertFalse(reply['ok'], reply)
        self.assertEqual(reply['errors'], [code], result.stdout + result.stderr)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(sum('phase=commit' in line for line in self.logger_lines()), commits)
        self.assertFalse((self.runtime / 'lock').exists())
        self.assertEqual(sorted(p.name for p in self.runtime.glob('.scope.*')), [])

    def tree(self):
        result = {}
        for top in ('etc', 'usr'):
            for path in sorted((self.f.root / top).rglob('*')):
                if path.is_file():
                    result[str(path.relative_to(self.f.root))] = (path.read_bytes(), path.stat().st_mode & 0o7777)
        return result

    def enroll(self, *macs):
        """Accept a policy whose one person uses `macs` (all must be in scope and attached)."""
        current = self.status()
        document = policy(current['acceptedPolicy']['revision'] + 1)
        document['people'][0]['macs'] = list(macs)
        request = dict(rpc_version=1, generation=current['generation'], operation_id='op_enroll',
                       expected_revision=current['acceptedPolicy']['revision'], expected_digest=current['policyDigest'],
                       policy=document)
        result = self.f.run('rpc-sync', document=request)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ScopeAddRemoveTests(ScopeCommon, unittest.TestCase):
    def test_add_grows_scope_reported_by_rpc_status_with_correct_sha_and_logs(self):
        old = self.base()
        self.assertEqual(old, scope_sha([KID]))
        result = self.add(NEW, old, env=dict(self.f.env, CF_SCOPE_ADMIN=ADMIN, SSH_CLIENT='192.168.1.10 40000 22',
                                             SSH_CONNECTION='192.168.1.10 40000 192.168.1.1 22'))
        reply = self.ok(result)
        self.assertEqual(reply['oldScopeSha'], old)
        self.assertEqual(reply['scopeSha'], scope_sha([KID, NEW]))
        self.assertIn(old, result.stdout)
        observed = self.status()
        self.assertEqual(observed['scope'], [KID, NEW])
        self.assertEqual(observed['scopeSha'], scope_sha([KID, NEW]))
        self.assertEqual(self.live.read_bytes(), (KID + '\n' + NEW + '\n').encode())
        self.assertEqual(self.live.stat().st_mode & 0o7777, 0o600)
        lines = self.logger_lines()
        self.assertEqual(len(lines), 2, lines)
        for line, phase in zip(lines, ('intent', 'commit')):
            self.assertTrue(line.startswith('-t couvrefeu '), line)
            for token in ('scope-add', 'phase=' + phase, 'admin=' + ADMIN, 'client=192.168.1.10:40000', 'mac=' + NEW,
                          'old=' + old, 'new=' + scope_sha([KID, NEW])):
                self.assertIn(token, line.split(), line)
            self.assertRegex(line, r' ppid=[1-9][0-9]* ')
        self.assertEqual(sorted(p.name for p in self.runtime.glob('.scope.*')), [])
        # The immutable floor is never touched.
        backup = self.f.root / 'etc/couvrefeu/backup'
        self.assertEqual((backup / 'etc_couvrefeu_rpc-allowed.staged').read_bytes(), (KID + '\n').encode())

    def test_add_then_remove_restores_floor_bytes(self):
        self.ok(self.add(NEW))
        self.ok(self.add(NEW2))
        self.assertEqual(self.status()['scope'], [KID, NEW, NEW2])
        reply = self.ok(self.remove(NEW))
        self.assertEqual(reply['scopeSha'], scope_sha([KID, NEW2]))
        self.ok(self.remove(NEW2))
        self.assertEqual(self.live.read_bytes(), (KID + '\n').encode())
        self.assertEqual(self.status()['scopeSha'], scope_sha([KID]))

    def test_remove_works_without_current_evidence(self):
        self.ok(self.add(NEW))
        backend = self.f.backend()
        self.f.update_backend(neighbors=[row for row in backend['neighbors'] if row['mac'] != NEW])
        leases = self.f.root / 'tmp/dhcp.leases'
        leases.write_text(''.join(line + '\n' for line in leases.read_text().splitlines() if NEW not in line))
        self.ok(self.remove(NEW))
        self.assertEqual(self.status()['scope'], [KID])

    def test_add_then_uninstall_restores_exact_tree_without_remove(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        pristine = self.tree()
        self.install()
        self.ok(self.add(NEW))
        self.ok(self.add(NEW2))
        result = self.script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.tree(), pristine)

    def test_enrolled_scope_added_mac_can_be_used_by_policy(self):
        self.ok(self.add(NEW))
        self.enroll(KID, NEW)
        self.assertIn(NEW, self.status()['acceptedPolicy']['people'][0]['macs'])


class ScopeRefusalTests(ScopeCommon, unittest.TestCase):
    def assert_refused(self, result, code, commits=0):
        self.refused(result, code, self.before, commits)

    def setUp(self):
        super().setUp()
        self.before = self.f.durable_snapshot()

    def test_non_canonical_mac_forms(self):
        for mac in ('02:00:00:00:00:0A', '02-00-00-00-00-03', '020000000003', '2:0:0:0:0:3', '02:00:00:00:00:03:', ' 02:00:00:00:00:03',
                    '02:00:00:00:00:0g', '0200.0000.0003'):
            with self.subTest(mac=mac):
                self.assert_refused(self.scope('scope-add', mac, '--base', SHA_ZERO, confirm='000003'), 'scope_mac_not_canonical')
                self.assert_refused(self.scope('scope-preview', mac), 'scope_mac_not_canonical')

    def test_multicast_and_zero_mac(self):
        for mac in ('03:00:00:00:00:03', 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
            with self.subTest(mac=mac):
                self.assert_refused(self.add(mac), 'scope_mac_invalid')

    def test_protected_mac(self):
        self.assert_refused(self.add(PROTECTED), 'scope_mac_protected')

    def test_ssh_client_mac(self):
        env = dict(self.f.env, SSH_CONNECTION='192.168.1.10 40000 192.168.1.1 22', SSH_CLIENT='192.168.1.10 40000 22')
        self.assert_refused(self.add(PROTECTED, env=env), 'scope_mac_is_ssh_client')

    def test_no_current_evidence(self):
        self.assert_refused(self.add(GHOST), 'scope_no_evidence')
        cases = (dict(ip='192.168.1.50', lease=True, neighbour=False, expiry='1000'),  # expired lease
                 dict(ip='192.168.1.51', lease=False, neighbour=True, state='FAILED'),
                 dict(ip='10.9.0.5', lease=True, neighbour=False))  # guest-pool lease is not br-lan evidence
        for case in cases:
            with self.subTest(case=case):
                self.tearDown();ScopeCommon.setUp(self)
                self.attach(GHOST, **case)
                self.before = self.f.durable_snapshot()
                self.assert_refused(self.add(GHOST), 'scope_no_evidence')

    def test_duplicate_add_and_missing_remove(self):
        self.assert_refused(self.add(KID), 'scope_mac_present')
        self.assert_refused(self.remove(NEW), 'scope_mac_absent')

    def test_floor_entry_cannot_be_removed(self):
        self.assert_refused(self.remove(KID), 'scope_mac_in_floor')

    def test_mac_in_use_by_a_person_cannot_be_removed(self):
        self.ok(self.add(NEW))
        self.enroll(KID, NEW)
        self.before = self.f.durable_snapshot()
        self.assert_refused(self.remove(NEW), 'scope_mac_in_use', commits=1)

    def test_more_than_256_entries(self):
        many = sorted({KID} | {'02:00:00:01:{:02x}:{:02x}'.format(i // 256, i % 256) for i in range(255)})
        self.assertEqual(len(many), 256)
        self.live.write_text(''.join(mac + '\n' for mac in many));self.live.chmod(0o600)
        self.before = self.f.durable_snapshot()
        self.assert_refused(self.add(NEW), 'scope_full')

    def test_stale_and_malformed_base(self):
        self.assert_refused(self.add(NEW, SHA_ZERO), 'scope_base_conflict')
        for base in ('abc', 'A' * 64, 'g' * 64, '0' * 65):
            with self.subTest(base=base):
                self.assert_refused(self.scope('scope-add', NEW, '--base', base, confirm=tail6(NEW)), 'scope_base_invalid')

    def test_command_shape(self):
        for args in (('scope-add', NEW), ('scope-add', NEW, '--base'), ('scope-add', NEW, '--sha', SHA_ZERO),
                     ('scope-add', NEW, '--base', SHA_ZERO, 'x'), ('scope-preview',), ('scope-preview', NEW, 'x'),
                     ('scope-remove',)):
            with self.subTest(args=args):
                self.assert_refused(self.scope(*args, confirm=tail6(NEW)), 'invalid_command')

    def test_tty_is_required_for_add_and_remove(self):
        self.assert_refused(self.add(NEW, tty=False), 'scope_tty_required')
        self.assert_refused(self.remove(NEW, tty=False), 'scope_tty_required')

    def test_wrong_confirmation(self):
        for typed in ('', '000004', NEW, 'yes', '00000'):
            with self.subTest(typed=typed):
                self.assert_refused(self.add(NEW, confirm=typed), 'scope_confirmation_mismatch')

    def test_service_forced_command_marker_refuses_every_scope_verb(self):
        env = dict(self.f.env, CF_SERVICE_FORCED_COMMAND='1')
        self.assert_refused(self.add(NEW, env=env), 'scope_forced_command_refused')
        self.assert_refused(self.remove(NEW, env=env), 'scope_forced_command_refused')
        self.assert_refused(self.scope('scope-preview', NEW, env=env), 'scope_forced_command_refused')

    def test_invalid_admin_label(self):
        for admin in ('Alpha', 'al1', 'a' * 17, 'a b', ''):
            with self.subTest(admin=admin):
                self.assert_refused(self.add(NEW, env=dict(self.f.env, CF_SCOPE_ADMIN=admin)), 'scope_admin_invalid')

    def test_incomplete_installation(self):
        complete = self.f.root / 'etc/couvrefeu/backup/complete'
        complete.unlink()
        self.before = self.f.durable_snapshot()
        self.assert_refused(self.add(NEW, SHA_ZERO), 'inactive_generation')
        self.assert_refused(self.scope('scope-preview', NEW), 'inactive_generation')

    def test_installation_in_progress(self):
        lock = self.f.root / '.couvrefeu-install.lock'
        lock.mkdir(mode=0o700)
        self.assert_refused(self.add(NEW, SHA_ZERO), 'installation_in_progress')

    def test_legacy_unscoped_install(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        self.install(unscoped=True)
        self.before = self.f.durable_snapshot()
        self.assert_refused(self.add(NEW, base=SHA_ZERO), 'scope_unscoped_install')
        self.assert_refused(self.scope('scope-preview', NEW), 'scope_unscoped_install')

    def test_scope_verbs_are_not_rpc_verbs(self):
        for args in (('rpc-sync', 'scope-add'), ('rpc-status', 'scope-add'), ('scope-add',)):
            with self.subTest(args=args):
                self.assertNotEqual(self.f.run(*args).returncode, 0)
        self.assertEqual(self.f.durable_snapshot(), self.before)
        for name in ('rpc.sh', 'activity.sh'):
            self.assertNotIn('scope-add', (REPO / 'router/lib' / name).read_text())


class ScopePreviewTests(ScopeCommon, unittest.TestCase):
    def test_preview_prints_evidence_la_bit_sha_and_is_read_only(self):
        self.attach(GHOST, '192.168.1.60', 'bad\x1b[31mname')
        before = self.f.durable_snapshot()
        result = self.scope('scope-preview', NEW, tty=False)
        reply = self.ok(result)
        self.assertEqual(reply['scopeSha'], scope_sha([KID]))
        self.assertEqual(reply['addRefusal'], None)
        self.assertEqual(reply['removeRefusal'], 'scope_mac_absent')
        self.assertTrue(reply['locallyAdministered'])
        self.assertIn('phone-a', result.stdout)
        self.assertIn('192.168.1.40', result.stdout)
        self.assertIn(scope_sha([KID]), result.stdout)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(self.logger_lines(), [])
        hostile = self.ok(self.scope('scope-preview', GHOST, tty=False))
        self.assertEqual(hostile['addRefusal'], None)
        out = self.scope('scope-preview', GHOST, tty=False).stdout
        self.assertIn('(unnamed)', out)
        self.assertNotIn('\x1b', out)
        self.assertNotIn('bad', out)

    def test_preview_flags_refusals_and_global_address(self):
        self.attach('00:11:22:33:44:55', '192.168.1.70', 'vendor')
        vendor = self.ok(self.scope('scope-preview', '00:11:22:33:44:55'))
        self.assertFalse(vendor['locallyAdministered'])
        self.assertEqual(self.ok(self.scope('scope-preview', PROTECTED))['addRefusal'], 'scope_mac_protected')
        floor = self.ok(self.scope('scope-preview', KID))
        self.assertEqual((floor['addRefusal'], floor['removeRefusal']), ('scope_mac_present', 'scope_mac_in_floor'))
        self.assertEqual(self.ok(self.scope('scope-preview', GHOST))['addRefusal'], 'scope_no_evidence')

    def test_preview_warns_when_protected_devices_are_absent(self):
        quiet = self.ok(self.scope('scope-preview', NEW))
        self.assertEqual(quiet['protectedAbsent'], 0)
        backend = self.f.backend()
        self.f.update_backend(neighbors=[row for row in backend['neighbors'] if row['mac'] != PROTECTED])
        result = self.scope('scope-preview', NEW)
        self.assertEqual(self.ok(result)['protectedAbsent'], 1)
        self.assertIn('WARNING', result.stdout)
        self.assertIn(PROTECTED, result.stdout)


def wait_marker(fixture, child, checkpoint):
    marker = fixture.root / 'rpc-stopped'
    deadline = time.monotonic() + 90
    while not (marker.exists() and marker.read_text().strip() == checkpoint) and child.poll() is None and time.monotonic() < deadline:
        time.sleep(.05)
    if not (marker.exists() and marker.read_text().strip() == checkpoint):
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        raise AssertionError('checkpoint %s not reached: %s' % (checkpoint, ''.join(child.communicate(timeout=10))))


class ScopeConcurrencyTests(ScopeCommon, unittest.TestCase):
    def start(self, args, checkpoint, confirm=None, env=None, stdin=None):
        (self.f.root / 'rpc-stopped').unlink(missing_ok=True)
        master = slave = None
        if confirm is not None:
            master, slave = pty.openpty()
            os.write(master, (confirm + '\n').encode())
            self.addCleanup(os.close, master);self.addCleanup(os.close, slave)
        child = subprocess.Popen(self.f.shell + [str(REPO / 'router/cfctl'), *args],
                                 env=dict(env or self.f.env, CF_TEST_RPC_STOP=checkpoint),
                                 stdin=slave if slave is not None else subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, start_new_session=True)
        if stdin is not None:
            child.stdin.write(stdin);child.stdin.close();child.stdin = None
        self.addCleanup(lambda: child.poll() is None and (os.killpg(child.pid, signal.SIGKILL), child.communicate()))
        wait_marker(self.f, child, checkpoint)
        return child

    def sync_request(self, identifier='op_c'):
        current = self.status()
        document = policy(current['acceptedPolicy']['revision'] + 1)
        document['people'][0]['macs'] = [KID]
        return json.dumps(dict(rpc_version=1, generation=current['generation'], operation_id=identifier,
                               expected_revision=current['acceptedPolicy']['revision'], expected_digest=current['policyDigest'],
                               policy=document))

    def test_scope_add_waits_for_rpc_sync_lock(self):
        base = self.base()
        child = self.start(['rpc-sync'], 'before_write', stdin=self.sync_request())
        before = self.f.durable_snapshot()
        result = self.add(NEW, base)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(last_json(result.stdout)['errors'], ['locked'])
        self.assertEqual(self.f.durable_snapshot(), before)
        child.send_signal(signal.SIGCONT)
        stdout, stderr = child.communicate(timeout=120)
        self.assertEqual(child.returncode, 0, stdout + stderr)
        self.ok(self.add(NEW, base))
        self.assertEqual(self.status()['scope'], [KID, NEW])

    def test_rpc_sync_waits_for_scope_add_lock(self):
        request = self.sync_request()  # read before the lock is taken; scope-add never changes policy
        child = self.start(['scope-add', NEW, '--base', self.base()], 'scope_before_write', confirm=tail6(NEW))
        result = self.f.run('rpc-sync', raw=request)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('locked', json.loads(result.stdout)['errors'])
        child.send_signal(signal.SIGCONT)
        stdout, stderr = child.communicate(timeout=120)
        self.assertEqual(child.returncode, 0, stdout + stderr)
        self.assertEqual(self.status()['scope'], [KID, NEW])
        result = self.f.run('rpc-sync', raw=request)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_two_admins_with_one_base_one_wins_other_is_stale(self):
        base = self.base()
        first = self.start(['scope-add', NEW, '--base', base], 'scope_before_lock', confirm=tail6(NEW),
                           env=dict(self.f.env, CF_SCOPE_ADMIN='alpha'))
        self.ok(self.add(NEW2, base, env=dict(self.f.env, CF_SCOPE_ADMIN='beta')))
        first.send_signal(signal.SIGCONT)
        stdout, stderr = first.communicate(timeout=120)
        self.assertNotEqual(first.returncode, 0, stdout + stderr)
        self.assertEqual(last_json(stdout)['errors'], ['scope_base_conflict'])
        self.assertEqual(self.status()['scope'], [KID, NEW2])

    def test_stop_and_crash_at_each_write_step_keeps_rpc_and_uninstall_working(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        pristine = self.tree()
        for checkpoint, committed in (('scope_before_write', False), ('scope_after_write', False),
                                      ('scope_before_rename', False), ('scope_after_rename', True)):
            with self.subTest(checkpoint=checkpoint):
                self.install()
                child = self.start(['scope-add', NEW, '--base', self.base()], checkpoint, confirm=tail6(NEW))
                # While stopped holding the lock, RPC fails closed (busy), never with a half-written scope.
                held = self.f.run('rpc-status', '--json')
                self.assertNotEqual(held.returncode, 0)
                self.assertIn('locked', json.loads(held.stdout)['errors'])
                os.killpg(child.pid, signal.SIGKILL);child.communicate(timeout=30)
                observed = self.status()
                self.assertEqual(observed['scope'], [KID, NEW] if committed else [KID])
                self.assertEqual(observed['scopeSha'], scope_sha([KID, NEW] if committed else [KID]))
                result = self.script('uninstall.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.tree(), pristine)

    def test_killed_candidate_never_blocks_uninstall(self):
        child = self.start(['scope-add', NEW, '--base', self.base()], 'scope_after_write', confirm=tail6(NEW))
        os.killpg(child.pid, signal.SIGKILL);child.communicate(timeout=30)
        self.assertEqual(len(list(self.runtime.glob('.scope.*'))), 1)
        lock = self.runtime / 'lock'
        for name in ('pid', 'reload'):
            (lock / name).unlink(missing_ok=True)
        lock.rmdir()
        result = self.script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)


class FakeTargetMixin:
    """A recording stand-in for /usr/sbin/cfctl, as in test-service-key-entry.py."""

    def fake_target(self):
        self.log = self.f.root / 'target.json'
        fake = self.f.bin / 'cfctl'
        fake.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                        + 'open(' + repr(str(self.log)) + ",'w').write(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ)}))\n"
                        + "print('{\"ok\":true}')\n")
        fake.chmod(0o700)

    def wrapper(self, name, command, *argv, env=None):
        self.log.unlink(missing_ok=True)
        environment = dict(env or self.f.env)
        if command is None:
            environment.pop('SSH_ORIGINAL_COMMAND', None)
        else:
            environment['SSH_ORIGINAL_COMMAND'] = command
        return subprocess.run(self.f.shell + [str(REPO / 'router' / name), *argv], env=environment,
                              text=True, capture_output=True, timeout=10)


class ServiceWrapperRejectsScopeTests(FakeTargetMixin, unittest.TestCase):
    def setUp(self):
        self.f = RouterFixture()
        self.fake_target()

    def tearDown(self):
        self.f.close()

    def test_both_cfctl_ssh_modes_reject_scope_verbs_including_colon_free_macs(self):
        commands = ['cfctl scope-add 020000000003 --base ' + SHA_ZERO, 'cfctl scope-remove 020000000003 --base ' + SHA_ZERO,
                    'cfctl scope-preview 020000000003', 'cfctl scope-add 02:00:00:00:00:03 --base ' + SHA_ZERO,
                    'cfctl scope-preview', 'cfctl scope-add', 'cfctl scope-remove']
        for command in commands:
            for flags in ((), ('--rpc-only',)):
                with self.subTest(command=command, flags=flags):
                    result = self.wrapper('cfctl-ssh', command, *flags)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertFalse(self.log.exists())

    def test_cfctl_ssh_marks_its_child_as_the_service_forced_command(self):
        result = self.wrapper('cfctl-ssh', 'cfctl rpc-sync', '--rpc-only')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.log.read_text())['env'].get('CF_SERVICE_FORCED_COMMAND'), '1')


class AdminWrapperTests(FakeTargetMixin, unittest.TestCase):
    def setUp(self):
        self.f = RouterFixture()
        self.fake_target()

    def tearDown(self):
        self.f.close()

    def accepted(self):
        return ['cfctl scope-preview ' + NEW, 'cfctl scope-add ' + NEW + ' --base ' + SHA_ZERO,
                'cfctl scope-remove ' + NEW + ' --base ' + 'a' * 64]

    def test_three_forms_are_admitted_with_admin_label_and_clean_environment(self):
        env = dict(self.f.env, SSH_CONNECTION='192.0.2.1 1 192.0.2.2 22', SSH_CLIENT='192.0.2.1 1 22',
                   CF_INHERITED_PROBE='leak', CF_SERVICE_FORCED_COMMAND='1', CF_SCOPE_ADMIN='mallory', ENV='/x', BASH_ENV='/x')
        for command in self.accepted():
            with self.subTest(command=command):
                result = self.wrapper('cfctl-scope', command, ADMIN, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(self.log.read_text())
                self.assertEqual(record['argv'], command.split(' ')[1:])
                child = record['env']
                self.assertEqual(child['CF_SCOPE_ADMIN'], ADMIN)
                for name in ('CF_INHERITED_PROBE', 'CF_SERVICE_FORCED_COMMAND', 'CF_TEST_MODE', 'CF_ROOT', 'CF_BACKEND_DIR',
                             'ENV', 'BASH_ENV', 'HOME', 'SSH_ORIGINAL_COMMAND'):
                    self.assertNotIn(name, child)
                self.assertEqual(child['SSH_CONNECTION'], '192.0.2.1 1 192.0.2.2 22')
                self.assertEqual(child['SSH_CLIENT'], '192.0.2.1 1 22')
                self.assertEqual(child['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')

    def test_admin_argument_is_validated(self):
        for argv in ((), ('',), ('Alpha',), ('al1',), ('a' * 17,), (ADMIN, 'extra'), ('-x',), ('a-b',), ('../x',)):
            with self.subTest(argv=argv):
                result = self.wrapper('cfctl-scope', self.accepted()[0], *argv)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.log.exists())

    def test_everything_else_is_rejected(self):
        mac = NEW
        rejected = [None, '', 'sh', '/bin/sh', 'sh -c id', 'id', 'internal-sftp', 'scp -t /tmp', 'cfctl',
                    'cfctl rpc-sync', 'cfctl rpc-status --json', 'cfctl rpc-activity --json', 'cfctl status --json',
                    'cfctl sync', 'cfctl pause alice', 'cfctl resume alice', 'cfctl expire', 'cfctl apply-fw', 'cfctl remove-fw',
                    'cfctl check', 'cfctl scope-preview', 'cfctl scope-preview ' + mac + ' extra',
                    'cfctl scope-add ' + mac, 'cfctl scope-add ' + mac + ' --base', 'cfctl scope-add ' + mac + ' --base ' + 'a' * 63,
                    'cfctl scope-add ' + mac + ' --base ' + 'a' * 65, 'cfctl scope-add ' + mac + ' --base ' + 'A' * 64,
                    'cfctl scope-add ' + mac + ' --sha ' + SHA_ZERO, 'cfctl scope-add ' + mac + ' --base ' + SHA_ZERO + ' x',
                    'cfctl scope-add 020000000003 --base ' + SHA_ZERO, 'cfctl scope-add 02:00:00:00:00:0A --base ' + SHA_ZERO,
                    'cfctl scope-add 02-00-00-00-00-03 --base ' + SHA_ZERO, 'cfctl scope-preview 02:00:00:00:00:003',
                    'cfctl scope-preview ' + mac + '; id', 'cfctl scope-preview $(id)', 'cfctl scope-preview `id`',
                    'cfctl scope-preview ' + mac + ' | cat', 'cfctl scope-preview ' + mac + '\nid',
                    'cfctl scope-preview ' + mac + ' && id', '/usr/sbin/cfctl scope-preview ' + mac,
                    'CFCTL scope-preview ' + mac, 'scope-preview ' + mac, 'cfctl scope-add ' + mac + ' --base ' + SHA_ZERO + ' ' + 'x' * 200,
                    'cfctl --base ' + SHA_ZERO + ' scope-add ' + mac, 'cfctl scope-add --base ' + SHA_ZERO + ' ' + mac,
                    # MAC-shaped second token: only the verb allow-list rejects these.
                    'cfctl rpc-status ' + mac, 'cfctl pause ' + mac, 'cfctl remove-fw ' + mac + ' --base ' + SHA_ZERO]
        for command in rejected:
            with self.subTest(command=command):
                result = self.wrapper('cfctl-scope', command, ADMIN)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(self.log.exists())

    def test_test_mode_requires_marked_private_root(self):
        outside = self.f.root.parent / 'not-a-couvre-feu-root'
        for name, override in {'root_not_marked_prefix': dict(CF_ROOT=str(outside)),
                               'backend_outside_root': dict(CF_BACKEND_DIR=str(outside / 'bin')),
                               'root_unset': dict(CF_ROOT=''), 'backend_unset': dict(CF_BACKEND_DIR='')}.items():
            with self.subTest(case=name):
                result = self.wrapper('cfctl-scope', self.accepted()[0], ADMIN, env=dict(self.f.env, **override))
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.log.exists())


class AdminWrapperEndToEndTests(ScopeCommon, unittest.TestCase):
    """cfctl-scope in front of the real cfctl: the admin name reaches the audit log."""

    def setUp(self):
        super().setUp()
        target = self.f.bin / 'cfctl'
        keep = {k: v for k, v in self.f.env.items() if k.startswith('CF_') and k != 'CF_TEST_RPC_STOP'}
        exports = ''.join('export {}={}\n'.format(k, json.dumps(v)) for k, v in sorted(keep.items()))
        target.write_text('#!/bin/sh\n' + exports + 'exec ' + ' '.join(self.f.shell) + ' ' + str(REPO / 'router/cfctl') + ' "$@"\n')
        target.chmod(0o700)

    def via_wrapper(self, command, confirm=None):
        env = dict(self.f.env, SSH_ORIGINAL_COMMAND=command)
        master, slave = pty.openpty()
        try:
            if confirm is not None:
                os.write(master, (confirm + '\n').encode())
            return subprocess.run(self.f.shell + [str(REPO / 'router/cfctl-scope'), ADMIN], env=env, stdin=slave,
                                  capture_output=True, text=True, timeout=120)
        finally:
            os.close(slave);os.close(master)

    def test_preview_then_add_through_the_wrapper_logs_the_admin(self):
        base = self.ok(self.via_wrapper('cfctl scope-preview ' + NEW))['scopeSha']
        self.ok(self.via_wrapper('cfctl scope-add {} --base {}'.format(NEW, base), confirm=tail6(NEW)))
        self.assertEqual(self.status()['scope'], [KID, NEW])
        lines = self.logger_lines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(('admin=' + ADMIN) in line.split() for line in lines), lines)


class InstallerTests(ScopeCommon, unittest.TestCase):
    def test_wrapper_is_installed_journaled_preserved_and_removed(self):
        installed = self.f.root / 'usr/sbin/cfctl-scope'
        self.assertEqual(installed.read_bytes(), (REPO / 'router/cfctl-scope').read_bytes())
        self.assertEqual(installed.stat().st_mode & 0o7777, 0o755)
        backup = self.f.root / 'etc/couvrefeu/backup'
        for suffix in ('before', 'after', 'staged', 'mtime'):
            self.assertTrue((backup / ('usr_sbin_cfctl-scope.' + suffix)).exists(), suffix)
        self.assertIn('/usr/sbin/cfctl-scope\n', (self.f.root / 'etc/sysupgrade.conf').read_text())
        result = self.script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(installed.exists())

    def test_drift_in_the_wrapper_refuses_uninstall_until_restored(self):
        installed = self.f.root / 'usr/sbin/cfctl-scope'
        original = installed.read_bytes()
        installed.write_bytes(original + b'# drift\n')
        before = self.tree()
        result = self.script('uninstall.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('drift at /usr/sbin/cfctl-scope', result.stderr)
        self.assertEqual(self.tree(), before)
        installed.write_bytes(original)
        self.assertEqual(self.script('uninstall.sh').returncode, 0)

    def test_interrupted_cleanup_after_the_wrapper_record_is_gone_still_finishes(self):
        # First interruption leaves the completed recovery journal; the second stops right after
        # the wrapper's .after record (C glob order) is deleted while its other records remain.
        result = self.script('uninstall.sh', env=dict(self.f.env, CF_TEST_UNINSTALL_CLEANUP_FAIL_AFTER='1'))
        self.assertNotEqual(result.returncode, 0)
        recovery = self.f.root / '.couvrefeu-recovery'
        names = sorted(os.listdir(recovery))
        index = names.index('usr_sbin_cfctl-scope.after')
        result = self.script('uninstall.sh', env=dict(self.f.env, CF_TEST_UNINSTALL_CLEANUP_FAIL_AFTER=str(index + 1)))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((recovery / 'usr_sbin_cfctl-scope.after').exists())
        self.assertTrue((recovery / 'usr_sbin_cfctl-scope.before').exists())
        result = self.script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.f.root / 'usr/sbin/cfctl-scope').exists())
        self.assertFalse(recovery.exists())

    def test_release_manifest_lists_the_wrapper_and_is_frozen(self):
        names = [line.split()[1] for line in (REPO / 'router/release.sha256').read_text().splitlines()]
        self.assertIn('cfctl-scope', names)
        self.assertEqual(len(names), 15)
        result = subprocess.run([sys.executable, str(REPO / 'tools/freeze-router-release.py'), '--check'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
