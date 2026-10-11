#!/usr/bin/env python3
"""RPC acceptance fixtures. No host firewall, SSH, packets or power-cut proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / 'fixtures'))
from harness import KID, OTHER_KID, PROTECTED, REPO, RouterFixture, policy


def scoped_policy(revision=1):
    result = policy(revision)
    result['people'][0]['macs'] = [KID]
    return result


class RpcTests(unittest.TestCase):
    def setUp(self):
        self.f = RouterFixture()
        self.install()
        self.base = self.observe()

    def tearDown(self):
        self.f.close()

    def script(self, name, *args, env=None):
        script_env = env or self.f.env
        if name == 'uninstall.sh':
            script_env = dict(script_env, CF_TEST_INSTALL_KERNEL='1')
        return subprocess.run(self.f.shell + [str(REPO / 'router' / name), *args],
                              env=script_env, capture_output=True, text=True, timeout=60)

    def install(self, **kwargs):
        result = self.script('install.sh', '--activate', '--protect', PROTECTED, '--rpc-allow', KID, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def observe(self, identifier=None):
        args = ('rpc-status', '--json') + ((identifier,) if identifier else ())
        result = self.f.run(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def request(self, identifier='op_1', base=None, document=None):
        base = base or self.base
        return dict(rpc_version=1, generation=base['generation'], operation_id=identifier,
                    expected_revision=base['acceptedPolicy']['revision'], expected_digest=base['policyDigest'],
                    policy=document or scoped_policy(base['acceptedPolicy']['revision'] + 1))

    def accept(self, request):
        result = self.f.run('rpc-sync', document=request)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def reject(self, request=None, raw=None, error=None):
        before = self.f.durable_snapshot()
        count = len(self.f.mutation_calls())
        result = self.f.run('rpc-sync', document=request, raw=raw)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        response = json.loads(result.stdout)
        if error:
            self.assertIn(error, response['errors'], response)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)
        return response

    def test_exact_acceptance_and_readonly_replay(self):
        request = self.request()
        result = self.accept(request)
        receipt = result['receipt']
        self.assertEqual(receipt['outcome'], 'accepted')
        self.assertTrue(receipt['current'])
        self.assertTrue(result['status']['ok'])
        self.assertEqual(receipt['acceptedDigest'], result['policyDigest'])
        expected = 'rpc1\n{}\n{}\n{}\n{}\n{}\n'.format(request['generation'], request['operation_id'],
                     request['expected_revision'], request['expected_digest'], result['policyDigest'])
        self.assertEqual(receipt['requestDigest'], hashlib.sha256(expected.encode()).hexdigest())
        before = self.f.durable_snapshot()
        count = len(self.f.mutation_calls())
        self.assertEqual(self.accept(request)['receipt'], receipt)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)

    def test_same_id_changed_request_conflicts_before_writes(self):
        request = self.request()
        self.accept(request)
        request['policy']['pauses'] = [{'person': 'alice', 'until': 0}]
        self.reject(request, error='operation_conflict')

    def test_cas_stale_base_and_generation(self):
        self.accept(self.request())
        self.reject(self.request('second'), error='policy_conflict')
        request = self.request('generation', self.observe())
        request['generation'] = '0' * 64
        self.reject(request, error='generation_conflict')

    def test_same_revision_different_digest_conflicts(self):
        state = self.f.root / 'etc/couvrefeu/state'
        state.write_text(state.read_text().replace('R\t0\n', 'R\t0\nP\talice\t' + KID + '\n'))
        self.reject(self.request(), error='policy_conflict')

    def test_scope_and_protected_guards_cover_legacy_full_sync(self):
        for mac in (OTHER_KID, PROTECTED):
            with self.subTest(mac=mac):
                document = scoped_policy()
                document['people'][0]['macs'] = [mac]
                self.reject(self.request(document=document))
                before = self.f.durable_snapshot()
                result = self.f.run('sync', document=document)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.f.durable_snapshot(), before)
                self.assertEqual(self.f.mutation_calls(), [])

    def test_local_edit_preserves_history_clears_current(self):
        request = self.request()
        self.accept(request)
        result = self.f.run('pause', 'alice')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIsNone(self.observe()['currentOperationId'])
        before = self.f.durable_snapshot()
        count = len(self.f.mutation_calls())
        old = self.accept(request)
        self.assertFalse(old['receipt']['current'])
        self.assertEqual(old['acceptedPolicy']['revision'], 2)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)
        self.reject(self.request('new_stale'), error='policy_conflict')

    def test_identical_legacy_sync_invalidates_current_receipt(self):
        request = self.request()
        accepted = self.accept(request)
        result = self.f.run('sync', document=accepted['acceptedPolicy'])
        self.assertEqual(result.returncode, 0, result.stdout)
        observed = self.observe('op_1')
        self.assertIsNone(observed['currentOperationId'])
        self.assertFalse(observed['receipt']['current'])

    def test_historical_rpc_replay_after_new_rpc_does_not_restore(self):
        old = self.request()
        first = self.accept(old)
        second = self.accept(self.request('op_2', first))
        before = self.f.durable_snapshot()
        count = len(self.f.mutation_calls())
        replay = self.accept(old)
        self.assertEqual(replay['acceptedPolicy'], second['acceptedPolicy'])
        self.assertEqual(replay['currentOperationId'], 'op_2')
        self.assertFalse(replay['receipt']['current'])
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)

    def test_expired_replay_preserves_original_until_and_never_reapplies(self):
        p = scoped_policy()
        p['pauses'] = [{'person': 'alice', 'until': int(self.f.env['CF_NOW']) + 5}]
        request = self.request(document=p)
        self.accept(request)
        self.f.env['CF_NOW'] = str(int(self.f.env['CF_NOW']) + 10)
        result = self.f.run('expire')
        self.assertEqual(result.returncode, 0, result.stdout)
        before = self.f.durable_snapshot()
        count = len(self.f.mutation_calls())
        result = self.accept(request)
        self.assertEqual(result['acceptedPolicy']['pauses'], p['pauses'])
        self.assertEqual(result['status']['effectivePauses'], [])
        self.assertEqual(result['status']['observed']['paused'], [])
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)

    def test_apply_failure_retains_receipt_and_replay_never_recovers(self):
        self.f.update_backend(failures=[{'command': 'ip6tables', 'contains': ['-A'], 'remaining': 1}])
        request = self.request()
        result = self.f.run('rpc-sync', document=request)
        self.assertNotEqual(result.returncode, 0)
        failed = json.loads(result.stdout)
        self.assertEqual(failed['receipt']['acceptedRevision'], 1)
        self.assertFalse(failed['status']['ok'])
        before = self.f.durable_snapshot()
        count = len(self.f.mutation_calls())
        replay = self.accept(request)
        self.assertFalse(replay['status']['ok'])
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)
        result = self.f.run('apply-fw')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.observe()['status']['ok'])

    def test_missing_sync_dependency_rejects_before_protection_or_policy_writes(self):
        (self.f.bin / 'sync').unlink()
        self.f.env['SSH_CONNECTION'] = '192.168.1.22 40000 192.168.1.1 22'
        self.reject(self.request(), error='missing_dependencies')
        before = self.f.durable_snapshot()
        for args, document in ((('sync',), scoped_policy()), (('apply-fw',), None), (('expire',), None)):
            result = self.f.run(*args, document=document)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(self.f.mutation_calls(), [])

    def test_rpc_unknown_or_enrolled_ssh_identity_rejects_before_writes(self):
        for ip in ('192.168.1.99', '192.168.1.20'):
            with self.subTest(ip=ip):
                self.f.env['SSH_CONNECTION'] = f'{ip} 40000 192.168.1.1 22'
                self.reject(self.request())

    def test_sync_failure_before_rename_retains_old_authority(self):
        self.f.update_backend(failures=[{'command': 'sync', 'remaining': 1}])
        result = self.f.run('rpc-sync', document=self.request())
        self.assertNotEqual(result.returncode, 0)
        observed = self.observe('op_1')
        self.assertEqual(observed['acceptedPolicy']['revision'], 0)
        self.assertIsNone(observed['receipt'])
        self.assertFalse(observed['status']['ok'])
        self.assertEqual(self.f.mutation_calls(), [])

    def test_sync_failure_after_rename_retains_receipt_without_apply(self):
        self.f.update_backend(failures=[{'command': 'sync', 'skip': 1, 'remaining': 1}])
        request = self.request()
        result = self.f.run('rpc-sync', document=request)
        self.assertNotEqual(result.returncode, 0)
        observed = self.observe('op_1')
        self.assertEqual(observed['acceptedPolicy']['revision'], 1)
        self.assertEqual(observed['receipt']['operationId'], 'op_1')
        self.assertFalse(observed['status']['ok'])
        self.assertEqual(self.f.mutation_calls(), [])
        before = self.f.durable_snapshot()
        self.accept(request)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(self.f.mutation_calls(), [])

    def test_missing_receipt_is_not_fabricated(self):
        self.assertIsNone(self.observe('not_yet')['receipt'])

    def test_normalized_whitespace_key_array_and_ipv6_replay(self):
        p = scoped_policy()
        p['people'].append({'id': 'empty', 'macs': []})
        p['doh']['ipv6'] = ['2001:0db8:0:0:0:0:0:1']
        p['schedules'] = [{'person': 'alice', 'id': 'night', 'weekdays': ['Tue', 'Mon'],
                           'start': '22:00', 'stop': '06:00'}]
        request = self.request(document=p)
        first = self.accept(request)
        request['policy']['people'].reverse()
        request['policy']['doh']['ipv6'] = ['2001:db8::1']
        request['policy']['schedules'][0]['weekdays'].reverse()
        before = self.f.durable_snapshot()
        result = self.f.run('rpc-sync', raw=json.dumps(dict(reversed(list(request.items()))), indent=3))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(json.loads(result.stdout)['receipt'], first['receipt'])
        self.assertEqual(self.f.durable_snapshot(), before)

    def test_invalid_envelopes_ascii_bounds_and_extra_documents(self):
        q = self.request()
        variants = [dict(q, extra=0), dict(q, rpc_version=2), dict(q, operation_id='-'),
                    dict(q, operation_id='A'), dict(q, operation_id='a' * 65),
                    dict(q, generation='A' * 64), dict(q, expected_digest='0' * 63),
                    dict(q, expected_revision=0.0), dict(q, expected_revision=2147483647)]
        for document in variants:
            with self.subTest(document=document):
                self.reject(document)
        for raw in (json.dumps(q) + '{}', json.dumps(q).replace('"rpc_version": 1', '"rpc_version": 1, "rpc_version": 1'),
                    json.dumps(q).replace('op_1', 'escape\\n'), '[' * 13 + '0' + ']' * 13,
                    '\x00' + json.dumps(q), '\u00e9' + json.dumps(q), ' ' * 65537):
            with self.subTest(raw=raw[:40]):
                self.reject(raw=raw)

    def test_receipt_metadata_corruption_fails_closed(self):
        self.accept(self.request())
        path = self.f.root / 'etc/couvrefeu/state'
        original = path.read_text()
        variants = [original + 'Z\t1\n', original + 'X\t1\n', original.replace('C\top_1', 'C\tmissing'),
                    original.replace('X\t1\n', ''), original + next(x for x in original.splitlines() if x.startswith('O\t')) + '\n',
                    original.replace('O\top_1\t', 'O\tINVALID\t'), original.replace('R\t1', 'R\t2')]
        for content in variants:
            with self.subTest(content=content[-80:]):
                path.write_text(content)
                self.reject(self.request('second'))
        path.write_text(original)

    def test_invalid_scope_generation_journal_and_markers_fail_closed(self):
        scope = self.f.root / 'etc/couvrefeu/rpc-allowed'
        backup = self.f.root / 'etc/couvrefeu/backup'
        original = scope.read_text()
        scope.write_text(OTHER_KID + '\n')
        self.reject(self.request())
        scope.write_text(original)
        scope.chmod(0o644)
        self.reject(self.request())
        scope.chmod(0o600)
        scope.unlink()
        scope.symlink_to(backup / 'etc_couvrefeu_rpc-allowed.staged')
        self.reject(self.request())
        scope.unlink();scope.write_text(original);scope.chmod(0o600)
        staged = backup / 'etc_couvrefeu_state.staged'
        content = staged.read_text();staged.write_text(content.replace(self.base['generation'], '0' * 64))
        self.reject(self.request())
        staged.write_text(content)
        complete = backup / 'complete';complete.unlink()
        self.reject(self.request())

    def test_missing_scope_and_metadata_never_downgrade_legacy_admission(self):
        state = self.f.root / 'etc/couvrefeu/state'
        state.write_text('V\t1\nR\t0\n')
        (self.f.root / 'etc/couvrefeu/rpc-allowed').unlink()
        before = self.f.durable_snapshot()
        result = self.f.run('sync', document=policy())
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(self.f.mutation_calls(), [])
        self.reject(self.request())

    def test_capacity_preserves_all_receipts_and_allows_exact_replay(self):
        request = self.request()
        accepted = self.accept(request)
        path = self.f.root / 'etc/couvrefeu/state'
        with path.open('a') as stream:
            for index in range(127):
                stream.write('O\tfiller_{}\t{}\t0\t{}\t1\t{}\n'.format(index, '0' * 64, self.base['policyDigest'], accepted['policyDigest']))
        self.reject(self.request('full', accepted), error='receipt_capacity')
        self.accept(request)
        self.assertEqual(sum(line.startswith('O\t') for line in path.read_text().splitlines()), 128)

    def test_uninstall_reinstall_generations_and_scope_original_restoration(self):
        old = self.request()
        result = self.script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.f.root / 'etc/couvrefeu/rpc-allowed').exists())
        self.install()
        new = self.observe()
        self.assertNotEqual(new['generation'], self.base['generation'])
        self.reject(old, error='generation_conflict')

    def test_rpc_scope_original_bytes_mode_and_absence_are_restored(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        original = self.f.root / 'etc/couvrefeu/rpc-allowed'
        original.write_bytes(b'original scope\x00bytes without terminal newline');original.chmod(0o640)
        content = original.read_bytes()
        self.install()
        self.assertEqual(original.read_text(), KID + '\n')
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        self.assertEqual(original.read_bytes(), content)
        self.assertEqual(original.stat().st_mode & 0o777, 0o640)

    def test_interrupted_activation_reuses_immutable_generation(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        result = self.script('install.sh', '--activate', '--protect', PROTECTED, '--rpc-allow', KID,
                             env=dict(self.f.env, CF_TEST_INSTALL_FAIL_AFTER='6'))
        self.assertNotEqual(result.returncode, 0)
        staged = self.f.root / 'etc/couvrefeu/backup/etc_couvrefeu_state.staged'
        content = staged.read_text()
        generation = next(row.split('\t')[1] for row in content.splitlines() if row.startswith('G\t'))
        self.install()
        self.assertEqual(self.observe()['generation'], generation)
        self.assertEqual(staged.read_text(), content)

    def test_initial_scoped_admission_rejects_nonallowed_existing_policy_before_managed_writes(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        state = self.f.root / 'etc/couvrefeu/state'
        state.write_text('V\t1\nR\t0\nP\talice\t' + OTHER_KID + '\n')
        before = self.f.durable_snapshot();count = len(self.f.mutation_calls())
        result = self.script('install.sh', '--activate', '--protect', PROTECTED, '--rpc-allow', KID)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)

    def test_rpc_state_symlink_mode_empty_and_oversize_fail_closed(self):
        state = self.f.root / 'etc/couvrefeu/state'
        original = state.read_bytes()
        for content in (b'', b'V\t1\nR\t0\nZ\t' + b'a' * 131072):
            state.write_bytes(content)
            self.reject(self.request())
        state.write_bytes(original);state.chmod(0o644)
        self.reject(self.request())
        state.chmod(0o600)
        state.unlink();state.symlink_to(self.f.root / 'etc/couvrefeu/backup/etc_couvrefeu_state.staged')
        self.reject(self.request())

    def test_scoped_kernel_activation_rpc_and_exact_uninstall(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        original = self.f.durable_snapshot()
        firewall = self.f.root / 'etc/config/firewall'
        firewall_original = (firewall.read_bytes(), firewall.stat().st_mode & 0o777)
        self.install(env=dict(self.f.env, CF_TEST_INSTALL_KERNEL='1'))
        observed = self.observe()
        self.assertTrue(observed['status']['ok'])
        accepted = self.accept(self.request(base=observed))
        self.assertTrue(accepted['receipt']['current'])
        self.assertTrue(accepted['status']['ok'])
        result = self.script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.f.durable_snapshot(), original)
        self.assertEqual((firewall.read_bytes(), firewall.stat().st_mode & 0o777), firewall_original)
        self.assertFalse((self.f.root / 'usr/sbin/cfctl').exists())
        self.assertFalse((self.f.root / 'etc/couvrefeu/runtime').exists())

    def test_install_token_never_bypasses_rpc_global_gate(self):
        lock = self.f.root / '.couvrefeu-install.lock'
        lock.mkdir(mode=0o700)
        for name, value in (('pid', str(os.getpid())), ('token', '0' * 64)):
            target = lock / name;target.write_text(value + '\n');target.chmod(0o600)
        before = self.f.durable_snapshot()
        for args in (('rpc-sync',), ('rpc-status', '--json')):
            result = self.f.run(*args, document=self.request() if args[0] == 'rpc-sync' else None,
                                env=dict(self.f.env, CF_INSTALL_TOKEN='0' * 64))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('installation_in_progress', json.loads(result.stdout)['errors'])
            self.assertNotIn('acceptedPolicy', json.loads(result.stdout))
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(self.f.mutation_calls(), [])

    def test_scoped_upgrade_of_recorded_legacy_refused(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        result = self.script('install.sh', '--activate', '--protect', PROTECTED)
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.f.durable_snapshot()
        result = self.script('install.sh', '--activate', '--protect', PROTECTED, '--rpc-allow', KID)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertIn('migration', result.stderr)

    def test_rpc_disabled_on_legacy_and_invalid_commands(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        result = self.f.run('rpc-status', '--json')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('rpc_disabled', json.loads(result.stdout)['errors'])
        for args in (('rpc-sync', 'extra'), ('rpc-status',), ('rpc-status', '--json', '-'),
                     ('rpc-status', '--json', 'bad;',), ('rpc-status', '--json', 'a' * 65)):
            self.assertNotEqual(self.f.run(*args).returncode, 0)

    def stopped(self, request, checkpoint):
        marker = self.f.root / 'rpc-stopped'
        marker.unlink(missing_ok=True)
        env = dict(self.f.env, CF_TEST_RPC_STOP=checkpoint)
        child = subprocess.Popen(self.f.shell + [str(REPO / 'router/cfctl'), 'rpc-sync'],
                                 env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        child.stdin.write(json.dumps(request));child.stdin.close();child.stdin = None
        deadline = time.monotonic() + 60
        while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        if not marker.exists():
            child.kill();stdout, stderr = child.communicate()
            self.fail('checkpoint not reached: ' + stdout + stderr)
        return child

    def test_interruptions_keep_old_or_new_complete_policy_and_receipt(self):
        request = self.request()
        for checkpoint, committed in (('before_write', False), ('during_write', False), ('after_write', False), ('before_rename', False),
                                      ('after_rename', True), ('before_confirmation', True), ('after_confirmation', True),
                                      ('after_apply', True), ('before_reply', True)):
            with self.subTest(checkpoint=checkpoint):
                # Fresh installation for each crash boundary; immutable originals preserved.
                if checkpoint != 'before_write':
                    self.assertEqual(self.script('uninstall.sh').returncode, 0)
                    self.install();self.base = self.observe();request = self.request()
                child = self.stopped(request, checkpoint)
                child.kill();child.communicate(timeout=10)
                # Reclaim a demonstrably dead lock through explicit recovery, not status.
                if committed:
                    replay = self.accept(request)
                    self.assertEqual(replay['receipt']['operationId'], request['operation_id'])
                    self.assertEqual(replay['acceptedPolicy']['revision'], 1)
                else:
                    result = self.f.run('apply-fw')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIsNone(self.observe(request['operation_id'])['receipt'])
                    self.assertEqual(self.observe()['acceptedPolicy']['revision'], 0)

    def test_delayed_prelock_request_cannot_apply_after_reinstall(self):
        request = self.request()
        child = self.stopped(request, 'before_lock')
        try:
            self.assertEqual(self.script('uninstall.sh').returncode, 0)
            self.install()
            before = self.f.durable_snapshot();count = len(self.f.mutation_calls())
            child.send_signal(signal.SIGCONT)
            stdout, stderr = child.communicate(timeout=30)
            self.assertNotEqual(child.returncode, 0, stdout + stderr)
            self.assertIn('generation_conflict', json.loads(stdout)['errors'])
            self.assertEqual(self.f.durable_snapshot(), before)
            self.assertEqual(len(self.f.mutation_calls()), count)
        finally:
            if child.poll() is None:
                child.kill();child.communicate()

    def test_runtime_owner_blocks_uninstall_and_competing_rpc(self):
        child = self.stopped(self.request(), 'before_write')
        try:
            before = self.f.durable_snapshot()
            result = self.script('uninstall.sh')
            self.assertNotEqual(result.returncode, 0)
            result = self.f.run('rpc-sync', document=self.request('competitor'))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('locked', json.loads(result.stdout)['errors'])
            self.assertEqual(self.f.durable_snapshot(), before)
            child.send_signal(signal.SIGCONT)
            stdout, stderr = child.communicate(timeout=60)
            self.assertEqual(child.returncode, 0, stdout + stderr)
            self.reject(self.request('competitor'), error='policy_conflict')
        finally:
            if child.poll() is None:
                child.kill();child.communicate()

    def test_open_stdin_does_not_lock_expiry_and_crosses_uninstall(self):
        child = subprocess.Popen(self.f.shell + [str(REPO / 'router/cfctl'), 'rpc-sync'], env=self.f.env,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            child.stdin.write(json.dumps(self.request()));child.stdin.flush()
            time.sleep(.2)
            self.assertFalse((self.f.root / 'etc/couvrefeu/runtime/lock').exists())
            result = self.f.run('expire')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = self.script('uninstall.sh')
            self.assertEqual(result.returncode, 0, result.stderr)
            child.stdin.close();child.stdin = None
            stdout, stderr = child.communicate(timeout=15)
            self.assertNotEqual(child.returncode, 0, stdout + stderr)
            self.assertFalse((self.f.root / 'etc/couvrefeu/backup').exists())
            self.assertFalse((self.f.root / 'etc/couvrefeu/runtime').exists())
        finally:
            if child.poll() is None:
                child.kill();child.communicate()

    def test_input_deadline_and_size_leave_state_unchanged(self):
        before = self.f.durable_snapshot();count = len(self.f.mutation_calls())
        child = subprocess.Popen(self.f.shell + [str(REPO / 'router/cfctl'), 'rpc-sync'], env=self.f.env,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        start = time.monotonic()
        try:
            child.stdin.write('{');child.stdin.flush()
            child.wait(timeout=14)
            self.assertLess(time.monotonic() - start, 14)
            self.assertNotEqual(child.returncode, 0)
            child.stdin.close();child.stdin = None
            child.communicate(timeout=3)
        finally:
            if child.poll() is None:
                child.kill();child.communicate()
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)

    def test_ssh_rpc_only_grammar_excludes_legacy_commands(self):
        target = self.f.bin / 'cfctl'
        target.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n');target.chmod(0o700)
        for original, permitted in (('cfctl rpc-sync', True), ('cfctl rpc-status --json', True),
                                    ('cfctl rpc-status --json op-1', True), ('cfctl sync', False),
                                    ('cfctl status --json', False), ('cfctl pause alice', False),
                                    ('cfctl expire', False), ('cfctl apply-fw', False),
                                    ('cfctl rpc-status --json -', False), ('cfctl rpc-sync; id', False),
                                    ('cfctl rpc-sync\n', False), ('cfctl rpc-status --json --rpc-only', True)):
            with self.subTest(original=original):
                result = self.script('cfctl-ssh', '--rpc-only', env=dict(self.f.env, SSH_ORIGINAL_COMMAND=original))
                self.assertEqual(result.returncode == 0, permitted, result.stdout + result.stderr)
        result = self.script('cfctl-ssh', env=dict(self.f.env, SSH_ORIGINAL_COMMAND='cfctl status --json'))
        self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
