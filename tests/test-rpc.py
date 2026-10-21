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

    def allowance_policy(self, until, revision=1):
        p = scoped_policy(revision)
        p['pauses'] = [{'person': 'alice', 'until': 0}]
        p['allowances'] = [{'person': 'alice', 'until': until}]
        return p

    def test_rpc_allowance_is_reported_and_expires_locally_with_idempotent_replay(self):
        self.assertNotIn('allowances', self.base['acceptedPolicy'])
        self.assertEqual(self.base['status']['desiredAllowances'], [])
        self.assertEqual(self.base['status']['effectiveAllowances'], [])
        now = int(self.f.env['CF_NOW'])
        request = self.request(document=self.allowance_policy(now + 60))
        result = self.accept(request)
        self.assertTrue(result['receipt']['current'])
        self.assertEqual(result['acceptedPolicy']['allowances'], [{'person': 'alice', 'until': now + 60}])
        self.assertEqual(result['status']['effectiveAllowances'], [{'person': 'alice', 'until': now + 60, 'remaining': 60}])
        self.assertEqual(result['status']['effectivePauses'], [{'person': 'alice', 'until': 0}])
        self.assertEqual(result['status']['observed']['paused'], [])
        # The service is absent: only the minute cron runs after the deadline.
        self.f.env['CF_NOW'] = str(now + 61)
        expired = self.f.run('expire')
        self.assertEqual(expired.returncode, 0, expired.stdout + expired.stderr)
        observed = self.observe()
        self.assertEqual(observed['policyDigest'], result['policyDigest'])
        self.assertEqual(observed['status']['effectiveAllowances'], [])
        self.assertEqual(observed['status']['observed']['paused'], [KID])
        before = self.f.durable_snapshot()
        count = len(self.f.mutation_calls())
        replay = self.accept(request)
        self.assertEqual(replay['receipt'], result['receipt'])
        self.assertEqual(replay['status']['observed']['paused'], [KID])
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)

    def test_rpc_allowance_beyond_router_horizon_or_unknown_person_rejected(self):
        now = int(self.f.env['CF_NOW'])
        self.reject(self.request(document=self.allowance_policy(now + 14401)), error='allowance_beyond_horizon')
        p = scoped_policy()
        p['allowances'] = [{'person': 'bob', 'until': now + 60}]
        self.reject(self.request(document=p), error='invalid_policy')

    def test_allowance_does_not_affect_exact_uninstall(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        original = self.f.durable_snapshot()
        firewall = self.f.root / 'etc/config/firewall'
        firewall_original = (firewall.read_bytes(), firewall.stat().st_mode & 0o777)
        self.install(env=dict(self.f.env, CF_TEST_INSTALL_KERNEL='1'))
        observed = self.observe()
        document = self.allowance_policy(int(self.f.env['CF_NOW']) + 60, observed['acceptedPolicy']['revision'] + 1)
        document['schedules'] = [{'person': 'alice', 'id': 'night', 'weekdays': ['Mon'], 'start': '22:00', 'stop': '06:30'}]
        accepted = self.accept(self.request(base=observed, document=document))
        self.assertTrue(accepted['status']['ok'], accepted)
        # Cron-driven expiry rewrites the journaled native config without the service.
        self.f.env['CF_NOW'] = str(int(self.f.env['CF_NOW']) + 61)
        expired = self.f.run('expire')
        self.assertEqual(expired.returncode, 0, expired.stdout + expired.stderr)
        self.assertIn('cf_sched_alice', firewall.read_text())
        result = self.script('uninstall.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.f.durable_snapshot(), original)
        self.assertEqual((firewall.read_bytes(), firewall.stat().st_mode & 0o777), firewall_original)

    def test_apply_failure_retains_receipt_and_replay_never_recovers(self):
        request = self.request()
        child = self.stopped(request, 'after_rename')
        try:
            self.f.update_backend(failures=[{'command': 'ip6tables', 'contains': ['-A'], 'remaining': 1}])
            child.send_signal(signal.SIGCONT)
            stdout, stderr = child.communicate(timeout=60)
            self.assertNotEqual(child.returncode, 0, stdout + stderr)
            self.assertEqual(self.f.backend()['failures'][0]['remaining'], 0)
            failed = json.loads(stdout)
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate(timeout=10)
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
        mutations = len(self.f.mutation_calls())
        self.f.update_backend(failures=[{'command': 'sync', 'remaining': 1}])
        result = self.f.run('rpc-sync', document=self.request())
        self.assertNotEqual(result.returncode, 0)
        observed = self.observe('op_1')
        self.assertEqual(observed['acceptedPolicy']['revision'], 0)
        self.assertIsNone(observed['receipt'])
        self.assertFalse(observed['status']['ok'])
        self.assertEqual(len(self.f.mutation_calls()), mutations)

    def test_sync_failure_after_rename_retains_receipt_without_apply(self):
        old_policy = scoped_policy()
        old_policy['pauses'] = [{'person': 'alice', 'until': 0}]
        old_policy['schedules'] = [{'person': 'alice', 'id': 'night', 'weekdays': ['Mon', 'Tue'],
                                    'start': '22:00', 'stop': '06:00'}]
        self.accept(self.request(identifier='old_operation', document=old_policy))
        self.base = self.observe()
        old_backend = self.f.backend()
        old_confirmed = (self.f.root / 'etc/couvrefeu/runtime/confirmed').read_bytes()
        old_firewall = (self.f.root / 'etc/config/firewall').read_bytes()
        request = self.request()
        revision = request['expected_revision'] + 1
        baseline_mutations = len(self.f.mutation_calls())

        def fragments(arguments):
            # Compare complete argument fragments independently of iptables'
            # option ordering; preserve values bound to their option.
            result = []
            index = 0
            while index < len(arguments):
                negate = arguments[index] == '!'
                if negate:
                    index += 1
                option = arguments[index]
                size = 3 if option == '--match-set' else 1 if option == '--kerneltz' else 2
                fragment = tuple(arguments[index:index + size])
                if negate:
                    fragment = ('!', *fragment)
                if fragment not in (('-m', 'tcp'), ('-m', 'udp')):
                    result.append(fragment)
                index += size
            return sorted(result)

        def assert_inactive_staging(staged):
            intent = (self.f.root / 'etc/couvrefeu/runtime/firewall.intent').read_text().splitlines()
            self.assertIn('PHASE staged', intent)
            self.assertIn('RECEIPT op_1', intent)
            self.assertIn('GENERATION ' + request['generation'], intent)
            slot = next(line.split()[1] for line in intent if line.startswith('SLOT '))
            prefix = 'cf2_' + slot + '_'
            expected_sets = {}
            expected_chains = {}
            for line in intent:
                fields = line.split()
                if fields[:2] == ['AFTER', 'SETDEF'] and fields[2].startswith(prefix):
                    expected_sets[fields[2]] = {'type': fields[3], 'family': fields[4], 'members': []}
                elif fields[:2] == ['AFTER', 'SET'] and fields[2].startswith(prefix):
                    expected_sets[fields[2]]['members'].append(fields[3])
                elif fields[:2] == ['AFTER', 'RULE'] and fields[4].startswith(prefix):
                    key = ('iptables' if fields[2] == '4' else 'ip6tables', fields[3], fields[4])
                    expected_chains.setdefault(key, [])
                    if fields[5] == '-A':
                        expected_chains[key].append(fragments(fields[7:]))
            self.assertTrue(expected_sets)
            self.assertTrue(expected_chains)
            actual_chains = {}
            for family, tables in staged['tables'].items():
                for table, chains in tables.items():
                    old_chains = old_backend['tables'][family][table]
                    for name, body in old_chains.items():
                        self.assertEqual(chains[name], body, 'old active rules/hooks/guards must remain unchanged')
                        self.assertFalse(any(token.startswith(prefix) for row in body for token in row),
                                         'the candidate must not be reachable from old rules')
                    for name, body in chains.items():
                        if name not in old_chains:
                            self.assertTrue(name.startswith(prefix), 'only recorded candidate chains may be added')
                            actual_chains[(family, table, name)] = [fragments(row) for row in body]
            self.assertEqual(actual_chains, expected_chains)
            for name, value in old_backend['sets'].items():
                self.assertEqual(staged['sets'][name], value, 'old active set contents must remain unchanged')
            actual_sets = {name: {'type': value['type'], 'family': value.get('family', 'inet'),
                                  'members': sorted(value['members'])}
                           for name, value in staged['sets'].items() if name not in old_backend['sets']}
            for value in expected_sets.values():
                value['members'].sort()
            self.assertEqual(actual_sets, expected_sets)
            self.assertEqual(staged['uci'], old_backend['uci'])
            self.assertEqual(staged.get('conntrack_deletions', []), old_backend.get('conntrack_deletions', []))
            self.assertEqual((self.f.root / 'etc/config/firewall').read_bytes(), old_firewall)
            self.assertEqual((self.f.root / 'etc/couvrefeu/runtime/confirmed').read_bytes(), old_confirmed)

        # With stable addresses, prepare may durably stage an unreachable slot.
        # Arm the fault at the policy rename boundary, after prior journal syncs.
        child = self.stopped(request, 'after_rename')
        try:
            state = (self.f.root / 'etc/couvrefeu/state').read_text().splitlines()
            self.assertIn('R\t' + str(revision), state)
            self.assertTrue(any(line.startswith('O\top_1\t') for line in state))
            assert_inactive_staging(self.f.backend())
            checkpoint_mutations = len(self.f.mutation_calls())
            self.assertGreater(checkpoint_mutations, baseline_mutations)
            barriers = sum(call['command'] == 'sync' for call in self.f.calls())
            self.f.update_backend(failures=[{'command': 'sync', 'remaining': 1}])
            child.send_signal(signal.SIGCONT)
            stdout, stderr = child.communicate(timeout=60)
            self.assertNotEqual(child.returncode, 0, stdout + stderr)
            self.assertEqual(self.f.backend()['failures'][0]['remaining'], 0)
            self.assertEqual(sum(call['command'] == 'sync' for call in self.f.calls()), barriers + 1)
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate(timeout=10)
        observed = self.observe('op_1')
        self.assertEqual(observed['acceptedPolicy']['revision'], revision)
        self.assertEqual(observed['receipt']['operationId'], 'op_1')
        self.assertFalse(observed['status']['ok'])
        self.assertEqual(len(self.f.mutation_calls()), checkpoint_mutations)
        assert_inactive_staging(self.f.backend())
        before = self.f.durable_snapshot()
        replay = self.accept(request)
        self.assertFalse(replay['status']['ok'])
        self.assertEqual(replay['receipt'], observed['receipt'])
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), checkpoint_mutations)
        assert_inactive_staging(self.f.backend())

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
                                 env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True)
        child.stdin.write(json.dumps(request));child.stdin.close();child.stdin = None
        deadline = time.monotonic() + 60
        while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        if not marker.exists():
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate(timeout=10)
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

    def test_rpc_activity_is_scoped_lockless_and_readonly(self):
        self.accept(self.request())
        before = self.f.durable_snapshot();count = len(self.f.mutation_calls())
        result = self.f.run('rpc-activity', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(list(document), ['version', 'router_epoch', 'counter_epoch', 'offload', 'devices', 'errors'])
        self.assertEqual([(d['person'], d['mac']) for d in document['devices']], [('alice', KID)])
        self.assertEqual(document['errors'], [])
        self.assertGreater(document['counter_epoch'], 0)
        self.assertNotIn(PROTECTED, result.stdout)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)
        self.assertNotEqual(self.f.run('rpc-activity').returncode, 0)

    def test_ssh_rpc_only_grammar_excludes_legacy_commands(self):
        target = self.f.bin / 'cfctl'
        target.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n');target.chmod(0o700)
        for original, permitted in (('cfctl rpc-sync', True), ('cfctl rpc-status --json', True),
                                    ('cfctl rpc-status --json op-1', True), ('cfctl sync', False),
                                    ('cfctl status --json', False), ('cfctl pause alice', False),
                                    ('cfctl expire', False), ('cfctl apply-fw', False),
                                    ('cfctl rpc-status --json -', False), ('cfctl rpc-sync; id', False),
                                    ('cfctl rpc-sync\n', False), ('cfctl rpc-status --json --rpc-only', False),
                                    ('cfctl rpc-activity --json', True), ('cfctl rpc-activity', False),
                                    ('cfctl rpc-activity --json op-1', False), ('cfctl activity --json', False),
                                    ('cfctl rpc-activity --json; id', False)):
            with self.subTest(original=original):
                result = self.script('cfctl-ssh', '--rpc-only', env=dict(self.f.env, SSH_ORIGINAL_COMMAND=original))
                self.assertEqual(result.returncode == 0, permitted, result.stdout + result.stderr)
        result = self.script('cfctl-ssh', env=dict(self.f.env, SSH_ORIGINAL_COMMAND='cfctl status --json'))
        self.assertEqual(result.returncode, 0)


THIRD_KID = '02:00:00:00:00:03'


def scope_args(*macs):
    return [arg for mac in macs for arg in ('--rpc-allow', mac)]


class MultiScopeRpcTests(unittest.TestCase):
    """Repeatable --rpc-allow: an immutable, sorted per-generation set of MACs."""

    def setUp(self):
        self.f = RouterFixture()
        self.install(OTHER_KID, KID)
        self.base = self.observe()

    def tearDown(self):
        self.f.close()

    script = RpcTests.script
    observe = RpcTests.observe
    accept = RpcTests.accept
    reject = RpcTests.reject

    def install(self, *macs, env=None, ok=True):
        result = self.script('install.sh', '--activate', '--protect', PROTECTED, *scope_args(*macs), env=env)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def request(self, identifier='op_1', base=None, document=None):
        base = base or self.base
        document = document or self.two_people(base['acceptedPolicy']['revision'] + 1)
        return dict(rpc_version=1, generation=base['generation'], operation_id=identifier,
                    expected_revision=base['acceptedPolicy']['revision'], expected_digest=base['policyDigest'],
                    policy=document)

    @staticmethod
    def two_people(revision=1, alice=(KID,), bob=(OTHER_KID,)):
        result = policy(revision)
        result['people'] = [{'id': 'alice', 'macs': list(alice)}, {'id': 'bob', 'macs': list(bob)}]
        return result

    def refused_install(self, *args, text=None):
        before = self.f.durable_snapshot();count = len(self.f.mutation_calls())
        result = self.script('install.sh', '--activate', '--protect', PROTECTED, *args)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        if text:
            self.assertIn(text, result.stderr)
        self.assertEqual(self.f.durable_snapshot(), before)
        self.assertEqual(len(self.f.mutation_calls()), count)

    def test_scope_file_is_lc_all_c_sorted_and_staged(self):
        expected = (KID + '\n' + OTHER_KID + '\n').encode()
        self.assertEqual((self.f.root / 'etc/couvrefeu/rpc-allowed').read_bytes(), expected)
        self.assertEqual((self.f.root / 'etc/couvrefeu/backup/etc_couvrefeu_rpc-allowed.staged').read_bytes(), expected)

    def test_policy_across_people_within_scope_accepted_and_activity_reports_both(self):
        accepted = self.accept(self.request())
        self.assertTrue(accepted['receipt']['current'])
        people = {p['id']: p['macs'] for p in accepted['acceptedPolicy']['people']}
        self.assertEqual(people, {'alice': [KID], 'bob': [OTHER_KID]})
        result = self.f.run('rpc-activity', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        devices = sorted((d['person'], d['mac']) for d in json.loads(result.stdout)['devices'])
        self.assertEqual(devices, [('alice', KID), ('bob', OTHER_KID)])
        self.assertNotIn(PROTECTED, result.stdout)
        # A subset of the scope is admissible: scope bounds, never requires, enrollment.
        self.accept(self.request('subset', base=accepted, document=self.two_people(
            accepted['acceptedPolicy']['revision'] + 1, alice=(KID, OTHER_KID), bob=())))

    def test_out_of_scope_or_protected_mac_rejected_for_rpc_and_legacy_sync(self):
        for mac in (THIRD_KID, PROTECTED):
            with self.subTest(mac=mac):
                document = self.two_people(alice=(KID, mac))
                self.reject(self.request(document=document),
                            error='rpc_scope_overlap' if mac == THIRD_KID else None)
                before = self.f.durable_snapshot()
                result = self.f.run('sync', document=document)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.f.durable_snapshot(), before)
                self.assertEqual(self.f.mutation_calls(), [])

    def test_reinstall_with_same_set_in_any_order_keeps_generation(self):
        self.install(KID, OTHER_KID)
        self.assertEqual(self.observe()['generation'], self.base['generation'])

    def test_reinstall_cannot_change_scope_subset_or_superset(self):
        for macs in ((KID,), (OTHER_KID,), (KID, OTHER_KID, THIRD_KID)):
            with self.subTest(macs=macs):
                self.refused_install(*scope_args(*macs), text='cannot change RPC scope')
        self.refused_install(text='requires explicit --rpc-allow')

    def test_scope_change_is_uninstall_then_fresh_generation(self):
        old = self.request()
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        self.assertFalse((self.f.root / 'etc/couvrefeu/rpc-allowed').exists())
        self.install(THIRD_KID, KID)
        new = self.observe()
        self.assertNotEqual(new['generation'], self.base['generation'])
        self.assertEqual((self.f.root / 'etc/couvrefeu/rpc-allowed').read_text(), KID + '\n' + THIRD_KID + '\n')
        self.reject(old, error='generation_conflict')
        self.reject(self.request('stale_scope', base=new), error='rpc_scope_overlap')
        self.attach(THIRD_KID)
        self.accept(self.request('fresh', base=new, document=self.two_people(
            new['acceptedPolicy']['revision'] + 1, bob=(THIRD_KID,))))

    def attach(self, *macs):
        # rpc-sync fails closed without current address coverage for every enrolled MAC.
        neighbors = self.f.backend()['neighbors']
        leases = self.f.root / 'tmp/dhcp.leases'
        lines = leases.read_text()
        for index, mac in enumerate(macs):
            ip = '192.168.{}.{}'.format(1 + (index + 30) // 250, 2 + (index + 30) % 250)
            neighbors.append({'ip': ip, 'mac': mac})
            lines += '0 {} {} host{} *\n'.format(mac, ip, index)
        self.f.update_backend(neighbors=neighbors)
        leases.write_text(lines)

    def test_install_refuses_protected_duplicate_malformed_and_oversized_scope(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        too_many = ['02:00:00:00:{:02x}:{:02x}'.format(i // 256, i % 256) for i in range(1, 258)]
        protected = 'RPC allowed MAC is protected'
        invalid = '--rpc-allow requires 1-256 unique canonical unicast MACs'
        argument = '--rpc-allow requires one canonical MAC'
        for args, text in ((scope_args(KID, PROTECTED), protected), (scope_args(PROTECTED), protected),
                           (scope_args(KID, KID), invalid),
                           (scope_args(KID, '02:00:00:00:00:0G'), invalid), (scope_args(KID, '02:00:00:00:00:0A'), invalid),
                           (scope_args(KID, '03:00:00:00:00:01'), invalid), (scope_args(KID, '00:00:00:00:00:00'), invalid),
                           (scope_args(KID, ''), argument), (scope_args(KID + '\n' + THIRD_KID), argument),
                           (['--rpc-allow'], argument), (scope_args(*too_many), invalid)):
            with self.subTest(args=args[:6]):
                self.refused_install(*args, text=text)

    def test_maximum_scope_of_256_installs_and_binds(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        macs = ['02:00:00:01:{:02x}:{:02x}'.format(i // 256, i % 256) for i in range(256)]
        self.install(*reversed(macs))
        scope = (self.f.root / 'etc/couvrefeu/rpc-allowed').read_text()
        self.assertEqual(scope, ''.join(mac + '\n' for mac in sorted(macs)))
        observed = self.observe()
        self.attach(*macs)
        document = policy(observed['acceptedPolicy']['revision'] + 1)
        document['people'] = [{'id': 'p{:02d}'.format(i), 'macs': macs[i * 32:(i + 1) * 32]} for i in range(8)]
        result = self.f.run('rpc-sync', document=self.request('max', base=observed, document=document), timeout=600)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        accepted = json.loads(result.stdout)
        self.assertEqual(sum(len(p['macs']) for p in accepted['acceptedPolicy']['people']), 256)

    def resign(self, content):
        directory = self.f.root / 'etc/couvrefeu'
        staged = directory / 'backup/etc_couvrefeu_rpc-allowed.staged'
        for path in (directory / 'rpc-allowed', staged):
            path.write_bytes(content);path.chmod(0o600)
        meta = staged.stat()
        (directory / 'backup/etc_couvrefeu_rpc-allowed.after').write_text('{}:{:o}:{}:{}\n'.format(
            hashlib.sha256(content).hexdigest(), meta.st_mode & 0o777, meta.st_uid, meta.st_gid))

    def test_consistently_resigned_noncanonical_scope_fails_closed(self):
        after = self.f.root / 'etc/couvrefeu/backup/etc_couvrefeu_rpc-allowed.after'
        original = (self.f.root / 'etc/couvrefeu/rpc-allowed').read_bytes()
        signature = after.read_bytes()
        # Prove the helper reproduces the installer signature, so cmp/signature cannot mask the parser.
        self.resign(original)
        self.assertEqual(after.read_bytes(), signature)
        many = ''.join('02:00:00:00:{:02x}:{:02x}\n'.format(i // 256, i % 256) for i in range(1, 258)).encode()
        k, o = KID.encode(), OTHER_KID.encode()
        for content in (b'', b'\n', o + b'\n' + k + b'\n', k + b'\n' + k + b'\n', b'0A' + k[2:] + b'\n',
                        k + b'\n' + o, k + b'\r\n', k + b'\n\n' + o + b'\n', k + b'\x00\n', b' ' + k + b'\n',
                        PROTECTED.encode() + b'\n', many):
            with self.subTest(content=content[:40]):
                self.resign(content)
                response = self.reject(self.request())
                self.assertTrue({'invalid_rpc_scope', 'protected_mac_overlap'} & set(response['errors']), response)
                self.assertNotIn('acceptedPolicy', response)
                result = self.f.run('rpc-activity', '--json')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(result.stdout)['devices'], [])
        self.resign(original)
        self.accept(self.request())

    def test_interrupted_multi_scope_activation_resumes_only_with_same_set(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        result = self.install(KID, OTHER_KID, env=dict(self.f.env, CF_TEST_INSTALL_FAIL_AFTER='6'), ok=False)
        self.assertNotEqual(result.returncode, 0)
        staged = self.f.root / 'etc/couvrefeu/backup/etc_couvrefeu_state.staged'
        content = staged.read_text()
        generation = next(row.split('\t')[1] for row in content.splitlines() if row.startswith('G\t'))
        result = self.install(KID, ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot change RPC scope', result.stderr)
        self.install(OTHER_KID, KID)
        self.assertEqual(self.observe()['generation'], generation)
        self.assertEqual(staged.read_text(), content)

    def test_exact_uninstall_restores_original_multi_line_scope_bytes_and_mode(self):
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        original = self.f.root / 'etc/couvrefeu/rpc-allowed'
        original.write_bytes((THIRD_KID + '\n' + KID + '\n').encode());original.chmod(0o640)
        content = original.read_bytes()
        self.install(KID, OTHER_KID)
        self.assertEqual(original.read_text(), KID + '\n' + OTHER_KID + '\n')
        self.assertEqual(self.script('uninstall.sh').returncode, 0)
        self.assertEqual(original.read_bytes(), content)
        self.assertEqual(original.stat().st_mode & 0o777, 0o640)


if __name__ == '__main__':
    unittest.main(verbosity=2)
