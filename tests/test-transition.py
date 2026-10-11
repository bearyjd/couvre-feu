#!/usr/bin/env python3
"""Guarded transition/crash models; these do not establish real packet behavior."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / 'fixtures'))
from harness import KID, OTHER_KID, PROTECTED, REPO, RouterFixture, policy
spec = importlib.util.spec_from_file_location('core_model', Path(__file__).with_name('test-core.py'))
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


def packet(family, adult=False, reverse=False):
    child = '2001:db8::20' if family == 'ip6tables' else '192.168.1.20'
    control = '2001:db8::10' if family == 'ip6tables' else '192.168.1.10'
    remote = '2001:db8:ffff::1' if family == 'ip6tables' else '198.51.100.1'
    address = control if adult else child
    return dict(src=remote if reverse else address, dst=address if reverse else remote,
                mac='02:ff:ff:ff:ff:01' if reverse else PROTECTED if adult else KID,
                **{'in': 'eth0' if reverse else 'br-lan', 'out': 'br-lan' if reverse else 'eth0'},
                protocol='udp', dport='5000', weekday='Mon', time='23:00:00', ctstate='ESTABLISHED')


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.f = RouterFixture()

    def tearDown(self):
        self.f.close()

    def success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'], result.stdout)

    def paused_policy(self, revision=1):
        doc = policy(revision)
        doc['pauses'] = [{'person': 'alice', 'until': 0}]
        return doc

    def verify_reachability(self, state, child_blocked=True):
        for family in ('iptables', 'ip6tables'):
            for reverse in (False, True):
                for adult in (False, True):
                    result = model.evaluate_fixture_chain(state['tables'][family]['filter'], 'FORWARD',
                                                          packet(family, adult, reverse), state['sets'])
                    with self.subTest(family=family, reverse=reverse, adult=adult):
                        self.assertEqual(result in ('REJECT', 'DROP'), child_blocked and not adult, result)

    def test_every_effect_preserves_paused_child_and_adult_reachability(self):
        self.success(self.f.run('sync', document=self.paused_policy()))
        self.f.update_backend(capture_effects=True, effects=[])
        doc = self.paused_policy(2)
        doc['doh'] = {'ipv4': ['1.1.1.1'], 'ipv6': ['2606:4700:4700::1111']}
        self.success(self.f.run('sync', document=doc))
        effects = self.f.backend()['effects']
        switches = [row for row in effects if '-R' in row['argv']]
        self.assertEqual(len(switches), 5)
        for row in effects:
            self.verify_reachability(row)
            if '-R' in row['argv']:
                for family in ('iptables', 'ip6tables'):
                    first = row['tables'][family]['filter']['cf_fwd'][0]
                    self.assertTrue(first[first.index('-j') + 1].endswith('_g'))
        parent_deletes = [row for row in effects if '-D' in row['argv'] and any(c in row['argv'] for c in ('forwarding_rule', 'input_rule', 'prerouting_rule'))]
        self.assertEqual(parent_deletes, [])

    def test_failed_second_family_switch_retains_guard_and_recovers(self):
        self.success(self.f.run('sync', document=self.paused_policy()))
        self.f.update_backend(failures=[{'command': 'ip6tables', 'contains': ['-R', 'cf_fwd'], 'remaining': 1}])
        doc = self.paused_policy(2)
        doc['doh']['ipv4'] = ['1.1.1.1']
        result = self.f.run('sync', document=doc)
        self.assertNotEqual(result.returncode, 0)
        status = json.loads(result.stdout)
        self.assertEqual(status['desiredRevision'], 2)
        self.assertEqual(status['confirmedRevision'], 1)
        self.assertFalse(status['ok'])
        self.verify_reachability(self.f.backend())
        self.success(self.f.run('apply-fw'))
        self.verify_reachability(self.f.backend())

    def test_foreign_reference_refuses_before_flushing_generation(self):
        self.success(self.f.run('sync', document=self.paused_policy()))
        state = self.f.backend()
        target = self.f.active_chain('f')
        state['tables']['iptables']['filter']['foreign'] = [['-j', target]]
        self.f.update_backend(tables=state['tables'])
        before = self.f.backend()
        mutations = len(self.f.mutation_calls())
        result = self.f.run('remove-fw')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.backend()['tables'], before['tables'])
        self.assertEqual(len(self.f.mutation_calls()), mutations)

    def stop_at(self, checkpoint, args, raw=None):
        env = dict(self.f.env, CF_TEST_RPC_STOP=checkpoint)
        process = subprocess.Popen(self.f.shell + [str(REPO / 'router' / args[0]), *args[1:]], env=env,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            if raw is not None:
                process.stdin.write(raw)
            process.stdin.close()
            deadline = time.monotonic() + 90
            while not (self.f.root / 'rpc-stopped').exists():
                if process.poll() is not None:
                    self.fail(process.stderr.read() + process.stdout.read())
                if time.monotonic() > deadline:
                    self.fail('checkpoint was not reached')
                time.sleep(0.05)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            process.stdout.close(); process.stderr.close()

    def install(self):
        env = dict(self.f.env, CF_TEST_INSTALL_KERNEL='1')
        result = subprocess.run(self.f.shell + [str(REPO / 'router/install.sh'), '--activate', '--protect', PROTECTED],
                                env=env, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)

    def uninstall(self):
        return subprocess.run(self.f.shell + [str(REPO / 'router/uninstall.sh')],
                              env=dict(self.f.env, CF_TEST_INSTALL_KERNEL='1'), capture_output=True, text=True, timeout=90)

    def test_corrupt_marker_blocks_uninstall_and_exact_retry_cleans_kernel(self):
        self.install()
        self.assertFalse((self.f.root / 'etc/couvrefeu/runtime/firewall.preflight').exists())
        self.success(self.f.run('sync', document=self.paused_policy()))
        runtime = self.f.root / 'etc/couvrefeu/runtime'
        marker = runtime / 'firewall.owned'
        original = marker.read_bytes()
        marker.write_text('corrupt\n')
        before = self.f.backend()
        mutations = len(self.f.mutation_calls())
        result = self.uninstall()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.f.backend()['tables'], before['tables'])
        self.assertEqual(self.f.backend()['sets'], before['sets'])
        self.assertEqual(len(self.f.mutation_calls()), mutations)
        self.assertTrue((self.f.root / 'usr/sbin/cfctl').exists())
        self.assertFalse((self.f.root / 'etc/couvrefeu/backup/kernel-cleaned').exists())
        marker.write_bytes(original)
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(name.startswith('cf2_') for name in self.f.backend()['sets']))
        for family in self.f.backend()['tables'].values():
            self.assertFalse(any(name.startswith(('cf2_', 'cf_')) for name in family['filter']))

    def test_no_marker_rejects_hidden_runtime_and_existing_kernel_objects(self):
        runtime = self.f.root / 'etc/couvrefeu/runtime'
        runtime.mkdir(mode=0o700)
        hidden = runtime / '.unknown'
        hidden.write_text('unowned\n'); hidden.chmod(0o600)
        result = self.f.run('remove-fw')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(hidden.exists())
        self.assertEqual(self.f.mutation_calls(), [])
        hidden.unlink()
        self.success(self.f.run('sync', document=self.paused_policy()))
        marker = runtime / 'firewall.owned'
        saved = marker.read_bytes()
        marker.unlink()
        before = self.f.backend()
        result = self.f.run('remove-fw')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.f.backend()['tables'], before['tables'])
        marker.symlink_to(self.f.root / 'etc/couvrefeu/protected')
        result = self.f.run('remove-fw')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(marker.is_symlink())
        marker.unlink(); marker.write_bytes(saved); marker.chmod(0o600)
        self.success(self.f.run('remove-fw'))

    def test_initial_ownership_journal_failure_uninstalls_without_kernel_mutation(self):
        self.f.env['CF_TEST_INSTALL_KERNEL'] = '1'
        self.f.update_backend(failures=[{'command': 'sync', 'skip': 5, 'remaining': 1}])
        result = subprocess.run(self.f.shell + [str(REPO / 'router/install.sh'), '--activate', '--protect', PROTECTED],
                                env=self.f.env, capture_output=True, text=True, timeout=90)
        self.assertNotEqual(result.returncode, 0)
        runtime = self.f.root / 'etc/couvrefeu/runtime'
        self.assertTrue((runtime / 'firewall.intent').exists())
        self.assertFalse((runtime / 'firewall.owned').exists())
        self.assertEqual(self.f.mutation_calls(), [])
        before = self.f.backend()
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.f.backend()['tables'], before['tables'])
        self.assertEqual(self.f.backend()['sets'], before['sets'])
        self.assertEqual(self.f.mutation_calls(), [])
        self.assertFalse((self.f.root / 'usr/sbin/cfctl').exists())

    def test_initial_descriptor_only_process_crash_removes_exact_journal(self):
        self.stop_at('after_initial_intent', ['cfctl', 'sync'], json.dumps(self.paused_policy()))
        runtime = self.f.root / 'etc/couvrefeu/runtime'
        self.assertTrue((runtime / 'firewall.intent').exists())
        self.assertFalse((runtime / 'firewall.owned').exists())
        self.assertEqual(self.f.mutation_calls(), [])
        result = self.f.run('remove-fw')
        self.success(result)
        self.assertTrue(json.loads(result.stdout)['zeroOwnedMutations'])
        self.assertFalse((runtime / 'firewall.intent').exists())
        self.assertEqual(self.f.mutation_calls(), [])

    def test_reload_guard_loss_fences_all_switches_and_confirmation(self):
        for drift in ('body', 'union', 'missing'):
            with self.subTest(drift=drift):
                if drift != 'body':
                    self.f.close(); self.f = RouterFixture()
                self.success(self.f.run('sync', document=self.paused_policy()))
                self.f.update_backend(reload_guard_drift=drift)
                doc = self.paused_policy(2)
                doc['schedules'] = [{'person': 'alice', 'id': 'night', 'weekdays': ['Mon'], 'start': '22:00', 'stop': '06:30'}]
                count = len(self.f.mutation_calls())
                result = self.f.run('sync', document=doc)
                self.assertNotEqual(result.returncode, 0)
                status = json.loads(result.stdout)
                self.assertFalse(status['ok'])
                self.assertEqual(status['confirmedRevision'], 1)
                calls = self.f.mutation_calls()[count:]
                self.assertTrue(any(call['command'] == 'fw3' and 'reload' in call['argv'] for call in calls), result.stdout + result.stderr)
                self.assertFalse(any('-R' in call['argv'] for call in calls))
                self.assertTrue((self.f.root / 'etc/couvrefeu/runtime/firewall.intent').exists())
                self.f.update_backend(reload_guard_drift=None)
                count = len(self.f.mutation_calls())
                retry = self.f.run('apply-fw')
                self.assertNotEqual(retry.returncode, 0)
                self.assertEqual(len(self.f.mutation_calls()), count)

    def test_native_awk_policy_serializer_and_weekday_outputs(self):
        command = shlex.split(os.environ.get('CF_TEST_AWK', ''))
        if len(command) != 2 or command[1] != 'awk':
            self.skipTest('requires explicitly selected native BusyBox awk')
        records = self.f.root / 'native-awk-policy'
        records.write_text('V\t1\nR\t3\n'
                           f'P\talice\t{KID}\nP\talice\t{OTHER_KID}\nP\tbob\t-\n'
                           'A\talice\t0\nA\tbob\t1736204700\n'
                           'S\talice\tnight\tMon,Wed,Sun\t22:00\t06:30\n'
                           'S\talice\tnoon\tTue\t12:00\t12:01\n'
                           'D4\t1.1.1.1\nD4\t9.9.9.9\nD6\t2001:db8::1\nD6\t2001:db8::2\n')
        env = dict(self.f.env, CF_PROBE_BUSYBOX=command[0], CF_PROBE_RECORD=str(records),
                   CF_PROBE_CORE=str(REPO / 'router/lib/core.sh'), CF_PROBE_FIREWALL=str(REPO / 'router/lib/firewall.sh'),
                   CF_PROBE_JSON=str(REPO / 'router/lib/json.awk'))
        script = '''awk() { "$CF_PROBE_BUSYBOX" awk "$@"; }
. "$CF_PROBE_CORE"
. "$CF_PROBE_FIREWALL"
serialized=$(cf_state_json "$CF_PROBE_RECORD") || exit 1
printf '%s\\n' "$serialized"
printf '%s\\n' "$serialized" | awk -f "$CF_PROBE_JSON" >/dev/null || exit 1
CF_POLICY=$(awk '{print}' "$CF_PROBE_RECORD")
cf_schedule_specs || exit 1
printf '%s\\n' '-A example -m time --weekdays Sun,Wed,Mon --kerneltz -j DROP' | cf_normal_rules
'''
        result = subprocess.run(self.f.shell + ['-c', script], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = result.stdout.splitlines()
        doc = json.loads(rows[0])
        self.assertEqual({p['id']: p['macs'] for p in doc['people']}, {'alice': [KID, OTHER_KID], 'bob': []})
        self.assertEqual(doc['pauses'], [{'person': 'alice', 'until': 0}, {'person': 'bob', 'until': 1736204700}])
        self.assertEqual(len(doc['schedules']), 2)
        self.assertEqual(doc['doh'], {'ipv4': ['1.1.1.1', '9.9.9.9'], 'ipv6': ['2001:db8::1', '2001:db8::2']})
        windows = [row.split('\t')[3:] for row in rows[1:-1]]
        self.assertEqual(len(windows), 6)
        self.assertEqual(windows.count(['Mon,Tue,Thu', '00:00:00', '06:29:59']), 2)
        self.assertEqual(windows.count(['Mon,Wed,Sun', '22:00:00', '23:59:59']), 2)
        self.assertEqual(windows.count(['Tue', '12:00:00', '12:00:59']), 2)
        self.assertIn('--weekdays Mon,Wed,Sun', rows[-1])

    def test_expiry_clears_offline_child_and_does_not_evict_reassigned_adult(self):
        doc = self.paused_policy()
        expiry = int(self.f.env['CF_NOW']) + 30
        doc['pauses'][0]['until'] = expiry
        self.success(self.f.run('sync', document=doc))
        state = self.f.backend()
        state['neighbors'] = [row for row in state['neighbors'] if row['mac'] not in (KID, OTHER_KID)]
        state['neighbors'].append({'ip': '192.168.1.20', 'mac': PROTECTED})
        self.f.update_backend(neighbors=state['neighbors'])
        (self.f.root / 'tmp/dhcp.leases').write_text('')
        self.f.env['CF_NOW'] = str(expiry + 1)
        offset = len(self.f.calls())
        self.success(self.f.run('expire'))
        self.assertEqual(self.f.backend()['sets'][self.f.active_set('p')]['members'], [])
        self.assertFalse(any('192.168.1.20' in row['argv'] for row in self.f.calls()[offset:] if row['command'] == 'conntrack'))
        state = self.f.backend()
        reply = packet('iptables', adult=True, reverse=True)
        reply['dst'] = '192.168.1.20'
        self.assertEqual(model.evaluate_fixture_chain(state['tables']['iptables']['filter'], 'FORWARD', reply, state['sets']), 'ACCEPT')

    def test_unchanged_active_schedule_drains_both_directions_without_rebuilding(self):
        doc = policy()
        self.f.env['CF_NOW'] = '1736204400'  # Monday fixture epoch.
        # Fixture clock is deliberately chosen inside the window; target clock/DST remain gates.
        doc['schedules'] = [{'person': 'alice', 'id': 'night', 'weekdays': ['Mon'], 'start': '00:00', 'stop': '23:59'}]
        self.success(self.f.run('sync', document=doc))
        offset = len(self.f.mutation_calls())
        self.success(self.f.run('expire'))
        effects = self.f.mutation_calls()[offset:]
        self.assertTrue(any(row['command'] == 'conntrack' and '-s' in row['argv'] for row in effects))
        self.assertTrue(any(row['command'] == 'conntrack' and '-d' in row['argv'] for row in effects))
        self.assertEqual([row for row in effects if row['command'] != 'conntrack'], [])

    def test_accepted_interrupted_pause_expiry_rebases_without_resurrection(self):
        self.success(self.f.run('sync', document=policy()))
        expiry = int(self.f.env['CF_NOW']) + 30
        doc = self.paused_policy(2)
        doc['pauses'][0]['until'] = expiry
        self.f.update_backend(failures=[{'command': 'ip6tables', 'contains': ['-R', 'cf_fwd'], 'remaining': 1}])
        result = self.f.run('sync', document=doc)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['desiredRevision'], 2)
        self.f.env['CF_NOW'] = str(expiry + 1)
        self.success(self.f.run('expire', timeout=160))
        self.assertEqual(self.f.backend()['sets'][self.f.active_set('p')]['members'], [])
        self.verify_reachability(self.f.backend(), child_blocked=False)
        self.assertFalse((self.f.root / 'etc/couvrefeu/runtime/firewall.intent').exists())

    def test_interrupted_expiry_repair_never_restores_a_protected_reverse_selector(self):
        self.success(self.f.run('sync', document=policy()))
        expiry = int(self.f.env['CF_NOW']) + 30
        doc = self.paused_policy(2)
        doc['pauses'][0]['until'] = expiry
        self.f.update_backend(failures=[{'command': 'ip6tables', 'contains': ['-R', 'cf_fwd'], 'remaining': 1}])
        self.assertNotEqual(self.f.run('sync', document=doc).returncode, 0)
        state = self.f.backend()
        for row in state['neighbors']:
            if row['ip'] == '192.168.1.20':
                row['mac'] = PROTECTED
        self.f.update_backend(neighbors=state['neighbors'], capture_effects=True, effects=[])
        (self.f.root / 'tmp/dhcp.leases').write_text('')
        self.f.env['CF_NOW'] = str(expiry + 1)
        offset = len(self.f.calls())
        self.success(self.f.run('expire', timeout=180))
        state = self.f.backend()
        adult = packet('iptables', adult=True, reverse=True); adult['dst'] = '192.168.1.20'
        self.assertEqual(model.evaluate_fixture_chain(state['tables']['iptables']['filter'], 'FORWARD', adult, state['sets']), 'ACCEPT')
        self.assertFalse(any('192.168.1.20' in row['argv'] for row in self.f.calls()[offset:] if row['command'] == 'conntrack'))
        # Once the exact unsafe selector is removed, no staged reconstruction restores it.
        removed = set()
        for effect in state['effects']:
            if '-D' in effect['argv'] and '192.168.1.20' in effect['argv']:
                removed.add(effect['argv'][effect['argv'].index('-D') + 1])
            for chain in removed:
                rows = effect['tables']['iptables']['filter'].get(chain, [])
                self.assertFalse(any('-d' in r and r[r.index('-d') + 1] == '192.168.1.20' and any(t in r for t in ('REJECT', 'DROP')) for r in rows))
        self.assertTrue(removed)

    def test_old_enrolled_child_cannot_become_protected_during_removal(self):
        self.success(self.f.run('sync', document=policy()))
        protected = self.f.root / 'etc/couvrefeu/protected'
        protected.write_text(PROTECTED + '\n' + KID + '\n')
        doc = policy(2); doc['people'][0]['macs'] = [OTHER_KID]
        before = len(self.f.mutation_calls())
        result = self.f.run('sync', document=doc)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.f.mutation_calls()), before)
        self.assertEqual((self.f.root / 'etc/couvrefeu/state').read_text().splitlines()[1], 'R\t1')

    def test_boot_identity_invalidates_confirmation_until_fresh_observation(self):
        self.success(self.f.run('sync', document=policy()))
        self.f.env['CF_TEST_BOOT_ID'] = 'fixture-reboot'
        result = self.f.run('status', '--json')
        self.assertFalse(json.loads(result.stdout)['ok'])
        self.success(self.f.run('apply-fw'))
        self.success(self.f.run('status', '--json'))

    def test_all_switch_and_unguard_failures_remain_safe_and_retry(self):
        self.success(self.f.run('sync', document=self.paused_policy()))
        effects = [('iptables', '-R', 'cf_fwd'), ('iptables', '-R', 'cf_input'),
                   ('ip6tables', '-R', 'cf_fwd'), ('ip6tables', '-R', 'cf_input'),
                   ('iptables', '-R', 'cf_dns'), ('iptables', '-D', 'cf_fwd'),
                   ('ip6tables', '-D', 'cf_fwd')]
        for revision, (command, operation, chain) in enumerate(effects, 2):
            with self.subTest(command=command, operation=operation, chain=chain):
                doc = self.paused_policy(revision)
                doc['doh']['ipv4'] = [f'1.1.1.{revision}']
                self.f.update_backend(failures=[{'command': command, 'contains': [operation, chain], 'remaining': 1}])
                result = self.f.run('sync', document=doc)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(json.loads(result.stdout)['ok'])
                self.verify_reachability(self.f.backend())
                self.success(self.f.run('apply-fw'))
                self.verify_reachability(self.f.backend())

    def test_full_reload_during_native_update_is_degraded_and_reconstructs(self):
        self.success(self.f.run('sync', document=self.paused_policy()))
        self.f.update_backend(full_restart=True)
        doc = self.paused_policy(2)
        doc['schedules'] = [{'person': 'alice', 'id': 'night', 'weekdays': ['Mon'], 'start': '22:00', 'stop': '06:30'}]
        result = self.f.run('sync', document=doc)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)['ok'])
        self.f.update_backend(full_restart=False)
        self.success(self.f.run('apply-fw'))
        self.verify_reachability(self.f.backend())

    def test_crash_after_first_switch_recovers_observed_effect_before_phase(self):
        self.success(self.f.run('sync', document=self.paused_policy()))
        doc = self.paused_policy(2)
        doc['doh']['ipv4'] = ['1.1.1.1']
        env = dict(self.f.env, CF_TEST_RPC_STOP='after_4_cf_fwd_R')
        process = subprocess.Popen(self.f.shell + [str(REPO / 'router/cfctl'), 'sync'], env=env,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            process.stdin.write(json.dumps(doc)); process.stdin.close()
            deadline = time.monotonic() + 90
            while not (self.f.root / 'rpc-stopped').exists():
                if process.poll() is not None:
                    self.fail(process.stderr.read() + process.stdout.read())
                if time.monotonic() > deadline:
                    self.fail('effect checkpoint was not reached')
                time.sleep(0.05)
            self.verify_reachability(self.f.backend())
            os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
            self.assertFalse(json.loads(self.f.run('status', '--json').stdout)['ok'])
            self.success(self.f.run('apply-fw'))
            self.verify_reachability(self.f.backend())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
            process.stdout.close(); process.stderr.close()


if __name__ == '__main__':
    print('Evidence: immutable-generation and packet-reachability fixture models only.')
    unittest.main(verbosity=2)
