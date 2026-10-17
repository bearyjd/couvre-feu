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
                protocol='udp', dport='5000', weekday='Mon', time='23:00:00', ctstate='ESTABLISHED',
                datetime='2025-01-06T23:00:00')


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
        switches = [row for row in effects if '-R' in row['argv'] and 'cf_acct' not in row['argv']]
        self.assertEqual(len(switches), 5)
        for row in effects:
            self.verify_reachability(row)
            if '-R' in row['argv'] and 'cf_acct' not in row['argv']:
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

    def test_interrupted_transition_never_revives_allowance_expired_in_between(self):
        # Conservative recovery replays the generation prepared while the allowance was active. Every
        # intermediate kernel state must still block at the real (post-until) time via the datestart gate.
        self.success(self.f.run('sync', document=self.paused_policy(), timeout=180))
        until = int(self.f.env['CF_NOW']) + 30
        doc = self.paused_policy(2)
        doc['allowances'] = [{'person': 'alice', 'until': until}]
        self.f.update_backend(failures=[{'command': 'ip6tables', 'contains': ['-R', 'cf_fwd'], 'remaining': 1}])
        result = self.f.run('sync', document=doc, timeout=180)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['desiredRevision'], 2)
        self.f.update_backend(capture_effects=True, effects=[])
        self.f.env['CF_NOW'] = str(until + 1)
        self.success(self.f.run('expire', timeout=240))
        state = self.f.backend()
        self.assertCountEqual(state['sets'][self.f.active_set('p')]['members'], [KID, OTHER_KID])
        self.verify_reachability(state, child_blocked=True)
        late = dict(datetime=time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(until + 1)))
        self.assertTrue(state['effects'])
        for effect in state['effects']:
            for family in ('iptables', 'ip6tables'):
                decision = model.evaluate_fixture_chain(effect['tables'][family]['filter'], 'FORWARD', {**packet(family), **late}, effect['sets'])
                with self.subTest(argv=effect['argv'][:6], family=family):
                    self.assertIn(decision, ('REJECT', 'DROP'))
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


class FailClosedReconstructionTests(unittest.TestCase):
    """Ordering models for fail-closed reconstruction; not real-kernel atomicity."""
    success = TransitionTests.success
    paused_policy, verify_reachability = TransitionTests.paused_policy, TransitionTests.verify_reachability
    stop_at, install, uninstall = TransitionTests.stop_at, TransitionTests.install, TransitionTests.uninstall
    SCHEDULE = [{'person': 'alice', 'id': 'night', 'weekdays': ['Mon'], 'start': '22:00', 'stop': '06:30'}]
    # Fresh fixture addresses per device; OTHER_KID has no IPv6 neighbor, so its
    # IPv6 probe is outbound-only and blocked solely by source-MAC selectors.
    DEVICES = {KID: {'iptables': '192.168.1.20', 'ip6tables': '2001:db8::20'},
               OTHER_KID: {'iptables': '192.168.1.22', 'ip6tables': None}}

    def setUp(self):
        TransitionTests.setUp(self)
        self.started = time.monotonic()

    def tearDown(self):
        # run-fixtures.py relays TIMING lines so CI reports per-test durations.
        print(f'TIMING: {self.id()} {time.monotonic() - self.started:.1f}s', file=sys.stderr, flush=True)
        TransitionTests.tearDown(self)

    @staticmethod
    def slots(fixture):
        old = fixture.slot()
        return old, 'b' if old == 'a' else 'a'

    def assert_switches_guarded(self, effects, new):
        switches = [row for row in effects if '-R' in row['argv'] and 'cf_acct' not in row['argv']]
        self.assertEqual(len(switches), 5)
        for row in switches:
            for family in ('iptables', 'ip6tables'):
                with self.subTest(switch=row['argv'], family=family):
                    first = self.dispatch_targets(row)[(family, 'cf_fwd')][0]
                    self.assertEqual(first, f'cf2_{new}_g', 'guard must be first in cf_fwd at every switch')

    def device_blocked(self, state, family, mac):
        """True/False when every probe agrees, otherwise the mixed probe verdicts."""
        remote = '2001:db8:ffff::1' if family == 'ip6tables' else '198.51.100.1'
        address = self.DEVICES[mac][family]
        probes = [(address or '2001:db8::22', False)] + ([(address, True)] if address else [])
        verdicts = []
        for local, reverse in probes:
            probe = dict(src=remote if reverse else local, dst=local if reverse else remote,
                         mac='02:ff:ff:ff:ff:01' if reverse else mac,
                         **{'in': 'eth0' if reverse else 'br-lan', 'out': 'br-lan' if reverse else 'eth0'},
                         protocol='udp', dport='5000', weekday='Mon', time='23:00:00', ctstate='ESTABLISHED')
            result = model.evaluate_fixture_chain(state['tables'][family]['filter'], 'FORWARD', probe, state['sets'])
            verdicts.append(result in ('REJECT', 'DROP'))
        return verdicts[0] if len(set(verdicts)) == 1 else verdicts

    def adults_reachable(self, state):
        for family in ('iptables', 'ip6tables'):
            for reverse in (False, True):
                result = model.evaluate_fixture_chain(state['tables'][family]['filter'], 'FORWARD',
                                                      packet(family, True, reverse), state['sets'])
                self.assertNotIn(result, ('REJECT', 'DROP'), (family, reverse))

    def child_set_transition(self, old_macs, new_macs):
        old_doc, new_doc = self.paused_policy(), self.paused_policy(2)
        old_doc['people'][0]['macs'], new_doc['people'][0]['macs'] = old_macs, new_macs
        self.success(self.cfctl('sync', document=old_doc))
        _, new = self.slots(self.f)
        self.f.update_backend(capture_effects=True, effects=[])
        self.success(self.cfctl('sync', document=new_doc))
        effects = self.f.backend()['effects']
        self.assert_switches_guarded(effects, new)
        def position(family, operation):
            matches = [index for index, row in enumerate(effects) if row['command'] == family
                       and operation in row['argv'] and 'cf_fwd' in row['argv'] and f'cf2_{new}_g' in row['argv']]
            self.assertEqual(len(matches), 1, (family, operation))
            return matches[0]
        attach = {family: position(family, '-I') for family in ('iptables', 'ip6tables')}
        unguard = {family: position(family, '-D') for family in ('iptables', 'ip6tables')}
        for index, row in enumerate(effects):
            with self.subTest(index=index, command=row['command'], argv=row['argv']):
                self.adults_reachable(row)
                for family in ('iptables', 'ip6tables'):
                    for mac in set(old_macs) | set(new_macs):
                        if mac in old_macs and mac in new_macs:
                            expected = True
                        elif mac in old_macs:  # removed: blocked until its family is unguarded
                            expected = index < unguard[family]
                        else:  # added: blocked from its family's guard attachment onward
                            expected = index >= attach[family]
                        self.assertIs(self.device_blocked(row, family, mac), expected, (family, mac))
        final = self.f.backend()
        for family in ('iptables', 'ip6tables'):
            for mac in set(old_macs) | set(new_macs):
                self.assertIs(self.device_blocked(final, family, mac), mac in new_macs, (family, mac))
        self.adults_reachable(final)
        self.assert_only_active_generation()
        return effects

    def test_added_child_is_guarded_before_switch_and_drained(self):
        effects = self.child_set_transition([KID], [KID, OTHER_KID])
        drained = [row['argv'] for row in effects if row['command'] == 'conntrack']
        self.assertIn(['-D', '-s', '192.168.1.22', '-f', 'ipv4'], drained)
        self.assertIn(['-D', '-d', '192.168.1.22', '-f', 'ipv4'], drained)

    def test_removed_child_stays_blocked_until_switch_completes(self):
        self.child_set_transition([KID, OTHER_KID], [KID])

    def test_router_sort_order_enrolled_transition_and_uninstall(self):
        # Live BusyBox 1.33 ordering (SET before SETDEF) must not read as object drift.
        self.f.router_sort()
        self.install()
        self.success(self.cfctl('sync', document=self.paused_policy()))
        self.assertTrue(self.f.backend()['sets'][self.f.active_set('k')])
        self.success(self.cfctl('sync', document=self.changed_policy()))
        self.assert_only_active_generation()
        self.success(self.cfctl('apply-fw'))
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_owned_kernel_objects()

    def test_router_order_stored_snapshot_is_accepted(self):
        # Routers keep snapshots written in the old order: each SETDEF after its SET rows.
        self.install()
        self.success(self.cfctl('sync', document=self.paused_policy()))
        snapshot = self.f.root / 'etc/couvrefeu/runtime/firewall.snapshot'
        lines = snapshot.read_text().splitlines()
        sets = [line for line in lines if line.split(' ')[0] in ('SET', 'SETDEF')]
        old = sorted(sets, key=lambda line: (line.split(' ')[1], line.split(' ')[0] == 'SETDEF', line))
        self.assertNotEqual(old, sets)
        rest = [line for line in lines if line not in sets]
        rules = [line for line in rest if not line.startswith('SCHEDULE ')]
        snapshot.write_text('\n'.join(rules + old + [line for line in rest if line not in rules]) + '\n')
        snapshot.chmod(0o600)
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_owned_kernel_objects()

    def test_status_after_refused_command_never_rewrites_shadow_intent(self):
        # A refused command reports status; status must not repair or re-plan the intent.
        self.install()
        self.success(self.cfctl('sync', document=policy()))
        active = self.f.slot()
        self.f.update_backend(failures=[{'command': 'ip6tables', 'contains': ['-R', 'cf_fwd'], 'remaining': 1}])
        doc = policy(2)
        doc['doh'] = {'ipv4': ['1.1.1.2'], 'ipv6': []}
        self.assertNotEqual(self.cfctl('sync', document=doc).returncode, 0)
        intent = self.f.root / 'etc/couvrefeu/runtime/firewall.intent'
        recorded = intent.read_bytes()
        self.assertIn(b'\nSLOT ' + ('b' if active == 'a' else 'a').encode() + b'\n', recorded)
        self.assertEqual(self.f.slot(), active)
        state = self.f.backend()
        for row in state['neighbors']:
            if row['ip'] == '192.168.1.20':
                row['ip'] = '192.168.1.30'
        self.f.update_backend(neighbors=state['neighbors'], failures=[])
        mutations = len(self.f.mutation_calls())
        result = self.cfctl('sync', document=policy(3))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(intent.read_bytes(), recorded)
        self.assertEqual(len(self.f.mutation_calls()), mutations)
        self.success(self.cfctl('apply-fw'))
        self.assertFalse(intent.exists())
        self.assert_only_active_generation()

    def test_swapped_child_mac_keeps_union_blocked_through_switch(self):
        self.child_set_transition([KID], [OTHER_KID])

    def cfctl(self, *args, **options):
        # Effect capture copies every modeled table per command; allow loaded CI lanes.
        options.setdefault('timeout', 300)
        return self.f.run(*args, **options)

    def changed_policy(self, revision=2):
        doc = self.paused_policy(revision)
        doc['doh'] = {'ipv4': [f'1.1.1.{revision}'], 'ipv6': []}
        doc['schedules'] = self.SCHEDULE
        return doc

    def owned_objects(self, state=None):
        state = self.f.backend() if state is None else state
        chains = {(family, table, chain): rules for family, tables in state['tables'].items()
                  for table, rows in tables.items() for chain, rules in rows.items()
                  if chain.startswith(('cf_', 'cf2_'))}
        sets = {name: value for name, value in state['sets'].items() if name.startswith(('cf_', 'cf2_'))}
        return chains, sets

    def generation(self, slot, state=None):
        chains, sets = self.owned_objects(state)
        return ({key: rules for key, rules in chains.items() if key[2].startswith(f'cf2_{slot}_')},
                {name: value for name, value in sets.items() if name.startswith(f'cf2_{slot}_')})

    def dispatch_targets(self, state=None):
        state = self.f.backend() if state is None else state
        targets = {}
        for family, table, chain in (('iptables', 'filter', 'cf_fwd'), ('ip6tables', 'filter', 'cf_fwd'),
                                     ('iptables', 'filter', 'cf_input'), ('ip6tables', 'filter', 'cf_input'),
                                     ('iptables', 'nat', 'cf_dns')):
            targets[(family, chain)] = [row[row.index('-j') + 1] for row in state['tables'][family][table][chain]]
        return targets

    def generation_targets(self, state):
        return {key: rows[-1] for key, rows in self.dispatch_targets(state).items()}

    def assert_only_active_generation(self, fixture=None):
        fixture = self.f if fixture is None else fixture
        state, slot = fixture.backend(), fixture.slot()
        other = 'b' if slot == 'a' else 'a'
        self.assertEqual(self.generation(other, state), ({}, {}), 'inactive generation leaked')
        guards = [key for key in self.owned_objects(state)[0] if key[2] == f'cf2_{slot}_g']
        self.assertEqual(guards, [], 'temporary guard leaked')
        self.assertEqual(f'cf2_{slot}_u' in state['sets'], False, 'temporary union set leaked')
        targets = self.dispatch_targets(state)
        self.assertTrue(all(target == f'cf2_{slot}_{key[1][3]}' for key, rows in targets.items() for target in rows), targets)

    def test_schedule_and_resolver_change_blocks_child_in_every_observed_state(self):
        self.success(self.cfctl('sync', document=self.paused_policy()))
        self.f.update_backend(capture_effects=True, effects=[])
        _, new = self.slots(self.f)
        self.success(self.cfctl('sync', document=self.changed_policy()))
        effects = self.f.backend()['effects']
        self.assertTrue(any(row['command'] == 'fw3' and 'reload' in row['argv'] for row in effects))
        self.assert_switches_guarded(effects, new)
        for index, row in enumerate(effects):
            with self.subTest(index=index, command=row['command'], argv=row['argv']):
                self.verify_reachability(row)
        self.assert_only_active_generation()

    def test_drift_repair_blocks_child_in_every_observed_state(self):
        doc = self.paused_policy()
        doc['doh']['ipv4'] = ['1.1.1.1']
        self.success(self.cfctl('sync', document=doc))
        state = self.f.backend()
        state['sets'][self.f.active_set('d4')]['members'] = []
        self.f.update_backend(sets=state['sets'], capture_effects=True, effects=[])
        old_slot, new = self.slots(self.f)
        self.success(self.cfctl('apply-fw'))
        self.assertEqual(self.f.slot(), new, 'drift must be repaired into a new generation')
        effects = self.f.backend()['effects']
        self.assert_switches_guarded(effects, new)
        for index, row in enumerate(effects):
            with self.subTest(index=index, command=row['command'], argv=row['argv']):
                self.verify_reachability(row)
        self.assert_only_active_generation()

    # Four representative pre-switch boundaries: shadow set membership, shadow
    # chain construction, second-family guard attachment and native reload.
    # {new} is the shadow slot. Switch/unguard failures are covered separately.
    STAGING_FAILURES = (
        ('ipset', ['add', 'cf2_{new}_p']), ('ip6tables', ['-A', 'cf2_{new}_f']),
        ('ip6tables', ['-I', 'cf_fwd', 'cf2_{new}_g']), ('fw3', ['reload']),
    )

    def staging_failure_case(self, command, contains):
        fixture = RouterFixture()
        try:
            self.success(fixture.run('sync', document=self.paused_policy(), timeout=300))
            before = fixture.backend()
            active, new = self.slots(fixture)
            contains = [part.format(new=new) for part in contains]
            old = self.generation(active, before)
            confirmation = (fixture.root / 'etc/couvrefeu/runtime/confirmed').read_bytes()
            fixture.update_backend(capture_effects=True, effects=[],
                                   failures=[{'command': command, 'contains': contains, 'remaining': 1}])
            result = fixture.run('sync', document=self.changed_policy(), timeout=300)
            state = fixture.backend()
            outcome = dict(returncode=result.returncode, ok=json.loads(result.stdout)['ok'],
                           injected=state['failures'][0]['remaining'] == 0,
                           switched=any('-R' in row['argv'] and 'cf_acct' not in row['argv'] for row in state['effects']),
                           dispatch=self.generation_targets(state) == self.generation_targets(before),
                           guard_only=all(target in (rows[-1], f'cf2_{new}_g') for rows in self.dispatch_targets(state).values()
                                          for target in rows),
                           old_intact=self.generation(active, state) == old,
                           confirmation=(fixture.root / 'etc/couvrefeu/runtime/confirmed').read_bytes() == confirmation,
                           blocked=[self.reachable(row) for row in state['effects']] + [self.reachable(state)])
            fixture.update_backend(failures=[], capture_effects=False)
            retry = fixture.run('sync', document=self.changed_policy(), timeout=300)
            outcome['retry'] = retry.returncode == 0 and json.loads(retry.stdout)['ok']
            outcome['after'] = self.reachable(fixture.backend())
            try:
                self.assert_only_active_generation(fixture)
                outcome['clean'] = True
            except AssertionError as error:
                outcome['clean'] = str(error)
            return outcome
        finally:
            fixture.close()

    def reachable(self, state):
        try:
            self.verify_reachability(state)
            return True
        except AssertionError as error:
            return str(error)

    def test_failure_at_each_staging_step_keeps_old_generation_dispatched(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(int(os.environ.get('CF_TEST_STAGING_WORKERS', '4'))) as pool:
            outcomes = list(pool.map(lambda case: self.staging_failure_case(*case), self.STAGING_FAILURES))
        for (command, contains), outcome in zip(self.STAGING_FAILURES, outcomes):
            with self.subTest(command=command, contains=contains):
                self.assertTrue(outcome['injected'], outcome)
                self.assertNotEqual(outcome['returncode'], 0, outcome)
                self.assertFalse(outcome['ok'], outcome)
                self.assertFalse(outcome['switched'], outcome)
                self.assertTrue(outcome['dispatch'], outcome)
                self.assertTrue(outcome['guard_only'], outcome)
                self.assertTrue(outcome['old_intact'], outcome)
                self.assertTrue(outcome['confirmation'], outcome)
                self.assertTrue(all(value is True for value in outcome['blocked']), outcome)
                self.assertTrue(outcome['retry'], outcome)
                self.assertTrue(outcome['after'], outcome)
                self.assertIs(outcome['clean'], True, outcome)

    def test_first_dispatcher_switch_failure_keeps_old_generation_dispatched(self):
        self.success(self.cfctl('sync', document=self.paused_policy()))
        _, new = self.slots(self.f)
        old_dispatch = self.dispatch_targets()
        self.f.update_backend(failures=[{'command': 'iptables', 'contains': ['-R', 'cf_fwd'], 'remaining': 1}])
        result = self.cfctl('sync', document=self.changed_policy())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)['ok'])
        state = self.f.backend()
        for key, targets in self.dispatch_targets(state).items():
            with self.subTest(dispatcher=key):
                self.assertEqual(targets[-1], old_dispatch[key][-1])
                if key[1] == 'cf_fwd':
                    self.assertEqual(targets[0], f'cf2_{new}_g', 'guard must stay attached while unswitched')
        self.verify_reachability(state)
        self.success(self.cfctl('apply-fw'))
        self.verify_reachability(self.f.backend())
        self.assert_only_active_generation()

    def test_crashed_staging_leftover_generation_is_removed_on_next_run(self):
        self.success(self.cfctl('sync', document=self.paused_policy()))
        before = self.f.backend()
        active, new = self.slots(self.f)
        old = self.generation(active, before)
        self.stop_at(f'after_6_cf2_{new}_f_A', ['cfctl', 'sync'], json.dumps(self.changed_policy()))
        crashed = self.f.backend()
        chains, sets = self.generation(new, crashed)
        self.assertTrue(chains and sets, 'crash must leave a partial shadow generation')
        self.assertEqual(self.generation(active, crashed), old)
        self.assertEqual(self.dispatch_targets(crashed), self.dispatch_targets(before))
        self.verify_reachability(crashed)
        self.assertFalse(json.loads(self.cfctl('status', '--json').stdout)['ok'])
        self.success(self.cfctl('apply-fw'))
        self.assertEqual(self.f.slot(), active)
        self.assertEqual(self.generation(active), old)
        self.assert_only_active_generation()
        self.verify_reachability(self.f.backend())
        self.success(self.cfctl('sync', document=self.changed_policy()))
        self.assert_only_active_generation()

    def assert_no_owned_kernel_objects(self):
        state = self.f.backend()
        self.assertEqual(self.owned_objects(state), ({}, {}))
        for family in state['tables'].values():
            for table in family.values():
                for rules in table.values():
                    self.assertFalse(any(token.startswith(('cf_', 'cf2_')) for rule in rules for token in rule))
        self.assertFalse(any(key.startswith('firewall.cf_sched_') for key in state['uci']))

    def test_uninstall_removes_failed_shadow_generation(self):
        self.install()
        self.success(self.cfctl('sync', document=self.paused_policy()))
        shadow = 'b' if self.f.slot() == 'a' else 'a'
        self.f.update_backend(failures=[{'command': 'iptables', 'contains': ['-A', f'cf2_{shadow}_d'], 'remaining': 1}])
        self.assertNotEqual(self.cfctl('sync', document=self.changed_policy()).returncode, 0)
        # A failed staging build rolls back its own unreferenced shadow slot.
        self.assertEqual(self.generation(shadow), ({}, {}))
        self.assertFalse((self.f.root / 'etc/couvrefeu/runtime/firewall.intent').exists())
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_owned_kernel_objects()

    # The second ip6tables mangle read of a changing sync is the final staging
    # inventory check (cf_reference_guard_v2), after the whole shadow is built.
    AFTER_BUILD = {'command': 'ip6tables', 'contains': ['-t', 'mangle', '-S'], 'skip': 1, 'remaining': 1}

    def kernel_view(self):
        # The fake backend lazily adds empty builtin chains on read; they are not rules.
        state = self.f.backend()
        rules = {(family, table, chain): rows for family, tables in state['tables'].items()
                 for table, chains in tables.items() for chain, rows in chains.items() if rows}
        return rules, state['sets']

    def fail_after_shadow_build(self, rollback_failures=()):
        """Fail a changing sync after its complete shadow build; returns (result, active, shadow)."""
        self.install()
        self.success(self.cfctl('sync', document=self.paused_policy()))
        active, shadow = self.slots(self.f)
        failures = [dict(self.AFTER_BUILD)] + [dict(row, contains=[part.format(shadow=shadow) for part in row['contains']])
                                               for row in rollback_failures]
        self.f.update_backend(capture_effects=True, effects=[], failures=failures)
        result = self.cfctl('sync', document=self.changed_policy())
        state = self.f.backend()
        self.assertEqual(state['failures'][0]['remaining'], 0, state['failures'])
        self.assertTrue(any(row['command'] == 'ip6tables' and '-A' in row['argv'] and f'cf2_{shadow}_g' in row['argv']
                            for row in state['effects']), 'failure must follow the complete shadow build')
        self.f.update_backend(failures=[], capture_effects=False, effects=[])
        self.assertNotEqual(result.returncode, 0)
        return result, active, shadow

    def test_failure_after_complete_shadow_build_rolls_back_slot_and_intent(self):
        result, active, shadow = self.fail_after_shadow_build()
        status = json.loads(result.stdout)
        self.assertFalse(status['ok'])
        self.assertEqual((status['desiredRevision'], status['confirmedRevision']), (1, 1))
        self.assertEqual(self.generation(shadow), ({}, {}))
        self.assertFalse((self.f.root / 'etc/couvrefeu/runtime/firewall.intent').exists())
        self.assertEqual(self.f.slot(), active)
        self.assert_only_active_generation()
        self.verify_reachability(self.f.backend())
        status = json.loads(self.cfctl('status', '--json').stdout)
        self.assertEqual((status['desiredRevision'], status['confirmedRevision'], status['drift']), (1, 1, False), status)
        self.success(self.cfctl('sync', document=self.changed_policy()))
        self.assert_only_active_generation()

    def staged_drifted_intent(self, rollback_failures):
        _, active, shadow = self.fail_after_shadow_build(rollback_failures)
        runtime = self.f.root / 'etc/couvrefeu/runtime'
        self.assertTrue((runtime / 'firewall.intent').exists(), 'failed rollback keeps the staging intent')
        self.assertTrue(all(self.generation(shadow)), 'failed rollback keeps the shadow slot')
        # Emulate the live failure: the staged slot no longer matches its recorded
        # inventory, so the transition inventory check refuses it.
        state = self.f.backend()
        state['sets'][f'cf2_{shadow}_u']['members'].append('02:00:00:00:00:99')
        self.f.update_backend(sets=state['sets'])
        mutations = len(self.f.mutation_calls())
        self.assertNotEqual(self.cfctl('apply-fw').returncode, 0, 'drifted staging must fail the inventory check')
        self.assertEqual(len(self.f.mutation_calls()), mutations)
        return active, shadow

    ROLLBACK_FAILS = ({'command': 'iptables', 'contains': ['-F', 'cf2_{shadow}_f'], 'remaining': 1},)

    def test_uninstall_from_drifted_staging_intent_restores_exactly(self):
        pristine = self.kernel_view()
        self.staged_drifted_intent(self.ROLLBACK_FAILS)
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_owned_kernel_objects()
        # uninstall.sh itself proves exact file restoration; every pristine rule
        # returns exactly, and only the modeled fw3 reload adds its base chains.
        rules, sets = self.kernel_view()
        self.assertEqual(({key: rows for key, rows in rules.items() if key in pristine[0]}, sets), pristine)
        self.assertTrue(all(key[2] == 'reject' or key[2].startswith('zone_') for key in rules if key not in pristine[0]), rules)
        self.assertFalse((self.f.root / 'usr/sbin/cfctl').exists())

    def assert_journal_or_clean(self, shadow):
        intent = (self.f.root / 'etc/couvrefeu/runtime/firewall.intent').exists()
        self.assertTrue(intent or self.generation(shadow) == ({}, {}), 'intent removed with shadow objects left')
        return intent

    def test_failed_set_read_never_drops_journal_and_uninstall_recovers(self):
        _, _, shadow = self.fail_after_shadow_build(
            ({'command': 'ipset', 'contains': ['save', 'cf2_{shadow}_k'], 'skip': 1, 'remaining': 1},))
        self.assert_journal_or_clean(shadow)
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_owned_kernel_objects()

    def test_rollback_failing_after_partial_deletes_keeps_journal_and_uninstall_recovers(self):
        result, _, shadow = self.fail_after_shadow_build(
            ({'command': 'ipset', 'contains': ['destroy', 'cf2_{shadow}_p'], 'remaining': 1},))
        self.assertIn('couvre-feu: staging_rollback refused: set_delete', result.stderr)
        chains, sets = self.generation(shadow)
        self.assertEqual(chains, {}, 'chain deletes precede the failed set delete')
        self.assertTrue(sets)
        self.assertTrue(self.assert_journal_or_clean(shadow), 'failed rollback keeps the staging intent')
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_owned_kernel_objects()

    def test_uninstall_refuses_referenced_staging_slot_without_mutation(self):
        _, shadow = self.staged_drifted_intent(self.ROLLBACK_FAILS)
        state = self.f.backend()
        state['tables']['iptables']['filter']['foreign'] = [['-j', f'cf2_{shadow}_g']]
        self.f.update_backend(tables=state['tables'])
        before, mutations = self.kernel_view(), len(self.f.mutation_calls())
        refused = self.uninstall()
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('remove-fw exit', refused.stderr)
        self.assertIn('couvre-feu: staging_rollback refused: referenced_target (after transition_object_drift)', refused.stderr)
        self.assertEqual(self.kernel_view(), before)
        self.assertEqual(len(self.f.mutation_calls()), mutations)
        self.assertTrue((self.f.root / 'etc/couvrefeu/runtime/firewall.intent').exists())

    def test_uninstall_after_crashed_staging_refuses_until_stale_lock_recovery(self):
        self.install()
        self.success(self.cfctl('sync', document=self.paused_policy()))
        shadow = 'b' if self.f.slot() == 'a' else 'a'
        self.stop_at(f'after_4_cf2_{shadow}_d_A', ['cfctl', 'sync'], json.dumps(self.changed_policy()))
        self.assertTrue(all(self.generation(shadow)), 'crash must leave a partial shadow generation')
        before, mutations = self.f.backend(), len(self.f.mutation_calls())
        refused = self.uninstall()
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual((self.f.backend()['tables'], self.f.backend()['sets']), (before['tables'], before['sets']))
        self.assertEqual(len(self.f.mutation_calls()), mutations)
        self.success(self.cfctl('apply-fw'))
        self.assert_only_active_generation()
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_owned_kernel_objects()

if __name__ == '__main__':
    print('Evidence: immutable-generation and packet-reachability fixture models only.')
    unittest.main(verbosity=2)
