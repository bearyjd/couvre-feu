#!/usr/bin/env python3
"""PERMANENT install tool fixtures: a fake ssh runs the payload against a private root.

No network or host-router command runs: ssh/ssh-add are local doubles and router
tools are the deterministic backends from tests/fixtures. Passing these fixtures
proves neither target BusyBox behavior nor a real install.
"""
import contextlib
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / 'tests/fixtures'))
from harness import RouterFixture  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Reuse the rehearsal fixtures (fresh-router model, fake agent, snapshots).
TLR = load('test_live_rehearsal', REPO / 'tests/test-live-rehearsal.py')
MGMT, JD, PENN, HISTORICAL, HOST = TLR.MGMT, TLR.JD, TLR.PENN, TLR.HISTORICAL, TLR.HOST
CT107 = {'ip': '192.0.2.50', 'mac': '02:00:00:00:00:50'}
PHONE_MAC = '02:00:00:00:00:34'
PROTECT = [MGMT['mac'], JD['mac'], CT107['mac'], HISTORICAL[0]]
RPC_ALLOW = [PENN['mac'], PHONE_MAC]
SOURCE = None
SOURCE_ROOT = None


def setUpModule():
    global SOURCE, SOURCE_ROOT
    SOURCE_ROOT = TLR.SourceCopy()
    SOURCE = load('permanent_install', SOURCE_ROOT.root / 'tools/live/permanent-install.py')


def tearDownModule():
    SOURCE_ROOT.tmp.cleanup()


class PermanentBase(unittest.TestCase):
    model_fresh_router = TLR.LiveRehearsalTests.model_fresh_router
    model_tmp_namespace_owner = TLR.LiveRehearsalTests.model_tmp_namespace_owner
    truncating_cp = TLR.LiveRehearsalTests.truncating_cp
    fake_tools = TLR.LiveRehearsalTests.fake_tools
    write_agent = TLR.LiveRehearsalTests.write_agent
    provision_mutex = TLR.LiveRehearsalTests.provision_mutex
    mutex_metadata = TLR.LiveRehearsalTests.mutex_metadata
    assert_mutex_continuity = TLR.LiveRehearsalTests.assert_mutex_continuity
    router_snapshot = TLR.LiveRehearsalTests.router_snapshot
    installer_ran = TLR.LiveRehearsalTests.installer_ran
    tamper_installed_file = TLR.LiveRehearsalTests.tamper_installed_file
    cleanup_staging = TLR.LiveRehearsalTests.cleanup_staging
    tool_env = TLR.LiveRehearsalTests.tool_env
    invoke = TLR.LiveRehearsalTests.invoke
    plan_details = TLR.LiveRehearsalTests.plan_details
    plan_sha = TLR.LiveRehearsalTests.plan_sha
    evidence = TLR.LiveRehearsalTests.evidence

    def setUp(self):
        self.tool = SOURCE
        self.fixture = RouterFixture()
        self.root = self.fixture.root
        self.addCleanup(self.fixture.close)
        self.work = Path(tempfile.mkdtemp(prefix='couvre-feu-perm-work-'))
        self.addCleanup(shutil.rmtree, self.work, True)
        persistent = Path.home() / '.cache'
        persistent.mkdir(parents=True, exist_ok=True)
        self.evidence_root = Path(tempfile.mkdtemp(prefix='couvre-feu-perm-evidence-', dir=persistent))
        self.addCleanup(shutil.rmtree, self.evidence_root, True)
        (self.evidence_root / 'evidence').mkdir(mode=0o700)
        self.model_fresh_router()
        self.provision_mutex()
        self.fake_tools()
        self.cp_log = self.work / 'cp-p.log'
        self.truncating_cp('s')
        self.now = datetime.datetime(2026, 10, 12, 18, 0, 0, tzinfo=datetime.timezone.utc)
        self.config = {
            'schemaVersion': 3, 'host': HOST,
            'adminPublicKeyPath': str(self.work / 'admin.pub'), 'adminKeyFingerprint': self.fingerprint,
            'knownHostsPath': str(self.work / 'known_hosts'), 'evidenceDir': str(self.evidence_root / 'evidence'),
            'authorizationPath': str(self.work / 'authorization.txt'),
            'deadlineUtc': '2026-10-12T19:00:00Z', 'platformProfile': 'strict', 'remoteTimeoutSeconds': 600,
            'roles': {'management': MGMT, 'jd_adult': JD, 'ct107': CT107},
            'protectedHistoricalMacs': HISTORICAL, 'protect': PROTECT, 'rpcAllow': RPC_ALLOW, 'activate': True}
        (self.work / 'known_hosts').write_text(HOST + ' ssh-ed25519 AAAAfixture\n')
        (self.work / 'authorization.txt').write_text('fixture authorization only\n')

    def write_config(self, **changes):
        path = self.work / 'config.json'
        path.write_text(json.dumps(dict(self.config, **changes)))
        return str(path)

    def execute(self, cleanup=True, **changes):
        config = self.write_config(**changes)
        result = self.invoke('execute', config, '--expect-plan-sha256', self.plan_sha(config))
        if cleanup:
            self.cleanup_staging()
        return result

    def stdout(self):
        return (self.evidence() / 'stdout.log').read_text()


class ConfigTests(PermanentBase):
    def refused(self, **changes):
        code, _, err = self.invoke('plan', self.write_config(**changes))
        self.assertEqual(code, 1, err)
        self.assertIn('REFUSED', err)
        self.assertFalse(self.ssh_log.exists())
        return err

    def test_example_config_is_valid_and_fictional(self):
        example = json.loads((REPO / 'tools/live/config.permanent.example.json').read_text())
        config = self.tool.validate_config(example)
        macs = [role['mac'] for role in config['roles'].values()] + config['protectedHistoricalMacs'] + config['rpcAllow']
        self.assertTrue(all(mac.startswith('02:00:00:00:00:') for mac in macs))
        self.assertTrue(config['host'].startswith('192.0.2.'))
        self.assertEqual(example['schemaVersion'], 3)

    def test_negative_values_are_refused(self):
        upper = PROTECT + ['02:00:00:00:00:7A']
        bad = [{'schemaVersion': 1}, {'schemaVersion': True}, {'extra': 1}, {'host': '192.0.2.01'},
               {'evidenceDir': 'relative/path'}, {'platformProfile': 'unknown'}, {'deadlineUtc': '2026-10-12 19:00'},
               {'remoteTimeoutSeconds': 599}, {'activate': 'yes'}, {'activate': 1},
               {'roles': {'management': MGMT, 'jd_adult': JD}},
               {'roles': {'management': MGMT, 'jd_adult': JD, 'ct107': CT107, 'penn_child': PENN}},
               {'roles': {'management': MGMT, 'jd_adult': JD, 'ct107': dict(CT107, mac=MGMT['mac'])}},
               {'roles': {'management': MGMT, 'jd_adult': JD, 'ct107': dict(CT107, ip=HOST)}},
               {'protectedHistoricalMacs': [JD['mac']]}, {'protectedHistoricalMacs': []},
               {'protect': upper}, {'protect': PROTECT + [PROTECT[0]]}, {'protect': PROTECT[1:]},
               {'protect': PROTECT[:3]}, {'protect': [CT107['mac'], JD['mac'], HISTORICAL[0]]},
               {'protect': PROTECT[:2] + ['03:00:00:00:00:50', HISTORICAL[0]]},
               {'rpcAllow': []}, {'rpcAllow': [PENN['mac'], PENN['mac']]},
               {'rpcAllow': [PENN['mac'], '03:00:00:00:00:34']}, {'rpcAllow': ['00:00:00:00:00:00']},
               {'rpcAllow': [PENN['mac'], PROTECT[2]]}, {'rpcAllow': [PENN['mac'], HISTORICAL[0]]},
               {'rpcAllow': ['02:00:00:01:%02x:%02x' % divmod(i, 256) for i in range(1, 258)]},
               {'rpcAllow': PENN['mac']}]
        for change in bad:
            with self.subTest(change=str(change)[:80]):
                self.refused(**change)

    def test_rpc_allow_bound_is_exactly_256(self):
        macs = ['02:00:00:01:%02x:%02x' % divmod(i, 256) for i in range(1, 257)]
        document = dict(self.config, rpcAllow=macs, platformProfile='strict')
        self.assertEqual(len(self.tool.validate_config(document)['rpcAllow']), 256)

    def test_missing_and_duplicate_keys_are_refused(self):
        for key in sorted(self.tool.REQUIRED_KEYS):
            with self.subTest(missing=key):
                document = {k: v for k, v in self.config.items() if k != key}
                path = self.work / 'missing.json'
                path.write_text(json.dumps(document))
                code, _, err = self.invoke('plan', str(path))
                self.assertEqual(code, 1, err)
                self.assertIn('missing', err)
        path = self.work / 'dup.json'
        path.write_text(json.dumps(self.config)[:-1] + ', "activate": false}')
        code, _, err = self.invoke('plan', str(path))
        self.assertEqual(code, 1, err)
        self.assertIn('duplicate key', err)

    def test_rehearsal_and_pilot_configs_are_not_accepted_and_vice_versa(self):
        rehearsal = json.loads((REPO / 'tools/live/config.example.json').read_text())
        with self.assertRaises(self.tool.Refusal):
            self.tool.validate_config(rehearsal)
        with self.assertRaises(self.tool.FR.Refusal):
            self.tool.FR.validate_config(json.loads((REPO / 'tools/live/config.permanent.example.json').read_text()))

    def test_exact_management_jd_pair_is_allowed_but_partial_match_is_not(self):
        same = {'management': MGMT, 'jd_adult': dict(MGMT), 'ct107': CT107}
        self.assertEqual(self.tool.validate_config(dict(self.config, roles=same, platformProfile='strict'))['roles'], same)
        self.refused(roles={'management': MGMT, 'jd_adult': dict(JD, ip=MGMT['ip']), 'ct107': CT107})


class PlanTests(PermanentBase):
    def test_plan_is_local_and_discloses_the_exact_installer_argv(self):
        details = self.plan_details(self.write_config())
        expected = ['router/install.sh', '--platform-profile', 'strict']
        for mac in PROTECT:
            expected += ['--protect', mac]
        for mac in RPC_ALLOW:
            expected += ['--rpc-allow', mac]
        self.assertEqual(details['installArgv'], expected + ['--activate'])
        self.assertEqual(details['phases'], list(self.tool.PHASES))
        self.assertIs(details['uninstallInHappyPath'], False)
        self.assertEqual(details['tool'], 'tools/live/permanent-install.py')
        self.assertFalse(self.ssh_log.exists())
        self.assertEqual(self.plan_details(self.write_config(activate=False))['phases'], list(self.tool.VALIDATE_PHASES))
        self.assertNotIn('--activate', self.plan_details(self.write_config(activate=False))['installArgv'])

    def test_plan_sha_changes_with_each_bound_input(self):
        base = self.plan_sha(self.write_config())
        self.assertEqual(base, self.plan_sha(self.write_config()))
        extra = '02:00:00:00:00:77'
        changes = [{'activate': False}, {'rpcAllow': RPC_ALLOW[:1]}, {'rpcAllow': RPC_ALLOW[::-1]},
                   {'rpcAllow': RPC_ALLOW + [extra]}, {'protect': PROTECT + [extra]},
                   {'protect': PROTECT[::-1]}, {'deadlineUtc': '2026-10-12T19:00:01Z'},
                   {'platformProfile': 'gl-xe3000-4.8.3-logd-011-v1'}, {'remoteTimeoutSeconds': 601},
                   {'host': '192.0.2.2'}, {'protectedHistoricalMacs': HISTORICAL + [extra]},
                   {'roles': {'management': MGMT, 'jd_adult': JD, 'ct107': dict(CT107, ip='192.0.2.51')}}]
        seen = {base}
        for change in changes:
            with self.subTest(change=str(change)[:60]):
                config = dict(self.config, **change)
                if 'protectedHistoricalMacs' in change:
                    config['protect'] = PROTECT + [extra]
                path = self.work / 'config-change.json'
                path.write_text(json.dumps(config))
                sha = self.plan_sha(str(path))
                self.assertNotIn(sha, seen)
                seen.add(sha)

    def test_plan_sha_binds_known_hosts_key_and_authorization_path_not_contents(self):
        base = self.plan_sha(self.write_config())
        (self.work / 'authorization.txt').write_text('written after plan\n')
        self.assertEqual(self.plan_sha(self.write_config()), base)
        (self.work / 'known_hosts').write_text(HOST + ' ssh-ed25519 AAAAother\n')
        self.assertNotEqual(self.plan_sha(self.write_config()), base)
        other, fingerprint = TLR.public_key()
        (self.work / 'admin.pub').write_text(other)
        self.assertNotEqual(self.plan_sha(self.write_config(adminKeyFingerprint=fingerprint)), base)

    def test_plan_sha_mismatch_refused_without_connection(self):
        code, _, err = self.invoke('execute', self.write_config(), '--expect-plan-sha256', 'a' * 64)
        self.assertEqual(code, 1)
        self.assertIn('differs from the disclosed value', err)
        self.assertFalse(self.ssh_log.exists())

    def test_deadline_includes_local_timeout_and_margin(self):
        config = self.write_config(deadlineUtc='2026-10-12T18:10:00Z')
        code, _, err = self.invoke('execute', config, '--expect-plan-sha256', self.plan_sha(config))
        self.assertEqual(code, 1)
        self.assertIn('deadline', err)
        self.assertFalse(self.ssh_log.exists())

    def test_cli_requires_isolated_mode_and_plan_is_local(self):
        config = self.write_config()
        plain = subprocess.run([sys.executable, str(SOURCE_ROOT.root / 'tools/live/permanent-install.py'), 'plan', config],
                               env=self.tool_env(), capture_output=True, text=True)
        self.assertEqual(plain.returncode, 1)
        self.assertIn('python3 -I', plain.stderr)
        isolated = subprocess.run([sys.executable, '-I', str(SOURCE_ROOT.root / 'tools/live/permanent-install.py'), 'plan', config],
                                  env=self.tool_env(), capture_output=True, text=True)
        self.assertEqual(isolated.returncode, 0, isolated.stderr)
        self.assertIn('--expect-plan-sha256 ' + self.plan_sha(config), isolated.stdout)
        self.assertFalse(self.ssh_log.exists())

    def test_dirty_source_refused(self):
        stray = SOURCE_ROOT.root / 'tools/live/stray.txt'
        stray.write_text('x\n')
        try:
            code, _, err = self.invoke('plan', self.write_config())
        finally:
            stray.unlink()
        self.assertEqual(code, 1)
        self.assertIn('differs from HEAD', err)


class PayloadTests(PermanentBase):
    def payload(self, **changes):
        config = self.tool.validate_config(json.loads(Path(self.write_config(**changes)).read_text()))
        commit, blobs = self.tool.FR.head_source()
        return self.tool.build_payload(config, commit, blobs)[0].decode(), blobs

    def test_payload_embeds_the_committed_emitted_router_tree(self):
        text, blobs = self.payload()
        tree = self.tool.FR.emitted_tree(blobs)
        for rel, (mode, data) in tree.items():
            digest = __import__('hashlib').sha256(data).hexdigest()
            self.assertIn(f'{digest} {mode} router/{rel}\n', text, rel)
        count = len(tree)
        self.assertIn(f'CFR_PAYLOAD_COUNT={count}\n', text)
        self.assertEqual(text.count('CFR_SOURCE_COMMIT='), 1)

    def test_payload_parameters_and_tail(self):
        text, _ = self.payload()
        flags = ' '.join(self.tool.installer_flags(self.tool.validate_config(json.loads(Path(self.write_config()).read_text()))))
        self.assertIn(f"CFPI_INSTALL_ARGS='{flags}'\n", text)
        self.assertNotIn('--activate', flags)
        self.assertIn("CFPI_ACTIVATE='1'\n", text)
        self.assertIn("CFPI_PROTECT='" + ' '.join(PROTECT) + "'\n", text)
        self.assertIn("CFPI_RPC_ALLOW='" + ' '.join(RPC_ALLOW) + "'\n", text)
        self.assertTrue(text.endswith('pi_main </dev/null\n# Unreachable unless pi_main returns; fail closed.\n'
                                      '# shellcheck disable=SC2317\nexit 20\n'))
        self.assertEqual(text.count('cfr_main </dev/null'), 0)
        self.assertIn("CFPI_ACTIVATE='0'\n", self.payload(activate=False)[0])

    def test_generated_payload_static_checks(self):
        text, _ = self.payload()
        path = self.work / 'payload.sh'
        path.write_text(text)
        checks = [['sh', '-n', str(path)], ['sh', '-n', str(REPO / 'tools/live/permanent-install.sh')]]
        if shutil.which('busybox'):
            checks.append(['busybox', 'ash', '-n', str(path)])
        for check in checks:
            result = subprocess.run(check, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, ' '.join(check) + result.stdout + result.stderr)

    def test_template_has_no_uninstall_run_and_never_touches_authentication(self):
        script = (REPO / 'tools/live/permanent-install.sh').read_text()
        code = re.sub(r'(?m)^\s*#.*$', '', script).replace('password login is the recovery path', '')
        self.assertIsNone(re.search(r'authorized_keys|dropbear|passwd|shadow|password|PasswordAuth|sshd|uci +(set|commit)|dnsmasq', code, re.I))
        self.assertNotIn('rm -rf', script)
        self.assertNotRegex(code, r'cfr_run_sh\s+"?\$cfr_uninstall|uninstall\.sh"?\s*>>')
        # ROLLBACK_COMMAND is only ever printed, and install runs once (no loop or retry around it).
        self.assertEqual(code.count('cfr_install --activate'), 1)
        self.assertNotRegex(code, r'(?s)(while|until|for)[^\n]*\n[^\n]*cfr_install')
        tool = (REPO / 'tools/live/permanent-install.py').read_text()
        self.assertIsNone(re.search(r'authorized_keys|dropbear|passwd|shadow|PasswordAuth', tool, re.I))
        self.assertNotIn('rm -rf', tool)

    def test_tools_live_scanners_cover_the_new_files(self):
        listed = {p.name for p in (REPO / 'tools/live').glob('*.sh')}
        self.assertIn('permanent-install.sh', listed)
        text = (REPO / 'tests/run.sh').read_text()
        self.assertIn('test-permanent-install.py', text)
        self.assertIn('test-permanent-install.py', (REPO / '.github/workflows/ci.yml').read_text())


class RemoteRunTests(PermanentBase):
    def setUp(self):
        super().setUp()
        self.model_tmp_namespace_owner()

    def release_dir(self):
        return self.root / ('etc/.couvrefeu-release-' + self.tool.FR.release_id(self.tool.FR.head_source()[1]))

    def test_happy_path_installs_once_and_keeps_everything(self):
        code, out, err = self.execute()
        run = self.evidence()
        self.assertEqual(code, 0, out + err + (run / 'stderr.log').read_text())
        stdout = self.stdout().splitlines()
        self.assertEqual(stdout[-1], 'PERMANENT_INSTALL_PASS')
        for phase in self.tool.PHASES:
            self.assertIn(f'PHASE {phase} OK', stdout)
        self.assertIn('MUTATION_BEGIN', stdout)
        flags = ' '.join(self.tool.installer_flags(self.tool.validate_config(json.loads(Path(self.write_config()).read_text()))))
        runs = [line for line in stdout if line.startswith('INFO run install.sh ')]
        self.assertEqual(runs, [f'INFO run install.sh {flags}', f'INFO run install.sh {flags} --activate'])
        self.assertFalse(any('uninstall' in line and line.startswith('INFO run') for line in stdout))
        self.assertFalse(any(line.startswith('PHASE UNINSTALL') or line.startswith('PHASE RESTORE') for line in stdout))
        # Kept: release dir with its uninstall.sh, journal, installed cfctl, and the planned scope.
        self.assertTrue((self.release_dir() / 'uninstall.sh').is_file())
        self.assertTrue((self.root / 'etc/couvrefeu/backup/complete').is_file())
        self.assertTrue((self.root / 'usr/sbin/cfctl').is_file())
        self.assertEqual((self.root / 'etc/couvrefeu/rpc-allowed').read_text().split(), sorted(RPC_ALLOW))
        protected = (self.root / 'etc/couvrefeu/protected').read_text().split()
        self.assertTrue(set(PROTECT) <= set(protected))
        # Generation comes from the installer journal and matches what RPC status reports.
        journal = (self.root / 'etc/couvrefeu/backup/etc_couvrefeu_state.staged').read_text()
        generation = re.search(r'^G\t([0-9a-f]{64})$', journal, re.M).group(1)
        self.assertIn(f'PERMANENT_GENERATION {generation}', stdout)
        summary = json.loads((run / 'summary.json').read_text())
        self.assertEqual((summary['outcome'], summary['exitCode'], summary['remoteExit'], summary['generation']),
                         ('PASS', 0, 0, generation))
        self.assertEqual(len([json.loads(line) for line in self.ssh_log.read_text().splitlines()]), 1)
        self.assertIn('PASS:', out)
        staging = next(line.split(' ', 2)[2] for line in stdout if line.startswith('INFO staging '))
        self.assertFalse(Path(staging).exists())

    def test_activate_false_validates_only_and_changes_nothing(self):
        before = self.router_snapshot()
        code, out, err = self.execute(activate=False)
        self.assertEqual(code, 0, out + err)
        stdout = self.stdout()
        self.assertTrue(stdout.rstrip().endswith('PERMANENT_INSTALL_VALIDATED_NO_MUTATION'))
        self.assertNotIn('MUTATION_BEGIN', stdout)
        self.assertNotIn('--activate', stdout)
        self.assertEqual(self.router_snapshot(), before)
        self.assertEqual(json.loads((self.evidence() / 'summary.json').read_text())['outcome'], 'VALIDATED')

    def test_identity_refusals_happen_before_any_installer_run(self):
        self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'),
                                               {'ip': JD['ip'], 'mac': '02:00:00:00:00:99', 'state': 'REACHABLE'}])
        before = self.router_snapshot()
        code, out, err = self.execute()
        self.assertEqual(code, 1, out + err)
        stdout = self.stdout()
        self.assertIn('PHASE IDENTITY FAIL jd_adult_neighbor_mismatch', stdout)
        self.assertIn('REFUSED_BEFORE_MUTATION IDENTITY', stdout)
        self.assertNotIn('MUTATION_BEGIN', stdout)
        self.assertFalse(self.installer_ran())
        self.assertEqual(self.router_snapshot(), before)

    def test_ssh_source_other_than_management_refused(self):
        self.spec['ssh_connection'] = f'{JD["ip"]} 50000 {HOST} 22'
        code, out, err = self.execute()
        self.assertEqual(code, 1, out + err)
        self.assertIn('PHASE IDENTITY FAIL ssh_source_not_management', self.stdout())
        self.assertFalse(self.installer_ran())

    def test_remote_gate_refuses_incomplete_protect_and_protected_scope(self):
        config = self.tool.validate_config(json.loads(Path(self.write_config()).read_text()))
        commit, blobs = self.tool.FR.head_source()
        for label, change, reason in (('ct107 not protected', {'protect': [m for m in PROTECT if m != CT107['mac']]},
                                       'protect_list_incomplete'),
                                      ('scope MAC protected', {'rpcAllow': [PENN['mac'], CT107['mac']]},
                                       'rpc_allow_mac_protected')):
            with self.subTest(label):
                payload = self.tool.build_payload(dict(config, **change), commit, blobs)[0]
                self.tool_env()
                result = subprocess.run([str(self.bin / 'ssh'), 'fixture'], input=payload, capture_output=True,
                                        env={'FAKE_SSH_SPEC': str(self.spec_path), 'PATH': os.environ['PATH']})
                self.assertEqual(result.returncode, 10, result.stderr.decode())
                self.assertIn(f'PHASE IDENTITY FAIL {reason}'.encode(), result.stdout)
                self.assertFalse(self.installer_ran())
                self.cleanup_staging_from(result.stdout)

    def cleanup_staging_from(self, stdout):
        for line in stdout.decode().splitlines():
            if line.startswith('INFO staging /tmp/couvre-feu-first.'):
                shutil.rmtree(line.split(' ', 2)[2], ignore_errors=True)

    def assert_stopped(self, code, out, err, phase):
        self.assertEqual(code, 2, out + err)
        stdout = self.stdout()
        self.assertIn('MUTATION_BEGIN', stdout)
        self.assertIn(f'STOPPED_AFTER_MUTATION {phase}', stdout)
        self.assertNotIn('PERMANENT_INSTALL_PASS', stdout)
        self.assertNotIn('INFO run uninstall.sh', stdout)
        self.assertNotIn('PHASE UNINSTALL', stdout)
        self.assertTrue(any(line.startswith('ROLLBACK_') for line in stdout.splitlines()))
        summary = json.loads((self.evidence() / 'summary.json').read_text())
        self.assertEqual((summary['outcome'], summary['exitCode'], summary['remoteExit']), ('STOPPED_AFTER_MUTATION', 2, 20))
        self.assertTrue(summary['rollback'])
        self.assertIn('STOPPED_AFTER_MUTATION', out)
        self.assertTrue((self.root / 'etc/couvrefeu/backup/ready').is_file(), 'journal must be retained')
        return stdout

    def test_installer_failure_stops_after_mutation_with_rollback_and_no_retry(self):
        self.spec['env']['CF_TEST_INSTALL_FAIL_AFTER'] = '3'
        code, out, err = self.execute()
        stdout = self.assert_stopped(code, out, err, 'INSTALL')
        self.assertEqual(len([line for line in stdout.splitlines() if line.endswith('--activate') and line.startswith('INFO run install.sh')]), 1)
        self.assertIn('install not retried', stdout)
        self.assertIn(f'DIFF - D {self.root}/etc/couvrefeu/backup absent', stdout)
        rollback = [line for line in stdout.splitlines() if line.startswith('ROLLBACK_COMMAND ')]
        self.assertTrue(rollback or 'ROLLBACK_UNAVAILABLE' in stdout)

    def test_tampered_installed_tree_stops_with_the_retained_uninstall_as_rollback(self):
        rid = self.tool.FR.release_id(self.tool.FR.head_source()[1])
        self.tamper_installed_file('usr/lib/couvrefeu/rpc.sh')
        code, out, err = self.execute()
        self.assertTrue((self.work / 'tampered').exists(), 'tamper hook never fired')
        stdout = self.assert_stopped(code, out, err, 'VERIFY')
        self.assertIn('installed_tree_mismatch usr/lib/couvrefeu/rpc.sh', stdout)
        self.assertIn(f'ROLLBACK_COMMAND /bin/sh /etc/.couvrefeu-release-{rid}/uninstall.sh', stdout)
        self.assertNotIn('PERMANENT_GENERATION', stdout)
        self.assertTrue((self.release_dir() / 'uninstall.sh').is_file())

    def test_unhealthy_status_stops_after_mutation(self):
        # The healthy status is replaced by an enrolled one just before VERIFY reads it.
        hook = self.fixture.bin / 'sha256sum'
        done = self.work / 'status-sabotaged'
        hook.write_text('#!/bin/sh\n'
                        'if [ "$#" = 0 ] && [ -f "$CF_ROOT/etc/couvrefeu/state" ] && [ ! -e ' + str(done) + ' ]; then\n'
                        '  target=$(readlink /proc/$$/fd/0 2>/dev/null)\n'
                        '  case "$target" in *"/usr/sbin/cfctl-ssh") : > ' + str(done) + '; printf "P\\tpenn\\t-\\n" >> "$CF_ROOT/etc/couvrefeu/state";; esac\n'
                        'fi\n'
                        f'exec {shutil.which("sha256sum")} "$@"\n')
        hook.chmod(0o700)
        code, out, err = self.execute()
        if not done.exists():
            self.skipTest('state sabotage hook did not fire in this shell')
        self.assertEqual(code, 2, out + err)
        stdout = self.stdout()
        self.assertIn('STOPPED_AFTER_MUTATION VERIFY', stdout)
        self.assertNotIn('PERMANENT_INSTALL_PASS', stdout)

    def test_connectivity_loss_after_install_stops_after_mutation(self):
        ip = self.fixture.bin / 'ip'
        self.assertTrue(ip.exists())
        counter = self.work / 'ip-calls'
        shutil.move(str(ip), str(self.fixture.bin / 'ip.real'))
        ip.write_text('#!/bin/sh\n'
                      'if [ "$1 $2 $3 $4 $5" = "-4 neigh show dev br-lan" ]; then\n'
                      f'  n=$(cat {counter} 2>/dev/null || echo 0); echo $((n + 1)) > {counter}\n'
                      '  if [ "$n" -ge 1 ]; then echo "192.0.2.10 lladdr 02:00:00:00:00:10 REACHABLE"; exit 0; fi\n'
                      'fi\n'
                      f'exec {self.fixture.bin / "ip.real"} "$@"\n')
        ip.chmod(0o700)
        code, out, err = self.execute()
        stdout = self.stdout()
        self.assertEqual(code, 2, out + err)
        self.assertIn('PHASE CONNECTIVITY FAIL jd_adult_neighbor_lost', stdout)
        self.assertIn('STOPPED_AFTER_MUTATION CONNECTIVITY', stdout)
        self.assertIn('ROLLBACK_COMMAND ', stdout)

    def test_ssh_drop_mid_run_is_unknown(self):
        self.spec['drop_after'] = 'PHASE INSTALL OK'
        code, out, err = self.execute()
        self.assertEqual(code, 2, out + err)
        summary = json.loads((self.evidence() / 'summary.json').read_text())
        self.assertEqual((summary['outcome'], summary['remoteExit']), ('UNKNOWN', 255))
        self.assertIn('UNKNOWN:', out)


class ClassifyTests(unittest.TestCase):
    healthy = ('INFO status {"ok":true,"drift":false,"errors":[],"desiredRevision":0,"confirmedRevision":0,"desiredPauses":[],'
               '"effectivePauses":[],"desiredAllowances":[],"effectiveAllowances":[],"observed":{"kids":[],"paused":[]},'
               '"capabilities":{}}')

    def lines(self, *extra, drop=(), end='PERMANENT_INSTALL_PASS'):
        base = [f'PHASE {p} OK' for p in SOURCE.PHASES[:4]] + ['MUTATION_BEGIN', 'PHASE INSTALL OK', self.healthy,
                                                              'PERMANENT_GENERATION ' + 'a' * 64, 'PHASE VERIFY OK',
                                                              'PHASE CONNECTIVITY OK']
        lines = [line for line in base if line not in drop] + list(extra)
        return '\n'.join(lines + ([end] if end else [])) + '\n'

    def test_pass_requires_everything(self):
        self.assertEqual(SOURCE.classify(self.lines(), 0, False)[:2], ('PASS', 0))
        for label, text, code, timed in (
                ('timeout', self.lines(), 0, True), ('exit 20', self.lines(), 20, False),
                ('no end line', self.lines(end=None), 0, False), ('verify missing', self.lines(drop=('PHASE VERIFY OK',)), 0, False),
                ('no generation', self.lines(drop=('PERMANENT_GENERATION ' + 'a' * 64,)), 0, False),
                ('two ends', self.lines('PERMANENT_INSTALL_PASS'), 0, False),
                ('bad status', self.lines().replace('"ok":true', '"ok":false'), 0, False),
                ('no mutation marker', self.lines(drop=('MUTATION_BEGIN',)), 0, False)):
            with self.subTest(label):
                self.assertNotEqual(SOURCE.classify(text, code, timed)[0], 'PASS')

    def test_stopped_refused_and_unknown(self):
        stopped = self.lines('PHASE VERIFY FAIL x', 'ROLLBACK_COMMAND /bin/sh /etc/.couvrefeu-release-x/uninstall.sh',
                             'STOPPED_AFTER_MUTATION VERIFY', end=None)
        self.assertEqual(SOURCE.classify(stopped, 20, False)[:2], ('STOPPED_AFTER_MUTATION', 2))
        self.assertEqual(SOURCE.classify(stopped, 255, False)[0], 'UNKNOWN')
        self.assertEqual(SOURCE.classify(stopped, 20, True)[0], 'UNKNOWN')
        refused = 'PHASE IDENTITY FAIL x\nREFUSED_BEFORE_MUTATION IDENTITY\n'
        self.assertEqual(SOURCE.classify(refused, 10, False)[:2], ('REFUSED', 1))
        self.assertEqual(SOURCE.classify('MUTATION_BEGIN\n' + refused, 10, False)[0], 'UNKNOWN')
        self.assertEqual(SOURCE.classify('', 0, False)[0], 'UNKNOWN')

    def test_validated_only_without_mutation(self):
        text = ''.join(f'PHASE {p} OK\n' for p in SOURCE.VALIDATE_PHASES) + 'PERMANENT_INSTALL_VALIDATED_NO_MUTATION\n'
        self.assertEqual(SOURCE.classify(text, 0, False, SOURCE.VALIDATE_PHASES)[:2], ('VALIDATED', 0))
        self.assertEqual(SOURCE.classify('MUTATION_BEGIN\n' + text, 0, False, SOURCE.VALIDATE_PHASES)[0], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
