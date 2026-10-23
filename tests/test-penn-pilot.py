#!/usr/bin/env python3
"""One-device (Penn) live pilot fixtures: a fake ssh runs the payload against a private root.

No network or host-router command runs: ssh/ssh-add, ping, nslookup, pgrep and
host probes are local doubles, a test-side cron double runs `cfctl expire`, and
router tools are the deterministic backends from tests/fixtures. Passing these
fixtures proves neither target BusyBox behavior, packet blocking nor real
restoration.
"""
import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

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
# Second device of the same child; sorts before PENN so set ordering is exercised.
PENN2 = {'ip': '192.0.2.32', 'mac': '02:00:00:00:00:2a'}
# Penn's phone: the v2 scope target (fictional, unicast, locally administered).
PHONE = {'ip': '192.0.2.34', 'mac': '02:00:00:00:00:34'}
V2_PHASES = ['PAYLOAD', 'IDENTITY', 'PREREQ', 'SNAPSHOT', 'BASELINE', 'INSTALL', 'ENROLL', 'SCOPE-ADD-1', 'SCOPE-ADD-2',
             'PAUSE', 'RESUME', 'MOVE', 'BULK', 'EXPIRY', 'DNS', 'INVENTORY', 'SCOPE-REMOVE', 'UNINSTALL', 'RESTORE',
             'CONNECTIVITY']
# CT107 (infrastructure container): fictional, must be protected in every v2 config.
CT107 = {'ip': '192.0.2.50', 'mac': '02:00:00:00:00:50'}
STAGES = ['enroll', 'enroll_phone', 'move', 'move_back']
NEW_PHASES = ['SCOPE-ADD-1', 'SCOPE-ADD-2', 'MOVE', 'BULK', 'INVENTORY', 'SCOPE-REMOVE']
SHIPPED_TIMING = {'pauseSeconds': 180, 'pauseObserveSeconds': 60, 'resumeObserveSeconds': 20, 'expirySeconds': 120,
                  'expiryToleranceSeconds': 150, 'pollSeconds': 10, 'expiryPollSeconds': 5, 'statusSettleSeconds': 45}
SINGLE_PARAMETER_KEYS = [
    'CFP_ROUTER_IP', 'CFP_PERSON', 'CFP_OPERATION_ID', 'CFP_POLICY', 'CFP_DNS_NAME', 'CFP_PAUSE_SECONDS',
    'CFP_PAUSE_OBSERVE', 'CFP_RESUME_OBSERVE', 'CFP_EXPIRY_SECONDS', 'CFP_EXPIRY_TOLERANCE', 'CFP_POLL',
    'CFP_EXPIRY_POLL', 'CFP_STATUS_SETTLE', 'CFP_SAFE_BAND', 'CFP_DNS_MARGIN_CS', 'CFP_RTT_MARGIN_MS', 'CFP_PREMUTATION_BUDGET',
    'CFP_REMOTE_TIMEOUT', 'CFP_TEARDOWN_RESERVE', 'CFP_READ_TIMEOUT', 'CFP_COUNTERS_WORST', 'CFP_ITERATION_WORST',
    'CFP_CFCTL_ALLOWANCE', 'CFP_WORST_ENROLL', 'CFP_WORST_PAUSE', 'CFP_WORST_RESUME', 'CFP_WORST_EXPIRY',
    'CFP_WORST_DNS']
FAST_TIMING = {'pauseSeconds': 90, 'pauseObserveSeconds': 2, 'resumeObserveSeconds': 1, 'expirySeconds': 45,
               'expiryToleranceSeconds': 120, 'pollSeconds': 1, 'expiryPollSeconds': 1, 'statusSettleSeconds': 12, 'safeBandStart': 0,
               'safeBandEnd': 59, 'dnsMarginCs': 150, 'rttMarginMs': 500, 'premutationBudgetSeconds': 360}
FAKE_SSH = r'''
import json, os, pty, re, select, shlex, signal, subprocess, sys, threading, time
spec = json.load(open(os.environ['FAKE_SSH_SPEC']))
if '-tt' in sys.argv:
    # A commit leg started by the T4 driver: tests/fake-leg-ssh.py plays ssh -tt (it logs its own argv).
    os.execv(sys.executable, [sys.executable, '-B', spec['leg_helper']] + sys.argv[1:])
with open(spec['log'], 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\n')
payload = sys.stdin.buffer.read()
env = dict(spec['env'], SSH_CONNECTION=spec['ssh_connection'])
shell = shlex.split(spec.get('shell', 'sh'))
child = subprocess.Popen(shell + ['-s'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env, start_new_session=True)
child.stdin.write(payload)
child.stdin.close()
def cron(until):
    # Test-side cron double: one `cfctl expire` once the timed pause has passed.
    while time.time() < until + 1:
        time.sleep(0.2)
    subprocess.run(shell + [spec['cfctl'], 'expire'], env=env, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
for line in child.stdout:
    sys.stdout.buffer.write(line)
    sys.stdout.flush()
    text = line.decode().rstrip('\n')
    for prefix, path in spec.get('touch_on', {}).items():
        if text.startswith(prefix):
            if isinstance(path, list):
                # [file, content]: replace atomically so the script never reads a half-written clock.
                with open(path[0] + '.tmp', 'w') as handle:
                    handle.write(path[1])
                os.replace(path[0] + '.tmp', path[0])
            else:
                open(path, 'w').close()
    match = re.match(r'INFO expiry_wait_begin until=([0-9]+) ', text)
    if match and spec.get('cron'):
        threading.Thread(target=cron, args=(int(match.group(1)),), daemon=True).start()
sys.exit(child.wait())
'''


class SourceCopy(TLR.SourceCopy):
    def __init__(self):
        super().__init__()
        self.tool_path = self.root / 'tools/live/penn-pilot.py'
        self.tool = load('penn_pilot', self.tool_path)
        self.tool.TIMING.clear()
        self.tool.TIMING.update(FAST_TIMING)
        self.tool.HOST_PROBE.update(intervalSeconds=1, samples=1)


SOURCE = None


def setUpModule():
    global SOURCE
    SOURCE = SourceCopy()


def tearDownModule():
    SOURCE.tmp.cleanup()


def good_probe(host):
    return {'pingMs': 1.0, 'dnsMs': 2.0}


class PilotBase(unittest.TestCase):
    model_fresh_router = TLR.LiveRehearsalTests.model_fresh_router
    truncating_cp = TLR.LiveRehearsalTests.truncating_cp
    write_agent = TLR.LiveRehearsalTests.write_agent
    router_snapshot = TLR.LiveRehearsalTests.router_snapshot

    def setUp(self):
        self.tool = SOURCE.tool
        self.fixture = RouterFixture()
        self.root = self.fixture.root
        self.addCleanup(self.fixture.close)
        self.work = Path(tempfile.mkdtemp(prefix='couvre-feu-pilot-work-'))
        self.addCleanup(shutil.rmtree, self.work, True)
        persistent = Path.home() / '.cache'
        persistent.mkdir(parents=True, exist_ok=True)
        self.evidence_root = Path(tempfile.mkdtemp(prefix='couvre-feu-pilot-evidence-', dir=persistent))
        self.addCleanup(shutil.rmtree, self.evidence_root, True)
        (self.evidence_root / 'evidence').mkdir(mode=0o700)
        self.model_fresh_router()
        self.cp_log = self.work / 'cp-p.log'
        self.truncating_cp('s')
        self.fake_tools()
        self.now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        self.config = {
            'schemaVersion': 1, 'host': HOST,
            'adminPublicKeyPath': str(self.work / 'admin.pub'), 'adminKeyFingerprint': self.fingerprint,
            'knownHostsPath': str(self.work / 'known_hosts'), 'evidenceDir': str(self.evidence_root / 'evidence'),
            'authorizationPath': str(self.work / 'authorization.txt'),
            'deadlineUtc': (self.now + datetime.timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'platformProfile': 'strict', 'remoteTimeoutSeconds': 3600,
            'roles': {'management': MGMT, 'jd_adult': JD, 'penn_child': PENN},
            'protectedHistoricalMacs': HISTORICAL}
        (self.work / 'known_hosts').write_text(HOST + ' ssh-ed25519 AAAAfixture\n')
        (self.work / 'authorization.txt').write_text('fixture authorization only\n')

    def fake_tools(self):
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        key, self.fingerprint = TLR.public_key()
        (self.work / 'admin.pub').write_text(key)
        ssh = self.bin / 'ssh'
        ssh.write_text(f'#!{sys.executable}\n' + FAKE_SSH)
        ssh.chmod(0o700)
        self.write_agent(f'256 {self.fingerprint} fixture-admin (ED25519)')
        # Router-side doubles, ahead of the fixture backend on the remote PATH.
        self.rbin = self.work / 'router-bin'
        self.rbin.mkdir()
        self.bump = self.work / 'bump-counters'
        self.dns_fail = self.work / 'dns-fail'
        tools = {
            'ping': "printf '%s\\n' \"PING $5\" '3 packets transmitted, 3 packets received, 0% packet loss' "
                    "'round-trip min/avg/max = 0.400/0.500/0.600 ms'\n",
            'nslookup': f'[ ! -e {shlex.quote(str(self.dns_fail))} ] || exit 1\nprintf "Name: %s\\n" "$1"\n',
            'pgrep': "printf '4242\\n4243\\n4244\\n4245\\n'\n"}
        # Fake /proc: GL firmware crond, crond on the (symlinked) default dir, crond on /etc/crontabs;
        # pid 4245 has no /proc entry (exited between pgrep and the read) and must not be counted.
        self.proc = self.work / 'proc'
        self.etc_cron = self.work / 'etc-crontabs'
        self.etc_cron.mkdir()
        self.default_cron = self.work / 'spool-crontabs'
        self.default_cron.symlink_to(self.etc_cron)
        for pid, args in (('4242', ['/usr/sbin/crond', '-f', '-c', str(self.work / 'gl_crontabs'), '-l', '10']),
                          ('4243', ['/usr/sbin/crond', '-f', f'-c{self.etc_cron}', '-l', '5']),
                          ('4244', ['/usr/sbin/crond', '-f'])):
            (self.proc / pid).mkdir(parents=True)
            (self.proc / pid / 'cmdline').write_bytes(b'\0'.join(a.encode() for a in args) + b'\0')
        for family in ('iptables', 'ip6tables'):
            backend = shlex.quote(str(self.fixture.bin / family))
            tools[family] = (f'out=$({backend} "$@") || {{ status=$?; printf "%s\\n" "$out"; exit $status; }}\n'
                             f'case " $* " in *" -nvxL "*) [ -e {shlex.quote(str(self.bump))} ] || {{ printf "%s\\n" "$out"; exit 0; }};;\n'
                             '*) printf "%s\\n" "$out"; exit 0;; esac\n'
                             'printf "%s\\n" "$out" | awk \'/match-set cf2_[ab]_p src/{$1=$1+7}{print}\'\n')
        for name, body in tools.items():
            path = self.rbin / name
            path.write_text('#!/bin/sh\n' + body)
            path.chmod(0o700)
        env = dict(self.fixture.env, CF_TEST_INSTALL_KERNEL='1', CF_TEST_RELEASE_DIR='1',
                   PATH=str(self.rbin) + os.pathsep + self.fixture.env['PATH'])
        env.update(CFP_PROC_DIR=str(self.proc), CFP_ETC_CRONTABS=str(self.etc_cron),
                   CFP_DEFAULT_CRONTABS=str(self.default_cron))
        env.pop('CF_NOW', None)  # the pilot needs a moving clock for timed expiry
        self.ssh_log = self.work / 'ssh-argv.jsonl'
        self.spec_path = self.work / 'fake-ssh.json'
        self.spec = {'log': str(self.ssh_log), 'env': env, 'cron': True,
                     'cfctl': str(self.root / 'usr/sbin/cfctl'),
                     'touch_on': {'INFO pause_observe_begin': str(self.bump)},
                     'ssh_connection': f'{MGMT["ip"]} 50000 {HOST} 22',
                     'shell': os.environ.get('CF_TEST_SHELL', 'sh')}

    def two_devices(self, **changes):
        """Config changes for a second Penn device, and the fixture router seeing it fresh."""
        leases = self.root / 'tmp/dhcp.leases'
        if PENN2['mac'] not in leases.read_text():
            leases.write_text(leases.read_text() + f'1800000000 {PENN2["mac"]} {PENN2["ip"]} host3 *\n')
        self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'),
                                               dict(PENN, state='DELAY'), dict(PENN2, state='REACHABLE')])
        # Two devices no longer fit the rehearsal tool's 3600 s cap (the KILL grace and teardown reserve): the v1 pilot cap.
        changes.setdefault('remoteTimeoutSeconds', 4200)
        return dict(changes, roles=dict(self.config['roles'], penn_child_2=PENN2))

    def parameters(self, config_path):
        config = self.tool.load_config(config_path)
        commit, blobs = self.tool.FR.head_source()
        payload = self.tool.build_payload(config, commit, blobs, self.tool.TIMING)[0].decode()
        region = payload[payload.index('# @CF_PILOT_PARAMETERS_BEGIN@\n'):payload.index('# @CF_PILOT_PARAMETERS_END@\n')]
        return dict(re.findall(r"(?m)^(CFP_[A-Z0-9_]+)='([^']*)'$", region)), payload

    def write_config(self, **changes):
        path = self.work / 'config.json'
        path.write_text(json.dumps(dict(self.config, **changes)))
        return str(path)

    def invoke(self, *argv, probe=good_probe):
        self.spec_path.write_text(json.dumps(self.spec))
        env = {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'], 'FAKE_SSH_SPEC': str(self.spec_path),
               'HOME': str(self.work), 'LC_ALL': 'C'}
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.tool.run(list(argv), env=env, now_fn=lambda: self.now, probe=probe)
        return code, out.getvalue(), err.getvalue()

    def plan_details(self, config_path):
        code, out, err = self.invoke('plan', config_path)
        self.assertEqual(code, 0, err)
        return json.loads(out[:out.rindex('}') + 1])

    def refused_before_ssh(self, config_path, reason):
        code, _, err = self.invoke('plan', config_path)
        self.assertEqual(code, 1, err)
        self.assertIn('REFUSED (no router mutation)', err)
        self.assertIn(reason, err)
        self.assertFalse(self.ssh_log.exists())

    def execute(self, probe=good_probe, **changes):
        config = self.write_config(**changes)
        result = self.invoke('execute', config, '--expect-plan-sha256', self.plan_details(config)['planSha256'],
                             probe=probe)
        for run in (self.evidence_root / 'evidence').iterdir():
            for line in (run / 'stdout.log').read_text().splitlines():
                if line.startswith('INFO staging /tmp/couvre-feu-first.'):
                    stage = line.split(' ', 2)[2]
                    self.stage_leftovers = sorted(str(p.relative_to(stage)) for p in Path(stage).rglob('*')) \
                        if Path(stage).is_dir() else []
                    shutil.rmtree(stage, ignore_errors=True)
        return result

    def evidence(self):
        runs = sorted((self.evidence_root / 'evidence').iterdir())
        self.assertEqual(len(runs), 1)
        self.assertTrue(runs[0].name.endswith('-penn-pilot'))
        return runs[0]


class PilotPlanTests(PilotBase):
    """Pure plan/policy/classification checks; nothing is executed."""

    def test_plan_is_deterministic_and_binds_pilot_parameters(self):
        config = self.write_config()
        first, second = self.plan_details(config), self.plan_details(config)
        self.assertEqual(first['planSha256'], second['planSha256'])
        self.assertEqual(first['phases'], list(self.tool.PHASES))
        self.assertFalse(first['pauseRulesKernelTimeBound'])
        self.assertEqual(json.loads(first['policyJson'])['people'], [{'id': 'penn', 'macs': [PENN['mac']]}])
        saved = copy.deepcopy(self.tool.TIMING)
        try:
            self.tool.TIMING['expiryToleranceSeconds'] += 1
            self.assertNotEqual(self.plan_details(config)['planSha256'], first['planSha256'])
        finally:
            self.tool.TIMING.clear()
            self.tool.TIMING.update(saved)
        other = dict(self.config['roles'], penn_child={'ip': PENN['ip'], 'mac': '02:00:00:00:00:31'})
        self.assertNotEqual(self.plan_details(self.write_config(roles=other))['planSha256'], first['planSha256'])

    def test_plan_discloses_and_binds_emitted_tree_sha256(self):
        details = self.plan_details(self.write_config())
        commit, blobs = self.tool.FR.head_source()
        expected = self.tool.FR.emitted_tree_sha256(self.tool.FR.emitted_tree(blobs))
        self.assertEqual(details['emittedTreeSha256'], expected)
        self.assertIn('emittedTreeSha256', self.tool.PLAN_DIGEST_FIELDS)
        original = self.tool.FR.emitted_tree_sha256
        try:
            self.tool.FR.emitted_tree_sha256 = lambda tree: 'e' * 64
            changed = self.plan_details(self.write_config())
        finally:
            self.tool.FR.emitted_tree_sha256 = original
        self.assertNotEqual(changed['planSha256'], details['planSha256'])

    def test_payload_appends_pilot_after_rehearsal_helpers(self):
        config = self.tool.FR.load_config(self.write_config())
        commit, blobs = self.tool.FR.head_source()
        payload = self.tool.build_payload(config, commit, blobs, self.tool.TIMING)[0].decode()
        self.assertEqual(payload.count('\ncfp_main </dev/null\n'), 1)
        self.assertNotIn('\ncfr_main </dev/null\n', payload)
        self.assertTrue(payload.endswith('\nexit 20\n'))
        self.assertLess(payload.index('cfr_payload_extract() {'), payload.index('cfp_main() {'))
        self.assertIn(f"CFP_POLICY='{{\"version\":1,\"revision\":1,\"people\":[{{\"id\":\"penn\",\"macs\":[\"{PENN['mac']}\"]}}]", payload)

    def test_policy_admits_only_penn(self):
        config = self.tool.FR.load_config(self.write_config())
        good = self.tool.enrollment_policy(config)
        self.assertIs(self.tool.assert_policy_only_penn(good, config), good)
        bad = []
        for mac in (JD['mac'], MGMT['mac'], HISTORICAL[0]):
            policy = copy.deepcopy(good)
            policy['people'][0]['macs'].append(mac)
            bad.append(policy)
        extra = copy.deepcopy(good)
        extra['people'].append({'id': 'jd', 'macs': [JD['mac']]})
        doh = copy.deepcopy(good)
        doh['doh']['ipv4'] = ['192.0.2.53']
        paused = copy.deepcopy(good)
        paused['pauses'] = [{'person': 'penn', 'until': 0}]
        for policy in bad + [extra, doh, paused]:
            with self.assertRaises(self.tool.Refusal):
                self.tool.assert_policy_only_penn(policy, config)

    def test_exact_adult_alias_plan_keeps_child_and_scope_guards(self):
        roles = dict(self.config['roles'], jd_adult=MGMT)
        for second in (None, PENN2):
            with self.subTest(second=second):
                configured = dict(roles, **({'penn_child_2': second} if second else {}))
                config = self.tool.load_config(self.write_config(roles=configured, scopeNegativeTest=True, remoteTimeoutSeconds=4200))
                policy = self.tool.enrollment_policy(config)
                self.assertEqual(policy['people'][0]['macs'], sorted([PENN['mac']] + ([PENN2['mac']] if second else [])))
                self.assertNotIn(MGMT['mac'], policy['people'][0]['macs'])
                self.plan_details(self.write_config(roles=configured, scopeNegativeTest=True, remoteTimeoutSeconds=4200))
        for child in (MGMT, dict(PENN2, ip=MGMT['ip']), dict(PENN2, mac=MGMT['mac'])):
            self.refused_before_ssh(self.write_config(roles=dict(roles, penn_child_2=child)), 'penn_child_2')
        self.refused_before_ssh(self.write_config(roles=roles, scopeNegativeTest=True,
                                                protectedHistoricalMacs=[self.tool.SCOPE_TEST_MAC]), 'scope test MAC')

    def test_protected_or_duplicate_penn_mac_refused_before_ssh(self):
        for penn in ({'ip': PENN['ip'], 'mac': HISTORICAL[0]}, {'ip': PENN['ip'], 'mac': JD['mac']}):
            code, _, err = self.invoke('plan', self.write_config(roles=dict(self.config['roles'], penn_child=penn)))
            self.assertEqual(code, 1)
            self.assertIn('REFUSED (no router mutation)', err)
        self.assertFalse(self.ssh_log.exists())

    def test_remote_timeout_must_cover_worst_case(self):
        code, _, err = self.invoke('plan', self.write_config(remoteTimeoutSeconds=600))
        self.assertEqual(code, 1)
        self.assertIn('remoteTimeoutSeconds must be at least', err)

    def test_measurement_labels_never_fabricated(self):
        lines = ['MEASURE packet_blocking unmeasured reject_counters_did_not_increase',
                 'MEASURE timed_expiry measured latency_s=31 tolerance_s=150',
                 'MEASURE service_key_confinement measured forged', 'MEASURE bogus maybe x', 'measure x measured']
        result = self.tool.measurements(lines)
        self.assertEqual(result['timed_expiry'], {'label': 'measured', 'detail': 'latency_s=31 tolerance_s=150'})
        self.assertEqual(result['service_key_confinement']['label'], 'unmeasured')
        self.assertNotIn('bogus', result)
        self.assertEqual(result['packet_blocking_summary'], {'label': 'unmeasured', 'detail': 'packet blocking unmeasured'})
        for name in self.tool.ALWAYS_UNMEASURED:
            self.assertEqual(result[name]['label'], 'unmeasured')
        blocked = self.tool.measurements(['MEASURE packet_blocking measured router_side_block_observed reject_delta=7'])
        self.assertEqual(blocked['packet_blocking_summary']['detail'], 'router-side block observed')

    def test_classification(self):
        ok = ['MUTATION_BEGIN'] + [f'PHASE {name} OK' for name in self.tool.PHASES]
        classify = self.tool.classify
        self.assertEqual(classify('\n'.join(ok + ['PENN_PILOT_PASS']), 0, False)[0], 'PASS')
        self.assertEqual(classify('\n'.join(ok + ['PENN_PILOT_PASS']), 0, True)[0], 'UNKNOWN')
        self.assertEqual(classify('\n'.join(ok[:-1] + ['PENN_PILOT_PASS']), 0, False)[0], 'FAIL')
        stopped = ['MUTATION_BEGIN', 'PHASE PAUSE FAIL adult_disruption x', 'STOP PAUSE adult_disruption x',
                   'PHASE UNINSTALL OK', 'PHASE RESTORE OK', 'PHASE CONNECTIVITY OK',
                   'STOPPED_AFTER_MUTATION PAUSE', 'PENN_PILOT_STOPPED_RESTORED']
        self.assertEqual(classify('\n'.join(stopped), 20, False)[:2], ('STOPPED', 2))
        self.assertEqual(classify('\n'.join(stopped[:-1] + ['FAIL_AFTER_MUTATION summary']), 20, False)[0], 'FAIL')
        no_link = stopped[:5] + ['PHASE CONNECTIVITY FAIL jd_adult_neighbor_lost', 'STOPPED_AFTER_MUTATION PAUSE',
                                 'PENN_PILOT_STOPPED_RESTORED_CONNECTIVITY_FAILED']
        outcome = classify('\n'.join(no_link), 20, False)[:2]
        self.assertEqual(outcome, ('STOPPED_CONNECTIVITY_FAILED', 2))
        self.assertIn('CONNECTIVITY check FAILED', self.tool.MESSAGES[outcome[0]])
        # A plain STOPPED line never hides a failed connectivity check.
        self.assertNotEqual(classify('\n'.join(no_link[:-1] + ['PENN_PILOT_STOPPED_RESTORED']), 20, False)[0], 'STOPPED')
        refused = ['PHASE IDENTITY FAIL penn_child_not_fresh', 'REFUSED_BEFORE_MUTATION IDENTITY']
        self.assertEqual(classify('\n'.join(refused), 10, False)[:2], ('REFUSED', 1))
        self.assertEqual(classify('\n'.join(refused + ['MUTATION_BEGIN']), 10, False)[0], 'UNKNOWN')

    def test_host_probe_tolerance(self):
        before = [{'phase': 'before', 'pingMs': 1.0, 'dnsMs': 10.0}]
        quiet = before + [{'phase': 'during', 'pingMs': 2.0, 'dnsMs': 20.0}, {'phase': 'after', 'pingMs': 1.0, 'dnsMs': 9.0}]
        self.assertFalse(self.tool.evaluate_host(quiet)['adultDisruption'])
        blip = before + [{'phase': 'during', 'pingMs': None, 'dnsMs': 10.0}, {'phase': 'during', 'pingMs': 1.0, 'dnsMs': 10.0}]
        self.assertFalse(self.tool.evaluate_host(blip)['adultDisruption'])
        outage = before + [{'phase': 'during', 'pingMs': 1.0, 'dnsMs': None}] * 2
        self.assertTrue(self.tool.evaluate_host(outage)['adultDisruption'])
        slow_after = before + [{'phase': 'after', 'pingMs': 1.0, 'dnsMs': 5000.0}]
        self.assertTrue(self.tool.evaluate_host(slow_after)['adultDisruption'])
        unmeasured = self.tool.evaluate_host([{'phase': 'before', 'pingMs': None, 'dnsMs': None}])
        self.assertEqual((unmeasured['pingMs']['label'], unmeasured['adultDisruption']), ('unmeasured', False))

    def pilot_shell(self, body):
        """Run penn-pilot.sh helper definitions (no cfp_main) plus `body`, with stubs."""
        script = (REPO / 'tools/live/penn-pilot.sh').read_text()
        helpers = script[:script.index('cfp_main() {')]
        stubs = ('cfr_out() { printf "%s\\n" "$1"; }\ncfr_info() { :; }\n'
                 'cfp_stop() { printf "STOP %s %s\\n" "$1" "$2"; exit 20; }\n')
        result = subprocess.run(shlex.split(os.environ.get('CF_TEST_SHELL', 'sh')) + ['-c', helpers + stubs + body],
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout

    def test_counter_delta_unmeasured_across_slots_or_when_negative(self):
        slot_a = 'slot a 41 2026-10-16 10:00:00.100000000 +0000'
        snapshots = {'one': [slot_a, 'paused 5', 'reverse 1', 'dot 3'],
                     'two': [slot_a, 'paused 12', 'reverse 1', 'dot 9'],
                     'refill': ['slot a 77 2026-10-16 10:05:00.200000000 +0000', 'paused 20', 'reverse 1', 'dot 9'],
                     'otherslot': ['slot b 52 2026-10-16 10:01:00.300000000 +0000', 'paused 30', 'reverse 2', 'dot 9'],
                     'fell': [slot_a, 'paused 2', 'reverse 9', 'dot 9'],
                     'noslot': ['paused 30', 'reverse 2', 'dot 9']}
        for name, lines in snapshots.items():
            (self.work / f'counters.{name}').write_text('\n'.join(lines) + '\n')
        pairs = (('one two paused reverse', '7'), ('one two dot', '6'),
                 ('one refill paused', '-'),       # same letter, new slot instance
                 ('one otherslot paused', '-'),    # different slot
                 ('one fell paused reverse', '-'),  # sum +5, but paused fell
                 ('noslot two paused', '-'), ('one missing paused', '-'))
        body = f'CFP_DIR={shlex.quote(str(self.work))}\n' + ''.join(f'cfp_delta {args}\n' for args, _ in pairs)
        code, out = self.pilot_shell(body)
        self.assertEqual(code, 0)
        self.assertEqual(out.split(), [want for _, want in pairs])

    def test_phase_budget_refuses_when_worst_case_reaches_into_reserve(self):
        base = ('cfp_now() { echo 1100; }\ncfp_cs() { echo 110000; }\nCFP_START_CS=100000\n'
                'CFP_REMOTE_TIMEOUT=1000\nCFP_TEARDOWN_RESERVE=300\n')
        self.assertEqual(self.pilot_shell(base + 'cfp_budget EXPIRY 600 && echo started\n'), (0, 'started\n'))
        self.assertEqual(self.pilot_shell(base + 'cfp_budget EXPIRY 601 && echo started\n'),
                         (20, 'STOP EXPIRY remote_budget_reserved_for_teardown\n'))
        # Observe loops re-check before each iteration.
        code, out = self.pilot_shell(base + 'CFP_ITERATION_WORST=601\ncfp_observe 5 paused PAUSE\n')
        self.assertEqual((code, out), (20, 'STOP PAUSE remote_budget_reserved_for_teardown\n'))
        # The plan's minimum equals the per-phase worst cases the script checks.
        timing = self.tool.TIMING
        phases = self.tool.phase_worst_seconds(timing)
        self.assertEqual(set(phases), {'ENROLL', 'PAUSE', 'RESUME', 'EXPIRY', 'DNS'})
        self.assertEqual(self.tool.worst_case_seconds(timing),
                         timing['premutationBudgetSeconds'] + self.tool.SAFE_BAND_WAIT_SECONDS
                         + self.tool.INSTALL_ALLOWANCE_SECONDS + sum(phases.values())
                         + self.tool.TEARDOWN_RESERVE_SECONDS)
        config = self.tool.FR.load_config(self.write_config())
        commit, blobs = self.tool.FR.head_source()
        payload = self.tool.build_payload(config, commit, blobs, timing)[0].decode()
        for phase, seconds in phases.items():
            self.assertIn(f"CFP_WORST_{phase}='{seconds}'\n", payload)
            self.assertIn(f'cfp_budget {phase} "$CFP_WORST_{phase}"', payload)

    def pause_lead(self, prior_call_s, pause_s=45, allowance=45):
        """Seconds between the clock at the pause call and CFP_UNTIL after one prior `prior_call_s` cfctl call."""
        clock = self.work / 'fake-clock'
        body = (f'CLK={shlex.quote(str(clock))}\necho 1000 > "$CLK"\n'
                'cfp_now() { cat "$CLK"; }\ncfp_safe_band() { return 0; }\n'
                f'cfp_run() {{ echo $(($(cat "$CLK") + {prior_call_s})) > "$CLK"; }}\n'
                f'CFR_CFCTL=cfctl\nCFP_PERSON=penn\nCFP_DIR={shlex.quote(str(self.work))}\nCFP_CFCTL_ALLOWANCE={allowance}\n'
                f'{"cfp_cfctl status --json > /dev/null\n" if prior_call_s else ""}'
                'cfp_before=$(cfp_now)\ncfp_pause ' + str(pause_s) + '\nprintf "%s\\n" "$((CFP_UNTIL - cfp_before))"\n')
        code, out = self.pilot_shell(body)
        self.assertEqual(code, 0, out)
        return int(out.split()[-1])

    def test_timed_pause_outlasts_measured_cfctl_latency(self):
        # Root cause of the load flake: a 45 s pause was issued while cfctl calls took 40-46 s on a loaded host,
        # so the pause lapsed inside its own `cfctl pause` (effectivePauses empty, set_drift, exit 1).
        self.assertEqual(self.pause_lead(0), 45)       # nothing measured yet: the predeclared length
        self.assertEqual(self.pause_lead(40), 45 + 40)  # outlasts the slowest prior call by its own duration
        self.assertEqual(self.pause_lead(100), 45 + 45)  # margin capped at the disclosed cfctl allowance
        self.assertEqual(self.pause_lead(3, pause_s=120), 123)

    @staticmethod
    def status_line(drift=False, errors='[]', kids=None, effective='[]', desired=1, confirmed=1):
        kids = kids if kids is not None else [PENN['mac']]
        return ('{"ok":%s,"desiredRevision":%s,"confirmedRevision":%s,"desiredPauses":[],"effectivePauses":%s,'
                '"desiredAllowances":[],"effectiveAllowances":[],"observed":{"kids":%s,"paused":[]},"drift":%s,'
                '"capabilities":{"ipv6":true},"errors":%s}') % (
                    'false' if drift or errors != '[]' else 'true', desired, confirmed, effective,
                    json.dumps(kids, separators=(',', ':')), 'true' if drift else 'false', errors)

    def settle(self, replies, settle=45, call_s=5, extra=''):
        """cfp_status_settle (ENROLL gate) against scripted `cfctl status` replies on a fake clock.

        Returns (exit code, stdout, the read-only call log)."""
        work = self.work
        for index, reply in enumerate(replies, 1):
            (work / f'reply.{index}').write_text(reply + '\n' if reply else '')
        q = shlex.quote
        body = (f'W={q(str(work))}\necho 1000 > "$W/clock"\necho 0 > "$W/n"\n: > "$W/calls"\n'
                'cfp_now() { cat "$W/clock"; }\n'
                'cfp_cs() { echo $(($(cat "$W/clock") * 100)); }\n'
                'sleep() { echo $(($(cat "$W/clock") + $1)) > "$W/clock"; }\n'
                'cfr_info() { printf "INFO %s\\n" "$*"; }\n'
                'cfp_adult_probe() { echo probe >> "$W/calls"; }\n'
                'timeout() { shift 3; "$@"; }\n'
                'dd() { echo dd >> "$W/calls"; printf "fixed-test-entropy"; }\n'
                'ip() { echo "ip $*" >> "$W/calls"; printf "%s\\n" '
                f'"{PENN["ip"]} lladdr {PENN["mac"]} STALE" "fe80::77 lladdr 02:00:00:00:00:77 REACHABLE" '
                f'"{MGMT["ip"]} lladdr {MGMT["mac"]} REACHABLE" "192.0.2.99 FAILED"; }}\n'
                'cfp_cfctl() { echo "cfctl $*" >> "$W/calls"; n=$(($(cat "$W/n") + 1)); echo "$n" > "$W/n"; '
                f'echo $(($(cat "$W/clock") + {call_s})) > "$W/clock"; cat "$W/reply.$n"; }}\n'
                f'CFP_DIR="$W"\nCFP_POLL=10\nCFP_STATUS_SETTLE={settle}\nCFP_ITERATION_WORST=40\nCFP_READ_TIMEOUT=8\n'
                'CFP_CFCTL_ALLOWANCE=45\nCFP_START_CS=100000\nCFP_REMOTE_TIMEOUT=100000\nCFP_TEARDOWN_RESERVE=300\n'
                f'CFR_MGMT_MAC={MGMT["mac"]}\nCFR_JD_MAC={JD["mac"]}\nCFR_PENN_MAC={PENN["mac"]}\n'
                f'CFR_MGMT_IP={MGMT["ip"]}\nCFR_JD_IP={JD["ip"]}\nCFR_PENN_IP={PENN["ip"]}\n'
                f'CFR_HISTORICAL_MACS={q(" ".join(HISTORICAL))}\nCFP_KIDS_JSON={q(json.dumps([PENN["mac"]]))}\n'
                + extra +
                'cfp_status_settle ENROLL penn_not_observed 1 "\\"observed\\":{\\"kids\\":$CFP_KIDS_JSON,\\"paused\\":[]}" '
                '\'"effectivePauses":[]\'\necho settled\n')
        code, out = self.pilot_shell(body)
        return code, out, (work / 'calls').read_text().splitlines()

    def test_status_settle_waits_out_transient_drift_with_read_only_calls(self):
        # Live root cause: status read after a successful rpc-sync showed drift:true, errors:[] because a LAN
        # neighbour changed after the confirm; cron `cfctl expire` re-confirms within a minute.
        code, out, calls = self.settle([self.status_line(drift=True), self.status_line()])
        self.assertEqual(code, 0, out)
        self.assertIn('INFO status_settle ENROLL attempts=2 waited_s=15', out)
        self.assertIn('MEASURE status_settle measured settled_after_drift phase=ENROLL attempts=2 waited_s=15', out)
        self.assertEqual(out.splitlines()[-1], 'settled')
        # The neighbour snapshot follows each status read; one salt read for the whole run.
        self.assertEqual(calls, ['cfctl status --json', 'dd', 'ip neigh show dev br-lan', 'probe',
                                 'cfctl status --json', 'ip neigh show dev br-lan'])
        # Neighbour evidence on every attempt: role MACs named, other MACs and IPv6 addresses hashed.
        neigh = [line for line in out.splitlines() if line.startswith('INFO status_settle_neigh ENROLL ')]
        self.assertEqual(len(neigh), 2, out)
        self.assertIn('penn_child=penn_child/STALE', neigh[0])
        self.assertIn('management=management/REACHABLE', neigh[0])
        self.assertRegex(neigh[0], r' ip6-[0-9a-f]{12}=mac-[0-9a-f]{12}/REACHABLE')
        self.assertRegex(neigh[0], r' ip4-[0-9a-f]{12}=-/FAILED')
        for secret in ('02:00:00:00:00:77', 'fe80::77', PENN['mac'], MGMT['mac'], '192.0.2.99', PENN['ip'], MGMT['ip']):
            self.assertNotIn(secret, '\n'.join(neigh))
        # Hashes are salted per run (sha256 of the salt hex + token), the salt is never logged, and one
        # token keeps one label across attempts.
        salt = hashlib.sha256(b'fixed-test-entropy').hexdigest()
        salted = hashlib.sha256((salt + '02:00:00:00:00:77').encode()).hexdigest()[:12]
        unsalted = hashlib.sha256(b'02:00:00:00:00:77').hexdigest()[:12]
        self.assertNotEqual(salted, unsalted)
        self.assertIn(f'=mac-{salted}/REACHABLE', neigh[0])
        self.assertIn(f'=mac-{salted}/REACHABLE', neigh[1])
        self.assertNotIn(unsalted, out)
        self.assertNotIn(salt, out)
        self.assertNotIn(salt, ''.join(f.read_text() for f in self.work.iterdir() if f.is_file() and f.name != 'calls'))

    def test_status_settle_without_salt_logs_no_hashes(self):
        code, out, calls = self.settle([self.status_line(drift=True), self.status_line()],
                                       extra='dd() { echo dd >> "$W/calls"; return 1; }\n')
        self.assertEqual(code, 0, out)
        neigh = [line for line in out.splitlines() if line.startswith('INFO status_settle_neigh ENROLL ')]
        self.assertEqual(neigh, ['INFO status_settle_neigh ENROLL attempt=1 salt_unavailable',
                                 'INFO status_settle_neigh ENROLL attempt=2 salt_unavailable'], out)

    def test_refresh_probe_requires_reply_to_establish_new_freshness(self):
        rehearsal = (REPO / 'tools/live/first-rehearsal.sh').read_text()
        neighbor = rehearsal[rehearsal.index('cfr_neighbor() {'):].split('\n}\n', 1)[0] + '\n}\n'
        for state in ('STALE', 'REACHABLE', 'DELAY'):
            for probe_succeeds in (False, True):
                with self.subTest(state=state, probe_succeeds=probe_succeeds):
                    body = (neighbor + f'CFP_DIR={shlex.quote(str(self.work))}\n'
                            f'printf "%s\\n" "{PENN["ip"]} lladdr {PENN["mac"]} {state}" > "$CFP_DIR/identity.neigh"\n'
                            'cfr_refuse() { printf "REFUSE %s %s\\n" "$1" "$2"; exit 21; }\n'
                            'timeout() { '
                            f'printf "%s\\n" "{PENN["ip"]} lladdr {PENN["mac"]} DELAY" > "$CFP_DIR/identity.neigh"; '
                            f'return {0 if probe_succeeds else 1}; }}\n'
                            f'cfp_refresh_probe penn_child {PENN["ip"]} {PENN["mac"]}\necho admitted\n')
                    code, out = self.pilot_shell(body)
                    if state == 'STALE' and not probe_succeeds:
                        self.assertEqual((code, out), (21, 'REFUSE IDENTITY penn_child_not_fresh\n'))
                    else:
                        self.assertEqual((code, out), (0, 'admitted\n'))

    def test_status_settle_first_read_pass_emits_no_measure(self):
        code, out, calls = self.settle([self.status_line()])
        self.assertEqual(code, 0, out)
        self.assertIn('INFO status_settle ENROLL attempts=1 waited_s=0', out)
        self.assertNotIn('MEASURE status_settle', out)

    def test_status_settle_rejects_clean_status_at_other_revisions(self):
        cases = {'confirmed_null': (1, 'null'),
                 'desired_null': ('null', 1),
                 'confirmed_stale': (1, 0),
                 'desired_stale': (0, 1),
                 'confirmed_ahead': (1, 2),
                 'desired_ahead': (2, 1),
                 'both_stale': (0, 0),
                 'both_ahead': (2, 2),
                 'both_null': ('null', 'null'),
                 'revision_prefix': (10, 10)}
        for name, (desired, confirmed) in cases.items():
            for after_drift in (False, True):
                with self.subTest(name=name, after_drift=after_drift):
                    replies = [self.status_line(drift=True)] if after_drift else []
                    replies += [self.status_line(desired=desired, confirmed=confirmed), self.status_line()]
                    code, out, calls = self.settle(replies)
                    attempts = 2 if after_drift else 1
                    waited = 15 if after_drift else 0
                    self.assertEqual((code, out.splitlines()[-1]), (20, 'STOP ENROLL penn_not_observed'), out)
                    self.assertEqual([c for c in calls if c.startswith('cfctl')], ['cfctl status --json'] * attempts)
                    self.assertEqual(calls.count('probe'), int(after_drift))
                    self.assertIn(f'INFO status_settle ENROLL attempts={attempts} waited_s={waited} not_transient', out)
                    self.assertNotIn('MEASURE status_settle', out)
                    self.assertNotIn('settled', out.splitlines())

    def test_status_settle_gives_up_after_budget_and_stops_with_gate_reason(self):
        code, out, calls = self.settle([self.status_line(drift=True)] * 20)
        self.assertEqual((code, out.splitlines()[-1]), (20, 'STOP ENROLL penn_not_observed'), out)
        # Reads at +0 (t0 1005), 15, 30, 45: the window closes at 45 s, never another read after it.
        self.assertIn('INFO status_settle ENROLL attempts=4 waited_s=45 gave_up', out)
        self.assertEqual([c for c in calls if c.startswith('cfctl')], ['cfctl status --json'] * 4)
        # Admission leaves one second for clock granularity: a 41 s window re-reads at 15 and 30 only.
        code, out, calls = self.settle([self.status_line(drift=True)] * 20, settle=41)
        self.assertEqual((code, out.splitlines()[-1]), (20, 'STOP ENROLL penn_not_observed'), out)
        self.assertIn('INFO status_settle ENROLL attempts=3 waited_s=40 gave_up', out)
        self.assertNotIn('MEASURE status_settle', out)
        # A zero window means one read only.
        code, out, calls = self.settle([self.status_line(drift=True)] * 20, settle=0)
        self.assertEqual((code, out.splitlines()[-1]), (20, 'STOP ENROLL penn_not_observed'), out)
        self.assertEqual([c for c in calls if c.startswith('cfctl')], ['cfctl status --json'])

    def test_status_settle_stops_on_first_read_unless_drift_only(self):
        other = '02:00:00:00:00:55'
        cases = {'errors': self.status_line(drift=True, errors='["x"]'),
                 'errors_no_drift': self.status_line(errors='["x"]'),
                 'kids_mismatch': self.status_line(drift=True, kids=[PENN['mac'], other]),
                 'kids_missing': self.status_line(drift=True, kids=[]),
                 'pause_mismatch': self.status_line(drift=True, effective='[{"person":"penn","until":5}]'),
                 'not_ok_no_drift': self.status_line().replace('"ok":true', '"ok":false'),
                 # A never-confirmed or stale apply is not waited out (cron must not repair it into a PASS).
                 'confirmed_null': self.status_line(drift=True, confirmed='null'),
                 'confirmed_stale': self.status_line(drift=True, confirmed=0),
                 'desired_stale': self.status_line(drift=True, desired=0, confirmed=0),
                 'desired_ahead': self.status_line(drift=True, desired=2, confirmed=1),
                 'revision_ahead': self.status_line(drift=True, desired=2, confirmed=2),
                 'revision_prefix': self.status_line(drift=True, desired=10, confirmed=10),
                 'empty': '',
                 'two_lines': self.status_line(drift=True) + '\n' + self.status_line(drift=True)}
        for name, reply in cases.items():
            with self.subTest(name=name):
                code, out, calls = self.settle([reply, self.status_line()])
                self.assertEqual((code, out.splitlines()[-1]), (20, 'STOP ENROLL penn_not_observed'), out)
                self.assertEqual([c for c in calls if c.startswith('cfctl')], ['cfctl status --json'])
                self.assertNotIn('probe', calls)
                self.assertIn('INFO status_settle ENROLL attempts=1 waited_s=0 not_transient', out)

    def test_status_settle_keeps_budget_and_adult_probe_gates(self):
        drift = [self.status_line(drift=True), self.status_line()]
        code, out, calls = self.settle(drift, extra='CFP_REMOTE_TIMEOUT=450\n')
        self.assertEqual((code, out.splitlines()[-1]), (20, 'STOP ENROLL remote_budget_reserved_for_teardown'), out)
        self.assertEqual([c for c in calls if c.startswith('cfctl')], ['cfctl status --json'])
        code, out, calls = self.settle(drift, extra='cfp_adult_probe() { CFP_ADULT_REASON=router_dns_failed; return 1; }\n')
        self.assertEqual((code, out.splitlines()[-1]), (20, 'STOP ENROLL adult_disruption router_dns_failed'), out)
        self.assertEqual([c for c in calls if c.startswith('cfctl')], ['cfctl status --json'])

    def test_status_settle_is_used_only_at_read_only_status_gates(self):
        script = (REPO / 'tools/live/penn-pilot.sh').read_text()
        self.assertEqual(script.count('cfp_status_settle ENROLL penn_not_observed '), 1)
        self.assertEqual(script.count('cfp_status_settle EXPIRY status_not_clean_after_expiry '), 1)
        # v2 adds exactly these read-only settled gates (never after a mutating pause/resume call itself).
        sites = re.findall(r'(?m)^\s+cfp_status_settle ([A-Z0-9-]+) ([a-z_]+) ', script)
        self.assertEqual(sites, [('ENROLL', 'penn_not_observed'), ('EXPIRY', 'status_not_clean_after_expiry'),
                                 ('SCOPE-ADD-2', 'phone_not_observed'), ('MOVE', 'move_not_observed'),
                                 ('MOVE', 'move_back_not_observed'), ('BULK', 'pause_all_not_observed'),
                                 ('BULK', 'resume_all_not_observed'), ('SCOPE-REMOVE', 'unenrol_not_observed')])
        # PAUSE, RESUME and the expiry pause gate the mutating call's own reply line, unchanged.
        self.assertIn('cfp_status_has "$CFP_DIR/status.json" "\\"effectivePauses\\":[{', script)
        self.assertIn('|| cfp_stop RESUME resume_not_clean', script)
        self.assertIn('|| cfp_stop EXPIRY pause_not_effective', script)
        settle = script[script.index('cfp_status_settle() {'):]
        settle = settle[:settle.index('\n}\n')]
        self.assertNotIn('rpc-sync', settle)
        self.assertEqual(re.findall(r'cfp_cfctl [a-z-]+', settle), ['cfp_cfctl status'] * 2)

    def test_status_settle_is_budgeted_and_disclosed(self):
        tool, timing = self.tool, dict(self.tool.TIMING, **SHIPPED_TIMING)
        call = tool.SAFE_BAND_WAIT_SECONDS + tool.CFCTL_CALL_SECONDS
        # First attempt's neighbour read, the window, then one admitted attempt (neighbour read + call).
        self.assertEqual(tool.status_settle_worst_seconds(timing), 8 + 45 + 8 + call)
        phases = tool.phase_worst_seconds(timing)
        self.assertEqual(phases['ENROLL'], 3 * call + tool.COUNTERS_WORST_SECONDS + 193)
        self.assertEqual({name: tool.worst_case_seconds(timing, devices, scope)
                          for name, devices, scope in (('one', 1, False), ('two', 2, False),
                                                       ('one_scope', 1, True), ('two_scope', 2, True))},
                         {'one': 3573, 'two': 3705, 'one_scope': 3753, 'two_scope': 3885})
        self.assertLessEqual(tool.worst_case_seconds(timing, 2, True), tool.V1_MAX_REMOTE_TIMEOUT_SECONDS)
        self.assertEqual(SHIPPED_TIMING['statusSettleSeconds'], 45)
        script = (REPO / 'tools/live/penn-pilot.sh').read_text()
        self.assertEqual(script.count('-lt "$((CFP_STATUS_SETTLE - 1))"'), 2)
        details = self.plan_details(self.write_config())
        self.assertEqual(details['timing']['statusSettleSeconds'], tool.TIMING['statusSettleSeconds'])
        params, _ = self.parameters(self.write_config())
        self.assertEqual(params['CFP_STATUS_SETTLE'], str(tool.TIMING['statusSettleSeconds']))
        with mock.patch.dict(tool.TIMING, statusSettleSeconds=tool.TIMING['statusSettleSeconds'] + 1):
            self.assertNotEqual(self.plan_details(self.write_config())['planSha256'], details['planSha256'])
        with mock.patch.dict(tool.TIMING, statusSettleSeconds=-1):
            self.refused_before_ssh(self.write_config(), 'timing statusSettleSeconds')
        # The plan refuses below the minimum.
        self.refused_before_ssh(self.write_config(remoteTimeoutSeconds=tool.worst_case_seconds(tool.TIMING) - 1),
                                f'at least {tool.worst_case_seconds(tool.TIMING)}')

    def test_expiry_worst_case_includes_pause_extension_and_is_disclosed(self):
        timing, tool = self.tool.TIMING, self.tool
        call = tool.SAFE_BAND_WAIT_SECONDS + tool.CFCTL_CALL_SECONDS
        expected = (call + timing['expirySeconds'] + tool.CFCTL_ALLOWANCE_SECONDS + timing['expiryToleranceSeconds']
                    + tool.iteration_worst_seconds(timing) + tool.COUNTERS_WORST_SECONDS + call
                    + tool.status_settle_worst_seconds(timing))
        self.assertEqual(tool.phase_worst_seconds(timing)['EXPIRY'], expected)
        # The shipped timing: with the pause extension, the ENROLL and post-expiry status settles and the KILL grace.
        self.assertEqual(tool.worst_case_seconds(dict(tool.TIMING, **SHIPPED_TIMING)), 3573)
        details = self.plan_details(self.write_config())
        self.assertEqual(details['timing']['cfctlAllowanceSeconds'], 45)
        config = tool.FR.load_config(self.write_config())
        commit, blobs = tool.FR.head_source()
        self.assertIn("CFP_CFCTL_ALLOWANCE='45'\n", tool.build_payload(config, commit, blobs, timing)[0].decode())

    def coverage_shell(self, extra=''):
        leases = self.work / 'diag.leases'
        leases.write_text(f'1900000000 {PENN["mac"]} {PENN["ip"]} PRIVATE_CHILD *\n'
                          '1900000000 02:00:00:00:00:99 192.0.2.99 PRIVATE_OTHER *\n')
        body = (f'CFP_DIR={shlex.quote(str(self.work))}\nCFR_LEASES={shlex.quote(str(leases))}\n'
                f'CFP_RPC_ALLOW={PENN["mac"]}\nCFR_PENN_IP={PENN["ip"]}\n'
                'CFP_READ_TIMEOUT=8\nCFP_START_CS=0\nCFP_REMOTE_TIMEOUT=2000\nCFP_TEARDOWN_RESERVE=300\n'
                'cfp_now() { echo 1000; }\ncfp_cs() { echo 100000; }\ncfr_info() { echo "INFO $1"; }\n'
                'ip() { case "$*" in\n'
                f' *neigh*) printf "%s\\n" "2001:db8::30 lladdr {PENN["mac"]} STALE" '
                f'"{PENN["ip"]} lladdr 02:00:00:00:00:88 REACHABLE" '
                '"192.0.2.99 lladdr 02:00:00:00:00:99 REACHABLE";;\n'
                ' *addr*) echo "2: br-lan inet6 2001:db8::1/64 scope global";; esac; }\n'
                'timeout() { shift 3; "$@"; }\n' + extra + '\ncfp_coverage_diag\necho TEARDOWN\n')
        return self.pilot_shell(body)

    def test_coverage_diag_scopes_neighbor_and_lease_fields(self):
        code, out = self.coverage_shell()
        self.assertEqual(code, 0, out)
        # Raw LAN addresses never reach the evidence: salted hashes (role labels for the pilot's own devices).
        for raw in ('2001:db8::30', '2001:db8::1', '192.0.2.99', PENN['ip']):
            self.assertNotIn(raw, out)
        self.assertRegex(out, rf'neighbor ip6-[0-9a-f]{{12}} mac={PENN["mac"]} state=STALE')
        self.assertIn('neighbor penn_child mac=02:00:00:00:00:88', out)
        self.assertIn(f'lease expiry=1900000000 mac={PENN["mac"]} ip=penn_child', out)
        self.assertRegex(out, r'lan inet6 ip6-[0-9a-f]{12}/64')
        self.assertNotIn('PRIVATE_', out)

    def test_coverage_diag_budget_skip_and_read_timeout_continue_teardown(self):
        code, out = self.coverage_shell('CFP_REMOTE_TIMEOUT=1350\ntimeout() { echo SHOULD_NOT_READ; return 1; }')
        self.assertEqual(code, 0, out)
        self.assertIn('coverage_diag skipped teardown_reserve', out)
        self.assertNotIn('SHOULD_NOT_READ', out)
        self.assertTrue(out.endswith('TEARDOWN\n'))
        code, out = self.coverage_shell('timeout() { return 137; }')
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count('unavailable read_timeout_or_failed'), 6)
        self.assertTrue(out.endswith('TEARDOWN\n'))
        # Recheck the actual remaining reserve before each subsequent read.
        code, out = self.coverage_shell('cfp_now() { echo 1000; }\n'
                                       'timeout() { CFP_REMOTE_TIMEOUT=1300; shift 3; "$@"; }')
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count('skipped teardown_reserve'), 5)

    def test_coverage_diag_limits_rows(self):
        code, out = self.coverage_shell(f'ip() {{ i=0; while [ "$i" -lt 40 ]; do '
                                       f'echo "2001:db8::$i lladdr {PENN["mac"]} STALE"; i=$((i+1)); done; }}')
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count('INFO coverage_diag neighbor ip6-'), 32)
        self.assertEqual(out.count('INFO coverage_diag neighbor truncated'), 2)

    def test_coverage_diag_only_exact_enroll_failure_token(self):
        for error, expected in [('incomplete_transition_address_coverage', True),
                                ('incomplete_transition_address_coverage_extra', False),
                                ('different_error', False)]:
            with self.subTest(error=error):
                status = json.dumps({'rpc_version': 1, 'generation': 'a' * 64, 'policyDigest': 'b' * 64,
                                     'acceptedPolicy': {'version': 1, 'revision': 0, 'people': [], 'pauses': []}}, separators=(',', ':'))
                body = (f'CFP_DIR={shlex.quote(str(self.work))}\nCFP_POLICY=policy\n'
                        f'cfp_cfctl() {{ echo {shlex.quote(status)}; }}\n'
                        f"cfp_cfctl_input() {{ echo '[\"{error}\"]'; return 1; }}\n"
                        'cfp_policy_only_penn() { return 0; }\n'
                        'cfp_coverage_diag() { echo DIAGNOSTIC; }\n'
                        'cfp_stop() { echo "STOP $1 $2"; exit 20; }\ncfp_enroll\n')
                code, out = self.pilot_shell(body)
                self.assertEqual(code, 20, out)
                self.assertEqual('DIAGNOSTIC' in out, expected, out)
                self.assertIn('STOP ENROLL rpc_sync_failed', out)

    def test_latency_guard_treats_empty_clock_as_zero(self):
        code, out = self.pilot_shell('cfp_now() { :; }\ncfp_lat_note 1000\necho "$cfp_lat $CFP_LAT_MAX"\n')
        self.assertEqual((code, out), (0, '0 0\n'))

    def test_empty_clock_stops_safely_instead_of_arithmetic_error(self):
        empty = 'cfp_now() { :; }\ncfp_cs() { return 1; }\nCFP_START_CS=100000\nCFP_REMOTE_TIMEOUT=1000\nCFP_TEARDOWN_RESERVE=300\n'
        self.assertEqual(self.pilot_shell(empty + 'cfp_elapsed_ok 0 || echo not_ok\n'), (0, 'not_ok\n'))
        self.assertEqual(self.pilot_shell(empty + 'cfp_observe 5 paused PAUSE\n'),
                         (20, 'STOP PAUSE clock_unavailable\n'))
        body = empty + 'cfp_safe_band() { return 0; }\nCFP_LAT_MAX=0\nCFP_CFCTL_ALLOWANCE=45\ncfp_pause 45 || echo pause_refused\n'
        self.assertEqual(self.pilot_shell(body), (0, 'pause_refused\n'))

    def test_teardown_ignores_signals_before_marking_itself(self):
        script = (REPO / 'tools/live/penn-pilot.sh').read_text()
        body = script[script.index('cfp_teardown() {'):]
        body = body[:body.index('\n}\n')]
        self.assertLess(body.index("trap '' INT TERM"), body.index('\n    CFP_TEARDOWN=1\n'))
        self.assertLess(body.index("trap '' INT TERM"), body.index('[ "$CFP_TEARDOWN" = 0 ]'))
        self.assertEqual(body.count('PENN_KERNEL_STATE $(cfp_kernel_state)'), 2)
        self.assertIn('PENN_PILOT_STOPPED_RESTORED_CONNECTIVITY_FAILED', body)

    def test_every_pause_is_timed_and_no_open_ended_pause(self):
        script = (REPO / 'tools/live/penn-pilot.sh').read_text()
        calls = [line for line in script.splitlines() if re.search(r'CFR_CFCTL"? .*\bpause\b', line)]
        self.assertEqual(len(calls), 1, calls)
        self.assertIn('--until "$CFP_UNTIL"', calls[0])
        self.assertNotRegex(script, r'(?m)^[^#]*\b(dnsmasq|authorized_keys)\b')


    # --- Two devices of one child and the optional SCOPE negative test ---------------

    def test_single_device_parameters_phases_and_minimum_unchanged(self):
        params, payload = self.parameters(self.write_config())
        self.assertEqual(list(params), SINGLE_PARAMETER_KEYS)
        self.assertEqual(json.loads(params['CFP_POLICY'])['people'], [{'id': 'penn', 'macs': [PENN['mac']]}])
        details = self.plan_details(self.write_config())
        self.assertEqual(details['phases'], list(self.tool.PHASES))
        self.assertNotIn('SCOPE', self.tool.PHASES)
        self.assertEqual(details['roles'], {'management': MGMT, 'jd_adult': JD, 'penn_child': PENN})
        for key in ('scopeNegativeTest', 'scopePolicyJson', 'scopePolicySha256', 'scopeTestMac'):
            self.assertNotIn(key, details)
        shipped = dict(self.tool.TIMING, **SHIPPED_TIMING)
        self.assertEqual(self.tool.worst_case_seconds(shipped), 3573)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=1, scope=False), 3573)
        self.assertIn('CFP_RPC_ALLOW', payload)  # the template default, not a generated parameter
        self.assertEqual(self.tool.load_config(self.write_config()),
                         dict(self.tool.FR.load_config(self.write_config()), schemaVersion=1))

    def test_second_device_config_is_validated_before_ssh(self):
        roles = self.config['roles']
        cases = [
            (dict(roles, penn_child_2={'ip': PENN2['ip'], 'mac': PENN['mac']}), 'penn_child_2'),
            (dict(roles, penn_child_2={'ip': PENN2['ip'], 'mac': JD['mac']}), 'penn_child_2'),
            (dict(roles, penn_child_2={'ip': PENN2['ip'], 'mac': MGMT['mac']}), 'penn_child_2'),
            (dict(roles, penn_child_2={'ip': PENN2['ip'], 'mac': HISTORICAL[0]}), 'penn_child_2'),
            (dict(roles, penn_child_2={'ip': PENN2['ip'], 'mac': self.tool.SCOPE_TEST_MAC}), 'penn_child_2'),
            (dict(roles, penn_child_2={'ip': PENN['ip'], 'mac': PENN2['mac']}), 'penn_child_2'),
            (dict(roles, penn_child_2={'ip': HOST, 'mac': PENN2['mac']}), 'penn_child_2'),
            (dict(roles, penn_child_2={'ip': PENN2['ip'], 'mac': '03:00:00:00:00:2a'}), 'unicast'),
            (dict(roles, penn_child_2={'ip': PENN2['ip'], 'mac': '02:00:00:00:00:2A'}), 'canonical'),
            (dict(roles, penn_child_2={'ip': PENN2['ip'], 'mac': PENN2['mac'], 'name': 'x'}), 'penn_child_2'),
            (dict(roles, penn_child_3=PENN2), 'roles must contain exactly'),
        ]
        for changed, reason in cases:
            with self.subTest(role=changed.get('penn_child_2', changed.get('penn_child_3'))):
                self.refused_before_ssh(self.write_config(roles=changed), reason)
        self.refused_before_ssh(self.write_config(scopeNegativeTest='yes'), 'scopeNegativeTest')
        self.refused_before_ssh(self.write_config(scopeNegativeTest=1), 'scopeNegativeTest')
        self.refused_before_ssh(self.write_config(protectedHistoricalMacs=[self.tool.SCOPE_TEST_MAC],
                                                  scopeNegativeTest=True), 'scope test MAC')

    def test_two_device_plan_binds_the_sorted_set(self):
        single = self.plan_details(self.write_config())
        config_path = self.write_config(**self.two_devices())
        details = self.plan_details(config_path)
        macs = sorted([PENN['mac'], PENN2['mac']])
        self.assertEqual(macs[0], PENN2['mac'])
        self.assertEqual(json.loads(details['policyJson'])['people'], [{'id': 'penn', 'macs': macs}])
        self.assertEqual(details['roles']['penn_child_2'], PENN2)
        self.assertEqual(details['phases'], list(self.tool.PHASES))
        self.assertNotEqual(details['planSha256'], single['planSha256'])
        params, _ = self.parameters(config_path)
        self.assertEqual(list(params)[:len(SINGLE_PARAMETER_KEYS)], SINGLE_PARAMETER_KEYS)
        self.assertEqual(params['CFP_RPC_ALLOW'], ' '.join(macs))
        self.assertEqual(params['CFP_KIDS_JSON'], json.dumps(macs, separators=(',', ':')))
        self.assertEqual((params['CFP_PENN2_IP'], params['CFP_PENN2_MAC']), (PENN2['ip'], PENN2['mac']))
        self.assertNotIn('CFP_SCOPE_TEST', params)
        shipped = dict(self.tool.TIMING, **SHIPPED_TIMING)
        call = self.tool.SAFE_BAND_WAIT_SECONDS + self.tool.CFCTL_CALL_SECONDS
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=2), 3573 + call)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=2), 3705)
        self.assertEqual(int(params['CFP_WORST_ENROLL']),
                         self.tool.phase_worst_seconds(self.tool.TIMING)['ENROLL'] + call)
        config = self.tool.load_config(config_path)
        policy = self.tool.enrollment_policy(config)
        self.assertIs(self.tool.assert_policy_only_penn(policy, config), policy)
        for bad in ([PENN['mac']], [PENN2['mac']], macs[::-1], macs + [JD['mac']]):
            with self.assertRaises(self.tool.Refusal):
                self.tool.assert_policy_only_penn(dict(policy, people=[{'id': 'penn', 'macs': bad}]), config)
        self.assertFalse(self.ssh_log.exists())

    def test_scope_phase_is_opt_in_disclosed_and_budgeted(self):
        shipped = dict(self.tool.TIMING, **SHIPPED_TIMING)
        call = self.tool.SAFE_BAND_WAIT_SECONDS + self.tool.CFCTL_CALL_SECONDS
        scope_worst = call + 2 * self.tool.FIREWALL_STATE_WORST_SECONDS
        self.assertEqual(self.tool.FIREWALL_STATE_WORST_SECONDS, 3 * self.tool.READ_TIMEOUT_SECONDS)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=1, scope=True), 3573 + scope_worst)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=1, scope=True), 3753)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=2, scope=True), 3885)
        self.assertLessEqual(self.tool.worst_case_seconds(shipped, devices=2, scope=True), self.tool.V1_MAX_REMOTE_TIMEOUT_SECONDS)
        disabled = self.plan_details(self.write_config(**self.two_devices(scopeNegativeTest=False)))
        self.assertEqual(disabled['phases'], list(self.tool.PHASES))
        config_path = self.write_config(**self.two_devices(scopeNegativeTest=True))
        details = self.plan_details(config_path)
        self.assertEqual(details['phases'][details['phases'].index('ENROLL') + 1], 'SCOPE')
        self.assertEqual(details['phases'][details['phases'].index('SCOPE') + 1], 'PAUSE')
        self.assertTrue(details['scopeNegativeTest'])
        self.assertEqual(details['scopeTestMac'], '02:00:00:00:00:99')
        self.assertNotEqual(details['planSha256'], disabled['planSha256'])
        scope_policy = json.loads(details['scopePolicyJson'])
        self.assertEqual(scope_policy['revision'], 2)
        self.assertEqual(scope_policy['people'],
                         [{'id': 'penn', 'macs': sorted([PENN['mac'], PENN2['mac'], '02:00:00:00:00:99'])}])
        params, payload = self.parameters(config_path)
        self.assertEqual(params['CFP_SCOPE_TEST'], '1')
        self.assertEqual(params['CFP_SCOPE_MAC'], '02:00:00:00:00:99')
        self.assertEqual(params['CFP_SCOPE_OPERATION_ID'], 'penn-pilot-scope-1')
        self.assertEqual(json.loads(params['CFP_SCOPE_POLICY']), scope_policy)
        self.assertEqual(int(params['CFP_WORST_SCOPE']), scope_worst)
        self.assertIn('cfp_budget SCOPE "$CFP_WORST_SCOPE"', payload)
        # The minimum is enforced per configuration.
        self.refused_before_ssh(self.write_config(**self.two_devices(scopeNegativeTest=True, remoteTimeoutSeconds=3000)),
                                f'at least {self.tool.worst_case_seconds(self.tool.TIMING, devices=2, scope=True)}')
        # A SCOPE line is required for PASS only when the plan listed it.
        phases = tuple(details['phases'])
        ok = ['MUTATION_BEGIN'] + [f'PHASE {name} OK' for name in phases] + ['PENN_PILOT_PASS']
        self.assertEqual(self.tool.classify('\n'.join(ok), 0, False, phases)[0], 'PASS')
        self.assertEqual(self.tool.classify('\n'.join(x for x in ok if x != 'PHASE SCOPE OK'), 0, False, phases)[0], 'FAIL')
        self.assertEqual(self.tool.classify('\n'.join(ok), 0, False)[0], 'FAIL')

    def test_kernel_state_is_paused_only_when_every_device_is(self):
        macs = ' '.join(sorted([PENN['mac'], PENN2['mac']]))
        cases = (([PENN['mac'], PENN2['mac']], 'paused'), ([], 'clear'), ([PENN['mac']], 'partial'),
                 ([PENN2['mac']], 'partial'), (['02:00:00:00:00:77'], 'clear'))
        for members, want in cases:
            listing = self.work / 'listing'
            listing.write_text(''.join(m + '\n' for m in members))
            body = (f'CFP_DIR={shlex.quote(str(self.work))}\nCFP_RPC_ALLOW={shlex.quote(macs)}\n'
                    f'cfp_paused_members() {{ cat {shlex.quote(str(listing))}; }}\ncfp_penn_state\n')
            self.assertEqual(self.pilot_shell(body), (0, want + '\n'), members)
        single = (f'CFP_DIR={shlex.quote(str(self.work))}\nCFP_RPC_ALLOW={PENN["mac"]}\n'
                  f'cfp_paused_members() {{ printf "%s\\n" {PENN["mac"]}; }}\ncfp_penn_state\n')
        self.assertEqual(self.pilot_shell(single), (0, 'paused\n'))
        # A partial set is never read as paused or clear: the pilot stops.
        partial = (f'CFP_DIR={shlex.quote(str(self.work))}\nCFP_RPC_ALLOW={shlex.quote(macs)}\nCFP_UNKNOWN=0\n'
                   f'cfp_paused_members() {{ printf "%s\\n" {PENN["mac"]}; }}\n')
        self.assertEqual(self.pilot_shell(partial + 'cfp_state_check paused PAUSE\n'),
                         (20, 'STOP PAUSE penn_kernel_state_partial\n'))
        self.assertEqual(self.pilot_shell(partial + "cfp_state_check '' EXPIRY\n"),
                         (20, 'STOP EXPIRY penn_kernel_state_partial\n'))

    def test_policy_mac_guard_requires_exactly_the_set(self):
        macs = ' '.join(sorted([PENN['mac'], PENN2['mac']]))
        cases = ((f'[\\"{PENN2["mac"]}\\",\\"{PENN["mac"]}\\"]', 0), (f'[\\"{PENN["mac"]}\\"]', 1),
                 (f'[\\"{PENN2["mac"]}\\",\\"{PENN["mac"]}\\",\\"{JD["mac"]}\\"]', 1), ('[]', 1))
        for text, want in cases:
            body = f'CFP_RPC_ALLOW={shlex.quote(macs)}\ncfp_policy_only_penn "{text}"; echo $?\n'
            self.assertEqual(self.pilot_shell(body), (0, f'{want}\n'), text)

    def scope_reply(self, **overrides):
        digest, gen = 'd' * 64, 'a' * 64
        kids = json.dumps(sorted([PENN['mac'], PENN2['mac']]), separators=(',', ':'))
        parts = {'head': f'{{"rpc_version":1,"generation":"{gen}",',
                 'accepted': f'"acceptedPolicy":{{"version":1,"revision":1,"people":[{{"id":"penn","macs":{kids}}}],'
                             '"pauses":[],"schedules":[],"doh":{"ipv4":[],"ipv6":[]}},',
                 'digest': f'"policyDigest":"{digest}","currentOperationId":"penn-pilot-enroll-1","routerTime":1,',
                 'receipt': '"receipt":null,',
                 'status': f'"status":{{"ok":true,"observed":{{"kids":{kids},"paused":[]}},"errors":[]}},',
                 'errors': '"errors":["rpc_scope_overlap"]}'}
        parts.update(overrides)
        return ''.join(parts.values()) + '\n', gen, digest, kids

    def scope_clean(self, reply, rc=1, gen='a' * 64, digest='d' * 64, kids=None):
        kids = kids or json.dumps(sorted([PENN['mac'], PENN2['mac']]), separators=(',', ':'))
        path = self.work / 'scope-sync.json'
        path.write_text(reply)
        body = (f'CFP_OPERATION_ID=penn-pilot-enroll-1\nCFP_SCOPE_MAC=02:00:00:00:00:99\nCFP_SCOPE_ERROR=rpc_scope_overlap\nCFP_KIDS_JSON={shlex.quote(kids)}\n'
                f'cfp_scope_clean {shlex.quote(str(path))} {rc} {gen} {digest}; echo $?\n')
        code, out = self.pilot_shell(body)
        self.assertEqual(code, 0)
        return out.split()[-1]

    def test_scope_reply_must_be_a_clean_rejection(self):
        reply, gen, digest, kids = self.scope_reply()
        self.assertEqual(self.scope_clean(reply), '0')
        suffix = f',"scope":{kids},"scopeSha":"{"c" * 64}"}}'
        scoped = reply.replace(']}\n', ']' + suffix + '\n')
        self.assertNotEqual(scoped, reply)
        self.assertEqual(self.scope_clean(scoped), '0')
        for name, text in {'scope_mac_in_scope': scoped.replace(f',"scopeSha"', ',"x":"02:00:00:00:00:99","scopeSha"'),
                           'short_sha': scoped.replace('c' * 64, 'c' * 63),
                           'trailing_key': scoped.replace('"}\n', '","extra":1}\n'),
                           'scope_before_errors': scoped.replace('"errors":["rpc_scope_overlap"]', '"errors":["rpc_scope_overlap"],"scope":[]')}.items():
            with self.subTest(name=name):
                self.assertEqual(self.scope_clean(text), '1')
        receipt = ('"receipt":{"operationId":"penn-pilot-scope-1","requestDigest":"x","baseRevision":1,"baseDigest":"x",'
                   '"acceptedRevision":2,"acceptedDigest":"x","outcome":"accepted","current":true},')
        bad = {
            'accepted_exit_zero': (reply, 0),
            'accepted_receipt': (self.scope_reply(receipt=receipt)[0], 1),
            'wrong_error': (self.scope_reply(errors='"errors":["policy_conflict"]}')[0], 1),
            'two_errors': (self.scope_reply(errors='"errors":["rpc_scope_overlap","apply_failed"]}')[0], 1),
            'no_error': (self.scope_reply(errors='"errors":[]}')[0], 1),
            'revision_2': (self.scope_reply(accepted='"acceptedPolicy":{"version":1,"revision":2,"people":[],'
                                                     '"pauses":[],"schedules":[],"doh":{"ipv4":[],"ipv6":[]}},')[0], 1),
            'digest_changed': (self.scope_reply(digest=f'"policyDigest":"{"e" * 64}","currentOperationId":'
                                                      '"penn-pilot-enroll-1","routerTime":1,')[0], 1),
            'current_op_changed': (self.scope_reply(digest=f'"policyDigest":"{digest}","currentOperationId":'
                                                          '"penn-pilot-scope-1","routerTime":1,')[0], 1),
            'other_generation': (self.scope_reply(head=f'{{"rpc_version":1,"generation":"{"b" * 64}",')[0], 1),
            'scope_mac_echoed': (self.scope_reply(status='"status":{"observed":{"kids":["02:00:00:00:00:99"],'
                                                         '"paused":[]}},')[0], 1),
            'kids_changed': (self.scope_reply(status=f'"status":{{"observed":{{"kids":["{PENN["mac"]}"],'
                                                     '"paused":[]}},')[0], 1),
            'two_lines': (reply + reply, 1),
            'empty': ('', 1),
            'busy_reject': ('{"rpc_version":1,"errors":["rpc_scope_overlap"]}\n', 1),
        }
        for name, (text, rc) in bad.items():
            with self.subTest(name=name):
                self.assertEqual(self.scope_clean(text, rc=rc), '1')

    def test_device_set_is_derived_from_identity_macs(self):
        macs = sorted([PENN['mac'], PENN2['mac']])
        good = (' '.join(macs), json.dumps(macs, separators=(',', ':')))
        cases = ((PENN['mac'], PENN2['mac'], *good, '0'), (PENN2['mac'], PENN['mac'], *good, '0'),
                 (PENN['mac'], PENN2['mac'], ' '.join(reversed(macs)), good[1], '1'),
                 (PENN['mac'], PENN2['mac'], f'{macs[0]} 02:00:00:00:00:77', good[1], '1'),
                 (PENN['mac'], PENN2['mac'], good[0], json.dumps(macs[::-1], separators=(',', ':')), '1'),
                 (PENN['mac'], PENN2['mac'], good[0], json.dumps(macs[:1], separators=(',', ':')), '1'),
                 (PENN['mac'], PENN['mac'], f'{PENN["mac"]} {PENN["mac"]}', json.dumps([PENN['mac']] * 2), '1'),
                 (PENN['mac'], PENN2['mac'].upper(), *good, '1'))
        for first, second, allow, kids, want in cases:
            body = (f'CFR_PENN_MAC={shlex.quote(first)}\nCFP_PENN2_MAC={shlex.quote(second)}\n'
                    f'CFP_RPC_ALLOW={shlex.quote(allow)}\nCFP_KIDS_JSON={shlex.quote(kids)}\ncfp_device_set; echo $?\n')
            self.assertEqual(self.pilot_shell(body), (0, want + '\n'), (first, second, allow, kids))

    def scope_phase_shell(self, band_open):
        (self.work / 'rpc-sync.json').write_text(f'{{"x":1,"policyDigest":"{"d" * 64}","y":2}}\n')
        policy = json.dumps({'people': [{'id': 'penn', 'macs': [PENN['mac'], '02:00:00:00:00:99']}]}, separators=(',', ':'))
        body = (f'CFP_DIR={shlex.quote(str(self.work))}\nCFR_STAGE={shlex.quote(str(self.work))}\n'
                f'CFP_RPC_ALLOW={PENN["mac"]}\nCFP_SCOPE_MAC=02:00:00:00:00:99\nCFP_SCOPE_POLICY={shlex.quote(policy)}\n'
                f'CFP_SCOPE_OPERATION_ID=penn-pilot-scope-1\nCFP_SCOPE_ERROR=rpc_scope_overlap\ncfp_gen={"a" * 64}\n'
                'cfp_fw_state() { : > "$1"; }\ncfp_now() { echo 1000; }\n'
                f'cfp_safe_band() {{ return {0 if band_open else 1}; }}\n'
                'CFR_SH=cfctl_called\ncfctl_called() { echo CFCTL_CALLED; return 1; }\ncfp_scope_phase\n')
        return self.pilot_shell(body)

    def test_scope_safe_band_unavailable_is_a_distinct_stop(self):
        self.assertEqual(self.scope_phase_shell(band_open=False), (20, 'STOP SCOPE safe_band_unavailable\n'))
        self.assertEqual(self.scope_phase_shell(band_open=True), (20, 'STOP SCOPE scope_not_cleanly_rejected\n'))

    def test_rpc_activity_lists_both_devices_if_exposed(self):
        macs = sorted([PENN['mac'], PENN2['mac']])
        def device(mac):
            return (f'{{"person":"penn","mac":"{mac}","ip":null,"neighbor":"none","tx_bytes":0,"rx_bytes":0,'
                    '"tx_packets":0,"rx_packets":0,"blocked_packets":0}')
        def run(text, rc=0):
            body = (f'CFP_DIR={shlex.quote(str(self.work))}\nCFP_RPC_ALLOW={shlex.quote(" ".join(macs))}\nCFP_PERSON=penn\n'
                    f'cfp_cfctl() {{ printf "%s" {shlex.quote(text)}; return {rc}; }}\ncfp_rpc_activity\n')
            return self.pilot_shell(body)
        head = '{"version":1,"router_epoch":1,"counter_epoch":1,"offload":"off","devices":['
        both = head + ','.join(device(m) for m in macs) + '],"errors":[]}\n'
        self.assertEqual(run(both), (0, 'MEASURE rpc_activity_devices measured listed=2/2 person=penn\n'))
        one = head + device(macs[0]) + '],"errors":["accounting_unavailable"]}\n'
        self.assertEqual(run(one), (0, 'MEASURE rpc_activity_devices measured listed=1/2 person=penn '
                                       'errors_reported\n'))
        self.assertEqual(run('{"version":1,"router_epoch":0,"counter_epoch":0,"offload":"unknown","devices":[],'
                             '"errors":["rpc_disabled"]}\n', rc=1),
                         (0, 'MEASURE rpc_activity_devices unmeasured rpc_activity_unavailable\n'))
        self.assertEqual(run(''), (0, 'MEASURE rpc_activity_devices unmeasured rpc_activity_unavailable\n'))
        outsider = head + ','.join(device(m) for m in macs + ['02:00:00:00:00:77']) + '],"errors":[]}\n'
        self.assertEqual(run(outsider), (20, 'STOP ENROLL rpc_activity_lists_unenrolled_mac\n'))


class PilotConfigV2Tests(PilotBase):
    """Config v2: Chromebook-only floor, phone as scope_target, pilot_b validator, phases, timing, plan fields."""

    def v2(self, roles=None, **changes):
        roles = dict(self.config['roles'], ct107=CT107, scope_target=PHONE) if roles is None else roles
        changes.setdefault('protectedHistoricalMacs', HISTORICAL + [CT107['mac']])
        return dict(changes, schemaVersion=2, roles=roles, remoteTimeoutSeconds=changes.get('remoteTimeoutSeconds', 10000))

    def v2_config(self, **changes):
        return self.tool.load_config(self.write_config(**self.v2(**changes)))

    def test_v2_floor_is_chromebook_only_and_phone_is_scope_target(self):
        config = self.v2_config()
        self.assertEqual(self.tool.penn_macs(config), [PENN['mac']])
        self.assertEqual(config['roles']['scope_target'], PHONE)
        details = self.plan_details(self.write_config(**self.v2()))
        self.assertEqual(json.loads(details['policyJson'])['people'], [{'id': 'penn', 'macs': [PENN['mac']]}])
        self.assertEqual(details['configSchemaVersion'], 2)
        self.assertEqual(details['phases'], V2_PHASES)
        self.assertEqual(details['roles']['scope_target'], PHONE)
        self.assertNotIn(PHONE['mac'], details['policyJson'])
        self.assertNotIn(PHONE['mac'], self.parameters(self.write_config(**self.v2()))[0]['CFP_POLICY'])

    def test_derived_syncs_are_disclosed_digest_bound_and_planned_revisions_reach_the_template(self):
        details = self.plan_details(self.write_config(**self.v2()))
        syncs = {sync['stage']: sync for sync in details['derivedSyncs']}
        self.assertEqual({name: sync['revision'] for name, sync in syncs.items()},
                         {'bulk_pause': 9, 'bulk_resume': 10, 'unenrol': 12})
        self.assertEqual([pause['person'] for pause in syncs['bulk_pause']['pauses']], ['penn', 'pilot_b'])
        self.assertEqual(syncs['bulk_resume']['pauses'], [])
        shape = lambda name: [(p['id'], p['macs']) for p in json.loads(syncs[name]['policyJson'])['people']]  # noqa: E731
        self.assertEqual(shape('bulk_pause'), [('penn', [PHONE['mac']]), ('pilot_b', [PENN['mac']])])
        self.assertEqual(shape('bulk_resume'), [('penn', sorted([PENN['mac'], PHONE['mac']]))])
        self.assertEqual(shape('unenrol'), [('penn', [PENN['mac']])])
        self.assertEqual(details['operationIds']['bulk_pause'], 'penn-pilot-bulk-1')
        params, _ = self.parameters(self.write_config(**self.v2()))
        self.assertEqual((params['CFP_REV_BULK_PAUSE'], params['CFP_REV_BULK_RESUME'], params['CFP_REV_UNENROL']), ('9', '10', '12'))
        for field in ('derivedSyncs', 'operationIds', 'selfAbortPercent'):
            mutated = copy.deepcopy(details)
            mutated[field] = [] if field == 'derivedSyncs' else {'x': 1} if field == 'operationIds' else 99
            self.assertNotEqual(self.tool.plan_digest(mutated), details['planSha256'], field)
            missing = copy.deepcopy(details)
            del missing[field]
            with self.assertRaises(self.tool.Refusal):
                self.tool.plan_digest(missing)
        self.assertEqual(details['selfAbortSeconds'], 10000 * 70 // 100)

    def test_v1_behaviour_is_explicit(self):
        v1 = self.plan_details(self.write_config())
        self.assertNotIn('configSchemaVersion', v1)
        self.assertEqual(v1['phases'], list(self.tool.PHASES))
        self.assertNotIn('legs', v1)
        self.refused_before_ssh(self.write_config(roles=dict(self.config['roles'], scope_target=PHONE)), 'schemaVersion 2')
        for version in (0, 3, True, '2'):
            self.refused_before_ssh(self.write_config(**dict(self.v2(), schemaVersion=version)), 'schemaVersion')
        # penn_child_2 is replaced by scope_target in v2 and never combined with it.
        self.refused_before_ssh(self.write_config(**self.v2(roles=dict(self.config['roles'], scope_target=PHONE,
                                                                     penn_child_2=PENN2))), 'scope_target')
        self.refused_before_ssh(self.write_config(**self.v2(roles=dict(self.config['roles'], penn_child_2=PENN2))),
                                'scope_target')
        self.refused_before_ssh(self.write_config(**self.v2(roles=dict(self.config['roles']))), 'scope_target')

    def test_scope_target_is_validated_before_ssh(self):
        roles = self.config['roles']
        bad = [(dict(PHONE, mac=HISTORICAL[0]), 'scope_target'), (dict(PHONE, mac=JD['mac']), 'scope_target'),
               (dict(PHONE, mac=MGMT['mac']), 'scope_target'), (dict(PHONE, mac=PENN['mac']), 'scope_target'),
               (dict(PHONE, mac=self.tool.SCOPE_TEST_MAC), 'scope_target'), (dict(PHONE, ip=PENN['ip']), 'scope_target'),
               (dict(PHONE, ip=HOST), 'scope_target'), (dict(PHONE, ip=MGMT['ip']), 'scope_target'),
               (dict(PHONE, mac=CT107['mac']), 'scope_target'), (dict(PHONE, ip=CT107['ip']), 'scope_target'),
               (dict(PHONE, mac='03:00:00:00:00:34'), 'unicast'), (dict(PHONE, mac='02:00:00:00:00:3A'), 'canonical'),
               (dict(PHONE, name='x'), 'scope_target'), ({'ip': PHONE['ip']}, 'scope_target'), ('phone', 'scope_target')]
        for target, reason in bad:
            with self.subTest(target=target):
                self.refused_before_ssh(self.write_config(**self.v2(roles=dict(roles, ct107=CT107, scope_target=target))), reason)

    def test_pilot_b_is_a_constant_never_from_config(self):
        self.assertEqual(self.tool.PILOT_B, 'pilot_b')
        self.refused_before_ssh(self.write_config(**self.v2(pilotB='mine')), 'unknown')
        stages = self.plan_details(self.write_config(**self.v2()))['pilotPolicies']
        move = {stage['stage']: json.loads(stage['policyJson']) for stage in stages}['move']
        self.assertEqual([person['id'] for person in move['people']], ['penn', 'pilot_b'])

    def test_v2_sibling_imports_standalone_and_binds(self):
        code = ("import importlib.util, sys; sys.dont_write_bytecode = True; "
                "spec = importlib.util.spec_from_file_location('v2', sys.argv[1]); m = importlib.util.module_from_spec(spec); "
                "spec.loader.exec_module(m); print(m.FR is None, callable(m.bind))")
        done = subprocess.run([sys.executable, '-B', '-I', '-c', code, str(REPO / 'tools/live/penn_pilot_v2.py')],
                              capture_output=True, text=True, check=False)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, 'True True'), done.stderr)
        self.assertNotIn('noqa: F821', (REPO / 'tools/live/penn_pilot_v2.py').read_text())
        self.assertIs(self.tool.V2.FR, self.tool.FR)
        self.assertIs(self.tool.V2.Refusal, self.tool.Refusal)

    def test_pilot_policies_refuse_a_wrong_candidate_for_every_stage(self):
        config = self.v2_config()
        base = self.tool.enrollment_policy(config)
        V2 = self.tool.V2
        good = V2.candidate_policies(config, base)
        self.assertEqual([name for name, _ in V2.pilot_policies(config, base)], list(V2.STAGES))
        for index, (stage, _) in enumerate(good):
            wrong = good[(index + 1) % len(good)][1]
            candidates = [(name, wrong if i == index else policy) for i, (name, policy) in enumerate(good)]
            with self.subTest(stage=stage):
                with self.assertRaises(self.tool.Refusal):
                    V2.pilot_policies(config, base, lambda c, b, cands=candidates: cands)

    def test_pilot_policy_validator_fails_closed(self):
        config = self.v2_config()
        policies = self.tool.pilot_policies(config)
        self.assertEqual([stage for stage, _ in policies], ['enroll', 'enroll_phone', 'move', 'move_back'])
        by_stage = dict(policies)
        self.assertEqual(by_stage['enroll']['people'], [{'id': 'penn', 'macs': [PENN['mac']]}])
        self.assertEqual(by_stage['enroll_phone']['people'], [{'id': 'penn', 'macs': sorted([PENN['mac'], PHONE['mac']])}])
        self.assertEqual(by_stage['move']['people'], [{'id': 'penn', 'macs': [PHONE['mac']]},
                                                      {'id': 'pilot_b', 'macs': [PENN['mac']]}])
        # rpc-sync needs revision == expected + 1 and pause/resume each add one: 1 enroll, 2 phone, 3-4 pause/resume,
        # 5 move A, 6-7 pilot_b pause/resume, 8 move back.
        self.assertEqual([stage['revision'] for _, stage in policies], [1, 2, 5, 8])
        for stage, policy in policies:
            self.assertIs(self.tool.assert_policy_pilot(policy, config, self.tool.expected_stage_policy(stage, config)), policy)
        good = by_stage['move']

        def mutated(change):
            policy = copy.deepcopy(good)
            change(policy)
            return policy
        cases = {
            'protected jd as pilot_b': mutated(lambda p: p['people'][1].update(macs=[JD['mac']])),
            'protected historical in penn': mutated(lambda p: p['people'][0]['macs'].append(HISTORICAL[0])),
            'management in policy': mutated(lambda p: p['people'][0]['macs'].append(MGMT['mac'])),
            'pilot_b overlapping penn': mutated(lambda p: p['people'][1].update(macs=[PENN['mac'], PHONE['mac']])),
            'chromebook in both people': mutated(lambda p: p['people'][0].update(macs=sorted([PHONE['mac'], PENN['mac']]))),
            'duplicate in one person': mutated(lambda p: p['people'][0].update(macs=[PHONE['mac'], PHONE['mac']])),
            'third person': mutated(lambda p: p['people'].append({'id': 'jd', 'macs': []})),
            'renamed person': mutated(lambda p: p['people'][1].update(id='pilot_c')),
            'unknown mac': mutated(lambda p: p['people'][1].update(macs=['02:00:00:00:00:77'])),
            'scope test mac': mutated(lambda p: p['people'][1].update(macs=[self.tool.SCOPE_TEST_MAC])),
            'schedule': mutated(lambda p: p.update(schedules=[{'x': 1}])),
            'pause': mutated(lambda p: p.update(pauses=[{'person': 'penn', 'until': 0}])),
            'doh': mutated(lambda p: p.update(doh={'ipv4': ['192.0.2.53'], 'ipv6': []})),
            'extra field': mutated(lambda p: p.update(extra=1)),
            'not exactly the expected policy': mutated(lambda p: p.update(revision=9)),
            # Type-strict emptiness: falsy is not empty (0 == False, '' and {} are falsy but not [] / the DoH shape).
            **{f'{key} {value!r}': mutated(lambda p, key=key, value=value: p.update({key: value}))
               for key in ('pauses', 'schedules', 'doh') for value in (0, '', {}, None, False)},
            'bool revision': mutated(lambda p: p.update(revision=True)),
            'float version': mutated(lambda p: p.update(version=1.0)),
            # Non-string ids are a Refusal, never a TypeError.
            **{f'id {value!r}': mutated(lambda p, value=value: p['people'][1].update(id=value))
               for value in (['x'], {}, 5, None, True)},
            'phone under pilot_b, chromebook missing': mutated(lambda p: p.update(
                people=[{'id': 'pilot_b', 'macs': [PHONE['mac']]}])),
        }
        independent_only = {'not exactly the expected policy', 'phone under pilot_b, chromebook missing'}
        for name, policy in cases.items():
            # Once against the good expected policy, once with the bad policy as its own expected value, so each
            # structural guard is exercised without the final equality check masking it.
            for expected in ((good, policy) if name not in independent_only else (good,)):
                with self.subTest(name, expected='good' if expected is good else 'self'):
                    with self.assertRaises(self.tool.Refusal):
                        self.tool.assert_policy_pilot(policy, config, expected)
        with self.assertRaises(self.tool.Refusal):
            self.tool.assert_policy_pilot('nope', config, good)
        # Defence in depth: a config that bypassed load_config and made a protected MAC the scope target.
        for protected in (JD['mac'], MGMT['mac'], HISTORICAL[0]):
            tampered = copy.deepcopy(config)
            tampered['roles']['scope_target']['mac'] = protected
            policy = copy.deepcopy(good)
            policy['people'][0]['macs'] = [protected]
            with self.subTest(tampered=protected), self.assertRaises(self.tool.Refusal):
                self.tool.assert_policy_pilot(policy, tampered, policy)
            # ct107 is protected too, even if a tampered config left it out of the historical list.
        tampered = copy.deepcopy(config)
        tampered['roles']['scope_target']['mac'] = CT107['mac']
        policy = copy.deepcopy(good)
        policy['people'][0]['macs'] = [CT107['mac']]
        with self.assertRaises(self.tool.Refusal):
            self.tool.assert_policy_pilot(policy, tampered, policy)
        # The guard also holds when the expected policy itself is the bad one.
        with self.assertRaises(self.tool.Refusal):
            self.tool.assert_policy_pilot(cases['pilot_b overlapping penn'], config, cases['pilot_b overlapping penn'])

    def test_plan_discloses_and_binds_legs_wording_and_policies(self):
        details = self.plan_details(self.write_config(**self.v2()))
        self.assertEqual(self.tool.FAILED_BLOCK_ALL_WORDING, 'unchanged')
        self.assertEqual(details['failedBlockAllWording'], 'unchanged')
        self.assertEqual(details['failedBlockAllWordingDecidedBy'], 'user')
        legs = details['legs']
        self.assertEqual([(leg['leg'], leg['form'], leg['op']) for leg in legs],
                         [('2a', 'cfctl', 'scope-add'), ('2b', 'cfctl', 'scope-remove'),
                          ('2c', 'cfctl-scope', 'scope-add'), ('2d', 'cfctl-scope', 'scope-remove')])
        bound = 'timeout -s KILL 60 '
        self.assertEqual(legs[0]['commandTemplate'], bound + '/usr/sbin/cfctl scope-add {MAC} --base {BASE}')
        self.assertEqual(legs[1]['commandTemplate'], bound + '/usr/sbin/cfctl scope-remove {MAC} --base {BASE}')
        self.assertEqual(legs[2]['commandTemplate'],
                         bound + "env SSH_ORIGINAL_COMMAND='cfctl scope-add {MAC} --base {BASE}' /usr/sbin/cfctl-scope pilot")
        self.assertEqual(legs[3]['commandTemplate'],
                         bound + "env SSH_ORIGINAL_COMMAND='cfctl scope-remove {MAC} --base {BASE}' /usr/sbin/cfctl-scope pilot")
        base = details['sshArgv']
        for leg in legs:  # the leg-1 argv with `-e none -tt` for `-T`: no ssh escape character on the pty
            self.assertEqual(leg['sshArgv'], base[:-3] + ['-e', 'none', '-tt', base[-2], leg['commandTemplate']])
        for leg in legs:
            self.assertEqual((leg['pty'], leg['timeoutSeconds'], leg['retry'], leg['confirmation']),
                             (True, 60, False, 'last6hex'))
            self.assertEqual(leg['scopeTargetMac'], PHONE['mac'])
        # Every disclosed v2 field is digest-bound: changing any one changes the plan digest.
        for field, other in (('legs', legs[:3]), ('failedBlockAllWording', 'not_blocking'),
                             ('failedBlockAllWordingDecidedBy', 'tool'), ('pilotPolicies', details['pilotPolicies'][:3]),
                             ('configSchemaVersion', 1), ('phases', details['phases'][:-1])):
            with self.subTest(field):
                self.assertNotEqual(self.tool.plan_digest(dict(details, **{field: other})), details['planSha256'])
        self.assertEqual(self.tool.plan_digest(details), details['planSha256'])
        for stage in details['pilotPolicies']:
            self.assertEqual(stage['policySha256'], hashlib.sha256(stage['policyJson'].encode()).hexdigest())

    def test_timing_model_covers_new_phases_and_minimum_grows(self):
        shipped = dict(self.tool.TIMING, **SHIPPED_TIMING)
        v1 = self.tool.phase_worst_seconds(shipped)
        v2 = self.tool.phase_worst_seconds(shipped, devices=1, scope=False, scope_target=True)
        self.assertEqual(set(v2) - set(v1), set(NEW_PHASES))
        for phase in NEW_PHASES:
            self.assertGreater(v2[phase], 0)
        leg, call = self.tool.SCOPE_LEG_SECONDS, self.tool.SAFE_BAND_WAIT_SECONDS + self.tool.CFCTL_CALL_SECONDS
        self.assertEqual(leg, 60)
        self.assertEqual(self.tool.worst_case_seconds(shipped, scope_target=True),
                         self.tool.worst_case_seconds(shipped) + sum(v2[phase] for phase in NEW_PHASES))
        details = self.plan_details(self.write_config(**self.v2()))
        self.assertEqual(details['minimumRemoteTimeoutSeconds'], self.tool.worst_case_seconds(self.tool.TIMING, scope_target=True))
        self.assertGreater(details['minimumRemoteTimeoutSeconds'], self.plan_details(self.write_config())['minimumRemoteTimeoutSeconds'])
        self.refused_before_ssh(self.write_config(**self.v2(remoteTimeoutSeconds=details['minimumRemoteTimeoutSeconds'] - 1)),
                                'at least')
        self.plan_details(self.write_config(**self.v2(remoteTimeoutSeconds=details['minimumRemoteTimeoutSeconds'])))

    def test_shipped_timing_fits_the_v2_cap_and_example_config_is_valid(self):
        shipped = dict(self.tool.TIMING, **SHIPPED_TIMING)
        worst = self.tool.worst_case_seconds(shipped, devices=1, scope=True, scope_target=True)
        self.assertGreater(worst, 3600)
        self.assertLessEqual(worst, self.tool.V2_MAX_REMOTE_TIMEOUT_SECONDS)
        example = REPO / 'tools/live/config.pilot.example.json'
        config = self.tool.load_config(str(example))
        macs = [role['mac'] for role in config['roles'].values()] + config['protectedHistoricalMacs']
        self.assertTrue(all(mac.startswith('02:00:00:00:00:') for mac in macs))
        self.assertTrue(config['host'].startswith('192.0.2.'))
        self.assertEqual(config['roles']['scope_target']['mac'], '02:00:00:00:00:34')
        self.assertGreaterEqual(config['remoteTimeoutSeconds'], worst)
        # ... and within the v2 cap, minimum + 900 s, of the shape the example describes (no SCOPE phase).
        self.assertLessEqual(config['remoteTimeoutSeconds'],
                             self.tool.remote_timeout_limit(self.tool.worst_case_seconds(shipped, scope_target=True)))
        self.assertEqual(config['protectedHistoricalMacs'].count(config['roles']['ct107']['mac']), 1)

    def test_remote_timeout_cap_is_explicit_per_schema(self):
        self.assertEqual(self.tool.V2_MAX_REMOTE_TIMEOUT_SECONDS, 10800)
        self.refused_before_ssh(self.write_config(remoteTimeoutSeconds=4201), 'remoteTimeoutSeconds')
        self.refused_before_ssh(self.write_config(**self.v2(remoteTimeoutSeconds=10801)), 'remoteTimeoutSeconds')
        self.refused_before_ssh(self.write_config(**self.v2(remoteTimeoutSeconds=599)), 'remoteTimeoutSeconds')
        self.refused_before_ssh(self.write_config(**self.v2(remoteTimeoutSeconds=True)), 'remoteTimeoutSeconds')
        self.assertEqual(self.v2_config(remoteTimeoutSeconds=10800)['remoteTimeoutSeconds'], 10800)

    def test_v2_payload_params_are_shell_identifiers_and_include_every_implemented_phase(self):
        params, payload = self.parameters(self.write_config(**self.v2()))
        region = payload.split('# @CF_PILOT_PARAMETERS_BEGIN@')[1].split('# @CF_PILOT_PARAMETERS_END@')[0]
        # Every emitted assignment is a valid sh variable (a hyphen would be a silent no-op command).
        self.assertTrue(all(re.fullmatch(r'CFP_[A-Z0-9_]+', key) for key in params))
        self.assertEqual(len(re.findall(r"(?m)^[A-Za-z_][A-Za-z0-9_-]*='", region)), len(params))
        self.assertEqual(list(params)[:len(SINGLE_PARAMETER_KEYS)], SINGLE_PARAMETER_KEYS)
        for phase in ('SCOPE_ADD_1', 'SCOPE_ADD_2', 'MOVE', 'BULK', 'INVENTORY', 'SCOPE_REMOVE'):
            self.assertRegex(params[f'CFP_WORST_{phase}'], r'^[0-9]+$')
        self.assertEqual(params['CFP_V2'], '1')
        self.assertEqual(params['CFP_SELF_ABORT_PCT'], '70')
        self.assertEqual(params['CFP_FAILED_BLOCK_ALL'], 'unchanged')
        self.assertEqual(params['CFP_PHONE_MAC'], PHONE['mac'])
        # The floor policy (and the enroll stage) never names the phone; v1 emits none of the v2 keys.
        self.assertNotIn(PHONE['mac'], params['CFP_POLICY'])
        v1, _ = self.parameters(self.write_config())
        self.assertEqual(list(v1), SINGLE_PARAMETER_KEYS)

    def test_execute_runs_v2_through_the_leg2_driver_and_never_for_a_missing_phase(self):
        config = self.write_config(**self.v2())
        sha = self.plan_details(config)['planSha256']
        # The template implements every v2 phase ...
        self.assertEqual(self.tool.IMPLEMENTED_PHASES, self.tool.PHASES + ('SCOPE',) + self.tool.NEW_PHASES)
        self.assertEqual(set(self.tool.pilot_phases(self.tool.load_config(config))) - set(self.tool.IMPLEMENTED_PHASES), set())
        # ... and the TTY commit legs have their driver (T4): a plan whose digest is not the approved one starts nothing.
        self.assertIs(self.tool.LEG2_DRIVER_IMPLEMENTED, True)
        code, out, err = self.invoke('execute', config, '--expect-plan-sha256', '0' * 64)
        self.assertEqual(code, 1)
        self.assertIn('differs from the disclosed value', err)
        self.assertNotIn('not implemented', err)
        self.assertFalse(self.ssh_log.exists())
        # A phase the template lacks is still refused first.
        with mock.patch.object(self.tool, 'IMPLEMENTED_PHASES', self.tool.PHASES):
            code, out, err = self.invoke('execute', config, '--expect-plan-sha256', sha)
        self.assertEqual(code, 1)
        self.assertIn('not implemented', err)

    def test_classification_accepts_new_phase_names(self):
        lines = ['MUTATION_BEGIN'] + [f'PHASE {name} OK' for name in V2_PHASES] + [self.tool.PASS_LINE]
        text = '\n'.join(lines) + '\n'
        outcome, code, phases = self.tool.classify(text, 0, False, tuple(V2_PHASES))
        self.assertEqual((outcome, code), ('PASS', 0))
        self.assertEqual(set(phases), set(V2_PHASES))
        skipped = text.replace('PHASE MOVE OK\n', '')
        self.assertEqual(self.tool.classify(skipped, 0, False, tuple(V2_PHASES))[0], 'FAIL')


    def policy_people(self, config, stage):
        return self.tool.expected_stage_policy(stage, config)['people']

    def test_expected_policy_is_built_per_stage_from_config_and_membership_is_exact(self):
        config = self.v2_config()
        chromebook, phone = PENN['mac'], PHONE['mac']
        both = sorted([chromebook, phone])
        self.assertEqual(self.policy_people(config, 'enroll'), [{'id': 'penn', 'macs': [chromebook]}])
        self.assertEqual(self.policy_people(config, 'enroll_phone'), [{'id': 'penn', 'macs': both}])
        self.assertEqual(self.policy_people(config, 'move'), [{'id': 'penn', 'macs': [phone]},
                                                              {'id': 'pilot_b', 'macs': [chromebook]}])
        self.assertEqual(self.policy_people(config, 'move_back'), [{'id': 'penn', 'macs': both}])
        for stage in STAGES:
            expected = self.tool.expected_stage_policy(stage, config)
            self.assertEqual((expected['pauses'], expected['schedules'], expected['doh']), ([], [], {'ipv4': [], 'ipv6': []}))
        with self.assertRaises(self.tool.Refusal):
            self.tool.expected_stage_policy('nope', config)
        wrong = {'enroll': [{'id': 'penn', 'macs': [phone]}],
                 'enroll_phone': [{'id': 'penn', 'macs': [chromebook]}],
                 'move': [{'id': 'pilot_b', 'macs': [phone]}],
                 'move_back': [{'id': 'penn', 'macs': [phone]}, {'id': 'pilot_b', 'macs': [chromebook]}]}
        for stage, people in wrong.items():
            policy = dict(self.tool.expected_stage_policy(stage, config), people=people)
            with self.subTest(stage), self.assertRaises(self.tool.Refusal):
                self.tool.assert_policy_pilot(policy, config, self.tool.expected_stage_policy(stage, config))
        # A stage-3 policy is not acceptable where stage 2 is expected, and vice versa.
        with self.assertRaises(self.tool.Refusal):
            self.tool.assert_policy_pilot(self.tool.expected_stage_policy('move', config), config,
                                          self.tool.expected_stage_policy('enroll_phone', config))

    def test_remote_timeout_is_capped_at_minimum_plus_slack(self):
        self.assertEqual(self.tool.V2_TIMEOUT_SLACK_SECONDS, 900)
        self.assertEqual(self.tool.remote_timeout_limit(5000), 5900)
        self.assertEqual(self.tool.remote_timeout_limit(10000), self.tool.V2_MAX_REMOTE_TIMEOUT_SECONDS)
        minimum = self.plan_details(self.write_config(**self.v2()))['minimumRemoteTimeoutSeconds']
        limit = minimum + 900
        details = self.plan_details(self.write_config(**self.v2(remoteTimeoutSeconds=limit)))
        self.assertEqual(details['remoteTimeoutSeconds'], limit)
        self.assertEqual(details['maximumRemoteTimeoutSeconds'], limit)
        self.refused_before_ssh(self.write_config(**self.v2(remoteTimeoutSeconds=limit + 1)), 'at most')
        self.refused_before_ssh(self.write_config(**self.v2(remoteTimeoutSeconds=10800)), 'minimumRemoteTimeoutSeconds')
        code, _, err = self.invoke('plan', self.write_config(**self.v2(remoteTimeoutSeconds=limit + 1)))
        self.assertIn(str(minimum), err)

    def test_v2_disclosure_echoes_scope_target_timeouts_and_break_glass(self):
        code, out, err = self.invoke('plan', self.write_config(**self.v2()))
        self.assertEqual(code, 0, err)
        minimum = self.plan_details(self.write_config(**self.v2()))['minimumRemoteTimeoutSeconds']
        tail = out[out.rindex('}') + 1:]
        self.assertIn(f'scope_target {PHONE["ip"]} {PHONE["mac"]}', tail)
        self.assertIn(f'minimumRemoteTimeoutSeconds {minimum}', tail)
        self.assertIn(f'maximumRemoteTimeoutSeconds {minimum + 900}', tail)
        self.assertIn('break-glass', tail)
        self.assertIn('manual password login on the router', tail)
        self.assertIn('never disabled', tail)
        # v1 prints none of it.
        self.assertNotIn('break-glass', self.invoke('plan', self.write_config())[1])

    def test_v2_protected_set_requires_ct107_adults_and_management(self):
        roles = self.config['roles']
        full = dict(roles, ct107=CT107, scope_target=PHONE)
        self.refused_before_ssh(self.write_config(**self.v2(roles=dict(roles, scope_target=PHONE))), 'ct107')
        self.refused_before_ssh(self.write_config(**self.v2(protectedHistoricalMacs=HISTORICAL)), 'ct107')
        self.refused_before_ssh(self.write_config(roles=dict(roles, ct107=CT107)), 'schemaVersion 2')
        for ct107, reason in ((dict(CT107, mac=MGMT['mac']), 'ct107'), (dict(CT107, mac=JD['mac']), 'ct107'),
                              (dict(CT107, ip=HOST), 'ct107'), (dict(CT107, ip=MGMT['ip']), 'ct107'),
                              (dict(CT107, mac='03:00:00:00:00:50'), 'unicast'), ({'ip': CT107['ip']}, 'ct107'), ('x', 'ct107')):
            with self.subTest(ct107=ct107):
                self.refused_before_ssh(self.write_config(**self.v2(roles=dict(full, ct107=ct107))), reason)
        config = self.v2_config()
        self.assertEqual(config['roles']['ct107'], CT107)
        protected = self.tool.protected_macs(config)
        self.assertLessEqual({MGMT['mac'], JD['mac'], CT107['mac'], *HISTORICAL}, protected)
        self.assertNotIn(PHONE['mac'], protected)
        self.assertEqual(self.plan_details(self.write_config(**self.v2()))['roles']['ct107'], CT107)

    def test_v2_digest_binds_roles_protected_profile_and_commit_and_is_mandatory(self):
        path = self.write_config(**self.v2())
        details = self.plan_details(path)
        other = copy.deepcopy(details['roles'])
        other['scope_target']['ip'] = '192.0.2.35'
        self.assertNotEqual(self.tool.plan_digest(dict(details, roles=other)), details['planSha256'])
        for field, other in (('protectedHistoricalMacs', ['02:00:00:00:00:41']), ('platformProfile', 'gl-xe3000-4.8.3-logd-011-v1'),
                             ('sourceCommit', '0' * 40)):
            with self.subTest(field):
                self.assertNotEqual(self.tool.plan_digest(dict(details, **{field: other})), details['planSha256'])
        for field in ('legs', 'pilotPolicies', 'failedBlockAllWording', 'failedBlockAllWordingDecidedBy',
                      'configSchemaVersion', 'roles', 'protectedHistoricalMacs', 'platformProfile', 'sourceCommit'):
            partial = {key: value for key, value in details.items() if key != field}
            with self.subTest(missing=field), self.assertRaises(self.tool.Refusal):
                self.tool.plan_digest(partial)
        # v1 keeps its field set: roles etc. are not bound outside v2.
        v1 = self.plan_details(self.write_config())
        self.assertEqual(self.tool.plan_digest(dict(v1, roles={}, sourceCommit='0' * 40)), v1['planSha256'])

    def test_loaded_config_keeps_its_real_schema_version(self):
        self.assertEqual(self.v2_config()['schemaVersion'], 2)
        self.assertEqual(self.tool.load_config(self.write_config())['schemaVersion'], 1)
        self.assertEqual(self.tool.config_schema_version(self.v2_config()), 2)

    def test_rehearsal_validator_rejects_the_pilot_example_and_readme_documents_v2(self):
        example = REPO / 'tools/live/config.pilot.example.json'
        with self.assertRaises(self.tool.Refusal):
            self.tool.FR.load_config(str(example))
        self.tool.load_config(str(example))
        self.assertIn('ct107', example.read_text())
        readme = (REPO / 'tools/live/README.md').read_text()
        for needle in ('schemaVersion` 2', 'scope_target', 'config.pilot.example.json', 'minimumRemoteTimeoutSeconds + 900',
                       'break-glass', '70%', 'roles.ct107', 'SCOPE-ADD-1', 'penn_pilot_leg2.py', 'CFP_LEG2_READY',
                       'remote_self_abort', 'teardown_proof', 'block_all_unchanged', 'CFP_WRAPPER_DIR'):
            with self.subTest(needle):
                self.assertIn(needle, readme)
        self.assertNotIn('TODO(T3)', readme)

    def test_penn_pilot_stays_under_the_file_size_cap_and_v2_pieces_live_in_a_sibling(self):
        self.assertLessEqual(len((REPO / 'tools/live/penn-pilot.py').read_text().splitlines()), 800)
        self.assertTrue((REPO / 'tools/live/penn_pilot_v2.py').is_file())
        self.assertEqual(set(self.tool.NEW_PHASES), set(self.tool.new_phase_worst_seconds(self.tool.TIMING)))
        self.assertEqual(self.tool.PHASES_V2, tuple(V2_PHASES))

    def test_shipped_worst_case_timings_are_pinned_exactly(self):
        shipped = dict(self.tool.TIMING, **SHIPPED_TIMING)
        v2 = self.tool.phase_worst_seconds(shipped, scope=True, scope_target=True)
        self.assertEqual(v2, {'ENROLL': 669, 'PAUSE': 480, 'RESUME': 360, 'EXPIRY': 892, 'DNS': 80, 'SCOPE': 180,
                              'SCOPE-ADD-1': 806, 'SCOPE-ADD-2': 1129, 'MOVE': 1562, 'BULK': 1606, 'INVENTORY': 538,
                              'SCOPE-REMOVE': 997})
        self.assertEqual(self.tool.worst_case_seconds(shipped), 3573)
        self.assertEqual(self.tool.worst_case_seconds(shipped, scope_target=True), 10211)
        self.assertEqual(self.tool.worst_case_seconds(shipped, scope=True, scope_target=True), 10391)

    def test_scope_negative_test_with_v2_orders_the_phase_and_budgets_it(self):
        details = self.plan_details(self.write_config(**self.v2(scopeNegativeTest=True)))
        phases = details['phases']
        self.assertEqual(phases[phases.index('SCOPE'):phases.index('SCOPE') + 2], ['SCOPE', 'SCOPE-ADD-1'])
        self.assertEqual(phases[phases.index('SCOPE') - 1], 'ENROLL')
        self.assertEqual([phase for phase in phases if phase != 'SCOPE'], V2_PHASES)
        self.assertEqual(details['minimumRemoteTimeoutSeconds'],
                         self.tool.worst_case_seconds(self.tool.TIMING, scope=True, scope_target=True))
        self.assertGreater(details['minimumRemoteTimeoutSeconds'],
                           self.plan_details(self.write_config(**self.v2()))['minimumRemoteTimeoutSeconds'])
        self.refused_before_ssh(self.write_config(**self.v2(scopeNegativeTest=True,
                                                            remoteTimeoutSeconds=details['minimumRemoteTimeoutSeconds'] - 1)),
                                'at least')

    def test_classify_requires_v2_phase_order_and_no_duplicates(self):
        expected = tuple(V2_PHASES)

        def text(names):
            return '\n'.join(['MUTATION_BEGIN'] + [f'PHASE {name} OK' for name in names] + [self.tool.PASS_LINE]) + '\n'
        self.assertEqual(self.tool.classify(text(V2_PHASES), 0, False, expected)[0], 'PASS')
        swapped = list(V2_PHASES)
        i, j = swapped.index('MOVE'), swapped.index('BULK')
        swapped[i], swapped[j] = swapped[j], swapped[i]
        self.assertEqual(self.tool.classify(text(swapped), 0, False, expected)[0], 'FAIL')
        doubled = V2_PHASES[:V2_PHASES.index('MOVE') + 1] + ['MOVE'] + V2_PHASES[V2_PHASES.index('MOVE') + 1:]
        self.assertEqual(self.tool.classify(text(doubled), 0, False, expected)[0], 'FAIL')
        self.assertEqual(self.tool.classify(text(V2_PHASES + ['SCOPE']), 0, False, expected)[0], 'FAIL')


class PilotFixtureTests(PilotBase):
    """End-to-end against the fixture router; slow (each run installs and uninstalls)."""

    def test_happy_path_passes_measures_and_restores_exactly(self):
        before = self.router_snapshot()
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 0, out + err + '\n'.join(stdout[-40:]))
        self.assertEqual(self.router_snapshot(), before)
        self.assertEqual(stdout[-1], 'PENN_PILOT_PASS')
        for phase in self.tool.PHASES:
            self.assertEqual(stdout.count(f'PHASE {phase} OK'), 1, phase)
        self.assertIn('MUTATION_BEGIN', stdout)
        self.assertTrue(any(line.startswith(f'INFO run install.sh --platform-profile strict --rpc-allow {PENN["mac"]} ')
                            for line in stdout))
        self.assertTrue(any(f'"observed":{{"kids":["{PENN["mac"]}"],"paused":[]}}' in line for line in stdout))
        summary = json.loads((self.evidence() / 'summary.json').read_text())
        self.assertEqual(summary['outcome'], 'PASS')
        self.assertNotIn('legs', summary)  # v1 has no leg-2 driver: its summary keeps the v1 key set
        self.assertFalse((self.evidence() / 'legs.json').exists())
        measured = summary['measurements']
        self.assertEqual(measured['packet_blocking']['label'], 'measured')
        self.assertRegex(measured['packet_blocking']['detail'], r'reject_delta=14 ')  # +7 per family
        self.assertEqual(measured['resume_unblock']['label'], 'measured')
        self.assertEqual(measured['timed_expiry']['label'], 'measured')
        self.assertEqual(measured['service_key_confinement']['label'], 'unmeasured')
        self.assertEqual(measured['dns_rule_doh']['label'], 'unmeasured')
        # etc= counts crond on /etc/crontabs (explicit -c/dir and default dir); GL's own crond is other.
        self.assertIn('baseline=etc2,other1 after_install=etc2,other1 during_expiry=etc2,other1 duplicate_etc_crond',
                      measured['crond_processes']['detail'])
        self.assertFalse(summary['pauseRulesKernelTimeBound'])
        argv = [json.loads(line) for line in self.ssh_log.read_text().splitlines()]
        self.assertEqual(len(argv), 1)

    def test_enroll_coverage_failure_captures_scoped_snapshot_once_and_restores(self):
        ipv6 = dict(ip='2001:db8::30', mac=PENN['mac'], state='STALE')
        self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'),
                                               dict(PENN, state='DELAY'), ipv6,
                                               dict(ip='2001:db8::99', mac='02:00:00:00:00:99', state='STALE')])
        shell = shlex.split(self.spec['shell'])
        program = shell[0]
        q = shlex.quote
        real, cfctl = q(shutil.which(program)), str(self.root / 'usr/sbin/cfctl')
        real_shell = ' '.join([real, *map(q, shell[1:])])
        rpc_log, accepted = self.work / 'rpc-count', self.work / 'accepted.json'
        reply = q('{"ok":false,"errors":["incomplete_transition_address_coverage"],"receipt":null}')
        self.router_double(program, (
            f'case " $* " in *{q(" " + cfctl + " rpc-sync ")}*)\n'
            f'  cat >/dev/null; echo rpc-sync >> {q(str(rpc_log))}\n'
            f'  {real_shell} {q(cfctl)} rpc-status --json > {q(str(accepted))}\n'
            f'  echo {reply}\n'
            '  exit 1;; esac\n'
            f'exec {real} "$@"\n'))
        before = self.router_snapshot()
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertEqual(code, 2, out + err + stdout[-4000:])
        self.assertRegex(stdout, r'coverage_diag neighbor ip6-[0-9a-f]{12} ')
        self.assertNotIn('2001:db8::30', stdout)
        self.assertIn('state=STALE', stdout)
        self.assertNotIn('2001:db8::99', stdout)
        self.assertLess(stdout.index('coverage_diag non_atomic'), stdout.index('STOP ENROLL rpc_sync_failed'))
        self.assertEqual(rpc_log.read_text().splitlines(), ['rpc-sync'])
        self.assertEqual(json.loads(accepted.read_text())['acceptedPolicy']['revision'], 0)
        self.assertEqual(stdout.count('PHASE UNINSTALL OK'), 1)
        self.assertIn('PHASE RESTORE OK', stdout)
        self.assertIn('PENN_PILOT_STOPPED_RESTORED', stdout)
        self.assertEqual(self.router_snapshot(), before)

    def test_adult_disruption_stops_and_always_tears_down(self):
        self.spec['touch_on']['INFO pause_observe_begin'] = str(self.dns_fail)
        before = self.router_snapshot()
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 2, out + err)
        self.assertIn('STOP PAUSE adult_disruption router_dns_failed', stdout)
        self.assertIn('PHASE UNINSTALL OK', stdout)
        self.assertIn('PHASE RESTORE OK', stdout)
        self.assertEqual(stdout[-1], 'PENN_PILOT_STOPPED_RESTORED')
        self.assertNotIn('PENN_PILOT_PASS', stdout)
        self.assertNotIn('PHASE RESUME OK', stdout)
        self.assertEqual(self.router_snapshot(), before)
        summary = json.loads((self.evidence() / 'summary.json').read_text())
        self.assertEqual(summary['outcome'], 'STOPPED')

    def test_ambiguous_or_stale_penn_refused_before_mutation(self):
        cases = (([dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'), dict(PENN, state='STALE')], 'penn_child_not_fresh'),
                 ([dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'), dict(PENN, state='DELAY'),
                   {'ip': '192.0.2.31', 'mac': PENN['mac'], 'state': 'STALE'}], 'penn_child_mac_ambiguous'))
        before = self.router_snapshot()
        for neighbors, reason in cases:
            self.fixture.update_backend(neighbors=neighbors)
            code, out, err = self.execute()
            stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
            self.assertEqual(code, 1, out + err)
            self.assertIn(f'PHASE IDENTITY FAIL {reason}', stdout)
            self.assertNotIn('MUTATION_BEGIN', stdout)
            self.assertEqual(self.router_snapshot(), before)
            shutil.rmtree(self.evidence())


    def adult_alias_pass(self, second):
        roles = dict(self.config['roles'], jd_adult=MGMT)
        devices = [MGMT, PENN]
        if second:
            roles['penn_child_2'] = PENN2
            devices.append(PENN2)
        self.fixture.update_backend(neighbors=[dict(role, state='REACHABLE') for role in devices])
        leases = self.root / 'tmp/dhcp.leases'
        leases.write_text(''.join(f'1800000000 {role["mac"]} {role["ip"]} host *\n' for role in devices))
        # Observe installed protection, before teardown removes it.
        protection = self.work / 'installed-protection'
        firewall = self.fixture.bin / 'ipset'
        real = self.fixture.bin / 'ipset.real'
        firewall.rename(real)
        protected = self.root / 'etc/couvrefeu/protected'
        firewall.write_text(f'#!/bin/sh\nif [ -f {shlex.quote(str(protected))} ]; then '
                            f'cat {shlex.quote(str(protected))} > {shlex.quote(str(protection))}; fi\n'
                            f'exec {shlex.quote(str(real))} "$@"\n')
        firewall.chmod(0o700)
        before = self.router_snapshot()
        code, out, err = self.execute(roles=roles, scopeNegativeTest=True, remoteTimeoutSeconds=4200)
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertEqual(code, 0, out + err + stdout[-5000:])
        self.assertIn('PENN_PILOT_PASS', stdout)
        self.assertIn('adult baseline management=jd_adult same_confirmed_device', stdout)
        self.assertIn('PHASE SCOPE OK', stdout)
        self.assertIn('"errors":["rpc_scope_overlap"]', stdout)
        self.assertEqual(sorted(protection.read_text().splitlines()), sorted([MGMT['mac'], *HISTORICAL]))
        self.assertEqual(self.router_snapshot(), before)

    def test_single_child_exact_adult_alias_passes_and_preserves_protection(self):
        self.adult_alias_pass(second=False)

    def test_two_children_exact_adult_alias_passes_and_preserves_protection(self):
        self.adult_alias_pass(second=True)

    def test_two_devices_with_scope_negative_test_pass_and_restore_exactly(self):
        changes = self.two_devices(scopeNegativeTest=True)
        before = self.router_snapshot()
        code, out, err = self.execute(**changes)
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 0, out + err + '\n'.join(stdout[-60:]))
        self.assertEqual(self.router_snapshot(), before)
        self.assertEqual(stdout[-1], 'PENN_PILOT_PASS')
        macs = sorted([PENN['mac'], PENN2['mac']])
        kids = json.dumps(macs, separators=(',', ':'))
        phases = self.tool.pilot_phases(self.tool.load_config(self.write_config(**changes)))
        self.assertIn('SCOPE', phases)
        for phase in phases:
            self.assertEqual(stdout.count(f'PHASE {phase} OK'), 1, phase)
        self.assertTrue(any(line.startswith(f'INFO run install.sh --platform-profile strict --rpc-allow {macs[0]} '
                                            f'--rpc-allow {macs[1]} --protect ') for line in stdout))
        self.assertTrue(any(f'"observed":{{"kids":{kids},"paused":[]}}' in line for line in stdout))
        self.assertTrue(any(f'"paused":{kids}' in line for line in stdout))
        self.assertTrue(any(line.startswith('INFO scope rpc-sync exit=1 ') and '"errors":["rpc_scope_overlap"]' in line
                            and '"receipt":null' in line for line in stdout))
        summary = json.loads((self.evidence() / 'summary.json').read_text())
        self.assertEqual(summary['outcome'], 'PASS')
        measured = summary['measurements']
        self.assertEqual(measured['scope_negative']['label'], 'measured')
        self.assertIn('filter_ipset_slot_unchanged', measured['scope_negative']['detail'])
        self.assertEqual(measured['packet_blocking']['label'], 'measured')
        self.assertRegex(measured['packet_blocking']['detail'], r'reject_delta=14 .*devices=2 aggregate')
        self.assertIn(measured['rpc_activity_devices']['label'], ('measured', 'unmeasured'))
        self.assertEqual(len(self.ssh_log.read_text().splitlines()), 1)

    def test_tampered_device_set_parameter_refused_before_mutation(self):
        changes = self.two_devices()
        macs = sorted([PENN['mac'], PENN2['mac']])
        real_allow = f"CFP_RPC_ALLOW='{' '.join(macs)}'\n"
        real_kids = f"CFP_KIDS_JSON='{json.dumps(macs, separators=(',', ':'))}'\n"
        tampers = ((real_allow, f"CFP_RPC_ALLOW='{macs[0]} 02:00:00:00:00:77'\n"),
                   (real_kids, f"CFP_KIDS_JSON='{json.dumps([macs[0], '02:00:00:00:00:77'], separators=(',', ':'))}'\n"))
        original = self.tool.build_payload
        before = self.router_snapshot()
        for old, new in tampers:
            def tampered(*args, **kwargs):
                payload, *rest = original(*args, **kwargs)
                text = payload.decode()
                self.assertEqual(text.count(old), 1)
                return (text.replace(old, new).encode(), *rest)
            with self.subTest(param=new.split('=')[0]), mock.patch.object(self.tool, 'build_payload', tampered):
                code, out, err = self.execute(**changes)
                stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
                self.assertEqual(code, 1, out + err)
                self.assertIn('PHASE PAYLOAD FAIL device_set_mismatch', stdout)
                self.assertIn('REFUSED_BEFORE_MUTATION PAYLOAD', stdout)
                self.assertNotIn('MUTATION_BEGIN', stdout)
                self.assertFalse(any(line.startswith('INFO run install.sh') for line in stdout))
                self.assertEqual(self.router_snapshot(), before)
                shutil.rmtree(self.evidence())

    def test_scope_mac_on_live_router_refused_at_identity(self):
        scope = {'ip': '192.0.2.40', 'mac': '02:00:00:00:00:99'}
        leases = self.root / 'tmp/dhcp.leases'
        original = leases.read_text()
        before = self.router_snapshot()
        for where in ('neighbor', 'lease'):
            with self.subTest(where=where):
                if where == 'neighbor':
                    self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'),
                                                           dict(PENN, state='DELAY'), dict(scope, state='STALE')])
                else:
                    self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'),
                                                           dict(PENN, state='DELAY')])
                    leases.write_text(original + f'1800000000 {scope["mac"]} {scope["ip"]} ghost *\n')
                    before = self.router_snapshot()
                code, out, err = self.execute(scopeNegativeTest=True)
                stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
                self.assertEqual(code, 1, out + err + '\n'.join(stdout[-20:]))
                self.assertIn('PHASE IDENTITY FAIL scope_mac_present', stdout)
                self.assertNotIn('MUTATION_BEGIN', stdout)
                self.assertEqual(self.router_snapshot(), before)
                shutil.rmtree(self.evidence())

    def scope_doubles(self, mode):
        """Router-side doubles keyed on the SCOPE fingerprint's ipset read (stdout is <stage>/pilot/fw.ipset).

        firewall: the second fingerprint read reports one extra cf* ipset line (the router itself is untouched).
        band: from the first fingerprint read, the next 71 `date +%S` reads fall outside the safe band
        (and `sleep` returns at once), so the SCOPE rpc-sync is never sent; later reads are real."""
        seen, count = self.work / 'fw-seen', self.work / 'band-count'
        q = shlex.quote
        if mode == 'firewall':
            on_first, on_second = ':', f'{q(str(self.fixture.bin / "ipset"))} "$@" || exit $?; echo "add cf2_x_fake 192.0.2.250"; exit 0'
        else:
            on_first, on_second = f'echo 0 > {q(str(count))}', ':'
        doubles = {
            'ipset': (f'case $(readlink /proc/$$/fd/1 2>/dev/null) in */pilot/fw.ipset)\n'
                      f'  if [ -e {q(str(seen))} ]; then {on_second}; else : > {q(str(seen))}; {on_first}; fi;;\nesac\n'
                      f'exec {q(str(self.fixture.bin / "ipset"))} "$@"\n'),
            'date': (f'if [ "$1" = +%S ] && [ -e {q(str(count))} ]; then n=$(cat {q(str(count))})\n'
                     f'  if [ "$n" -lt 71 ]; then echo $((n + 1)) > {q(str(count))}; echo 60; exit 0; fi\nfi\n'
                     f'exec {q(shutil.which("date"))} "$@"\n'),
            'sleep': (f'if [ -e {q(str(count))} ] && [ "$(cat {q(str(count))})" -lt 71 ]; then exit 0; fi\n'
                      f'exec {q(shutil.which("sleep"))} "$@"\n')}
        for name, body in doubles.items():
            path = self.rbin / name
            path.write_text('#!/bin/sh\n' + body)
            path.chmod(0o700)

    def assert_scope_stop_torn_down_once(self, reason, before):
        code, out, err = self.execute(scopeNegativeTest=True)
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 2, out + err + '\n'.join(stdout[-40:]))
        self.assertIn(f'STOP SCOPE {reason}', stdout)
        self.assertEqual(sum(line.startswith('INFO run uninstall.sh once') for line in stdout), 1)
        self.assertEqual(stdout.count('PHASE UNINSTALL OK'), 1)
        self.assertIn('PHASE RESTORE OK', stdout)
        self.assertNotIn('PHASE PAUSE OK', stdout)
        self.assertNotIn('PENN_PILOT_PASS', stdout)
        self.assertEqual(stdout[-1], 'PENN_PILOT_STOPPED_RESTORED')
        self.assertEqual(self.router_snapshot(), before)
        self.assertEqual(json.loads((self.evidence() / 'summary.json').read_text())['outcome'], 'STOPPED')
        return stdout

    def test_scope_firewall_change_stops_and_tears_down_once(self):
        self.scope_doubles('firewall')
        before = self.router_snapshot()
        stdout = self.assert_scope_stop_torn_down_once('firewall_changed', before)
        self.assertEqual(sum(line.startswith('INFO scope rpc-sync exit=') for line in stdout), 1)

    def test_scope_safe_band_never_opening_stops_and_tears_down_once(self):
        self.scope_doubles('band')
        before = self.router_snapshot()
        stdout = self.assert_scope_stop_torn_down_once('safe_band_unavailable', before)
        self.assertIn('PHASE SCOPE FAIL safe_band_unavailable', stdout)
        self.assertFalse(any(line.startswith('INFO scope rpc-sync exit=') for line in stdout))
        self.assertNotIn('STOP SCOPE scope_not_cleanly_rejected', stdout)

    def router_double(self, name, body):
        path = self.rbin / name
        path.write_text('#!/bin/sh\n' + body)
        path.chmod(0o700)

    def status_double(self, rewrite, count, skip=0):
        """Double of the fixture's CFR_SH program from PATH (`sh`, or `busybox` for `busybox ash`): logs every
        `cfctl rpc-sync` and pipes `count` `cfctl status --json` replies after the first rpc-sync, from the
        one after the first `skip`, through sed `rewrite`. Every call still runs the real cfctl exactly once."""
        program = shlex.split(self.spec['shell'])[0]
        q = shlex.quote
        real, cfctl = q(shutil.which(program)), str(self.root / 'usr/sbin/cfctl')
        self.rpc_log, count_file = self.work / 'rpc-sync.log', self.work / 'status-rewrites'
        self.router_double(program, (
            f'case " $* " in\n'
            f'  *{q(" " + cfctl + " rpc-sync ")}*) echo rpc-sync >> {q(str(self.rpc_log))};;\n'
            f'  *{q(" " + cfctl + " status --json ")}*)\n'
            f'    n=$(cat {q(str(count_file))} 2>/dev/null || echo 0)\n'
            f'    [ -s {q(str(self.rpc_log))} ] && echo $((n + 1)) > {q(str(count_file))}\n'
            f'    if [ -s {q(str(self.rpc_log))} ] && [ "$n" -ge {skip} ] && [ "$n" -lt {skip + count} ]; then\n'
            f'      out=$({real} "$@"); rc=$?\n'
            f'      printf "%s\\n" "$out" | sed {q(rewrite)}\n'
            f'      exit $rc\n'
            f'    fi;;\n'
            f'esac\n'
            f'exec {real} "$@"\n'))

    DRIFT = 's/"ok":true,/"ok":false,/;s/"drift":false,/"drift":true,/'

    def assert_enroll_stop_torn_down_once(self, before):
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 2, out + err + '\n'.join(stdout[-40:]))
        self.assertIn('STOP ENROLL penn_not_observed', stdout)
        self.assertEqual(self.rpc_log.read_text().splitlines(), ['rpc-sync'])
        self.assertEqual(sum(line.startswith('INFO run uninstall.sh once') for line in stdout), 1)
        self.assertEqual(stdout.count('PHASE UNINSTALL OK'), 1)
        self.assertIn('PHASE RESTORE OK', stdout)
        self.assertNotIn('PHASE ENROLL OK', stdout)
        self.assertEqual(stdout[-1], 'PENN_PILOT_STOPPED_RESTORED')
        self.assertEqual(self.router_snapshot(), before)
        self.assertEqual(json.loads((self.evidence() / 'summary.json').read_text())['outcome'], 'STOPPED')
        return stdout

    def test_transient_drift_after_rpc_sync_settles_with_one_rpc_sync(self):
        # (a) drift:true, errors:[] on the first status read after rpc-sync, then clean: ENROLL passes, and the
        # stale-on-arrival device is refreshed by the IDENTITY probe (d).
        self.stale_penn_refreshed_by_probe(refreshes=True)
        self.status_double(self.DRIFT, 1)
        before = self.router_snapshot()
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 0, out + err + '\n'.join(stdout[-40:]))
        self.assertEqual(stdout[-1], 'PENN_PILOT_PASS')
        self.assertEqual(self.rpc_log.read_text().splitlines(), ['rpc-sync'])
        self.assertTrue(any('"drift":true,' in line and line.startswith('INFO status ') for line in stdout))
        self.assertTrue(any(re.fullmatch(r'INFO status_settle ENROLL attempts=2 waited_s=[0-9]+', line) for line in stdout))
        self.assertTrue(any(line.startswith('INFO status_settle_neigh ENROLL attempt=2 ') for line in stdout))
        self.assertTrue(any(re.fullmatch(r'INFO status_settle EXPIRY attempts=1 waited_s=[0-9]+', line) for line in stdout))
        self.assertIn('INFO identity refresh_probe penn_child ping_count=2 network_probe_only', stdout)
        self.assertIn(PENN['ip'], self.ping_log.read_text())
        self.assertEqual(self.router_snapshot(), before)

    def test_transient_drift_after_expiry_settles_at_the_accounted_revision(self):
        # Only the post-expiry status read drifts: its settle must expect revision 4 (enroll, pause, resume,
        # expiry pause; cron expire keeps it) and pass.
        self.status_double(self.DRIFT, 1, skip=1)
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 0, out + err + '\n'.join(stdout[-40:]))
        self.assertEqual(stdout[-1], 'PENN_PILOT_PASS')
        self.assertTrue(any(re.fullmatch(r'INFO status_settle ENROLL attempts=1 waited_s=[0-9]+', line) for line in stdout))
        self.assertTrue(any(re.fullmatch(r'INFO status_settle EXPIRY attempts=2 waited_s=[0-9]+', line) for line in stdout))
        self.assertTrue(any(re.fullmatch(r'MEASURE status_settle measured settled_after_drift phase=EXPIRY attempts=2 '
                                         r'waited_s=[0-9]+', line) for line in stdout), '\n'.join(stdout[-40:]))

    def test_persistent_drift_stops_enroll_after_settle_and_restores(self):
        # (b) drift past the settle window: STOP penn_not_observed, one teardown, exact restore, one rpc-sync.
        self.status_double(self.DRIFT, 1000)
        stdout = self.assert_enroll_stop_torn_down_once(self.router_snapshot())
        self.assertTrue(any(re.fullmatch(r'INFO status_settle ENROLL attempts=[2-9][0-9]* waited_s=[0-9]+ gave_up', line)
                            for line in stdout), '\n'.join(stdout[-40:]))

    def test_status_errors_stop_enroll_on_first_read(self):
        # (c) errors:["x"] is never waited out.
        self.status_double(self.DRIFT + r';s/"errors":\[\]}$/"errors":["x"]}/', 1000)
        stdout = self.assert_enroll_stop_torn_down_once(self.router_snapshot())
        self.assertTrue(any(re.fullmatch(r'INFO status_settle ENROLL attempts=1 waited_s=[0-9]+ not_transient', line)
                            for line in stdout))
        self.assertFalse(any(line.startswith('INFO status_settle_neigh ENROLL attempt=2') for line in stdout))

    def stale_penn_refreshed_by_probe(self, refreshes, probe_succeeds=True, refreshed_state='REACHABLE'):
        """Penn arrives STALE; the `ping` double logs its targets and, if `refreshes`, the `ip` double then
        reports Penn's row REACHABLE (as the kernel does once the device answers ARP)."""
        self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'),
                                               dict(PENN, state='STALE')])
        q = shlex.quote
        self.ping_log, flag = self.work / 'ping.log', self.work / 'penn-refreshed'
        ping = (self.rbin / 'ping').read_text().split('\n', 1)[1]
        self.router_double('ping', f'echo "$*" >> {q(str(self.ping_log))}\n'
                           + (f'case " $* " in *" {PENN["ip"]} "*) : > {q(str(flag))};; esac\n' if refreshes else '')
                           + (f'case " $* " in *" {PENN["ip"]} "*) exit 1;; esac\n' if not probe_succeeds else '')
                           + ping)
        self.router_double('ip', f'out=$({q(str(self.fixture.bin / "ip"))} "$@") || exit $?\n'
                           f'if [ -e {q(str(flag))} ]; then printf "%s\\n" "$out" | '
                           f'sed {q("s/^" + PENN["ip"].replace(".", "[.]") + " \\(.*\\) STALE$/" + PENN["ip"] + " \\1 " + refreshed_state + "/")}\n'
                           'else printf "%s\\n" "$out"; fi\n')

    def test_failed_refresh_probe_moving_stale_to_delay_refused_before_mutation(self):
        # Sending alone can move STALE to DELAY; no reply means no renewed freshness evidence.
        self.stale_penn_refreshed_by_probe(refreshes=True, probe_succeeds=False, refreshed_state='DELAY')
        before = self.router_snapshot()
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 1, out + err)
        self.assertIn('PHASE IDENTITY FAIL penn_child_not_fresh', stdout)
        self.assertEqual(self.ping_log.read_text().splitlines(), [f'-c 2 -W 1 -q {PENN["ip"]}'])
        self.assertNotIn('MUTATION_BEGIN', stdout)
        self.assertEqual(self.router_snapshot(), before)

    def test_stale_penn_not_refreshed_by_probe_refused_before_mutation(self):
        # (d) the probe ran, Penn stayed stale: the existing refusal, before any mutation.
        self.stale_penn_refreshed_by_probe(refreshes=False)
        before = self.router_snapshot()
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 1, out + err)
        self.assertIn('PHASE IDENTITY FAIL penn_child_not_fresh', stdout)
        self.assertIn('INFO identity refresh_probe penn_child ping_count=2 network_probe_only', stdout)
        self.assertEqual(self.ping_log.read_text().splitlines(), [f'-c 2 -W 1 -q {PENN["ip"]}'])
        self.assertNotIn('MUTATION_BEGIN', stdout)
        self.assertEqual(self.router_snapshot(), before)

    def test_second_device_stale_refused_before_mutation(self):
        changes = self.two_devices()
        self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'),
                                               dict(PENN, state='DELAY'), dict(PENN2, state='STALE')])
        before = self.router_snapshot()
        code, out, err = self.execute(**changes)
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        self.assertEqual(code, 1, out + err)
        self.assertIn('PHASE IDENTITY FAIL penn_child_2_not_fresh', stdout)
        self.assertNotIn('MUTATION_BEGIN', stdout)
        self.assertEqual(self.router_snapshot(), before)


PRELUDE = r'''
H=%(h)s
CFR_STAGE=$H/stage
mkdir -p "$CFR_STAGE/pilot" "$H/root"
CFP_DIR=$CFR_STAGE/pilot
CFR_SH=sh
CFR_FIXTURE=1
CFR_ROOT=$H/root
CFR_START=$(date +%%s)
CFP_START_CS=$(cfp_cs)
CFR_CFCTL=$CFR_ROOT/usr/sbin/cfctl
cfp_safe_band() { return 0; }
%(stop)s
cfp_v2_check || { echo 'V2CHECK_FAILED'; exit 66; }
%(driver)s
'''

# A tiny rpc model: files rev, scopesha, scopejson under $H; status/sync stubs read and write them.
RPC_STUBS = r'''
G=0000000000000000000000000000000000000000000000000000000000000001
D=0000000000000000000000000000000000000000000000000000000000000002
cfp_cfctl() {
    case "$1" in
        rpc-status)
            # `rpc-status --json <op>` answers with that operation's receipt(s): RECEIPTS copies (default one).
            r=null
            if [ -n "$3" ]; then
                r=$(n=${RECEIPTS:-1}; while [ "$n" -gt 0 ]; do printf '{"operationId":"%s","requestDigest":"aa","baseRevision":1,"baseDigest":"bb","acceptedRevision":2,"acceptedDigest":"cc","outcome":"accepted","current":true}' "$3"; n=$((n - 1)); done)
                [ -n "$r" ] || r=null
            fi
            printf '{"rpc_version":1,"generation":"%s","acceptedPolicy":{"version":1,"revision":%s,"people":[],"pauses":[]},"policyDigest":"%s","currentOperationId":null,"routerTime":1,"receipt":%s,"status":{},"errors":[],"scope":[%s],"scopeSha":"%s"}\n' \
                "$G" "$(cat "$H/rev")" "$D" "$r" "$(cat "$H/scopejson")" "$(cat "$H/scopesha")";;
        *) return 1;;
    esac
}
cfp_scope_file_sha() { cat "$H/filesha"; }
cfp_cfctl_input() {
    echo sync >> "$H/calls"
    op=$(sed -n 's/.*"operation_id":"\([^"]*\)".*/\1/p' "$1")
    cp "$1" "$H/request.$op.json"
    r=$(cat "$H/rev"); n=$((r + 1)); echo "$n" > "$H/rev"
    printf '{"rpc_version":1,"generation":"%s","receipt":{"operationId":"%s","requestDigest":"%s","baseRevision":%s,"baseDigest":"%s","acceptedRevision":%s,"acceptedDigest":"%s","outcome":"accepted","current":true},"errors":[]}\n' "$G" "$op" "$D" "$r" "$D" "$n" "$D"
}
cfp_status_settle() { echo settle >> "$H/calls"; }
cfp_observe() { echo observe >> "$H/calls"; }
cfp_fw_shape() { printf 'shape\n' > "$1"; }
cfp_slot() { echo a; }
cfp_penn_state() { cat "$H/penn_state"; }
cfp_chain_counts() { echo "chain $1" >> "$H/calls"; cat "$H/chain$1" ; }
'''


def device_json(mac, host=None):
    name = 'null' if host is None else f'"{host}"'
    return f'{{"mac":"{mac}","ipv4":["192.0.2.9"],"hostname":{name},"source":"both"}}'


def inventory_reply(macs, hosts=None, truncated='false', errors=''):
    hosts = hosts or {}
    devices = ','.join(device_json(mac, hosts.get(mac)) for mac in macs)
    return ('{"inventory_version":1,"generation":"' + 'a' * 64 + '","routerTime":1800000100,"devices":[' + devices
            + f'],"truncated":{truncated},"errors":[{errors}]}}')


SENTINEL_HOST = 'sentinel-host-9f3c'
SENTINEL_MAC = '02:00:00:00:00:77'
SENTINEL_IP = '192.0.2.77'


class PilotShellBase(PilotBase):
    """Function-level harness: the generated v2 payload minus its final call, run under `sh` with a driver that
    stubs the router (seconds per run instead of minutes). It runs the template's own functions."""
    TAIL = '# Parse everything above first; no child can read the remaining script.\ncfp_main </dev/null'

    def v2_changes(self, **changes):
        roles = dict(self.config['roles'], ct107=CT107, scope_target=PHONE)
        changes.setdefault('protectedHistoricalMacs', HISTORICAL + [CT107['mac']])
        # The v2 local timeout is far longer than v1's: the authorization deadline must outlast it.
        changes.setdefault('deadlineUtc', (self.now + datetime.timedelta(hours=5)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        # The harness hardcodes remoteTimeoutSeconds=10000 unless a test overrides it: a fixed test value that sits
        # inside the v2 range but does NOT come from the plan's minimumRemoteTimeoutSeconds (min + 900), so it
        # bypasses the plan's own sizing/validation of the timeout. Production configs get no such default.
        return dict(changes, schemaVersion=2, roles=roles, remoteTimeoutSeconds=changes.get('remoteTimeoutSeconds', 10000))

    STUB_STOP = 'cfp_stop() { printf \'STOP %s %s\\n\' "$1" "$2"; exit 77; }'

    def run_driver(self, driver, files=None, params=None, timeout=120, stub_stop=True):
        _, payload = self.parameters(self.write_config(**self.v2_changes()))
        head = payload[:payload.rindex(self.TAIL)]
        for key, value in (params or {}).items():
            head += f"\n{key}='{value}'"
        home = self.work / 'harness'
        shutil.rmtree(home, ignore_errors=True)
        home.mkdir()
        for name, text in (files or {}).items():
            (home / name).write_text(text)
        (home / 'script.sh').write_text(head + '\n' + PRELUDE % {'h': shlex.quote(str(home)), 'driver': driver,
                                                                  'stop': self.STUB_STOP if stub_stop else ':'})
        env = {'PATH': os.environ['PATH'], 'LC_ALL': 'C', 'HOME': str(home)}
        done = subprocess.run(['sh', str(home / 'script.sh')], env=env, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=timeout, check=False)
        done.home = home
        return done

    def stop_of(self, done):
        return [line for line in done.stdout.splitlines() if line.startswith('STOP ')]

    @staticmethod
    def scope_sha(macs):
        """The router's scopeSha: sha256 of the C-sorted MACs, one per line."""
        return hashlib.sha256(''.join(mac + '\n' for mac in sorted(macs)).encode()).hexdigest()

    def rpc_files(self, rev=8, scope=(PENN['mac'],)):
        return {'rev': f'{rev}\n', 'scopesha': self.scope_sha(scope) + '\n', 'filesha': self.scope_sha(scope) + '\n',
                'scopejson': ','.join(f'"{mac}"' for mac in scope) + '\n'}


class PilotShellInventoryTests(PilotShellBase):
    """INVENTORY: counts, shape and hashes only; the raw reply (hostnames, non-Penn MACs) is never printed."""

    DRIVER = r'''
cfp_run() { cat "$H/reply"; return "${REPLY_RC:-0}"; }
cfp_wrapper_run() { cat "$H/reply"; return "${WRAPPER_RC:-0}"; }
cfp_inventory_phase
echo "LEFT:$(ls "$CFP_DIR" | tr '\n' ' ')"
'''

    def inventory(self, reply, rc=0, wrapper_rc=0, wrapper_reply=None):
        driver = f'REPLY_RC={rc}\nWRAPPER_RC={wrapper_rc}\n' + self.DRIVER
        return self.run_driver(driver, files={'reply': reply + '\n'})

    def good_reply(self, **changes):
        macs = [PENN['mac'], PHONE['mac'], SENTINEL_MAC]
        return inventory_reply(macs, hosts={SENTINEL_MAC: SENTINEL_HOST, PENN['mac']: 'chromebook-x'}, **changes)

    def test_good_reply_is_summarised_without_hostnames_or_foreign_macs(self):
        done = self.inventory(self.good_reply())
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('PHASE INVENTORY OK', done.stdout)
        line = next(line for line in done.stdout.splitlines() if line.startswith('MEASURE inventory measured '))
        self.assertRegex(line, r'device_counts=3,3,3 protected_listed=0 penn_devices_listed=2 truncated=false bytes=[0-9]+ '
                               r'shape=[0-9a-f]{12} reply_salted_sha256=[0-9a-f]{12} elapsed_ms=[0-9]+,[0-9]+,[0-9]+ '
                               r'wrapper_rpc_only=same_shape$')
        for leaked in (SENTINEL_HOST, SENTINEL_MAC, 'chromebook-x'):
            self.assertNotIn(leaked, done.stdout)
            self.assertNotIn(leaked, done.stderr)
        # Raw replies are removed as soon as they are summarised, not only at cleanup.
        self.assertRegex(done.stdout, r'LEFT:\s*$')
        self.assertFalse(list((done.home / 'stage/pilot').glob('inventory*')))

    def test_salted_hash_differs_per_run_but_shape_is_stable(self):
        first = self.inventory(self.good_reply())
        second = self.inventory(self.good_reply())
        pick = lambda done, key: re.search(key + r'=([0-9a-f]{12})', done.stdout).group(1)  # noqa: E731
        self.assertEqual(pick(first, 'shape'), pick(second, 'shape'))
        self.assertNotEqual(pick(first, 'reply_salted_sha256'), pick(second, 'reply_salted_sha256'))

    def test_device_count_may_vary_between_samples_but_the_shape_may_not(self):
        # A guest joins between samples: counts are recorded per sample, only the shape is compared.
        more = inventory_reply([PENN['mac'], PHONE['mac'], SENTINEL_MAC, '02:00:00:00:00:78'])
        driver = ('cfp_run() { n=$(cat "$H/n" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$H/n"; '
                  'if [ "$n" = 2 ]; then cat "$H/reply2"; else cat "$H/reply"; fi; }\n'
                  'cfp_wrapper_run() { cat "$H/reply"; }\ncfp_inventory_phase\n')
        done = self.run_driver(driver, files={'reply': self.good_reply() + '\n', 'reply2': more + '\n'})
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('device_counts=3,4,3 ', done.stdout)
        reshaped = self.good_reply().replace('"truncated"', '"extra":1,"truncated"')
        done = self.run_driver(driver, files={'reply': self.good_reply() + '\n', 'reply2': reshaped + '\n'})
        self.assertEqual(self.stop_of(done), ['STOP INVENTORY inventory_shape_changed'])

    def test_truncated_flag_is_recorded(self):
        done = self.inventory(self.good_reply(truncated='true'))
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertIn('truncated=true', done.stdout)

    def test_protected_device_in_the_listing_stops(self):
        for protected in (MGMT['mac'], JD['mac'], HISTORICAL[0], CT107['mac']):
            with self.subTest(protected=protected):
                reply = inventory_reply([PENN['mac'], PHONE['mac'], protected], hosts={protected: SENTINEL_HOST})
                done = self.inventory(reply)
                self.assertEqual(self.stop_of(done), ['STOP INVENTORY inventory_protected_device_listed'])
                self.assertNotIn('PHASE INVENTORY OK', done.stdout)
                self.assertNotIn(SENTINEL_HOST, done.stdout + done.stderr)
                self.assertNotIn(protected, done.stdout + done.stderr)

    def test_a_missing_penn_device_stops(self):
        for macs in ([PENN['mac']], [PHONE['mac']], [SENTINEL_MAC]):
            with self.subTest(macs=macs):
                done = self.inventory(inventory_reply(macs + [SENTINEL_MAC]))
                self.assertEqual(self.stop_of(done), ['STOP INVENTORY inventory_penn_device_missing'])

    def test_old_router_and_broken_replies_stop_with_a_reason(self):
        cases = {'invalid_command': ('{"ok":false,"errors":["invalid_command"]}', 2, 'inventory_unsupported exit=2'),
                 'empty': ('', 2, 'inventory_unsupported exit=2'),
                 'errors': (self.good_reply().replace('"errors":[]', '"errors":["inventory_unavailable"]'), 1,
                            'inventory_reply_errors_inventory_unavailable'),
                 'two lines': (self.good_reply() + '\n' + self.good_reply(), 0, 'inventory_not_one_line'),
                 'not v1': ('{"inventory_version":2}', 0, 'inventory_not_inventory_v1')}
        for name, (reply, rc, reason) in cases.items():
            with self.subTest(case=name):
                done = self.inventory(reply, rc=rc)
                self.assertEqual(self.stop_of(done), [f'STOP INVENTORY {reason}'], done.stdout)
                self.assertNotIn(SENTINEL_HOST, done.stdout + done.stderr)

    def test_reply_at_the_size_limit_stops(self):
        reply = inventory_reply([PENN['mac'], PHONE['mac']])
        padded = reply.replace('],"truncated"', ',' + device_json(SENTINEL_MAC, SENTINEL_HOST * 8000) + '],"truncated"')
        self.assertGreater(len(padded), 131072)
        done = self.inventory(padded)
        self.assertEqual(self.stop_of(done), ['STOP INVENTORY inventory_reply_too_large'])
        self.assertNotIn(SENTINEL_HOST, done.stdout + done.stderr)

    def test_wrapper_path_failure_or_differing_shape_stops(self):
        done = self.run_driver('REPLY_RC=0\nWRAPPER_RC=3\n' + self.DRIVER, files={'reply': self.good_reply() + '\n'})
        self.assertEqual(self.stop_of(done), ['STOP INVENTORY wrapper_inventory_failed exit=3'])
        done = self.run_driver(self.DRIVER.replace('cfp_wrapper_run() { cat "$H/reply"; return "${WRAPPER_RC:-0}"; }',
                                                   'cfp_wrapper_run() { sed "s/\\"truncated\\"/\\"cut\\"/" "$H/reply"; }'),
                               files={'reply': self.good_reply() + '\n'})
        self.assertEqual(len(self.stop_of(done)), 1)
        self.assertNotIn('PHASE INVENTORY OK', done.stdout)

    def test_stage_cleanup_removes_every_raw_file(self):
        # An interrupted phase leaves the raw reply only until cfp_cleanup removes it.
        driver = 'echo secret > "$CFP_DIR/inventory.json"; echo secret > "$CFP_DIR/preview.out"; echo s > "$CFP_DIR/inventory.w.json"\n' \
                 'CFR_STAGE=\ncfp_cleanup\n[ ! -d "$CFP_DIR" ] || echo DIRTHERE; echo END'
        done = self.run_driver(driver)
        self.assertIn('END', done.stdout)
        self.assertNotIn('DIRTHERE', done.stdout)


class PilotShellBulkTests(PilotShellBase):
    """BULK: pause_all and resume_all are ONE rpc-sync each; IPv4 and IPv6 chain state is recorded."""

    def bulk(self, penn_state='paused', chain4='paused 0\n', chain6='paused 0\n', extra='', rev=8):
        both = ' '.join(sorted([PENN['mac'], PHONE['mac']]))
        kids = '[' + ','.join(f'"{m}"' for m in both.split()) + ']'
        driver = (RPC_STUBS + f'CFP_RPC_ALLOW="{both}"\nCFP_KIDS_JSON=\'{kids}\'\nCFP_REV={rev}\nCFP_LAT_MAX=0\n' + extra
                  + 'cfp_bulk_phase\necho "REV:$CFP_REV"\n')
        files = dict(self.rpc_files(rev=rev), penn_state=penn_state + '\n', chain4=chain4, chain6=chain6, calls='')
        return self.run_driver(driver, files=files)

    def calls(self, done):
        return (done.home / 'calls').read_text().split()

    def test_exactly_one_sync_per_bulk_operation_and_revisions_step_by_one(self):
        # The kernel set reads paused after pause_all and clear after resume_all.
        done = self.bulk(extra=self.SEQ)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.calls(done).count('sync'), 2)
        self.assertIn('PHASE BULK OK', done.stdout)
        self.assertIn('MEASURE bulk_receipts measured pause_all=1 resume_all=1 revisions=8,9,10', done.stdout)
        self.assertIn('REV:10', done.stdout)
        first = (done.home / 'request.penn-pilot-bulk-1.json').read_text()
        second = (done.home / 'request.penn-pilot-bulk-2.json').read_text()
        self.assertIn('"operation_id":"penn-pilot-bulk-1"', first)
        self.assertIn('"operation_id":"penn-pilot-bulk-2"', second)
        # pause_all names both persons with the same timed, non-zero until; resume_all has no pauses.
        match = re.search(r'"pauses":\[\{"person":"penn","until":([0-9]+)\},\{"person":"pilot_b","until":([0-9]+)\}\]', first)
        self.assertTrue(match, first)
        self.assertEqual(match.group(1), match.group(2))
        self.assertGreater(int(match.group(1)), int(datetime.datetime.now().timestamp()))
        self.assertIn('"pauses":[],', second)
        self.assertIn(f'{{"id":"pilot_b","macs":["{PENN["mac"]}"]}}', first)
        self.assertNotIn('pilot_b', second)

    # Paused on the first read (after pause_all), clear afterwards (command substitutions: state lives in a file).
    SEQ = ('cfp_penn_state() { c=$(cat "$H/ps" 2>/dev/null || echo 0); c=$((c + 1)); echo $c > "$H/ps"; '
           '[ "$c" -gt 1 ] && echo clear || echo paused; }\n')

    def test_a_failed_block_all_uses_the_single_constant_wording(self):
        done = self.bulk(penn_state='clear')
        self.assertEqual(self.stop_of(done), ['STOP BULK block_all_unchanged set_not_paused'])
        self.assertEqual(self.calls(done).count('sync'), 1)
        self.assertIn('INFO bulk firewall_fingerprint same', done.stdout)
        self.assertNotIn('not_blocking', done.stdout)
        done = self.bulk(chain4='', extra=self.SEQ)
        self.assertEqual(self.stop_of(done), ['STOP BULK block_all_unchanged ipv4_chain_not_blocking'])

    def test_ipv6_partial_is_recorded_not_retried_and_not_a_failure(self):
        done = self.bulk(chain6='', extra=self.SEQ)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('MEASURE bulk_ipv6 unmeasured partial_or_unconfirmed paused_rules=0 not_retried', done.stdout)
        self.assertIn('MEASURE bulk_ipv4 measured paused_rules=1 set_members=2', done.stdout)
        self.assertEqual(self.calls(done).count('chain'), 4)  # (v4, v6) while paused, (v4, v6) after resume: no retry

    def test_the_sync_revision_must_be_the_planned_one(self):
        # BULK is planned at revisions 9 and 10 (digest-bound derivedSyncs): a run that is one revision off stops
        # before sending anything, even though its own CAS read agrees with its own count.
        done = self.bulk(rev=9)
        self.assertEqual(self.stop_of(done), ['STOP BULK policy_revision_mismatch'])
        self.assertEqual(self.calls(done).count('sync'), 0)

    def test_a_revision_the_pilot_did_not_set_stops_before_any_sync(self):
        done = self.bulk(extra='echo 9 > "$H/rev"\n')
        self.assertEqual(self.stop_of(done), ['STOP BULK revision_unexpected seen=9 want=8'])
        self.assertEqual(self.calls(done).count('sync'), 0)

    def test_a_double_sync_or_wrong_receipt_revision_stops(self):
        stub = 'cfp_cfctl_input() { echo sync >> "$H/calls"; op=$(sed -n \'s/.*"operation_id":"\\([^"]*\\)".*/\\1/p\' "$1"); ' \
               'printf \'{"receipt":{"operationId":"%s","requestDigest":"aa","baseRevision":8,"baseDigest":"bb","acceptedRevision":10,"acceptedDigest":"cc"}}\\n\' "$op"; }\n'
        done = self.bulk(extra=self.SEQ + stub)
        self.assertEqual(self.stop_of(done), ['STOP BULK receipt_revision_unexpected base=8 accepted=10'])


class PilotShellMoveScopeTests(PilotShellBase):
    """MOVE kernel checks, SCOPE preview/refusal/marker, SCOPE-REMOVE ordering, self-abort and the teardown proof."""

    def test_stage_policies_equal_the_policies_the_template_derives(self):
        done = self.run_driver('echo CHECKED')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('CHECKED', done.stdout)
        stages = self.plan_details(self.write_config(**self.v2_changes()))['pilotPolicies']
        params, _ = self.parameters(self.write_config(**self.v2_changes()))
        self.assertEqual({'enroll': params['CFP_POLICY'], 'enroll_phone': params['CFP_POLICY_PHONE'],
                          'move': params['CFP_POLICY_MOVE'], 'move_back': params['CFP_POLICY_BACK']},
                         {stage['stage']: stage['policyJson'] for stage in stages})

    def test_a_tampered_stage_policy_or_pilot_b_refuses_the_payload(self):
        both = sorted([PENN['mac'], PHONE['mac']])
        wrong = {'CFP_POLICY_MOVE': '{"version":1,"revision":5,"people":[{"id":"penn","macs":["%s","%s"]},{"id":"pilot_b","macs":["%s"]}],'
                                    '"pauses":[],"schedules":[],"doh":{"ipv4":[],"ipv6":[]}}' % (both[0], both[1], PENN['mac']),
                 'CFP_POLICY_PHONE': '{"version":1,"revision":2,"people":[{"id":"penn","macs":["%s"]}],"pauses":[],"schedules":[],'
                                     '"doh":{"ipv4":[],"ipv6":[]}}' % PENN['mac'],
                 'CFP_POLICY_BACK': '{"version":1,"revision":8,"people":[{"id":"penn","macs":["%s","%s"]},{"id":"mine","macs":[]}],'
                                    '"pauses":[],"schedules":[],"doh":{"ipv4":[],"ipv6":[]}}' % (both[0], both[1]),
                 'CFP_PILOT_B': 'mine'}
        for key, value in wrong.items():
            with self.subTest(key=key):
                payload_driver = f"{key}='{value}'\n"
                _, payload = self.parameters(self.write_config(**self.v2_changes()))
                head = payload[:payload.rindex(self.TAIL)] + '\n' + payload_driver
                home = self.work / 'tamper'
                shutil.rmtree(home, ignore_errors=True)
                home.mkdir()
                (home / 's.sh').write_text(head + '\ncfp_v2_check && echo ACCEPTED || echo REFUSED\n')
                done = subprocess.run(['sh', str(home / 's.sh')], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                      env={'PATH': os.environ['PATH'], 'LC_ALL': 'C'}, check=False)
                self.assertIn('REFUSED', done.stdout, done.stderr)

    PREVIEW_DRIVER = r'''
cfp_run() {
    case "$*" in
        *scope-preview*) cat "$H/preview";;
        *scope-add*) cat "$H/refusal"; return "${REFUSAL_RC:-1}";;
    esac
}
cfp_wrapper_run() { cat "$H/preview"; }
cfp_scope_add_1_phase
'''

    def preview(self, in_scope='false', evidence='true', add='null', host=SENTINEL_HOST):
        text = (f'scope-preview {PHONE["mac"]}\n  address: locally administered\n  evidence: lease 192.0.2.34 expires 1 name {host}\n'
                f'  WARNING: 1 protected device(s) not seen on the LAN now: {JD["mac"]}\n')
        line = (f'{{"ok":true,"action":"scope-preview","mac":"{PHONE["mac"]}","locallyAdministered":true,"inScope":{in_scope},'
                f'"evidence":{evidence},"scopeSha":"{self.scope_sha([PENN["mac"]])}","scopeCount":1,"addRefusal":{add},"removeRefusal":"scope_mac_absent",'
                f'"protectedAbsent":1,"errors":[]}}')
        return text + line + '\n'

    def scope_one(self, preview=None, refusal='{"ok":false,"errors":["scope_tty_required"]}\n', rc=1, rev_files=None, extra=''):
        files = dict(self.rpc_files(), preview=preview or self.preview(), refusal=refusal)
        files.update(rev_files or {})
        driver = RPC_STUBS + f'REFUSAL_RC={rc}\n' + extra + self.PREVIEW_DRIVER
        return self.run_driver(driver, files=files, timeout=60)

    def test_preview_prints_only_counts_and_never_the_hostname_or_protected_macs(self):
        # Leg 2 is not started here, so the phase times out at the marker; the output up to there is what matters.
        done = self.scope_one(extra='CFP_SCOPE_LEG_SECONDS=1\n')
        self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-1 scope_leg_timeout'])
        self.assertIn('MEASURE scope_preview_add_1 measured in_scope=false evidence=true add_refusal=none scope_entries=1 protected_absent=1',
                      done.stdout)
        self.assertIn('MEASURE scope_no_tty_refusal measured scope_tty_required exit=1 state_unchanged', done.stdout)
        for leaked in (SENTINEL_HOST, JD['mac'], MGMT['mac']):
            self.assertNotIn(leaked, done.stdout + done.stderr)

    def test_marker_is_one_strict_line_and_precedes_any_poll(self):
        extra = ('CFP_SCOPE_LEG_SECONDS=1\ncfr_out() { printf \'%s\\n\' "$1"; case $1 in CFP_LEG2_READY*) echo marker >> "$H/calls";; esac; }\n'
                 'cfp_cfctl_logged() { echo read >> "$H/calls"; }\n')
        done = self.scope_one(extra=extra.replace('cfp_cfctl_logged() { echo read >> "$H/calls"; }\n', ''))
        markers = [line for line in done.stdout.splitlines() if line.startswith('CFP_LEG2_READY')]
        self.assertEqual(len(markers), 1)
        self.assertRegex(markers[0], r'^CFP_LEG2_READY 2a [0-9a-f]{64}$')
        self.assertEqual(markers[0].split()[2], self.scope_sha([PENN['mac']]))
        self.assertLess(done.stdout.index('CFP_LEG2_READY'), done.stdout.index('STOP SCOPE-ADD-1'))
        # one rpc-status read (after the refusal) precedes the marker; the poll starts after it
        calls = (done.home / 'calls').read_text().split()
        self.assertEqual(calls.count('marker'), 1)

    def test_leg_effect_is_proved_by_rereading_rpc_status_and_leg_report_is_ignored(self):
        # The leg "reports" success on the marker line but the scope never changed: timeout, not success.
        done = self.scope_one(extra='CFP_SCOPE_LEG_SECONDS=1\n')
        self.assertNotIn('PHASE SCOPE-ADD-1 OK', done.stdout)
        self.assertNotIn('MEASURE scope_leg_2a', done.stdout)
        # The scope becomes the right one while the phase polls: it proceeds to the remove leg (marker 2b, new base).
        both = [PENN['mac'], PHONE['mac']]
        sha_added = self.scope_sha(both)
        sorted_both = sorted(both)
        extra = (f'CFP_SCOPE_LEG_SECONDS=3\n( sleep 1; echo {sha_added} > "$H/filesha"; echo {sha_added} > "$H/scopesha"; '
                 f'echo \'"{sorted_both[0]}","{sorted_both[1]}"\' > "$H/scopejson" ) &\n')
        done = self.scope_one(extra=extra)
        self.assertIn('MEASURE scope_leg_2a measured scope_sha_changed membership=add reread_rpc_status', done.stdout)
        markers = [line.split()[1:] for line in done.stdout.splitlines() if line.startswith('CFP_LEG2_READY')]
        self.assertEqual(markers, [['2a', self.scope_sha([PENN['mac']])], ['2b', sha_added]])
        self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-1 scope_leg_timeout'])

    def test_unexpected_scope_sha_or_membership_stops_immediately(self):
        # During the poll: a scope that is neither the base nor the expected one.
        done = self.scope_one(extra='CFP_SCOPE_LEG_SECONDS=5\n( sleep 1; echo ' + 'd' * 64 + ' > "$H/filesha" ) &\n')
        self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-1 scope_sha_unexpected'])
        # The file says the leg worked but the authoritative re-read disagrees: the leg's effect is not believed.
        sha_added = self.scope_sha([PENN['mac'], PHONE['mac']])
        done = self.scope_one(extra=f'CFP_SCOPE_LEG_SECONDS=5\n( sleep 1; echo {sha_added} > "$H/filesha" ) &\n')
        self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-1 scope_reread_mismatch'])
        # The right sha on both reads but the phone is not in the listed scope: membership mismatch.
        done = self.scope_one(extra=f'CFP_SCOPE_LEG_SECONDS=5\n( sleep 1; echo {sha_added} > "$H/filesha"; '
                                    f'echo {sha_added} > "$H/scopesha" ) &\n')
        self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-1 scope_membership_unexpected'])

    def test_no_tty_refusal_must_be_exactly_scope_tty_required(self):
        for refusal, rc in (('{"ok":false,"errors":["scope_confirmation_required"]}\n', 1),
                            ('{"ok":false,"errors":["scope_tty_required"]}\n', 0), ('', 1), ('{"ok":true}\n', 0)):
            with self.subTest(refusal=refusal, rc=rc):
                done = self.scope_one(refusal=refusal, rc=rc)
                self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-1 scope_tty_refusal_unexpected'])
                self.assertNotIn('CFP_LEG2_READY', done.stdout)

    def test_preview_refusals_stop_before_the_marker(self):
        cases = {'in scope': (self.preview(in_scope='true'), 'scope_target_in_scope_at_start'),
                 'no evidence': (self.preview(evidence='false'), 'scope_target_no_evidence'),
                 'add refused': (self.preview(add='"scope_mac_protected"'), 'scope_add_refused scope_mac_protected')}
        for name, (text, reason) in cases.items():
            with self.subTest(case=name):
                done = self.scope_one(preview=text)
                self.assertEqual(self.stop_of(done), [f'STOP SCOPE-ADD-1 {reason}'])
                self.assertNotIn('CFP_LEG2_READY', done.stdout)

    def test_state_changed_by_the_refusal_stops(self):
        done = self.scope_one(extra='cfp_status_read() { echo ' + 'e' * 64 + ' > "$H/scopesha"; cfp_cfctl rpc-status --json > "$CFP_DIR/rpc-status.json"; cfp_status_parse; }\n')
        self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-1 scope_changed_by_refusal'])

    def test_wrapper_argv_negatives_must_exit_2_with_no_output(self):
        base = RPC_STUBS + f'CFP_BASE0={"c" * 64}\n'  # any 64-hex base
        ok = self.run_driver(base + 'cfp_wrapper_run() { return 2; }\ncfp_wrapper_negatives\n')
        self.assertIn('MEASURE scope_wrapper_argv_negatives measured rejected=4 exit=2 no_output', ok.stdout)
        for body in ('return 0', 'echo out; return 2', 'return 1', 'return 127'):
            with self.subTest(body=body):
                done = self.run_driver(base + f'cfp_wrapper_run() {{ {body}; }}\ncfp_wrapper_negatives\n')
                self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-2 wrapper_negative_accepted'])
        # The four commands are exactly the malformed grammar the wrapper must refuse.
        log = self.run_driver(base + 'cfp_wrapper_run() { echo "$2" >> "$H/seen"; return 2; }\ncfp_wrapper_negatives\n')
        seen = (log.home / 'seen').read_text().splitlines()
        self.assertEqual(seen, ['cfctl scope-add bad', f'cfctl scope-add {PHONE["mac"]} --base short',
                                f'cfctl scope-add {PHONE["mac"]} --base {"c" * 64} extra', 'cfctl scope-preview'])

    def test_move_kernel_state_is_checked_per_device(self):
        driver = 'cfp_set_state() { cat "$H/state.$(echo "$1" | tr : _)"; }\ncfp_move_kernel_check %s %s\necho DONE\n'
        files = {f'state.{PENN["mac"].replace(":", "_")}': 'paused\n', f'state.{PHONE["mac"].replace(":", "_")}': 'clear\n'}
        ok = self.run_driver(driver % ('paused', 'clear'), files=files)
        self.assertIn('DONE', ok.stdout)
        # The block did not follow the device: the phone is paused instead of the Chromebook.
        swapped = {f'state.{PENN["mac"].replace(":", "_")}': 'clear\n', f'state.{PHONE["mac"].replace(":", "_")}': 'paused\n'}
        done = self.run_driver(driver % ('paused', 'clear'), files=swapped)
        self.assertEqual(self.stop_of(done), ['STOP MOVE chromebook_kernel_state_not_paused'])
        both = {key: 'paused\n' for key in files}
        done = self.run_driver(driver % ('paused', 'clear'), files=both)
        self.assertEqual(self.stop_of(done), ['STOP MOVE phone_kernel_state_not_clear'])

    def test_scope_remove_unenrols_before_the_remove_leg(self):
        driver = (RPC_STUBS + f'CFP_SC_ADDED="x"\nCFP_SHA_ADDED={"c" * 64}\nCFP_BASE0={"b" * 64}\nCFP_REV=8\n'
                  'cfp_sync() { echo "sync $2" >> "$H/order"; CFP_REV=$((CFP_REV + 1)); }\n'
                  'cfp_status_read() { echo status >> "$H/order"; cfp_sc_sha=$CFP_SHA_ADDED; }\n'
                  'cfp_leg2() { echo "leg $2" >> "$H/order"; }\n'
                  'cfp_audit_count() { :; }\ncfp_scope_remove_phase\n')
        done = self.run_driver(driver, files=self.rpc_files())
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual((done.home / 'order').read_text().split('\n')[:-1], ['sync penn-pilot-unenrol-1', 'status', 'leg 2d'])
        self.assertIn('PHASE SCOPE-REMOVE OK', done.stdout)
        # The unenrol policy is the floor policy (Chromebook only) at the next revision.
        driver2 = (RPC_STUBS + f'CFP_SHA_ADDED={"c" * 64}\nCFP_BASE0={"b" * 64}\nCFP_REV=11\n'
                   'cfp_leg2() { :; }\ncfp_audit_count() { :; }\n'
                   'cfp_scope_remove_phase\n')
        done = self.run_driver(driver2, files=self.rpc_files(rev=11))
        request = (done.home / 'request.penn-pilot-unenrol-1.json').read_text()
        self.assertIn(f'"policy":{{"version":1,"revision":12,"people":[{{"id":"penn","macs":["{PENN["mac"]}"]}}],"pauses":[]', request)
        self.assertNotIn(PHONE['mac'], request)

    SELF_ABORT = r'''
CFP_SELF_ABORT_PCT=%(pct)s
CFP_REMOTE_TIMEOUT=1000
CFP_TEARDOWN_RESERVE=300
CFP_START_CS=$(( $(cfp_cs) - %(elapsed)s * 100 ))
cfp_budget TESTPHASE 10
echo SURVIVED
'''

    def test_self_abort_begins_teardown_at_seventy_percent(self):
        for elapsed, survives in ((690, True), (701, False), (999, False)):
            with self.subTest(elapsed=elapsed):
                done = self.run_driver(self.SELF_ABORT % {'pct': 70, 'elapsed': elapsed})
                if survives:
                    self.assertIn('SURVIVED', done.stdout)
                else:
                    self.assertEqual(self.stop_of(done), ['STOP TESTPHASE remote_self_abort'])
        # v1 (no percent) keeps the legacy shape.
        done = self.run_driver(self.SELF_ABORT % {'pct': "''", 'elapsed': 999})
        self.assertIn('STOP TESTPHASE remote_budget_reserved_for_teardown', done.stdout)

    def test_self_abort_fires_inside_the_leg_poll_loop(self):
        driver = (RPC_STUBS + 'CFP_SELF_ABORT_PCT=70\nCFP_REMOTE_TIMEOUT=1000\nCFP_START_CS=$(( $(cfp_cs) - 80000 ))\n'
                  'cfp_leg2 SCOPE-ADD-1 2a ' + 'c' * 64 + ' ' + 'd' * 64 + ' add\n')
        done = self.run_driver(driver, files=self.rpc_files())
        self.assertEqual(self.stop_of(done), ['STOP SCOPE-ADD-1 remote_self_abort'])

    def test_teardown_proof_checks_leftovers_and_prints_counts_only(self):
        setup = (
            'CFR_STAGE=$H/stage; CFR_ROOT=$H/root; CFR_RELEASE_DIR=$CFR_ROOT/etc/.couvrefeu-release-x\n'
            'for k in ipset ipsetsave iptables ip6tables; do : > "$CFR_STAGE/text.before.$k"; : > "$CFR_STAGE/text.after.$k"; done\n'
            'CFP_CROND_UNINSTALL=2 CFP_CROND_BASELINE=2\n%s\ncfp_teardown_proof\necho "FAILED:$CFP_PROOF_FAILED"\n')
        done = self.run_driver(setup % ':')
        self.assertIn('MEASURE teardown_proof measured scope_candidates=0 cf_ipset_lines=0/0 cf_iptables_lines=0/0 '
                      'cf_ip6tables_lines=0/0 crond_etc=2/2 state_people=0 release_dir=absent', done.stdout)
        self.assertIn('FAILED:0', done.stdout)
        leftovers = {
            'teardown_scope_candidate_left': 'mkdir -p $CFR_ROOT/etc/couvrefeu/runtime; : > $CFR_ROOT/etc/couvrefeu/runtime/.scope.123',
            'teardown_cf_ipset_left': 'echo "create cf2_a_p hash:mac" > "$CFR_STAGE/text.after.ipsetsave"',
            'teardown_cf_chain_left': 'echo "-N cf_fwd" > "$CFR_STAGE/text.after.ip6tables"',
            'teardown_crond_count_changed': 'CFP_CROND_UNINSTALL=3',
            'teardown_person_left_in_state': 'mkdir -p $CFR_ROOT/etc/couvrefeu; printf "P\\tpilot_b\\tx\\n" > $CFR_ROOT/etc/couvrefeu/state',
            'teardown_release_dir_left': 'mkdir -p "$CFR_RELEASE_DIR"'}
        for reason, command in leftovers.items():
            with self.subTest(reason=reason):
                done = self.run_driver(setup % command)
                self.assertIn(f'PHASE RESTORE FAIL {reason}', done.stdout)
                self.assertIn('FAILED:1', done.stdout)

    def function_text(self, name):
        script = (REPO / 'tools/live/penn-pilot.sh').read_text()
        start = script.index(f'\n{name}() {{') + 1
        return script[start:script.index('\n}\n', start)]

    def test_every_stop_runs_exactly_one_teardown(self):
        # The real cfp_stop (not the harness stub): it records the stop, prints it and hands over to the teardown once.
        done = self.run_driver('cfp_teardown() { echo TEARDOWN; exit 20; }\ncfp_stop SCOPE-REMOVE leg_failed\necho NOT_REACHED',
                               stub_stop=False)
        lines = done.stdout.splitlines()
        self.assertEqual(done.returncode, 20, done.stdout)
        self.assertIn('PHASE SCOPE-REMOVE FAIL leg_failed', lines)
        self.assertEqual(lines[-2:], ['STOP SCOPE-REMOVE leg_failed', 'TEARDOWN'])
        self.assertNotIn('NOT_REACHED', lines)

    def test_teardown_proof_runs_after_restore_and_before_connectivity(self):
        body = self.function_text('cfp_teardown')
        self.assertLess(body.index('cfp_restore'), body.index('cfr_connectivity'))
        restore = self.function_text('cfp_restore')
        self.assertLess(restore.index('cfr_snapshot after'), restore.index('cfp_teardown_proof'))
        self.assertLess(restore.index('cfp_teardown_proof'), restore.index('cfr_ok RESTORE'))
        self.assertIn('"$CFP_PROOF_FAILED" = 0', body)

    def test_self_abort_check_guards_every_wait_loop(self):
        for name in ('cfp_budget', 'cfp_observe', 'cfp_status_settle', 'cfp_expiry_phase', 'cfp_leg2'):
            with self.subTest(function=name):
                self.assertIn('cfp_abort_check', self.function_text(name))

    def test_template_never_touches_authentication_or_login_configuration(self):
        # The one operator note naming password login as the recovery path is output text, not a configuration touch.
        text = (REPO / 'tools/live/penn-pilot.sh').read_text().replace('password login is the recovery path', '')
        self.assertIsNone(re.search(r'authorized_keys|dropbear|passwd|shadow|password|PasswordAuth|sshd|uci +(set|commit)', text, re.I))
        self.assertNotIn('rm -rf', text)


class PilotShellMoveFlowTests(PilotShellBase):
    """The MOVE sequence against canned replies: the block follows the Chromebook and the move is undone."""

    def reply(self, penn, pilot_b=None):
        people = [f'{{"id":"penn","macs":{json.dumps(penn, separators=(",", ":"))}}}']
        if pilot_b is not None:
            people.append(f'{{"id":"pilot_b","macs":{json.dumps(pilot_b, separators=(",", ":"))}}}')
        return '{"rpc_version":1,"acceptedPolicy":{"version":1,"revision":5,"people":[' + ','.join(people) + '],"pauses":[]}}\n'

    def move(self, reply_a=None, reply_b=None, shape_after='shape', extra='', states='paused clear clear clear'):
        both = sorted([PENN['mac'], PHONE['mac']])
        reply_a = reply_a or self.reply([PHONE['mac']], [PENN['mac']])
        reply_b = reply_b or self.reply(both)
        kids = '[' + ','.join(f'"{m}"' for m in both) + ']'
        driver = (
            f'CFP_RPC_ALLOW="{" ".join(both)}"\nCFP_KIDS_JSON=\'{kids}\'\nCFP_REV=4\nCFP_PAUSE_SECONDS=180\nCFP_LAT_MAX=0\n'
            'cfp_sync() { n=$(cat "$H/n" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$H/n"; cp "$H/reply.$n" "$CFP_DIR/rpc-sync.json"; '
            'echo "sync $2" >> "$H/calls"; CFP_REV=$((CFP_REV + 1)); }\n'
            'cfp_status_settle() { :; }\n'
            'cfp_pause() { CFP_UNTIL=2000000000; echo "pause $CFP_PAUSE_WHO" >> "$H/calls"; printf \'%s\\n\' "$PAUSE_STATUS" > "$CFP_DIR/status.json"; }\n'
            f'PAUSE_STATUS=\'{{"ok":true,"drift":false,"errors":[],"effectivePauses":[{{"person":"pilot_b","until":2000000000}}],"paused":["{PENN["mac"]}"]}}\'\n'
            'cfp_status_has() { grep -Fq "$2" "$1"; }\n'
            'cfp_cfctl() { echo "cfctl $*" >> "$H/calls"; echo \'{"ok":true,"effectivePauses":[],"paused":[]}\' ; }\n'
            'cfp_adult_probe() { return 0; }\n'
            'cfp_set_state() { n=$(cat "$H/s" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$H/s"; '
            'set -- $(cat "$H/states"); eval "echo \\${$n}"; }\n'
            'cfp_fw_shape() { if [ ! -e "$H/shape0" ]; then echo shape > "$1"; : > "$H/shape0"; else cat "$H/shape1" > "$1"; fi; }\n' + extra
            + 'cfp_move_phase\necho "REV:$CFP_REV"\n')
        files = {'reply.1': reply_a, 'reply.2': reply_b, 'shape1': shape_after + '\n', 'states': states + '\n'}
        return self.run_driver(driver, files=files)

    def test_move_there_and_back_with_the_block_following_the_chromebook(self):
        # Kernel reads in order: chromebook (paused), phone (clear) while pilot_b is paused; both clear after resume.
        done = self.move(states='paused clear clear clear')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('PHASE MOVE OK', done.stdout)
        calls = (done.home / 'calls').read_text().split('\n')
        self.assertEqual([c for c in calls if c.startswith(('sync', 'pause', 'cfctl resume'))],
                         ['sync penn-pilot-move-1', 'pause pilot_b', 'cfctl resume pilot_b', 'sync penn-pilot-move-2'])
        self.assertIn('REV:8', done.stdout)

    def test_move_stops_when_the_state_is_not_what_the_move_requires(self):
        both = sorted([PENN['mac'], PHONE['mac']])
        cases = {
            'pilot_b not populated': (dict(reply_a=self.reply([PENN['mac'], PHONE['mac']])), 'pilot_b_not_populated'),
            'chromebook in both persons': (dict(reply_a=self.reply(both, [PENN['mac']])), 'penn_not_phone_only'),
            'pilot_b left populated': (dict(reply_b=self.reply(both, [PENN['mac']])), 'pilot_b_left_populated'),
            'penn not restored': (dict(reply_b=self.reply([PHONE['mac']])), 'penn_not_restored'),
            'firewall differs after move back': (dict(shape_after='shape-different'), 'firewall_not_restored_after_move_back'),
            'phone paused instead': (dict(states='clear paused clear clear'), 'chromebook_kernel_state_not_paused'),
            'still paused after resume': (dict(states='paused clear paused clear'), 'chromebook_kernel_state_not_clear')}
        for name, (kwargs, reason) in cases.items():
            with self.subTest(case=name):
                done = self.move(**kwargs)
                self.assertEqual(self.stop_of(done), [f'STOP MOVE {reason}'], done.stdout)
                self.assertNotIn('PHASE MOVE OK', done.stdout)


class PilotReviewFixTests(PilotShellBase):
    """Review fixes: bounded children, leg-2 cancel, no raw LAN IPv4, the uptime clock, a real BULK receipt check,
    a non-vacuous teardown proof and the fixture-only wrapper directory."""

    HANG = '#!/bin/sh\nexec sleep 30\n'

    def hang_driver(self, call, seconds=1):
        return (f'CFR_CFCTL=$H/hang.sh\nCFP_CFCTL_ALLOWANCE={seconds}\nmkdir -p "$CFR_ROOT/usr/sbin"\n'
                'cp "$H/hang.sh" "$CFR_ROOT/usr/sbin/cfctl-ssh"\nt0=$(date +%s)\n' + call
                + '\necho "ELAPSED:$(( $(date +%s) - t0 ))"\n')

    def elapsed(self, done):
        return int(re.search(r'ELAPSED:([0-9]+)', done.stdout).group(1))

    def test_a_hung_cfctl_or_wrapper_call_is_killed_at_the_allowance(self):
        calls = {'cfctl': 'cfp_cfctl status --json > /dev/null; echo "RC:$?"',
                 'cfctl with input': 'echo x > "$H/in"; cfp_cfctl_input "$H/in" rpc-sync > /dev/null; echo "RC:$?"',
                 'wrapper': "cfp_wrapper_run cfctl-ssh 'cfctl rpc-inventory --json' --rpc-only > /dev/null; echo \"RC:$?\"",
                 'pause': 'CFP_UNTIL=1; cfp_pause 30; echo "RC:$?"'}
        for name, call in calls.items():
            with self.subTest(call=name):
                done = self.run_driver(self.hang_driver(call), files={'hang.sh': self.HANG}, timeout=60)
                self.assertLess(self.elapsed(done), 10, done.stdout + done.stderr)
                if name != 'pause':
                    self.assertIn('RC:143', done.stdout)  # TERM at the allowance; the KILL grace is not reached
                else:
                    self.assertIn('INFO pause exit 143', done.stdout)

    @unittest.skipUnless(shutil.which('busybox'), 'busybox absent')
    def test_the_kill_also_works_with_busybox_timeout(self):
        driver = ('mkdir -p "$H/bb"; ln -sf "$(command -v busybox)" "$H/bb/timeout"; PATH=$H/bb:$PATH\n'
                  + self.hang_driver('cfp_cfctl status --json > /dev/null; echo "RC:$?"'))
        done = self.run_driver(driver, files={'hang.sh': self.HANG}, timeout=60)
        self.assertLess(self.elapsed(done), 10, done.stdout + done.stderr)
        self.assertIn('RC:143', done.stdout)

    def test_a_phase_whose_call_hangs_stops_instead_of_waiting(self):
        done = self.run_driver(self.hang_driver('cfp_status_read PHASE'), files={'hang.sh': self.HANG}, timeout=60)
        self.assertEqual(self.stop_of(done), ['STOP PHASE rpc_status_failed'])
        done = self.run_driver(self.hang_driver('CFP_PHONE_MAC=02:00:00:00:00:34; cfp_preview PHASE direct add_1'),
                               files={'hang.sh': self.HANG}, timeout=60)
        self.assertEqual(self.stop_of(done), ['STOP PHASE scope_preview_failed'])
        done = self.run_driver(self.hang_driver('cfp_inventory_phase'), files={'hang.sh': self.HANG}, timeout=60)
        self.assertEqual(len(self.stop_of(done)), 1, done.stdout)

    def test_no_child_is_started_outside_the_bounded_helper(self):
        text = (REPO / 'tools/live/penn-pilot.sh').read_text()
        loose = [line for line in text.splitlines()
                 if not line.lstrip().startswith('#') and ('cfr_run_sh' in line or '$CFR_SH' in line)
                 and 'exec $CFR_SH' not in line]
        self.assertEqual(loose, [])

    UNINSTALL_DRIVER = r'''
CFR_RELEASE_DIR=$H/rel
mkdir -p "$CFR_RELEASE_DIR"
cp "$H/uninstall.sh" "$CFR_RELEASE_DIR/uninstall.sh"
cfr_snapshot() { return 1; }
cfp_kernel_state() { echo stub; }
cfp_crond_count() { :; }
cfp_teardown
'''

    def test_a_hung_uninstall_is_killed_and_reported_as_uninstall_timeout(self):
        done = self.run_driver(self.UNINSTALL_DRIVER, files={'uninstall.sh': self.HANG},
                               params={'CFP_UNINSTALL_ALLOWANCE': 1}, timeout=60)
        self.assertEqual(done.returncode, 20, done.stdout + done.stderr)
        self.assertIn('PHASE UNINSTALL FAIL uninstall_timeout', done.stdout)
        self.assertEqual(done.stdout.splitlines()[-1], 'FAIL_AFTER_MUTATION UNINSTALL')
        self.assertNotIn('PHASE UNINSTALL OK', done.stdout)

    def test_a_refused_uninstall_keeps_its_own_reason(self):
        done = self.run_driver(self.UNINSTALL_DRIVER, files={'uninstall.sh': 'exit 1\n'}, timeout=60)
        self.assertIn('PHASE UNINSTALL FAIL uninstall_refused_or_failed', done.stdout)
        self.assertNotIn('uninstall_timeout', done.stdout)

    LEG_DRIVER = r'''
CFR_RELEASE_DIR=$H/rel
mkdir -p "$CFR_RELEASE_DIR" "$CFR_ROOT/etc/couvrefeu/runtime"
cat > "$CFR_RELEASE_DIR/uninstall.sh" <<'EOS'
if [ -e "$LOCK" ]; then echo LOCK_PRESENT > "$H/seen"; else echo LOCK_ABSENT > "$H/seen"; fi
cat "$H/filesha" >> "$H/seen"
exit 1
EOS
LOCK=$CFR_ROOT/etc/couvrefeu/runtime/lock
export LOCK H
cfp_scope_file_sha() { cat "$H/filesha"; }
cfr_snapshot() { return 1; }
cfp_kernel_state() { echo stub; }
cfp_crond_count() { :; }
%s
cfp_teardown
'''

    def leg_teardown(self, setup, params=None):
        return self.run_driver(self.LEG_DRIVER % setup, files={'filesha': 'aaa\n'}, params=params, timeout=60)

    def test_a_stop_during_a_leg_cancels_it_and_waits_for_quiet_before_uninstall(self):
        # The lock is held and the scope file changes after the stop: uninstall must see neither.
        setup = ('CFP_LEG2_ACTIVE=2c\nmkdir "$LOCK"\n: > "$CFR_STAGE/leg2-idle"\n'
                 '( sleep 2; echo bbb > "$H/filesha"; sleep 1; rmdir "$LOCK" ) &\n')
        done = self.leg_teardown(setup)
        lines = done.stdout.splitlines()
        self.assertIn('CFP_LEG2_CANCEL 2c', lines, done.stdout)
        self.assertLess(lines.index('CFP_LEG2_CANCEL 2c'), next(i for i, l in enumerate(lines) if 'run uninstall.sh once' in l))
        self.assertEqual((done.home / 'seen').read_text().split(), ['LOCK_ABSENT', 'bbb'])

    def test_quiet_means_the_scope_file_is_unchanged_across_two_reads(self):
        # No lock, but the scope file keeps changing for ~3 s after the stop: uninstall must wait for it to settle.
        setup = ('CFP_LEG2_ACTIVE=2b\n( sleep 0.2; : > "$CFR_STAGE/leg2-idle" ) &\n( sleep 0.5; echo b > "$H/filesha"; sleep 1; echo c > "$H/filesha"; '
                 'sleep 1; echo d > "$H/filesha" ) &\n')
        done = self.leg_teardown(setup)
        self.assertEqual((done.home / 'seen').read_text().split(), ['LOCK_ABSENT', 'd'], done.stdout)

    def test_the_cancel_wait_is_bounded_and_uninstall_still_runs(self):
        done = self.leg_teardown('CFP_LEG2_ACTIVE=2a\nmkdir "$LOCK"\n', params={'CFP_LEG2_CANCEL_WAIT': 2})
        self.assertIn('CFP_LEG2_CANCEL 2a', done.stdout)
        self.assertIn('INFO leg2_quiesce_timeout', done.stdout)
        self.assertEqual((done.home / 'seen').read_text().split()[0], 'LOCK_PRESENT')
        self.assertIn('PHASE UNINSTALL FAIL', done.stdout)

    def test_no_cancel_marker_without_an_outstanding_leg(self):
        done = self.leg_teardown(':')
        self.assertNotIn('CFP_LEG2_CANCEL', done.stdout)

    def test_the_leg_flag_is_set_before_the_marker_and_cleared_after_the_confirming_read(self):
        body = self.function_text('cfp_leg2')
        self.assertLess(body.index('CFP_LEG2_ACTIVE=$cfp_l_leg'), body.index('CFP_LEG2_READY'))
        self.assertLess(body.index('scope_sha_inconsistent'), body.rindex('CFP_LEG2_ACTIVE='))
        self.assertTrue(body.rstrip().splitlines()[-1].strip().startswith('CFP_LEG2_ACTIVE='), body[-200:])

    NEIGH_STUBS = (
        'timeout() { shift 3; "$@"; }\n'
        'dd() { printf "fixed-test-entropy"; }\n'
        'ip() { printf "%s\\n" "192.0.2.88 lladdr 02:00:00:00:00:88 STALE" "192.0.2.99 FAILED" '
        f'"{MGMT["ip"]} lladdr {MGMT["mac"]} REACHABLE" "{PENN["ip"]} lladdr {PENN["mac"]} DELAY" '
        f'"{PHONE["ip"]} lladdr {PHONE["mac"]} STALE"; }}\n')

    def test_non_role_ipv4_addresses_are_hashed_and_role_addresses_named(self):
        done = self.run_driver(self.NEIGH_STUBS + 'cfp_neigh_evidence ENROLL\n')
        phase_log = (done.home / 'stage/phase.log').read_text()
        for text in (done.stdout, phase_log):
            for raw in ('192.0.2.88', '192.0.2.99', '02:00:00:00:00:88'):
                self.assertNotIn(raw, text)
        line = next(l for l in done.stdout.splitlines() if l.startswith('INFO status_settle_neigh ENROLL '))
        self.assertRegex(line, r' ip4-[0-9a-f]{12}=mac-[0-9a-f]{12}/STALE')
        self.assertRegex(line, r' ip4-[0-9a-f]{12}=-/FAILED')
        self.assertIn('management=management/REACHABLE', line)
        self.assertIn('penn_child=penn_child/DELAY', line)
        self.assertIn('scope_target=scope_target/STALE', line)

    CLOCK = ('CFP_REMOTE_TIMEOUT=1000\nCFP_TEARDOWN_RESERVE=300\nCFP_START_CS=100000\n'
             'cfp_now() { echo 5; }\ncfp_cs() { echo $((100000 + %(elapsed)s * 100)); }\n')

    def test_elapsed_budget_and_abort_use_the_uptime_clock_not_the_wall_clock(self):
        for elapsed, ok in ((690, True), (701, False)):
            with self.subTest(elapsed=elapsed):
                done = self.run_driver(self.CLOCK % {'elapsed': elapsed} + 'cfp_elapsed_ok 10 && echo ok || echo not_ok\n')
                self.assertEqual(done.stdout.split(), ['ok' if ok else 'not_ok'], done.stdout + done.stderr)
        done = self.run_driver(self.CLOCK % {'elapsed': 701} + 'CFP_SELF_ABORT_PCT=70\ncfp_abort_check T\necho SURVIVED\n')
        self.assertEqual(self.stop_of(done), ['STOP T remote_self_abort'])
        done = self.run_driver(self.CLOCK % {'elapsed': 100} + 'CFP_SELF_ABORT_PCT=70\ncfp_abort_check T\necho SURVIVED\n')
        self.assertIn('SURVIVED', done.stdout)
        done = self.run_driver(self.CLOCK % {'elapsed': 100} + 'cfp_cs() { return 1; }\ncfp_elapsed_ok 0 || echo not_ok\n')
        self.assertEqual(done.stdout.split()[-1], 'not_ok')

    def test_a_phase_whose_worst_case_crosses_the_abort_mark_is_not_started(self):
        # Mark: 70% of 2000 = 1400 s; the 100% budget (2000 - 300 reserve) is further out.
        base = self.CLOCK % {'elapsed': 600} + 'CFP_REMOTE_TIMEOUT=2000\nCFP_SELF_ABORT_PCT=70\n'
        done = self.run_driver(base + 'cfp_budget P 800\necho STARTED\n')
        self.assertIn('STARTED', done.stdout)
        done = self.run_driver(base + 'cfp_budget P 801\necho STARTED\n')
        self.assertEqual(self.stop_of(done), ['STOP P remote_self_abort_worst_case'])
        # v1 (no percent) keeps its legacy shape.
        done = self.run_driver(base + "CFP_SELF_ABORT_PCT=''\ncfp_budget P 801\necho STARTED\n")
        self.assertIn('STARTED', done.stdout)

    def test_the_inventory_salt_needs_a_real_read(self):
        # A failed urandom read hashes nothing: the empty-input digest is no salt.
        done = self.run_driver('dd() { :; }\ncfp_inventory_phase\n')
        self.assertEqual(self.stop_of(done), ['STOP INVENTORY salt_unavailable'])

    def test_router_supplied_lists_are_never_glob_expanded(self):
        done = self.run_driver('cd "$H"\ntouch aaa bbb\ncfp_scope_sha "*"\n')
        self.assertEqual(done.stdout.strip(), hashlib.sha256(b'*\n').hexdigest())
        done = self.run_driver(f'cd "$H"\ntouch aaa bbb\ncfp_scope_with "*" {PHONE["mac"]}\necho\necho "SET:$-"\n')
        words = done.stdout.split('\n')
        self.assertEqual(words[0], f'* {PHONE["mac"]}', done.stdout + done.stderr)
        self.assertNotIn('f', words[1])

    def test_raw_reply_files_are_removed_even_when_stdout_is_lost(self):
        raw = ('preview.out', 'wrapper.out', 'inventory.json', 'inventory.w.json', 'settle.neigh', 'settle.tokens', 'settle.map')
        driver = ''.join(f'echo secret > "$CFP_DIR/{name}"\n' for name in raw) + \
                 'echo keep > "$CFP_DIR/status.json"\nCFR_STDOUT_LOST=1\ncfp_cleanup\nls "$CFP_DIR" | tr "\\n" " "\n'
        done = self.run_driver(driver)
        self.assertEqual(done.stdout.strip(), 'status.json', done.stdout + done.stderr)

    def test_the_raw_scope_preview_is_removed_as_soon_as_it_is_parsed(self):
        driver = f'cfp_run() {{ cat "$H/preview"; }}\nCFP_PHONE_MAC={PHONE["mac"]}\ncfp_preview P direct add_1\necho "LEFT:$(ls "$CFP_DIR")"\n'
        done = self.run_driver(driver, files={'preview': PilotShellMoveScopeTests.preview(self)})
        self.assertIn('MEASURE scope_preview_add_1 measured', done.stdout)
        self.assertIn('LEFT:', done.stdout)
        self.assertNotIn('preview.out', done.stdout)
        self.assertNotIn(SENTINEL_HOST, done.stdout)

    def test_an_empty_scope_is_unparsable_because_it_cannot_exist(self):
        # router/lib/core.sh: cf_scope_file requires 1-256 MACs, install refuses an empty --rpc-allow, scope-remove
        # refuses a floor MAC (scope_mac_in_floor) and cf_scope_load refuses an unscoped install.
        files = dict(self.rpc_files(), scopejson='\n')
        done = self.run_driver(RPC_STUBS + 'cfp_status_read P\necho PARSED\n', files=files)
        self.assertEqual(self.stop_of(done), ['STOP P rpc_status_unparsed'])

    def bulk_receipts(self, receipts):
        both = ' '.join(sorted([PENN['mac'], PHONE['mac']]))
        kids = '[' + ','.join(f'"{m}"' for m in both.split()) + ']'
        driver = (RPC_STUBS + f'CFP_RPC_ALLOW="{both}"\nCFP_KIDS_JSON=\'{kids}\'\nCFP_REV=8\nCFP_LAT_MAX=0\nRECEIPTS={receipts}\n'
                  + PilotShellBulkTests.SEQ + 'cfp_bulk_phase\n')
        files = dict(self.rpc_files(rev=8), penn_state='paused\n', chain4='paused 0\n', chain6='paused 0\n', calls='')
        return self.run_driver(driver, files=files)

    def test_bulk_requires_exactly_one_receipt_per_operation_id(self):
        done = self.bulk_receipts(1)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('PHASE BULK OK', done.stdout)
        for count in (0, 2):
            with self.subTest(count=count):
                done = self.bulk_receipts(count)
                stops = self.stop_of(done)
                self.assertEqual(len(stops), 1, done.stdout)
                self.assertTrue(stops[0].startswith('STOP BULK bulk_receipt_count_unexpected'), stops)
                self.assertNotIn('PHASE BULK OK', done.stdout)

    def test_bulk_has_no_dead_revision_difference_guard(self):
        self.assertNotIn('cfp_bk_rev1 - cfp_bk_rev0', self.function_text('cfp_bulk_phase'))

    def test_the_wrapper_directory_override_is_honoured_only_in_fixture_mode(self):
        driver = ('unset CF_TEST_MODE CF_ROOT CF_BACKEND_DIR\nCFP_WRAPPER_DIR=/evil/dir\ncfr_setup_paths\n'
                  'echo "FIXTURE:$CFR_FIXTURE"\ncfp_wrapper_dir\n')
        done = self.run_driver(driver)
        self.assertEqual(done.stdout.split(), ['FIXTURE:0', '/usr/sbin'], done.stdout + done.stderr)
        done = self.run_driver('CFR_FIXTURE=1\nCFP_WRAPPER_DIR=/fixture/dir\ncfp_wrapper_dir\n')
        self.assertEqual(done.stdout.strip(), '/fixture/dir')

    def function_text(self, name):
        script = (REPO / 'tools/live/penn-pilot.sh').read_text()
        start = script.index(f'\n{name}() {{') + 1
        return script[start:script.index('\n}\n', start)]

    def test_teardown_proof_needs_its_evidence_files(self):
        setup = (
            'CFR_STAGE=$H/stage; CFR_ROOT=$H/root; CFR_RELEASE_DIR=$CFR_ROOT/etc/.couvrefeu-release-x\n'
            'for k in ipset ipsetsave iptables ip6tables; do : > "$CFR_STAGE/text.before.$k"; : > "$CFR_STAGE/text.after.$k"; done\n'
            'CFP_CROND_UNINSTALL=2 CFP_CROND_BASELINE=2\n%s\ncfp_teardown_proof\necho "FAILED:$CFP_PROOF_FAILED"\n')
        for kind in ('ipset', 'ipsetsave', 'iptables', 'ip6tables'):
            with self.subTest(missing=kind):
                done = self.run_driver(setup % f'rm -f "$CFR_STAGE/text.after.{kind}"')
                self.assertIn('PHASE RESTORE FAIL teardown_evidence_missing', done.stdout)
                self.assertIn('FAILED:1', done.stdout)
        done = self.run_driver(setup % 'rm -f "$CFR_STAGE/text.before.iptables"')
        self.assertIn('PHASE RESTORE FAIL teardown_evidence_missing', done.stdout)
        # Present but not a regular file: awk would skip a directory with a zero count, so it must count as missing.
        done = self.run_driver(setup % 'rm -f "$CFR_STAGE/text.after.ip6tables"; mkdir "$CFR_STAGE/text.after.ip6tables"')
        self.assertIn('PHASE RESTORE FAIL teardown_evidence_missing', done.stdout)

    RESTORE_DRIVER = (
        'CFR_ROOT=$H/root; CFR_RELEASE_DIR=$CFR_ROOT/etc/.couvrefeu-release-x\n'
        'for k in ipset ipsetsave iptables ip6tables; do : > "$CFR_STAGE/text.before.$k"; : > "$CFR_STAGE/text.after.$k"; done\n'
        'CFP_CROND_UNINSTALL=2 CFP_CROND_BASELINE=2\n'
        'cfr_snapshot() { echo same > "$CFR_STAGE/snapshot.$1"; }\ncfr_snapshot before\n%s\ncfp_restore\n')

    def test_one_restore_verdict_only_after_the_teardown_proof(self):
        done = self.run_driver(self.RESTORE_DRIVER % ':')
        self.assertEqual(done.stdout.count('PHASE RESTORE OK'), 1, done.stdout)
        self.assertNotIn('RESTORE FAIL', done.stdout)
        done = self.run_driver(self.RESTORE_DRIVER % 'mkdir -p "$CFR_RELEASE_DIR"')
        self.assertIn('PHASE RESTORE FAIL teardown_release_dir_left', done.stdout)
        self.assertNotIn('PHASE RESTORE OK', done.stdout)
        done = self.run_driver(self.RESTORE_DRIVER % 'rm -f "$CFR_STAGE/text.after.iptables"')
        self.assertNotIn('PHASE RESTORE OK', done.stdout)
        done = self.run_driver(self.RESTORE_DRIVER % 'cfr_snapshot() { return 1; }')
        self.assertIn('PHASE RESTORE FAIL snapshot_failed', done.stdout)
        self.assertNotIn('PHASE RESTORE OK', done.stdout)


class PilotV2FixtureTests(PilotShellBase):
    """End to end against the fixture router, schema v2. The real T4 driver starts each commit leg when it sees a valid
    marker; tests/fake-leg-ssh.py plays `ssh -tt` (own pty, the repository's cfctl). Slow (every phase installs, syncs
    and uninstalls)."""

    def setUp(self):
        super().setUp()
        leg_patch = mock.patch.object(self.tool.V2, 'SCOPE_LEG_SECONDS', 15)
        leg_patch.start()
        self.addCleanup(leg_patch.stop)
        # The router's own interfaces (scope-add refuses a router address and needs to read them).
        for name, mac in (('lo', '00:00:00:00:00:00'), ('br-lan', '02:00:00:00:00:01')):
            (self.root / 'sys/class/net' / name).mkdir(parents=True)
            (self.root / 'sys/class/net' / name / 'address').write_text(mac + '\n')
        leases = self.root / 'tmp/dhcp.leases'
        leases.write_text(leases.read_text() + f'1800000000 {PHONE["mac"]} {PHONE["ip"]} phone *\n'
                          f'1800000000 {SENTINEL_MAC} 192.0.2.77 {SENTINEL_HOST} *\n')
        self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'),
                                               dict(PENN, state='DELAY'), dict(PHONE, state='REACHABLE'),
                                               dict(ip='192.0.2.77', mac=SENTINEL_MAC, state='REACHABLE')])
        # Wrapper positives need a cfctl at $CF_BACKEND_DIR/cfctl: re-enter the fixture's installed cfctl with the
        # test environment, keeping what the wrappers pass through.
        env = {k: v for k, v in self.spec['env'].items() if k.startswith('CF_') or k == 'PATH'}
        target = self.fixture.bin / 'cfctl'
        target.write_text('#!/bin/sh\nexec env -i ' + ' '.join(shlex.quote(f'{k}={v}') for k, v in env.items())
                         + ' SSH_CONNECTION="$SSH_CONNECTION" SSH_CLIENT="$SSH_CLIENT" CF_SCOPE_ADMIN="$CF_SCOPE_ADMIN" '
                         + f'{os.environ.get("CF_TEST_SHELL", "sh")} {shlex.quote(str(self.root / "usr/sbin/cfctl"))} "$@"\n')
        target.chmod(0o700)
        self.leg_log = self.work / 'legs.jsonl'
        self.spec['env'].update(CFP_WRAPPER_DIR=str(REPO / 'router'))
        self.spec['leg2'] = {'mode': 'fixture', 'wrapper_scope': str(REPO / 'router/cfctl-scope'), 'log': str(self.leg_log)}
        self.spec['leg_helper'] = str(REPO / 'tests/fake-leg-ssh.py')
        self.spec['cfctl'] = str(self.root / 'usr/sbin/cfctl')

    def run_v2(self, **changes):
        self.status_double('s/NOTHING_TO_REWRITE//', 0)
        code, out, err = self.execute(**self.v2_changes(**changes))
        if not any((self.evidence_root / 'evidence').iterdir()):
            self.fail(f'no evidence directory (refused before ssh): {out}{err}')
        return code, out, err

    status_double = PilotFixtureTests.status_double
    router_double = PilotFixtureTests.router_double

    def stdout_lines(self):
        return (self.evidence() / 'stdout.log').read_text().splitlines()

    def assert_no_leaks(self):
        for path in self.evidence().iterdir():
            text = path.read_text(errors='replace')
            for leaked in (SENTINEL_HOST, SENTINEL_MAC, SENTINEL_IP):
                self.assertNotIn(leaked, text, path.name)

    def test_v2_happy_path_passes_in_order_and_restores_exactly(self):
        before = self.router_snapshot()
        code, out, err = self.run_v2()
        stdout = self.stdout_lines()
        self.assertEqual(code, 0, out + err + '\n'.join(stdout[-50:]))
        self.assertEqual(self.router_snapshot(), before)
        self.assertEqual(stdout[-1], 'PENN_PILOT_PASS')
        phases = [line.split()[1] for line in stdout if line.startswith('PHASE ') and line.endswith(' OK')]
        self.assertEqual(phases, V2_PHASES)
        # Four commit legs ran under a pty, none refused; each marker is a strict line printed once.
        legs = json.loads((self.evidence() / 'legs.json').read_text())['legs']
        self.assertEqual([leg['leg'] for leg in legs], ['2a', '2b', '2c', '2d'])
        self.assertTrue(all((leg['outcome'], leg['exit'], leg['ok'], leg['confirmationSent']) == ('exited', 0, True, True)
                            for leg in legs), legs)
        ssh_calls = [json.loads(line) for line in self.ssh_log.read_text().splitlines()]
        self.assertEqual([('-T' in call, '-tt' in call) for call in ssh_calls], [(True, False)] + [(False, True)] * 4)
        self.assertFalse([line for line in stdout if line.startswith('CFP_LEG2_CANCEL')])
        markers = [line for line in stdout if line.startswith('CFP_LEG2_READY')]
        self.assertEqual([m.split()[1] for m in markers], ['2a', '2b', '2c', '2d'])
        self.assertTrue(all(re.fullmatch(r'CFP_LEG2_READY 2[a-d] [0-9a-f]{64}', m) for m in markers))
        # rpc-sync: enroll, phone, move, move back, pause_all, resume_all, unenrol. BULK is two of them.
        self.assertEqual(self.rpc_log.read_text().splitlines(), ['rpc-sync'] * 7)
        summary = json.loads((self.evidence() / 'summary.json').read_text())
        self.assertEqual(summary['outcome'], 'PASS')
        measured = summary['measurements']
        for name in ('scope_preview_add_1', 'scope_preview_add_2', 'scope_no_tty_refusal', 'scope_wrapper_argv_negatives',
                     'scope_leg_2a', 'scope_leg_2d', 'move_block_follows_device', 'bulk_receipts', 'bulk_ipv4', 'bulk_ipv6',
                     'inventory', 'teardown_proof'):
            self.assertIn(name, measured)
        self.assertEqual(measured['inventory']['label'], 'measured')
        self.assertRegex(measured['inventory']['detail'], r'device_counts=[0-9]+,[0-9]+,[0-9]+ protected_listed=0 penn_devices_listed=2')
        self.assertIn('revisions=8,9,10', measured['bulk_receipts']['detail'])
        self.assertIn('scope_candidates=0', measured['teardown_proof']['detail'])
        self.assertEqual(self.stage_leftovers, [])
        self.assert_no_leaks()
        self.assertEqual(summary['legs']['legs'], legs)

    def test_v2_leg_that_never_runs_stops_and_tears_down_once_with_exact_restore(self):
        # The 2c leg's ssh dies before it reaches cfctl: leg 1 sees no change, stops, and nothing is retried.
        self.spec['leg2']['exit255_match'] = 'scope-add.*cfctl-scope'
        before = self.router_snapshot()
        code, out, err = self.run_v2()
        stdout = self.stdout_lines()
        self.assertEqual(code, 2, out + err + '\n'.join(stdout[-40:]))
        self.assertIn('STOP SCOPE-ADD-2 scope_leg_timeout', stdout)
        self.assertEqual(sum('-tt' in json.loads(line) for line in self.ssh_log.read_text().splitlines()), 3)
        # The outstanding leg is cancelled before the single uninstall.
        self.assertLess(stdout.index('CFP_LEG2_CANCEL 2c'), next(i for i, l in enumerate(stdout) if l.startswith('INFO run uninstall.sh once')))
        self.assertEqual(sum(line.startswith('INFO run uninstall.sh once') for line in stdout), 1)
        self.assertEqual(stdout.count('PHASE UNINSTALL OK'), 1)
        self.assertIn('PHASE RESTORE OK', stdout)
        self.assertEqual(stdout[-1], 'PENN_PILOT_STOPPED_RESTORED')
        self.assertNotIn('PHASE PAUSE OK', stdout)
        self.assertEqual(self.router_snapshot(), before)
        self.assertEqual(self.stage_leftovers, [])
        self.assertEqual(json.loads((self.evidence() / 'summary.json').read_text())['outcome'], 'STOPPED')
        self.assert_no_leaks()

    def test_v2_wrong_confirmation_is_a_refused_leg_and_leg_one_does_not_believe_anything(self):
        self.spec['leg2']['wrong_digits_match'] = '^timeout -s KILL [0-9]+ /usr/sbin/cfctl scope-add'
        before = self.router_snapshot()
        code, out, err = self.run_v2()
        stdout = self.stdout_lines()
        self.assertEqual(code, 2, out + err + '\n'.join(stdout[-40:]))
        self.assertIn('STOP SCOPE-ADD-1 scope_leg_timeout', stdout)
        legs = json.loads((self.evidence() / 'legs.json').read_text())['legs']
        self.assertEqual((legs[0]['ok'], legs[0]['errors']), (False, ['scope_confirmation_mismatch']))
        self.assertEqual(len(legs), 1)
        self.assertEqual(stdout[-1], 'PENN_PILOT_STOPPED_RESTORED')
        self.assertEqual(self.router_snapshot(), before)

    def test_v2_self_abort_at_seventy_percent_ends_stopped_and_restored(self):
        # The router's uptime clock (the elapsed/abort clock; CFP_UPTIME_FILE is honoured in fixture mode only)
        # jumps past 70% of remoteTimeoutSeconds once ENROLL is done. The wall clock `date` is untouched.
        uptime = self.work / 'uptime'
        uptime.write_text('1000000.00 0.00\n')
        self.spec['env']['CFP_UPTIME_FILE'] = str(uptime)
        self.spec['touch_on']['PHASE ENROLL OK'] = [str(uptime), '1007000.00 0.00\n']
        before = self.router_snapshot()
        code, out, err = self.run_v2()
        stdout = self.stdout_lines()
        self.assertEqual(code, 2, out + err + '\n'.join(stdout[-40:]))
        self.assertTrue(any(line.startswith('STOP ') and line.endswith(' remote_self_abort') for line in stdout), stdout[-20:])
        self.assertEqual(sum(line.startswith('INFO run uninstall.sh once') for line in stdout), 1)
        self.assertEqual(self.router_snapshot(), before)
        self.assertNotIn('PENN_PILOT_PASS', stdout)


class PilotTermGraceTests(PilotShellBase):
    """Second security pass: every cfctl, wrapper and uninstall child gets TERM at its allowance (cfctl and the
    installers trap it and release /tmp/couvrefeu-platform.lock) and KILL only after a grace; a KILL that leaves the
    platform lock is reported with the manual recovery; the leg-2 quiesce needs the driver's acknowledgement."""

    TERM_TRAP = ('#!/bin/sh\ntrap \'echo released > "$H/lock-released"; rmdir "$H/lock"; kill "$s" 2>/dev/null; exit 143\' TERM\n'
                 'mkdir "$H/lock"\nsleep 30 >/dev/null 2>&1 &\ns=$!\nwait\n')
    TERM_IGNORED = ('#!/bin/sh\ntrap \'\' TERM\nmkdir "$PLOCK"\nwhile :; do sleep 1; done >/dev/null 2>&1\n')
    TEARDOWN = r"""
CFR_RELEASE_DIR=$H/rel
mkdir -p "$CFR_RELEASE_DIR"
cp "$H/uninstall.sh" "$CFR_RELEASE_DIR/uninstall.sh"
cfr_snapshot() { return 1; }
cfp_kernel_state() { echo stub; }
cfp_crond_count() { :; }
"""

    def term_driver(self, call, allowance=1, grace=3, shell='sh'):
        return (f'export H\nCFR_SH={shlex.quote(shell)}\nPLOCK=$H/plock\nexport PLOCK\nCFR_PLATFORM_LOCK=$PLOCK\n'
                f'CFR_CFCTL=$H/cfctl.sh\nCFP_CFCTL_ALLOWANCE={allowance}\nCFP_KILL_GRACE={grace}\nt0=$(date +%s)\n' + call
                + '\necho "ELAPSED:$(( $(date +%s) - t0 ))"\n')

    def elapsed(self, done):
        return int(re.search(r'ELAPSED:([0-9]+)', done.stdout).group(1))

    def test_a_hung_cfctl_gets_term_first_and_releases_its_lock(self):
        for shell in ('sh', 'busybox ash'):
            if shell != 'sh' and not shutil.which('busybox'):
                continue
            with self.subTest(shell=shell):
                done = self.run_driver(self.term_driver('cfp_cfctl status --json > /dev/null; echo "RC:$?"', shell=shell),
                                       files={'cfctl.sh': self.TERM_TRAP}, timeout=60)
                self.assertIn('RC:143', done.stdout, done.stdout + done.stderr)
                self.assertEqual((done.home / 'lock-released').read_text().strip(), 'released')
                self.assertFalse((done.home / 'lock').exists())
                self.assertLess(self.elapsed(done), 3, 'TERM must come at the allowance, not after the grace')

    def test_term_reaches_the_child_when_the_session_ignores_term_as_the_teardown_does(self):
        done = self.run_driver(self.term_driver("trap '' INT TERM\ncfp_cfctl status --json > /dev/null; echo \"RC:$?\""),
                               files={'cfctl.sh': self.TERM_TRAP}, timeout=60)
        self.assertIn('RC:143', done.stdout, done.stdout + done.stderr)
        self.assertTrue((done.home / 'lock-released').exists())

    def test_a_child_that_ignores_term_is_killed_after_the_grace(self):
        done = self.run_driver(self.term_driver('cfp_cfctl status --json > /dev/null; echo "RC:$?"'),
                               files={'cfctl.sh': self.TERM_IGNORED}, timeout=60)
        self.assertIn('RC:137', done.stdout, done.stdout + done.stderr)
        self.assertGreaterEqual(self.elapsed(done), 3, 'KILL only after the grace')
        self.assertLess(self.elapsed(done), 10)
        self.assertTrue((done.home / 'plock').is_dir(), 'a KILL skips the trap: the lock stays')

    def test_a_child_term_stage_is_not_skipped_for_the_wrapper(self):
        driver = self.term_driver("cfp_wrapper_run cfctl-ssh 'cfctl rpc-inventory --json' --rpc-only > /dev/null; echo \"RC:$?\"")
        driver = 'mkdir -p "$CFR_ROOT/usr/sbin"\ncp "$H/cfctl.sh" "$CFR_ROOT/usr/sbin/cfctl-ssh"\n' + driver
        done = self.run_driver(driver, files={'cfctl.sh': self.TERM_TRAP}, timeout=60)
        self.assertIn('RC:143', done.stdout, done.stdout + done.stderr)
        self.assertTrue((done.home / 'lock-released').exists())

    def test_a_stale_platform_lock_after_a_kill_is_reported_with_the_manual_recovery(self):
        driver = self.TEARDOWN + self.term_driver('cfp_cfctl status --json > /dev/null || cfp_stop PHASE rpc_status_failed')
        done = self.run_driver(driver, files={'cfctl.sh': self.TERM_IGNORED, 'uninstall.sh': 'exit 1\n'}, timeout=60,
                               stub_stop=False)
        self.assertEqual(self.stop_of(done), ['STOP PHASE platform_lock_stale_after_kill'], done.stdout)
        note = [line for line in done.stdout.splitlines() if 'stale_platform_lock' in line]
        self.assertEqual(len(note), 1, done.stdout)
        self.assertIn('cfctl recover-platform-lock', note[0])
        self.assertIn('password login', note[0])
        self.assertEqual(done.stdout.count('run uninstall.sh once'), 1, 'the run still tears down')
        self.assertEqual(done.stdout.splitlines()[-1], 'FAIL_AFTER_MUTATION UNINSTALL')

    def test_no_stale_lock_note_without_a_lock(self):
        done = self.run_driver(self.term_driver('cfp_cfctl status --json > /dev/null; echo "RC:$?"'),
                               files={'cfctl.sh': '#!/bin/sh\ntrap \'\' TERM\nwhile :; do sleep 1; done >/dev/null 2>&1\n'}, timeout=60)
        self.assertIn('RC:137', done.stdout)
        self.assertNotIn('stale_platform_lock', done.stdout)

    def test_the_uninstall_is_termed_at_its_allowance_and_reported_as_a_timeout(self):
        uninstall = '#!/bin/sh\ntrap \'echo term > "$H/term-seen"; exit 143\' TERM\nsleep 30 >/dev/null 2>&1 &\nwait\n'
        driver = 'export H\n' + self.TEARDOWN + 'CFP_UNINSTALL_ALLOWANCE=1\nCFP_KILL_GRACE=3\ncfp_teardown\n'
        done = self.run_driver(driver, files={'uninstall.sh': uninstall}, timeout=60)
        self.assertEqual((done.home / 'term-seen').read_text().strip(), 'term', done.stdout + done.stderr)
        self.assertIn('PHASE UNINSTALL FAIL uninstall_timeout', done.stdout)
        self.assertEqual(done.stdout.splitlines()[-1], 'FAIL_AFTER_MUTATION UNINSTALL')

    def test_the_uninstall_allowance_is_not_shorter_than_the_install_allowance(self):
        text = (REPO / 'tools/live/penn-pilot.sh').read_text()
        allowance = int(re.search(r'^CFP_UNINSTALL_ALLOWANCE=([0-9]+)$', text, re.M).group(1))
        self.assertGreaterEqual(allowance, self.tool.INSTALL_ALLOWANCE_SECONDS)
        grace = int(re.search(r'^CFP_KILL_GRACE=([0-9]+)$', text, re.M).group(1))
        self.assertEqual(grace, self.tool.KILL_GRACE_SECONDS)
        # teardown arithmetic: ack/quiesce wait + one safe-band wait + uninstall + grace stay inside the reserve
        self.assertLess(20 + 71 + allowance + grace, self.tool.TEARDOWN_RESERVE_SECONDS)

    LEG_ACK = PilotReviewFixTests.LEG_DRIVER

    def leg_ack(self, setup, params=None):
        return self.run_driver(self.LEG_ACK % setup, files={'filesha': 'aaa\n'}, params=params, timeout=60)

    def test_quiesce_waits_for_the_driver_acknowledgement(self):
        # Quiet from the start (the leg has not started): only the acknowledgement lets the uninstall proceed.
        done = self.leg_ack('CFP_LEG2_ACTIVE=2a\n( sleep 3; : > "$CFR_STAGE/leg2-idle" ) &\nt0=$(date +%s)\n'
                            'cfr_uninstall_probe() { :; }\n')
        lines = done.stdout.splitlines()
        self.assertIn('CFP_LEG2_CANCEL 2a', lines, done.stdout)
        ack = [l for l in lines if l.startswith('CFP_LEG2_ACK_FILE ')]
        self.assertEqual(len(ack), 1, done.stdout)
        self.assertTrue(ack[0].endswith('/stage/leg2-idle'), ack)
        self.assertIn('INFO leg2_quiesced 2a', lines)
        self.assertNotIn('leg2_quiesce_timeout', done.stdout)

    def test_without_the_acknowledgement_the_wait_is_bounded_and_logged(self):
        t0 = time.monotonic()
        done = self.leg_ack('CFP_LEG2_ACTIVE=2a\n', params={'CFP_LEG2_CANCEL_WAIT': 2})
        self.assertGreaterEqual(time.monotonic() - t0, 2)
        self.assertIn('INFO leg2_quiesce_timeout 2a no_acknowledgement', done.stdout)
        self.assertIn('PHASE UNINSTALL FAIL', done.stdout)

    def test_a_stale_acknowledgement_does_not_count(self):
        done = self.leg_ack('CFP_LEG2_ACTIVE=2a\n: > "$CFR_STAGE/leg2-idle"\n', params={'CFP_LEG2_CANCEL_WAIT': 2})
        self.assertIn('leg2_quiesce_timeout 2a no_acknowledgement', done.stdout)

    def test_the_t4_contract_documents_the_acknowledgement(self):
        text = (REPO / 'tools/live/README.md').read_text()
        self.assertIn('CFP_LEG2_ACK_FILE', text)
        self.assertIn('leg2-idle', text)

    def test_raw_lan_files_are_removed_even_when_stdout_is_lost(self):
        raw = ('identity.neigh', 'coverage.leases', 'coverage.neigh4', 'coverage.neigh6', 'coverage.addr4', 'coverage.addr6',
               'members.all', 'members', 'members.list', 'fw.ipset', 'dns.out')
        driver = ''.join(f'echo secret > "$CFP_DIR/{name}"\n' for name in raw) + \
                 'echo secret > "$CFR_STAGE/connectivity.neigh"\necho keep > "$CFP_DIR/status.json"\n' \
                 'CFR_STDOUT_LOST=1\ncfp_cleanup\nls "$CFP_DIR" | tr "\\n" " "\nls "$CFR_STAGE" | grep -c connectivity.neigh\n'
        done = self.run_driver(driver)
        self.assertEqual(done.stdout.split(), ['status.json', '0'], done.stdout + done.stderr)

    def test_snapshot_reads_are_bounded_and_a_killed_read_fails_the_snapshot(self):
        for tool in ('iptables-save', 'ipset'):
            with self.subTest(tool=tool):
                driver = ('mkdir -p "$H/bin"\nfor t in iptables-save ip6tables-save ipset uci; do printf "#!/bin/sh\\necho x\\n" > "$H/bin/$t"; '
                          'chmod +x "$H/bin/$t"; done\n'
                          f'printf "#!/bin/sh\\nexec sleep 30\\n" > "$H/bin/{tool}"\nPATH=$H/bin:$PATH\n'
                          'CFP_READ_TIMEOUT=1\nCFR_FILES=\nCFR_DIRS=\nCFR_RELEASE_FILES=\n'
                          'cfr_file_record() { :; }\ncfr_dir_record() { :; }\ncfr_glob_count() { echo 0; }\n'
                          'CFR_STAGE_PARENT=/tmp CFR_STAGE_PREFIX=x CFR_RECOVERY=x CFR_RELEASE_DIR=x\n'
                          't0=$(date +%s)\ncfr_snapshot before; echo "RC:$?"\necho "ELAPSED:$(( $(date +%s) - t0 ))"\n')
                done = self.run_driver(driver, timeout=60)
                self.assertIn('RC:1', done.stdout, done.stdout + done.stderr)
                self.assertLess(self.elapsed(done), 10)

    def test_connectivity_neighbor_read_is_bounded(self):
        driver = ('mkdir -p "$H/bin"\nprintf "#!/bin/sh\\nexec sleep 30\\n" > "$H/bin/ip"\nchmod +x "$H/bin/ip"\nPATH=$H/bin:$PATH\n'
                  'CFP_READ_TIMEOUT=1\nt0=$(date +%s)\ncfr_connectivity\necho "ELAPSED:$(( $(date +%s) - t0 ))"\n')
        done = self.run_driver(driver, timeout=60)
        self.assertIn('CONNECTIVITY FAIL neighbor_read_failed', done.stdout, done.stdout + done.stderr)
        self.assertLess(self.elapsed(done), 10)


if __name__ == '__main__':
    unittest.main()
