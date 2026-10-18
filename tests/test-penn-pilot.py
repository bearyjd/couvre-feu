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
import json, os, re, shlex, signal, subprocess, sys, threading, time
spec = json.load(open(os.environ['FAKE_SSH_SPEC']))
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
                    shutil.rmtree(line.split(' ', 2)[2], ignore_errors=True)
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
                config = self.tool.load_config(self.write_config(roles=configured, scopeNegativeTest=True))
                policy = self.tool.enrollment_policy(config)
                self.assertEqual(policy['people'][0]['macs'], sorted([PENN['mac']] + ([PENN2['mac']] if second else [])))
                self.assertNotIn(MGMT['mac'], policy['people'][0]['macs'])
                self.plan_details(self.write_config(roles=configured, scopeNegativeTest=True))
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
        base = 'cfp_now() { echo 1100; }\nCFR_START=1000\nCFP_REMOTE_TIMEOUT=1000\nCFP_TEARDOWN_RESERVE=300\n'
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
                f'cfr_run_sh() {{ echo $(($(cat "$CLK") + {prior_call_s})) > "$CLK"; }}\n'
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
                'CFP_CFCTL_ALLOWANCE=45\nCFR_START=1000\nCFP_REMOTE_TIMEOUT=100000\nCFP_TEARDOWN_RESERVE=300\n'
                f'CFR_MGMT_MAC={MGMT["mac"]}\nCFR_JD_MAC={JD["mac"]}\nCFR_PENN_MAC={PENN["mac"]}\n'
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
        self.assertIn(f'{PENN["ip"]}=penn_child/STALE', neigh[0])
        self.assertIn(f'{MGMT["ip"]}=management/REACHABLE', neigh[0])
        self.assertRegex(neigh[0], r' ip6-[0-9a-f]{12}=mac-[0-9a-f]{12}/REACHABLE')
        self.assertIn('192.0.2.99=-/FAILED', neigh[0])
        for secret in ('02:00:00:00:00:77', 'fe80::77', PENN['mac'], MGMT['mac']):
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
        self.assertEqual(len(re.findall(r'(?m)^\s+cfp_status_settle ', script)), 2)
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
        call = tool.SAFE_BAND_WAIT_SECONDS + tool.CFCTL_ALLOWANCE_SECONDS
        # First attempt's neighbour read, the window, then one admitted attempt (neighbour read + call).
        self.assertEqual(tool.status_settle_worst_seconds(timing), 8 + 45 + 8 + call)
        phases = tool.phase_worst_seconds(timing)
        self.assertEqual(phases['ENROLL'], 3 * call + tool.COUNTERS_WORST_SECONDS + 178)
        self.assertEqual({name: tool.worst_case_seconds(timing, devices, scope)
                          for name, devices, scope in (('one', 1, False), ('two', 2, False),
                                                       ('one_scope', 1, True), ('two_scope', 2, True))},
                         {'one': 3318, 'two': 3435, 'one_scope': 3483, 'two_scope': 3600})
        self.assertLessEqual(tool.worst_case_seconds(timing, 2, True), 3600)
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
        call = tool.SAFE_BAND_WAIT_SECONDS + tool.CFCTL_ALLOWANCE_SECONDS
        expected = (call + timing['expirySeconds'] + tool.CFCTL_ALLOWANCE_SECONDS + timing['expiryToleranceSeconds']
                    + tool.iteration_worst_seconds(timing) + tool.COUNTERS_WORST_SECONDS + call
                    + tool.status_settle_worst_seconds(timing))
        self.assertEqual(tool.phase_worst_seconds(timing)['EXPIRY'], expected)
        # The shipped timing: 2962 with the pause extension, 3318 with the ENROLL and post-expiry status settles.
        self.assertEqual(tool.worst_case_seconds(dict(tool.TIMING, **SHIPPED_TIMING)), 3318)
        details = self.plan_details(self.write_config())
        self.assertEqual(details['timing']['cfctlAllowanceSeconds'], 45)
        config = tool.FR.load_config(self.write_config())
        commit, blobs = tool.FR.head_source()
        self.assertIn("CFP_CFCTL_ALLOWANCE='45'\n", tool.build_payload(config, commit, blobs, timing)[0].decode())

    def test_latency_guard_treats_empty_clock_as_zero(self):
        code, out = self.pilot_shell('cfp_now() { :; }\ncfp_lat_note 1000\necho "$cfp_lat $CFP_LAT_MAX"\n')
        self.assertEqual((code, out), (0, '0 0\n'))

    def test_empty_clock_stops_safely_instead_of_arithmetic_error(self):
        empty = 'cfp_now() { :; }\nCFR_START=1000\nCFP_REMOTE_TIMEOUT=1000\nCFP_TEARDOWN_RESERVE=300\n'
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
        self.assertEqual(self.tool.worst_case_seconds(shipped), 3318)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=1, scope=False), 3318)
        self.assertIn('CFP_RPC_ALLOW', payload)  # the template default, not a generated parameter
        self.assertEqual(self.tool.load_config(self.write_config()), self.tool.FR.load_config(self.write_config()))

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
        call = self.tool.SAFE_BAND_WAIT_SECONDS + self.tool.CFCTL_ALLOWANCE_SECONDS
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=2), 3318 + call)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=2), 3435)
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
        call = self.tool.SAFE_BAND_WAIT_SECONDS + self.tool.CFCTL_ALLOWANCE_SECONDS
        scope_worst = call + 2 * self.tool.FIREWALL_STATE_WORST_SECONDS
        self.assertEqual(self.tool.FIREWALL_STATE_WORST_SECONDS, 3 * self.tool.READ_TIMEOUT_SECONDS)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=1, scope=True), 3318 + scope_worst)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=1, scope=True), 3483)
        self.assertEqual(self.tool.worst_case_seconds(shipped, devices=2, scope=True), 3600)
        self.assertLessEqual(self.tool.worst_case_seconds(shipped, devices=2, scope=True), 3600)
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
        firewall = self.fixture.bin / 'firewall'
        real = self.fixture.bin / 'firewall.real'
        firewall.rename(real)
        protected = self.root / 'etc/couvrefeu/protected'
        firewall.write_text(f'#!/bin/sh\nif [ -f {shlex.quote(str(protected))} ]; then '
                            f'cat {shlex.quote(str(protected))} > {shlex.quote(str(protection))}; fi\n'
                            f'exec {shlex.quote(str(real))} "$@"\n')
        firewall.chmod(0o700)
        before = self.router_snapshot()
        code, out, err = self.execute(roles=roles, scopeNegativeTest=True)
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


if __name__ == '__main__':
    unittest.main()
