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
FAST_TIMING = {'pauseSeconds': 90, 'pauseObserveSeconds': 2, 'resumeObserveSeconds': 1, 'expirySeconds': 45,
               'expiryToleranceSeconds': 120, 'pollSeconds': 1, 'expiryPollSeconds': 1, 'safeBandStart': 0,
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

    def test_expiry_worst_case_includes_pause_extension_and_is_disclosed(self):
        timing, tool = self.tool.TIMING, self.tool
        call = tool.SAFE_BAND_WAIT_SECONDS + tool.CFCTL_ALLOWANCE_SECONDS
        expected = (call + timing['expirySeconds'] + tool.CFCTL_ALLOWANCE_SECONDS + timing['expiryToleranceSeconds']
                    + tool.iteration_worst_seconds(timing) + tool.COUNTERS_WORST_SECONDS + call)
        self.assertEqual(tool.phase_worst_seconds(timing)['EXPIRY'], expected)
        # The shipped timing: 2917 before the pause extension, 2962 with it.
        self.assertEqual(tool.worst_case_seconds(dict(tool.TIMING, **{
            'pauseSeconds': 180, 'pauseObserveSeconds': 60, 'resumeObserveSeconds': 20, 'expirySeconds': 120,
            'expiryToleranceSeconds': 150, 'pollSeconds': 10, 'expiryPollSeconds': 5})), 2962)
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


if __name__ == '__main__':
    unittest.main()
