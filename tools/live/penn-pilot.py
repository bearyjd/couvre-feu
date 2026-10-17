#!/usr/bin/env python3
"""Single-session one-device (Penn) live pilot: plan locally, then execute once.

`plan CONFIG` builds the exact payload and prints what the operator discloses.
`execute CONFIG --expect-plan-sha256 HEX` rebuilds the plan, refuses on any
digest mismatch, stale authorization or missing agent key, then runs one SSH
invocation with no retry while sampling host-side adult probes.

The configuration schema, source binding, SSH argv, deadline, agent and
evidence checks are imported from first-rehearsal.py; the remote script is the
filled rehearsal script followed by penn-pilot.sh. Standard library only; must
run as `python3 -I`.

Exit codes: 0 PASS, 1 REFUSED before any router mutation, 2 STOPPED/FAIL/UNKNOWN
after mutation possibly began.
"""
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any


def _load_rehearsal():
    # -I drops the script directory from sys.path; never write __pycache__,
    # which would make the committed-source check refuse.
    sys.dont_write_bytecode = True
    path = Path(__file__).resolve().with_name('first-rehearsal.py')
    spec = importlib.util.spec_from_file_location('couvre_feu_first_rehearsal', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FR = _load_rehearsal()
Refusal = FR.Refusal
EXIT_PASS, EXIT_REFUSED, EXIT_FAIL = FR.EXIT_PASS, FR.EXIT_REFUSED, FR.EXIT_FAIL
REMOTE_PASS, REMOTE_REFUSED, REMOTE_FAIL = FR.REMOTE_PASS, FR.REMOTE_REFUSED, FR.REMOTE_FAIL
TOOL_PATH = 'tools/live/penn-pilot.py'
PILOT_TEMPLATE = 'tools/live/penn-pilot.sh'
REHEARSAL_TAIL = ('# Parse everything above first; no child can read the remaining script.\n'
                  'cfr_main </dev/null\n'
                  '# Unreachable unless cfr_main returns; fail closed.\n'
                  '# shellcheck disable=SC2317\n'
                  'exit 20\n')
PHASES = ('PAYLOAD', 'IDENTITY', 'PREREQ', 'SNAPSHOT', 'BASELINE', 'INSTALL', 'ENROLL', 'PAUSE', 'RESUME',
          'EXPIRY', 'DNS', 'UNINSTALL', 'RESTORE', 'CONNECTIVITY')
PASS_LINE = 'PENN_PILOT_PASS'
STOPPED_LINE = 'PENN_PILOT_STOPPED_RESTORED'
STOPPED_NO_CONNECTIVITY_LINE = 'PENN_PILOT_STOPPED_RESTORED_CONNECTIVITY_FAILED'
PERSON = 'penn'
OPERATION_ID = 'penn-pilot-enroll-1'
DNS_PROBE_NAME = 'example.com'
# Predeclared, disclosed and digest-bound. Every pause is timed (--until).
TIMING = {'pauseSeconds': 180, 'pauseObserveSeconds': 60, 'resumeObserveSeconds': 20,
          'expirySeconds': 120, 'expiryToleranceSeconds': 150, 'pollSeconds': 10, 'expiryPollSeconds': 5,
          'safeBandStart': 15, 'safeBandEnd': 45, 'dnsMarginCs': 150, 'rttMarginMs': 500,
          'premutationBudgetSeconds': 360}
HOST_PROBE = {'intervalSeconds': 15, 'samples': 3, 'timeoutSeconds': 2, 'dnsMarginMs': 1500,
              'rttMarginMs': 500, 'consecutiveFailures': 2}
# Worst-case allowances for the remote session; remoteTimeoutSeconds must cover them.
# The remote script re-checks each phase's worst case (and every observe/expiry
# iteration) against the teardown reserve before starting it.
SAFE_BAND_WAIT_SECONDS = 72
CFCTL_ALLOWANCE_SECONDS = 45
INSTALL_ALLOWANCE_SECONDS = 240
TEARDOWN_RESERVE_SECONDS = 300
# Router-side `timeout -s KILL` bound for each read-only iptables/ipset read.
READ_TIMEOUT_SECONDS = 8
# One counters snapshot: five chains, each read with -S and -nvxL.
COUNTERS_WORST_SECONDS = 10 * READ_TIMEOUT_SECONDS
# One adult-probe iteration before its poll sleep: nslookup (5 s), two pings
# (8 s each) and one ipset read, rounded up.
PROBE_ITERATION_SECONDS = 30
# The tool cannot measure these; they are never reported otherwise.
ALWAYS_UNMEASURED = {
    'service_key_confinement': 'not_exercised; no authorized_keys or service-key provisioning',
    'ipv4_cutoff_client_timestamps': 'no client-origin traffic capture in this tool',
    'client_dns_redirect_and_doh': 'client-side measurement not performed; router counters only',
    'inbound_udp_continuing': 'no continuing client UDP flow measured',
    'ipv6_client_traffic': 'not measured',
    'acceleration_offload_coverage': 'not measured; offload left untouched',
}
MAC_TOKEN = re.compile(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}')
PARAM_VALUE = re.compile(r'[0-9A-Za-z.:_ {}\[\]",-]+')


def validate_timing(timing):
    for key, value in timing.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise Refusal(f'timing {key} must be a non-negative integer')
    if not 0 <= timing['safeBandStart'] <= timing['safeBandEnd'] <= 59:
        raise Refusal('timing safe band must lie within 0..59')
    if timing['pauseSeconds'] < timing['pauseObserveSeconds'] + timing['pollSeconds'] + 20:
        raise Refusal('timing pause must outlast its observation window')
    if min(timing['pollSeconds'], timing['expiryPollSeconds'], timing['expirySeconds']) < 1:
        raise Refusal('timing polls and expiry pause must be at least one second')


def iteration_worst_seconds(timing):
    return PROBE_ITERATION_SECONDS + max(timing['pollSeconds'], timing['expiryPollSeconds'])


def phase_worst_seconds(timing):
    """Worst case of each post-install phase, as the remote script budgets it."""
    call = SAFE_BAND_WAIT_SECONDS + CFCTL_ALLOWANCE_SECONDS
    snap, read, iteration = COUNTERS_WORST_SECONDS, READ_TIMEOUT_SECONDS, iteration_worst_seconds(timing)
    return {
        # rpc-status, rpc-sync, status; counters enrolled
        'ENROLL': 3 * call + snap,
        # counters prepause, pause, kernel read, counters pause0, observe, counters pause1
        'PAUSE': snap + call + read + snap + timing['pauseObserveSeconds'] + iteration + snap,
        # resume, kernel read, counters resume0, observe, counters resume1
        'RESUME': call + read + snap + timing['resumeObserveSeconds'] + iteration + snap,
        # pause (extended by up to one cfctl allowance), wait until expiry plus tolerance, counters expired, status
        'EXPIRY': (call + timing['expirySeconds'] + CFCTL_ALLOWANCE_SECONDS + timing['expiryToleranceSeconds']
                   + iteration + snap + call),
        # counters final
        'DNS': snap,
    }


def worst_case_seconds(timing):
    # The install waits for one safe band before running.
    return (timing['premutationBudgetSeconds'] + SAFE_BAND_WAIT_SECONDS + INSTALL_ALLOWANCE_SECONDS
            + sum(phase_worst_seconds(timing).values()) + TEARDOWN_RESERVE_SECONDS)


def enrollment_policy(config):
    return {'version': 1, 'revision': 1, 'people': [{'id': PERSON, 'macs': [config['roles']['penn_child']['mac']]}],
            'pauses': [], 'schedules': [], 'doh': {'ipv4': [], 'ipv6': []}}


def assert_policy_only_penn(policy, config):
    """The enrolled policy names Penn's MAC and nothing else, ever."""
    roles = config['roles']
    penn = roles['penn_child']['mac']
    protected = {roles['management']['mac'], roles['jd_adult']['mac'], *config['protectedHistoricalMacs']}
    if penn in protected:
        raise Refusal('penn_child MAC is protected')
    if not isinstance(policy, dict) or set(policy) != {'version', 'revision', 'people', 'pauses', 'schedules', 'doh'}:
        raise Refusal('enrollment policy has unexpected fields')
    if policy['people'] != [{'id': PERSON, 'macs': [penn]}]:
        raise Refusal('enrollment policy must contain exactly one person with only the penn_child MAC')
    if policy['pauses'] or policy['schedules'] or policy['doh'] != {'ipv4': [], 'ipv6': []}:
        raise Refusal('enrollment policy must not carry pauses, schedules or DoH addresses')
    if MAC_TOKEN.findall(json.dumps(policy).lower()) != [penn]:
        raise Refusal('enrollment policy contains a MAC other than penn_child')
    return policy


def build_payload(config, commit, blobs, timing):
    if PILOT_TEMPLATE not in blobs:
        raise Refusal('HEAD lacks the pilot script template')
    rehearsal, rehearsal_sha = FR.build_payload(config, commit, blobs)
    text = rehearsal.decode('utf-8')
    if text.count(REHEARSAL_TAIL) != 1 or not text.endswith(REHEARSAL_TAIL):
        raise Refusal('rehearsal script tail differs from the expected invocation')
    policy = assert_policy_only_penn(enrollment_policy(config), config)
    policy_json = json.dumps(policy, separators=(',', ':'), sort_keys=False)
    values = {'CFP_ROUTER_IP': config['host'], 'CFP_PERSON': PERSON, 'CFP_OPERATION_ID': OPERATION_ID,
              'CFP_POLICY': policy_json, 'CFP_DNS_NAME': DNS_PROBE_NAME,
              'CFP_PAUSE_SECONDS': timing['pauseSeconds'], 'CFP_PAUSE_OBSERVE': timing['pauseObserveSeconds'],
              'CFP_RESUME_OBSERVE': timing['resumeObserveSeconds'], 'CFP_EXPIRY_SECONDS': timing['expirySeconds'],
              'CFP_EXPIRY_TOLERANCE': timing['expiryToleranceSeconds'], 'CFP_POLL': timing['pollSeconds'],
              'CFP_EXPIRY_POLL': timing['expiryPollSeconds'],
              'CFP_SAFE_BAND': f"{timing['safeBandStart']} {timing['safeBandEnd']}",
              'CFP_DNS_MARGIN_CS': timing['dnsMarginCs'], 'CFP_RTT_MARGIN_MS': timing['rttMarginMs'],
              'CFP_PREMUTATION_BUDGET': timing['premutationBudgetSeconds'],
              'CFP_REMOTE_TIMEOUT': config['remoteTimeoutSeconds'], 'CFP_TEARDOWN_RESERVE': TEARDOWN_RESERVE_SECONDS,
              'CFP_READ_TIMEOUT': READ_TIMEOUT_SECONDS, 'CFP_COUNTERS_WORST': COUNTERS_WORST_SECONDS,
              'CFP_ITERATION_WORST': iteration_worst_seconds(timing),
              'CFP_CFCTL_ALLOWANCE': CFCTL_ALLOWANCE_SECONDS}
    values.update({f'CFP_WORST_{phase}': seconds for phase, seconds in phase_worst_seconds(timing).items()})
    values = {key: str(value) for key, value in values.items()}
    for value in values.values():
        if not PARAM_VALUE.fullmatch(value):
            raise Refusal('generated pilot parameter has unexpected characters')
    params = ''.join(f"{key}='{value}'\n" for key, value in values.items())
    template = blobs[PILOT_TEMPLATE]
    pilot = FR.replace_region(template.decode('utf-8'), 'CF_PILOT_PARAMETERS', params)
    payload = (text[:-len(REHEARSAL_TAIL)] + pilot).encode('utf-8')
    return payload, rehearsal_sha, hashlib.sha256(template).hexdigest(), policy_json


PLAN_DIGEST_FIELDS = FR.PLAN_DIGEST_FIELDS + ('tool', 'phases', 'timing', 'hostProbe', 'dnsProbeName', 'person',
                                              'operationId', 'policySha256')


def plan_digest(details):
    bound = {field: details[field] for field in PLAN_DIGEST_FIELDS}
    return hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def plan(config, env):
    validate_timing(TIMING)
    minimum = worst_case_seconds(TIMING)
    if config['remoteTimeoutSeconds'] < minimum:
        raise Refusal(f'remoteTimeoutSeconds must be at least {minimum} for the pilot worst case')
    commit, blobs = FR.head_source()
    payload, rehearsal_sha, pilot_sha, policy_json = build_payload(config, commit, blobs, TIMING)
    argv = FR.ssh_argv(config, env)
    details = {'tool': TOOL_PATH, 'sourceCommit': commit, 'releaseId': FR.release_id(blobs),
               'platformProfile': config['platformProfile'], 'payloadSha256': hashlib.sha256(payload).hexdigest(),
               'payloadBytes': len(payload), 'remoteScriptSha256': rehearsal_sha, 'pilotScriptSha256': pilot_sha,
               'sshArgv': argv, 'sshCommandLine': shlex.join(argv), 'remoteTimeoutSeconds': config['remoteTimeoutSeconds'],
               'localTimeoutSeconds': config['remoteTimeoutSeconds'] + FR.LOCAL_TIMEOUT_EXTRA_SECONDS,
               'minimumRemoteTimeoutSeconds': minimum, 'deadlineUtc': config['deadlineUtc'],
               'authorizationPath': config['authorizationPath'], 'evidenceDir': config['evidenceDir'],
               'roles': config['roles'], 'protectedHistoricalMacs': config['protectedHistoricalMacs'],
               'knownHostsSha256': FR.regular_file_sha256(config['knownHostsPath'], 'knownHostsPath'),
               'adminPublicKeySha256': FR.regular_file_sha256(config['adminPublicKeyPath'], 'adminPublicKeyPath'),
               'phases': list(PHASES), 'timing': dict(TIMING, cfctlAllowanceSeconds=CFCTL_ALLOWANCE_SECONDS), 'hostProbe': dict(HOST_PROBE),
               'dnsProbeName': DNS_PROBE_NAME, 'person': PERSON, 'operationId': OPERATION_ID,
               'policyJson': policy_json, 'policySha256': hashlib.sha256(policy_json.encode()).hexdigest(),
               'pauseRulesKernelTimeBound': False,
               'serviceKeyConfinement': 'not exercised'}
    details['planSha256'] = plan_digest(details)
    return details, payload


def dns_query_ms(server, name, timeout):
    """One A query straight to the router resolver; None unless a positive answer arrives."""
    query_id = os.urandom(2)
    question = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.')) + b'\0'
    packet = query_id + struct.pack('>HHHHH', 0x0100, 1, 0, 0, 0) + question + struct.pack('>HH', 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            started = time.monotonic()
            sock.sendto(packet, (server, 53))
            for _ in range(8):
                data, address = sock.recvfrom(1500)
                if address[0] == server and len(data) >= 12 and data[:2] == query_id:
                    elapsed = (time.monotonic() - started) * 1000
                    flags, answers = struct.unpack('>H', data[2:4])[0], struct.unpack('>H', data[6:8])[0]
                    return round(elapsed, 1) if flags & 0x8000 and flags & 0xF == 0 and answers else None
    except OSError:
        return None
    return None


def default_probe(host):
    """Host-side adult probe: one ICMP echo and one DNS query to the router."""
    ping_ms = None
    ping = shutil.which('ping')
    if ping:
        try:
            result = subprocess.run([ping, '-n', '-c', '1', '-W', str(HOST_PROBE['timeoutSeconds']), host],
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
            match = re.search(r'time[=<]([0-9.]+) ?ms', result.stdout)
            ping_ms = float(match.group(1)) if result.returncode == 0 and match else None
        except (OSError, subprocess.TimeoutExpired):
            ping_ms = None
    return {'pingMs': ping_ms, 'dnsMs': dns_query_ms(host, DNS_PROBE_NAME, HOST_PROBE['timeoutSeconds'])}


class HostProbes:
    """Evidence only: host probes never stop or alter the remote script."""

    def __init__(self, probe, host):
        self.probe, self.host = probe, host
        self.samples = []
        self.stop_event = threading.Event()
        self.thread = None

    def sample(self, phase):
        try:
            result = dict(self.probe(self.host))
        except Exception as error:  # a broken probe is a failed sample, not a crash
            result = {'pingMs': None, 'dnsMs': None, 'error': type(error).__name__}
        result.update(phase=phase, monotonic=round(time.monotonic(), 3))
        self.samples.append(result)

    def collect(self, phase):
        for index in range(HOST_PROBE['samples']):
            if index:
                time.sleep(1)
            self.sample(phase)

    def start(self):
        def loop():
            while not self.stop_event.wait(HOST_PROBE['intervalSeconds']):
                self.sample('during')
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(HOST_PROBE['intervalSeconds'] + 30)


def evaluate_host(samples):
    """Predeclared tolerance relative to the pre-session baseline."""
    result: dict[str, Any] = {'adultDisruption': False}
    for metric, margin in (('pingMs', HOST_PROBE['rttMarginMs']), ('dnsMs', HOST_PROBE['dnsMarginMs'])):
        baseline = [s[metric] for s in samples if s['phase'] == 'before' and s.get(metric) is not None]
        if not baseline:
            result[metric] = {'label': 'unmeasured', 'detail': 'no successful baseline sample'}
            continue
        limit = max(baseline) + margin
        run = worst_run = 0
        failures = 0
        after_failure = False
        for sample in samples:
            if sample['phase'] == 'before':
                continue
            failed = sample.get(metric) is None or sample[metric] > limit
            failures += failed
            run = run + 1 if failed else 0
            worst_run = max(worst_run, run)
            after_failure = after_failure or (failed and sample['phase'] == 'after')
        disrupted = worst_run >= HOST_PROBE['consecutiveFailures'] or after_failure
        result[metric] = {'label': 'measured', 'baselineMaxMs': max(baseline), 'limitMs': limit,
                          'failures': failures, 'samples': sum(s['phase'] != 'before' for s in samples),
                          'disruption': disrupted}
        result['adultDisruption'] = result['adultDisruption'] or disrupted
    return result


def measurements(lines):
    result = {}
    for line in lines:
        parts = line.split(' ', 3)
        if (len(parts) >= 3 and parts[0] == 'MEASURE' and re.fullmatch(r'[a-z0-9_]+', parts[1])
                and parts[2] in ('measured', 'unmeasured')):
            result[parts[1]] = {'label': parts[2], 'detail': parts[3] if len(parts) == 4 else ''}
    for name, detail in ALWAYS_UNMEASURED.items():
        result[name] = {'label': 'unmeasured', 'detail': detail}
    blocking = result.get('packet_blocking', {}).get('label') == 'measured'
    result['packet_blocking_summary'] = {'label': 'measured' if blocking else 'unmeasured',
                                         'detail': 'router-side block observed' if blocking else 'packet blocking unmeasured'}
    return result


def classify(stdout_text, remote_exit, timed_out):
    lines = stdout_text.splitlines()
    phases = {}
    for line in lines:
        parts = line.split(' ', 3)
        if len(parts) >= 3 and parts[0] == 'PHASE' and parts[1] in PHASES:
            phases.setdefault(parts[1], []).append(parts[2] if len(parts) == 3 else parts[2] + ' ' + parts[3])
    stopped = any(line.startswith('STOP ') for line in lines)
    passed = (not timed_out and remote_exit == REMOTE_PASS and lines.count(PASS_LINE) == 1 and lines[-1] == PASS_LINE
              and 'MUTATION_BEGIN' in lines and not stopped
              and all(phases.get(name) == ['OK'] for name in PHASES) and len(phases) == len(PHASES))
    if passed:
        return 'PASS', EXIT_PASS, phases
    refused = (not timed_out and remote_exit == REMOTE_REFUSED and 'MUTATION_BEGIN' not in lines
               and PASS_LINE not in lines and any(line.startswith('REFUSED_BEFORE_MUTATION ') for line in lines))
    if refused:
        return 'REFUSED', EXIT_REFUSED, phases
    torn_down = (not timed_out and remote_exit == REMOTE_FAIL and stopped and bool(lines)
                 and phases.get('UNINSTALL') == ['OK'] and phases.get('RESTORE') == ['OK'])
    if torn_down and lines[-1] == STOPPED_LINE and phases.get('CONNECTIVITY') == ['OK']:
        return 'STOPPED', EXIT_FAIL, phases
    if (torn_down and lines[-1] == STOPPED_NO_CONNECTIVITY_LINE
            and any(result.startswith('FAIL') for result in phases.get('CONNECTIVITY', []))):
        return 'STOPPED_CONNECTIVITY_FAILED', EXIT_FAIL, phases
    failed = any(result.startswith('FAIL') for results in phases.values() for result in results)
    if not timed_out and remote_exit in (REMOTE_FAIL, REMOTE_PASS) and (failed or remote_exit == REMOTE_PASS):
        return 'FAIL', EXIT_FAIL, phases
    return 'UNKNOWN', EXIT_FAIL, phases


MESSAGES = {'PASS': 'PASS: every phase passed; original state restored exactly. Packet blocking: {blocking}.',
            'STOPPED': 'STOPPED: a predeclared gate stopped the pilot; teardown ran and restored the original state exactly.',
            'STOPPED_CONNECTIVITY_FAILED': ('STOPPED: a predeclared gate stopped the pilot; teardown restored the original '
                                            'files and firewall exactly, but the post-teardown CONNECTIVITY check FAILED '
                                            '(management or JD adult neighbor lost). Check adult connectivity now; do not retry.'),
            'REFUSED': 'REFUSED: the remote script refused before any router mutation.',
            'FAIL': 'FAIL: mutation may have begun or a gate failed. Preserve evidence; do not retry.',
            'UNKNOWN': FR.MESSAGES['UNKNOWN']}
PRINTED = ('PHASE ', 'DIFF ', 'REFUSED_', 'FAIL_', 'STOP', 'MEASURE ', 'PENN_KERNEL_STATE ', PASS_LINE)


def execute(config, expected_plan_sha, env, now_fn, probe):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_plan_sha or ''):
        raise Refusal('--expect-plan-sha256 must be 64 lowercase hex characters')
    details, payload = plan(config, env)
    if not hmac.compare_digest(details['planSha256'], expected_plan_sha):
        raise Refusal(f'plan sha256 {details["planSha256"]} differs from the disclosed value')
    FR.check_deadline(config, now_fn())
    details['authorizationSha256'] = FR.regular_file_sha256(config['authorizationPath'], 'authorizationPath')
    FR.check_agent(config, env)
    started = now_fn()
    directory = FR.evidence_directory(config, started, suffix='penn-pilot')
    FR.write_evidence(directory, 'plan.json', json.dumps(details, indent=2, sort_keys=True) + '\n')
    stdout_fd = FR.open_evidence(directory, 'stdout.log')
    stderr_fd = FR.open_evidence(directory, 'stderr.log')
    try:
        FR.check_deadline(config, now_fn())
    except Refusal:
        os.close(stdout_fd)
        os.close(stderr_fd)
        FR.write_evidence(directory, 'summary.json', json.dumps({'outcome': 'REFUSED', 'reason': 'deadline'}) + '\n')
        raise
    print(f'Evidence: {directory}', flush=True)
    print('Connecting once; no retry. Do not interrupt.', flush=True)
    # From the first probe onward every failure, including Ctrl-C, is UNKNOWN (exit 2).
    try:
        probes = HostProbes(probe, config['host'])
        probes.collect('before')
        probes.start()
        try:
            remote_exit, timed_out = FR.run_ssh(details['sshArgv'], payload, env, stdout_fd, stderr_fd,
                                                details['localTimeoutSeconds'])
        finally:
            os.close(stdout_fd)
            os.close(stderr_fd)
            probes.stop()
        probes.collect('after')
        stdout_text = Path(directory, 'stdout.log').read_text(errors='replace')
        outcome, code, phases = classify(stdout_text, remote_exit, timed_out)
        host = evaluate_host(probes.samples)
        reasons = []
        if outcome == 'PASS' and host['adultDisruption']:
            outcome, code = 'FAIL', EXIT_FAIL
            reasons.append('host_adult_disruption')
        measured = measurements(stdout_text.splitlines())
        FR.write_evidence(directory, 'exit-code.txt', f'{remote_exit}\n')
        FR.write_evidence(directory, 'host-probes.json', json.dumps(probes.samples, indent=2) + '\n')
        summary = {'outcome': outcome, 'exitCode': code, 'remoteExit': remote_exit, 'timedOut': timed_out,
                   'reasons': reasons, 'phases': phases, 'measurements': measured, 'hostProbes': host,
                   'pauseRulesKernelTimeBound': False, 'payloadSha256': details['payloadSha256'],
                   'planSha256': details['planSha256'], 'sourceCommit': details['sourceCommit'],
                   'startedUtc': started.strftime('%Y-%m-%dT%H:%M:%SZ'),
                   'finishedUtc': now_fn().strftime('%Y-%m-%dT%H:%M:%SZ')}
        FR.write_evidence(directory, 'summary.json', json.dumps(summary, indent=2, sort_keys=True) + '\n')
        for line in FR.console_lines(directory, stdout_text, PRINTED):
            print(line)
        if reasons:
            print('Host-side adult probes exceeded the predeclared tolerance: ' + ', '.join(reasons))
        print(MESSAGES[outcome].format(blocking=measured['packet_blocking_summary']['detail']))
        return code
    except BaseException as error:
        FR.write_unknown(directory, error)
        try:
            print(MESSAGES['UNKNOWN'], file=sys.stderr)
        except BaseException:
            pass
        return EXIT_FAIL


def run(argv, *, env=None, now_fn=None, probe=None):
    env = dict(os.environ) if env is None else env
    now_fn = now_fn or (lambda: datetime.datetime.now(datetime.timezone.utc))
    usage = 'usage: penn-pilot.py plan CONFIG | execute CONFIG --expect-plan-sha256 HEX'
    try:
        if len(argv) == 2 and argv[0] == 'plan':
            details, _ = plan(FR.load_config(argv[1]), env)
            print(json.dumps(details, indent=2, sort_keys=True))
            print('PLAN ONLY: nothing was sent. Disclose this output, then run:')
            print('python3 -I tools/live/penn-pilot.py execute ' + shlex.quote(argv[1])
                  + ' --expect-plan-sha256 ' + details['planSha256'])
            return EXIT_PASS
        if len(argv) == 4 and argv[0] == 'execute' and argv[2] == '--expect-plan-sha256':
            return execute(FR.load_config(argv[1]), argv[3], env, now_fn, probe or default_probe)
        print(usage, file=sys.stderr)
        return EXIT_REFUSED
    except Refusal as refusal:
        print(f'REFUSED (no router mutation): {refusal}', file=sys.stderr)
        return EXIT_REFUSED


if __name__ == '__main__':
    if not sys.flags.isolated:
        print('REFUSED (no router mutation): run with python3 -I', file=sys.stderr)
        sys.exit(EXIT_REFUSED)
    sys.exit(run(sys.argv[1:]))
