#!/usr/bin/env python3
"""Single-session PERMANENT install on the router: plan locally, then execute exactly once.

`plan CONFIG` builds the exact payload and prints what the operator discloses.
`execute CONFIG --expect-plan-sha256 HEX` rebuilds the plan, refuses on any
digest mismatch, stale authorization or missing agent key, then runs one SSH
invocation with no retry. Unlike the rehearsal there is no uninstall: the
install stays. A failure after mutation ends STOPPED_AFTER_MUTATION and prints
the retained release's uninstall.sh as the rollback command; it is never run by
this tool. Source binding, SSH argv, deadline, agent and evidence checks are
imported from first-rehearsal.py. Standard library only; must run as `python3 -I`.

Exit codes: 0 PASS (or VALIDATED with activate=false), 1 REFUSED before any router
mutation, 2 STOPPED_AFTER_MUTATION/UNKNOWN after mutation possibly began.
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
import sys


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
TOOL_PATH = 'tools/live/permanent-install.py'
TEMPLATE_PATH = 'tools/live/permanent-install.sh'
REHEARSAL_TAIL = ('# Parse everything above first; no child can read the remaining script.\n'
                  'cfr_main </dev/null\n'
                  '# Unreachable unless cfr_main returns; fail closed.\n'
                  '# shellcheck disable=SC2317\n'
                  'exit 20\n')
SCHEMA_VERSION = 3
ROLES = ('management', 'jd_adult', 'ct107')
PHASES = ('PAYLOAD', 'IDENTITY', 'PREREQ', 'SNAPSHOT', 'INSTALL', 'VERIFY', 'CONNECTIVITY')
VALIDATE_PHASES = PHASES[:4]
CONFIG_KEYS = FR.CONFIG_KEYS | {'protect', 'rpcAllow', 'activate'}
REQUIRED_KEYS = CONFIG_KEYS - {'platformProfile', 'remoteTimeoutSeconds'}
MAX_PROTECT, MAX_RPC_ALLOW = 64, 256
PASS_LINE = 'PERMANENT_INSTALL_PASS'
VALIDATED_LINE = 'PERMANENT_INSTALL_VALIDATED_NO_MUTATION'
STOPPED_PREFIX = 'STOPPED_AFTER_MUTATION '
SAFE_PATH = re.compile(r'[A-Za-z0-9._/-]+')
PARAM_VALUE = re.compile(r'[0-9a-z.: -]+')
PRINTED = ('PHASE ', 'DIFF ', 'REFUSED_', 'STOPPED_', 'ROLLBACK_', 'PERMANENT_', 'MUTATION_BEGIN')
MESSAGES = {
    'PASS': 'PASS: permanent install verified (status ok, revision 0, release retained). Nothing was uninstalled.',
    'VALIDATED': 'VALIDATED: activate=false; installer staged and validated only, nothing was installed.',
    'REFUSED': 'REFUSED: the remote script refused before any router mutation.',
    'STOPPED_AFTER_MUTATION': 'STOPPED_AFTER_MUTATION: the install is in place or half done. Preserve evidence; do not rerun '
                              'install. Rollback is the retained release uninstall.sh (ROLLBACK_COMMAND above, unless ROLLBACK_UNTRUSTED/ROLLBACK_UNAVAILABLE), run '
                              'separately after separate approval. Password login is untouched and is the recovery path.',
    'UNKNOWN': 'UNKNOWN: session ended without a complete result. Treat the router as possibly mutated; preserve '
               'evidence; do not retry blindly. A SIGKILL during the unbounded install.sh skips its traps and the installer '
               'may still be running: check /tmp/couvrefeu-install.lock and /tmp/couvrefeu-platform.lock before anything. '
               'See the runbook before any inspection.'}


def safe_path(value, field):
    """ssh -o UserKnownHostsFile= parses whitespace and %-tokens, so only plain path characters are allowed."""
    FR.absolute_path(value, field)
    if not SAFE_PATH.fullmatch(value):
        raise Refusal(f'{field}: only [A-Za-z0-9._/-] characters are allowed')
    return value


def unique_macs(value, field, low, high):
    if not isinstance(value, list) or not low <= len(value) <= high:
        raise Refusal(f'{field} must list {low} to {high} MACs')
    macs = [FR.canonical_mac(mac, field) for mac in value]
    if len(set(macs)) != len(macs):
        raise Refusal(f'{field} contains duplicates')
    return macs


def validate_roles(document, host):
    roles = document['roles']
    if not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise Refusal(f'roles must contain exactly {", ".join(ROLES)}')
    result = {}
    for role in ROLES:
        entry = roles[role]
        if not isinstance(entry, dict) or set(entry) != {'ip', 'mac'}:
            raise Refusal(f'roles.{role} must contain exactly ip and mac')
        result[role] = {'ip': FR.canonical_ipv4(entry['ip'], f'roles.{role}.ip'),
                        'mac': FR.canonical_mac(entry['mac'], f'roles.{role}.mac')}
    # Only these two adult roles may describe one confirmed device.
    distinct = [role for role in ROLES if not (role == 'jd_adult' and result['management'] == result['jd_adult'])]
    macs = [result[role]['mac'] for role in distinct]
    ips = [result[role]['ip'] for role in distinct] + [host]
    if len(set(macs)) != len(macs) or len(set(ips)) != len(ips):
        raise Refusal('live roles and host must have distinct MACs and IPs except an exact management/jd_adult pair')
    return result


def validate_common(document):
    config = {'host': FR.canonical_ipv4(document['host'], 'host')}
    for key in ('adminPublicKeyPath', 'knownHostsPath', 'evidenceDir', 'authorizationPath'):
        config[key] = safe_path(document[key], key)
    fingerprint = document['adminKeyFingerprint']
    if not isinstance(fingerprint, str) or not FR.FINGERPRINT.fullmatch(fingerprint):
        raise Refusal('adminKeyFingerprint: SHA256:<43 base64 characters> required')
    config['adminKeyFingerprint'] = fingerprint
    config['deadlineUtc'] = document['deadlineUtc']
    config['deadline'] = FR.parse_deadline(document['deadlineUtc'])
    profile = document.get('platformProfile', FR.DEFAULT_PROFILE)
    if profile not in FR.PROFILES:
        raise Refusal(f'platformProfile must be one of {", ".join(FR.PROFILES)}')
    config['platformProfile'] = profile
    timeout = document.get('remoteTimeoutSeconds', 1800)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 600 <= timeout <= 3600:
        raise Refusal('remoteTimeoutSeconds must be an integer from 600 to 3600')
    config['remoteTimeoutSeconds'] = timeout
    return config


def validate_config(document):
    if not isinstance(document, dict):
        raise Refusal('config must be a JSON object')
    unknown, missing = set(document) - CONFIG_KEYS, REQUIRED_KEYS - set(document)
    if unknown or missing:
        raise Refusal(f'config keys: unknown={sorted(unknown)} missing={sorted(missing)}')
    if document['schemaVersion'] != SCHEMA_VERSION or isinstance(document['schemaVersion'], bool):
        raise Refusal(f'schemaVersion must be {SCHEMA_VERSION}')
    config = validate_common(document)
    config['roles'] = validate_roles(document, config['host'])
    historical = unique_macs(document['protectedHistoricalMacs'], 'protectedHistoricalMacs', 1, 32)
    protect = unique_macs(document['protect'], 'protect', 1, MAX_PROTECT)
    rpc_allow = unique_macs(document['rpcAllow'], 'rpcAllow', 1, MAX_RPC_ALLOW)
    live = [role['mac'] for role in config['roles'].values()]
    if set(live) & set(historical):
        raise Refusal('a live role MAC equals a protected historical MAC')
    if not set(live + historical) <= set(protect):
        raise Refusal('protect must include the management, jd_adult and ct107 MACs and every protectedHistoricalMacs entry')
    if set(rpc_allow) & set(protect):
        raise Refusal('rpcAllow must not contain any protect MAC')
    if not isinstance(document['activate'], bool):
        raise Refusal('activate must be true or false')
    config.update({'protectedHistoricalMacs': historical, 'protect': protect, 'rpcAllow': rpc_allow,
                   'activate': document['activate']})
    return config


def load_config(path):
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(65537)
    except OSError as error:
        raise Refusal(f'config unreadable: {error.strerror}') from None
    if len(raw) > 65536:
        raise Refusal('config too large')
    try:
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=FR._unique_keys)
    except (UnicodeDecodeError, ValueError) as error:
        raise Refusal(f'config is not strict JSON: {error}') from None
    return validate_config(document)


def installer_flags(config):
    """The installer flags without --activate (the INSTALL phase adds it)."""
    flags = ['--platform-profile', config['platformProfile']]
    for mac in config['protect']:
        flags += ['--protect', mac]
    for mac in config['rpcAllow']:
        flags += ['--rpc-allow', mac]
    return flags


def install_argv(config):
    """The exact planned argument vector of the one activating install.sh invocation."""
    return ['router/install.sh'] + installer_flags(config) + (['--activate'] if config['activate'] else [])


def planned_phases(config):
    return list(PHASES if config['activate'] else VALIDATE_PHASES)


def checked_params(values):
    for value in values.values():
        if not PARAM_VALUE.fullmatch(value):
            raise Refusal('generated parameter has unexpected characters')
    return ''.join(f"{key}='{value}'\n" for key, value in values.items())


def rehearsal_base(config, commit, blobs):
    roles = config['roles']
    values = {'CFR_SOURCE_COMMIT': commit, 'CFR_RELEASE_ID': FR.release_id(blobs), 'CFR_PROFILE': config['platformProfile'],
              'CFR_SETSID_HELPER_SHA256': FR.setsid_helper_pin(blobs['router/lib/platform-bootstrap.sh']),
              'CFR_MGMT_IP': roles['management']['ip'], 'CFR_MGMT_MAC': roles['management']['mac'],
              'CFR_JD_IP': roles['jd_adult']['ip'], 'CFR_JD_MAC': roles['jd_adult']['mac'],
              'CFR_HISTORICAL_MACS': ' '.join(config['protectedHistoricalMacs'])}
    # The permanent install has no child device: its rehearsal parameters stay empty and unused.
    params = checked_params(values) + "CFR_PENN_IP=\nCFR_PENN_MAC=\n"
    template = blobs[FR.TEMPLATE_PATH]
    text = FR.replace_region(template.decode('utf-8'), 'CF_GENERATED_PARAMETERS', params)
    text = FR.replace_region(text, 'CF_GENERATED_PAYLOAD', FR.payload_region(blobs))
    return text, hashlib.sha256(template).hexdigest()


def build_payload(config, commit, blobs):
    if TEMPLATE_PATH not in blobs:
        raise Refusal('HEAD lacks the permanent install script template')
    text, rehearsal_sha = rehearsal_base(config, commit, blobs)
    if text.count(REHEARSAL_TAIL) != 1 or not text.endswith(REHEARSAL_TAIL):
        raise Refusal('rehearsal script tail differs from the expected invocation')
    values = {'CFPI_INSTALL_ARGS': ' '.join(installer_flags(config)), 'CFPI_ACTIVATE': '1' if config['activate'] else '0',
              'CFPI_PROTECT': ' '.join(config['protect']), 'CFPI_RPC_ALLOW': ' '.join(config['rpcAllow']),
              'CFPI_CT107_MAC': config['roles']['ct107']['mac']}
    template = blobs[TEMPLATE_PATH]
    permanent = FR.replace_region(template.decode('utf-8'), 'CF_PERMANENT_PARAMETERS', checked_params(values))
    payload = (text[:-len(REHEARSAL_TAIL)] + permanent).encode('utf-8')
    return payload, rehearsal_sha, hashlib.sha256(template).hexdigest()


PLAN_DIGEST_FIELDS = FR.PLAN_DIGEST_FIELDS + (
    'tool', 'configSchemaVersion', 'sourceCommit', 'releaseId', 'platformProfile', 'roles', 'protectedHistoricalMacs',
    'protect', 'rpcAllow', 'rpcAllowFixedAtInstall', 'activate', 'installArgv', 'phases', 'permanentScriptSha256')


def plan_digest(details):
    bound = {field: details[field] for field in PLAN_DIGEST_FIELDS}
    return hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def plan(config, env):
    commit, blobs = FR.head_source()
    payload, rehearsal_sha, permanent_sha = build_payload(config, commit, blobs)
    argv = FR.ssh_argv(config, env)
    details = {'tool': TOOL_PATH, 'configSchemaVersion': SCHEMA_VERSION, 'sourceCommit': commit,
               'releaseId': FR.release_id(blobs), 'emittedTreeSha256': FR.emitted_tree_sha256(FR.emitted_tree(blobs)),
               'platformProfile': config['platformProfile'], 'payloadSha256': hashlib.sha256(payload).hexdigest(),
               'payloadBytes': len(payload), 'remoteScriptSha256': rehearsal_sha, 'permanentScriptSha256': permanent_sha,
               'sshArgv': argv, 'sshCommandLine': shlex.join(argv), 'remoteTimeoutSeconds': config['remoteTimeoutSeconds'],
               'localTimeoutSeconds': config['remoteTimeoutSeconds'] + FR.LOCAL_TIMEOUT_EXTRA_SECONDS,
               'deadlineUtc': config['deadlineUtc'], 'authorizationPath': config['authorizationPath'],
               'evidenceDir': config['evidenceDir'], 'roles': config['roles'],
               'protectedHistoricalMacs': config['protectedHistoricalMacs'], 'protect': config['protect'],
               'rpcAllow': config['rpcAllow'], 'rpcAllowFixedAtInstall': True, 'activate': config['activate'], 'installArgv': install_argv(config),
               'phases': planned_phases(config), 'uninstallInHappyPath': False,
               'knownHostsSha256': FR.regular_file_sha256(config['knownHostsPath'], 'knownHostsPath'),
               'adminPublicKeySha256': FR.regular_file_sha256(config['adminPublicKeyPath'], 'adminPublicKeyPath')}
    details['planSha256'] = plan_digest(details)
    return details, payload


def phase_results(lines, phases):
    results = {}
    for line in lines:
        parts = line.split(' ', 3)
        if len(parts) >= 3 and parts[0] == 'PHASE' and parts[1] in phases:
            results.setdefault(parts[1], []).append(parts[2] if len(parts) == 3 else parts[2] + ' ' + parts[3])
    return results


def completed(lines, remote_exit, timed_out, phases, results, activate):
    """Every planned phase OK once, the single final line, and for an install a healthy status and one generation."""
    end_line = PASS_LINE if activate else VALIDATED_LINE
    ok = (tuple(phases) == (PHASES if activate else VALIDATE_PHASES) and not timed_out and remote_exit == FR.REMOTE_PASS and lines.count(end_line) == 1 and lines[-1:] == [end_line]
          and all(results.get(name) == ['OK'] for name in phases) and len(results) == len(phases))
    if not ok:
        return False
    if end_line == VALIDATED_LINE:
        return 'MUTATION_BEGIN' not in lines
    generations = [line.split(' ', 1)[1] for line in lines if line.startswith('PERMANENT_GENERATION ')]
    return (lines.count('MUTATION_BEGIN') == 1 and len(generations) == 1
            and re.fullmatch(r'[0-9a-f]{64}', generations[0]) is not None and FR.status_healthy(lines))


def classify(stdout_text, remote_exit, timed_out, phases=PHASES, activate=True):
    lines = stdout_text.splitlines()
    results = phase_results(lines, phases)
    if completed(lines, remote_exit, timed_out, phases, results, activate):
        return ('PASS' if activate else 'VALIDATED'), EXIT_PASS, results
    refused = (not timed_out and remote_exit == FR.REMOTE_REFUSED and 'MUTATION_BEGIN' not in lines
               and any(line.startswith('REFUSED_BEFORE_MUTATION ') for line in lines))
    if refused:
        return 'REFUSED', EXIT_REFUSED, results
    stopped = (not timed_out and remote_exit == FR.REMOTE_FAIL and 'MUTATION_BEGIN' in lines
               and any(line.startswith(STOPPED_PREFIX) for line in lines))
    if stopped:
        return 'STOPPED_AFTER_MUTATION', EXIT_FAIL, results
    return 'UNKNOWN', EXIT_FAIL, results


def rollback_lines(stdout_text):
    return [line for line in stdout_text.splitlines() if line.startswith('ROLLBACK_')]


def unknown_rollback(details):
    return (f'ROLLBACK_COMMAND /bin/sh /etc/.couvrefeu-release-{details["releaseId"]}/uninstall.sh '
            '(separate approval; verify the file first)')


def already_executed(config, plan_sha):
    """One approved planSha256 is single-use: any earlier run directory that recorded it blocks a rerun."""
    try:
        names = sorted(os.listdir(config['evidenceDir']))
    except OSError:
        return False
    for name in names:
        if not name.endswith('-permanent-install'):
            continue
        try:
            recorded = json.loads(Path(config['evidenceDir'], name, 'plan.json').read_text())
        except (OSError, ValueError):
            continue
        if isinstance(recorded, dict) and recorded.get('planSha256') == plan_sha:
            return True
    return False


def write_unknown(directory, details, error):
    try:
        FR.write_evidence(directory, 'summary.json', json.dumps(
            {'outcome': 'UNKNOWN', 'exitCode': EXIT_FAIL, 'error': type(error).__name__,
             'rollback': [unknown_rollback(details)]}, sort_keys=True) + '\n')
    except BaseException:
        pass


def generation_of(stdout_text):
    found = [line.split(' ', 1)[1] for line in stdout_text.splitlines() if line.startswith('PERMANENT_GENERATION ')]
    return found[0] if len(found) == 1 else None


def execute(config, expected_plan_sha, env, now_fn):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_plan_sha or ''):
        raise Refusal('--expect-plan-sha256 must be 64 lowercase hex characters')
    details, payload = plan(config, env)
    if not hmac.compare_digest(details['planSha256'], expected_plan_sha):
        raise Refusal(f'plan sha256 {details["planSha256"]} differs from the disclosed value')
    if already_executed(config, details['planSha256']):
        raise Refusal('this plan sha256 was already executed (evidence exists); a new plan and approval are required')
    FR.check_deadline(config, now_fn())
    details['authorizationSha256'] = FR.regular_file_sha256(config['authorizationPath'], 'authorizationPath')
    FR.check_agent(config, env)
    started = now_fn()
    directory = FR.evidence_directory(config, started, suffix='permanent-install')
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
    # From Popen onward every failure, including Ctrl-C, is UNKNOWN (exit 2).
    try:
        try:
            remote_exit, timed_out = FR.run_ssh(details['sshArgv'], payload, env, stdout_fd, stderr_fd,
                                                details['localTimeoutSeconds'])
        finally:
            os.close(stdout_fd)
            os.close(stderr_fd)
        return conclude(directory, details, started, remote_exit, timed_out, now_fn)
    except BaseException as error:
        write_unknown(directory, details, error)
        try:
            print(unknown_rollback(details), file=sys.stderr)
            print(MESSAGES['UNKNOWN'], file=sys.stderr)
        except BaseException:
            pass
        return EXIT_FAIL


def conclude(directory, details, started, remote_exit, timed_out, now_fn):
    stdout_text = Path(directory, 'stdout.log').read_text(errors='replace')
    outcome, code, phases = classify(stdout_text, remote_exit, timed_out, tuple(details['phases']), details['activate'])
    FR.write_evidence(directory, 'exit-code.txt', f'{remote_exit}\n')
    summary = {'outcome': outcome, 'exitCode': code, 'remoteExit': remote_exit, 'timedOut': timed_out, 'phases': phases,
               'generation': generation_of(stdout_text) if outcome == 'PASS' else None,
               'rollback': rollback_lines(stdout_text) or ([unknown_rollback(details)] if outcome == 'UNKNOWN' else []),
               'payloadSha256': details['payloadSha256'],
               'planSha256': details['planSha256'], 'sourceCommit': details['sourceCommit'],
               'startedUtc': started.strftime('%Y-%m-%dT%H:%M:%SZ'),
               'finishedUtc': now_fn().strftime('%Y-%m-%dT%H:%M:%SZ')}
    FR.write_evidence(directory, 'summary.json', json.dumps(summary, indent=2, sort_keys=True) + '\n')
    for line in FR.console_lines(directory, stdout_text, PRINTED):
        print(line)
    if outcome == 'UNKNOWN':
        print(unknown_rollback(details))
    print(MESSAGES[outcome])
    return code


def scope_warnings(details):
    lines = []
    for key in ('rpcAllow', 'protect'):
        macs = sorted(details[key])
        lines.append(f'WARNING {key} is FIXED AT INSTALL and cannot be changed by reinstalling: {len(macs)} MACs:')
        lines += macs
    return lines


def run(argv, *, env=None, now_fn=None):
    env = dict(os.environ) if env is None else env
    now_fn = now_fn or (lambda: datetime.datetime.now(datetime.timezone.utc))
    usage = 'usage: permanent-install.py plan CONFIG | execute CONFIG --expect-plan-sha256 HEX'
    try:
        if len(argv) == 2 and argv[0] == 'plan':
            details, _ = plan(load_config(argv[1]), env)
            print(json.dumps(details, indent=2, sort_keys=True))
            print('\n'.join(scope_warnings(details)))
            print('PLAN ONLY: nothing was sent. Disclose this output, then run:')
            print('python3 -I tools/live/permanent-install.py execute ' + shlex.quote(argv[1])
                  + ' --expect-plan-sha256 ' + details['planSha256'])
            return EXIT_PASS
        if len(argv) == 4 and argv[0] == 'execute' and argv[2] == '--expect-plan-sha256':
            return execute(load_config(argv[1]), argv[3], env, now_fn)
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
