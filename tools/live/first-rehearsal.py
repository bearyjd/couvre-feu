#!/usr/bin/env python3
"""Single-session FIRST live rehearsal: plan locally, then execute exactly once.

`plan CONFIG` builds the exact payload and prints what the operator discloses.
`execute CONFIG --expect-plan-sha256 HEX` rebuilds the plan, refuses on any
digest mismatch, stale authorization or missing agent key, then runs one SSH
invocation with no retry. Standard library only; must run as `python3 -I`.

Exit codes: 0 PASS, 1 REFUSED before any router mutation, 2 FAIL/UNKNOWN after
mutation possibly began.
"""
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys

TOOL = Path(__file__).resolve()
REPO = TOOL.parents[2]
TEMPLATE_PATH = 'tools/live/first-rehearsal.sh'
SOURCE_DIRS = ('router', 'tools/live')
PROFILES = ('strict', 'gl-xe3000-4.8.3-logd-011-v1', 'gl-xe3000-4.8.3-os-trust-v1')
DEFAULT_PROFILE = 'gl-xe3000-4.8.3-os-trust-v1'
ROLES = ('management', 'jd_adult', 'penn_child')
PHASES = ('PAYLOAD', 'IDENTITY', 'PREREQ', 'SNAPSHOT', 'INSTALL', 'VERIFY', 'UNINSTALL', 'RESTORE', 'CONNECTIVITY')
CONFIG_KEYS = {'schemaVersion', 'host', 'adminPublicKeyPath', 'adminKeyFingerprint', 'knownHostsPath',
               'evidenceDir', 'authorizationPath', 'deadlineUtc', 'platformProfile',
               'remoteTimeoutSeconds', 'roles', 'protectedHistoricalMacs'}
REQUIRED_KEYS = CONFIG_KEYS - {'platformProfile', 'remoteTimeoutSeconds'}
MAC = re.compile(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}')
FINGERPRINT = re.compile(r'SHA256:[A-Za-z0-9+/]{43}')
DEADLINE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
SAFETY_MARGIN_SECONDS = 300
LOCAL_TIMEOUT_EXTRA_SECONDS = 60
EXIT_PASS, EXIT_REFUSED, EXIT_FAIL = 0, 1, 2
REMOTE_PASS, REMOTE_REFUSED, REMOTE_FAIL = 0, 10, 20
PASS_LINE = 'FIRST_REHEARSAL_PASS'


class Refusal(Exception):
    """Refused before any SSH connection; nothing on the router changed."""


def canonical_mac(value, field):
    if not isinstance(value, str) or not MAC.fullmatch(value):
        raise Refusal(f'{field}: MAC must be canonical lowercase aa:bb:cc:dd:ee:ff')
    if value == '00:00:00:00:00:00' or int(value[:2], 16) & 1:
        raise Refusal(f'{field}: MAC must be a non-zero unicast address')
    return value


def canonical_ipv4(value, field):
    try:
        address = ipaddress.IPv4Address(value) if isinstance(value, str) else None
    except ValueError:
        address = None
    if address is None or str(address) != value:
        raise Refusal(f'{field}: canonical dotted IPv4 address required')
    return value


def absolute_path(value, field):
    if not isinstance(value, str) or not value.startswith('/') or '\0' in value or os.path.normpath(value) != value:
        raise Refusal(f'{field}: normalized absolute path required')
    return value


def parse_deadline(value):
    if not isinstance(value, str) or not DEADLINE.fullmatch(value):
        raise Refusal('deadlineUtc: YYYY-MM-DDTHH:MM:SSZ required')
    try:
        parsed = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as error:
        raise Refusal(f'deadlineUtc: {error}') from None
    return parsed.replace(tzinfo=datetime.timezone.utc)


def load_config(path):
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(65537)
    except OSError as error:
        raise Refusal(f'config unreadable: {error.strerror}') from None
    if len(raw) > 65536:
        raise Refusal('config too large')
    try:
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, ValueError) as error:
        raise Refusal(f'config is not strict JSON: {error}') from None
    return validate_config(document)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate key {key!r}')
        result[key] = value
    return result


def validate_config(document):
    if not isinstance(document, dict):
        raise Refusal('config must be a JSON object')
    unknown = set(document) - CONFIG_KEYS
    missing = REQUIRED_KEYS - set(document)
    if unknown or missing:
        raise Refusal(f'config keys: unknown={sorted(unknown)} missing={sorted(missing)}')
    if document['schemaVersion'] != 1 or isinstance(document['schemaVersion'], bool):
        raise Refusal('schemaVersion must be 1')
    config = {'host': canonical_ipv4(document['host'], 'host')}
    for key in ('adminPublicKeyPath', 'knownHostsPath', 'evidenceDir', 'authorizationPath'):
        config[key] = absolute_path(document[key], key)
    fingerprint = document['adminKeyFingerprint']
    if not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint):
        raise Refusal('adminKeyFingerprint: SHA256:<43 base64 characters> required')
    config['adminKeyFingerprint'] = fingerprint
    config['deadlineUtc'] = document['deadlineUtc']
    config['deadline'] = parse_deadline(document['deadlineUtc'])
    profile = document.get('platformProfile', DEFAULT_PROFILE)
    if profile not in PROFILES:
        raise Refusal(f'platformProfile must be one of {", ".join(PROFILES)}')
    config['platformProfile'] = profile
    timeout = document.get('remoteTimeoutSeconds', 1800)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 600 <= timeout <= 3600:
        raise Refusal('remoteTimeoutSeconds must be an integer from 600 to 3600')
    config['remoteTimeoutSeconds'] = timeout
    roles = document['roles']
    if not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise Refusal(f'roles must contain exactly {", ".join(ROLES)}')
    config['roles'] = {}
    for role in ROLES:
        entry = roles[role]
        if not isinstance(entry, dict) or set(entry) != {'ip', 'mac'}:
            raise Refusal(f'roles.{role} must contain exactly ip and mac')
        config['roles'][role] = {'ip': canonical_ipv4(entry['ip'], f'roles.{role}.ip'),
                                 'mac': canonical_mac(entry['mac'], f'roles.{role}.mac')}
    historical = document['protectedHistoricalMacs']
    if not isinstance(historical, list) or not 1 <= len(historical) <= 32:
        raise Refusal('protectedHistoricalMacs must list 1 to 32 MACs')
    config['protectedHistoricalMacs'] = [canonical_mac(mac, 'protectedHistoricalMacs') for mac in historical]
    live_macs = [config['roles'][role]['mac'] for role in ROLES]
    live_ips = [config['roles'][role]['ip'] for role in ROLES] + [config['host']]
    if len(set(live_macs)) != len(live_macs) or len(set(live_ips)) != len(live_ips):
        raise Refusal('live roles and host must have distinct MACs and IPs')
    if len(set(config['protectedHistoricalMacs'])) != len(historical):
        raise Refusal('protectedHistoricalMacs contains duplicates')
    if set(live_macs) & set(config['protectedHistoricalMacs']):
        raise Refusal('a live role MAC equals a protected historical MAC')
    return config


def git(*args, text=True):
    # Ambient GIT_* settings and fsmonitor hooks cannot redirect the source.
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    result = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-C', str(REPO), *args], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, text=text, timeout=30)
    if result.returncode:
        stderr = result.stderr if text else result.stderr.decode(errors='replace')
        raise Refusal(f'git {args[0]} failed: {stderr.strip()[:200]}')
    return result.stdout


def blob_id(data):
    return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()


def head_source():
    """HEAD blobs for router/ and tools/live, refused unless disk and index match exactly."""
    commit = git('rev-parse', 'HEAD').strip()
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise Refusal('unexpected source commit format (SHA-1 repository required)')
    tree = {}
    for entry in filter(None, git('ls-tree', '-r', '-z', '--full-tree', 'HEAD', '--', *SOURCE_DIRS).split('\0')):
        meta, path = entry.split('\t', 1)
        mode, kind, sha = meta.split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise Refusal(f'{path}: only regular committed files may be embedded')
        tree[path] = (mode, sha)
    if not any(path.startswith('router/') for path in tree) or TEMPLATE_PATH not in tree:
        raise Refusal('HEAD lacks router/ or the remote script template')
    index = {}
    for entry in filter(None, git('ls-files', '-s', '-z', '--', *SOURCE_DIRS).split('\0')):
        meta, path = entry.split('\t', 1)
        mode, sha, stage_number = meta.split()
        index[path] = (mode, sha, stage_number)
    if index != {path: (mode, sha, '0') for path, (mode, sha) in tree.items()}:
        raise Refusal('index differs from HEAD for router/ or tools/live')
    for entry in filter(None, git('ls-files', '-v', '-z', '--', *SOURCE_DIRS).split('\0')):
        if entry[0] != 'H':
            raise Refusal(f'{entry[2:]}: skip-worktree, assume-unchanged or unusual index flag')
    disk = {}
    for top in SOURCE_DIRS:
        for directory, subdirs, files in os.walk(REPO / top):
            for name in subdirs + files:
                path = os.path.join(directory, name)
                if os.path.islink(path) or not (os.path.isdir(path) or os.path.isfile(path)):
                    raise Refusal(f'{os.path.relpath(path, REPO)}: symlink or special file')
            for name in files:
                path = os.path.join(directory, name)
                disk[os.path.relpath(path, REPO).replace(os.sep, '/')] = Path(path).read_bytes()
    if set(disk) != set(tree):
        extra, missing = sorted(set(disk) - set(tree)), sorted(set(tree) - set(disk))
        raise Refusal(f'disk differs from HEAD (untracked/ignored {extra[:5]}, missing {missing[:5]})')
    blobs = {}
    for path, (_, sha) in sorted(tree.items()):
        if blob_id(disk[path]) != sha:
            raise Refusal(f'{path}: working tree content differs from HEAD')
        data = git('cat-file', 'blob', sha, text=False)
        if blob_id(data) != sha:
            raise Refusal(f'{path}: blob integrity check failed')
        blobs[path] = data
    return commit, blobs


def release_id(blobs):
    text = blobs['router/lib/platform-bootstrap.sh'].decode('utf-8')
    found = re.findall(r'^CF_RELEASE_ID=([0-9a-f]{64})$', text, flags=re.M)
    if len(found) != 1:
        raise Refusal('release identity not found in platform-bootstrap.sh')
    return found[0]


def payload_mode(rel):
    if rel == 'release.sha256':
        return '600'
    if rel in ('install.sh', 'uninstall.sh', 'cfctl', 'cfctl-ssh'):
        return '755'
    return '644'


def payload_region(blobs):
    """Read-ahead-safe self-extraction: one quoted here-document per HEAD blob."""
    files = sorted(path for path in blobs if path.startswith('router/'))
    dirs = {'router'}
    for path in files:
        parts = path.split('/')[:-1]
        dirs.update('/'.join(parts[:i]) for i in range(1, len(parts) + 1))
    create_order = sorted(dirs, key=lambda d: (d.count('/'), d))
    cleanup_order = sorted(dirs, key=lambda d: (-d.count('/'), d))
    manifest, bodies = [], []
    for path in files:
        data = blobs[path]
        rel = path[len('router/'):]
        if b'\0' in data or not data.endswith(b'\n') or not re.fullmatch(r'[A-Za-z0-9._/-]+', rel):
            raise Refusal(f'{path} cannot be embedded safely')
        digest = hashlib.sha256(data).hexdigest()
        delimiter = 'CF_FIRST_PAYLOAD_EOF_' + digest[:24]
        if delimiter.encode() in data:
            raise Refusal(f'{path} contains its delimiter')
        manifest.append(f'{digest} {payload_mode(rel)} {path}')
        bodies.append(f'cat > "$CFR_STAGE/{path}" <<\'{delimiter}\' || return 1\n'
                      + data.decode('utf-8') + delimiter + '\n')
    text = '\n'.join(manifest) + '\n'
    lines = [f"CFR_PAYLOAD_DIRS='{' '.join(cleanup_order)}'", f'CFR_PAYLOAD_COUNT={len(files)}', 'cfr_payload_extract() {',
             "cat > \"$CFR_STAGE/manifest\" <<'CF_FIRST_MANIFEST_EOF' || return 1", text + 'CF_FIRST_MANIFEST_EOF']
    lines += [f'mkdir -m 700 "$CFR_STAGE/{d}" || return 1' for d in create_order]
    return '\n'.join(lines) + '\n' + ''.join(bodies) + '}\n'


def replace_region(text, name, body):
    begin, end = f'# @{name}_BEGIN@\n', f'# @{name}_END@\n'
    if text.count(begin) != 1 or text.count(end) != 1 or text.index(begin) > text.index(end):
        raise Refusal(f'template region {name} malformed')
    head, rest = text.split(begin)
    _, tail = rest.split(end)
    return head + begin + body + end + tail


def build_payload(config, commit, blobs):
    template = blobs[TEMPLATE_PATH]
    roles = config['roles']
    values = {'CFR_SOURCE_COMMIT': commit, 'CFR_RELEASE_ID': release_id(blobs),
              'CFR_PROFILE': config['platformProfile'],
              'CFR_MGMT_IP': roles['management']['ip'], 'CFR_MGMT_MAC': roles['management']['mac'],
              'CFR_JD_IP': roles['jd_adult']['ip'], 'CFR_JD_MAC': roles['jd_adult']['mac'],
              'CFR_PENN_IP': roles['penn_child']['ip'], 'CFR_PENN_MAC': roles['penn_child']['mac'],
              'CFR_HISTORICAL_MACS': ' '.join(config['protectedHistoricalMacs'])}
    for value in values.values():
        if not re.fullmatch(r'[0-9a-z.: -]+', value):
            raise Refusal('generated parameter has unexpected characters')
    params = ''.join(f"{key}='{value}'\n" for key, value in values.items())
    text = replace_region(template.decode('utf-8'), 'CF_GENERATED_PARAMETERS', params)
    text = replace_region(text, 'CF_GENERATED_PAYLOAD', payload_region(blobs))
    return text.encode('utf-8'), hashlib.sha256(template).hexdigest()


def remote_command(config):
    return ('exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C SSH_CONNECTION="$SSH_CONNECTION" '
            f"timeout -s KILL {config['remoteTimeoutSeconds']} /bin/sh -s")


def ssh_argv(config, env):
    ssh = shutil.which('ssh', path=env.get('PATH', ''))
    if ssh is None:
        raise Refusal('ssh not found on PATH')
    return [ssh, '-F', '/dev/null', '-i', config['adminPublicKeyPath'], '-o', 'IdentitiesOnly=yes',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + config['knownHostsPath'], '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=5',
            '-o', 'ConnectionAttempts=1', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
            '-T', 'root@' + config['host'], remote_command(config)]


def regular_file_sha256(path, field):
    try:
        info = os.lstat(path)
    except OSError:
        raise Refusal(f'{field} missing') from None
    if not stat.S_ISREG(info.st_mode):
        raise Refusal(f'{field} must be a regular file, not a symlink')
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def public_key_fingerprint(path):
    regular_file_sha256(path, 'adminPublicKeyPath')
    fields = Path(path).read_text().split()
    try:
        blob = base64.b64decode(fields[1], validate=True)
        length = int.from_bytes(blob[:4], 'big')
        key_type = blob[4:4 + length].decode('ascii')
    except (IndexError, ValueError, UnicodeDecodeError):
        raise Refusal('adminPublicKeyPath is not an OpenSSH public key') from None
    if key_type != fields[0]:
        raise Refusal('adminPublicKeyPath key type mismatch')
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


PLAN_DIGEST_FIELDS = ('payloadSha256', 'sshArgv', 'localTimeoutSeconds', 'remoteTimeoutSeconds', 'deadlineUtc',
                      'authorizationPath', 'evidenceDir', 'knownHostsSha256', 'adminPublicKeySha256')


def plan_digest(details):
    bound = {field: details[field] for field in PLAN_DIGEST_FIELDS}
    return hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def plan(config, env):
    commit, blobs = head_source()
    payload, script_sha = build_payload(config, commit, blobs)
    argv = ssh_argv(config, env)
    details = {'tool': 'tools/live/first-rehearsal.py', 'sourceCommit': commit, 'releaseId': release_id(blobs),
               'platformProfile': config['platformProfile'], 'payloadSha256': hashlib.sha256(payload).hexdigest(),
               'payloadBytes': len(payload), 'remoteScriptSha256': script_sha, 'sshArgv': argv,
               'sshCommandLine': shlex.join(argv), 'remoteTimeoutSeconds': config['remoteTimeoutSeconds'],
               'localTimeoutSeconds': config['remoteTimeoutSeconds'] + LOCAL_TIMEOUT_EXTRA_SECONDS,
               'deadlineUtc': config['deadlineUtc'], 'authorizationPath': config['authorizationPath'],
               'evidenceDir': config['evidenceDir'], 'roles': config['roles'],
               'protectedHistoricalMacs': config['protectedHistoricalMacs'],
               'knownHostsSha256': regular_file_sha256(config['knownHostsPath'], 'knownHostsPath'),
               'adminPublicKeySha256': regular_file_sha256(config['adminPublicKeyPath'], 'adminPublicKeyPath')}
    details['planSha256'] = plan_digest(details)
    return details, payload


def check_deadline(config, now):
    """The whole bounded session plus the safety margin must end before the deadline."""
    needed = config['remoteTimeoutSeconds'] + LOCAL_TIMEOUT_EXTRA_SECONDS + SAFETY_MARGIN_SECONDS
    if now + datetime.timedelta(seconds=needed) > config['deadline']:
        raise Refusal(f'authorization deadline {config["deadlineUtc"]} is earlier than now + local timeout + '
                      f'{SAFETY_MARGIN_SECONDS}s safety margin')


def check_agent(config, env):
    if public_key_fingerprint(config['adminPublicKeyPath']) != config['adminKeyFingerprint']:
        raise Refusal('adminPublicKeyPath does not match adminKeyFingerprint')
    ssh_add = shutil.which('ssh-add', path=env.get('PATH', ''))
    if ssh_add is None:
        raise Refusal('ssh-add not found on PATH')
    try:
        result = subprocess.run([ssh_add, '-l'], env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        raise Refusal('ssh-add -l timed out') from None
    held = {line.split()[1] for line in result.stdout.splitlines() if len(line.split()) >= 2}
    if result.returncode != 0 or config['adminKeyFingerprint'] not in held:
        raise Refusal('ssh-agent does not hold the configured admin key fingerprint')


VOLATILE_PREFIXES = ('/tmp', '/run', '/dev/shm', '/var/tmp')
VOLATILE_FILESYSTEMS = {'tmpfs', 'ramfs', 'devtmpfs'}


def volatile_location(path):
    real = os.path.realpath(path)
    if any(real == prefix or real.startswith(prefix + '/') for prefix in VOLATILE_PREFIXES):
        return True
    best, fstype = '', None
    try:
        with open('/proc/mounts', encoding='utf-8') as mounts:
            for line in mounts:
                fields = line.split()
                if len(fields) < 3:
                    continue
                point = fields[1].replace('\\040', ' ')
                if (real == point or real.startswith(point.rstrip('/') + '/')) and len(point) >= len(best):
                    best, fstype = point, fields[2]
    except OSError:
        raise Refusal('cannot read /proc/mounts to prove evidenceDir persistence') from None
    return fstype is None or fstype in VOLATILE_FILESYSTEMS


def evidence_directory(config, now):
    parent = config['evidenceDir']
    try:
        info = os.lstat(parent)
    except OSError:
        raise Refusal('evidenceDir missing') from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Refusal('evidenceDir must be an owned, non-symlink directory without group/other write')
    if volatile_location(parent):
        raise Refusal('evidenceDir must be on persistent storage, not /tmp, /run, /dev/shm or tmpfs')
    path = os.path.join(parent, now.strftime('%Y%m%dT%H%M%SZ') + '-first-rehearsal')
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        raise Refusal(f'evidence directory already exists: {path}') from None
    os.chmod(path, 0o700)
    return path


def open_evidence(directory, name):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    return os.open(os.path.join(directory, name), flags, 0o600)


def write_evidence(directory, name, text):
    descriptor = open_evidence(directory, name)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        handle.write(text)


def run_ssh(argv, payload, env, stdout_fd, stderr_fd, timeout):
    """Exactly one invocation. The child group is always killed and reaped."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stdout_fd, stderr=stderr_fd,
                               env=env, start_new_session=True)
    timed_out = False
    try:
        process.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    return process.returncode, timed_out


HEALTHY_STATUS = {'ok': True, 'drift': False, 'errors': [], 'desiredRevision': 0, 'confirmedRevision': 0,
                  'desiredPauses': [], 'effectivePauses': [], 'observed': {'kids': [], 'paused': []}}


def status_healthy(lines):
    statuses = [line[len('INFO status '):] for line in lines if line.startswith('INFO status ')]
    if len(statuses) != 1:
        return False
    try:
        status = json.loads(statuses[0])
    except ValueError:
        return False
    return isinstance(status, dict) and all(status.get(key) == value for key, value in HEALTHY_STATUS.items())


def classify(stdout_text, remote_exit, timed_out):
    lines = stdout_text.splitlines()
    phases = {}
    for line in lines:
        parts = line.split(' ', 3)
        if len(parts) >= 3 and parts[0] == 'PHASE' and parts[1] in PHASES:
            phases.setdefault(parts[1], []).append(parts[2] if len(parts) == 3 else parts[2] + ' ' + parts[3])
    passed = (not timed_out and remote_exit == REMOTE_PASS and lines.count(PASS_LINE) == 1
              and lines and lines[-1] == PASS_LINE and status_healthy(lines)
              and all(phases.get(name) == ['OK'] for name in PHASES) and len(phases) == len(PHASES))
    if passed:
        return 'PASS', EXIT_PASS, phases
    refused = (not timed_out and remote_exit == REMOTE_REFUSED and 'MUTATION_BEGIN' not in lines
               and PASS_LINE not in lines and any(line.startswith('REFUSED_BEFORE_MUTATION ') for line in lines))
    if refused:
        return 'REFUSED', EXIT_REFUSED, phases
    failed = any(result.startswith('FAIL') for results in phases.values() for result in results)
    if not timed_out and remote_exit in (REMOTE_FAIL, REMOTE_PASS) and (failed or remote_exit == REMOTE_PASS):
        return 'FAIL', EXIT_FAIL, phases
    return 'UNKNOWN', EXIT_FAIL, phases


MESSAGES = {'PASS': 'PASS: all phases passed; original state restored exactly.',
            'REFUSED': 'REFUSED: the remote script refused before any router mutation.',
            'FAIL': 'FAIL: mutation may have begun. Preserve evidence; do not retry blindly.',
            'UNKNOWN': 'UNKNOWN: session ended without a complete result. Treat the router as possibly mutated; '
                       'preserve evidence; do not retry blindly. See the runbook before any inspection.'}


def write_unknown(directory, error):
    try:
        write_evidence(directory, 'summary.json', json.dumps(
            {'outcome': 'UNKNOWN', 'exitCode': EXIT_FAIL, 'error': type(error).__name__}, sort_keys=True) + '\n')
    except BaseException:
        pass


def execute(config, expected_plan_sha, env, now_fn):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_plan_sha or ''):
        raise Refusal('--expect-plan-sha256 must be 64 lowercase hex characters')
    details, payload = plan(config, env)
    if not hmac.compare_digest(details['planSha256'], expected_plan_sha):
        raise Refusal(f'plan sha256 {details["planSha256"]} differs from the disclosed value')
    check_deadline(config, now_fn())
    details['authorizationSha256'] = regular_file_sha256(config['authorizationPath'], 'authorizationPath')
    check_agent(config, env)
    started = now_fn()
    directory = evidence_directory(config, started)
    write_evidence(directory, 'plan.json', json.dumps(details, indent=2, sort_keys=True) + '\n')
    stdout_fd = open_evidence(directory, 'stdout.log')
    stderr_fd = open_evidence(directory, 'stderr.log')
    try:
        check_deadline(config, now_fn())
    except Refusal:
        os.close(stdout_fd)
        os.close(stderr_fd)
        write_evidence(directory, 'summary.json', json.dumps({'outcome': 'REFUSED', 'reason': 'deadline'}) + '\n')
        raise
    print(f'Evidence: {directory}', flush=True)
    print('Connecting once; no retry. Do not interrupt.', flush=True)
    # From Popen onward every failure, including Ctrl-C, is UNKNOWN (exit 2).
    try:
        try:
            remote_exit, timed_out = run_ssh(details['sshArgv'], payload, env, stdout_fd, stderr_fd,
                                             details['localTimeoutSeconds'])
        finally:
            os.close(stdout_fd)
            os.close(stderr_fd)
        stdout_text = Path(directory, 'stdout.log').read_text(errors='replace')
        outcome, code, phases = classify(stdout_text, remote_exit, timed_out)
        write_evidence(directory, 'exit-code.txt', f'{remote_exit}\n')
        summary = {'outcome': outcome, 'exitCode': code, 'remoteExit': remote_exit, 'timedOut': timed_out,
                   'phases': phases, 'payloadSha256': details['payloadSha256'], 'planSha256': details['planSha256'],
                   'sourceCommit': details['sourceCommit'], 'startedUtc': started.strftime('%Y-%m-%dT%H:%M:%SZ'),
                   'finishedUtc': now_fn().strftime('%Y-%m-%dT%H:%M:%SZ')}
        write_evidence(directory, 'summary.json', json.dumps(summary, indent=2, sort_keys=True) + '\n')
        for line in stdout_text.splitlines():
            if line.startswith(('PHASE ', 'DIFF ', 'REFUSED_', 'FAIL_', PASS_LINE)):
                print(line)
        print(MESSAGES[outcome])
        return code
    except BaseException as error:
        write_unknown(directory, error)
        try:
            print(MESSAGES['UNKNOWN'], file=sys.stderr)
        except BaseException:
            pass
        return EXIT_FAIL


def run(argv, *, env=None, now_fn=None):
    env = dict(os.environ) if env is None else env
    now_fn = now_fn or (lambda: datetime.datetime.now(datetime.timezone.utc))
    usage = 'usage: first-rehearsal.py plan CONFIG | execute CONFIG --expect-plan-sha256 HEX'
    try:
        if len(argv) == 2 and argv[0] == 'plan':
            details, _ = plan(load_config(argv[1]), env)
            print(json.dumps(details, indent=2, sort_keys=True))
            print('PLAN ONLY: nothing was sent. Disclose this output, then run:')
            print('python3 -I tools/live/first-rehearsal.py execute ' + shlex.quote(argv[1])
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
