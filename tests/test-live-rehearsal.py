#!/usr/bin/env python3
"""FIRST live rehearsal fixtures: a fake ssh runs the payload against a private root.

No network or host-router command runs: ssh/ssh-add are local doubles and
router tools are the deterministic backends from tests/fixtures. Passing these
fixtures proves neither target BusyBox behavior nor real restoration.
"""
import base64
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests/fixtures'))
from harness import RouterFixture  # noqa: E402

MGMT = {'ip': '192.0.2.10', 'mac': '02:00:00:00:00:10'}
JD = {'ip': '192.0.2.20', 'mac': '02:00:00:00:00:20'}
PENN = {'ip': '192.0.2.30', 'mac': '02:00:00:00:00:30'}
HISTORICAL = ['02:00:00:00:00:40']
HOST = '192.0.2.1'
STAMP = 1_700_000_000_123_456_789
FAKE_SSH = r'''
import json, os, shlex, signal, subprocess, sys
spec = json.load(open(os.environ['FAKE_SSH_SPEC']))
with open(spec['log'], 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\n')
payload = sys.stdin.buffer.read()
env = dict(spec['env'], SSH_CONNECTION=spec['ssh_connection'])
child = subprocess.Popen(shlex.split(spec.get('shell', 'sh')) + ['-s'], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, env=env, start_new_session=True)
child.stdin.write(payload)
child.stdin.close()
for line in child.stdout:
    sys.stdout.buffer.write(line)
    sys.stdout.flush()
    if spec.get('drop_after') and line.decode().rstrip('\n') == spec['drop_after']:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        sys.exit(255)
    if spec.get('hangup_after') and line.decode().rstrip('\n') == spec['hangup_after']:
        # A dropped session: hang up and close the channel; the router side lives on.
        os.killpg(child.pid, signal.SIGHUP)
        child.stdout.close()
        sys.exit(255)
sys.exit(child.wait())
'''


def load_tool(path):
    sys.dont_write_bytecode = True  # keep the committed source copy clean
    spec = importlib.util.spec_from_file_location('first_rehearsal', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_key():
    blob = b''.join(len(part).to_bytes(4, 'big') + part for part in (b'ssh-ed25519', os.urandom(32)))
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode() + ' fixture-admin\n', fingerprint


class SourceCopy:
    """A clean committed copy so the tool's source-commit binding is exercised."""
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='couvre-feu-live-src-')
        self.root = Path(self.tmp.name)
        shutil.copytree(REPO / 'router', self.root / 'router')
        shutil.copytree(REPO / 'tools/live', self.root / 'tools/live',
                        ignore=shutil.ignore_patterns('__pycache__'))
        quiet = {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL, 'check': True}
        git = ['git', '-C', str(self.root), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid']
        subprocess.run(git + ['init', '-q'], **quiet)
        subprocess.run(git + ['add', '-A'], **quiet)
        subprocess.run(git + ['commit', '-q', '-m', 'fixture source'], **quiet)
        self.tool_path = self.root / 'tools/live/first-rehearsal.py'
        self.tool = load_tool(self.tool_path)


SOURCE = None


def setUpModule():
    global SOURCE
    SOURCE = SourceCopy()


def tearDownModule():
    SOURCE.tmp.cleanup()


class LiveRehearsalTests(unittest.TestCase):
    def setUp(self):
        self.tool = SOURCE.tool
        self.fixture = RouterFixture()
        self.root = self.fixture.root
        self.addCleanup(self.fixture.close)
        self.work = Path(tempfile.mkdtemp(prefix='couvre-feu-live-work-'))
        self.addCleanup(shutil.rmtree, self.work, True)
        # Evidence must be persistent storage, never /tmp or tmpfs.
        persistent = Path.home() / '.cache'
        persistent.mkdir(parents=True, exist_ok=True)
        self.evidence_root = Path(tempfile.mkdtemp(prefix='couvre-feu-live-evidence-', dir=persistent))
        self.addCleanup(shutil.rmtree, self.evidence_root, True)
        self.model_fresh_router()
        self.fake_tools()
        self.now = datetime.datetime(2026, 10, 12, 18, 0, 0, tzinfo=datetime.timezone.utc)
        self.config = {
            'schemaVersion': 1, 'host': HOST,
            'adminPublicKeyPath': str(self.work / 'admin.pub'), 'adminKeyFingerprint': self.fingerprint,
            'knownHostsPath': str(self.work / 'known_hosts'), 'evidenceDir': str(self.evidence_root / 'evidence'),
            'authorizationPath': str(self.work / 'authorization.txt'),
            'deadlineUtc': '2026-10-12T19:00:00Z', 'platformProfile': 'strict', 'remoteTimeoutSeconds': 600,
            'roles': {'management': MGMT, 'jd_adult': JD, 'penn_child': PENN},
            'protectedHistoricalMacs': HISTORICAL}
        (self.evidence_root / 'evidence').mkdir(mode=0o700)
        (self.work / 'known_hosts').write_text(HOST + ' ssh-ed25519 AAAAfixture\n')
        (self.work / 'authorization.txt').write_text('fixture authorization only\n')

    def model_fresh_router(self):
        shutil.rmtree(self.root / 'etc/couvrefeu')
        originals = {'etc/config/firewall': b"config defaults 'defaults'\n\toption input 'REJECT'\n",
                     'etc/sysupgrade.conf': b'# vendor list\n/etc/vendor\n',
                     'etc/crontabs/root': b'5 * * * * vendor-check\n'}
        for rel, content in originals.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o644)
            os.utime(path, ns=(STAMP, STAMP))
        (self.root / 'tmp/dhcp.leases').write_text(''.join(
            f'1800000000 {role["mac"]} {role["ip"]} host{i} *\n' for i, role in enumerate((MGMT, JD, PENN))))
        self.fixture.update_backend(
            neighbors=[dict(MGMT, state='REACHABLE'), dict(JD, state='STALE'), dict(PENN, state='DELAY')],
            uci={'network.lan.ipaddr': HOST}, addresses4=[f'2: br-lan    inet {HOST}/24 scope global br-lan'])
        # Seed steady post-reload tables so a clean uninstall is comparable.
        subprocess.run([str(self.fixture.bin / 'firewall'), 'reload'], env=self.fixture.env, check=True)

    def fake_tools(self):
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        key, self.fingerprint = public_key()
        (self.work / 'admin.pub').write_text(key)
        ssh = self.bin / 'ssh'
        ssh.write_text(f'#!{sys.executable}\n' + FAKE_SSH)
        ssh.chmod(0o700)
        self.agent_line = f'256 {self.fingerprint} fixture-admin (ED25519)'
        self.write_agent(self.agent_line)
        self.ssh_log = self.work / 'ssh-argv.jsonl'
        self.spec_path = self.work / 'fake-ssh.json'
        self.spec = {'log': str(self.ssh_log),
                     'env': dict(self.fixture.env, CF_TEST_INSTALL_KERNEL='1', CF_TEST_RELEASE_DIR='1'),
                     'ssh_connection': f'{MGMT["ip"]} 50000 {HOST} 22',
                     'shell': os.environ.get('CF_TEST_SHELL', 'sh')}

    def write_agent(self, line):
        agent = self.bin / 'ssh-add'
        agent.write_text('#!/bin/sh\n[ "$1" = -l ] || exit 2\n' + (f"printf '%s\\n' '{line}'\n" if line else 'exit 1\n'))
        agent.chmod(0o700)

    def write_config(self, **changes):
        path = self.work / 'config.json'
        path.write_text(json.dumps(dict(self.config, **changes)))
        return str(path)

    def tool_env(self):
        self.spec_path.write_text(json.dumps(self.spec))
        return {'PATH': str(self.bin) + os.pathsep + os.environ['PATH'], 'FAKE_SSH_SPEC': str(self.spec_path),
                'HOME': str(self.work), 'LC_ALL': 'C'}

    def invoke(self, *argv, now=None):
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.tool.run(list(argv), env=self.tool_env(), now_fn=lambda: now or self.now)
        return code, out.getvalue(), err.getvalue()

    def plan_details(self, config_path):
        code, out, err = self.invoke('plan', config_path)
        self.assertEqual(code, 0, err)
        return json.loads(out[:out.rindex('}') + 1])

    def plan_sha(self, config_path):
        return self.plan_details(config_path)['planSha256']

    def execute(self, cleanup=True, **changes):
        config = self.write_config(**changes)
        result = self.invoke('execute', config, '--expect-plan-sha256', self.plan_sha(config))
        if cleanup:
            self.cleanup_staging()
        return result

    def evidence(self):
        runs = sorted((self.evidence_root / 'evidence').iterdir())
        self.assertEqual(len(runs), 1)
        return runs[0]

    def cleanup_staging(self):
        # A killed session cannot run its own trap; reclaim only our staging dir.
        for run in (self.evidence_root / 'evidence').iterdir():
            stdout = run / 'stdout.log'
            for line in stdout.read_text().splitlines() if stdout.exists() else []:
                if line.startswith('INFO staging /tmp/couvre-feu-first.'):
                    shutil.rmtree(line.split(' ', 2)[2], ignore_errors=True)

    def router_snapshot(self):
        result = {}
        for path in sorted(self.root.rglob('*')):
            rel = str(path.relative_to(self.root))
            if rel.startswith(('backend', '.arm')):
                continue
            st = path.lstat()
            data = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else 'dir'
            result[rel] = (data, st.st_mode, st.st_mtime_ns if path.is_file() else None)
        backend = self.fixture.backend()
        # The fake backend lazily adds empty tables on read; they are not rules.
        tables = {family: {name: chains for name, chains in table.items() if chains}
                  for family, table in backend['tables'].items()}
        return result, tables, backend['sets']

    def installer_ran(self):
        # The installer alone resolves the SSH client with `ip neigh show ADDRESS`.
        return any(call['command'] == 'ip' and MGMT['ip'] in call['argv'] for call in self.fixture.calls())

    def test_happy_path_passes_and_restores_exactly(self):
        before = self.router_snapshot()
        code, out, err = self.execute()
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.router_snapshot(), before)
        run = self.evidence()
        self.assertEqual(run.stat().st_mode & 0o777, 0o700)
        for name in ('plan.json', 'stdout.log', 'stderr.log', 'exit-code.txt', 'summary.json'):
            self.assertEqual((run / name).stat().st_mode & 0o777, 0o600, name)
        stdout = (run / 'stdout.log').read_text().splitlines()
        self.assertEqual(stdout[-1], 'FIRST_REHEARSAL_PASS')
        self.assertEqual(stdout.count('FIRST_REHEARSAL_PASS'), 1)
        for phase in self.tool.PHASES:
            self.assertIn(f'PHASE {phase} OK', stdout)
        self.assertIn('INFO mtime_precision nanoseconds', stdout)
        release = next(line.split(': ', 1)[1] for line in stdout if line.startswith('INFO run uninstall.sh once: '))
        self.assertRegex(release, r'/etc/\.couvrefeu-release-[0-9a-f]{64}/uninstall\.sh$')
        self.assertFalse(Path(release).parent.exists())
        self.assertTrue(any(line.startswith('INFO tools stat=') for line in stdout))
        summary = json.loads((run / 'summary.json').read_text())
        self.assertEqual((summary['outcome'], summary['exitCode'], summary['remoteExit']), ('PASS', 0, 0))
        staging = next(line.split(' ', 2)[2] for line in stdout if line.startswith('INFO staging '))
        self.assertFalse(Path(staging).exists())
        argv = [json.loads(line) for line in self.ssh_log.read_text().splitlines()]
        self.assertEqual(len(argv), 1)
        self.assertEqual(argv[0][:2], ['-F', '/dev/null'])
        self.assertEqual(argv[0][-2:], ['root@' + HOST, 'exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C '
                                        'SSH_CONNECTION="$SSH_CONNECTION" timeout -s KILL 600 /bin/sh -s'])
        self.assertIn('PASS:', out)

    def test_identity_mac_mismatch_refused_before_install(self):
        self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'),
                                               {'ip': JD['ip'], 'mac': '02:00:00:00:00:99', 'state': 'REACHABLE'},
                                               dict(PENN, state='REACHABLE')])
        before = self.router_snapshot()
        code, out, err = self.execute()
        self.assertEqual(code, 1, out + err)
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertIn('PHASE IDENTITY FAIL jd_adult_neighbor_mismatch', stdout)
        self.assertIn('REFUSED_BEFORE_MUTATION IDENTITY', stdout)
        self.assertNotIn('run install.sh', stdout)
        self.assertNotIn('MUTATION_BEGIN', stdout)
        self.assertFalse(self.installer_ran())
        self.assertEqual(self.router_snapshot(), before)

    def test_live_role_equal_to_historical_mac_refused(self):
        code, _, err = self.invoke('plan', self.write_config(protectedHistoricalMacs=[PENN['mac']]))
        self.assertEqual(code, 1)
        self.assertIn('protected historical MAC', err)
        self.assertFalse(self.ssh_log.exists())
        # The remote gate refuses independently of local config validation.
        config = self.tool.validate_config(json.loads(Path(self.write_config()).read_text()))
        config['protectedHistoricalMacs'] = [JD['mac']]
        commit, blobs = self.tool.head_source()
        payload, _ = self.tool.build_payload(config, commit, blobs)
        self.tool_env()
        result = subprocess.run([str(self.bin / 'ssh'), 'fixture'], input=payload, capture_output=True,
                                env={'FAKE_SSH_SPEC': str(self.spec_path), 'PATH': os.environ['PATH']})
        self.assertEqual(result.returncode, 10, result.stderr.decode())
        self.assertIn(b'PHASE IDENTITY FAIL live_role_matches_protected_historical_mac', result.stdout)
        self.assertFalse(self.installer_ran())

    def test_ssh_source_other_than_management_refused(self):
        self.spec['ssh_connection'] = f'{JD["ip"]} 50000 {HOST} 22'
        code, out, err = self.execute()
        self.assertEqual(code, 1, out + err)
        self.assertIn('PHASE IDENTITY FAIL ssh_source_not_management', (self.evidence() / 'stdout.log').read_text())
        self.assertFalse(self.installer_ran())

    def arm_restore_tamper(self, action):
        """After uninstall's reload, the next snapshot read tampers with one original."""
        firewall_save = self.fixture.bin / 'iptables-save'
        original = self.fixture.bin / 'iptables-save.real'
        firewall_save.rename(original)
        firewall_save.write_text('#!/bin/sh\n'
                                 'if [ -f "$CF_ROOT/.arm" ] && [ ! -e "$CF_ROOT/.couvrefeu-recovery" ]; then\n'
                                 f'    rm -f "$CF_ROOT/.arm"; {action}\nfi\n'
                                 f'exec {shlex.quote(str(original))} "$@"\n')
        firewall_save.chmod(0o700)
        reload = self.fixture.bin / 'firewall'
        real_reload = self.fixture.bin / 'firewall.real'
        reload.rename(real_reload)
        reload.write_text('#!/bin/sh\n[ ! -d "$CF_ROOT/.couvrefeu-recovery" ] || : > "$CF_ROOT/.arm"\n'
                          f'exec {shlex.quote(str(real_reload))} "$@"\n')
        reload.chmod(0o700)

    def assert_restore_failure(self, action):
        target = self.root / 'etc/config/firewall'
        self.arm_restore_tamper(action)
        code, out, err = self.execute()
        self.assertEqual(code, 2, out + err)
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertIn('PHASE UNINSTALL OK', stdout)
        self.assertIn('PHASE RESTORE FAIL snapshot_mismatch', stdout)
        self.assertIn(f'DIFF - F {target} ', stdout)
        self.assertIn(f'DIFF + F {target} ', stdout)
        self.assertNotIn('FIRST_REHEARSAL_PASS', stdout)
        self.assertEqual(json.loads((self.evidence() / 'summary.json').read_text())['outcome'], 'FAIL')
        self.assertIn('FAIL: mutation may have begun', out)

    def test_restoration_mtime_truncation_fails_with_diff(self):
        self.assert_restore_failure(f'touch -m -d @{STAMP // 10**9} "$CF_ROOT/etc/config/firewall"')

    def test_restoration_changed_byte_fails_with_diff(self):
        self.assert_restore_failure('printf x >> "$CF_ROOT/etc/config/firewall"')

    def test_install_failure_does_not_attempt_uninstall(self):
        self.spec['env']['CF_TEST_INSTALL_FAIL_AFTER'] = '3'
        code, out, err = self.execute()
        self.assertEqual(code, 2, out + err)
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertIn('MUTATION_BEGIN', stdout)
        self.assertIn('PHASE INSTALL FAIL', stdout)
        self.assertNotIn('run uninstall.sh', stdout)
        self.assertNotIn('PHASE UNINSTALL', stdout)
        self.assertTrue((self.root / 'etc/couvrefeu/backup/ready').is_file())

    def test_ssh_drop_mid_run_is_unknown(self):
        self.spec['drop_after'] = 'PHASE INSTALL OK'
        code, out, err = self.execute()
        self.assertEqual(code, 2, out + err)
        summary = json.loads((self.evidence() / 'summary.json').read_text())
        self.assertEqual((summary['outcome'], summary['remoteExit']), ('UNKNOWN', 255))
        self.assertIn('UNKNOWN:', out)

    def test_plan_sha_mismatch_refused_without_connection(self):
        code, _, err = self.invoke('execute', self.write_config(), '--expect-plan-sha256', 'a' * 64)
        self.assertEqual(code, 1)
        self.assertIn('differs from the disclosed value', err)
        self.assertFalse(self.ssh_log.exists())
        self.assertEqual(list((self.evidence_root / 'evidence').iterdir()), [])

    def test_plan_sha_binds_argv_timeouts_and_key_files(self):
        details = self.plan_details(self.write_config())
        for field in self.tool.PLAN_DIGEST_FIELDS:
            self.assertIn(field, details)
        self.assertIn('GlobalKnownHostsFile=/dev/null', details['sshArgv'])
        disclosed = details['planSha256']
        original_hosts = (self.work / 'known_hosts').read_text()
        changes = {'remote timeout': lambda: self.write_config(remoteTimeoutSeconds=900),
                   'known hosts': lambda: (self.work / 'known_hosts').write_text(HOST + ' ssh-ed25519 AAAAchanged\n'),
                   'deadline': lambda: self.write_config(deadlineUtc='2026-10-12T19:30:00Z')}
        for label, change in changes.items():
            with self.subTest(label):
                change()
                code, _, err = self.invoke('execute', str(self.work / 'config.json'), '--expect-plan-sha256', disclosed)
                self.assertEqual(code, 1)
                self.assertIn('differs from the disclosed value', err)
                (self.work / 'known_hosts').write_text(original_hosts)
                self.write_config()
        self.assertFalse(self.ssh_log.exists())

    def test_deadline_includes_local_timeout_and_margin(self):
        config = self.tool.validate_config(json.loads(Path(self.write_config()).read_text()))
        needed = datetime.timedelta(seconds=600 + 60 + 300)
        self.tool.check_deadline(dict(config, deadline=self.now + needed), self.now)
        with self.assertRaises(self.tool.Refusal):
            self.tool.check_deadline(dict(config, deadline=self.now + needed - datetime.timedelta(seconds=1)), self.now)
        cli = self.write_config(deadlineUtc='2026-10-12T18:14:00Z')
        code, _, err = self.invoke('execute', cli, '--expect-plan-sha256', self.plan_sha(cli))
        self.assertEqual(code, 1)
        self.assertIn('safety margin', err)
        self.assertFalse(self.ssh_log.exists())

    def test_interrupt_after_connection_is_unknown_exit_2(self):
        original = self.tool.run_ssh

        def interrupted(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt
        self.tool.run_ssh = interrupted
        try:
            code, out, err = self.execute()
        finally:
            self.tool.run_ssh = original
        self.assertEqual(code, 2, out + err)
        self.assertEqual(json.loads((self.evidence() / 'summary.json').read_text())['outcome'], 'UNKNOWN')
        self.assertIn('UNKNOWN:', err)

    def test_dropped_session_still_completes_and_retains_stage_log(self):
        before = self.router_snapshot()
        self.spec['hangup_after'] = 'MUTATION_BEGIN'
        code, out, err = self.execute(cleanup=False)
        self.assertEqual(code, 2, out + err)
        self.assertEqual(json.loads((self.evidence() / 'summary.json').read_text())['outcome'], 'UNKNOWN')
        stdout = (self.evidence() / 'stdout.log').read_text().splitlines()
        stage = Path(next(line.split(' ', 2)[2] for line in stdout if line.startswith('INFO staging ')))
        self.addCleanup(shutil.rmtree, stage, True)
        phase_log = stage / 'phase.log'
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline and 'STAGE_RETAINED' not in (phase_log.read_text() if phase_log.exists() else ''):
            time.sleep(0.5)
        log = phase_log.read_text().splitlines()
        self.assertIn('STAGE_RETAINED ' + str(stage), log)
        for phase in ('INSTALL', 'VERIFY', 'UNINSTALL', 'RESTORE', 'CONNECTIVITY'):
            self.assertIn(f'PHASE {phase} OK', log)
        self.assertIn('FIRST_REHEARSAL_PASS', log)
        self.assertTrue((stage / 'child.log').is_file())
        self.assertEqual(self.router_snapshot(), before)

    def test_evidence_dir_on_volatile_storage_refused(self):
        volatile = self.work / 'evidence'
        volatile.mkdir(mode=0o700)
        config = self.write_config(evidenceDir=str(volatile))
        code, _, err = self.invoke('execute', config, '--expect-plan-sha256', self.plan_sha(config))
        self.assertEqual(code, 1)
        self.assertIn('persistent storage', err)
        self.assertFalse(self.ssh_log.exists())

    def test_source_must_equal_head_blobs(self):
        git = ['git', '-C', str(SOURCE.root)]
        target = SOURCE.root / 'router/cron'
        original = target.read_bytes()
        exclude = SOURCE.root / '.git/info/exclude'
        cases = {
            'modified tracked file': (lambda: target.write_bytes(original + b'# drift\n'), lambda: target.write_bytes(original)),
            'skip-worktree drift': (lambda: (subprocess.run(git + ['update-index', '--skip-worktree', 'router/cron'], check=True),
                                             target.write_bytes(original + b'# hidden\n')),
                                    lambda: (target.write_bytes(original),
                                             subprocess.run(git + ['update-index', '--no-skip-worktree', 'router/cron'], check=True))),
            'ignored file': (lambda: (exclude.write_text('ignored.txt\n'), (SOURCE.root / 'router/ignored.txt').write_text('x\n')),
                             lambda: ((SOURCE.root / 'router/ignored.txt').unlink(), exclude.write_text(''))),
        }
        for label, (apply, revert) in cases.items():
            with self.subTest(label):
                apply()
                try:
                    status = subprocess.run(git + ['status', '--porcelain'], capture_output=True, text=True).stdout
                    if label != 'modified tracked file':
                        self.assertEqual(status, '', 'git itself reports clean; only the tool can catch this')
                    code, _, err = self.invoke('plan', self.write_config())
                finally:
                    revert()
                self.assertEqual(code, 1, label)
                self.assertIn('REFUSED', err)
        self.assertEqual(self.invoke('plan', self.write_config())[0], 0)

    def test_evidence_directory_collision_refused(self):
        (self.evidence_root / 'evidence/20261012T180000Z-first-rehearsal').mkdir(mode=0o700)
        config = self.write_config()
        code, _, err = self.invoke('execute', config, '--expect-plan-sha256', self.plan_sha(config))
        self.assertEqual(code, 1)
        self.assertIn('already exists', err)
        self.assertFalse(self.ssh_log.exists())

    def test_agent_without_admin_key_refused(self):
        self.write_agent('256 SHA256:' + 'A' * 43 + ' other (ED25519)')
        config = self.write_config()
        code, _, err = self.invoke('execute', config, '--expect-plan-sha256', self.plan_sha(config))
        self.assertEqual(code, 1)
        self.assertIn('ssh-agent does not hold', err)
        self.assertFalse(self.ssh_log.exists())

    def test_config_validation_is_strict(self):
        bad = [{'host': '192.0.2.01'}, {'evidenceDir': 'relative/path'}, {'adminKeyFingerprint': 'SHA256:short'},
               {'roles': {'management': {'ip': MGMT['ip'], 'mac': '02:00:00:00:00:1A'}, 'jd_adult': JD, 'penn_child': PENN}},
               {'roles': {'management': {'ip': MGMT['ip'], 'mac': '03:00:00:00:00:10'}, 'jd_adult': JD, 'penn_child': PENN}},
               {'platformProfile': 'unknown'}, {'deadlineUtc': '2026-10-12 19:00'}, {'extra': 1}]
        for change in bad:
            with self.subTest(change=change):
                code, _, err = self.invoke('plan', self.write_config(**change))
                self.assertEqual(code, 1, err)
                self.assertIn('REFUSED', err)

    def test_example_config_is_valid_and_fictional(self):
        example = json.loads((REPO / 'tools/live/config.example.json').read_text())
        config = self.tool.validate_config(example)
        macs = [role['mac'] for role in config['roles'].values()] + config['protectedHistoricalMacs']
        self.assertTrue(all(mac.startswith('02:00:00:00:00:') for mac in macs))
        self.assertTrue(config['host'].startswith('192.0.2.'))

    def test_dirty_source_refused(self):
        stray = SOURCE.root / 'router/stray'
        stray.write_text('x\n')
        try:
            code, _, err = self.invoke('plan', self.write_config())
        finally:
            stray.unlink()
        self.assertEqual(code, 1)
        self.assertIn('differs from HEAD', err)

    def test_cli_requires_isolated_mode_and_plan_is_local(self):
        config = self.write_config()
        env = self.tool_env()
        plain = subprocess.run([sys.executable, str(SOURCE.tool_path), 'plan', config],
                               env=env, capture_output=True, text=True)
        self.assertEqual(plain.returncode, 1)
        self.assertIn('python3 -I', plain.stderr)
        isolated = subprocess.run([sys.executable, '-I', str(SOURCE.tool_path), 'plan', config],
                                  env=env, capture_output=True, text=True)
        self.assertEqual(isolated.returncode, 0, isolated.stderr)
        details = json.loads(isolated.stdout[:isolated.stdout.rindex('}') + 1])
        self.assertEqual(details['planSha256'], self.plan_sha(config))
        self.assertEqual(details['sshArgv'][0], str(self.bin / 'ssh'))
        self.assertFalse(self.ssh_log.exists())

    def test_generated_payload_static_checks(self):
        config = self.tool.validate_config(json.loads(Path(self.write_config()).read_text()))
        commit, blobs = self.tool.head_source()
        payload, _ = self.tool.build_payload(config, commit, blobs)
        path = self.work / 'payload.sh'
        path.write_bytes(payload)
        checks = [['sh', '-n', str(path)]]
        if shutil.which('busybox'):
            checks.append(['busybox', 'ash', '-n', str(path)])
        if shutil.which('shellcheck'):
            checks.append(['shellcheck', '-s', 'sh', '-S', 'warning', str(path)])
        for check in checks:
            result = subprocess.run(check, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, check[0] + result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
