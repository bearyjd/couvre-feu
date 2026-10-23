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
import re
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
        shutil.copyfile(REPO / 'tools/strip-test-mode.py', self.root / 'tools/strip-test-mode.py')
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
        self.cp_log = self.work / 'cp-p.log'
        self.truncating_cp('s')
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

    def truncating_cp(self, precision):
        """Router `cp -p` like BusyBox: fractional mtimes lost to seconds or microseconds."""
        stat = shlex.quote(shutil.which('stat'))
        stamp = '"@$seconds"' if precision == 's' else '"@$seconds.${fraction%???}"'
        wrapper = self.fixture.bin / 'cp'
        wrapper.write_text('#!/bin/sh\n' + shlex.quote(shutil.which('cp')) + ' "$@" || exit\n'
                           'case " $* " in *" -p "*) ;; *) exit 0;; esac\n'
                           'for destination do :; done\n[ -f "$destination" ] || exit 0\n'
                           f'seconds=$({stat} -c %Y "$destination")\n'
                           f'fraction=$({stat} -c %y "$destination" | sed "s/.*\\.\\([0-9]*\\) .*/\\1/")\n'
                           f'{shlex.quote(shutil.which("touch"))} -m -d {stamp} "$destination"\n'
                           f'printf "%s\\n" "$destination" >> {shlex.quote(str(self.cp_log))}\n')
        wrapper.chmod(0o700)

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
        # Exact restoration is by rename; touch is no longer a prerequisite.
        self.assertFalse(any(line.startswith('INFO tools touch=') for line in stdout))
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
        # The baseline is local evidence: digests of every original and table.
        self.assertIn(f'SNAPSHOT F {self.root}/etc/config/firewall ', '\n'.join(stdout))
        for kind in ('iptables', 'ip6tables', 'ipset', 'ipsetsave', 'uci', 'cron'):
            self.assertTrue(any(line.startswith(f'SNAPSHOT H {kind} ') for line in stdout), kind)
        # Fractional originals were restored exactly although cp -p truncated.
        self.assertTrue(self.cp_log.read_text().strip())

    def test_microsecond_truncating_cp_still_restores_exactly(self):
        self.truncating_cp('us')
        before = self.router_snapshot()
        code, out, err = self.execute()
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.router_snapshot(), before)
        self.assertTrue(self.cp_log.read_text().strip())

    def test_truncating_touch_is_never_invoked(self):
        # BusyBox 1.33.2 `touch -r` truncates (live PREREQ refusal 2026-10-15).
        # Neither the rehearsal nor the installer calls touch at all now.
        touch_log = self.work / 'touch.log'
        wrapper = self.fixture.bin / 'touch'
        wrapper.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> {shlex.quote(str(touch_log))}\nexit 1\n')
        wrapper.chmod(0o700)
        before = self.router_snapshot()
        code, out, err = self.execute()
        self.assertEqual(code, 0, out + err)
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertIn('PHASE PREREQ OK', stdout)
        self.assertIn('FIRST_REHEARSAL_PASS', stdout)
        self.assertNotIn('touch_mtime_not_nanosecond', stdout)
        self.assertEqual(self.router_snapshot(), before)
        self.assertFalse(touch_log.exists())

    def shell_status_check(self, line):
        script = (REPO / 'tools/live/first-rehearsal.sh').read_text()
        program = re.search(r"awk '(/\^\\\{\"ok\":true.*?\$/\{n\+\+\}END\{exit !\(NR==1&&n==1\)\})'", script).group(1)
        awk = shutil.which('busybox') and [shutil.which('busybox'), 'awk'] or ['awk']
        return subprocess.run(awk + [program], input=line + '\n', text=True, capture_output=True).returncode == 0

    def test_empty_install_status_line_gates_agree_and_shell_is_order_strict(self):
        healthy = ('{"ok":true,"desiredRevision":0,"confirmedRevision":0,"desiredPauses":[],"effectivePauses":[],'
                   '"desiredAllowances":[],"effectiveAllowances":[],"observed":{"kids":[],"paused":[]},"drift":false,"capabilities":{"ipv6":false,"conntrack":false,'
                   '"nativeKernelConfirmed":false,"addressCoverageComplete":false,"routerCompatibilityVerified":false},"errors":[]}')
        # Same printf shape as router/lib/core.sh cf_status.
        self.assertIn('{"ok":%s,"desiredRevision":%s,"confirmedRevision":%s,"desiredPauses":%s,"effectivePauses":%s,'
                      '"desiredAllowances":%s,"effectiveAllowances":%s,"observed":{"kids":%s,"paused":%s},"drift":%s,"capabilities":{"ipv6":%s,"conntrack":%s,',
                      (REPO / 'router/lib/core.sh').read_text())
        verdicts = lambda line: (self.shell_status_check(line), self.tool.status_healthy(['INFO status ' + line]))  # noqa: E731
        self.assertEqual(verdicts(healthy), (True, True))
        fields = json.loads(healthy)
        extra = json.dumps(dict(fields, extra=1), separators=(',', ':'))
        self.assertEqual(verdicts(extra), (False, False))
        reordered = json.dumps({key: fields[key] for key in reversed(list(fields))}, separators=(',', ':'))
        self.assertEqual(verdicts(reordered), (False, True))
        missing = json.dumps({k: v for k, v in fields.items() if k != 'capabilities'}, separators=(',', ':'))
        self.assertEqual(verdicts(missing), (False, False))

    def test_exact_adult_alias_parser_preserves_other_identity_guards(self):
        roles = dict(self.config['roles'], jd_adult=MGMT)
        config = dict(self.config, roles=roles)
        self.assertEqual(self.tool.validate_config(config)['roles']['jd_adult'], MGMT)
        for replacement in (dict(MGMT, mac=JD['mac']), dict(MGMT, ip=JD['ip'])):
            with self.subTest(partial=replacement), self.assertRaises(self.tool.Refusal):
                self.tool.validate_config(dict(config, roles=dict(roles, jd_adult=replacement)))
        for child in (MGMT, dict(PENN, ip=MGMT['ip']), dict(PENN, mac=MGMT['mac'])):
            with self.subTest(child=child), self.assertRaises(self.tool.Refusal):
                self.tool.validate_config(dict(config, roles=dict(roles, penn_child=child)))
        for changes in ({'host': MGMT['ip']}, {'host': PENN['ip']},
                        {'protectedHistoricalMacs': HISTORICAL * 2},
                        {'protectedHistoricalMacs': [MGMT['mac']]}):
            with self.subTest(changes=changes), self.assertRaises(self.tool.Refusal):
                self.tool.validate_config(dict(config, **changes))

    def test_remote_partial_and_child_alias_payloads_refused(self):
        config = self.tool.validate_config(self.config)
        commit, blobs = self.tool.head_source()
        self.tool_env()
        cases = [(dict(config['roles'], jd_adult=dict(MGMT, mac=JD['mac'])), 'duplicate_live_ip'),
                 (dict(config['roles'], jd_adult=dict(MGMT, ip=JD['ip'])), 'duplicate_live_mac'),
                 (dict(config['roles'], jd_adult=MGMT, penn_child=MGMT), 'duplicate_live_mac'),
                 (dict(config['roles'], jd_adult=MGMT, penn_child=dict(PENN, ip=MGMT['ip'])),
                  'duplicate_live_ip')]
        for roles, reason in cases:
            # Bypass the parser: the router must make this decision independently.
            with self.subTest(roles=roles):
                payload, _ = self.tool.build_payload(dict(config, roles=roles), commit, blobs)
                result = subprocess.run([str(self.bin / 'ssh'), 'fixture'], input=payload, capture_output=True,
                                        env={'FAKE_SSH_SPEC': str(self.spec_path), 'PATH': os.environ['PATH']})
                self.assertEqual(result.returncode, 10, result.stderr.decode())
                self.assertIn(f'PHASE IDENTITY FAIL {reason}'.encode(), result.stdout)
                self.assertNotIn(b'MUTATION_BEGIN', result.stdout)
                self.assertFalse(self.installer_ran())

    def test_exact_adult_alias_rehearsal_passes_with_one_neighbor_and_lease(self):
        self.fixture.update_backend(neighbors=[dict(MGMT, state='REACHABLE'), dict(PENN, state='DELAY')])
        leases = self.root / 'tmp/dhcp.leases'
        leases.write_text(''.join(f'1800000000 {role["mac"]} {role["ip"]} host *\n' for role in (MGMT, PENN)))
        before = self.router_snapshot()
        code, out, err = self.execute(roles=dict(self.config['roles'], jd_adult=MGMT))
        self.assertEqual(code, 0, out + err)
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertIn('management=jd_adult same_confirmed_device', stdout)
        self.assertIn('FIRST_REHEARSAL_PASS', stdout)
        self.assertEqual(self.router_snapshot(), before)

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

    def test_restoration_mode_change_fails_with_diff(self):
        self.assert_restore_failure('chmod 600 "$CF_ROOT/etc/config/firewall"')

    def test_restored_original_with_new_inode_and_ctime_passes(self):
        # A rename-restored original may report another inode and always has a
        # new ctime on the overlay; RESTORE compares content and metadata only.
        copy = shlex.quote(shutil.which('cp'))
        mv = shlex.quote(shutil.which('mv'))
        target = '"$CF_ROOT/etc/config/firewall"'
        self.arm_restore_tamper(f'{copy} -p {target} "$CF_ROOT/.arm-copy" && {mv} -f "$CF_ROOT/.arm-copy" {target}')
        inode = (self.root / 'etc/config/firewall').stat().st_ino
        before = self.router_snapshot()
        code, out, err = self.execute()
        self.assertEqual(code, 0, out + err)
        self.assertIn('PHASE RESTORE OK', (self.evidence() / 'stdout.log').read_text())
        self.assertEqual(self.router_snapshot(), before)
        self.assertNotEqual((self.root / 'etc/config/firewall').stat().st_ino, inode)

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
        # A read-only re-snapshot reports exactly what the failed install left.
        self.assertIn(f'DIFF - D {self.root}/etc/couvrefeu/backup absent', stdout)
        self.assertIn(f'DIFF + D {self.root}/etc/couvrefeu/backup dir:700:', stdout)
        self.assertIn('SNAPSHOT F ', stdout)
        self.assertLess(stdout.index('DIFF - D'), stdout.index('FAIL_AFTER_MUTATION INSTALL'))

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

    def committed_copy(self, **edits):
        """A fresh committed source copy whose HEAD carries the given path -> bytes edits (None deletes)."""
        copy = SourceCopy()
        self.addCleanup(copy.tmp.cleanup)
        for rel, data in edits.items():
            if data is None:
                (copy.root / rel).unlink()
            else:
                (copy.root / rel).write_bytes(data)
        git = ['git', '-C', str(copy.root), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid']
        subprocess.run(git + ['add', '-A'], check=True, capture_output=True)
        subprocess.run(git + ['commit', '-q', '-m', 'edit'], check=True, capture_output=True)
        return copy

    def assert_head_source_refused(self, copy, needle):
        with self.assertRaises(copy.tool.Refusal) as caught:
            copy.tool.head_source()
        self.assertIn(needle, str(caught.exception))

    def test_stripper_is_bound_to_head_and_never_run_from_disk(self):
        copy = SourceCopy()
        self.addCleanup(copy.tmp.cleanup)
        stripper = copy.root / 'tools/strip-test-mode.py'
        original = stripper.read_bytes()
        marker = copy.root.parent / (copy.root.name + '-ran')
        git = ['git', '-C', str(copy.root)]
        cases = {
            'modified on disk': (lambda: stripper.write_bytes(original + b'\nopen(%r, "w").write("x")\n' % str(marker)),
                                 lambda: stripper.write_bytes(original), 'differs from HEAD'),
            'removed from index': (lambda: subprocess.run(git + ['rm', '--cached', '-q', 'tools/strip-test-mode.py'], check=True),
                                   lambda: subprocess.run(git + ['add', 'tools/strip-test-mode.py'], check=True), 'index differs'),
        }
        for label, (apply, revert, needle) in cases.items():
            with self.subTest(label):
                apply()
                try:
                    self.assert_head_source_refused(copy, needle)
                finally:
                    revert()
                self.assertFalse(marker.exists(), 'stripper executed from disk')
        self.assertEqual(copy.tool.head_source()[0], copy.tool.git('rev-parse', 'HEAD').strip())

    def test_stripper_missing_from_head_refused(self):
        self.assert_head_source_refused(self.committed_copy(**{'tools/strip-test-mode.py': None}), 'strip-test-mode.py')

    def test_committed_stripper_is_the_one_executed_and_its_blob_is_recorded(self):
        original = (REPO / 'tools/strip-test-mode.py').read_bytes()
        copy = self.committed_copy(**{'tools/strip-test-mode.py': original + b'\nBLOCK_LINES = {"cfctl-ssh": 1, "cfctl-scope": 1}\n'})
        self.assert_head_source_refused(copy, 'router/cfctl-ssh')
        self.assertEqual(self.plan_details(self.write_config())['stripperBlobSha1'], self.tool.blob_id(original))

    def test_tampered_wrapper_blob_refused(self):
        rel = 'router/cfctl-scope'
        copy = self.committed_copy(**{rel: (SOURCE.root / rel).read_bytes() + b'# tampered\n'})
        self.assert_head_source_refused(copy, 'do not match release.sha256')

    def test_wrapper_without_test_mode_marker_refused(self):
        rel = 'router/cfctl-ssh'
        text = (SOURCE.root / rel).read_text().replace('# The grammar fixture may invoke only a marked private-root executable.\n', '')
        self.assert_head_source_refused(self.committed_copy(**{rel: text.encode()}), 'marker')

    def test_unknown_or_malformed_manifest_entry_refused_not_keyerror(self):
        manifest = (SOURCE.root / 'router/release.sha256').read_bytes()
        for label, line in (('unknown', b'0' * 64 + b'  no-such-file\n'), ('malformed', b'justonefield\n')):
            with self.subTest(label):
                copy = self.committed_copy(**{'router/release.sha256': manifest + line})
                self.assert_head_source_refused(copy, 'release.sha256')

    def forged_copy(self, edits, repin=True):
        """A committed copy whose edited router files keep release.sha256 (and pins) self-consistent.

        Only the release id is left as the edit made it, so each case isolates one identity check."""
        copy = SourceCopy()
        self.addCleanup(copy.tmp.cleanup)
        router = copy.root / 'router'
        for rel, data in edits.items():
            (router / rel).write_bytes(data)
        if repin:
            pin = hashlib.sha256((router / 'lib/platform-bootstrap.sh').read_bytes()).hexdigest().encode()
            for rel in ('install.sh', 'uninstall.sh', 'cfctl'):
                (router / rel).write_bytes(re.sub(rb'(?m)^CF_BOOTSTRAP_PIN=.*$', b'CF_BOOTSTRAP_PIN=' + pin, (router / rel).read_bytes()))
        lines = []
        for line in (router / 'release.sha256').read_text().splitlines():
            digest, rel = line.split()
            if rel in ('cfctl-ssh', 'cfctl-scope'):
                lines.append(line)
            else:
                lines.append(hashlib.sha256((router / rel).read_bytes()).hexdigest() + '  ' + rel)
        (router / 'release.sha256').write_text('\n'.join(lines) + '\n')
        git = ['git', '-C', str(copy.root), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid']
        subprocess.run(git + ['add', '-A'], check=True, capture_output=True)
        subprocess.run(git + ['commit', '-q', '--allow-empty', '-m', 'forged'], check=True, capture_output=True)
        return copy

    def test_fixture_copy_forging_is_consistent_when_unedited(self):
        copy = self.forged_copy({})
        self.assertEqual(copy.tool.head_source()[0], copy.tool.git('rev-parse', 'HEAD').strip())

    def test_release_id_is_recomputed_from_shipped_bytes(self):
        boot = (SOURCE.root / 'router/lib/platform-bootstrap.sh').read_text()
        flipped = re.sub(r'(?m)^CF_RELEASE_ID=([0-9a-f]{64})$', lambda m: 'CF_RELEASE_ID=' + 'f' * 64, boot)
        self.assert_head_source_refused(self.forged_copy({'lib/platform-bootstrap.sh': flipped.encode()}), 'release id')
        # The id covers the boundary files: an edit to cfctl (pin kept self-consistent) changes it.
        cfctl = (SOURCE.root / 'router/cfctl').read_bytes() + b'# boundary edit\n'
        self.assert_head_source_refused(self.forged_copy({'cfctl': cfctl}), 'release id')
        core = (SOURCE.root / 'router/lib/core.sh').read_bytes() + b'# module edit\n'
        self.assert_head_source_refused(self.forged_copy({'lib/core.sh': core}), 'release id')

    def test_release_modules_line_must_match_shipped_modules(self):
        boot = (SOURCE.root / 'router/lib/platform-bootstrap.sh').read_text()
        edited = re.sub(r"(?m)^CF_RELEASE_MODULES='core.sh:[0-9a-f]{64}", "CF_RELEASE_MODULES='core.sh:" + '0' * 64, boot)
        self.assertNotEqual(edited, boot)
        self.assert_head_source_refused(self.forged_copy({'lib/platform-bootstrap.sh': edited.encode()}), 'CF_RELEASE_MODULES')

    def test_bootstrap_pins_must_equal_shipped_bootstrap_hash(self):
        for rel in ('install.sh', 'uninstall.sh', 'cfctl'):
            with self.subTest(rel):
                data = re.sub(rb'(?m)^CF_BOOTSTRAP_PIN=.*$', b'CF_BOOTSTRAP_PIN=' + b'1' * 64,
                              (SOURCE.root / 'router' / rel).read_bytes())
                self.assert_head_source_refused(self.forged_copy({rel: data}, repin=False), 'CF_BOOTSTRAP_PIN')

    def test_unlisted_tracked_router_file_refused_but_known_unused_files_are_not_shipped(self):
        self.assert_head_source_refused(self.forged_copy({'extra.sh': b'echo extra\n'}), 'not in release.sha256')
        config = self.tool.load_config(self.write_config())
        commit, blobs = self.tool.head_source()
        self.assertIn('router/cron', blobs)
        self.assertIn('router/firewall.include', blobs)
        payload, _ = self.tool.build_payload(config, commit, blobs)
        text = payload.decode()
        self.assertNotIn('router/cron', text)
        self.assertNotIn('router/firewall.include', text)
        manifest = [line.split() for line in (SOURCE.root / 'router/release.sha256').read_text().splitlines()]
        self.assertEqual(self.payload_manifest_paths(text), sorted(['router/' + rel for _, rel in manifest] + ['router/release.sha256']))
        self.assertIn(f'CFR_PAYLOAD_COUNT={len(manifest) + 1}\n', text)

    def test_manifest_entry_dropped_makes_a_shipped_file_unlisted(self):
        manifest = (SOURCE.root / 'router/release.sha256').read_text()
        kept = ''.join(line + '\n' for line in manifest.splitlines() if not line.endswith('lib/activity.sh'))
        self.assertNotEqual(kept, manifest)
        copy = self.committed_copy(**{'router/release.sha256': kept.encode()})
        self.assert_head_source_refused(copy, 'not in release.sha256')

    def test_manifest_must_list_exactly_the_routers_fixed_file_set(self):
        # Mirrors platform-bootstrap.sh platform_external_closure: 15 fixed entries, nothing else.
        boot = (REPO / 'router/lib/platform-bootstrap.sh').read_text()
        pattern = re.search(r'\$2!~/\^\((install\.sh.*?)\)\$/', boot).group(1)
        fixed = {'install.sh', 'uninstall.sh', 'cfctl', 'cfctl-ssh', 'cfctl-scope'}
        fixed |= {'lib/' + name for name in re.search(r'lib\\/\((.*?)\)', pattern).group(1).replace('\\.', '.').split('|')}
        self.assertEqual(set(self.tool.MANIFEST_FILES), fixed)
        self.assertEqual(len(self.tool.MANIFEST_FILES), 15)
        manifest = (SOURCE.root / 'router/release.sha256').read_text()
        extra = b'echo extra\n'
        line = hashlib.sha256(extra).hexdigest() + '  extra.sh\n'
        copy = self.committed_copy(**{'router/extra.sh': extra, 'router/release.sha256': (manifest + line).encode()})
        self.assert_head_source_refused(copy, 'fixed manifest file set')
        # A shipped entry set that lacks a fixed file refuses too (checked on the parsed blobs).
        commit, blobs = self.tool.head_source()
        short = dict(blobs, **{'router/release.sha256': ''.join(
            l + '\n' for l in blobs['router/release.sha256'].decode().splitlines() if not l.endswith('lib/activity.sh')).encode()})
        with self.assertRaises(self.tool.Refusal):
            self.tool.emitted_tree(short)

    def test_stripped_wrapper_must_pass_sh_n(self):
        rel = 'router/cfctl-ssh'
        broken = (SOURCE.root / rel).read_bytes() + b'if then\n'
        self.assert_head_source_refused(self.committed_copy(**{rel: broken}), 'sh -n')

    def test_payload_region_refuses_a_file_set_that_differs_from_the_manifest(self):
        commit, blobs = self.tool.head_source()
        extra = dict(blobs, **{'router/stray.sh': b'echo stray\n'})
        with self.assertRaises(self.tool.Refusal) as caught:
            self.tool.payload_region(extra)
        self.assertIn('release.sha256', str(caught.exception))
        missing = {path: data for path, data in blobs.items() if path != 'router/lib/json.awk'}
        with self.assertRaises(self.tool.Refusal):
            self.tool.payload_region(missing)

    @staticmethod
    def payload_manifest_paths(text):
        body = text[text.index("cat > \"$CFR_STAGE/manifest\" <<'CF_FIRST_MANIFEST_EOF'"):]
        body = body[body.index('\n') + 1:body.index('CF_FIRST_MANIFEST_EOF\n', 10)]
        return sorted(line.split()[2] for line in body.splitlines())

    @staticmethod
    def tree_sha256(entries):
        return hashlib.sha256(''.join(f'{mode} {rel} {digest}\n' for rel, (mode, digest) in sorted(entries.items())).encode()).hexdigest()

    def test_emitted_tree_matches_freezer_emit_and_is_disclosed_and_bound(self):
        out = Path(tempfile.mkdtemp(prefix='couvre-feu-emit-'))
        self.addCleanup(shutil.rmtree, out, True)
        emitted = out / 'tree'
        freezer = subprocess.run([sys.executable, str(REPO / 'tools/freeze-router-release.py'), '--emit', str(emitted)],
                                 capture_output=True, text=True, check=True, cwd=out)
        entries = {}
        for path in sorted(emitted.rglob('*')):
            if path.is_file():
                entries[str(path.relative_to(emitted))] = ('%o' % (path.stat().st_mode & 0o777),
                                                           hashlib.sha256(path.read_bytes()).hexdigest())
        commit, blobs = self.tool.head_source()
        tree = self.tool.emitted_tree(blobs)
        self.assertEqual({rel: (mode, hashlib.sha256(data).hexdigest()) for rel, (mode, data) in tree.items()}, entries)
        for rel, (mode, data) in tree.items():
            self.assertEqual((emitted / rel).read_bytes(), data, rel)
        self.assertEqual(self.tool.release_id(blobs), freezer.stdout.strip())
        details = self.plan_details(self.write_config())
        self.assertEqual(details['emittedTreeSha256'], self.tree_sha256(entries))
        self.assertIn('emittedTreeSha256', self.tool.PLAN_DIGEST_FIELDS)

    def test_release_id_recomputed_from_the_emitted_tree_equals_freezer_stdout(self):
        out = Path(tempfile.mkdtemp(prefix='couvre-feu-emit-'))
        self.addCleanup(shutil.rmtree, out, True)
        emitted = out / 'tree'
        freezer = subprocess.run([sys.executable, str(REPO / 'tools/freeze-router-release.py'), '--emit', str(emitted)],
                                 capture_output=True, text=True, check=True, cwd=out)
        # The freezer's formula, applied to the files it wrote (not to anything the tool declares).
        sha = lambda data: hashlib.sha256(data).hexdigest()
        lines = [name + ':' + sha((emitted / 'lib' / name).read_bytes()) for name in self.tool.RELEASE_MODULES]
        cfctl = re.sub(rb'(?m)^CF_BOOTSTRAP_PIN=.*$', b'CF_BOOTSTRAP_PIN=', (emitted / 'cfctl').read_bytes())
        lines += ['cfctl:' + sha(cfctl)] + [name + ':' + sha((emitted / name).read_bytes()) for name in ('cfctl-ssh', 'cfctl-scope')]
        recomputed = sha(('\n'.join(lines) + '\n').encode())
        self.assertEqual(recomputed, freezer.stdout.strip())
        commit, blobs = self.tool.head_source()
        self.assertEqual(self.tool.release_id(blobs), recomputed)
        installed = (emitted / 'lib/platform-bootstrap.sh').read_text()
        self.assertIn(f'CF_RELEASE_ID={recomputed}\n', installed)

    def test_emitted_tree_change_changes_the_plan_digest(self):
        first = self.plan_details(self.write_config())
        saved = self.tool.emitted_tree_sha256
        try:
            self.tool.emitted_tree_sha256 = lambda tree: 'e' * 64
            second = self.plan_details(self.write_config())
        finally:
            self.tool.emitted_tree_sha256 = saved
        self.assertNotEqual(first['planSha256'], second['planSha256'])

    def verify_installed(self, tamper=None, drop=None, planned_id=None, mutate=None):
        """Run only cfr_verify_installed from the template over a private copy of the emitted tree."""
        template = (REPO / 'tools/live/first-rehearsal.sh').read_text()
        match = re.search(r'(?ms)^cfr_verify_installed\(\) \{\n.*?^\}\n', template)
        self.assertIsNotNone(match, 'cfr_verify_installed missing from the template')
        commit, blobs = self.tool.head_source()
        tree = self.tool.emitted_tree(blobs)
        release_id = self.tool.release_id(blobs)
        scratch = Path(tempfile.mkdtemp(prefix='verify-', dir=self.work))
        root, stage = scratch / 'root', scratch / 'stage'
        release = root / f'etc/.couvrefeu-release-{release_id}'
        stage.mkdir()
        manifest = ''
        for rel, (mode, data) in tree.items():
            manifest += f'{hashlib.sha256(data).hexdigest()} {mode} router/{rel}\n'
            targets = [release / rel]
            if rel in ('cfctl', 'cfctl-ssh', 'cfctl-scope'):
                targets.append(root / 'usr/sbin' / rel)
            elif rel.startswith('lib/'):
                targets.append(root / 'usr/lib/couvrefeu' / rel[4:])
            for target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        (stage / 'manifest').write_text(manifest)
        if tamper:
            (root / tamper).write_bytes((root / tamper).read_bytes() + b'x')
        if drop:
            (root / drop).unlink()
        if mutate:
            mutate(root)
        script = ('cfr_info() { echo "INFO $*"; }\ncfr_fail() { echo "PHASE $1 FAIL $2"; }\n' + match.group(0)
                  + f'CFR_ROOT={shlex.quote(str(root))} CFR_STAGE={shlex.quote(str(stage))} '
                  f'CFR_RELEASE_DIR={shlex.quote(str(release))} CFR_RELEASE_ID={planned_id or release_id}\n'
                  'cfr_verify_installed; echo "rc=$?"\n')
        result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=20)
        return result.stdout + result.stderr, release_id

    def test_verify_installed_accepts_the_emitted_tree(self):
        out, release_id = self.verify_installed()
        self.assertIn('INFO installed_tree ok', out)
        self.assertIn(release_id, out)
        self.assertTrue(out.rstrip().endswith('rc=0'), out)

    def test_verify_installed_detects_tampering_or_absence(self):
        rid = self.tool.release_id(self.tool.head_source()[1])
        # Uninstall inputs (release directory, usr/lib/couvrefeu) return 2 without a FAIL line: the caller stops.
        uninstall_inputs = {'release dir file': f'etc/.couvrefeu-release-{rid}/lib/core.sh',
                            'release dir uninstall.sh': f'etc/.couvrefeu-release-{rid}/uninstall.sh',
                            'installed lib': 'usr/lib/couvrefeu/rpc.sh',
                            'installed bootstrap (id carrier)': 'usr/lib/couvrefeu/platform-bootstrap.sh'}
        for label, path in uninstall_inputs.items():
            with self.subTest(label):
                out, _ = self.verify_installed(tamper=path)
                self.assertIn('INFO installed_tree_mismatch', out)
                self.assertNotIn('PHASE VERIFY FAIL', out)
                self.assertTrue(out.rstrip().endswith('rc=2'), out)
        out, _ = self.verify_installed(tamper='usr/sbin/cfctl')
        self.assertIn('PHASE VERIFY FAIL installed_tree_mismatch', out)
        self.assertTrue(out.rstrip().endswith('rc=1'), out)
        out, _ = self.verify_installed(drop='usr/sbin/cfctl-scope')
        self.assertIn('PHASE VERIFY FAIL installed_tree_mismatch', out)
        out, _ = self.verify_installed(drop='usr/lib/couvrefeu/json.awk')
        self.assertTrue(out.rstrip().endswith('rc=2'), out)
        # Installed files carry another release id than the planned one.
        out, _ = self.verify_installed(planned_id='a' * 64)
        self.assertIn('installed_release_id', out)
        self.assertTrue(out.rstrip().endswith('rc=2'), out)

    def test_verify_installed_refuses_symlinks_and_non_regular_files(self):
        rid = self.tool.release_id(self.tool.head_source()[1])

        def symlink(rel):
            def apply(root):
                target = root / rel
                copy = target.with_name(target.name + '.real')
                copy.write_bytes(target.read_bytes())  # right bytes behind the link
                target.unlink()
                target.symlink_to(copy.name)
            return apply

        def fifo(rel):
            def apply(root):
                (root / rel).unlink()
                os.mkfifo(root / rel)
            return apply

        cases = {'symlinked sbin cfctl': (symlink('usr/sbin/cfctl'), 'rc=1'),
                 'symlinked installed lib': (symlink('usr/lib/couvrefeu/rpc.sh'), 'rc=2'),
                 'symlinked release file': (symlink(f'etc/.couvrefeu-release-{rid}/uninstall.sh'), 'rc=2'),
                 'fifo installed lib': (fifo('usr/lib/couvrefeu/rpc.sh'), 'rc=2'),
                 'fifo sbin cfctl': (fifo('usr/sbin/cfctl'), 'rc=1')}
        for label, (mutate, rc) in cases.items():
            with self.subTest(label):
                try:
                    out, _ = self.verify_installed(mutate=mutate)
                except subprocess.TimeoutExpired:
                    self.fail('a FIFO blocked the verifier')
                self.assertIn('installed_tree_mismatch', out)
                self.assertTrue(out.rstrip().endswith(rc), out)

    def tamper_installed_file(self, rel):
        """Router `sha256sum` double: append to an installed file just before VERIFY reads it by stdin redirection."""
        done = shlex.quote(str(self.work / 'tampered'))
        wrapper = self.fixture.bin / 'sha256sum'
        wrapper.write_text('#!/bin/sh\n'
                           'if [ "$#" = 0 ]; then target=$(readlink /proc/$$/fd/0 2>/dev/null)\n'
                           f'  case "$target" in {shlex.quote(str(self.root / rel))}) '
                           f'[ -e {done} ] || {{ : > {done}; printf x >> "$target"; }};; esac\nfi\n'
                           f'exec {shlex.quote(shutil.which("sha256sum"))} "$@"\n')
        wrapper.chmod(0o700)

    def assert_tampered_uninstall_input_stops(self, rel):
        release = self.tool.release_id(self.tool.head_source()[1])
        rel = rel.replace('RID', release)
        self.tamper_installed_file(rel)
        code, out, err = self.execute()
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertTrue((self.work / 'tampered').exists(), 'tamper hook never fired')
        self.assertNotEqual(code, 0, out + err)
        self.assertIn('PHASE VERIFY FAIL installed_uninstall_inputs_mismatch', stdout)
        self.assertIn('uninstall not attempted; journal retained', stdout)
        self.assertIn(f'installed_uninstall_inputs_mismatch {rel};', stdout)
        self.assertIn('FAIL_AFTER_MUTATION VERIFY', stdout)
        self.assertNotIn('run uninstall.sh', stdout)
        self.assertNotIn('PHASE UNINSTALL', stdout)
        self.assertNotIn('FIRST_REHEARSAL_PASS', stdout)
        self.assertTrue((self.root / 'etc/couvrefeu/backup/ready').is_file(), 'journal must be retained')
        self.assertTrue((self.root / f'etc/.couvrefeu-release-{release}/uninstall.sh').is_file())

    def test_tampered_release_dir_uninstall_stops_without_running_it(self):
        self.assert_tampered_uninstall_input_stops('etc/.couvrefeu-release-RID/uninstall.sh')

    def test_tampered_installed_lib_stops_without_running_uninstall(self):
        self.assert_tampered_uninstall_input_stops('usr/lib/couvrefeu/rpc.sh')

    def test_rehearsal_reports_installed_tree_check(self):
        code, out, err = self.execute()
        self.assertEqual(code, 0, out + err)
        stdout = (self.evidence() / 'stdout.log').read_text()
        self.assertIn(f'INFO installed_tree ok release={self.tool.release_id(self.tool.head_source()[1])}', stdout)
        self.assertLess(stdout.index('INFO installed_tree ok'), stdout.index('PHASE VERIFY OK'))

    def test_release_module_list_matches_freezer(self):
        freezer = (REPO / 'tools/freeze-router-release.py').read_text()
        names = re.search(r"^names = \[(.*)\]$", freezer, re.M).group(1)
        self.assertEqual(tuple(re.findall(r"'([^']+)'", names)), self.tool.RELEASE_MODULES)

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

    def rehearsal_var(self, name):
        text = (REPO / 'tools/live/first-rehearsal.sh').read_text()
        match = re.search(r"^%s='([^']*)'$" % name, text, re.M)
        self.assertIsNotNone(match, name)
        return set(match.group(1).split())

    def test_rehearsal_file_lists_cover_release_and_install(self):
        release = {line.split()[1] for line in (REPO / 'router/release.sha256').read_text().splitlines() if line.strip()}
        # release.sha256 cannot list itself; the rehearsal inventories it explicitly.
        self.assertEqual(self.rehearsal_var('CFR_RELEASE_FILES'), release | {'release.sha256'})
        installed = set(re.findall(r'^\s+((?:usr|etc)/\S+?\))\s', (REPO / 'router/install.sh').read_text(), re.M))
        installed = {item.rstrip(')') for item in installed}
        installed |= set(re.findall(r'; ((?:usr|etc)/\S+?)\) staged=', (REPO / 'router/install.sh').read_text()))
        self.assertTrue(installed)
        self.assertEqual(installed - self.rehearsal_var('CFR_FILES'), set())
        # install-common.sh's own FILES inventory (initial list plus every appended path, activity.sh included).
        common = (REPO / 'router/lib/install-common.sh').read_text()
        common_files = set(re.findall(r"^FILES='([^']*)'$", common, re.M)[0].split())
        for appended in re.findall(r'^\s*FILES="\$FILES ([^"]*)"$', common, re.M):
            common_files |= set(appended.split())
        self.assertIn('usr/lib/couvrefeu/activity.sh', common_files)
        self.assertEqual(common_files - self.rehearsal_var('CFR_FILES'), set())

    def test_busy_result_status_keys_match_cf_status(self):
        lines = [line for line in (REPO / 'router/lib/core.sh').read_text().splitlines()
                 if line.lstrip().startswith("printf '{\"ok\":") and 'desiredRevision' in line]
        self.assertEqual(len(lines), 2)
        keys = [re.findall(r'"(\w+)":', line) for line in lines]
        self.assertEqual(keys[0], keys[1])


if __name__ == '__main__':
    unittest.main()
