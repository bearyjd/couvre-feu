#!/usr/bin/env python3
"""Static checks for deploy/ and docs/runbooks/deploy.md. No network, no Docker daemon, no live host.

Unit files are compared against their COMPLETE directive lists, so any added, removed or changed
hardening directive fails here and has to be reviewed deliberately.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(os.environ.get('CF_DEPLOY_REPO', Path(__file__).resolve().parent.parent))
UNITS, DOCKER = REPO / 'deploy' / 'systemd', REPO / 'deploy' / 'docker'
DOC_PATH = REPO / 'docs' / 'runbooks' / 'deploy.md'
SANDBOX = [
    'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'AmbientCapabilities=', 'ProtectSystem=strict', 'ProtectHome=yes',
    'PrivateTmp=yes', 'PrivateDevices=yes', 'ProtectProc=invisible', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes',
    'ProtectKernelLogs=yes', 'ProtectControlGroups=yes', 'ProtectClock=yes', 'ProtectHostname=yes', 'RestrictNamespaces=yes',
    'RestrictRealtime=yes', 'RestrictSUIDSGID=yes', 'LockPersonality=yes', 'SystemCallArchitectures=native',
    'SystemCallFilter=@system-service', 'SystemCallFilter=~@privileged @resources', 'LimitCORE=0',
]
APP_EXPECTED = [
    '[Unit]', 'Description=Couvre-feu parent app', 'Documentation=https://github.com/bearyjd/couvre-feu/blob/main/docs/runbooks/deploy.md',
    'After=network-online.target couvrefeu-agent.service', 'Wants=network-online.target', 'Requires=couvrefeu-agent.service',
    '[Service]', 'Type=simple', 'User=couvrefeu', 'Group=couvrefeu', 'WorkingDirectory=/opt/couvrefeu',
    'ExecStart=/usr/local/bin/node /opt/couvrefeu/service/src/integration-main.ts /etc/couvrefeu/manifest.json',
    'StartLimitIntervalSec=0', 'Restart=always', 'RestartSec=5', 'RestartSteps=5', 'RestartMaxDelaySec=5min', 'RestartPreventExitStatus=78', 'UMask=0077', 'TimeoutStopSec=30', 'ReadWritePaths=/var/lib/couvrefeu',
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX', 'TasksMax=64', 'MemoryMax=512M', *SANDBOX,
    '[Install]', 'WantedBy=multi-user.target',
]
AGENT_EXPECTED = [
    '[Unit]', 'Description=Couvre-feu dedicated ssh-agent', 'Documentation=https://github.com/bearyjd/couvre-feu/blob/main/docs/runbooks/deploy.md',
    '[Service]', 'Type=simple', 'User=couvrefeu', 'Group=couvrefeu', 'RuntimeDirectory=couvrefeu', 'RuntimeDirectoryMode=0700',
    'RuntimeDirectoryPreserve=restart', 'UMask=0077', 'ExecStartPre=-/usr/bin/rm -f /run/couvrefeu/agent.sock',
    'ExecStart=/usr/bin/ssh-agent -D -a /run/couvrefeu/agent.sock', 'Restart=on-failure', 'RestartSec=5',
    'PrivateNetwork=yes', 'RestrictAddressFamilies=AF_UNIX', 'MemoryDenyWriteExecute=yes', 'TasksMax=16', 'MemoryMax=64M', *SANDBOX,
    '[Install]', 'WantedBy=multi-user.target',
]
DOC_URL = 'Documentation=https://github.com/bearyjd/couvre-feu/blob/main/docs/runbooks/deploy.md'
HEARTBEAT_EXPECTED = [
    '[Unit]', 'Description=Couvre-feu heartbeat push', DOC_URL, 'After=network-online.target', 'Wants=network-online.target',
    '[Service]', 'Type=oneshot', 'ExecStart=/usr/local/sbin/couvrefeu-heartbeat', 'TimeoutStartSec=60', 'UMask=0077',
    'NoNewPrivileges=yes', 'ProtectSystem=strict', 'PrivateTmp=yes', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes',
    'ProtectControlGroups=yes', 'RestrictRealtime=yes', 'LockPersonality=yes', 'ProtectHome=read-only', 'PrivateDevices=yes',
    'ProtectKernelLogs=yes', 'ProtectClock=yes', 'ProtectHostname=yes', 'RestrictNamespaces=yes', 'RestrictSUIDSGID=yes',
    'SystemCallArchitectures=native', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6', 'CapabilityBoundingSet=CAP_DAC_OVERRIDE',
    'MemoryMax=64M', 'TasksMax=32',
]
HEARTBEAT_TIMER_EXPECTED = [
    '[Unit]', 'Description=Couvre-feu heartbeat every minute', DOC_URL,
    '[Timer]', 'OnBootSec=2min', 'OnUnitActiveSec=1min', 'AccuracySec=5s', '[Install]', 'WantedBy=timers.target',
]
BACKUP_EXPECTED = [
    '[Unit]', 'Description=Couvre-feu database backup', DOC_URL,
    '[Service]', 'Type=oneshot', 'User=couvrefeu', 'Group=couvrefeu', 'WorkingDirectory=/opt/couvrefeu',
    'ExecStart=/usr/local/bin/node /opt/couvrefeu/deploy/backup.mjs', 'UMask=0077', 'TimeoutStartSec=10min',
    'ReadWritePaths=/var/backups/couvrefeu /var/lib/couvrefeu', 'PrivateNetwork=yes', 'RestrictAddressFamilies=AF_UNIX',
    'TasksMax=32', 'MemoryMax=512M', *SANDBOX,
]
BACKUP_TIMER_EXPECTED = [
    '[Unit]', 'Description=Couvre-feu daily database backup', DOC_URL,
    '[Timer]', 'OnCalendar=*-*-* 03:30', 'RandomizedDelaySec=30min', 'Persistent=true', '[Install]', 'WantedBy=timers.target',
]
NFT_RULES = [
    'add table inet couvrefeu', 'delete table inet couvrefeu', 'table inet couvrefeu {', 'chain input {', 'chain output {',
    'iif lo accept', 'ct state established,related accept', 'ct state invalid drop', 'meta l4proto { icmp, ipv6-icmp } accept',
    'ip saddr <ADMIN_IP> tcp dport 22 accept', 'ip saddr <PROXY_IP> tcp dport 4273 accept',
    'oif lo accept', 'ip daddr <ROUTER_IP> tcp dport 22 accept', 'ip daddr <DNS_IP> udp dport 53 accept',
    'ip daddr <DNS_IP> tcp dport 53 accept', 'ip daddr <NTP_IP> udp dport 123 accept',
    'ct state established,related accept', 'meta l4proto { icmp, ipv6-icmp } accept',
]
DOCKERIGNORE = ['*', '!package.json', '!package-lock.json', '!LICENSE', '!VERSION', '!shared/src', '!service/src',
                '!service/migrations', '!web/public', '!deploy/docker/healthcheck.mjs']
SERVICE_READABLE = ('/etc/couvrefeu/', '/var/lib/couvrefeu/', '/opt/couvrefeu/', '/run/couvrefeu/', '/tmp/', '/home/')
ALLOWED_ETC = {'manifest.json', 'known_hosts', 'service_key.pub'}
IPV4 = re.compile(r'(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])')
IPV6 = re.compile(r'(?<![\w:/])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}|(?<![\w:/])::[0-9A-Fa-f]{0,4}')
MAC = re.compile(r'(?<![\w:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:])')


def lines(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith('#')]


def read(*parts):
    return (REPO.joinpath(*parts)).read_text()


def public_files():
    return [p for root in (REPO / 'deploy',) for p in root.rglob('*') if p.is_file()] + [REPO / '.dockerignore', DOC_PATH]


def unit_verify_problems(stderr, unit_paths):
    names = '|'.join(re.escape(Path(path).name) for path in unit_paths)
    if not names:
        return []
    unit_reference = re.compile(r'(?<![\w.@:+\\-])(?:' + names + r')(?![\w.@+\\-])')
    # Only interpreter/script binaries may be absent on the machine running this check.
    absent = {f'{unit}: Command {binary} is not executable: No such file or directory' for unit, binary in (
        ('couvrefeu.service', '/usr/local/bin/node'), ('couvrefeu-backup.service', '/usr/local/bin/node'),
        ('couvrefeu-heartbeat.service', '/usr/local/sbin/couvrefeu-heartbeat'))}
    return [line for line in stderr.splitlines() if unit_reference.search(line) and line not in absent]


class UnitVerifyDiagnostics(unittest.TestCase):
    def test_foreign_unit_diagnostics_are_ignored(self):
        stderr = '\n'.join([
            '/usr/lib/systemd/system/xfs_scrub_all.service:26: Support for option CPUAccounting= has been removed and it is ignored',
            '/usr/lib/systemd/system/system-xfs_scrub.slice:12: Support for option CPUAccounting= has been removed and it is ignored',
            '/usr/lib/systemd/system/walinuxagent.service:14: Support for option CPUAccounting= has been removed and it is ignored',
        ])
        self.assertEqual(unit_verify_problems(stderr, [UNITS / 'couvrefeu.service']), [])

    def test_own_unit_diagnostics_survive_interleaved_foreign_output(self):
        own = [
            f'{UNITS / "couvrefeu.service"}:12: Unknown key name',
            'couvrefeu-agent.service: Failed to load configuration',
        ]
        stderr = '\n'.join(['xfs_scrub_all.service: warning', own[0],
                            'walinuxagent.service: error', own[1], 'system-xfs_scrub.slice: error'])
        self.assertEqual(unit_verify_problems(stderr, [UNITS / 'couvrefeu.service',
                                                      UNITS / 'couvrefeu-agent.service']), own)

    def test_unit_names_are_bounded_and_supplied_units_are_generic(self):
        own = '/tmp/extra@sample.service:9: Unknown key name'
        stderr = '\n'.join(['prefix-extra@sample.service: warning',
                            'extra@sample.service.backup: warning', own,
                            'extra@sample.service: Failed to load configuration'])
        self.assertEqual(unit_verify_problems(stderr, [Path('/tmp/extra@sample.service')]),
                         [own, 'extra@sample.service: Failed to load configuration'])

    def test_only_exact_missing_node_diagnostic_is_exempt(self):
        missing = 'couvrefeu.service: Command /usr/local/bin/node is not executable: No such file or directory'
        other = missing.replace('No such file or directory', 'Permission denied')
        self.assertEqual(unit_verify_problems('\n'.join([missing, other]), [UNITS / 'couvrefeu.service']), [other])


class DeployFiles(unittest.TestCase):
    def test_app_unit_has_exactly_the_reviewed_directives(self):
        text = read('deploy', 'systemd', 'couvrefeu.service')
        self.assertEqual(sorted(lines(text)), sorted(APP_EXPECTED))
        self.assertLess(text.index('SystemCallFilter=@system-service'), text.index('SystemCallFilter=~@privileged'))
        self.assertNotIn('MemoryDenyWriteExecute=yes', read('deploy', 'systemd', 'couvrefeu.service'))

    def test_app_unit_always_restarts_without_start_limit_or_watchdog(self):
        text = read('deploy', 'systemd', 'couvrefeu.service')
        unit, service = text.split('[Service]')
        self.assertIn('StartLimitIntervalSec=0', lines(unit))
        self.assertIn('Restart=always', lines(service))
        self.assertIn('RestartSec=5', lines(service))
        self.assertEqual(sorted(l for l in lines(service) if l.startswith('Restart') and l != 'Restart=always'),
                         ['RestartMaxDelaySec=5min', 'RestartPreventExitStatus=78', 'RestartSec=5', 'RestartSteps=5'])
        self.assertNotIn('StartLimitBurst', text)
        self.assertNotIn('WatchdogSec', text)

    def test_heartbeat_keeps_cap_dac_override_to_reach_the_agent_socket(self):
        caps = [l for l in lines(read('deploy', 'systemd', 'couvrefeu-heartbeat.service')) if l.startswith('CapabilityBoundingSet=')]
        self.assertEqual(caps, ['CapabilityBoundingSet=CAP_DAC_OVERRIDE'])
        self.assertNotIn('ProtectHome=yes', lines(read('deploy', 'systemd', 'couvrefeu-heartbeat.service')))

    def test_exit_78_is_the_startup_refusal_code_in_the_service(self):
        main = read('service', 'src', 'integration-main.ts')
        self.assertIn('process.exit(78)', main)
        self.assertIn('RestartPreventExitStatus=78', read('deploy', 'systemd', 'couvrefeu.service'))

    def test_heartbeat_and_backup_units_have_exactly_the_reviewed_directives(self):
        for name, expected in (('couvrefeu-heartbeat.service', HEARTBEAT_EXPECTED), ('couvrefeu-heartbeat.timer', HEARTBEAT_TIMER_EXPECTED),
                               ('couvrefeu-backup.service', BACKUP_EXPECTED), ('couvrefeu-backup.timer', BACKUP_TIMER_EXPECTED)):
            self.assertEqual(sorted(lines(read('deploy', 'systemd', name))), sorted(expected), name)
        self.assertLess(read('deploy', 'systemd', 'couvrefeu-backup.service').index('SystemCallFilter=@system-service'),
                        read('deploy', 'systemd', 'couvrefeu-backup.service').index('SystemCallFilter=~@privileged'))

    def test_agent_unit_has_exactly_the_reviewed_directives_and_no_partof(self):
        text = read('deploy', 'systemd', 'couvrefeu-agent.service')
        self.assertEqual(sorted(lines(text)), sorted(AGENT_EXPECTED))
        self.assertLess(text.index('SystemCallFilter=@system-service'), text.index('SystemCallFilter=~@privileged'))
        for forbidden in ('PartOf=', 'BindsTo=', 'ssh-add', 'PrivateNetwork=no'):
            self.assertNotIn(forbidden, '\n'.join(lines(text)))

    def test_nft_is_scoped_default_drop_and_never_flushes(self):
        text = read('deploy', 'systemd', 'couvrefeu.nft')
        self.assertNotIn('flush', text)
        self.assertEqual(len(re.findall(r'policy drop;', text)), 2)
        body = [l for l in lines(text) if not l.startswith('type filter hook') and l != '}' and not l.startswith('#!')]
        self.assertEqual(sorted(body), sorted(NFT_RULES))
        self.assertEqual(set(re.findall(r'<[A-Z_]+>', '\n'.join(lines(text)))), {'<ADMIN_IP>', '<PROXY_IP>', '<ROUTER_IP>', '<DNS_IP>', '<NTP_IP>'})

    def test_nft_syntax_with_documentation_addresses(self):
        if not shutil.which('nft'):
            self.skipTest('nft is not installed')
        text = read('deploy', 'systemd', 'couvrefeu.nft')
        for name, addr in {'ADMIN_IP': '192.0.2.10', 'PROXY_IP': '192.0.2.20', 'ROUTER_IP': '192.0.2.1', 'DNS_IP': '192.0.2.1', 'NTP_IP': '192.0.2.1'}.items():
            text = text.replace(f'<{name}>', addr)
        with tempfile.NamedTemporaryFile('w', suffix='.nft') as f:
            f.write(text); f.flush()
            result = subprocess.run(['nft', '-c', '-f', f.name], capture_output=True, text=True, timeout=30)
        if 'Operation not permitted' in result.stderr or 'Permission denied' in result.stderr:
            self.skipTest('nft -c needs netlink privileges here')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dockerfile_pins_node_by_version_and_digest_and_runs_unprivileged(self):
        text = read('deploy', 'docker', 'Dockerfile')
        self.assertEqual(len(re.findall(r'^FROM node:26\.13\.1-slim@sha256:[0-9a-f]{64}( AS \w+)?$', text, re.M)), 2)
        self.assertEqual(text.count('FROM '), 2)
        self.assertIn('USER 10001:10001', text)
        self.assertIn('HEALTHCHECK', text)
        self.assertNotIn('npm run', text)
        self.assertEqual(lines(read('.dockerignore')), DOCKERIGNORE)

    def test_compose_enforces_source_address_fidelity_and_lockdown(self):
        text = read('deploy', 'docker', 'compose.yaml')
        for line in ['network_mode: host', 'user: "10001:10001"', 'read_only: true', 'cap_drop: [ALL]', 'no-new-privileges:true',
                     '- /etc/couvrefeu:/etc/couvrefeu:ro', '- /run/couvrefeu:/run/couvrefeu:ro', '- /var/lib/couvrefeu:/var/lib/couvrefeu']:
            self.assertIn(line, lines(text) if line.startswith('- ') else text)
        volumes = [l for l in lines(text) if l.startswith('- /')]
        self.assertEqual(len(volumes), 3)
        self.assertEqual([v for v in volumes if not v.endswith(':ro')], ['- /var/lib/couvrefeu:/var/lib/couvrefeu'])
        self.assertIsNone(re.search(r'^\s*ports:', text, re.M))
        self.assertIsNone(re.search(r'privileged:\s*true|/var/run/docker.sock|cap_add', text))

    def test_public_files_contain_no_addresses_or_key_material(self):
        for path in public_files():
            text = path.read_text()
            for pattern in (IPV4, IPV6, MAC):
                self.assertIsNone(pattern.search(text), f'{path.name}: {pattern.pattern}')
            self.assertIsNone(re.search(r'(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-\w+) AAAA|BEGIN [A-Z ]*PRIVATE KEY|SHA256:[A-Za-z0-9+/]{43}', text), path.name)

    def test_private_key_is_never_placed_in_a_service_readable_path(self):
        for path in public_files():
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if re.search(r'ssh-add|ssh-keygen|IdentityFile|PRIVATE', line):
                    line = re.sub(r'SSH_AUTH_SOCK=\S+', '', line)
                    for root in SERVICE_READABLE:
                        self.assertNotIn(root, line, f'{path.name}:{number}')
            for name in re.findall(r'/etc/couvrefeu/([A-Za-z0-9_.<>-]+)', path.read_text()):
                self.assertIn(name, ALLOWED_ETC, f'{path.name}: {name}')
        doc = DOC_PATH.read_text()
        self.assertIn('/root/couvrefeu-key/service_key', doc)
        self.assertIn('install -d -o root -g root -m 0700 /root/couvrefeu-key', doc)

    def test_ssh_add_commands_force_tty_prompt_and_root_can_connect(self):
        doc = DOC_PATH.read_text()
        loads = [l for l in doc.splitlines() if re.search(r'ssh-add .*couvrefeu-key/service_key', l)]
        self.assertEqual(len(loads), 1)
        self.assertIn('env SSH_ASKPASS_REQUIRE=never SSH_AUTH_SOCK=/run/couvrefeu/agent.sock ssh-add', loads[0])
        self.assertNotIn('only talks to its own uid', doc)
        self.assertNotIn('sudo -u couvrefeu env SSH_AUTH_SOCK', doc)

    def test_push_url_credential_never_in_curl_argv(self):
        for text in (DOC_PATH.read_text(), read('deploy', 'heartbeat.sh')):
            for line in [l for l in text.splitlines() if re.search(r'(?:^|\| )curl\b', l.strip())]:
                self.assertNotRegex(line[line.index('curl'):], r'\$\{?(?:URL|PUSH)', line)
                self.assertNotIn('<MONITOR_PUSH_URL>', line)
        script = read('deploy', 'heartbeat.sh')
        pushes = [l for l in script.splitlines() if '?status=' in l and 'curl' in l]
        self.assertEqual(len(pushes), 1)
        self.assertRegex(pushes[0], r"printf 'url = \"%s\?status=%s&msg=%s\"\\n' \"\$URL\" \"\$status\" \"\$msg\" \| curl -q -fsS -m 10 --proto \"=\$PROTO\" --proto-redir \"=\$PROTO\" -K - >/dev/null")
        doc = DOC_PATH.read_text()
        self.assertNotIn('?status=...', doc)
        self.assertIn('bare monitor push URL', doc)

    def test_tailscale_note_lists_all_required_rules(self):
        doc = DOC_PATH.read_text()
        for phrase in ('oif "tailscale0" accept', 'udp dport 3478', 'udp dport 41641', 'Tailscale is not combinable as written'):
            self.assertIn(phrase, doc)

    def test_nft_file_documents_static_ip_ipv4_and_tailscale_limits(self):
        header = '\n'.join(l for l in read('deploy', 'systemd', 'couvrefeu.nft').splitlines() if l.startswith('#'))
        for phrase in ('REQUIRES A STATIC ADDRESS', 'udp 67/68', 'IPv4-only', 'tailscaled'):
            self.assertIn(phrase, header)

    def test_doc_links_resolve_and_cover_required_topics(self):
        doc = DOC_PATH.read_text()
        for target in re.findall(r'\]\(([^)#]+)\)', doc):
            if '://' not in target:
                self.assertTrue((DOC_PATH.parent / target).resolve().exists(), target)
        for phrase in ['network_mode: host', 'ss -tn sport = :4273', 'not reversible', 'manifest digest', 'RP ID', 'http-behind-proxy.md',
                       'docker exec', 'ssh-add -t <LIFETIME>', 'gpg --verify SHASUMS256.txt.sig SHASUMS256.txt', 'sha256sum -c --ignore-missing',
                       'nft -c -f', 'systemd-run --unit=couvrefeu-nft-rollback --on-active=5m nft delete table inet couvrefeu', 'systemctl stop couvrefeu-nft-rollback.timer',
                       'NEW SSH session', 'Static address required', 'udp dport { 67, 68 } accept', 'IPv4 only', 'Tailscale is not combinable',
                       'UDP 41641', 'tailscale0', 'Key lifetime', 'ssh-add -l', 'couvrefeu-heartbeat', 'OnUnitActiveSec=1min', 'PartOf=', 'does **not** show']:
            self.assertIn(phrase, doc)

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyze is not installed')
    def test_systemd_analyze_verify(self):
        names = ('couvrefeu-agent.service', 'couvrefeu.service', 'couvrefeu-heartbeat.service',
                 'couvrefeu-heartbeat.timer', 'couvrefeu-backup.service', 'couvrefeu-backup.timer')
        version = subprocess.run(['systemd-analyze', '--version'], capture_output=True, text=True, timeout=60)
        match = re.match(r'systemd (\d+)', version.stdout)
        old_systemd = bool(match) and int(match.group(1)) < 254  # RestartSteps/RestartMaxDelaySec arrived in 254
        with tempfile.TemporaryDirectory() as tmp:
            unit_paths = []
            for name in names:
                text = (UNITS / name).read_text()
                if old_systemd:
                    text = ''.join(l for l in text.splitlines(True) if not l.startswith(('RestartSteps=', 'RestartMaxDelaySec=')))
                path = Path(tmp) / name
                path.write_text(text)
                unit_paths.append(path)
            result = subprocess.run(['systemd-analyze', 'verify', *map(str, unit_paths)],
                                    capture_output=True, text=True, timeout=60)
        # Only the interpreter/script binaries may be absent on the machine running this check.
        problems = unit_verify_problems(result.stderr, unit_paths)
        self.assertEqual(problems, [], result.stderr)


if __name__ == '__main__':
    unittest.main()
