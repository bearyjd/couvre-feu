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
    'Restart=on-failure', 'RestartSec=5', 'UMask=0077', 'TimeoutStopSec=30', 'ReadWritePaths=/var/lib/couvrefeu',
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
NFT_RULES = [
    'add table inet couvrefeu', 'delete table inet couvrefeu', 'table inet couvrefeu {', 'chain input {', 'chain output {',
    'iif lo accept', 'ct state established,related accept', 'ct state invalid drop', 'meta l4proto { icmp, ipv6-icmp } accept',
    'ip saddr <ADMIN_IP> tcp dport 22 accept', 'ip saddr <PROXY_IP> tcp dport 4273 accept',
    'oif lo accept', 'ip daddr <ROUTER_IP> tcp dport 22 accept', 'ip daddr <DNS_IP> udp dport 53 accept',
    'ip daddr <DNS_IP> tcp dport 53 accept', 'ip daddr <NTP_IP> udp dport 123 accept',
    'ct state established,related accept', 'meta l4proto { icmp, ipv6-icmp } accept',
]
DOCKERIGNORE = ['*', '!package.json', '!package-lock.json', '!LICENSE', '!shared/src', '!service/src', '!service/migrations',
                '!web/public', '!deploy/docker/healthcheck.mjs']
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


class DeployFiles(unittest.TestCase):
    def test_app_unit_has_exactly_the_reviewed_directives(self):
        text = read('deploy', 'systemd', 'couvrefeu.service')
        self.assertEqual(sorted(lines(text)), sorted(APP_EXPECTED))
        self.assertLess(text.index('SystemCallFilter=@system-service'), text.index('SystemCallFilter=~@privileged'))
        self.assertNotIn('MemoryDenyWriteExecute=yes', read('deploy', 'systemd', 'couvrefeu.service'))

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
        self.assertEqual(len(re.findall(r'^FROM node:26\.8\.1-slim@sha256:[0-9a-f]{64}( AS \w+)?$', text, re.M)), 2)
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
                       'UDP 41641', 'tailscale0', 'Key lifetime', 'ssh-add -l', 'couvrefeu-agent-check', 'OnUnitActiveSec=1min', 'PartOf=', 'does **not** show']:
            self.assertIn(phrase, doc)

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyze is not installed')
    def test_systemd_analyze_verify(self):
        result = subprocess.run(['systemd-analyze', 'verify', str(UNITS / 'couvrefeu-agent.service'), str(UNITS / 'couvrefeu.service')],
                                capture_output=True, text=True, timeout=60)
        # Only the interpreter binary may be absent on the machine running this check.
        problems = [l for l in result.stderr.splitlines() if l and not re.fullmatch(r'couvrefeu\.service: Command /usr/local/bin/node is not executable: No such file or directory', l)]
        self.assertEqual(problems, [], result.stderr)


if __name__ == '__main__':
    unittest.main()
