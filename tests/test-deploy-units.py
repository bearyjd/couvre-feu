#!/usr/bin/env python3
"""Static checks for deploy/ and docs/runbooks/deploy.md. No network, no Docker daemon, no live host."""
from pathlib import Path
import re
import shutil
import subprocess
import unittest

REPO = Path(__file__).resolve().parent.parent
UNITS = REPO / 'deploy' / 'systemd'
APP, AGENT = (UNITS / 'couvrefeu.service').read_text(), (UNITS / 'couvrefeu-agent.service').read_text()
DOCKERFILE = (REPO / 'deploy' / 'docker' / 'Dockerfile').read_text()
COMPOSE = (REPO / 'deploy' / 'docker' / 'compose.yaml').read_text()
DOC = (REPO / 'docs' / 'runbooks' / 'deploy.md').read_text()
PUBLIC = [UNITS / 'couvrefeu.service', UNITS / 'couvrefeu-agent.service', UNITS / 'couvrefeu.nft',
          REPO / 'deploy' / 'docker' / 'Dockerfile', REPO / 'deploy' / 'docker' / 'compose.yaml',
          REPO / 'docs' / 'runbooks' / 'deploy.md']


class DeployFiles(unittest.TestCase):
    def test_app_unit_is_hardened_and_least_privilege(self):
        for line in ['User=couvrefeu', 'NoNewPrivileges=yes', 'ProtectSystem=strict', 'ReadWritePaths=/var/lib/couvrefeu',
                     'PrivateTmp=yes', 'UMask=0077', 'CapabilityBoundingSet=', 'Requires=couvrefeu-agent.service',
                     'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX']:
            self.assertIn(line, APP)
        self.assertIn('service/src/integration-main.ts /etc/couvrefeu/manifest.json', APP)
        self.assertNotIn('ReadWritePaths=/opt', APP)

    def test_agent_unit_is_private_and_networkless(self):
        for line in ['User=couvrefeu', 'RuntimeDirectory=couvrefeu', 'RuntimeDirectoryMode=0700', 'PrivateNetwork=yes',
                     'RestrictAddressFamilies=AF_UNIX', 'ssh-agent -D -a /run/couvrefeu/agent.sock', 'NoNewPrivileges=yes']:
            self.assertIn(line, AGENT)
        self.assertNotIn('ssh-add', AGENT)

    def test_docker_pins_node_by_version_and_digest_and_runs_unprivileged(self):
        self.assertEqual(len(re.findall(r'^FROM node:26\.8\.1-slim@sha256:[0-9a-f]{64}( AS \w+)?$', DOCKERFILE, re.M)), 2)
        self.assertEqual(DOCKERFILE.count('FROM '), 2)
        self.assertIn('USER 10001:10001', DOCKERFILE)
        self.assertIn('HEALTHCHECK', DOCKERFILE)
        self.assertNotIn('npm run', DOCKERFILE)

    def test_compose_enforces_source_address_fidelity_and_lockdown(self):
        for line in ['network_mode: host', 'read_only: true', 'cap_drop: [ALL]', 'no-new-privileges:true', '/etc/couvrefeu:/etc/couvrefeu:ro']:
            self.assertIn(line, COMPOSE)
        self.assertIsNone(re.search(r'^\s*ports:', COMPOSE, re.M))

    def test_public_files_contain_only_placeholders(self):
        for path in PUBLIC:
            text = path.read_text()
            self.assertIsNone(re.search(r'\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+(?:\.\d+)?\b', text.replace('172.17.0.1', '').replace('172.16.0.0/12', '')), path.name)
            self.assertIsNone(re.search(r'(?:ssh-ed25519|ssh-rsa) AAAA|BEGIN [A-Z ]*PRIVATE KEY|SHA256:[A-Za-z0-9+/]{43}', text), path.name)

    def test_doc_links_resolve_and_cover_required_topics(self):
        for target in re.findall(r'\]\(([^)#]+)\)', DOC):
            if '://' not in target:
                self.assertTrue((DOC_PATH.parent / target).resolve().exists(), target)
        for phrase in ['network_mode: host', 'ss -tn sport = :4273', 'irreversible', 'manifest digest', 'RP ID', 'http-behind-proxy.md']:
            self.assertIn(phrase, DOC)

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyze is not installed')
    def test_systemd_analyze_verify(self):
        result = subprocess.run(['systemd-analyze', 'verify', str(UNITS / 'couvrefeu-agent.service'), str(UNITS / 'couvrefeu.service')],
                                capture_output=True, text=True, timeout=60)
        # Only the absent interpreter/agent binaries and the not-yet-created user may differ per host.
        problems = [l for l in result.stderr.splitlines() if l and not re.search(r'is not executable|Failed to (?:resolve|look up) user|not found', l)]
        self.assertEqual(problems, [], result.stderr)


DOC_PATH = REPO / 'docs' / 'runbooks' / 'deploy.md'
if __name__ == '__main__':
    unittest.main()
