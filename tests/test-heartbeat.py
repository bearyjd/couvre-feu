#!/usr/bin/env python3
"""deploy/heartbeat.sh against stubbed systemctl, ssh-add and curl. No network, no systemd, no real agent."""
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / 'deploy' / 'heartbeat.sh'
SECRET = 'https://monitor.example.invalid/push/SECRETTOKEN123'
HEALTH = 'https://app.example.invalid:4273/health'
PATH_LINE = 'PATH=/usr/sbin:/usr/bin:/sbin:/bin'
RUN_SECONDS = 60

SYSTEMCTL = """#!/bin/sh
# usage: systemctl is-enabled|is-active --quiet NAME
case " ${STUB_DISABLED:-} " in *" $3 "*) [ "$1" = is-enabled ] && exit 1;; esac
case " ${STUB_INACTIVE:-} " in *" $3 "*) [ "$1" = is-active ] && exit 3;; esac
exit 0
"""
SSH_ADD = """#!/bin/sh
printf '%s\\n' "${SSH_AUTH_SOCK:-}" > "$STUB_DIR/ssh-add-sock"
[ -z "${STUB_AGENT_EMPTY:-}" ]
"""
STAT = """#!/bin/sh
printf '%s\\n' "${STUB_STAT:-0:600}"
"""
TIMEOUT = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_DIR/timeout-argv"
shift
exec "$@"
"""
CURL = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_DIR/curl-argv"
cfg=$(cat)
printf '%s\\n' "$cfg" >> "$STUB_DIR/curl-stdin"
case "$cfg" in
    *"$STUB_HEALTH_MARK"*)
        printf '%s\\n%s' "${STUB_HEALTH_BODY:-{\\"ok\\":true}}" "${STUB_HEALTH_CODE:-200}"
        [ -z "${STUB_HEALTH_FAIL:-}" ];;
    *) [ -z "${STUB_PUSH_FAIL:-}" ] || exit 22;;
esac
"""


class Heartbeat(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.bin = self.dir / 'bin'
        self.bin.mkdir()
        for name, body in (('systemctl', SYSTEMCTL), ('ssh-add', SSH_ADD), ('curl', CURL), ('stat', STAT), ('timeout', TIMEOUT)):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        self.url_file = self.dir / 'push-url'
        self.url_file.write_text(SECRET + '\n')
        self.url_file.chmod(0o600)
        # The script pins PATH to system directories; tests run a copy whose PATH line points at the stubs.
        text = SCRIPT.read_text()
        self.assertIn(PATH_LINE + '\n', text)
        self.script = self.dir / 'heartbeat.sh'
        self.script.write_text(text.replace(PATH_LINE + '\n', f'PATH={self.bin}:/usr/bin:/bin\n', 1))

    def tearDown(self):
        self._tmp.cleanup()

    def run_hb(self, health=False, url_file=None, **extra):
        env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'STUB_DIR': str(self.dir), 'STUB_HEALTH_MARK': 'app.example',
               'HEARTBEAT_URL_FILE': str(url_file or self.url_file), 'SSH_AUTH_SOCK': '/run/example/agent.sock'}  # inherited value must be ignored
        if health:
            env['HEARTBEAT_HEALTH_URL'] = HEALTH
        env.update(extra)
        return subprocess.run(['sh', str(self.script)], env=env, capture_output=True, text=True, timeout=RUN_SECONDS)

    def pushed(self):
        """The push request config handed to curl (the last stdin config that contains the secret)."""
        text = (self.dir / 'curl-stdin').read_text()
        lines = [l for l in text.splitlines() if SECRET in l]
        self.assertEqual(len(lines), 1, text)
        return lines[0]

    def assert_status(self, result, status, msg):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.pushed(), f'url = "{SECRET}?status={status}&msg={msg}"')

    def test_all_good(self):
        self.assert_status(self.run_hb(), 'up', 'ok')

    def test_all_good_with_health(self):
        result = self.run_hb(health=True)
        self.assert_status(result, 'up', 'ok')
        self.assertIn(HEALTH, (self.dir / 'curl-stdin').read_text())

    def test_service_disabled(self):
        self.assert_status(self.run_hb(STUB_DISABLED='couvrefeu'), 'down', 'service-disabled')

    def test_agent_unit_disabled(self):
        self.assert_status(self.run_hb(STUB_DISABLED='couvrefeu-agent'), 'down', 'service-disabled')

    def test_service_inactive(self):
        self.assert_status(self.run_hb(STUB_INACTIVE='couvrefeu'), 'down', 'service-down')

    def test_agent_empty(self):
        self.assert_status(self.run_hb(STUB_AGENT_EMPTY='1'), 'down', 'agent-empty')
        self.assertEqual((self.dir / 'ssh-add-sock').read_text().strip(), '/run/couvrefeu/agent.sock')

    def test_health_failures(self):
        for extra in ({'STUB_HEALTH_FAIL': '1'}, {'STUB_HEALTH_CODE': '503'}, {'STUB_HEALTH_BODY': '{"ok":false}'},
                      {'STUB_HEALTH_BODY': 'not json'}):
            (self.dir / 'curl-stdin').unlink(missing_ok=True)
            with self.subTest(extra):
                self.assert_status(self.run_hb(health=True, **extra), 'down', 'health-failed')

    def test_health_ignored_when_not_configured(self):
        self.assert_status(self.run_hb(STUB_HEALTH_FAIL='1', STUB_HEALTH_CODE='500'), 'up', 'ok')
        self.assertNotIn('app.example', (self.dir / 'curl-stdin').read_text())

    def test_url_never_in_any_argv_or_output(self):
        result = self.run_hb(health=True)
        argv = (self.dir / 'curl-argv').read_text()
        self.assertIn('-K -', argv)
        for call in argv.splitlines():
            self.assertIn('-m 10', call)
        for fragment in ('SECRETTOKEN', 'monitor.example', '/health', 'app.example'):
            self.assertNotIn(fragment, argv)
        self.assertNotIn('SECRETTOKEN', result.stdout + result.stderr)

    def test_msg_token_charset_and_fixed_set(self):
        seen = set()
        for extra in ({}, {'STUB_DISABLED': 'couvrefeu'}, {'STUB_INACTIVE': 'couvrefeu'}, {'STUB_AGENT_EMPTY': '1'},
                      {'STUB_HEALTH_FAIL': '1'}):
            (self.dir / 'curl-stdin').unlink(missing_ok=True)
            self.run_hb(health=bool(extra.get('STUB_HEALTH_FAIL')), **extra)
            m = re.fullmatch(r'url = "' + re.escape(SECRET) + r'\?status=(up|down)&msg=([A-Za-z0-9_.-]+)"', self.pushed())
            self.assertIsNotNone(m)
            seen.add(m.group(2))
        self.assertEqual(seen, {'ok', 'service-disabled', 'service-down', 'agent-empty', 'health-failed'})

    def test_missing_url_file_logs_and_fails_without_calling_curl(self):
        result = self.run_hb(url_file=self.dir / 'absent')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('status=up', result.stdout + result.stderr)
        self.assertIn('missing', result.stderr)
        self.assertFalse((self.dir / 'curl-argv').exists())

    def test_empty_or_unsafe_url_file_is_refused(self):
        for content in ('', '\n', 'https://x.example.invalid/p"\nheader = "X: y', 'https://x.example.invalid/p q'):
            with self.subTest(content=content):
                self.url_file.write_text(content)
                result = self.run_hb()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.dir / 'curl-argv').exists())

    def test_push_failure_is_nonzero_and_logs_curl_exit_code_only(self):
        result = self.run_hb(STUB_PUSH_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('rc=22', result.stderr)
        self.assertNotIn('SECRETTOKEN', result.stdout + result.stderr)

    def test_url_file_symlink_is_refused(self):
        link = self.dir / 'link'
        link.symlink_to(self.url_file)
        result = self.run_hb(url_file=link)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)
        self.assertFalse((self.dir / 'curl-argv').exists())

    def test_url_file_must_be_root_owned_0600(self):
        for stat in ('1000:600', '0:644', '0:640', '0:700', '0:666'):
            with self.subTest(stat=stat):
                result = self.run_hb(STUB_STAT=stat)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('0600', result.stderr)
                self.assertFalse((self.dir / 'curl-argv').exists())

    def test_ssh_add_has_a_timeout(self):
        self.run_hb()
        self.assertEqual((self.dir / 'timeout-argv').read_text().strip(), '10 ssh-add -l')

    def test_curl_ignores_curlrc_and_pins_protocols(self):
        self.run_hb(health=True)
        calls = (self.dir / 'curl-argv').read_text().splitlines()
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertTrue(call.startswith('-q '), call)
            self.assertIn('--proto =https', call)
            self.assertIn('--proto-redir =https', call)
        health = [c for c in calls if '--max-filesize 65536' in c]
        self.assertEqual(len(health), 1)

    def test_push_url_scheme_allowlist(self):
        for url in ('file:///etc/shadow', 'ftp://monitor.example.invalid/p', 'http://monitor.example.invalid/p',
                    'gopher://monitor.example.invalid/p', 'https://', '//monitor.example.invalid/p'):
            with self.subTest(url=url):
                self.url_file.write_text(url + '\n')
                (self.dir / 'curl-argv').unlink(missing_ok=True)
                self.assertNotEqual(self.run_hb().returncode, 0)
                self.assertFalse((self.dir / 'curl-argv').exists())
        self.url_file.write_text(SECRET + '\n')
        self.assertEqual(self.run_hb().returncode, 0)

    def test_plain_http_only_with_explicit_flag(self):
        self.url_file.write_text('http://monitor.example.invalid/push/SECRETTOKEN123\n')
        self.assertNotEqual(self.run_hb().returncode, 0)
        result = self.run_hb(HEARTBEAT_ALLOW_HTTP='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        call = (self.dir / 'curl-argv').read_text()
        self.assertIn('--proto =http,https', call)
        self.assertIn('--proto-redir =http,https', call)

    def test_health_url_is_validated_before_it_reaches_curl(self):
        for url in ('https://app.example.invalid/health" \nheader = "X: y', 'https://app.example.invalid/a b',
                    'https://app.example.invalid/h"', 'file:///etc/passwd', 'ftp://app.example.invalid/h',
                    'http://app.example.invalid/health', 'https://app.example.invalid/\\n'):
            with self.subTest(url=url):
                (self.dir / 'curl-stdin').unlink(missing_ok=True)
                result = subprocess.run(['sh', str(self.script)], env={
                    'PATH': f'{self.bin}:/usr/bin:/bin', 'STUB_DIR': str(self.dir), 'STUB_HEALTH_MARK': 'app.example',
                    'HEARTBEAT_URL_FILE': str(self.url_file), 'HEARTBEAT_HEALTH_URL': url}, capture_output=True, text=True, timeout=RUN_SECONDS)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.pushed(), f'url = "{SECRET}?status=down&msg=health-failed"')
                self.assertNotIn('header', (self.dir / 'curl-stdin').read_text())

    def test_plain_http_health_allowed_with_flag(self):
        result = self.run_hb(HEARTBEAT_ALLOW_HTTP='1', HEARTBEAT_HEALTH_URL='http://app.example.invalid:4273/health')
        self.assert_status(result, 'up', 'ok')

    def test_idempotent(self):
        first = self.run_hb()
        (self.dir / 'curl-stdin').unlink()
        second = self.run_hb()
        self.assertEqual((first.returncode, first.stdout), (second.returncode, second.stdout))
        self.assert_status(second, 'up', 'ok')

    def test_script_has_no_inline_credentials_and_is_posix(self):
        text = SCRIPT.read_text()
        self.assertTrue(text.startswith('#!/bin/sh\n'))
        self.assertNotIn('bash', text)
        self.assertNotRegex(text, r'curl[^\n|]*\$\{?URL')


if __name__ == '__main__':
    unittest.main()
