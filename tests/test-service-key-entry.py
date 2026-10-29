#!/usr/bin/env python3
# timeout-ok-file: measured: cfctl-ssh shell runs <0.15 s against 5-10 s limits (load 21-22)
"""Offline checks of the service authorized_keys template and the --rpc-only forced-command boundary.

Static and fixture-only: no SSH, Dropbear, router or key material is used, and nothing here proves
that a real Dropbear enforces any option. The README line is parsed as-is; the service argv is asserted in
service/tests/ssh-router.test.ts.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / 'fixtures'))
from harness import REPO, RouterFixture

FIXED_OPTIONS = ['command="/usr/sbin/cfctl-ssh --rpc-only"', 'restrict', 'no-port-forwarding', 'no-agent-forwarding',
                 'no-X11-forwarding', 'no-pty']
LABEL = 'couvrefeu-service'
KEY_TYPES = r'(?:ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)'


def split_options(text):
    """Split an authorized_keys option list on commas outside double quotes."""
    options, current, quoted = [], '', False
    for char in text:
        if char == '"':
            quoted = not quoted
        if char == ',' and not quoted:
            options.append(current)
            current = ''
        else:
            current += char
    if quoted:
        raise ValueError('unterminated quote')
    options.append(current)
    return options


def readme_entry_lines():
    return [line for line in (REPO / 'README.md').read_text().splitlines() if line.startswith('command="/usr/sbin/cfctl-ssh')]


class TemplateTests(unittest.TestCase):
    def parsed(self):
        lines = readme_entry_lines()
        self.assertEqual(len(lines), 1, lines)
        match = re.fullmatch(r'((?:[^\s"]|"[^"]*")+) (ssh-ed25519) (<PUBLIC_KEY_BLOB>) (\S+)', lines[0])
        self.assertIsNotNone(match, lines[0])
        return split_options(match.group(1)), match.group(2), match.group(3), match.group(4)

    def test_readme_line_option_set_order_and_key_slot(self):
        options, key_type, blob, label = self.parsed()
        self.assertEqual(options[:-1], FIXED_OPTIONS)
        self.assertEqual(options[0], FIXED_OPTIONS[0])
        self.assertIn('restrict', options)
        for explicit in ('no-port-forwarding', 'no-agent-forwarding', 'no-X11-forwarding', 'no-pty'):
            self.assertIn(explicit, options)
        self.assertEqual((key_type, blob, label), ('ssh-ed25519', '<PUBLIC_KEY_BLOB>', LABEL))

    def test_from_option_is_last_and_a_single_host_not_a_wildcard(self):
        options, *_ = self.parsed()
        self.assertEqual(len(options), len(FIXED_OPTIONS) + 1)
        match = re.fullmatch(r'from="([^"]*)"', options[-1])
        self.assertIsNotNone(match, options[-1])
        value = match.group(1)
        self.assertEqual(sum(1 for o in options if o.startswith('from=')), 1)
        for bad in '*?/,!':
            self.assertNotIn(bad, value)
        self.assertNotEqual(value, '0.0.0.0')
        octets = value.split('.')
        self.assertEqual(len(octets), 4, value)
        self.assertTrue(all(o.isdigit() and 0 <= int(o) <= 255 for o in octets), value)

    def test_no_real_key_material_in_docs_or_template(self):
        paths = [REPO / 'README.md', *sorted((REPO / 'docs').rglob('*.md'))]
        for path in paths:
            text = path.read_text()
            with self.subTest(path=str(path)):
                self.assertIsNone(re.search(KEY_TYPES + r' AAAA[A-Za-z0-9+/=]{20,}', text))
                self.assertNotIn('-----BEGIN OPENSSH PRIVATE KEY-----', text)
                self.assertNotIn('-----BEGIN RSA PRIVATE KEY-----', text)


class RpcOnlyWrapperTests(unittest.TestCase):
    OPERATION_IDS = ('op_1', 'a', 'a-b_c', '0', 'x' * 64)

    def setUp(self):
        self.fixture = RouterFixture()
        self.log = self.fixture.root / 'wrapper.json'
        fake = self.fixture.bin / 'cfctl'
        fake.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                        + 'open(' + repr(str(self.log)) + ",'w').write(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ)}))\n"
                        + "print('{\"ok\":true}')\n")
        fake.chmod(0o700)

    def tearDown(self):
        self.fixture.close()

    def run_wrapper(self, command, *flags):
        environment = dict(self.fixture.env, SSH_ORIGINAL_COMMAND=command)
        return subprocess.run(self.fixture.shell + [str(REPO / 'router/cfctl-ssh'), *flags],
                              env=environment, text=True, capture_output=True, timeout=5)

    def service_commands(self):
        commands = ['cfctl rpc-sync', 'cfctl rpc-activity --json', 'cfctl rpc-inventory --json', 'cfctl rpc-status --json']
        return commands + ['cfctl rpc-status --json ' + op for op in self.OPERATION_IDS]

    def test_every_service_command_is_admitted_with_rpc_only(self):
        for command in self.service_commands():
            with self.subTest(command=command):
                self.log.unlink(missing_ok=True)
                result = self.run_wrapper(command, '--rpc-only')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(self.log.read_text())['argv'], command.split(' ')[1:])

    def test_legacy_shell_and_pty_style_strings_rejected(self):
        legacy = ('cfctl status --json', 'cfctl sync', 'cfctl pause alice', 'cfctl pause alice --until 1736204500',
                  'cfctl resume alice', 'cfctl expire', 'cfctl activity --json', 'cfctl apply-fw',
                  'cfctl remove-fw', 'cfctl check')
        shells = ('', 'sh', 'bash -i', '/bin/sh', 'sh -c id', 'login', 'internal-sftp', 'scp -t /tmp', 'id',
                  '/usr/sbin/cfctl rpc-sync', 'cfctl', 'cfctl rpc-sync extra', 'cfctl rpc-sync; id',
                  'cfctl rpc-sync && id', 'cfctl rpc-sync | cat', 'cfctl rpc-sync > /tmp/x', 'cfctl rpc-sync\nid',
                  'cfctl rpc-sync $(id)', 'cfctl rpc-sync `id`', 'cfctl rpc-status --json $(id)',
                  'cfctl rpc-status --json op_1;id', 'cfctl rpc-status --json op_1 extra', 'cfctl rpc-status',
                  'cfctl rpc-status --json -', 'cfctl rpc-status --json -x', 'cfctl rpc-status --json --',
                  'cfctl rpc-status --json --json', 'cfctl rpc-status --json _x', 'cfctl rpc-status --json UPPER', 'cfctl rpc-status --json ../x',
                  'cfctl rpc-status --json ' + 'x' * 65, 'cfctl rpc-activity', 'cfctl rpc-activity --json op_1',
                  "cfctl rpc-sync 'x'", 'CFCTL rpc-sync', 'cfctl rpc-sync ' + 'x' * 200,
                  'cfctl rpc-status op_1', 'cfctl rpc-status --json -', 'foo rpc-sync', 'sh rpc-sync', 'rpc-sync rpc-sync',
                  'x rpc-activity --json', 'rpc-status --json op_1', 'rpc-sync', 'rpc-activity --json',
                  'cfctl rpc-inventory', 'cfctl rpc-inventory --json op_1', 'rpc-inventory --json')
        for command in legacy + shells:
            with self.subTest(command=command):
                self.log.unlink(missing_ok=True)
                result = self.run_wrapper(command, '--rpc-only')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.log.exists())

    def test_wrapper_flag_forms_other_than_rpc_only_rejected(self):
        for flags in (('--rpc-only', 'extra'), ('--rpc', ), ('rpc-only',), ('-s',)):
            with self.subTest(flags=flags):
                self.log.unlink(missing_ok=True)
                result = self.run_wrapper('cfctl rpc-sync', *flags)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.log.exists())

    def test_missing_original_command_is_an_interactive_shell_request(self):
        self.log.unlink(missing_ok=True)
        environment = {key: value for key, value in self.fixture.env.items() if key != 'SSH_ORIGINAL_COMMAND'}
        result = subprocess.run(self.fixture.shell + [str(REPO / 'router/cfctl-ssh'), '--rpc-only'],
                                env=environment, text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_child_runs_under_env_i_keeping_only_ssh_connection_and_client(self):
        self.log.unlink(missing_ok=True)
        environment = dict(self.fixture.env, SSH_ORIGINAL_COMMAND='cfctl rpc-sync', CF_INHERITED_PROBE='leak',
                           SSH_CONNECTION='192.0.2.1 1 192.0.2.2 22', SSH_CLIENT='192.0.2.1 1 22', ENV='/x', BASH_ENV='/x')
        result = subprocess.run(self.fixture.shell + [str(REPO / 'router/cfctl-ssh'), '--rpc-only'],
                                env=environment, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        child = json.loads(self.log.read_text())['env']
        for name in ('CF_INHERITED_PROBE', 'CF_TEST_MODE', 'CF_ROOT', 'CF_BACKEND_DIR', 'ENV', 'BASH_ENV', 'HOME'):
            self.assertNotIn(name, child)
        self.assertEqual(child['SSH_CONNECTION'], '192.0.2.1 1 192.0.2.2 22')
        self.assertEqual(child['SSH_CLIENT'], '192.0.2.1 1 22')
        self.assertEqual(child['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')

    def test_test_mode_requires_marked_private_root(self):
        marker = self.fixture.bin / '.couvrefeu-test-backend'
        outside = self.fixture.root.parent / 'not-a-couvre-feu-root'
        cases = {'root_not_marked_prefix': dict(CF_ROOT=str(outside)),
                 'backend_outside_root': dict(CF_BACKEND_DIR=str(outside / 'bin')),
                 'root_unset': dict(CF_ROOT=''),
                 'backend_unset': dict(CF_BACKEND_DIR='')}
        for name, override in cases.items():
            with self.subTest(case=name):
                self.log.unlink(missing_ok=True)
                environment = dict(self.fixture.env, SSH_ORIGINAL_COMMAND='cfctl rpc-sync', **override)
                result = subprocess.run(self.fixture.shell + [str(REPO / 'router/cfctl-ssh'), '--rpc-only'],
                                        env=environment, text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.log.exists())
        with self.subTest(case='marker_missing'):
            self.log.unlink(missing_ok=True)
            marker.rename(marker.with_name('.renamed'))
            result = self.run_wrapper('cfctl rpc-sync', '--rpc-only')
            self.assertEqual(result.returncode, 2)
            self.assertFalse(self.log.exists())

    def test_operation_id_must_start_alphanumeric(self):
        for operation in ('-x', '--', '--json', '-', '-a-b', '--rpc-only', '_x'):
            with self.subTest(rejected=operation):
                self.log.unlink(missing_ok=True)
                result = self.run_wrapper('cfctl rpc-status --json ' + operation, '--rpc-only')
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.log.exists())
        for operation in ('op_1', 'a-b_1'):
            with self.subTest(accepted=operation):
                self.log.unlink(missing_ok=True)
                result = self.run_wrapper('cfctl rpc-status --json ' + operation, '--rpc-only')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(self.log.read_text())['argv'], ['rpc-status', '--json', operation])


class StrippedProductionCopyTests(unittest.TestCase):
    """The installed router copy has no CF_TEST_MODE branch; it differs from the repo file only by that block."""

    def setUp(self):
        self.fixture = RouterFixture()
        self.stripped = self.fixture.root / 'cfctl-ssh-stripped'
        tool = REPO / 'tools/strip-test-mode.py'
        result = subprocess.run([sys.executable, '-I', str(tool), str(self.stripped)], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.digest = result.stdout.strip()
        self.log = self.fixture.root / 'wrapper.json'
        fake = self.fixture.bin / 'cfctl'
        fake.write_text('#!' + sys.executable + '\nopen(' + repr(str(self.log)) + ",'w').write('ran')\n")
        fake.chmod(0o700)

    def tearDown(self):
        self.fixture.close()

    def run_stripped(self, command, env=None):
        environment = dict(self.fixture.env if env is None else env, SSH_ORIGINAL_COMMAND=command)
        return subprocess.run(self.fixture.shell + [str(self.stripped), '--rpc-only'],
                              env=environment, text=True, capture_output=True, timeout=5)

    def test_digest_is_deterministic_and_matches_file(self):
        self.assertEqual(self.digest, hashlib.sha256(self.stripped.read_bytes()).hexdigest())
        again = self.fixture.root / 'again'
        subprocess.run([sys.executable, '-I', str(REPO / 'tools/strip-test-mode.py'), str(again)], check=True, capture_output=True)
        self.assertEqual(again.read_bytes(), self.stripped.read_bytes())

    def test_differs_from_repo_file_only_by_the_test_mode_block(self):
        original = (REPO / 'router/cfctl-ssh').read_text().splitlines(keepends=True)
        stripped = self.stripped.read_text().splitlines(keepends=True)
        self.assertEqual(len(original) - len(stripped), 9)
        index = next(i for i, line in enumerate(original) if line.startswith('# The grammar fixture'))
        self.assertEqual(original[:index] + original[index + 9:], stripped)
        self.assertNotIn('CF_TEST_MODE', self.stripped.read_text())
        self.assertEqual(subprocess.run(['sh', '-n', str(self.stripped)]).returncode, 0)

    def test_grammar_unchanged_without_test_mode(self):
        if Path('/usr/sbin/cfctl').exists():
            self.skipTest('host has /usr/sbin/cfctl; not executing it')
        plain = {key: value for key, value in self.fixture.env.items() if not key.startswith('CF_')}
        accepted = ['cfctl rpc-sync', 'cfctl rpc-activity --json', 'cfctl rpc-inventory --json', 'cfctl rpc-status --json', 'cfctl rpc-status --json op_1']
        rejected = ['cfctl status --json', 'cfctl rpc-sync; id', 'cfctl rpc-status --json -x', 'cfctl rpc-status --json --json', 'sh', '']
        for command in accepted:
            with self.subTest(accepted=command):
                self.assertNotEqual(self.run_stripped(command, plain).returncode, 2)
        for command in rejected:
            with self.subTest(rejected=command):
                self.assertEqual(self.run_stripped(command, plain).returncode, 2)
        self.assertFalse(self.log.exists())

    def test_cf_test_mode_environment_cannot_redirect_the_backend(self):
        if Path('/usr/sbin/cfctl').exists():
            self.skipTest('host has /usr/sbin/cfctl; not executing it')
        self.assertEqual(self.fixture.env.get('CF_TEST_MODE'), '1')
        self.run_stripped('cfctl rpc-sync')
        self.assertFalse(self.log.exists())


class EmittedReleaseTreeTests(unittest.TestCase):
    """freeze-router-release.py --emit writes the shippable tree: wrappers stripped, manifest over emitted bytes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / 'tree'
        cls.result = subprocess.run([sys.executable, '-I', str(REPO / 'tools/freeze-router-release.py'), '--emit', str(cls.out)],
                                    text=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_emit_succeeds(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr)

    def test_wrappers_equal_strip_of_repo_without_test_mode(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr)
        spec = importlib.util.spec_from_file_location('strip_test_mode', REPO / 'tools/strip-test-mode.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in ('cfctl-ssh', 'cfctl-scope'):
            with self.subTest(name=name):
                emitted = (self.out / name).read_text()
                self.assertEqual(emitted, module.strip((REPO / 'router' / name).read_text(), module.BLOCK_LINES[name]))
                self.assertNotIn('CF_TEST_MODE', emitted)
                self.assertIn('CF_TEST_MODE', (REPO / 'router' / name).read_text())

    def test_manifest_hashes_emitted_bytes(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr)
        lines = (self.out / 'release.sha256').read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split('  ')
            self.assertEqual(digest, hashlib.sha256((self.out / name).read_bytes()).hexdigest(), name)
        self.assertEqual((self.out / 'release.sha256').read_bytes(), (REPO / 'router/release.sha256').read_bytes())

    def test_release_id_covers_boundary_files(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr)
        text = (self.out / 'lib/platform-bootstrap.sh').read_text()
        release_id = re.search(r'^CF_RELEASE_ID=(\w+)$', text, re.M).group(1)
        modules = re.search(r"^CF_RELEASE_MODULES='(.*)'$", text, re.M).group(1).split()
        self.assertTrue(all(pair.split(':')[0].endswith(('.sh', '.awk')) for pair in modules), modules)
        self.assertEqual(self.result.stdout.strip(), release_id)
        # Independent version 2 oracle: explicit domain and path order, normalized generated fields.
        entries = ['couvrefeu-router-release-v2'] + ['lib/' + pair for pair in modules]
        for name in ('cfctl', 'cfctl-ssh', 'cfctl-scope', 'install.sh', 'uninstall.sh', 'lib/platform-bootstrap.sh'):
            data = (self.out / name).read_bytes()
            if name in ('cfctl', 'install.sh', 'uninstall.sh'):
                data = re.sub(rb'^CF_BOOTSTRAP_PIN=.*$', b'CF_BOOTSTRAP_PIN=', data, flags=re.M)
            elif name == 'lib/platform-bootstrap.sh':
                data = re.sub(rb'^CF_RELEASE_ID=.*$', b'CF_RELEASE_ID=', data, flags=re.M)
                data = re.sub(rb'^CF_RELEASE_MODULES=.*$', b'CF_RELEASE_MODULES=', data, flags=re.M)
            entries.append(name + ':' + hashlib.sha256(data).hexdigest())
        self.assertEqual(hashlib.sha256(('\n'.join(entries) + '\n').encode()).hexdigest(), release_id)

    def test_release_id_changes_when_a_wrapper_changes(self):
        with ScratchRepo() as scratch:
            base = scratch.run().stdout.strip()
            self.assertEqual(base, self.result.stdout.strip())
            for name in ('cfctl-scope', 'cfctl-ssh', 'cfctl'):
                with self.subTest(name=name):
                    scratch.append(f'router/{name}', '# perturbation\n')
                    changed = scratch.run()
                    self.assertEqual(changed.returncode, 0, changed.stderr)
                    self.assertNotEqual(changed.stdout.strip(), base)
                    scratch.restore(f'router/{name}')

    def test_emitted_modes_match_what_install_expects(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr)
        mode = lambda path: stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode(self.out), 0o700)
        self.assertEqual(mode(self.out / 'lib'), 0o700)
        for name in ('install.sh', 'uninstall.sh', 'cfctl', 'cfctl-ssh', 'cfctl-scope'):
            self.assertEqual(mode(self.out / name), 0o755, name)
        for path in sorted((self.out / 'lib').iterdir()):
            self.assertEqual(mode(path), 0o644, path.name)
        self.assertEqual(mode(self.out / 'release.sha256'), 0o600)


class ScratchRepo:
    """A throwaway copy of the files freeze-router-release.py reads, so drift can be injected safely."""

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'repo'
        shutil.copytree(REPO / 'router', self.root / 'router')
        (self.root / 'tools').mkdir()
        for name in ('freeze-router-release.py', 'strip-test-mode.py'):
            shutil.copyfile(REPO / 'tools' / name, self.root / 'tools' / name)
        self.originals = {}
        return self

    def __exit__(self, *exc):
        self.tmp.cleanup()

    def append(self, rel, text):
        path = self.root / rel
        self.originals.setdefault(rel, path.read_bytes())
        path.write_bytes(path.read_bytes() + text.encode())

    def replace(self, rel, old, new):
        path = self.root / rel
        self.originals.setdefault(rel, path.read_bytes())
        data = path.read_bytes()
        assert old in data
        path.write_bytes(data.replace(old, new, 1))

    def restore(self, rel):
        (self.root / rel).write_bytes(self.originals.pop(rel))

    def run(self, *args):
        return subprocess.run([sys.executable, '-I', str(self.root / 'tools/freeze-router-release.py'), *args],
                              text=True, capture_output=True, timeout=30)

    def siblings(self):
        return sorted(p.name for p in self.tmp_path().iterdir())

    def tmp_path(self):
        return Path(self.tmp.name)


class FreezeScriptRefusalTests(unittest.TestCase):
    def assert_refused(self, result, needle, out):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('refused: ', result.stderr)
        self.assertIn(needle, result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse(out.exists())

    def test_emit_refuses_when_router_not_frozen(self):
        with ScratchRepo() as scratch:
            scratch.append('router/lib/core.sh', '# drift\n')
            out = scratch.tmp_path() / 'tree'
            self.assert_refused(scratch.run('--emit', str(out)), 'router not frozen', out)
            self.assertEqual(scratch.siblings(), ['repo'])
            self.assertEqual(scratch.run('--check').returncode, 1)

    def test_emit_refuses_when_a_wrapper_drifts_from_the_manifest(self):
        with ScratchRepo() as scratch:
            scratch.append('router/cfctl-scope', '# drift\n')
            out = scratch.tmp_path() / 'tree'
            self.assert_refused(scratch.run('--emit', str(out)), 'router not frozen', out)

    def test_emit_to_existing_directory_is_refused_cleanly(self):
        with ScratchRepo() as scratch:
            out = scratch.tmp_path() / 'tree'
            out.mkdir()
            result = scratch.run('--emit', str(out))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('refused: ', result.stderr)
            self.assertNotIn('Traceback', result.stderr)
            self.assertEqual(list(out.iterdir()), [])

    def test_emit_with_missing_parent_is_refused_cleanly(self):
        with ScratchRepo() as scratch:
            out = scratch.tmp_path() / 'no-such-parent' / 'tree'
            self.assert_refused(scratch.run('--emit', str(out)), '', out)

    def test_emit_and_check_cannot_be_combined(self):
        with ScratchRepo() as scratch:
            for args in (('--emit', str(scratch.tmp_path() / 't'), '--check'), ('--check', '--emit', str(scratch.tmp_path() / 't'))):
                with self.subTest(args=args):
                    result = scratch.run(*args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('usage', result.stderr)
                    self.assertFalse((scratch.tmp_path() / 't').exists())

    def test_stripped_wrapper_must_pass_sh_n(self):
        with ScratchRepo() as scratch:
            scratch.append('router/cfctl-ssh', 'fi )\n')
            out = scratch.tmp_path() / 'tree'
            self.assert_refused(scratch.run('--emit', str(out)), 'sh -n', out)

    def test_cfctl_needs_exactly_one_bootstrap_pin_line(self):
        for label, edit in (('duplicate', lambda s: s.append('router/cfctl', 'CF_BOOTSTRAP_PIN=' + '0' * 64 + '\n')),
                            ('malformed', lambda s: s.replace('router/cfctl', b'CF_BOOTSTRAP_PIN=', b'CF_BOOTSTRAP_PIN=Z')),
                            ('missing', lambda s: s.replace('router/cfctl', b'\nCF_BOOTSTRAP_PIN=', b'\nCF_BOOTSTRAP_PINX='))):
            with self.subTest(label), ScratchRepo() as scratch:
                edit(scratch)
                out = scratch.tmp_path() / 'tree'
                self.assert_refused(scratch.run('--emit', str(out)), 'CF_BOOTSTRAP_PIN', out)


class VersionedReleaseIdentityTests(unittest.TestCase):
    def test_valid_generated_values_are_normalized_and_freezing_is_idempotent(self):
        with ScratchRepo() as scratch:
            first = scratch.run()
            self.assertEqual(first.returncode, 0, first.stderr)
            frozen = {str(p): p.read_bytes() for p in (scratch.root / 'router').rglob('*') if p.is_file()}
            for rel in ('install.sh', 'uninstall.sh', 'cfctl'):
                path = scratch.root / 'router' / rel
                path.write_bytes(re.sub(rb'(?m)^CF_BOOTSTRAP_PIN=.*$', b'CF_BOOTSTRAP_PIN=' + b'0' * 64, path.read_bytes()))
            path = scratch.root / 'router/lib/platform-bootstrap.sh'
            data = re.sub(rb'(?m)^CF_RELEASE_ID=.*$', b'CF_RELEASE_ID=' + b'1' * 64, path.read_bytes())
            data = re.sub(rb'(?<=:)[0-9a-f]{64}', b'2' * 64, data, count=9)
            path.write_bytes(data)
            second = scratch.run()
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(second.stdout, first.stdout)
            self.assertEqual(frozen, {str(p): p.read_bytes() for p in (scratch.root / 'router').rglob('*') if p.is_file()})
            self.assertEqual(scratch.run('--check').returncode, 0)

    def test_every_shipped_source_changes_identity(self):
        with ScratchRepo() as scratch:
            first = scratch.run()
            self.assertEqual(first.returncode, 0, first.stderr)
            baseline = first.stdout.strip()
            paths = ['install.sh', 'uninstall.sh', 'cfctl', 'cfctl-ssh', 'cfctl-scope']
            paths += [str(path.relative_to(scratch.root / 'router'))
                      for path in sorted((scratch.root / 'router/lib').iterdir()) if path.is_file()]
            for rel in paths:
                with self.subTest(rel=rel):
                    scratch.append('router/' + rel, '# identity perturbation\n')
                    changed = scratch.run()
                    self.assertEqual(changed.returncode, 0, changed.stderr)
                    self.assertNotEqual(changed.stdout.strip(), baseline, rel)
                    scratch.restore('router/' + rel)
                    self.assertEqual(scratch.run().stdout.strip(), baseline)

    def test_generated_fields_are_strict_before_any_write(self):
        fields = [(name, 'CF_BOOTSTRAP_PIN') for name in ('install.sh', 'uninstall.sh', 'cfctl')]
        fields += [('lib/platform-bootstrap.sh', field) for field in ('CF_RELEASE_ID', 'CF_RELEASE_MODULES')]
        for rel, field in fields:
            for defect in ('duplicate', 'missing', 'malformed', 'malformed-duplicate',
                           'readonly ', 'export ', 'readonly -- ', 'export -- ',
                           'readonly OTHER=value ', 'export OTHER=value ', 'readonly "', "export '"):
                with self.subTest(rel=rel, field=field, defect=defect), ScratchRepo() as scratch:
                    path = scratch.root / 'router' / rel
                    original = path.read_bytes()
                    match = re.search(rb'(?m)^' + field.encode() + rb'=.*$', original)
                    self.assertIsNotNone(match)
                    if defect == 'duplicate':
                        changed = original + match[0] + b'\n'
                    elif defect == 'missing':
                        changed = original[:match.start()] + original[match.end() + 1:]
                    elif defect == 'malformed':
                        changed = original.replace(match[0], field.encode() + b'=invalid', 1)
                    elif defect == 'malformed-duplicate':
                        changed = original + field.encode() + b'=invalid\n'
                    else:
                        suffix = defect[-1] if defect[-1] in ('"', "'") else ''
                        changed = original + (defect + field + '=invalid' + suffix + '\n').encode()
                    path.write_bytes(changed)
                    before = {str(p): p.read_bytes() for p in (scratch.root / 'router').rglob('*') if p.is_file()}
                    result = scratch.run()
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn('refused:', result.stderr)
                    self.assertIn(field, result.stderr)
                    self.assertEqual(before, {str(p): p.read_bytes() for p in (scratch.root / 'router').rglob('*') if p.is_file()})


if __name__ == '__main__':
    unittest.main()
