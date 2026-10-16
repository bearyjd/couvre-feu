#!/usr/bin/env python3
"""OpenWrt has no /dev/stdin and BusyBox awk opens operands literally.

gawk and CI runners provide /dev/stdin, which hid the bug. These fixtures put an awk
on PATH that rejects /dev/std* and /dev/fd/* operands the way the router does.
"""
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
from harness import REPO, RouterFixture  # noqa: E402

GUARD = '''#!/bin/sh
for arg do
    case $arg in
    /dev/std*|/dev/fd/*|/proc/self/fd/*)
        printf 'awk: %s: No such file or directory\\n' "$arg" >&2; exit 2;;
    esac
done
exec {real} "$@"
'''


def guard_dir(name):
    """A /tmp/<dir> holding `busybox` (CF_TEST_AWK seam) that acts as the strict awk."""
    directory = Path(tempfile.mkdtemp(prefix='cf-nostdin-', dir='/tmp'))
    wrapper = directory / name
    wrapper.write_text(GUARD.replace('{real}', shutil.which('awk')))
    wrapper.chmod(0o700)
    return directory, wrapper


class NoDevStdinTests(unittest.TestCase):
    def test_static_no_dev_fd_operands(self):
        pattern = re.compile(r'/dev/(stdin|fd)|/proc/self/fd')
        # Live tools run the same router shell remotely, so their scripts are in scope too.
        files = [p for p in sorted((REPO / 'router').rglob('*')) if p.is_file()] + sorted((REPO / 'tools/live').glob('*.sh'))
        self.assertIn(REPO / 'tools/live/penn-pilot.sh', files)
        hits = [f'{p.relative_to(REPO)}:{n}' for p in files
                for n, line in enumerate(p.read_text(errors='replace').splitlines(), 1) if pattern.search(line)]
        self.assertEqual(hits, [])

    def test_static_no_dev_stderr_in_awk(self):
        hits = [str(p.relative_to(REPO)) for p in sorted((REPO / 'router/lib').glob('*.awk')) if '/dev/std' in p.read_text()]
        self.assertEqual(hits, [])

    def fixture(self):
        directory, wrapper = guard_dir('busybox')
        # CF_TEST_AWK seam runs `<busybox> awk ...`; drop the applet name.
        wrapper.write_text(wrapper.read_text().replace('for arg do', 'shift\nfor arg do', 1))
        self.addCleanup(shutil.rmtree, directory, True)
        os.environ['CF_TEST_AWK'] = f'{wrapper} awk'
        self.addCleanup(os.environ.pop, 'CF_TEST_AWK', None)
        fixture = RouterFixture()
        self.addCleanup(fixture.close)
        return fixture

    def test_guard_rejects_dev_stdin(self):
        directory, wrapper = guard_dir('awk')
        self.addCleanup(shutil.rmtree, directory, True)
        result = subprocess.run([str(wrapper), '{print}', '/dev/stdin'], input='x\n', capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('No such file or directory', result.stderr)

    def test_status_on_empty_state(self):
        result = self.fixture().run('status', '--json')
        self.assertNotIn('invalid_state', result.stdout + result.stderr)
        self.assertNotIn('No such file', result.stdout + result.stderr)

    def test_rpc_status_on_empty_state(self):
        result = self.fixture().run('rpc-status', '--json')
        self.assertNotIn('No such file', result.stdout + result.stderr)
        self.assertNotEqual(json.loads(result.stdout).get('policy', 1), None)

    def test_install_stage_validation(self):
        directory, wrapper = guard_dir('awk')
        self.addCleanup(shutil.rmtree, directory, True)
        root = Path(tempfile.mkdtemp(prefix='couvre-feu-install-'))
        self.addCleanup(shutil.rmtree, root, True)
        env = dict(os.environ, CF_TEST_MODE='1', CF_ROOT=str(root), PATH=f'{directory}:{os.environ["PATH"]}')
        env.pop('SSH_CONNECTION', None)
        env.pop('SSH_CLIENT', None)
        result = subprocess.run(['sh', str(REPO / 'router/install.sh'), '--source-dir', str(REPO / 'router'),
                                 '--protect', '02:00:00:00:00:01', '--rpc-allow', '02:00:00:00:00:02'], env=env, capture_output=True, text=True)
        self.assertNotIn('No such file', result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
