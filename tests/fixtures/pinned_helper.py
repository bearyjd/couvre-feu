"""Host-architecture substitution ONLY in disposable test source trees.

Production has no helper override: this rewrites reviewed source constants, then
runs the ordinary freeze tool. The shippable router bytes retain the aarch64 pin.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

PRODUCTION_HELPER_SHA256 = 'c25f66e5ac29ea3e373b8fb2d3549a59d058fbef9ed11b67fdaba1dc37bf75f5'
# Existing offline CF_M4b toolkit's x86_64 BusyBox v1.33.1 build; this is
# deliberately a second exact test-only artifact pin, never a release pin.
LOCAL_HELPER_SHA256 = 'b9e75f97de336e3d04b7f07c2d213da779c6b2cf702ebf1935b4cd09c0b97ddb'
X86_HELPER_SHA256 = 'afa625460bd5f4d1db52787dfd84e6c5b8126d7ab841b65cf61e410554edb60a'


def prepare_helper_release(root):
    """Refreeze a disposable repository copy using the CI-pinned x86_64 helper."""
    root = Path(root)
    helper = Path(os.environ.get('CF_TEST_BUSYBOX') or shutil.which('busybox') or '')
    digest = hashlib.sha256(helper.read_bytes()).hexdigest() if helper.is_file() else ''
    if digest not in (X86_HELPER_SHA256, LOCAL_HELPER_SHA256):
        raise AssertionError('tests require the hash-pinned x86_64 BusyBox 1.33.1 helper')
    shutil.copyfile(helper, root / 'router/lib/busybox-static')
    (root / 'router/lib/busybox-static').chmod(0o755)
    for rel in ('router/lib/platform-bootstrap.sh', 'tools/live/penn_pilot_v2.py'):
        path = root / rel
        if path.exists():
            path.write_text(path.read_text().replace(PRODUCTION_HELPER_SHA256, digest))
    subprocess.run([sys.executable, '-I', str(root / 'tools/freeze-router-release.py')],
                   check=True, capture_output=True)
    return digest


def fixture_router(repo, destination):
    """Emit from an isolated rewritten source, leaving repository bytes intact."""
    destination = Path(destination)
    source = destination.parent / 'fixture-source'
    (source / 'tools').mkdir(parents=True)
    shutil.copytree(Path(repo) / 'router', source / 'router')
    for name in ('freeze-router-release.py', 'strip-test-mode.py'):
        shutil.copyfile(Path(repo) / 'tools' / name, source / 'tools' / name)
    prepare_helper_release(source)
    subprocess.run([sys.executable, '-I', str(source / 'tools/freeze-router-release.py'), '--emit', str(destination)],
                   check=True, capture_output=True)
    return destination
