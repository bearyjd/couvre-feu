"""Host-architecture substitution ONLY in disposable test source trees.

Production has no helper override: this rewrites reviewed source constants, then
runs the ordinary freeze tool. The shippable router bytes retain the aarch64 pin.
"""
import hashlib
import atexit
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

PRODUCTION_HELPER_SHA256 = 'c25f66e5ac29ea3e373b8fb2d3549a59d058fbef9ed11b67fdaba1dc37bf75f5'
# Existing offline CF_M4b toolkit's x86_64 BusyBox v1.33.1 build; this is
# deliberately a second exact test-only artifact pin, never a release pin.
LOCAL_HELPER_SHA256 = 'b9e75f97de336e3d04b7f07c2d213da779c6b2cf702ebf1935b4cd09c0b97ddb'
X86_HELPER_SHA256 = 'afa625460bd5f4d1db52787dfd84e6c5b8126d7ab841b65cf61e410554edb60a'
_SOURCES = {}


def helper_binary():
    """Select an exact reviewed host artifact, never an arbitrary PATH wrapper."""
    helper = Path(os.environ.get('CF_TEST_BUSYBOX') or shutil.which('busybox') or '')
    digest = hashlib.sha256(helper.read_bytes()).hexdigest() if helper.is_file() else ''
    if digest not in (X86_HELPER_SHA256, LOCAL_HELPER_SHA256):
        raise AssertionError('tests require the hash-pinned x86_64 BusyBox 1.33.1 helper')
    subprocess.run([str(helper), 'true'], check=True, capture_output=True)
    return helper, digest


def prepare_helper_release(root):
    """Refreeze a disposable repository copy using the CI-pinned x86_64 helper."""
    root = Path(root)
    helper, digest = helper_binary()
    shutil.copyfile(helper, root / 'router/lib/busybox-static')
    (root / 'router/lib/busybox-static').chmod(0o755)
    for rel in ('router/lib/platform-bootstrap.sh',):
        path = root / rel
        if path.exists():
            contents, count = re.subn(r'(?m)^CF_SETSID_HELPER_SHA256=[0-9a-f]{64}$',
                                      'CF_SETSID_HELPER_SHA256=' + digest, path.read_text())
            if count != 1:
                raise AssertionError('fixture bootstrap must carry exactly one helper pin')
            path.write_text(contents)
    subprocess.run([sys.executable, '-I', str(root / 'tools/freeze-router-release.py')],
                   check=True, capture_output=True)
    return digest


def fixture_source(repo):
    """A cached, unstripped runtime source copy with the pinned host helper."""
    repo = Path(repo).resolve()
    if repo not in _SOURCES:
        temporary = tempfile.TemporaryDirectory(prefix='couvre-feu-fixture-source-', dir='/tmp')
        atexit.register(temporary.cleanup)
        source = Path(temporary.name)
        (source / 'tools').mkdir()
        shutil.copytree(repo / 'router', source / 'router')
        for name in ('freeze-router-release.py', 'strip-test-mode.py'):
            shutil.copyfile(repo / 'tools' / name, source / 'tools' / name)
        prepare_helper_release(source)
        _SOURCES[repo] = source
    return _SOURCES[repo]


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
