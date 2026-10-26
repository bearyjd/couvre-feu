#!/usr/bin/env python3
"""Compile deterministic module pins and the outer reviewed release manifest.

The full manifest is frozen/reviewed by the release operator; entry scripts do
not claim to recursively authenticate their own bytes. No runtime hash input.
With --check, compare the expected frozen bytes read-only and write nothing.
With --emit DIR, write the shippable router tree (cfctl-ssh and cfctl-scope stripped of
CF_TEST_MODE blocks); release.sha256 hashes the emitted bytes. DIR must not exist and its
parent must. --emit refuses unless router/ is already frozen (the --check comparison), and the
tree is built in a temporary sibling and renamed, so a failure leaves nothing behind.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

args = sys.argv[1:]
if not (args in ([], ['--check']) or (len(args) == 2 and args[0] == '--emit')):
    sys.exit('usage: freeze-router-release.py [--check | --emit DIR]')
check = args == ['--check']
emit = Path(args[1]) if args[:1] == ['--emit'] else None
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('strip_test_mode', Path(__file__).resolve().parent / 'strip-test-mode.py')
stripper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stripper)
router = Path(__file__).resolve().parents[1] / 'router'
names = ['core.sh', 'rpc.sh', 'firewall.sh', 'install-common.sh', 'state.awk', 'rules.awk', 'json.awk', 'vendor-platform.sh', 'activity.sh']
IDENTITY_FORMAT = 'couvrefeu-router-release-v2'


def generated_field(data, path, field, value_pattern):
    """Require a canonical assignment; forbid export/readonly declarations of this field.

    This generated-field policy recognizes declaration lines, not arbitrary shell evaluation.
    """
    key = field.encode()
    assignments = re.findall(rb'^[ \t]*' + key + rb'[ \t]*=.*$', data, flags=re.M)
    declarations = re.findall(rb'^[ \t]*(?:export|readonly)[ \t]+[^\r\n]*\b' + key + rb'\b[^\r\n]*$', data, flags=re.M)
    valid = re.findall(rb'^' + key + rb'=(' + value_pattern + rb')$', data, flags=re.M)
    if len(assignments) != 1 or len(valid) != 1 or declarations:
        raise ValueError(path + ': must carry exactly one well-formed ' + field + ' assignment')
    return re.sub(rb'^' + key + rb'=.*$', key + b'=', data, flags=re.M)


pairs = [name + ':' + hashlib.sha256((router / 'lib' / name).read_bytes()).hexdigest() for name in names]
expected = {}
try:
    for name in ('cfctl-ssh', 'cfctl-scope'):
        expected[name] = stripper.strip((router / name).read_text(), stripper.BLOCK_LINES[name]).encode()
        if subprocess.run(['sh', '-n'], input=expected[name], capture_output=True).returncode:
            raise ValueError(name + ': stripped wrapper fails sh -n')
except ValueError as error:
    sys.exit('refused: ' + str(error))
# Version 2 binds every emitted source. Generated assignments are blanked only for
# identity to break the id -> bootstrap -> entry pin cycle; the manifest hashes final bytes.
try:
    normalized = {name: generated_field((router / name).read_bytes(), name, 'CF_BOOTSTRAP_PIN', rb'[0-9a-f]{64}')
                  for name in ('install.sh', 'uninstall.sh', 'cfctl')}
    bootstrap = (router / 'lib/platform-bootstrap.sh').read_bytes()
    bootstrap_identity = generated_field(bootstrap, 'lib/platform-bootstrap.sh', 'CF_RELEASE_ID', rb'[0-9a-f]{64}')
    module_pattern = b"'" + b' '.join(re.escape(name.encode()) + rb':[0-9a-f]{64}' for name in names) + b"'"
    normalized['lib/platform-bootstrap.sh'] = generated_field(
        bootstrap_identity, 'lib/platform-bootstrap.sh', 'CF_RELEASE_MODULES', module_pattern)
except ValueError as error:
    sys.exit('refused: ' + str(error))
identity_paths = ['lib/' + name for name in names] + [
    'cfctl', 'cfctl-ssh', 'cfctl-scope', 'install.sh', 'uninstall.sh', 'lib/platform-bootstrap.sh']
identity_lines = [IDENTITY_FORMAT] + [name + ':' + hashlib.sha256(
    normalized[name] if name in normalized else expected[name] if name in expected else (router / name).read_bytes()
).hexdigest() for name in identity_paths]
identity = hashlib.sha256(('\n'.join(identity_lines) + '\n').encode()).hexdigest()
s = re.sub(rb'^CF_RELEASE_ID=.*$', b'CF_RELEASE_ID=' + identity.encode(), bootstrap, flags=re.M)
s = re.sub(rb'^CF_RELEASE_MODULES=.*$', b"CF_RELEASE_MODULES='" + ' '.join(pairs).encode() + b"'", s, flags=re.M)
expected['lib/platform-bootstrap.sh'] = s
pin = hashlib.sha256(expected['lib/platform-bootstrap.sh']).hexdigest()
for name in ['install.sh', 'uninstall.sh', 'cfctl']:
    s = (router / name).read_bytes()
    s = re.sub(rb'^CF_BOOTSTRAP_PIN=.*$', b'CF_BOOTSTRAP_PIN=' + pin.encode(), s, flags=re.M)
    expected[name] = s
files = ['install.sh', 'uninstall.sh', 'cfctl', 'cfctl-ssh', 'cfctl-scope'] + ['lib/' + name for name in names] + ['lib/platform-bootstrap.sh']
expected['release.sha256'] = ''.join(
    hashlib.sha256(expected[name] if name in expected else (router / name).read_bytes()).hexdigest() + '  ' + name + '\n'
    for name in files).encode()
# Repo wrappers keep CF_TEST_MODE for tests, so cfctl-ssh/cfctl-scope are not compared byte for byte.
# Wrapper drift is still caught: their stripped bytes feed CF_RELEASE_ID (platform-bootstrap.sh) and
# release.sha256, both compared here.
mismatches = [name for name, data in expected.items()
              if name not in ('cfctl-ssh', 'cfctl-scope') and (router / name).read_bytes() != data]
if check:
    for name in mismatches:
        print('not frozen: router/' + name, file=sys.stderr)
    sys.exit(1 if mismatches else 0)
if emit is not None:
    if mismatches:
        sys.exit('refused: router not frozen: ' + ', '.join('router/' + name for name in mismatches))
    if os.path.lexists(emit):
        sys.exit('refused: emit target already exists: ' + str(emit))
    if not emit.parent.is_dir():
        sys.exit('refused: emit target parent is not a directory: ' + str(emit.parent))
    try:
        staging = Path(tempfile.mkdtemp(prefix='.' + emit.name + '.', dir=emit.parent))
    except OSError as error:
        sys.exit('refused: cannot create staging directory: ' + str(error))
    try:
        (staging / 'lib').mkdir(mode=0o700)
        for name in files:
            data = expected[name] if name in expected else (router / name).read_bytes()
            (staging / name).write_bytes(data)
            (staging / name).chmod(0o644 if name.startswith('lib/') else 0o755)
        (staging / 'release.sha256').write_bytes(expected['release.sha256'])
        (staging / 'release.sha256').chmod(0o600)
        staging.chmod(0o700)
        os.rename(staging, emit)
    except OSError as error:
        shutil.rmtree(staging, ignore_errors=True)
        sys.exit('refused: cannot write emit tree: ' + str(error))
    print(identity)
    sys.exit(0)
for name, data in expected.items():
    if name not in ('release.sha256', 'cfctl-ssh', 'cfctl-scope'):
        (router / name).write_bytes(data)
manifest = router / 'release.sha256'
manifest.write_bytes(expected['release.sha256'])
manifest.chmod(0o600)
print(identity)
