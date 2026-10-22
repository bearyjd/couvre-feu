#!/usr/bin/env python3
"""Compile deterministic module pins and the outer reviewed release manifest.

The full manifest is frozen/reviewed by the release operator; entry scripts do
not claim to recursively authenticate their own bytes. No runtime hash input.
With --check, compare the expected frozen bytes read-only and write nothing.
With --emit DIR, write the shippable router tree (cfctl-ssh and cfctl-scope stripped of
CF_TEST_MODE blocks); release.sha256 hashes the emitted bytes. DIR must not exist.
"""
import hashlib
import importlib.util
from pathlib import Path
import re
import sys

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
pairs = [name + ':' + hashlib.sha256((router / 'lib' / name).read_bytes()).hexdigest() for name in names]
expected = {}
try:
    for name in ('cfctl-ssh', 'cfctl-scope'):
        expected[name] = stripper.strip((router / name).read_text(), stripper.BLOCK_LINES[name]).encode()
except ValueError as error:
    sys.exit('refused: ' + str(error))
# The CF_RELEASE_ID additionally covers the boundary files. cfctl embeds CF_BOOTSTRAP_PIN, which
# depends on the id, so its pin line is blanked for identity only; the manifest hashes it as shipped.
cfctl_identity = re.sub(rb'^CF_BOOTSTRAP_PIN=.*$', b'CF_BOOTSTRAP_PIN=', (router / 'cfctl').read_bytes(), flags=re.M)
extras = ['cfctl:' + hashlib.sha256(cfctl_identity).hexdigest()] + [
    name + ':' + hashlib.sha256(expected[name]).hexdigest() for name in ('cfctl-ssh', 'cfctl-scope')]
identity = hashlib.sha256(('\n'.join(pairs + extras) + '\n').encode()).hexdigest()
s = (router / 'lib/platform-bootstrap.sh').read_text()
s = re.sub(r'^CF_RELEASE_ID=.*$', 'CF_RELEASE_ID=' + identity, s, flags=re.M)
s = re.sub(r"^CF_RELEASE_MODULES=.*$", "CF_RELEASE_MODULES='" + ' '.join(pairs) + "'", s, flags=re.M)
expected['lib/platform-bootstrap.sh'] = s.encode()
pin = hashlib.sha256(expected['lib/platform-bootstrap.sh']).hexdigest()
for name in ['install.sh', 'uninstall.sh', 'cfctl']:
    s = (router / name).read_text()
    s = re.sub(r'^CF_BOOTSTRAP_PIN=.*$', 'CF_BOOTSTRAP_PIN=' + pin, s, flags=re.M)
    expected[name] = s.encode()
files = ['install.sh', 'uninstall.sh', 'cfctl', 'cfctl-ssh', 'cfctl-scope'] + ['lib/' + name for name in names] + ['lib/platform-bootstrap.sh']
expected['release.sha256'] = ''.join(
    hashlib.sha256(expected[name] if name in expected else (router / name).read_bytes()).hexdigest() + '  ' + name + '\n'
    for name in files).encode()
if emit is not None:
    emit.mkdir(mode=0o700)
    (emit / 'lib').mkdir(mode=0o700)
    for name in files:
        data = expected[name] if name in expected else (router / name).read_bytes()
        (emit / name).write_bytes(data)
        (emit / name).chmod(0o644 if name.startswith('lib/') else 0o755)
    (emit / 'release.sha256').write_bytes(expected['release.sha256'])
    (emit / 'release.sha256').chmod(0o600)
    print(identity)
    sys.exit(0)
if check:
    # Repo wrappers keep CF_TEST_MODE for tests; only the emitted bytes are stripped.
    mismatches = [name for name, data in expected.items()
                  if name not in ('cfctl-ssh', 'cfctl-scope') and (router / name).read_bytes() != data]
    for name in mismatches:
        print('not frozen: router/' + name, file=sys.stderr)
    sys.exit(1 if mismatches else 0)
for name, data in expected.items():
    if name not in ('release.sha256', 'cfctl-ssh', 'cfctl-scope'):
        (router / name).write_bytes(data)
manifest = router / 'release.sha256'
manifest.write_bytes(expected['release.sha256'])
manifest.chmod(0o600)
print(identity)
