#!/usr/bin/env python3
"""Compile deterministic module pins and the outer reviewed release manifest.

The full manifest is frozen/reviewed by the release operator; entry scripts do
not claim to recursively authenticate their own bytes. No runtime hash input.
With --check, compare the expected frozen bytes read-only and write nothing.
"""
import hashlib
from pathlib import Path
import re
import sys

args = sys.argv[1:]
if args not in ([], ['--check']):
    sys.exit('usage: freeze-router-release.py [--check]')
check = args == ['--check']
router = Path(__file__).resolve().parents[1] / 'router'
names = ['core.sh', 'rpc.sh', 'firewall.sh', 'install-common.sh', 'state.awk', 'rules.awk', 'json.awk', 'vendor-platform.sh']
pairs = [name + ':' + hashlib.sha256((router / 'lib' / name).read_bytes()).hexdigest() for name in names]
identity = hashlib.sha256(('\n'.join(pairs) + '\n').encode()).hexdigest()
expected = {}
s = (router / 'lib/platform-bootstrap.sh').read_text()
s = re.sub(r'^CF_RELEASE_ID=.*$', 'CF_RELEASE_ID=' + identity, s, flags=re.M)
s = re.sub(r"^CF_RELEASE_MODULES=.*$", "CF_RELEASE_MODULES='" + ' '.join(pairs) + "'", s, flags=re.M)
expected['lib/platform-bootstrap.sh'] = s.encode()
pin = hashlib.sha256(expected['lib/platform-bootstrap.sh']).hexdigest()
for name in ['install.sh', 'uninstall.sh', 'cfctl']:
    s = (router / name).read_text()
    s = re.sub(r'^CF_BOOTSTRAP_PIN=.*$', 'CF_BOOTSTRAP_PIN=' + pin, s, flags=re.M)
    expected[name] = s.encode()
files = ['install.sh', 'uninstall.sh', 'cfctl', 'cfctl-ssh'] + ['lib/' + name for name in names] + ['lib/platform-bootstrap.sh']
expected['release.sha256'] = ''.join(
    hashlib.sha256(expected[name] if name in expected else (router / name).read_bytes()).hexdigest() + '  ' + name + '\n'
    for name in files).encode()
if check:
    mismatches = [name for name, data in expected.items() if (router / name).read_bytes() != data]
    for name in mismatches:
        print('not frozen: router/' + name, file=sys.stderr)
    sys.exit(1 if mismatches else 0)
for name, data in expected.items():
    if name != 'release.sha256':
        (router / name).write_bytes(data)
manifest = router / 'release.sha256'
manifest.write_bytes(expected['release.sha256'])
manifest.chmod(0o600)
print(identity)
