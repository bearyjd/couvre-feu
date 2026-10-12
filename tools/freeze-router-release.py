#!/usr/bin/env python3
"""Compile deterministic module pins and the outer reviewed release manifest.

The full manifest is frozen/reviewed by the release operator; entry scripts do
not claim to recursively authenticate their own bytes. No runtime hash input.
"""
import hashlib
from pathlib import Path
import re

router = Path(__file__).resolve().parents[1] / 'router'
names = ['core.sh', 'rpc.sh', 'firewall.sh', 'install-common.sh', 'state.awk', 'rules.awk', 'json.awk', 'vendor-platform.sh']
pairs = [name + ':' + hashlib.sha256((router / 'lib' / name).read_bytes()).hexdigest() for name in names]
identity = hashlib.sha256(('\n'.join(pairs) + '\n').encode()).hexdigest()
bootstrap = router / 'lib/platform-bootstrap.sh'
s = bootstrap.read_text()
s = re.sub(r'^CF_RELEASE_ID=.*$', 'CF_RELEASE_ID=' + identity, s, flags=re.M)
s = re.sub(r"^CF_RELEASE_MODULES=.*$", "CF_RELEASE_MODULES='" + ' '.join(pairs) + "'", s, flags=re.M)
bootstrap.write_text(s)
pin = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
for name in ['install.sh', 'uninstall.sh', 'cfctl']:
    entry = router / name
    s = entry.read_text()
    s = re.sub(r'^CF_BOOTSTRAP_PIN=.*$', 'CF_BOOTSTRAP_PIN=' + pin, s, flags=re.M)
    entry.write_text(s)
files = ['install.sh', 'uninstall.sh', 'cfctl', 'cfctl-ssh'] + ['lib/' + name for name in names] + ['lib/platform-bootstrap.sh']
manifest = router / 'release.sha256'
manifest.write_text(''.join(hashlib.sha256((router / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in files))
manifest.chmod(0o600)
print(identity)
