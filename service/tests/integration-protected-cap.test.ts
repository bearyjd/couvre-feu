import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { integrationConfig, PROTECTED_MAC_LIMIT } from '../src/integration-config.ts';
import { testConfig } from './fixtures/integration.ts';

const macN = (n: number) => `02:20:00:00:${(n >> 8).toString(16).padStart(2, '0')}:${(n & 255).toString(16).padStart(2, '0')}`;

test('router protected-list cap in install-common.sh equals the service cap (drift test)', () => {
    const source = readFileSync(fileURLToPath(new URL('../../router/lib/install-common.sh', import.meta.url)), 'utf8');
    const fn = /valid_protection\(\) \{[\s\S]*?\n\}/.exec(source);
    assert.ok(fn, 'valid_protection not found in install-common.sh');
    const cap = /NR\s*<\s*1\s*\|\|\s*NR\s*>\s*(\d+)/.exec(fn![0]);
    assert.ok(cap, 'protected cap not found in valid_protection');
    assert.equal(Number(cap![1]), PROTECTED_MAC_LIMIT);
    assert.equal(PROTECTED_MAC_LIMIT, 128);
});

test('manifest accepts 128 protected MACs and rejects 129 or none', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-protected-cap-test-')), sample = testConfig(dir), socket = createServer();
    socket.listen(sample.router.agentSocket); await once(socket, 'listening'); chmodSync(sample.router.agentSocket, 0o600);
    const data = Buffer.concat([Buffer.from([0,0,0,11]), Buffer.from('ssh-ed25519'), Buffer.from([0,0,0,32]), Buffer.alloc(32, 1)]), blob = data.toString('base64'), fp = 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
    writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n`, {mode: 0o600});
    writeFileSync(sample.router.publicIdentity, `ssh-ed25519 ${blob} test-public-key\n`, {mode: 0o600});
    const {origin: _o, host: _h, manifestDigest: _m, targetDigest: _t, provenance: _p, ...manifest} = sample;
    manifest.router.hostFingerprint = fp; manifest.router.publicKeyFingerprint = fp;
    const path = join(dir, 'manifest.json');
    const save = (protectedMacs: string[]) => writeFileSync(path, JSON.stringify({...manifest, protectedMacs}), {mode: 0o600});
    try {
        save(Array.from({length: 128}, (_, i) => macN(i + 1)));
        assert.equal(integrationConfig(path).protectedMacs.length, 128);
        save(Array.from({length: 129}, (_, i) => macN(i + 1)));
        assert.throws(() => integrationConfig(path), /protected_identities_required/);
        save([]);
        assert.throws(() => integrationConfig(path), /protected_identities_required/);
    } finally { socket.close(); await once(socket, 'close'); rmSync(dir, {recursive: true, force: true}); }
});
