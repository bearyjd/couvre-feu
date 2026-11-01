import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, chmodSync, symlinkSync, unlinkSync, existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { integrationConfig, privateHTTPSOrigin } from '../src/integration-config.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { Store } from '../src/db.ts';
import { testConfig } from './fixtures/integration.ts';
import { ACCOUNT_LIMIT } from '../src/account-limits.ts';

test('private manifest validates explicit real bindings, pinned public keys and agent; rejects unsafe or fictional mode', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-private-config-test-')), sample = testConfig(dir), socket = createServer();
    socket.listen(sample.router.agentSocket); await once(socket, 'listening'); chmodSync(sample.router.agentSocket, 0o600);
    const data = Buffer.concat([Buffer.from([0,0,0,11]), Buffer.from('ssh-ed25519'), Buffer.from([0,0,0,32]), Buffer.alloc(32, 1)]), blob = data.toString('base64'), fp = 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
    writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n`, {mode: 0o600});
    writeFileSync(sample.router.publicIdentity, `ssh-ed25519 ${blob} test-public-key\n`, {mode: 0o600});
    const {origin: _o, host: _h, manifestDigest: _m, targetDigest: _t, provenance: _p, ...manifest} = sample;
    manifest.router.hostFingerprint = fp; manifest.router.publicKeyFingerprint = fp;
    const path = join(dir, 'manifest.json');
    const save = (value: unknown) => writeFileSync(path, JSON.stringify(value), {mode: 0o600});
    try {
        save(manifest); const c = integrationConfig(path);
        // routerScope (the router's install-time --rpc-allow set) is optional: absent, the v1 target digest keeps its exact pre-008 form.
        assert.equal(c.routerScope, undefined);
        assert.equal(c.targetDigest, createHash('sha256').update(JSON.stringify({host: c.router.host, user: c.router.user, port: c.router.port, hostFingerprint: fp, publicKeyFingerprint: fp, generation: c.router.generation, allowedMac: c.person.device.mac, protectedMacs: [...c.protectedMacs].sort()})).digest('hex'));
        save({...manifest, routerScope: ['02:10:20:30:40:52', manifest.person.device.mac]});
        const scoped = integrationConfig(path); assert.deepEqual(scoped.routerScope, [manifest.person.device.mac, '02:10:20:30:40:52']); assert.notEqual(scoped.targetDigest, c.targetDigest);
        for (const routerScope of [[], ['02:10:20:30:40:52'], [manifest.person.device.mac, manifest.person.device.mac], [manifest.person.device.mac, '03:10:20:30:40:52'], 'x', Array.from({length: 257}, (_, i) => `02:00:00:00:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`)]) {
            save({...manifest, routerScope}); assert.throws(() => integrationConfig(path), /invalid_router_scope/);
        }
        save({...manifest, routerScope: [manifest.person.device.mac, manifest.protectedMacs[0]]}); assert.throws(() => integrationConfig(path), /protected_mac_overlap/);
        // No 16-account product cap: manifest accounts only seed a fresh database, bounded by the defensive ACCOUNT_LIMIT.
        const seeded = Array.from({length: 40}, (_, i) => ({id: `parent_${i}`, displayName: `Parent ${i}`, role: 'parent', personIds: ['pilot']}));
        save({...manifest, accounts: [...manifest.accounts, ...seeded]}); assert.equal(integrationConfig(path).accounts.length, 42);
        save({...manifest, accounts: [...manifest.accounts, ...Array.from({length: ACCOUNT_LIMIT}, (_, i) => ({id: `p${i}`, displayName: 'P', role: 'parent', personIds: ['pilot']}))]}); assert.throws(() => integrationConfig(path), /invalid_integration_manifest|body_too_large/); // the 64 KiB manifest bound may bind first
        assert.equal(c.dispatch, undefined);
        assert.equal(c.timeRequests, undefined, 'time requests are off unless explicitly enabled');
        // Legacy {enabled} still parses: true is 'parents' (every parent, as before), false is 'off'.
        save({...manifest, timeRequests: {enabled: true}}); assert.deepEqual(integrationConfig(path).timeRequests, {mode: 'parents'});
        save({...manifest, timeRequests: {enabled: false}}); assert.deepEqual(integrationConfig(path).timeRequests, {mode: 'off'});
        for (const mode of ['off', 'parents']) { save({...manifest, timeRequests: {mode}}); assert.deepEqual(integrationConfig(path).timeRequests, {mode}); assert.equal(integrationConfig(path).ownerAccountId, undefined); }
        save({...manifest, timeRequests: {mode: 'owner'}, ownerAccountId: 'parent'});
        const owned = integrationConfig(path); assert.deepEqual(owned.timeRequests, {mode: 'owner'}); assert.equal(owned.ownerAccountId, 'parent');
        assert.notEqual(owned.manifestDigest, c.manifestDigest, 'the new keys change the manifest digest and integration scope');
        assert.notEqual(owned.provenance.integrationScope, c.provenance.integrationScope);
        save({...manifest, timeRequests: {mode: 'parents'}, ownerAccountId: 'operator'}); assert.equal(integrationConfig(path).ownerAccountId, 'operator');
        save({...manifest, timeRequests: {mode: 'owner'}}); assert.throws(() => integrationConfig(path), /owner_account_required/);
        save({...manifest, timeRequests: {mode: 'owner'}, ownerAccountId: 'stranger'}); assert.throws(() => integrationConfig(path), /invalid_owner_account/);
        save({...manifest, ownerAccountId: 'stranger'}); assert.throws(() => integrationConfig(path), /invalid_owner_account/);
        for (const ownerAccountId of [1, null, '', ['parent']]) { save({...manifest, timeRequests: {mode: 'owner'}, ownerAccountId}); assert.throws(() => integrationConfig(path)); }
        for (const timeRequests of [{mode: 'everyone'}, {mode: 1}, {mode: 'owner', extra: 1}, {mode: 'owner', enabled: true}, {mode: 'off', enabled: false}]) { save({...manifest, timeRequests, ownerAccountId: 'parent'}); assert.throws(() => integrationConfig(path)); }
        for (const timeRequests of [{enabled: 'true'}, {enabled: 1}, {}, {enabled: true, extra: 1}, true, null, []]) { save({...manifest, timeRequests}); assert.throws(() => integrationConfig(path)); }
        // auditLog: absent is OFF; strict {enabled: boolean}.
        assert.equal(c.auditLog, undefined, 'the audit log is off unless explicitly enabled');
        for (const enabled of [true, false]) { save({...manifest, auditLog: {enabled}}); assert.deepEqual(integrationConfig(path).auditLog, {enabled}); }
        for (const auditLog of [{enabled: 'true'}, {enabled: 1}, {}, {enabled: true, extra: 1}, {mode: 'on'}, true, null, []]) { save({...manifest, auditLog}); assert.throws(() => integrationConfig(path)); }
        // push and digest (B7): absent is OFF; strict {enabled: boolean}; the digest is delivered by push, so it needs push on.
        assert.equal(c.push, undefined); assert.equal(c.digest, undefined);
        for (const enabled of [true, false]) { save({...manifest, push: {enabled}}); assert.deepEqual(integrationConfig(path).push, {enabled}); }
        for (const push of [{enabled: 'true'}, {enabled: 1}, {}, {enabled: true, topic: 'x'}, true, null, []]) { save({...manifest, push}); assert.throws(() => integrationConfig(path)); }
        for (const digest of [{enabled: 'true'}, {}, {enabled: true, day: 1}, null]) { save({...manifest, push: {enabled: true}, digest}); assert.throws(() => integrationConfig(path)); }
        save({...manifest, digest: {enabled: true}}); assert.throws(() => integrationConfig(path), /digest_requires_push/);
        save({...manifest, push: {enabled: false}, digest: {enabled: true}}); assert.throws(() => integrationConfig(path), /digest_requires_push/);
        save({...manifest, push: {enabled: true}, digest: {enabled: true}}); assert.deepEqual(integrationConfig(path).digest, {enabled: true});
        // rewardTime (F4): absent is OFF; strict {enabled: boolean}.
        assert.equal(c.rewardTime, undefined, 'reward time is off unless explicitly enabled');
        for (const enabled of [true, false]) { save({...manifest, rewardTime: {enabled}}); assert.deepEqual(integrationConfig(path).rewardTime, {enabled}); }
        for (const rewardTime of [{enabled: 'true'}, {enabled: 1}, {}, {enabled: true, extra: 1}, {mode: 'on'}, true, null, []]) { save({...manifest, rewardTime}); assert.throws(() => integrationConfig(path)); }
        // focus (F5): absent is OFF; strict {enabled: boolean}.
        assert.equal(c.focus, undefined, 'focus window is off unless explicitly enabled');
        for (const enabled of [true, false]) { save({...manifest, focus: {enabled}}); assert.deepEqual(integrationConfig(path).focus, {enabled}); }
        for (const focus of [{enabled: 'true'}, {enabled: 1}, {}, {enabled: true, extra: 1}, {mode: 'on'}, true, null, []]) { save({...manifest, focus}); assert.throws(() => integrationConfig(path)); }
        save({...manifest, origin: 'https://parent.example.test:8443', dispatch: {enabled: true, pollSeconds: 2, maxBackoffSeconds: 60}});
        const enabled = integrationConfig(path); assert.equal(enabled.origin, 'https://parent.example.test:8443'); assert.equal(enabled.host, 'parent.example.test:8443'); assert.equal(enabled.dispatch?.enabled, true);
        const scheduled = {...manifest, enrollment: {...manifest.enrollment, schedules: [{person: 'pilot', id: 'bedtime', weekdays: ['Mon'], start: '21:00', stop: '07:00'}]}, scheduleClock: {timezone: 'America/New_York'}};
        save(scheduled); const unverified = integrationConfig(path);
        assert.equal(unverified.enrollment.schedules.length, 1); assert.equal(unverified.scheduleClock?.conformance, undefined);
        const conformance = {utcOffsetMinutes: -240, verifiedAt: 1791763200, validUntil: 1791849600, evidenceSha256: 'e'.repeat(64)};
        save({...scheduled, scheduleClock: {...scheduled.scheduleClock, conformance}});
        assert.deepEqual(integrationConfig(path).scheduleClock?.conformance, conformance);
        save({...scheduled, scheduleClock: undefined}); assert.throws(() => integrationConfig(path), /owner_schedule_clock_required/);
        save({...scheduled, scheduleClock: {...scheduled.scheduleClock, conformance: {...conformance, validUntil: conformance.verifiedAt + 7 * 86400 + 1}}}); assert.throws(() => integrationConfig(path), /invalid_schedule_conformance/);
        for (const dispatch of [{enabled: 'true', pollSeconds: 2, maxBackoffSeconds: 60}, {enabled: true, pollSeconds: 0, maxBackoffSeconds: 60}, {enabled: true, pollSeconds: 2, maxBackoffSeconds: 301}, {enabled: true, pollSeconds: 10, maxBackoffSeconds: 2}, {enabled: true, pollSeconds: 2, maxBackoffSeconds: 60, bypass: true}]) { save({...manifest, dispatch}); assert.throws(() => integrationConfig(path)); }
        save(manifest);
        assert.equal(c.provenance.source, 'real-router-integration'); assert.equal(c.provenance.routerCompatibilityVerified, false);
        assert.deepEqual(c.accounts.map(a => a.id), ['operator', 'parent']); assert.equal(c.router.generation, manifest.router.generation);
        for (const changed of [{...manifest, mode: 'demo'}, {...manifest, protectedMacs: [manifest.person.device.mac]}, {...manifest, router: {...manifest.router, generation: undefined}}, {...manifest, router: {...manifest.router, host: 'evil.example'}}, {...manifest, accounts: [{...manifest.accounts[0], personIds: ['other']}]}, {...manifest, accounts: [{...manifest.accounts[0], personIds: []}]}, {...manifest, enrollment: {...manifest.enrollment, people: [{id: 'pilot', macs: ['02:aa:bb:cc:dd:ee']}]}}]) { save(changed); assert.throws(() => integrationConfig(path)); }
        save(manifest); chmodSync(path, 0o644); assert.throws(() => integrationConfig(path), /unsafe_private_path/); chmodSync(path, 0o600);
        const link = join(dir, 'link.json'); symlinkSync(path, link); assert.throws(() => integrationConfig(link), /unsafe_private_path/);
        writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n192.168.1.2 ssh-ed25519 ${blob}\n`); assert.throws(() => integrationConfig(path), /invalid_pinned_host_key/);
        writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n`);
        writeFileSync(sample.router.publicIdentity, '-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n'); assert.throws(() => integrationConfig(path), /invalid_public_identity/);
    } finally { socket.close(); await once(socket, 'close'); rmSync(dir, {recursive: true, force: true}); }
});
test('private HTTPS origin is exact, hostname-bound and rejects credentials, path, query and insecure alternatives', () => {
    assert.equal(privateHTTPSOrigin('https://parent.example.test'), 'https://parent.example.test');
    for (const value of ['http://parent.example.test', 'https://127.0.0.1', 'https://localhost', 'https://parent.example.test/', 'https://parent.example.test/path', 'https://parent.example.test?query', 'https://user@parent.example.test', 'https://parent.example.test#fragment', 'https://PARENT.example.test', 'https://parent.example.test:443', null]) assert.throws(() => privateHTTPSOrigin(value));
});
test('integration and demo DBs refuse cross-mode reuse or changed installation/manifest identities', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-private-db-test-')), c = testConfig(dir), store = new IntegrationStore(c);
    try {
        store.close();
        assert.throws(() => new Store(join(dir, 'integration.sqlite')), /integration_database_forbidden/);
        assert.throws(() => new IntegrationStore({...c, manifestDigest: 'e'.repeat(64)}), /integration_database_identity_mismatch/);
        assert.throws(() => new IntegrationStore({...c, router: {...c.router, generation: 'e'.repeat(64)}}), /integration_database_identity_mismatch/);
        const restored = new IntegrationStore(c); assert.equal(restored.integrationState().dispatch_stopped, 1); restored.close();
        const otherDir = join(dir, 'foreign');
        const foreign = new Store(join(otherDir, 'integration.sqlite')); foreign.close();
        assert.throws(() => new IntegrationStore({...c, dataDir: otherDir}), /demo_database_forbidden/);
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
test('dangling DB, WAL, SHM and rollback-journal symlinks are rejected before SQLite creates any outside target', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-private-symlink-test-')), dataDir = join(dir, 'data'); mkdirSync(dataDir, {mode: 0o700});
    try {
        for (const suffix of ['', '-wal', '-shm', '-journal']) {
            const target = join(dir, `unexpected${suffix}.sqlite`), link = join(dataDir, `integration.sqlite${suffix}`);
            symlinkSync(target, link);
            assert.throws(() => new IntegrationStore(testConfig(dataDir)), /unsafe_private_path/);
            assert.equal(existsSync(target), false, suffix || 'main DB'); assert.equal(existsSync(join(dataDir, 'integration.sqlite')), false);
            unlinkSync(link);
        }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
