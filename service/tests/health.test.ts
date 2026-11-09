import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { Auth } from '../src/auth.ts';
import { seedAccounts } from '../src/fixtures.ts';
import { FakeRouter } from '../../demo-router/src/router.ts';
import { PolicyService } from '../src/policy.ts';
import { appServer } from '../src/http.ts';
import { Health, HEALTH_RATE_PER_MINUTE, buildVersion } from '../src/health.ts';

const KEYS = ['lastInventoryOkAgeSeconds', 'ok', 'schemaVersion', 'uptimeSeconds', 'version'];

async function boot(offset: number) {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-health-')), port = 30000 + (process.pid + offset) % 10000, origin = `http://localhost:${port}`;
    const store = new Store(join(dir, 'service.sqlite'));
    seedAccounts(store);
    const now = 1791691200, router = new FakeRouter(join(dir, 'fake.sqlite'), {now: () => now, delay: 1});
    router.tick();
    const server = appServer(new Auth(store, origin, () => now), new PolicyService(store, router, () => now), {port, origin, host: `localhost:${port}`, dataDir: dir});
    server.listen(port, '127.0.0.1');
    await once(server, 'listening');
    const get = (path: string, init: RequestInit = {}) => fetch(`${origin}${path}`, {redirect: 'manual', ...init});
    return {store, server, get, close: () => { server.close(); server.closeAllConnections(); store.close(); }};
}

test('GET /health answers without a session, with an exact key set, no-store, and no identifying data', async () => {
    const h = await boot(1);
    try {
        const res = await h.get('/health');
        assert.equal(res.status, 200);
        assert.equal(res.headers.get('cache-control'), 'no-store');
        assert.match(res.headers.get('content-type') ?? '', /^application\/json/);
        const text = await res.text(), body = JSON.parse(text);
        assert.deepEqual(Object.keys(body).sort(), KEYS);
        assert.equal(body.ok, true);
        assert.equal(typeof body.version, 'string');
        assert.ok(Number.isInteger(body.uptimeSeconds) && body.uptimeSeconds >= 0);
        assert.equal(body.schemaVersion, h.store.get<{user_version: number}>('PRAGMA user_version')!.user_version);
        assert.equal(body.lastInventoryOkAgeSeconds, null);
        // Leak guard: no MAC-, IPv4- or hostname-looking text, no demo manifest or account strings.
        assert.doesNotMatch(text, /[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
        assert.doesNotMatch(text, /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
        assert.doesNotMatch(text, /localhost|\/home|\/tmp|\.sqlite|bryn|jack|penn|ford|source|integrationScope|router/i);
    } finally { h.close(); }
});

test('HEAD works with no body; other methods are 405 with no detail', async () => {
    const h = await boot(2);
    try {
        const head = await h.get('/health', {method: 'HEAD'});
        assert.equal(head.status, 200);
        assert.equal(await head.text(), '');
        for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
            const res = await h.get('/health', {method, headers: {Origin: new URL(res0(h)).origin, 'Content-Type': 'application/json'}, body: '{}'});
            assert.equal(res.status, 405, method);
            assert.deepEqual(await res.json(), {ok: false});
        }
        assert.equal((await h.get('/health?x=1')).status, 400);
    } finally { h.close(); }
});
function res0(h: {server: {address(): unknown}}) { return `http://localhost:${(h.server.address() as {port: number}).port}`; }

test('a database failure is a bare 503 {ok:false}', async () => {
    const h = await boot(3);
    try {
        h.store.close();
        const res = await h.get('/health');
        assert.equal(res.status, 503);
        assert.equal(await res.text(), JSON.stringify({ok: false}));
    } finally { h.server.close(); h.server.closeAllConnections(); }
});

test('the rate limit trips after the modest cap and answers identically', async () => {
    const h = await boot(4);
    try {
        let last = 200;
        for (let i = 0; i < HEALTH_RATE_PER_MINUTE + 1; i++) last = (await h.get('/health')).status;
        assert.equal(last, 429);
        assert.equal(await (await h.get('/health')).text(), JSON.stringify({ok: false}));
    } finally { h.close(); }
});

test('Health reports the inventory age and clamps a future timestamp to zero', () => {
    const store = new Store(':memory:');
    try {
        assert.equal(new Health(store, () => 1000, () => 1090, 'v').answer()?.lastInventoryOkAgeSeconds, 90);
        assert.equal(new Health(store, () => 2000, () => 1090, 'v').answer()?.lastInventoryOkAgeSeconds, 0);
        assert.equal(new Health(store, () => { throw new Error('/secret/path'); }, () => 0, 'v').answer(), null);
    } finally { store.close(); }
});

test('buildVersion prefers a VERSION file, never leaks a malformed one, and falls back to package.json plus dev', () => {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-ver-')), root = new URL(`file://${dir}/`);
    assert.equal(buildVersion(root), '0-dev');
    writeFileSync(join(dir, 'package.json'), '{"version":"1.2.3"}');
    assert.equal(buildVersion(root), '1.2.3-dev');
    writeFileSync(join(dir, 'VERSION'), 'abc1234\n');
    assert.equal(buildVersion(root), 'abc1234');
    writeFileSync(join(dir, 'VERSION'), '/etc/passwd secret\n');
    assert.equal(buildVersion(root), '1.2.3-dev');
    assert.match(buildVersion(), /-dev$|^[A-Za-z0-9._+-]+$/);
});
