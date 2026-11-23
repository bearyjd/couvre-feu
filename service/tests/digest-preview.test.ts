import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { ContentFilterCountsStore } from '../src/content-filter-counts.ts';
import { appServer } from '../src/http.ts';
import { TestAuthenticator } from './authenticator.ts';
import { readDigestPreview } from '../src/digest-preview.ts';
import { integrationFixture } from './fixtures/integration.ts';

const epoch = (s: string) => Date.parse(s) / 1000;

test('digest preview returns the scheduled window through spring and fall DST with no notification state', (t) => {
    const f = integrationFixture();
    try {
        const fetch = t.mock.method(globalThis, 'fetch');
        const timer = t.mock.method(globalThis, 'setInterval');
        const write = t.mock.method(f.store, 'run');
        for (const [start, end] of [
            ['2026-03-01T23:00:00Z', '2026-03-08T22:00:00Z'],
            ['2026-10-25T22:00:00Z', '2026-11-01T23:00:00Z'],
        ]) {
            const range = {start: epoch(start), end: epoch(end)};
            assert.deepEqual(readDigestPreview(f.config, f.store, range.end, 'operator'), {
                period: range, counts: {requests: 0, grants: 0, pauses: 0},
            });
        }
        assert.equal(fetch.mock.callCount(), 0);
        assert.equal(timer.mock.callCount(), 0);
        assert.equal(write.mock.callCount(), 0);
        assert.equal(f.store.get("SELECT name FROM sqlite_master WHERE name='notify_state'"), undefined);
    } finally { f.cleanup(); }
});

test('a failed local read reports unavailable instead of zero', () => {
    const f = integrationFixture();
    try {
        f.store.run('DROP TABLE time_requests');
        assert.throws(() => readDigestPreview(f.config, f.store, epoch('2026-11-01T23:00:00Z'), 'operator'), {code: 'digest_preview_unavailable'});
    } finally { f.cleanup(); }
});

test('blocked lookups cover the previous Sunday through Saturday with honest partial coverage', () => {
    const f = integrationFixture();
    try {
        const end = epoch('2026-11-08T23:00:00Z');
        f.config.ownerAccountId = 'operator';
        f.config.contentFilter = {mode: 'owner', apiKeyFile: '/unused', defaultProfile: 'abcd1234',
            profiles: {pilot: 'abcd5678'}, counts: {enabled: true}};
        assert.equal(readDigestPreview(f.config, f.store, end, 'operator').blockedLookups, undefined);
        const store = new ContentFilterCountsStore(f.store);
        for (const day of ['2026-11-01', '2026-11-07', '2026-11-08']) {
            store.put('pilot', {day, state: 'ok', total: 4, blocked: 2, classes: {adult: 2}}, 1);
        }
        assert.deepEqual(readDigestPreview(f.config, f.store, end, 'operator'), {
            period: {start: epoch('2026-11-01T23:00:00Z'), end},
            counts: {requests: 0, grants: 0, pauses: 0},
            blockedLookups: {firstDay: '2026-11-01', lastDay: '2026-11-07', count: 4, daysCounted: 2},
        });
    } finally { f.cleanup(); }
});

async function signIn(f: ReturnType<typeof integrationFixture>, origin: string, account: string) {
    const cookies = new Map<string, string>();
    async function send(path: string, body?: unknown) {
        const response = await fetch(origin + path, {
            method: body === undefined ? 'GET' : 'POST',
            headers: {Origin: origin, 'Content-Type': 'application/json', Cookie: [...cookies].map(([key, value]) => key + '=' + value).join('; ')},
            ...(body === undefined ? {} : {body: JSON.stringify(body)}),
        });
        for (const entry of response.headers.getSetCookie()) {
            const [key, value] = entry.split(';')[0].split('=');
            cookies.set(key, value);
        }
        return response;
    }
    const options = await send('/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
    assert.equal(options.status, 200);
    const {challengeId, options: credential} = await options.json();
    const verified = await send('/auth/register/verify', {challengeId, response: new TestAuthenticator().register(credential, origin)});
    assert.equal(verified.status, 200);
    await verified.json();
    return send;
}

test('preview HTTP enforces flag, admin, and owner-only blocked-lookup visibility', async () => {
    const f = integrationFixture();
    f.advance(epoch('2026-11-08T23:00:00Z') - f.now());
    f.store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES(?,?,'admin',?,?)",
        'secondadmin', 'Second admin', '["pilot"]', 'secondadmin-auth-id');
    f.config.ownerAccountId = 'operator';
    f.config.contentFilter = {mode: 'owner', apiKeyFile: '/unused', defaultProfile: 'abcd1234',
        profiles: {pilot: 'abcd5678'}, counts: {enabled: true}};
    new ContentFilterCountsStore(f.store).put('pilot',
        {day: '2026-11-07', state: 'ok', total: 4, blocked: 2, classes: {adult: 2}}, 1);
    const { freePort } = await import('./free-port.ts');
    const port = await freePort(), origin = 'http://localhost:' + port;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: 'localhost:' + port});
    server.listen(port, '127.0.0.1');
    await once(server, 'listening');
    try {
        const admin = await signIn(f, origin, 'operator'), parent = await signIn(f, origin, 'parent');
        const off = await admin('/digest/preview');
        assert.equal(off.status, 404);
        await off.json();
        f.config.digestPreview = {enabled: true};
        const denied = await parent('/digest/preview');
        assert.equal(denied.status, 404);
        await denied.json();
        const response = await admin('/digest/preview');
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('cache-control'), 'no-store');
        const expected = {period: {start: epoch('2026-11-01T23:00:00Z'), end: f.now()},
            counts: {requests: 0, grants: 0, pauses: 0}};
        assert.deepEqual(await response.json(), {...expected,
            blockedLookups: {firstDay: '2026-11-01', lastDay: '2026-11-07', count: 2, daysCounted: 1}});
        const secondAdmin = await signIn(f, origin, 'secondadmin');
        const secondResponse = await secondAdmin('/digest/preview');
        assert.equal(secondResponse.status, 200);
        assert.deepEqual(await secondResponse.json(), expected);
        assert.equal(f.store.get("SELECT name FROM sqlite_master WHERE name='notify_state'"), undefined);
    } finally {
        server.close();
        await once(server, 'close');
        f.cleanup();
    }
});
