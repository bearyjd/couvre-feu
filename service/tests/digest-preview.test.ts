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

const OP = "INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES(?,'operator','pilot','pause',?,'confirmed','{}','{}','{}',?,?,?)";

test('event window is (start, end] and now before the slot shows the previous period', () => {
    const f = integrationFixture();
    try {
        for (const [start, end] of [
            [epoch('2026-03-01T23:00:00Z'), epoch('2026-03-08T22:00:00Z')],
            [epoch('2026-10-25T22:00:00Z'), epoch('2026-11-01T23:00:00Z')],
        ]) {
            f.store.run('DELETE FROM operations');
            [start, start + 1, end, end + 1].forEach((at, i) => f.store.run(OP, 'b' + i, i + 1, 'k' + i, at, at));
            const at = readDigestPreview(f.config, f.store, end, 'operator');
            assert.deepEqual(at.period, {start, end});
            assert.equal(at.counts.pauses, 2, 'start excluded, end included, end+1 excluded');
            const later = readDigestPreview(f.config, f.store, end + 3600, 'operator');
            assert.deepEqual(later.period, {start, end}, 'inside the slot hour the period is unchanged');
            const before = readDigestPreview(f.config, f.store, end - 1, 'operator');
            assert.equal(before.period.end, start);
            assert.equal(before.counts.pauses, 1, 'the row at start closes the previous period');
            const next = readDigestPreview(f.config, f.store, end + 7 * 86400, 'operator');
            assert.equal(next.counts.pauses, 1, 'end+1 belongs to the following period');
        }
    } finally { f.cleanup(); }
});

test('blocked lookups week splits at Saturday/Sunday and spans the fall DST change', () => {
    const f = integrationFixture();
    try {
        f.config.ownerAccountId = 'operator';
        f.config.contentFilter = {mode: 'owner', apiKeyFile: '/unused', defaultProfile: 'abcd1234',
            profiles: {pilot: 'abcd5678'}, counts: {enabled: true}};
        const store = new ContentFilterCountsStore(f.store);
        for (const day of ['2026-10-24', '2026-10-25', '2026-10-31', '2026-11-01']) {
            store.put('pilot', {day, state: 'ok', total: 4, blocked: 1, classes: {adult: 1}}, 1);
        }
        const end = epoch('2026-11-01T23:00:00Z');
        assert.deepEqual(readDigestPreview(f.config, f.store, end, 'operator').blockedLookups,
            {firstDay: '2026-10-25', lastDay: '2026-10-31', count: 2, daysCounted: 2});
    } finally { f.cleanup(); }
});

test('failed blocked read is logged by tag, a failed event read logs its tag and nothing else', () => {
    const f = integrationFixture();
    try {
        const lines: string[] = [];
        f.config.ownerAccountId = 'operator';
        f.config.contentFilter = {mode: 'owner', apiKeyFile: '/unused', defaultProfile: 'abcd1234',
            profiles: {pilot: 'abcd5678'}, counts: {enabled: true}};
        f.store.run('DROP TABLE content_filter_day');
        const end = epoch('2026-11-08T23:00:00Z');
        assert.equal(readDigestPreview(f.config, f.store, end, 'operator', {log: l => lines.push(l)}).blockedLookups, undefined);
        assert.deepEqual(lines, ['digest_blocked_failed\n']);
        lines.length = 0;
        f.store.run('DROP TABLE time_requests');
        assert.throws(() => readDigestPreview(f.config, f.store, end, 'operator', {log: l => lines.push(l)}), {code: 'digest_preview_unavailable'});
        assert.ok(lines.includes('digest_preview_failed\n'));
        assert.ok(lines.every(l => /^[a-z_]+\n$/.test(l)), 'tags only');
    } finally { f.cleanup(); }
});

const LINK = "INSERT INTO request_links(id,person_id,token_hash,created_by,created_at) VALUES(?,?,?,'operator',1)";
const REQUEST = "INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,decided_at,expires_at) VALUES(?,?,?,15,'',?,?,?,?)";

test('requests, grants and pauses are counted separately, each in its own field', () => {
    const f = integrationFixture();
    try {
        const end = epoch('2026-11-08T23:00:00Z'), inside = end - 3600;
        ['a', 'b', 'c'].forEach((id, i) => {
            const person = 'kid_' + id;
            f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES(?,?,'child',1,1)", person, person);
            f.store.run(LINK, 'link' + id, person, String(i).repeat(64));
            f.store.run(REQUEST, id, 'link' + id, person, id === 'a' ? 'approved' : 'pending', inside, id === 'a' ? inside : null, inside + 600);
        });
        f.store.run(OP, 'p1', 1, 'k1', inside, inside);
        assert.deepEqual(readDigestPreview(f.config, f.store, end, 'operator').counts, {requests: 3, grants: 1, pauses: 1});
    } finally { f.cleanup(); }
});

test('blocked lookups follow the content-filter mode, the counts flag and the viewer scope', () => {
    const f = integrationFixture();
    try {
        const end = epoch('2026-11-08T23:00:00Z');
        f.config.ownerAccountId = 'operator';
        new ContentFilterCountsStore(f.store).put('pilot', {day: '2026-11-07', state: 'ok', total: 4, blocked: 2, classes: {adult: 2}}, 1);
        const filter = (mode: 'off' | 'owner' | 'parents', counts: boolean) => ({mode, apiKeyFile: '/unused', defaultProfile: 'abcd1234', profiles: {pilot: 'abcd5678'}, counts: {enabled: counts}});
        const blocked = (account: string, canSee?: (person: string) => boolean) => readDigestPreview(f.config, f.store, end, account, {canSee}).blockedLookups;
        f.config.contentFilter = filter('parents', true);
        assert.equal(blocked('operator')?.count, 2);
        assert.equal(blocked('someone-else')?.count, 2, 'parents mode: any admin');
        assert.equal(blocked('operator', person => person === 'pilot')?.count, 2, 'in scope');
        assert.equal(blocked('operator', () => false), undefined, 'a child out of scope omits the household total');
        f.config.contentFilter = filter('owner', true);
        assert.equal(blocked('someone-else'), undefined);
        f.config.contentFilter = filter('off', true);
        assert.equal(blocked('operator'), undefined);
        f.config.contentFilter = filter('parents', false);
        assert.equal(blocked('operator'), undefined);
        f.config.contentFilter = undefined;
        assert.equal(blocked('operator'), undefined);
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
        const before = JSON.stringify(f.store.get('SELECT (SELECT count(*) FROM operations) o, (SELECT count(*) FROM time_requests) t, (SELECT count(*) FROM sqlite_master) m'));
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
        assert.equal(JSON.stringify(f.store.get('SELECT (SELECT count(*) FROM operations) o, (SELECT count(*) FROM time_requests) t, (SELECT count(*) FROM sqlite_master) m')), before);
    } finally {
        server.close();
        await once(server, 'close');
        f.cleanup();
    }
});

test('preview HTTP: a scoped admin gets no blocked total, 401 when signed out, and 503 is no-store', async () => {
    const f = integrationFixture();
    f.advance(epoch('2026-11-08T23:00:00Z') - f.now());
    f.store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES(?,?,'admin',?,?)", 'scopedadmin', 'Scoped admin', '[]', 'scopedadmin-auth-id');
    f.config.digestPreview = {enabled: true};
    f.config.contentFilter = {mode: 'parents', apiKeyFile: '/unused', defaultProfile: 'abcd1234', profiles: {pilot: 'abcd5678'}, counts: {enabled: true}};
    new ContentFilterCountsStore(f.store).put('pilot', {day: '2026-11-07', state: 'ok', total: 4, blocked: 2, classes: {adult: 2}}, 1);
    const { freePort } = await import('./free-port.ts');
    const port = await freePort(), origin = 'http://localhost:' + port;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: 'localhost:' + port});
    server.listen(port, '127.0.0.1');
    await once(server, 'listening');
    try {
        assert.equal((await fetch(origin + '/digest/preview')).status, 401);
        const admin = await signIn(f, origin, 'operator'), scoped = await signIn(f, origin, 'scopedadmin');
        const full = await (await admin('/digest/preview')).json();
        assert.equal(full.blockedLookups.count, 2);
        const limited = await (await scoped('/digest/preview')).json();
        assert.equal(limited.blockedLookups, undefined);
        assert.deepEqual(limited.counts, full.counts);
        f.store.run('DROP TABLE time_requests');
        const failed = await admin('/digest/preview');
        assert.equal(failed.status, 503);
        assert.equal(failed.headers.get('cache-control'), 'no-store');
        assert.equal((await failed.json()).error.code, 'digest_preview_unavailable');
    } finally {
        server.close();
        await once(server, 'close');
        f.cleanup();
    }
});
