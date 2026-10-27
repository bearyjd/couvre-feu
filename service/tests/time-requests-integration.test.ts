import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import { TestAuthenticator } from './authenticator.ts';

let runs = 0;
/** Starts the real-integration HTTP server; returns how many 5 s time-request timers it armed. */
async function run(enabled: boolean | undefined, body: (origin: string, timers: number[]) => Promise<void>) {
    const f = integrationFixture(), port = 38000 + process.pid % 10000 + runs++, origin = `http://localhost:${port}`, host = `localhost:${port}`;
    const config = {...f.config, port, origin, host, ...(enabled === undefined ? {} : {timeRequests: {enabled}})};
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const timers: number[] = [], original = globalThis.setInterval;
    globalThis.setInterval = ((handler: () => void, ms?: number, ...args: unknown[]) => { if (ms === 5000) timers.push(ms); return original(handler, ms, ...args); }) as typeof setInterval;
    const server = appServer(auth, f.policy, config);
    try {
        server.listen(port, '127.0.0.1'); await once(server, 'listening');
        await body(origin, timers);
    } finally {
        globalThis.setInterval = original;
        server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
        f.cleanup();
    }
}
const post = (origin: string, path: string, body: unknown) => fetch(origin + path, {method: 'POST', headers: {'Content-Type': 'application/json', origin}, body: JSON.stringify(body)});

for (const enabled of [undefined, false]) test(`integration time requests are off ${enabled === undefined ? 'by default' : 'when the manifest says false'}: no child routes, no page, no timer`, async () => {
    await run(enabled, async (origin, timers) => {
        const token = 'a'.repeat(43);
        for (const path of ['/child/status', '/child/request']) {
            const response = await post(origin, path, {token, minutes: 15});
            assert.equal(response.status, 404, path);
            assert.equal(((await response.json()) as {error: {code: string}}).error.code, 'route_not_found');
        }
        assert.equal((await fetch(`${origin}/request.html`)).status, 404);
        assert.equal((await fetch(`${origin}/request.js`)).status, 404);
        assert.equal((await fetch(`${origin}/time-requests`, {headers: {origin}})).status, 401, 'authenticated routes are not mounted either; nothing is served');
        assert.deepEqual(timers, []);
    });
});

test('integration time requests mount only when the manifest enables them', async () => {
    await run(true, async (origin, timers) => {
        const response = await post(origin, '/child/status', {token: 'a'.repeat(43)});
        assert.equal(response.status, 404);
        assert.equal(((await response.json()) as {error: {code: string}}).error.code, 'link_invalid', 'the route exists and rejects an unknown link');
        assert.equal((await fetch(`${origin}/request.html`)).status, 200);
        assert.equal(timers.length, 1);
    });
});

test('after time requests are switched off, owed restores still drain and then the timer stops', async () => {
    const f = integrationFixture(), port = 38000 + process.pid % 10000 + runs++, origin = `http://localhost:${port}`, host = `localhost:${port}`;
    const person = f.config.person.id, now = f.now();
    // State left behind by an approval made while the flag was on: pause lifted, restore owed, allowance over.
    f.store.run('INSERT INTO request_links(id,person_id,token_hash,created_by,created_at,revoked_at,revoked_by) VALUES(?,?,?,?,?,?,?)', 'link-1', person, 'h'.repeat(64), 'parent', now - 2000, now - 100, 'parent');
    f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at,decided_by,decided_at,granted_minutes,allowance_until,original_pause_until,repause_state) VALUES('req-1','link-1',?,15,'','approved',?,?,'parent',?,15,?,0,'waiting')", person, now - 1500, now - 600, now - 1000, now - 10);
    const calls: string[] = [];
    const policy = {
        people: () => ({people: [{id: person, manualPause: null}], revisionToken: '"s1-r1-x"'}),
        mutate: (_actor: unknown, who: string, action: string) => { calls.push(`${who}:${action}`); return {status: 200, result: {operation: {id: 'op-1', revision: 5, state: 'confirmed'}}}; },
        now: f.now, devices: () => ({}), operation: () => ({}), reconcile: () => undefined,
    };
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const ticks: (() => unknown)[] = [], cleared: unknown[] = [], realSet = globalThis.setInterval, realClear = globalThis.clearInterval;
    globalThis.setInterval = ((handler: () => unknown, ms?: number, ...args: unknown[]) => { if (ms === 5000) { ticks.push(handler); return {unref() {}} as unknown as NodeJS.Timeout; } return realSet(handler, ms, ...args); }) as typeof setInterval;
    globalThis.clearInterval = ((handle: never) => { cleared.push(handle); return realClear(handle); }) as typeof clearInterval;
    const server = appServer(auth, policy as never, {...f.config, port, origin, host});
    try {
        server.listen(port, '127.0.0.1'); await once(server, 'listening');
        assert.equal(ticks.length, 1, 'a drain-only timer is armed because a restore is owed');
        assert.equal((await post(origin, '/child/status', {token: 'a'.repeat(43)})).status, 404, 'no routes are mounted');
        await ticks[0]();
        assert.deepEqual(calls, [`${person}:pause`], 'the lifted pause is restored');
        assert.equal(f.store.get<{repause_state: string}>("SELECT repause_state FROM time_requests WHERE id='req-1'")!.repause_state, 'done');
        await new Promise(resolve => setImmediate(resolve));
        assert.ok(cleared.length >= 1, 'the drain timer stops once nothing is owed');
        await ticks[0]();
        assert.equal(calls.length, 1);
    } finally {
        globalThis.setInterval = realSet; globalThis.clearInterval = realClear;
        server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
        f.cleanup();
    }
});

/** Per-account gate: a pending request exists; each of owner / other parent / admin asks the parent routes and the alert feed. */
async function gated(timeRequests: unknown, ownerAccountId: string | undefined, body: (who: (account: string) => Promise<(path: string, input?: unknown) => Promise<{status: number; body: Record<string, any>}>>, ctx: {origin: string; timers: number[]; requestId: string}) => Promise<void>) {
    const f = integrationFixture(), port = 38000 + process.pid % 10000 + runs++, origin = `http://localhost:${port}`, host = `localhost:${port}`;
    const person = f.config.person.id, now = f.now(), requestId = '11111111-1111-4111-8111-111111111111';
    f.store.run('INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES(?,?,?,?,?)', 'parent2', 'Second parent', 'parent', JSON.stringify([person]), 'w'.repeat(43));
    f.store.run('INSERT INTO request_links(id,person_id,token_hash,created_by,created_at) VALUES(?,?,?,?,?)', 'link-1', person, 'b'.repeat(64), 'parent', now - 100);
    f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at) VALUES(?,?,?,15,'','pending',?,?)", requestId, 'link-1', person, now - 50, now + 3000);
    const alerts = new ParentAlerts(f.store, null, f.now);
    alerts.reconcile({now, timeRequests: [{person, requestId, createdAt: now - 50}]});
    const config = {...f.config, port, origin, host, timeRequests, ...(ownerAccountId === undefined ? {} : {ownerAccountId})};
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const timers: number[] = [], original = globalThis.setInterval;
    globalThis.setInterval = ((handler: () => void, ms?: number, ...args: unknown[]) => { if (ms === 5000) timers.push(ms); return original(handler, ms, ...args); }) as typeof setInterval;
    const server = appServer(auth, f.policy, config as never, alerts);
    const who = async (account: string) => {
        const cookies = new Map<string, string>(); let csrf = '';
        const call = async (path: string, input?: unknown) => {
            const response = await fetch(origin + path, {method: input === undefined ? 'GET' : 'POST', headers: {Origin: origin, Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; '), ...(csrf ? {'X-CSRF-Token': csrf} : {}), ...(input === undefined ? {} : {'Content-Type': 'application/json'})}, ...(input === undefined ? {} : {body: JSON.stringify(input)})});
            for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); cookies.set(k, v); }
            return {status: response.status, body: await response.json() as Record<string, any>};
        };
        const key = new TestAuthenticator(), options = await call('/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
        const verified = await call('/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, origin)});
        assert.equal(verified.status, 200); csrf = verified.body.csrfToken;
        return call;
    };
    try {
        server.listen(port, '127.0.0.1'); await once(server, 'listening');
        await body(who, {origin, timers, requestId});
    } finally {
        globalThis.setInterval = original;
        server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
        f.cleanup();
    }
}
const kinds = (r: {body: Record<string, any>}) => r.body.alerts.map((a: {kind: string}) => a.kind);

test("mode 'owner': only the owner account sees and decides requests and their alert; other parents and admins get nothing; child routes and timer stay on", async () => {
    await gated({mode: 'owner'}, 'parent', async (who, {origin, timers, requestId}) => {
        const owner = await who('parent'), other = await who('parent2'), admin = await who('operator');
        const ownView = await owner('/time-requests'); assert.equal(ownView.status, 200); assert.equal(ownView.body.requests.length, 1);
        assert.deepEqual(kinds(await owner('/alerts')), ['time_request_pending']);
        for (const denied of [other, admin]) {
            const view = await denied('/time-requests'); assert.equal(view.status, 404); assert.equal(view.body.error.code, 'route_not_found');
            assert.equal((await denied(`/time-requests/${requestId}/decline`, {})).status, 404);
            assert.equal((await denied(`/time-requests/${requestId}/approve`, {minutes: 15})).status, 404);
            assert.equal((await denied('/people/pilot/request-link', {})).status, 404);
            const feed = await denied('/alerts'); assert.equal(feed.status, 200); assert.ok(!kinds(feed).includes('time_request_pending')); assert.equal(feed.body.openCount, 0);
            const id = (await owner('/alerts')).body.alerts[0].id;
            assert.equal((await denied(`/alerts/${id}/acknowledge`, {})).status, 404, 'the alert cannot be acknowledged by an account that cannot see it');
        }
        const child = await post(origin, '/child/status', {token: 'a'.repeat(43)});
        assert.equal(((await child.json()) as {error: {code: string}}).error.code, 'link_invalid', 'child routes are mounted');
        assert.equal(timers.length, 1);
        const declined = await owner(`/time-requests/${requestId}/decline`, {}); assert.equal(declined.status, 200);
    });
});

test("mode 'parents' (and legacy enabled:true): every parent and admin sees requests and the alert", async () => {
    for (const timeRequests of [{mode: 'parents'}, {enabled: true}]) await gated(timeRequests, undefined, async who => {
        for (const account of ['parent', 'parent2', 'operator']) {
            const call = await who(account);
            assert.equal((await call('/time-requests')).status, 200, account);
            assert.deepEqual(kinds(await call('/alerts')), ['time_request_pending'], account);
        }
    });
});

test("mode 'off': parent routes 404, the request alert is hidden from everyone, no timer", async () => {
    await gated({mode: 'off'}, undefined, async (who, {origin, timers}) => {
        const call = await who('parent');
        assert.equal((await call('/time-requests')).status, 404);
        assert.ok(!kinds(await call('/alerts')).includes('time_request_pending'));
        assert.equal((await post(origin, '/child/status', {token: 'a'.repeat(43)})).status, 404);
        assert.deepEqual(timers, []);
    });
});
