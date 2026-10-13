import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth } from '../src/auth.ts';
import { appServer } from '../src/http.ts';

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
