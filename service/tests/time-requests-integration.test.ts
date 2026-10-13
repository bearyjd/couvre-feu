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
