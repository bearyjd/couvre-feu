import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { TestAuthenticator } from './authenticator.ts';
import { InventoryStore } from '../src/inventory-store.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import { actor } from './fixtures/integration.ts';

const child = (name = 'Private batch child') => ({action: 'child_create', target: '', params: {name, kind: 'child'}, key: 'http_batch_item_0001'});
let nextPort = 39000 + process.pid % 10000;
async function world() {
    const f = integrationFixture();
    const port = nextPort++, origin = `http://localhost:${port}`;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    const jar = new Map<string, string>(); let csrf = '';
    async function call(path: string, input: unknown, extra: Record<string, string> = {}, omit: string[] = []) {
        const headers: Record<string, string> = {Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), 'X-CSRF-Token': csrf, 'Content-Type': 'application/json', ...extra};
        for (const key of omit) delete headers[key];
        const response = await fetch(origin + path, {method: 'POST', headers, body: JSON.stringify(input)});
        for (const entry of response.headers.getSetCookie()) { const [key, value] = entry.split(';')[0].split('='); jar.set(key, value); }
        const body = await response.json();
        if (body.csrfToken) csrf = body.csrfToken;
        return {status: response.status, body};
    }
    async function signIn(account = 'operator') {
        const key = new TestAuthenticator(), token = issueOperatorBootstrap(f.store, account, f.now());
        const o = await call('/auth/register/options', {token}); assert.equal(o.status, 200);
        assert.equal((await call('/auth/register/verify', {challengeId: o.body.challengeId, response: key.register(o.body.options, origin)})).status, 200);
        return key;
    }
    async function proof(key: TestAuthenticator, clientKey: string, items = [child()]) {
        const o = await call('/step-up/options', {action: 'child_batch', clientKey, precondition: null, items});
        assert.equal(o.status, 200, JSON.stringify(o.body));
        return {challengeId: o.body.challengeId, response: key.login(o.body.options, origin)};
    }
    return {...f, auth, origin, call, signIn, proof, cleanup: async () => {server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); f.cleanup();}};
}

test('HTTP batch: options branches before ordinary child actions and Idempotency-Key is bound to the exact list', async () => {
    const f = await world();
    try {
        const key = await f.signIn(), clientKey = 'http_batch_client_0001', items = [child()], stepUp = await f.proof(key, clientKey);
        const mismatch = await f.call('/admin/children/batch', {items, precondition: null, stepUp}, {'Idempotency-Key': 'http_batch_client_0002'});
        assert.equal(mismatch.status, 403); assert.equal(mismatch.body.error.code, 'step_up_mismatch');
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM people')!.n, 1);
        const result = await f.call('/admin/children/batch', {items, precondition: null, stepUp: await f.proof(key, clientKey)}, {'Idempotency-Key': clientKey});
        assert.equal(result.status, 200); assert.equal(result.body.results[0].status, 'saved'); assert.ok(result.body.batchId);
        const replay = await f.call('/admin/children/batch', {items, precondition: null, stepUp: await f.proof(key, clientKey)}, {'Idempotency-Key': clientKey});
        assert.equal(replay.status, 200); assert.deepEqual(replay.body, result.body);
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM people')!.n, 2);
    } finally { await f.cleanup(); }
});

test('HTTP batch: missing Idempotency-Key, unknown body field and missing step-up are refused', async () => {
    const f = await world();
    try {
        const key = await f.signIn(), clientKey = 'http_batch_client_0001', items = [child()], stepUp = await f.proof(key, clientKey);
        const missing = await f.call('/admin/children/batch', {items, precondition: null, stepUp});
        assert.equal(missing.status, 400); assert.equal(missing.body.error.code, 'idempotency_key_required');
        const injected = await f.call('/admin/children/batch', {items, precondition: null, stepUp, clientKey}, {'Idempotency-Key': clientKey});
        assert.equal(injected.status, 400);
        const noProof = await f.call('/admin/children/batch', {items, precondition: null}, {'Idempotency-Key': clientKey});
        assert.equal(noProof.status, 400);
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM people')!.n, 1);
    } finally { await f.cleanup(); }
});

test('HTTP batch: origin, session and CSRF gates cover options and execution', async () => {
    const f = await world();
    try {
        await f.signIn();
        for (const path of ['/step-up/options', '/admin/children/batch']) {
            const input = path === '/step-up/options' ? {action: 'child_batch', clientKey: 'http_batch_client_0001', items: [child()], precondition: null} : {items: [child()], precondition: null, stepUp: {}};
            for (const [headers, omit] of [[{Origin: 'https://elsewhere.invalid'}, []], [{}, ['X-CSRF-Token']], [{}, ['Cookie']]] as const) {
                const r = await f.call(path, input, headers, [...omit]);
                assert.ok([401, 403].includes(r.status), `${path}: ${r.status}`);
            }
        }
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM people')!.n, 1);
    } finally { await f.cleanup(); }
});

test('HTTP batch: item cap, forbidden action and 64KiB body cap apply before changes', async () => {
    const f = await world();
    try {
        await f.signIn();
        const items = Array.from({length: 41}, (_, n) => ({...child(), key: `http_batch_item_${String(n).padStart(4, '0')}`}));
        const oversized = await f.call('/step-up/options', {action: 'child_batch', clientKey: 'http_batch_client_0001', precondition: null, items});
        assert.equal(oversized.status, 400); assert.equal(oversized.body.error.code, 'max_batch_items');
        for (const action of ['account_role', 'device_remove', 'device_move', 'pause_all']) {
            const r = await f.call('/step-up/options', {action: 'child_batch', clientKey: 'http_batch_client_0001', precondition: null, items: [{...child(), target: 'pilot', action}]});
            assert.equal(r.status, 400); assert.equal(r.body.error.code, 'invalid_action');
        }
        const huge = await f.call('/admin/children/batch', {items: [child('x'.repeat(65537))], precondition: null, stepUp: {}}, {'Idempotency-Key': 'http_batch_client_0001'});
        assert.equal(huge.status, 413); assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM people')!.n, 1);
    } finally { await f.cleanup(); }
});

test('HTTP batch: parent account cannot obtain options or execute', async () => {
    const f = await world();
    try {
        await f.signIn('parent');
        const options = await f.call('/step-up/options', {action: 'child_batch', clientKey: 'http_batch_client_0001', precondition: null, items: [child()]});
        assert.equal(options.status, 403); assert.equal(options.body.error.code, 'admin_required');
        const execute = await f.call('/admin/children/batch', {items: [child()], precondition: null, stepUp: {}}, {'Idempotency-Key': 'http_batch_client_0001'});
        assert.equal(execute.status, 403); assert.equal(execute.body.error.code, 'admin_required');
    } finally { await f.cleanup(); }
});

test('HTTP batch: ready device with a new child queues one composed policy and settles after dispatch', async () => {
    const f = await world();
    try {
        const key = await f.signIn(), address = '02:aa:00:00:00:01'; await f.observe();
        (f.config as {routerScope?: string[]}).routerScope = [f.config.person.device.mac, address];
        new InventoryStore(f.store, new ParentAlerts(f.store, null, f.now), f.now).ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), truncated: false, errors: [], devices: [{mac: address, ipv4: ['192.168.1.20'], hostname: null, source: 'lease'}]});
        const items = [child(), {action: 'device_add', target: '@0', params: {label: 'Private test device', mac: address}, key: 'http_batch_item_0002'}];
        const precondition = f.policy.people(actor).revisionToken, clientKey = 'http_batch_device_0001';
        const o = await f.call('/step-up/options', {action: 'child_batch', clientKey, precondition, items}); assert.equal(o.status, 200);
        const result = await f.call('/admin/children/batch', {precondition, items, stepUp: {challengeId: o.body.challengeId, response: key.login(o.body.options, f.origin)}}, {'Idempotency-Key': clientKey});
        assert.equal(result.status, 200); assert.deepEqual(result.body.results.map((r: {status: string}) => r.status), ['saved', 'queued']);
        const plan = f.worker.prepare('apply', result.body.operation.id); await f.worker.execute(plan, plan.scriptSha256);
        assert.equal(f.store.get<{state: string}>('SELECT state FROM devices WHERE identifier=?', address)!.state, 'active');
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
    } finally { await f.cleanup(); }
});
