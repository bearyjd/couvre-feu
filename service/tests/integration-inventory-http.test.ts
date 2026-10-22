import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { TestAuthenticator } from './authenticator.ts';
import type { InventoryDevice } from '../../shared/src/router-inventory.ts';

const m = (n: number) => `00:00:5e:00:00:${n.toString(16).padStart(2, '0')}`;
const dev = (n: number, over: Partial<InventoryDevice> = {}): InventoryDevice => ({mac: m(n), ipv4: [`192.0.2.${n}`], hostname: `host-${n}`, source: 'both', ...over});

let worlds = 0;
async function world(opts: {automatic?: boolean} = {}) {
    const f = integrationFixture(), port = 26000 + (process.pid + 7 * worlds++) % 9000, origin = `http://localhost:${port}`;
    if (opts.automatic) f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
    const automatic = opts.automatic ? new AutomaticDispatch(f.worker) : null;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`}, undefined, undefined, undefined, f.worker.inventory);
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    async function client(account: string) {
        const cookies = new Map<string, string>(); let csrf = '';
        const call = async (path: string, input?: unknown, headers: Record<string, string> = {}, method = input === undefined ? 'GET' : 'POST') => {
            const response = await fetch(origin + path, {method, headers: {Origin: origin, Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; '), ...(csrf ? {'X-CSRF-Token': csrf} : {}), ...(input === undefined ? {} : {'Content-Type': 'application/json'}), ...headers}, ...(input === undefined ? {} : {body: JSON.stringify(input)})});
            for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); cookies.set(k, v); }
            return {status: response.status, body: await response.json() as Record<string, any>};
        };
        const key = new TestAuthenticator(), options = await call('/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
        const verified = await call('/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, origin)});
        assert.equal(verified.status, 200); csrf = verified.body.csrfToken;
        return Object.assign(call, {dropCsrf: () => { csrf = ''; }});
    }
    const close = async () => { const closed = once(server, 'close'); server.close(); server.closeAllConnections(); await closed; await automatic?.stop(); f.cleanup(); };
    const seed = () => { const poll = (d: InventoryDevice[]) => f.worker.inventory.ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices: d, truncated: false, errors: []}, f.now()); poll([dev(1)]); f.advance(60); poll([dev(1), dev(2, {hostname: null})]); };
    return {...f, client, close, origin, seed};
}

test('admin lists the inventory: flags, hostnames as device-reported strings, no protected MAC', async () => {
    const w = await world();
    try {
        w.seed();
        w.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'both',1,1)", w.config.router.generation, w.config.protectedMacs[0]);
        const admin = await w.client('operator'), r = await admin('/admin/inventory');
        assert.equal(r.status, 200); assert.equal(r.body.source, 'real-router-integration');
        const devices = r.body.inventory.devices as {mac: string; hostname: string | null; reportedByDevice: boolean; flags: Record<string, boolean>}[];
        assert.deepEqual(devices.map(d => d.mac).sort(), [m(1), m(2)]);
        const one = devices.find(d => d.mac === m(1))!, two = devices.find(d => d.mac === m(2))!;
        assert.equal(one.hostname, 'host-1'); assert.equal(one.reportedByDevice, true); assert.equal(typeof one.hostname, 'string'); assert.equal(two.hostname, null);
        assert.deepEqual(two.flags, {new: true, private: false, unassigned: true});
        assert.equal(r.body.inventory.status.pollSeconds, 60);
        assert.ok(!JSON.stringify(r.body).includes(w.config.protectedMacs[0]));
    } finally { await w.close(); }
});
test('a parent is refused (403) on the list, acknowledge and refresh; nothing changes', async () => {
    const w = await world({automatic: true});
    try {
        w.seed();
        const parent = await w.client('parent');
        for (const [path, body] of [['/admin/inventory'], ['/admin/inventory/acknowledge', {mac: m(2)}], ['/admin/inventory/refresh', {}]] as [string, unknown?][]) {
            const r = await parent(path, body); assert.equal(r.status, 403, path); assert.equal(r.body.error.code, 'admin_required');
            assert.ok(!JSON.stringify(r.body).includes('host-'));
        }
        assert.equal(w.store.get<{a: number | null}>('SELECT acknowledged_at a FROM inventory_devices WHERE mac=?', m(2))!.a, null);
        assert.equal(w.store.get<{p: number}>('SELECT refresh_pending p FROM inventory_state')!.p, 0);
    } finally { await w.close(); }
});
test('unauthenticated requests are refused and POSTs need Origin and CSRF', async () => {
    const w = await world({automatic: true});
    try {
        w.seed();
        const anon = await fetch(w.origin + '/admin/inventory'); assert.equal(anon.status, 401);
        const admin = await w.client('operator');
        assert.equal((await admin('/admin/inventory/acknowledge', {mac: m(2)}, {Origin: 'http://evil.example'})).status, 403);
        admin.dropCsrf(); assert.equal((await admin('/admin/inventory/refresh', {})).status, 403);
        assert.equal((await admin('/admin/inventory', undefined, {}, 'DELETE')).status, 405);
    } finally { await w.close(); }
});
test('acknowledge: strict input, 404 for an unknown MAC, clears New', async () => {
    const w = await world();
    try {
        w.seed();
        const admin = await w.client('operator');
        for (const body of [{}, {mac: 5}, {mac: m(2), extra: 1}, {mac: m(2).toUpperCase()}, {mac: 'nope'}, []]) assert.equal((await admin('/admin/inventory/acknowledge', body)).status, 400, JSON.stringify(body));
        assert.equal((await admin('/admin/inventory/acknowledge', {mac: m(77)})).status, 404);
        const ok = await admin('/admin/inventory/acknowledge', {mac: m(2)});
        assert.equal(ok.status, 200); assert.equal(ok.body.device.flags.new, false);
        assert.equal((await admin('/admin/inventory')).body.inventory.devices.find((d: {mac: string}) => d.mac === m(2)).flags.new, false);
    } finally { await w.close(); }
});
test('refresh: 409 when dispatch is off, otherwise 202 once per 10 s (429), and it never opens SSH', async () => {
    const off = await world();
    try { const admin = await off.client('operator'); const r = await admin('/admin/inventory/refresh', {}); assert.equal(r.status, 409); assert.equal(r.body.error.code, 'inventory_dispatch_disabled'); } finally { await off.close(); }
    const w = await world({automatic: true});
    try {
        const admin = await w.client('operator');
        assert.equal((await admin('/admin/inventory/refresh', {a: 1})).status, 400);
        const first = await admin('/admin/inventory/refresh', {}); assert.equal(first.status, 202);
        const second = await admin('/admin/inventory/refresh', {}); assert.equal(second.status, 429); assert.equal(second.body.error.code, 'inventory_refresh_rate_limited');
        w.advance(10); assert.equal((await admin('/admin/inventory/refresh', {})).status, 202);
        assert.equal(w.router.calls.length, 0);
    } finally { await w.close(); }
});
test('integration-main wires the store, the retention and a periodic prune (and keeps the literal ParentAlerts wiring)', () => {
    const main = readFileSync(new URL('../src/integration-main.ts', import.meta.url), 'utf8');
    assert.match(main, /new ParentAlerts\(store, null\)/);
    assert.match(main, /inventoryRetentionDays\(\)/);
    assert.match(main, /worker\.inventory/);
    assert.match(main, /inventory\.prune\(\)/);
});
