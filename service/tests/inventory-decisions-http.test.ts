import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { wireIntegration } from '../src/integration-wiring.ts';
import { TestAuthenticator } from './authenticator.ts';
import type { InventoryDevice } from '../../shared/src/router-inventory.ts';

const m = (n: number) => `00:00:5e:00:00:${n.toString(16).padStart(2, '0')}`;
const dev = (n: number, over: Partial<InventoryDevice> = {}): InventoryDevice => ({mac: m(n), ipv4: [`192.0.2.${n}`], hostname: `host-${n}`, source: 'both', ...over});

async function freePort(): Promise<number> {
    const probe = createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const {port} = probe.address() as AddressInfo; probe.close(); await once(probe, 'close');
    return port;
}
async function world(opts: {automatic?: boolean; triage?: boolean} = {}) {
    const f = integrationFixture();
    if (opts.triage !== false) f.config.inventoryUi = {triage: true, wizard: false, installReadiness: false};
    f.config.auditLog = {enabled: true};
    const port = await freePort(), origin = `http://localhost:${port}`;
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


const rowId = (w: Awaited<ReturnType<typeof world>>, mac: string) => w.store.get<{id: number}>('SELECT rowid id FROM inventory_devices WHERE mac=?', mac)!.id;

test('classify, undo, link, unlink and stable over HTTP: bodies, DTO and audit', async () => {
    const w = await world();
    try {
        w.seed();
        const admin = await w.client('operator'), b = rowId(w, m(2)), a = rowId(w, m(1));
        const list = await admin('/admin/inventory');
        assert.equal(list.body.inventory.newCount, 1); assert.equal(list.body.inventory.hiddenCount, 0);
        const c = await admin(`/admin/inventory/${b}/classify`, {role: 'home', label: 'Kitchen TV'});
        assert.equal(c.status, 200); assert.equal(c.body.source, 'real-router-integration');
        assert.equal(c.body.device.role, 'home'); assert.equal(c.body.device.label, 'Kitchen TV'); assert.equal(c.body.device.id, b);
        assert.equal((await admin('/admin/inventory')).body.inventory.newCount, 0);
        assert.equal((await admin(`/admin/inventory/${b}/undo`, {})).body.device.role, 'new');
        const l = await admin(`/admin/inventory/${b}/link`, {replaces: a});
        assert.equal(l.status, 200); assert.equal(l.body.device.linkedFrom, a);
        const u = await admin(`/admin/inventory/${b}/link`, undefined, {}, 'DELETE');
        assert.equal(u.status, 200); assert.equal(u.body.device.linkedFrom, undefined);
        const s = await admin(`/admin/inventory/${b}/stable`, {value: true});
        assert.equal(s.status, 200); assert.equal(s.body.device.stableConfirmed, true);
        assert.deepEqual(w.store.all<{action: string}>('SELECT action FROM parent_audit ORDER BY id').map(r => r.action), ['inventory_classify', 'inventory_undo', 'inventory_link', 'inventory_unlink', 'inventory_stable']);
        const old = await admin('/admin/inventory/acknowledge', {mac: m(2)});
        assert.equal(old.status, 200); assert.equal(old.body.device.role, 'new');
    } finally { await w.close(); }
});

test('bodies are strict and ids are bounded; unknown and protected ids answer the same 404', async () => {
    const w = await world();
    try {
        w.seed();
        w.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'both',1,1)", w.config.router.generation, w.config.protectedMacs[0]);
        const admin = await w.client('operator'), b = rowId(w, m(2)), prot = rowId(w, w.config.protectedMacs[0]);
        const bad: [string, unknown][] = [[`/admin/inventory/${b}/classify`, {}], [`/admin/inventory/${b}/classify`, {role: 'home', extra: 1}], [`/admin/inventory/${b}/classify`, {role: 'home', mac: m(2)}],
            [`/admin/inventory/${b}/classify`, {role: 'bogus'}], [`/admin/inventory/${b}/classify`, {role: 'home', label: 'x'.repeat(41)}], [`/admin/inventory/${b}/undo`, {x: 1}],
            [`/admin/inventory/${b}/link`, {}], [`/admin/inventory/${b}/link`, {replaces: '1'}], [`/admin/inventory/${b}/link`, {replaces: b}], [`/admin/inventory/${b}/link`, {replaces: 1, mac: m(1)}],
            [`/admin/inventory/${b}/stable`, {}], [`/admin/inventory/${b}/stable`, {value: 'yes'}], [`/admin/inventory/${b}/stable`, {value: true, extra: 1}]];
        for (const [path, body] of bad) { const r = await admin(path, body); assert.equal(r.status, 400, `${path} ${JSON.stringify(body)}`); }
        const missing = await admin('/admin/inventory/99999/classify', {role: 'home'}), protectedRow = await admin(`/admin/inventory/${prot}/classify`, {role: 'adult'});
        assert.equal(missing.status, 404); assert.deepEqual(protectedRow.body.error, missing.body.error); assert.equal(missing.body.error.code, 'inventory_device_not_found');
        for (const path of ['/admin/inventory/0/classify', '/admin/inventory/01/classify', '/admin/inventory/abc/classify', '/admin/inventory/99999999999/classify', `/admin/inventory/${b}/other`, `/admin/inventory/${b}`]) {
            const r = await admin(path, {role: 'home'}); assert.equal(r.status, 404, path); assert.equal(r.body.error.code, 'route_not_found');
        }
        assert.equal(w.store.get<{n: number}>('SELECT count(*) n FROM inventory_decisions')!.n, 0);
    } finally { await w.close(); }
});

test('parents get 403 on every decision route, CSRF and Origin are enforced, nothing changes', async () => {
    const w = await world();
    try {
        w.seed();
        const parent = await w.client('parent'), admin = await w.client('operator'), b = rowId(w, m(2));
        const calls: [string, unknown, string][] = [[`/admin/inventory/${b}/classify`, {role: 'home'}, 'POST'], [`/admin/inventory/${b}/undo`, {}, 'POST'], [`/admin/inventory/${b}/link`, {replaces: 1}, 'POST'],
            [`/admin/inventory/${b}/link`, undefined, 'DELETE'], [`/admin/inventory/${b}/stable`, {value: true}, 'POST'], ['/admin/inventory/hidden', undefined, 'GET']];
        for (const [path, body, method] of calls) { const r = await parent(path, body, {}, method); assert.equal(r.status, 403, `${method} ${path}`); assert.equal(r.body.error.code, 'admin_required'); }
        for (const [path, body, method] of calls.slice(0, 5)) { const r = await admin(path, body, {Origin: 'http://evil.example'}, method); assert.equal(r.status, 403); assert.equal(r.body.error.code, 'origin_rejected', `${method} ${path}`); }
        // no Origin at all (the global check only compares a header that is present)
        for (const [path, body, method] of calls.slice(0, 5)) { const r = await admin(path, body, {Origin: ''}, method); assert.equal(r.status, 403); assert.equal(r.body.error.code, 'origin_rejected', `no origin ${method} ${path}`); }
        admin.dropCsrf();
        for (const [path, body, method] of calls.slice(0, 5)) { const r = await admin(path, body, {}, method); assert.equal(r.status, 403, `csrf ${method} ${path}`); }
        assert.equal(w.store.get<{n: number}>('SELECT count(*) n FROM inventory_decisions')!.n, 0);
    } finally { await w.close(); }
});

test('GET /admin/inventory/hidden lists auto-hidden guests; the default list leaves them out', async () => {
    const w = await world();
    try {
        w.seed();
        w.worker.inventory.classify(actor, rowId(w, m(2)), 'guest');
        w.advance(15 * 86400); w.worker.inventory.ingest({inventory_version: 1, generation: w.config.router.generation, routerTime: w.now(), devices: [dev(1)], truncated: false, errors: []}, w.now());
        const admin = await w.client('operator');
        const normal = await admin('/admin/inventory'), all = await admin('/admin/inventory/hidden');
        assert.equal(normal.body.inventory.devices.length, 1); assert.equal(normal.body.inventory.hiddenCount, 1);
        assert.equal(all.status, 200); assert.equal(all.body.inventory.devices.length, 2);
    } finally { await w.close(); }
});

test('triage off: the old routes behave as before and the new routes do not exist', async () => {
    const w = await world({triage: false});
    try {
        w.seed();
        const admin = await w.client('operator'), b = rowId(w, m(2));
        const list = await admin('/admin/inventory');
        assert.equal(list.status, 200); assert.ok(!('newCount' in list.body.inventory)); assert.ok(!('role' in list.body.inventory.devices[0]));
        assert.equal((await admin('/admin/inventory/acknowledge', {mac: m(2)})).status, 200);
        for (const [path, body] of [[`/admin/inventory/${b}/classify`, {role: 'home'}], [`/admin/inventory/${b}/undo`, {}], [`/admin/inventory/${b}/link`, {replaces: 1}], [`/admin/inventory/${b}/stable`, {value: true}]] as [string, unknown][]) {
            const r = await admin(path, body); assert.equal(r.status, 404, path); assert.equal(r.body.error.code, 'route_not_found');
        }
        const del = await admin(`/admin/inventory/${b}/link`, undefined, {}, 'DELETE'); assert.equal(del.status, 405); assert.equal(del.body.error.code, 'method_not_allowed');
        const hidden = await admin('/admin/inventory/hidden'); assert.equal(hidden.status, 404);
        // an authenticated parent, flag off: same as today's unknown POST
        const parent = await w.client('parent');
        const refused = await parent(`/admin/inventory/${b}/classify`, {role: 'home'}); assert.equal(refused.status, 404); assert.equal(refused.body.error.code, 'route_not_found');
        assert.equal(w.store.get<{n: number}>('SELECT count(*) n FROM inventory_decisions')!.n, 0);
    } finally { await w.close(); }
});

test('privacy over HTTP: a label never reaches stdout, stderr, audit or alerts, on success or on a refused body', async () => {
    const writes: string[] = [], real = {out: process.stdout.write, err: process.stderr.write};
    const w = await world();
    try {
        w.seed();
        const admin = await w.client('operator'), b = rowId(w, m(2));
        process.stdout.write = ((chunk: unknown) => { writes.push(String(chunk)); return true; }) as typeof process.stdout.write; process.stderr.write = process.stdout.write;
        const ok = await admin(`/admin/inventory/${b}/classify`, {role: 'home', label: 'SecretLabel'});
        const bad = await admin(`/admin/inventory/${b}/classify`, {role: 'home', label: 'SecretLabel<b>'});
        const extra = await admin(`/admin/inventory/${b}/classify`, {role: 'home', label: 'SecretLabel', hostname: 'secrethost'});
        process.stdout.write = real.out; process.stderr.write = real.err;
        assert.equal(ok.status, 200); assert.equal(bad.status, 400); assert.equal(extra.status, 400);
        for (const refused of [bad, extra]) assert.ok(!JSON.stringify(refused.body).includes('SecretLabel') && !JSON.stringify(refused.body).includes('secrethost'));
        const dump = JSON.stringify([writes, w.store.all('SELECT * FROM audit'), w.store.all('SELECT * FROM parent_audit'), w.store.all('SELECT * FROM parent_alerts')]);
        assert.ok(!dump.includes('SecretLabel') && !dump.includes('secrethost') && !dump.includes(m(2)));
    } finally { process.stdout.write = real.out; process.stderr.write = real.err; await w.close(); }
});

test('DELETE: unauthenticated is 401 whatever the flag says; flag off with a valid session and CSRF is a 405, not a crash', async () => {
    for (const triage of [true, false]) {
        const w = await world({triage});
        try {
            w.seed();
            const b = rowId(w, m(2)), anonymous = await fetch(`${w.origin}/admin/inventory/${b}/link`, {method: 'DELETE', headers: {Origin: w.origin}});
            assert.equal(anonymous.status, 401, `triage ${triage}`);
            const admin = await w.client('operator'), r = await admin(`/admin/inventory/${b}/link`, undefined, {}, 'DELETE');
            assert.equal(r.status, triage ? 200 : 405); if (!triage) assert.equal(r.body.error.code, 'method_not_allowed');
        } finally { await w.close(); }
    }
});
