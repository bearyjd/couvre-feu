import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { InstallReadiness, readinessDigest, canonical, decisions, QUIET_SECONDS } from '../src/install-readiness.ts';
import { digest as sha256 } from '../src/auth.ts';
import { TestAuthenticator } from './authenticator.ts';
import type { InventoryDevice } from '../../shared/src/router-inventory.ts';

const PILOT_MAC = '02:10:20:30:40:50';
const STABLE_MAC = '00:00:5e:00:00:10';
const dev = (mac: string, hostname: string | null, n: number, source: InventoryDevice['source'] = 'both'): InventoryDevice => ({mac, ipv4: [`192.0.2.${n}`], hostname, source});
const MAC_ANYWHERE = /[0-9a-f]{2}(:[0-9a-f]{2}){5}/i;

async function freePort(): Promise<number> {
    const probe = createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const port = (probe.address() as {port: number}).port;
    await new Promise<void>(resolve => probe.close(() => resolve()));
    return port;
}
async function world(options: {enabled?: boolean} = {}) {
    const f = integrationFixture(), port = await freePort(), origin = `http://localhost:${port}`;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const readiness = options.enabled === false ? undefined : new InstallReadiness(auth, f.worker.inventory);
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`}, undefined, undefined, undefined, f.worker.inventory, undefined, readiness);
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    const poll = (devices: InventoryDevice[]) => f.worker.inventory.ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices, truncated: false, errors: []}, f.now());
    async function client(account: string) {
        const jar = new Map<string, string>(); let csrf = '';
        const call = async (method: string, path: string, input?: unknown, omit: string[] = [], extra: Record<string, string> = {}) => {
            const headers: Record<string, string> = {Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), 'X-CSRF-Token': csrf, 'Content-Type': 'application/json', ...extra};
            for (const key of omit) delete headers[key];
            const response = await fetch(origin + path, {method, headers, ...(input === undefined ? {} : {body: JSON.stringify(input)})});
            for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); jar.set(k, v); }
            const text = await response.text(), body = JSON.parse(text) as Record<string, any>;
            if (body.csrfToken) csrf = body.csrfToken;
            return {status: response.status, body, text};
        };
        const key = new TestAuthenticator(), options = await call('POST', '/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
        assert.equal((await call('POST', '/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, origin)})).status, 200);
        const challenge = async (digest: string) => {
            const o = await call('POST', '/step-up/options', {action: 'install_list_approve', digest});
            assert.equal(o.status, 200, o.text);
            return {challengeId: o.body.challengeId, response: key.login(o.body.options, origin)};
        };
        return {call, challenge, get: () => call('GET', '/admin/install-readiness'), approve: (digest: string, stepUp?: unknown) => call('POST', '/admin/install-readiness/approve', stepUp === undefined ? {digest} : {digest, stepUp}),
            exportList: (digest: string) => call('POST', '/admin/install-readiness/export', {digest})};
    }
    const audit = () => f.store.all<Record<string, unknown>>("SELECT * FROM audit WHERE action LIKE 'install_list_%' ORDER BY id").map(r => ({...r}));
    const cleanup = async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); f.cleanup(); };
    return {...f, auth, client, poll, audit, cleanup, origin};
}
const err = (r: {status: number; body: Record<string, any>}, status: number, code: string) => { assert.equal(r.status, status, JSON.stringify(r.body)); assert.equal(r.body.error?.code, code); };

test('digest is stable across key order and list order, and changes with the list', () => {
    const a = {children: [{id: 'a', name: 'A', devices: [{mac: 'x', label: 'p', stable: true, inScope: true, enrolled: true}, {mac: 'y', label: 'q', stable: false, inScope: false, enrolled: false}]}], adults: []};
    const b = {adults: [], children: [{id: 'a', devices: [{enrolled: true, inScope: true, stable: true, label: 'p', mac: 'x'}, {enrolled: false, inScope: false, stable: false, label: 'q', mac: 'y'}], name: 'A'}]};
    assert.equal(readinessDigest(a), readinessDigest(b));
    assert.match(readinessDigest(a), /^[0-9a-f]{64}$/);
    const c = {...a, children: [{id: 'a', name: 'A', devices: [{mac: 'x', label: 'p', stable: false, inScope: true, enrolled: true}, a.children[0].devices[1]]}]};
    assert.notEqual(readinessDigest(a), readinessDigest(c));
});

test('admin reads the list: enrolled child devices, adapter adults, vendor and presence hints, a stable digest', async () => {
    const w = await world();
    try {
        w.config.routerScope = [PILOT_MAC];
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20), dev(STABLE_MAC, 'x', 21)]);
        const admin = await w.client('operator'), r = await admin.get();
        assert.equal(r.status, 200, r.text);
        assert.equal(r.body.source, 'real-router-integration');
        const child = r.body.children.find((c: any) => c.name === 'Explicit test person');
        assert.deepEqual(child.devices.map((d: any) => ({label: d.label, mac: d.mac, stable: d.stable, inScope: d.inScope, enrolled: d.enrolled, presence: d.presence})),
            [{label: 'Explicit test device', mac: PILOT_MAC, stable: false, inScope: true, enrolled: true, presence: 'online'}]);
        // adults come from the protected baseline; the GET never carries their addresses
        assert.deepEqual(r.body.adults.map((a: any) => ({...a})), [{label: 'Protected device', vendor: null, stable: false, inScope: r.body.adults[0].inScope, enrolled: false, presence: 'unknown'}]);
        assert.equal(r.body.adultsSource, 'protected-baseline'); assert.equal(r.body.adultsAvailable, true);
        assert.ok(!r.text.includes(w.config.protectedMacs[0]), 'GET carries no protected MAC');
        assert.equal((await admin.call('GET', '/people')).body.installReadiness, true); // the page's one gate; admins only
        assert.match(r.body.digest, /^[0-9a-f]{64}$/);
        assert.equal(r.body.reviewedAt, null);
        // presence moves every poll; the digest must not
        w.advance(60); w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        assert.equal((await admin.get()).body.digest, r.body.digest);
        // a changed list does
        w.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d2','pilot','Tablet','mac',?, 'active',1)", STABLE_MAC);
        assert.notEqual((await admin.get()).body.digest, r.body.digest);
    } finally { await w.cleanup(); }
});

test('warnings: unconfirmed private address, quiet over 7 days, child with no device', async () => {
    const w = await world();
    try {
        w.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES('empty','Empty child','child',1,1)");
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        const admin = await w.client('operator');
        let r = await admin.get();
        const codes = (body: Record<string, any>) => body.warnings.map((x: any) => x.code).sort();
        assert.deepEqual(codes(r.body), ['child_no_device', 'private_address_unconfirmed']);
        assert.deepEqual(r.body.warnings.find((x: any) => x.code === 'child_no_device'), {code: 'child_no_device', child: 'Empty child', device: null});
        w.store.run('UPDATE inventory_devices SET last_seen=?', w.now() - QUIET_SECONDS - 60); // the session would not outlive a real 7-day advance
        r = await admin.get();
        assert.deepEqual(codes(r.body), ['child_no_device', 'device_quiet', 'private_address_unconfirmed']);
        assert.equal(r.body.children.find((c: any) => c.name === 'Explicit test person').devices[0].presence, 'quiet');
        for (const warning of r.body.warnings) assert.ok(!MAC_ANYWHERE.test(JSON.stringify(warning)), 'warnings never carry a MAC');
        // a non-private address with no warning source
        w.store.run("UPDATE devices SET identifier=? WHERE id='phone'", STABLE_MAC);
        w.poll([dev(STABLE_MAC, 'pilot-phone', 20)]);
        assert.deepEqual(codes((await admin.get()).body), ['child_no_device']);
    } finally { await w.cleanup(); }
});

test('approve: step-up bound to the digest, recorded as an audit row with no MAC, shown as reviewed', async () => {
    const w = await world();
    try {
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        const admin = await w.client('operator'), {body: {digest}} = await admin.get();
        const done = await admin.approve(digest, await admin.challenge(digest));
        assert.equal(done.status, 200, done.text);
        assert.equal(done.body.digest, digest); assert.equal(done.body.approved, true);
        const rows = w.audit();
        assert.equal(rows.length, 1); assert.equal(rows[0].action, 'install_list_reviewed'); assert.equal(rows[0].actor_id, 'operator');
        assert.ok(!MAC_ANYWHERE.test(JSON.stringify(rows)), 'audit rows never carry a MAC');
        assert.equal(typeof (await admin.get()).body.reviewedAt, 'number');
    } finally { await w.cleanup(); }
});

test('approve refusals: no step-up, replayed challenge, mismatched binding, stale digest', async () => {
    const w = await world();
    try {
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        const admin = await w.client('operator'), {body: {digest}} = await admin.get();
        err(await admin.approve(digest), 403, 'step_up_required');
        const proof = await admin.challenge(digest);
        assert.equal((await admin.approve(digest, proof)).status, 200);
        err(await admin.approve(digest, proof), 401, 'invalid_challenge');
        // a challenge bound to the old list cannot approve the new one
        const old = await admin.challenge(digest);
        w.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d2','pilot','Tablet','mac',?, 'active',1)", STABLE_MAC);
        const next = (await admin.get()).body.digest;
        assert.notEqual(next, digest);
        err(await admin.approve(next, old), 403, 'step_up_mismatch');
        err(await admin.approve(digest, await admin.challenge(next)), 409, 'install_list_stale');
        err(await admin.call('POST', '/step-up/options', {action: 'install_list_approve', digest}), 409, 'install_list_stale');
        err(await admin.approve('nope'), 400, 'invalid_digest');
        assert.equal(w.audit().length, 1);
    } finally { await w.cleanup(); }
});

test('export returns the exact list for the current digest and is audited without MACs', async () => {
    const w = await world();
    try {
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        const admin = await w.client('operator'), {body: {digest}} = await admin.get();
        err(await admin.exportList('f'.repeat(64)), 409, 'install_list_stale');
        assert.equal(w.audit().length, 0);
        const r = await admin.exportList(digest);
        assert.equal(r.status, 200, r.text);
        assert.equal(r.body.export.digest, digest);
        assert.equal(r.body.export.children[0].devices[0].mac, PILOT_MAC);
        const rows = w.audit();
        assert.deepEqual(rows.map(x => x.action), ['install_list_exported']);
        assert.ok(!MAC_ANYWHERE.test(JSON.stringify(rows)));
    } finally { await w.cleanup(); }
});

test('admin only, session, Origin and CSRF gates on every route', async () => {
    const w = await world();
    try {
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        const parent = await w.client('parent'), admin = await w.client('operator'), {body: {digest}} = await admin.get();
        err(await parent.get(), 403, 'admin_required');
        err(await parent.call('POST', '/step-up/options', {action: 'install_list_approve', digest}), 403, 'admin_required');
        err(await parent.approve(digest, {challengeId: 'x', response: {}}), 403, 'admin_required');
        err(await parent.exportList(digest), 403, 'admin_required');
        const proof = await admin.challenge(digest);
        for (const [path, body] of [['/admin/install-readiness/approve', {digest, stepUp: proof}], ['/admin/install-readiness/export', {digest}], ['/step-up/options', {action: 'install_list_approve', digest}]] as const) {
            assert.equal((await admin.call('POST', path, body, ['X-CSRF-Token'])).status, 403, `${path} without CSRF`);
            assert.equal((await admin.call('POST', path, body, [], {Origin: 'http://evil.example'})).status, 403, `${path} cross-origin`);
        }
        assert.equal(w.audit().length, 0);
        const anon = await fetch(w.origin + '/admin/install-readiness', {headers: {Origin: w.origin}});
        assert.equal(anon.status, 401);
    } finally { await w.cleanup(); }
});

test('flag off: the routes do not exist', async () => {
    const w = await world({enabled: false});
    try {
        const admin = await w.client('operator');
        assert.equal((await admin.get()).status, 404);
        assert.ok(!('installReadiness' in (await admin.call('GET', '/people')).body));
        assert.notEqual((await admin.call('POST', '/step-up/options', {action: 'install_list_approve', digest: 'a'.repeat(64)})).status, 200);
        assert.equal((await admin.exportList('a'.repeat(64))).status, 404);
        assert.equal(w.audit().length, 0);
    } finally { await w.cleanup(); }
});

test('canonical sorts keys at every depth (removing the sort must fail this)', () => {
    assert.equal(canonical({b: {y: 1, x: [{d: 1, c: 2}]}, a: null}), canonical({a: null, b: {x: [{c: 2, d: 1}], y: 1}}));
    assert.equal(canonical({b: 1, a: 2}), '{"a":2,"b":1}');
});

test('digest binds child ids: two same-name children swapping devices change it; input is versioned', () => {
    const d = (mac: string) => ({mac, label: 'p', stable: true, inScope: true, enrolled: true});
    const one = {children: [{id: 'a', name: 'Sam', devices: [d('x')]}, {id: 'b', name: 'Sam', devices: [d('y')]}], adults: []};
    const swapped = {children: [{id: 'a', name: 'Sam', devices: [d('y')]}, {id: 'b', name: 'Sam', devices: [d('x')]}], adults: []};
    assert.notEqual(readinessDigest(one), readinessDigest(swapped));
    assert.notEqual(readinessDigest(one), sha256(canonical({children: one.children, adults: []})), 'the {v:1} prefix is part of the digest input');
});

test('adults come from protectedMacs: GET has no MACs, export has them; empty set is unavailable and cannot be approved', async () => {
    const w = await world();
    try {
        const admin = await w.client('operator'), protectedMac = w.config.protectedMacs[0];
        const full = await admin.get();
        assert.equal(full.body.adultsAvailable, true); assert.equal(full.body.adults.length, 1); assert.ok(!('mac' in full.body.adults[0]));
        const exported = (await admin.exportList(full.body.digest)).body.export;
        assert.equal(exported.adultsAvailable, true); assert.equal(exported.adultsSource, 'protected-baseline');
        assert.equal(exported.adults[0].mac, protectedMac);
        // the audit trail still holds only the digest
        assert.ok(!JSON.stringify(w.audit()).includes(protectedMac));
        // a new protected MAC changes the digest the approval binds to
        w.config.protectedMacs = [...w.config.protectedMacs, STABLE_MAC];
        const grown = await admin.get();
        assert.notEqual(grown.body.digest, full.body.digest); assert.equal(grown.body.adults.length, 2);
        // none: partial, and the service itself refuses to approve it
        w.config.protectedMacs = [];
        const none = await admin.get();
        assert.equal(none.body.adultsAvailable, false); assert.deepEqual(none.body.adults, []);
        err(await admin.approve(none.body.digest, await admin.challenge(none.body.digest)), 409, 'install_list_incomplete');
        assert.equal(w.audit().filter(r => r.action === 'install_list_reviewed').length, 0);
    } finally { await w.cleanup(); }
});

test('the TODO(D) seam adds extra adults on top of the protected baseline, without duplicates', async () => {
    const w = await world();
    try {
        const admin = await w.client('operator'), real = {...decisions};
        decisions.adultDevices = () => [{label: 'Bryn phone', mac: STABLE_MAC}, {label: 'dup', mac: w.config.protectedMacs[0]}];
        try {
            const r = await admin.get();
            assert.deepEqual(r.body.adults.map((a: any) => a.label).sort(), ['Bryn phone', 'Protected device']);
        } finally { Object.assign(decisions, real); }
    } finally { await w.cleanup(); }
});

test('no inventory row is device_unseen; exactly 7 days is not quiet, 7 days and 1 second is', async () => {
    const w = await world();
    try {
        const admin = await w.client('operator'), codes = async () => (await admin.get()).body.warnings.map((x: any) => x.code).filter((c: string) => c.startsWith('device_'));
        assert.deepEqual(await codes(), ['device_unseen']);
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        assert.deepEqual(await codes(), []);
        w.store.run('UPDATE inventory_devices SET last_seen=?', w.now() - QUIET_SECONDS);
        assert.deepEqual(await codes(), []);
        w.store.run('UPDATE inventory_devices SET last_seen=?', w.now() - QUIET_SECONDS - 1);
        assert.deepEqual(await codes(), ['device_quiet']);
    } finally { await w.cleanup(); }
});

test('the list changing during the passkey step is refused (409) and records nothing', async () => {
    const w = await world();
    try {
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        const admin = await w.client('operator'), {body: {digest}} = await admin.get(), proof = await admin.challenge(digest);
        const verify = w.auth.stepUpVerify.bind(w.auth);
        w.auth.stepUpVerify = async (...args: Parameters<typeof verify>) => {
            const result = await verify(...args);
            w.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d9','pilot','Late','mac',?, 'active',1)", STABLE_MAC);
            return result;
        };
        err(await admin.approve(digest, proof), 409, 'install_list_stale');
        assert.equal(w.audit().length, 0);
    } finally { await w.cleanup(); }
});

test('an admin demoted during the passkey step is refused and records nothing', async () => {
    const w = await world();
    try {
        w.poll([dev(PILOT_MAC, 'pilot-phone', 20)]);
        const admin = await w.client('operator'), {body: {digest}} = await admin.get(), proof = await admin.challenge(digest);
        const verify = w.auth.stepUpVerify.bind(w.auth);
        w.auth.stepUpVerify = async (...args: Parameters<typeof verify>) => {
            const result = await verify(...args);
            w.store.run("UPDATE accounts SET role='parent' WHERE id='operator'");
            return result;
        };
        err(await admin.approve(digest, proof), 403, 'admin_required');
        assert.equal(w.audit().length, 0);
    } finally { await w.cleanup(); }
});
