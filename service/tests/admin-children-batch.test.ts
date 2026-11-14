import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { InventoryStore } from '../src/inventory-store.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import type { InventorySource } from '../../shared/src/router-inventory.ts';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { Auth, digest, issueOperatorBootstrap } from '../src/auth.ts';
import { ChildBatchAdmin } from '../src/admin-children-batch.ts';
import { AppError } from '../../shared/src/errors.ts';
import { ChildAdmin } from '../src/admin-children.ts';
import { BulkOps } from '../src/integration-bulk.ts';
import { TestAuthenticator } from './authenticator.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { Store as PreviousStore } from './fixtures/previous-store.ts';
import { join } from 'node:path';
import { OBSERVATION_FRESH_SECONDS } from '../src/integration-policy.ts';

const origin = 'http://localhost:4273';
const SEED = '02:10:20:30:40:50', PROTECTED = '02:10:20:30:40:51';
const mac = (n: number) => `02:aa:00:00:${Math.floor(n / 256).toString(16).padStart(2, '0')}:${(n % 256).toString(16).padStart(2, '0')}`;
type Item = {action: string; target: string; params: Record<string, unknown>; key: string};
const itemKey = (n: number) => `batch_item_key_${String(n).padStart(4, '0')}`;
const create = (n = 0, name = `Private child ${n}`, kind = 'child'): Item => ({action: 'child_create', target: '', params: {name, kind}, key: itemKey(n)});
const add = (n: number, target = 'pilot', address = mac(n)): Item => ({action: 'device_add', target, params: {label: `Private device ${n}`, mac: address}, key: itemKey(n)});
const rename = (n: number, target = 'pilot', name = 'Private renamed child'): Item => ({action: 'child_rename', target, params: {name}, key: itemKey(n)});

function world() {
    const f = integrationFixture();
    f.config.auditLog = {enabled: true};
    (f.config as {routerScope?: string[]}).routerScope = [SEED, ...Array.from({length: 400}, (_, n) => mac(n))];
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance});
    const batch = new ChildBatchAdmin(auth, f.policy);
    async function signIn(account = 'operator') {
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, account, f.now())}, browser);
        const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, session: () => auth.session(result.token, browser)};
    }
    type Who = Awaited<ReturnType<typeof signIn>>;
    async function anotherSession(who: Who) {
        const browser = randomBytes(32).toString('base64url'), o = await auth.loginOptions({}, browser);
        const result = await auth.loginVerify({challengeId: o.challengeId, response: who.key.login(o.options, origin)}, browser);
        return {key: who.key, session: () => auth.session(result.token, browser)};
    }
    const inventory = new InventoryStore(f.store, new ParentAlerts(f.store, null, f.now), f.now);
    function ready(addresses: string[], source: InventorySource = 'both', age = 0) {
        const at = f.now() - age;
        inventory.ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: at, truncated: false, errors: [],
            devices: addresses.filter(m => !f.config.protectedMacs.includes(m)).sort().map(m => ({mac: m, ipv4: ['192.168.1.20'], hostname: null, source}))}, at);
    }
    async function options(who: Who, items: Item[], clientKey = 'batch_client_key_0001', precondition: string | null = items.some(i => i.action === 'device_add') ? f.policy.people(actor).revisionToken : null) {
        return batch.stepUpOptions(who.session(), {action: 'child_batch', clientKey, precondition, items});
    }
    async function proof(who: Who, items: Item[], clientKey = 'batch_client_key_0001', precondition: string | null = items.some(i => i.action === 'device_add') ? f.policy.people(actor).revisionToken : null) {
        const o = await options(who, items, clientKey, precondition);
        return {challengeId: o.challengeId, response: who.key.login(o.options, origin)};
    }
    async function perform(who: Who, items: Item[], clientKey = 'batch_client_key_0001', precondition: string | null = items.some(i => i.action === 'device_add') ? f.policy.people(actor).revisionToken : null) {
        const binding = digest(JSON.stringify(['child_admin_batch', 1, clientKey, precondition, items]));
        const o = await auth.stepUpChallenge(who.session(), binding, true);
        return batch.perform(who.session(), {items, precondition, stepUp: {challengeId: o.challengeId, response: who.key.login(o.options, origin)}}, clientKey);
    }
    const count = (table: string) => f.store.get<{n: number}>(`SELECT count(*) n FROM ${table}`)!.n;
    const token = () => {
        const o = f.store.observation().value!, highwater = f.store.get<{highwater: number}>('SELECT highwater FROM service_state')!.highwater;
        return `"s${highwater}-r${o.acceptedPolicy.revision}-${o.policyDigest}"`;
    };
    const dispatch = async (id: string) => { const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256); };
    return {...f, auth, batch, inventory, signIn, anotherSession, ready, options, proof, perform, count, token, dispatch};
}
type World = ReturnType<typeof world>;
type BatchBody = {batchId: string; results: {index: number; key: string; status: string; childId?: string; deviceId?: string}[]; operation?: {id: string}};
const body = (r: {body: unknown}) => r.body as BatchBody;
async function refuses(work: Promise<unknown>, code: string, failedIndex?: number) {
    let error: {code?: string; failedIndex?: number; key?: string} | undefined;
    try {
        const result = await work as {status: number; body: {error?: typeof error}};
        assert.ok(result.status >= 400, `expected ${code}, received success`);
        error = result.body.error;
    } catch (caught) {
        if (caught instanceof assert.AssertionError) throw caught;
        error = caught as typeof error;
    }
    assert.equal(error?.code, code);
    if (failedIndex !== undefined) assert.equal(error?.failedIndex, failedIndex);
}
function unchanged(f: World) { assert.equal(f.count('people'), 1); assert.equal(f.count('devices'), 1); assert.equal(f.count('operations'), 0); assert.equal(f.count('scope_requests'), 0); }
function spent(f: World, challenge: {challengeId: string}) { assert.equal(f.store.get<{consumed: number}>('SELECT consumed FROM step_ups WHERE id=?', challenge.challengeId)?.consumed, 1); }

test('batch: 3 creates and 6 adds use one assertion, one revision and one operation; every device settles', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready(Array.from({length: 6}, (_, n) => mac(n + 3)));
        const items = [create(0), create(1), create(2), ...Array.from({length: 6}, (_, n) => add(n + 3, `@${Math.floor(n / 2)}`))];
        let result: Awaited<ReturnType<typeof f.perform>> | undefined;
        await assert.doesNotReject(async () => { result = await f.perform(who, items); });
        assert.ok(result); assert.equal(result.status, 200);
        const b = body(result);
        assert.equal(who.key.counter, 1); assert.equal(b.results.length, 9);
        assert.deepEqual(b.results.map(r => [r.index, r.key, r.status]), items.map((i, n) => [n, i.key, n < 3 ? 'saved' : 'queued']));
        assert.equal(f.count('operations'), 1); assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM devices WHERE state='enrolling'")!.n, 6);
        const op = f.store.get<{revision: number; payload_json: string; idempotency_key: string}>('SELECT * FROM operations')!;
        assert.equal(op.revision, 1); assert.equal(JSON.parse(op.payload_json).revision, 1); assert.notEqual(op.idempotency_key, 'batch_client_key_0001');
        assert.equal(f.count('operation_people'), 3); assert.equal(f.policy.people(who.session().dto.actor).revisionToken, null);
        await f.dispatch(b.operation!.id);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM devices WHERE state='active'")!.n, 7);
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
    } finally { f.cleanup(); }
});

test('batch: local create and rename need no router observation, precondition or operation', async () => {
    const f = world();
    try {
        const who = await f.signIn();
        let result: Awaited<ReturnType<typeof f.perform>> | undefined;
        let queueCalls = 0;
        f.policy.queue = () => { queueCalls++; assert.fail('local-only batch called policy.queue'); };
        await assert.doesNotReject(async () => { result = await f.perform(who, [create(), rename(1, '@0', 'Final private name'), rename(2)]); });
        assert.ok(result); assert.equal(queueCalls, 0);
        assert.equal(result.status, 200); assert.equal(f.count('operations'), 0); assert.equal(f.router.calls.length, 0);
        assert.equal(f.store.get<{name: string}>('SELECT name FROM people WHERE id=?', body(result).results[0].childId!)!.name, 'Final private name');
        assert.equal(f.store.get<{name: string}>("SELECT name FROM people WHERE id='pilot'")!.name, 'Private renamed child');
    } finally { f.cleanup(); }
});

test('batch: canonical ordered items and client key are committed into the authenticator challenge', async () => {
    const f = world();
    try {
        const who = await f.signIn(), items = [create(0, '  Cafe\u0301  ')];
        const o = await f.options(who, items);
        const canonical = [{action: 'child_create', target: '', params: {name: 'Café', kind: 'child'}, key: itemKey(0)}];
        assert.deepEqual(o.items, canonical); assert.equal(o.bindingVersion, 1);
        assert.equal(o.binding, digest(JSON.stringify(['child_admin_batch', 1, 'batch_client_key_0001', null, canonical])));
        assert.equal(o.options.challenge, createHash('sha256').update(o.binding + o.nonce).digest('base64url'));
    } finally { f.cleanup(); }
});

for (const mutation of ['params', 'reorder', 'extra', 'omit', 'precondition', 'clientKey']) test(`batch binding refuses ${mutation}, consumes proof and applies nothing`, async () => {
    const f = world();
    try {
        const who = await f.signIn(), items = [create(0), create(1)], stepUp = await f.proof(who, items);
        const changed = structuredClone(items);
        if (mutation === 'params') changed[0].params.name = 'Substituted';
        if (mutation === 'reorder') changed.reverse();
        if (mutation === 'extra') changed.push(create(2));
        if (mutation === 'omit') changed.pop();
        const precondition = mutation === 'precondition' ? '"s0-r0-' + 'a'.repeat(64) + '"' : null;
        await refuses(f.batch.perform(who.session(), {items: changed, precondition, stepUp}, mutation === 'clientKey' ? 'batch_client_key_0002' : 'batch_client_key_0001'), 'step_up_mismatch');
        spent(f, stepUp); unchanged(f);
    } finally { f.cleanup(); }
});

for (const kind of ['same_account_session', 'other_account', 'expired', 'replay']) test(`batch proof isolation: ${kind}`, async () => {
    const f = world();
    try {
        const who = await f.signIn(), items = [create()], stepUp = await f.proof(who, items);
        let other = who;
        if (kind === 'same_account_session') other = await f.anotherSession(who);
        if (kind === 'other_account') { f.store.run("UPDATE accounts SET role='admin',scope_all=1 WHERE id='parent'"); other = await f.signIn('parent'); }
        if (kind === 'expired') f.advance(121);
        if (kind === 'replay') await f.batch.perform(who.session(), {items, precondition: null, stepUp}, 'batch_client_key_0001');
        await refuses(f.batch.perform(other.session(), {items, precondition: null, stepUp}, 'batch_client_key_0001'), kind === 'expired' || kind === 'replay' ? 'invalid_challenge' : 'step_up_mismatch');
        if (kind !== 'replay') unchanged(f); else assert.equal(f.count('people'), 2);
    } finally { f.cleanup(); }
});

test('batch: single and bulk proofs cannot authorize batches and batch proof cannot authorize a single change', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); const single = new ChildAdmin(f.auth, f.policy), bulk = new BulkOps(f.auth, f.policy);
        const s = await single.stepUpOptions(who.session(), {action: 'child_create', target: '', params: {name: 'Private child 0'}});
        await refuses(f.batch.perform(who.session(), {items: [create()], precondition: null, stepUp: {challengeId: s.challengeId, response: who.key.login(s.options, origin)}}, 'batch_client_key_0001'), 'step_up_mismatch');
        const b = await bulk.stepUpOptions(who.session(), {action: 'pause_all', params: {until: 0, precondition: f.policy.people(actor).revisionToken}});
        await refuses(f.batch.perform(who.session(), {items: [create()], precondition: null, stepUp: {challengeId: b.challengeId, response: who.key.login(b.options, origin)}}, 'batch_client_key_0002'), 'step_up_mismatch');
        await refuses(single.perform(who.session(), 'child_create', '', {name: 'Private child 0', stepUp: await f.proof(who, [create()])}), 'step_up_mismatch'); unchanged(f);
    } finally { f.cleanup(); }
});

for (const scenario of ['missing', 'scope', 'stale_coverage', 'stale_poll', 'wrong_generation', 'empty_address', 'future']) test(`batch ready-only refuses ${scenario} atomically without scope requests`, async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        if (scenario === 'missing') f.store.run('DELETE FROM inventory_devices');
        if (scenario === 'scope') (f.config as {routerScope?: string[]}).routerScope = [SEED];
        if (scenario === 'stale_coverage') f.store.run('UPDATE inventory_coverage SET observed_at=?', f.now() - 31);
        if (scenario === 'stale_poll') f.store.run('UPDATE inventory_state SET last_ok_at=?', f.now() - 31);
        if (scenario === 'wrong_generation') f.store.run('UPDATE inventory_devices SET generation=?', 'e'.repeat(64));
        if (scenario === 'empty_address') f.store.run("UPDATE inventory_devices SET ipv4_json='[]'");
        if (scenario === 'future') f.store.run('UPDATE inventory_coverage SET observed_at=?', f.now() + 2);
        await refuses(f.perform(who, [create(0), add(1, '@0')]), 'device_not_ready', 1); unchanged(f);
        assert.equal(f.count('admin_batches'), 1, 'consumed semantic refusal is durably idempotent');
    } finally { f.cleanup(); }
});

test('batch: ready state is rechecked between options and commit, including a scope-pending device', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const items = [create(0), add(1, '@0')], precondition = f.policy.people(actor).revisionToken, stepUp = await f.proof(who, items);
        f.advance(31); await f.observe();
        await refuses(f.batch.perform(who.session(), {items, precondition, stepUp}, 'batch_client_key_0001'), 'device_not_ready', 1); spent(f, stepUp); unchanged(f);
        f.ready([mac(1)]); (f.config as {routerScope?: string[]}).routerScope = [SEED];
        new ChildAdmin(f.auth, f.policy).scope.request(who.session().dto.actor, 'pilot', mac(1));
        await refuses(f.perform(who, [add(1)], 'batch_client_key_0002'), 'device_not_ready', 0); assert.equal(f.count('scope_requests'), 1);
    } finally { f.cleanup(); }
});

test('batch: fresh lease-only address at the 30-second boundary is ready', async () => {
    const f = world();
    try { const who = await f.signIn(); await f.observe(); f.ready([mac(1)], 'lease', 30); assert.equal((await f.perform(who, [add(1)])).status, 200); }
    finally { f.cleanup(); }
});

test('batch: item five duplicate rolls back earlier children/devices and preserves failed index/key', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(3), mac(4), SEED]);
        const items = [create(0), create(1), create(2), add(3, '@0'), add(4, '@1'), add(5, '@2', SEED)];
        await refuses(f.perform(who, items), 'device_already_enrolled', 5); unchanged(f);
        const stored = f.store.get<{result_json: string}>('SELECT result_json FROM admin_batches')!.result_json;
        assert.ok(stored.includes(itemKey(5))); assert.ok(stored.includes('device_already_enrolled'));
    } finally { f.cleanup(); }
});

for (const scenario of ['duplicate_mac', 'protected_mac', 'forward', 'wrong_ref', 'duplicate_key', 'forbidden_action']) test(`batch: rejects ${scenario}`, async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1), PROTECTED]);
        let items = [add(1), add(2, 'pilot', mac(1))]; let expected = 'device_already_enrolled';
        if (scenario === 'protected_mac') { items = [add(1, 'pilot', PROTECTED)]; expected = 'device_mac_protected'; }
        if (scenario === 'forward') { items = [add(1, '@1'), create(2)]; expected = 'invalid_batch_reference'; }
        if (scenario === 'wrong_ref') { items = [rename(0), add(1, '@0')]; expected = 'invalid_batch_reference'; }
        if (scenario === 'duplicate_key') { items = [create(0), create(0)]; expected = 'duplicate_item_key'; }
        if (scenario === 'forbidden_action') { items = [{...create(), action: 'device_remove', target: 'pilot'}]; expected = 'invalid_action'; }
        await refuses(f.perform(who, items), expected); unchanged(f);
    } finally { f.cleanup(); }
});

test('batch: reference to a created device group assigns to that group', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const r = await f.perform(who, [create(0, 'Shared devices', 'device_group'), add(1, '@0')]);
        const group = body(r).results[0].childId!;
        assert.equal(f.store.get<{kind: string}>('SELECT kind FROM people WHERE id=?', group)!.kind, 'device_group');
        assert.equal(f.store.get<{person_id: string}>('SELECT person_id FROM devices WHERE identifier=?', mac(1))!.person_id, group);
    } finally { f.cleanup(); }
});

test('batch: idempotency returns stored success/refusal after a fresh proof; different payload conflicts', async () => {
    const f = world();
    try {
        const who = await f.signIn(), items = [create()]; await f.observe();
        let first: Awaited<ReturnType<typeof f.perform>> | undefined, replay: Awaited<ReturnType<typeof f.perform>> | undefined;
        await assert.doesNotReject(async () => { first = await f.perform(who, items); replay = await f.perform(who, items); });
        assert.ok(first); assert.ok(replay);
        assert.deepEqual(replay, first); assert.equal(f.count('people'), 2); assert.equal(f.count('admin_batches'), 1);
        await refuses(f.perform(who, [create(0, 'Different name')]), 'idempotency_payload_conflict');
        f.advance(61); await f.observe(); f.ready([mac(1)]);
        (f.config as {routerScope?: string[]}).routerScope = [SEED];
        await refuses(f.perform(who, [add(1)], 'batch_client_refusal_1'), 'device_not_ready', 0);
        (f.config as {routerScope?: string[]}).routerScope = [SEED, mac(1)];
        await refuses(f.perform(who, [add(1)], 'batch_client_refusal_1'), 'device_not_ready', 0);
        assert.equal(f.count('operations'), 0);
    } finally { f.cleanup(); }
});

test('batch: fourth options issue is rate limited without inserting another step-up', async () => {
    const f = world();
    try {
        const who = await f.signIn(); for (let i = 0; i < 3; i++) await f.options(who, [create()], `batch_client_rate_${i}`);
        const n = f.count('step_ups'); await refuses(f.options(who, [create()], 'batch_client_rate_4'), 'batch_rate_limited'); assert.equal(f.count('step_ups'), n);
        f.advance(61); assert.ok((await f.options(who, [create()])).challengeId);
    } finally { f.cleanup(); }
});

test('batch: parent role, stale permission and existing out-of-scope child cannot authorize changes', async () => {
    const f = world();
    try {
        const parent = await f.signIn('parent'); await refuses(f.options(parent, [create()]), 'admin_required');
        const who = await f.signIn(), items = [rename(0)], stepUp = await f.proof(who, items), frozen = who.session();
        f.store.run("UPDATE accounts SET person_ids='[]',scope_all=0 WHERE id='operator'");
        await refuses(f.batch.perform(frozen, {items, precondition: null, stepUp}, 'batch_client_key_0001'), 'person_not_found');
        assert.equal(f.store.get<{name: string}>("SELECT name FROM people WHERE id='pilot'")!.name, 'Explicit test person');
        await refuses(f.perform(who, [create()], 'batch_client_key_0002'), 'scope_all_required');
    } finally { f.cleanup(); }
});

test('batch: limits accumulate across items and refuse the entire batch', async t => {
    for (const scenario of ['children', 'per_child', 'system']) await t.test(scenario, async () => {
        const f = world();
        try {
            const who = await f.signIn();
            if (scenario === 'children') {
                for (let n = 0; n < 62; n++) f.store.run("INSERT INTO people(id,name,created_at) VALUES(?,?,0)", `kid${n}`, `Existing ${n}`);
                await refuses(f.perform(who, [create(0), create(1), create(2)]), 'child_limit_reached', 1); assert.equal(f.count('people'), 63);
            } else {
                if (scenario === 'system') for (let n = 0; n < 8; n++) f.store.run("INSERT INTO people(id,name,created_at) VALUES(?,?,0)", `kid${n}`, `Existing ${n}`);
                const total = scenario === 'per_child' ? 30 : 253;
                for (let n = 0; n < total; n++) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',0)", `d_existing_${n}`, scenario === 'per_child' ? 'pilot' : `kid${Math.floor(n / 32)}`, 'Existing', mac(1000 + n));
                await f.observe(); f.ready([mac(1), mac(2), mac(3)]);
                const o = f.store.observation().value!, highwater = f.store.get<{highwater: number}>('SELECT highwater FROM service_state')!.highwater;
                const token = `"s${highwater}-r${o.acceptedPolicy.revision}-${o.policyDigest}"`;
                await refuses(f.perform(who, [add(1), add(2), add(3)], 'batch_client_limit_0001', token), scenario === 'per_child' ? 'child_device_limit_reached' : 'device_limit_reached', scenario === 'per_child' ? 1 : 2);
                assert.equal(f.count('devices'), total + 1); assert.equal(f.count('operations'), 0);
            }
        } finally { f.cleanup(); }
    });
});

test('batch: audit stores one row per child and operation, contains no private labels, MACs or proofs', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(2), mac(3), mac(4)]);
        const r = await f.perform(who, [create(0), create(1), add(2, '@0'), add(3, '@0'), add(4, '@1')]);
        const rows = f.store.all<{person_id: string; operation_id: string}>('SELECT * FROM parent_audit');
        assert.equal(rows.length, 2); assert.equal(new Set(rows.map(r => r.person_id)).size, 2);
        assert.ok(rows.every(row => row.operation_id === body(r).operation!.id));
        const adminRows = f.store.all<{outcome: string; operation_id: string}>("SELECT outcome,operation_id FROM audit WHERE action LIKE 'admin_%'");
        assert.equal(adminRows.length, 2, 'one general admin audit row per touched child');
        assert.deepEqual(adminRows.map(row => row.outcome.match(/devices:(\d+)$/)?.[1]).sort(), ['1', '2']);
        assert.ok(adminRows.every(row => row.operation_id === body(r).operation!.id));
        const audit = JSON.stringify([...rows, ...f.store.all('SELECT * FROM audit')]);
        for (const forbidden of ['Private child', 'Private device', mac(2), mac(3), mac(4), 'clientDataJSON', 'authenticatorData']) assert.ok(!audit.includes(forbidden), forbidden);
        assert.deepEqual(f.store.all<{name: string}>("SELECT name FROM pragma_table_info('parent_audit')").map(c => c.name), ['id', 'at', 'actor_id', 'action', 'person_id', 'operation_id', 'result']);
    } finally { f.cleanup(); }
});

test('batch: pre-write router rejection removes every staged device, keeps children and permits a new-key retry', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(2), mac(3)]);
        const r = await f.perform(who, [create(0), create(1), add(2, '@0'), add(3, '@1')]);
        f.router.reject = 'incomplete_address_coverage'; await f.dispatch(body(r).operation!.id);
        assert.equal(f.count('devices'), 1); assert.equal(f.count('people'), 3);
        const a = new ChildAdmin(f.auth, f.policy).list(who.session().dto.actor).lastRejection;
        assert.equal(a?.devices.length, 3, 'seed and both batch devices remain explainable after rollback');
        f.router.reject = null; f.advance(1); await f.observe(); f.ready([mac(2), mac(3)]);
        const retried = await f.perform(who, [add(2, body(r).results[0].childId!), add(3, body(r).results[1].childId!)], 'batch_client_retry_0002');
        assert.equal(retried.status, 200); assert.equal(f.count('operations'), 2);
    } finally { f.cleanup(); }
});

test('batch: first-run completion refuses later setup with confirmed nonseed devices, including options', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const r = await f.perform(who, [create(0), add(1, '@0')]); await f.dispatch(body(r).operation!.id);
        await refuses(f.options(who, [create()], 'batch_client_later_01'), 'batch_setup_completed');
        assert.equal(f.store.get<{setup_completed: number}>('SELECT setup_completed FROM admin_batch_setup WHERE singleton=1')!.setup_completed, 1);
    } finally { f.cleanup(); }
});

test('batch: tables stay additive, but migration 014 raises the version so the pre-014 binary refuses the database', () => {
    const f = world();
    try {
        assert.equal(f.store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 13);
        assert.equal(f.count('people'), 1); assert.equal(f.count('devices'), 1);
        const sql = f.store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='admin_batches'")!.sql;
        assert.match(sql, /UNIQUE\s*\(actor_id,\s*client_key\)/i);
        assert.equal(f.store.all('PRAGMA foreign_key_check').length, 0);
        const old = readFileSync(new URL('../migrations/013.sql', import.meta.url), 'utf8');
        assert.ok(old.includes("'device_assign'")); assert.equal(f.count('parent_audit'), 0);
        // 014 (content filtering) rebuilds parent_audit, like 010-013 before it: the binary from before it cannot open a database that has run it.
        assert.throws(() => new PreviousStore(join(f.dir, 'integration.sqlite'), undefined, 'integration'), /unsupported_database_version/);
    } finally { f.cleanup(); }
});

test('batch: a complete lease poll refreshes coverage without neighbour last_seen and omission removes readiness', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)], 'lease');
        f.store.run('UPDATE inventory_devices SET last_seen=?', f.now() - 86400);
        f.ready([mac(1)], 'lease');
        assert.equal(f.store.get<{last_seen: number}>('SELECT last_seen FROM inventory_devices')!.last_seen, f.now() - 86400);
        assert.ok((await f.options(who, [add(1)])).challengeId);
        f.ready([]);
        await refuses(f.options(who, [add(1)], 'batch_client_absent_01'), 'device_not_ready');
        unchanged(f);
    } finally { f.cleanup(); }
});

for (const failure of ['incomplete', 'failed']) test(`batch: ${failure} inventory poll invalidates prior ready addresses`, async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const items = [add(1)], precondition = f.policy.people(actor).revisionToken, stepUp = await f.proof(who, items);
        if (failure === 'failed') f.inventory.recordFailure('inventory_unavailable:test');
        else f.inventory.ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices: [], truncated: true, errors: []});
        await refuses(f.batch.perform(who.session(), {items, precondition, stepUp}, 'batch_client_key_0001'), 'device_not_ready', 0); unchanged(f);
    } finally { f.cleanup(); }
});

test('batch: worker conflicts settle every device under its own child id', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(2), mac(3)]);
        const r = await f.perform(who, [create(0), create(1), add(2, '@0'), add(3, '@1')]);
        f.router.afterApply = () => { f.router.policy = normalizePolicy({...f.router.policy, revision: f.router.policy.revision + 1}); };
        await f.dispatch(body(r).operation!.id);
        assert.equal(f.store.get<{state: string}>('SELECT state FROM operations')!.state, 'conflict');
        assert.deepEqual(f.store.all<{identifier: string; state: string}>('SELECT identifier,state FROM devices WHERE identifier IN (?,?) ORDER BY identifier', mac(2), mac(3)).map(r => [r.identifier, r.state]), [[mac(2), 'active'], [mac(3), 'active']]);
    } finally { f.cleanup(); }
});

test('batch: pending removal and moving rows cannot reopen first-run after router confirmation', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const r = await f.perform(who, [create(0), add(1, '@0')]); await f.dispatch(body(r).operation!.id);
        for (const state of ['removing', 'moving']) {
            f.store.run('UPDATE devices SET state=?,move_to=? WHERE identifier=?', state, state === 'moving' ? 'pilot' : null, mac(1));
            await refuses(f.options(who, [create()], `batch_client_gate_${state}`), 'batch_setup_completed');
            await refuses(f.perform(who, [create()], `batch_client_exec_${state}`), 'batch_setup_completed');
        }
        assert.equal(f.count('people'), 2);
    } finally { f.cleanup(); }
});

test('batch: matching lost-response retry still works after router-confirmed first run and stale inventory', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const items = [create(0), add(1, '@0')], precondition = f.policy.people(actor).revisionToken;
        const first = await f.perform(who, items); await f.dispatch(body(first).operation!.id); f.advance(31);
        const stepUp = await f.proof(who, items, 'batch_client_key_0001', precondition);
        const again = await f.batch.perform(who.session(), {items, precondition, stepUp}, 'batch_client_key_0001');
        assert.deepEqual(again, first); assert.equal(f.count('operations'), 1); assert.equal(f.count('people'), 2);
    } finally { f.cleanup(); }
});

test('batch: rename-only setup records completion and seed-only fresh policy permits continuing setup', async () => {
    const f = world();
    try {
        const who = await f.signIn(); assert.equal((await f.perform(who, [rename(0)])).status, 200);
        assert.equal(f.store.get<{setup_completed: number}>('SELECT setup_completed FROM admin_batch_setup')?.setup_completed, 1);
        assert.equal(f.count('parent_audit'), 0); assert.equal(f.store.all("SELECT id FROM audit WHERE action LIKE 'admin_%'").length, 1);
        await refuses(f.options(who, [create()], 'batch_client_stale_rename'), 'batch_setup_completed');
        await f.observe();
        assert.equal((await f.perform(who, [create()], 'batch_client_after_rename')).status, 200);
    } finally { f.cleanup(); }
});

test('batch: local creates without devices have no parent assignment audit', async () => {
    const f = world();
    try {
        const who = await f.signIn(); assert.equal((await f.perform(who, [create()])).status, 200);
        assert.equal(f.count('parent_audit'), 0);
        const rows = f.store.all<{outcome: string}>("SELECT outcome FROM audit WHERE action LIKE 'admin_%'");
        assert.equal(rows.length, 1); assert.match(rows[0].outcome, /devices:0$/);
    } finally { f.cleanup(); }
});

test('batch: a second active router change and a changed revision refuse all local staging', async t => {
    for (const conflict of ['active', 'revision']) await t.test(conflict, async () => {
        const f = world();
        try {
            const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
            let precondition = f.policy.people(actor).revisionToken;
            const items = [create(0), add(1, '@0')];
            if (conflict === 'active') { f.pause(); precondition = f.token(); }
            else { f.router.policy = normalizePolicy({...f.router.policy, revision: 1}); f.advance(1); await f.observe(); }
            await refuses(f.perform(who, items, 'batch_client_key_0001', precondition), conflict === 'active' ? 'operation_in_progress' : 'revision_conflict');
            assert.equal(f.count('people'), 1); assert.equal(f.count('devices'), 1);
        } finally { f.cleanup(); }
    });
});

for (const invisible of ['\u200b', '\u202e', '\u00ad', '\ufe0f', '\u034f']) test(`batch: names reject invisible code point ${invisible.codePointAt(0)!.toString(16)}`, async () => {
    const f = world();
    try { const who = await f.signIn(); await refuses(f.options(who, [create(0, `Private${invisible}name`)]), 'invalid_child_name'); unchanged(f); }
    finally { f.cleanup(); }
});

test('batch: final staged child/device/MAC invariants catch transaction-time interference', async t => {
    for (const interference of ['child_count', 'device_count', 'per_child_count', 'mac_set']) await t.test(interference, async () => {
        const f = world();
        try {
            const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
            if (interference === 'child_count') f.store.db.exec("CREATE TRIGGER batch_inject AFTER INSERT ON devices WHEN NEW.state='enrolling' BEGIN INSERT INTO people(id,name,created_at) VALUES('unconfirmed','Injected',0); END");
            if (interference === 'device_count') f.store.db.exec(`CREATE TRIGGER batch_inject AFTER INSERT ON devices WHEN NEW.state='enrolling' BEGIN INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('injected','pilot','Injected','mac','${mac(300)}','active',0); END`);
            if (interference === 'per_child_count') {
                f.store.run("INSERT INTO people(id,name,created_at) VALUES('kid2','Other child',0)");
                f.store.db.exec("CREATE TRIGGER batch_inject AFTER INSERT ON devices WHEN NEW.state='enrolling' BEGIN UPDATE devices SET person_id='kid2' WHERE id=NEW.id; END");
            }
            if (interference === 'mac_set') f.store.db.exec(`CREATE TRIGGER batch_inject AFTER INSERT ON devices WHEN NEW.state='enrolling' BEGIN UPDATE devices SET identifier='${mac(300)}' WHERE id=NEW.id; END`);
            const result = await f.perform(who, [add(1)]);
            assert.ok((result.body as {error?: object}).error);
            assert.deepEqual(Object.keys((result.body as {error: object}).error), ['code']);
            await refuses(Promise.resolve(result), interference === 'child_count' ? 'child_limit_reached' : interference === 'device_count' ? 'device_limit_reached' : interference === 'per_child_count' ? 'child_device_limit_reached' : 'device_already_enrolled');
            assert.equal(f.count('people'), interference === 'per_child_count' ? 2 : 1); assert.equal(f.count('devices'), 1); assert.equal(f.count('operations'), 0);
        } finally { f.cleanup(); }
    });
});

test('batch: device-only setup for the existing seed child closes the first-run gate after confirmation', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const r = await f.perform(who, [add(1)]); await f.dispatch(body(r).operation!.id);
        assert.equal(f.store.get<{setup_completed: number}>('SELECT setup_completed FROM admin_batch_setup')?.setup_completed, 1);
        await refuses(f.options(who, [rename(0)], 'batch_client_after_seed'), 'batch_setup_completed');
    } finally { f.cleanup(); }
});

for (const target of ['@00', '@01', '@-1', '@100', '@1.0', 1]) test(`batch: reference grammar rejects ${String(target)}`, async () => {
    const f = world();
    try {
        const who = await f.signIn();
        await refuses(f.batch.stepUpOptions(who.session(), {action: 'child_batch', clientKey: 'batch_client_key_0001', precondition: null, items: [create(0), {...rename(1), target}]}), typeof target === 'string' ? 'invalid_batch_reference' : 'invalid_target'); unchanged(f);
    } finally { f.cleanup(); }
});

test('batch: concurrent options reserve three actor slots before asynchronous proof generation', async () => {
    const f = world();
    try {
        const who = await f.signIn(), results = await Promise.allSettled(Array.from({length: 6}, (_, n) => f.options(who, [create()], `batch_client_concurrent_${n}`)));
        assert.equal(results.filter(r => r.status === 'fulfilled').length, 3);
        const refused = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
        assert.equal(refused.length, 3); assert.ok(refused.every(r => r.reason.code === 'batch_rate_limited')); assert.equal(f.count('step_ups'), 3);
    } finally { f.cleanup(); }
});

test('batch: old idempotency rows expire after 90 days without resetting first-run completion', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe();
        f.store.run('INSERT INTO admin_batch_setup(singleton,setup_completed) VALUES(1,1) ON CONFLICT(singleton) DO UPDATE SET setup_completed=1');
        for (const [n, age] of [[0, 90 * 86400 + 1], [1, 90 * 86400 - 1]]) f.store.run("INSERT INTO admin_batches(id,actor_id,client_key,digest,result_json,created_at) VALUES(?,'operator',?,'digest','{}',?)", `expired_${n}`, `batch_retention_key_${n}`, f.now() - age);
        await f.options(who, [create()]);
        assert.deepEqual(f.store.all<{id: string}>('SELECT id FROM admin_batches').map(r => r.id), ['expired_1']);
        assert.equal(f.store.get<{setup_completed: number}>('SELECT setup_completed FROM admin_batch_setup')!.setup_completed, 1);
    } finally { f.cleanup(); }
});

test('batch: permission-version, passkey revocation and account deactivation invalidate a previously signed assertion', async t => {
    for (const revoke of ['permission', 'passkey', 'account']) await t.test(revoke, async () => {
        const f = world();
        try {
            const who = await f.signIn(), items = [create()], stepUp = await f.proof(who, items), frozen = who.session();
            if (revoke === 'permission') f.store.run("UPDATE accounts SET permission_version=permission_version+1 WHERE id='operator'");
            if (revoke === 'passkey') f.store.run("DELETE FROM credentials WHERE account_id='operator'");
            if (revoke === 'account') f.store.run("UPDATE accounts SET active=0 WHERE id='operator'");
            await refuses(f.batch.perform(frozen, {items, precondition: null, stepUp}, 'batch_client_key_0001'), revoke === 'passkey' ? 'credential_not_bound' : revoke === 'permission' ? 'permissions_changed' : 'account_disabled');
            spent(f, stepUp); unchanged(f);
        } finally { f.cleanup(); }
    });
});

test('batch: options preflight enforces exact shapes, references, keys, readiness and scope', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const base = {action: 'child_batch', clientKey: 'batch_client_key_0001', precondition: null, items: [create()]};
        const cases: [Record<string, unknown>, string][] = [
            [{...base, ignored: true}, 'invalid_fields'],
            [{...base, items: []}, 'invalid_batch_items'],
            [{...base, items: {}}, 'invalid_batch_items'],
            [{...base, items: Array.from({length: 41}, (_, n) => create(n))}, 'max_batch_items'],
            [{...base, clientKey: 'short'}, 'idempotency_key_required'],
            [{...base, items: [{...create(), key: 'short'}]}, 'invalid_item_key'],
            [{...base, items: [{...create(), key: 'tr-reserved_key_0001'}]}, 'invalid_item_key'],
            [{...base, items: [{...create(), extra: true}]}, 'invalid_fields'],
            [{...base, items: [{...create(), params: {name: 'Valid', kind: 'child', extra: 1}}]}, 'invalid_fields'],
            [{...base, items: [{...create(), target: 'pilot'}]}, 'invalid_target'],
            [{...base, items: [{...create(), params: {name: 'Valid', kind: 'admin'}}]}, 'invalid_kind'],
            [{...base, items: [{...create(), params: {name: 1}}]}, 'invalid_child_name'],
            [{...base, items: [create(0), create(0)]}, 'duplicate_item_key'],
            [{...base, items: [rename(0, '@1'), create(1)]}, 'invalid_batch_reference'],
            [{...base, items: [rename(0), rename(1, '@0')]}, 'invalid_batch_reference'],
            [{...base, items: [add(1)], precondition: null}, 'revision_precondition_required'],
            [{...base, items: [add(1)], precondition: 1}, 'revision_precondition_required'],
            [{...base, items: [add(1, 'pilot', PROTECTED)], precondition: f.policy.people(actor).revisionToken}, 'device_mac_protected'],
            [{...base, items: [add(2)], precondition: f.policy.people(actor).revisionToken}, 'device_not_ready'],
            [{...base, items: [rename(0, 'missing')]}, 'person_not_found'],
        ];
        for (const [input, expected] of cases) await refuses(f.batch.stepUpOptions(who.session(), input), expected);
        assert.equal(f.count('step_ups'), 0); unchanged(f);
    } finally { f.cleanup(); }
});

test('batch: duplicate rename of one existing or referenced child refuses the entire list', async () => {
    const f = world();
    try {
        const who = await f.signIn();
        await refuses(f.perform(who, [rename(0), rename(1)]), 'duplicate_child_setup', 1); unchanged(f);
        await refuses(f.perform(who, [create(0), rename(1, '@0'), rename(2, '@0')], 'batch_client_rename_02'), 'duplicate_child_setup', 2); unchanged(f);
    } finally { f.cleanup(); }
});

test('batch: maximum forty canonical local items fit one proof and transaction', async () => {
    const f = world();
    try {
        const who = await f.signIn(), items = Array.from({length: 40}, (_, n) => create(n));
        const result = await f.perform(who, items); assert.equal(result.status, 200); assert.equal(body(result).results.length, 40);
        assert.equal(f.count('people'), 41); assert.equal(f.count('operations'), 0); assert.equal(who.key.counter, 1);
    } finally { f.cleanup(); }
});

test('batch: idempotency lookup and insertion occur inside the write transaction after committing the fresh proof', async () => {
    const f = world();
    try {
        const who = await f.signIn(), items = [create()], stepUp = await f.proof(who, items);
        const originalGet = f.store.get.bind(f.store), originalCommit = f.auth.commitStepUp.bind(f.auth), originalRun = f.store.run.bind(f.store);
        let committed = false, lookups = 0, inserts = 0;
        f.auth.commitStepUp = (...args) => { const actor = originalCommit(...args); committed = true; return actor; };
        f.store.get = function<T>(sql: string, ...args: (string | number | null | Uint8Array)[]): T | undefined {
            if (/FROM admin_batches WHERE actor_id/.test(sql)) { assert.ok(committed); assert.ok(f.store.db.isTransaction); lookups++; }
            return originalGet<T>(sql, ...args);
        };
        f.store.run = (sql, ...args) => {
            if (/INSERT INTO admin_batches/.test(sql)) { assert.ok(committed); assert.ok(f.store.db.isTransaction); inserts++; }
            return originalRun(sql, ...args);
        };
        const result = await f.batch.perform(who.session(), {items, precondition: null, stepUp}, 'batch_client_key_0001');
        assert.equal(result.status, 200); assert.equal(lookups, 1); assert.equal(inserts, 1);
    } finally { f.cleanup(); }
});

test('batch: idempotency keys are scoped to each actor', async () => {
    const f = world();
    try {
        f.store.run("UPDATE accounts SET role='admin',scope_all=1 WHERE id='parent'");
        const first = await f.signIn(), second = await f.signIn('parent'); await f.observe();
        assert.equal((await f.perform(first, [create()])).status, 200);
        assert.equal((await f.perform(second, [create()])).status, 200);
        assert.equal(f.count('people'), 3); assert.equal(f.count('admin_batches'), 2);
    } finally { f.cleanup(); }
});

test('batch: router observation can expire after options while inventory coverage remains fresh', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        const items = [create(0), add(1, '@0')], precondition = f.token(), stepUp = await f.proof(who, items);
        f.advance(OBSERVATION_FRESH_SECONDS + 1); f.ready([mac(1)]);
        await refuses(f.batch.perform(who.session(), {items, precondition, stepUp}, 'batch_client_key_0001'), 'device_not_ready', 1);
        spent(f, stepUp); unchanged(f);
    } finally { f.cleanup(); }
});

test('batch: offline configured device hides revision token without an active operation; local deletion permits a new-key batch', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
        f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('offline','pilot','Private offline','mac',?,'active',0)", mac(1));
        assert.equal(f.store.integrationState().active_operation_id, null); assert.equal(f.policy.people(actor).revisionToken, null);
        const single = new ChildAdmin(f.auth, f.policy), options = await single.stepUpOptions(who.session(), {action: 'device_remove', target: 'offline', params: {precondition: null}});
        const removed = await single.perform(who.session(), 'device_remove', 'offline', {precondition: null, stepUp: {challengeId: options.challengeId, response: who.key.login(options.options, origin)}});
        assert.equal(removed.status, 200); assert.equal(f.count('operations'), 0); assert.equal(f.count('devices'), 1);
        const stepUp = await f.proof(who, [add(1)], 'batch_client_after_offline');
        const result = await f.batch.perform(who.session(), {items: [add(1)], precondition: f.token(), stepUp}, 'batch_client_after_offline');
        assert.equal(result.status, 200); assert.equal(f.count('operations'), 1); assert.equal(f.count('devices'), 2);
    } finally { f.cleanup(); }
});

test('batch: audit writes are transactional and a parent-audit failure rolls back the composed operation', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe(); f.ready([mac(2), mac(3)]);
        const items = [create(0), create(1), add(2, '@0'), add(3, '@1')], originalRun = f.store.run.bind(f.store);
        let abortParent = true, adminWrites = 0, parentWrites = 0;
        f.store.run = (sql, ...args) => {
            if (/INSERT INTO audit/.test(sql) && typeof args[2] === 'string' && args[2].startsWith('admin_')) {
                assert.ok(f.store.db.isTransaction, 'admin audit must share the batch transaction'); adminWrites++;
            }
            if (/INSERT(?: OR IGNORE)? INTO parent_audit/.test(sql)) {
                assert.ok(f.store.db.isTransaction, 'parent audit must share the batch transaction'); parentWrites++;
                if (abortParent) {
                    assert.equal(f.count('operations'), 1, 'the composed operation is staged before audit insertion');
                    assert.equal(f.count('devices'), 3, 'both batch device rows are staged before audit insertion');
                    throw new Error('synthetic_parent_audit_abort');
                }
            }
            return originalRun(sql, ...args);
        };
        await assert.rejects(f.perform(who, items), /synthetic_parent_audit_abort/);
        assert.equal(parentWrites, 1); assert.equal(adminWrites, 1);
        unchanged(f); assert.equal(f.count('parent_audit'), 0); assert.equal(f.count('admin_batches'), 0);
        assert.equal(f.store.all("SELECT id FROM audit WHERE action LIKE 'admin_%'").length, 0);
        assert.equal(f.store.get<{highwater: number}>('SELECT highwater FROM service_state')!.highwater, 0);
        assert.equal(f.store.integrationState().active_operation_id, null);
        abortParent = false; adminWrites = 0; parentWrites = 0;
        const retry = await f.perform(who, items);
        assert.equal(retry.status, 200); assert.equal(adminWrites, 2); assert.equal(parentWrites, 2);
        assert.equal(f.count('operations'), 1); assert.equal(f.count('devices'), 3); assert.equal(f.count('people'), 3);
    } finally { f.cleanup(); }
});


test('batch: retryable execution errors are not persisted and final refusals are audited once', async () => {
    for (const [status, code] of [[409, 'revision_conflict'], [409, 'operation_in_progress'], [409, 'batch_setup_completed'], [503, 'unavailable']] as const) {
        const f = world();
        try {
            const who = await f.signIn(); await f.observe(); f.ready([mac(1)]);
            const original = f.policy.queue.bind(f.policy);
            f.policy.queue = () => { throw new AppError(status, code); };
            await refuses(f.perform(who, [add(1)]), code);
            assert.equal(f.count('admin_batches'), 0);
            assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM audit WHERE outcome LIKE 'refused:%'")!.n, 1);
            assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM parent_audit WHERE result='refused'")!.n, 1);
            f.policy.queue = original;
            assert.equal((await f.perform(who, [add(1)])).status, 200);
        } finally { f.cleanup(); }
    }
    const f = world();
    try {
        const who = await f.signIn(); await f.observe();
        const items = [add(1)];
        const first = await f.perform(who, items), second = await f.perform(who, items);
        assert.deepEqual(first, second);
        const row = f.store.get<{action: string; outcome: string}>("SELECT action,outcome FROM audit WHERE outcome LIKE 'refused:%'")!;
        assert.deepEqual({...row}, {action: 'admin_device_add', outcome: 'refused:device_not_ready:1'});
        const parent = f.store.get<{action: string; result: string; person_id: string | null}>("SELECT action,result,person_id FROM parent_audit WHERE result='refused'")!;
        assert.deepEqual({...parent}, {action: 'device_assign', result: 'refused', person_id: null});
    } finally { f.cleanup(); }
});

test('batch: failed options release only their own concurrent rate reservation', async () => {
    const f = world();
    try {
        const who = await f.signIn(), original = f.auth.stepUpChallenge.bind(f.auth);
        let reject!: (reason: Error) => void;
        f.auth.stepUpChallenge = () => new Promise((_, fail) => { reject = fail; });
        const failed = f.options(who, [create()], 'batch_client_reserve_1');
        f.auth.stepUpChallenge = original;
        await Promise.all([f.options(who, [create()], 'batch_client_reserve_2'), f.options(who, [create()], 'batch_client_reserve_3')]);
        reject(new Error('auth failed')); await assert.rejects(failed, /auth failed/);
        await f.options(who, [create()], 'batch_client_reserve_4');
        await refuses(f.options(who, [create()], 'batch_client_reserve_5'), 'batch_rate_limited');
    } finally { f.cleanup(); }
});


test('batch: identity and gate failures have no item attribution', async () => {
    for (const kind of ['identity', 'gate']) {
        const f = world();
        try {
            const who = await f.signIn();
            if (kind === 'identity') f.store.assertIdentity = () => { throw new AppError(409, 'identity_changed'); };
            else f.store.run('INSERT INTO admin_batch_setup(singleton,setup_completed) VALUES(1,1)');
            const result = await f.perform(who, [create()]);
            assert.deepEqual(result.body, {error: {code: kind === 'identity' ? 'identity_changed' : 'batch_setup_completed'}});
        } finally { f.cleanup(); }
    }
});


test('batch: refusal remains stored if parent audit insertion fails', async () => {
    const f = world();
    try {
        const who = await f.signIn(); await f.observe();
        f.store.db.exec("CREATE TRIGGER fail_parent_refusal BEFORE INSERT ON parent_audit WHEN NEW.result='refused' BEGIN SELECT RAISE(FAIL, 'audit unavailable'); END");
        const items = [add(1)], first = await f.perform(who, items);
        assert.equal(first.status, 409);
        assert.deepEqual(await f.perform(who, items), first);
        assert.equal(f.count('admin_batches'), 1);
        assert.equal(f.count('parent_audit'), 0);
        assert.equal(f.store.get<{outcome: string}>("SELECT outcome FROM audit WHERE outcome LIKE 'refused:%'")?.outcome, 'refused:device_not_ready:1');
    } finally { f.cleanup(); }
});
