import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { integrationFixture, storeDump, actor } from './fixtures/integration.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { expandedWindows, settleSchedule } from '../src/integration-schedule-settle.ts';
import { scheduleWindows } from '../src/integration-schedule-store.ts';
import { policyDigest, requestDigest } from '../../shared/src/router-rpc.ts';
import { normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import type { RouterPolicy, Schedule } from '../../shared/src/router-schema.ts';
import type { IntegrationOperation } from '../src/integration-policy.ts';

// Schedule settlement seam (roadmap item 2, S2a; schedules.editable, off; unverified on this router). There is no producer yet:
// every test inserts the operation rows directly and drives the real worker.
type Fixture = ReturnType<typeof integrationFixture>;
type Window = Omit<Schedule, 'person'>;
const night: Window = {id: 'night', weekdays: ['Mon', 'Tue'], start: '20:30', stop: '07:00'};
const macOf = (n: number) => '02:10:20:30:41:' + n.toString(16).padStart(2, '0');

/** A fixture with the flag on, a clock, and `devices` addresses under the one child (database rows and router policy agree). */
function world(devices = 1, flag: boolean | undefined = true) {
    const f = integrationFixture(flag === undefined ? {} : {schedules: {editable: flag}});
    (f.config as {scheduleClock?: unknown}).scheduleClock = {timezone: 'UTC'};
    const macs = ['02:10:20:30:40:50', ...Array.from({length: devices - 1}, (_, i) => macOf(i))];
    f.store.transaction(() => { for (const [i, mac] of macs.slice(1).entries()) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',?)", `d${i}`, 'pilot', `Device ${i}`, mac, 1); });
    f.router.policy = normalizePolicy({version: 1, revision: 0, people: [{id: 'pilot', macs}], pauses: [], schedules: []});
    return f;
}
const withWindows = (base: RouterPolicy, windows: readonly Window[]): RouterPolicy => normalizePolicy({...base, revision: base.revision + 1, schedules: windows.map(w => ({person: 'pilot', ...w}))});
/** Inserts a pending schedule operation (and its envelope against the stored observation) as the future producer will, and makes it the active one. */
function queue(f: Fixture, windows: readonly Window[], action: IntegrationOperation['action'] = 'schedule_update'): string {
    const o = f.store.observation().value!, id = randomUUID(), policy = withWindows(o.acceptedPolicy, windows);
    const envelope = {rpc_version: 1 as const, generation: o.generation, operation_id: id, expected_revision: o.acceptedPolicy.revision, expected_digest: o.policyDigest, policy};
    f.store.transaction(() => {
        f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error) VALUES(?,?,?,?,?,'pending',?,?,'{}',?,?,?,'awaiting_operator_dispatch')", id, 'operator', 'pilot', action, policy.revision, policyJSON(policy), policyJSON(o.acceptedPolicy), 'k_' + id, f.now(), f.now());
        f.store.run("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase) VALUES(?,?,?,?,?,'queued')", id, o.generation, o.policyDigest, requestDigest(envelope), JSON.stringify(envelope));
        f.store.run('UPDATE integration_state SET active_operation_id=? WHERE singleton=1', id);
    });
    return id;
}
const apply = async (f: Fixture, id: string) => { const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256); };
const receipt = async (f: Fixture, id: string) => { const plan = f.worker.prepare('receipt', id); await f.worker.execute(plan, plan.scriptSha256); };
const op = (f: Fixture, id: string) => f.store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id)!;
const committed = (f: Fixture) => scheduleWindows(f.store).map(({person, ...w}) => w);
const active = (f: Fixture) => f.store.integrationState().active_operation_id;

test('accepted: an exact healthy receipt promotes the payload windows and confirms', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]); await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.equal(op(f, id).error, null); assert.equal(op(f, id).confirmed_at, f.now());
        assert.deepEqual(committed(f), [night]); assert.equal(active(f), null);
        assert.deepEqual(f.router.policy.schedules.map(s => s.id), ['night']);
    } finally { f.cleanup(); }
});
test('delete promotes the empty set for the child', async () => {
    const f = world();
    try {
        await f.observe(); await apply(f, queue(f, [night]));
        f.advance(1); await f.observe(); const id = queue(f, [], 'schedule_delete'); await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.deepEqual(committed(f), []);
    } finally { f.cleanup(); }
});
test('exact historical receipt promotes the payload even though the child is now inactive', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response'); await apply(f, id);
        assert.equal(op(f, id).state, 'unknown'); assert.deepEqual(committed(f), []);
        // The router moves on (a later revision) and the child is removed before the receipt is read.
        f.router.afterApplyFailure = null; f.advance(70);
        f.router.policy = normalizePolicy({...f.router.policy, revision: f.router.policy.revision + 1, pauses: [{person: 'pilot', until: f.now() + 600}]});
        f.store.transaction(() => f.store.run('UPDATE people SET active=0 WHERE id=?', 'pilot'));
        await receipt(f, id);
        assert.equal(op(f, id).state, 'conflict'); assert.equal(op(f, id).error, 'router_receipt_historical');
        assert.deepEqual(committed(f), [night]); assert.equal(active(f), null);
    } finally { f.cleanup(); }
});
test('absent child: an accepted receipt still promotes and confirms', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApply = () => f.store.transaction(() => f.store.run('UPDATE people SET active=0 WHERE id=?', 'pilot'));
        await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.deepEqual(committed(f), [night]);
    } finally { f.cleanup(); }
});
test('pre-dispatch base change settles as a conflict and promotes nothing', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.policy = normalizePolicy({...f.router.policy, revision: 1, pauses: [{person: 'pilot', until: f.now() + 600}]});
        f.advance(1); await f.observe();
        assert.equal(op(f, id).state, 'conflict'); assert.equal(op(f, id).error, 'router_base_changed_before_dispatch');
        assert.deepEqual(committed(f), []); assert.equal(active(f), null);
    } finally { f.cleanup(); }
});
test('non-delivery settles as failed and promotes nothing', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.failure = new RouterTransportError('test_spawn_failed', 'not_delivered'); await apply(f, id);
        assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'test_spawn_failed');
        assert.deepEqual(committed(f), []); assert.equal(active(f), null);
    } finally { f.cleanup(); }
});
test('a possibly delivered failure stays unknown and promotes nothing', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.failure = new RouterTransportError('test_timeout'); await apply(f, id);
        assert.equal(op(f, id).state, 'unknown'); assert.deepEqual(committed(f), []); assert.equal(active(f), id);
    } finally { f.cleanup(); }
});
test('a foreign device reply (another operation, another request digest) never promotes', async () => {
    for (const tamper of [{operationId: randomUUID()}, {requestDigest: 'f'.repeat(64)}, {acceptedDigest: 'e'.repeat(64)}]) {
        const f = world();
        try {
            await f.observe(); const id = queue(f, [night]);
            f.router.transform = o => o.receipt ? {...o, receipt: {...o.receipt, ...tamper}} : o;
            await apply(f, id);
            assert.equal(op(f, id).state, 'unknown'); assert.match(op(f, id).error!, /^(receipt_missing_remote_outcome_unknown|router_observation_invalid)$/, JSON.stringify(tamper));
            assert.deepEqual(committed(f), []);
        } finally { f.cleanup(); }
    }
});
test('the seam itself refuses a stored receipt that is not this operation\'s own', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        const own = f.policy.envelope(id);
        const foreign = {operationId: randomUUID(), requestDigest: requestDigest(own), baseRevision: own.expected_revision, baseDigest: own.expected_digest, acceptedRevision: own.policy.revision, acceptedDigest: policyDigest(own.policy), outcome: 'applied', current: true};
        f.store.transaction(() => { f.store.run("UPDATE operation_rpc SET receipt_json=? WHERE operation_id=?", JSON.stringify(foreign), id); settleSchedule(f.store, op(f, id), {state: 'confirmed', error: null, confirmedAt: f.now(), now: f.now()}); });
        assert.deepEqual(committed(f), []); assert.equal(op(f, id).confirmed_at, null); assert.equal(op(f, id).error, 'schedule_receipt_unverified');
    } finally { f.cleanup(); }
});
test('a mismatch with the rest of the committed set withholds the health claim but never blocks settlement', async () => {
    const f = world();
    try {
        await f.observe();
        // The router set carries a window for the child that the committed set does not have (another operation's); the payload is the whole router set.
        const id = queue(f, [night]);
        f.store.transaction(() => f.store.run("INSERT INTO people(id,name,active,created_at) VALUES('other','Other',1,2)"));
        const e = f.policy.envelope(id);
        const widened = {...e, policy: normalizePolicy({...e.policy, people: [...e.policy.people, {id: 'other', macs: ['02:10:20:30:49:49']}], schedules: [...e.policy.schedules, {person: 'other', id: 'late', weekdays: ['Fri'], start: '21:00', stop: '23:00'}]})};
        f.store.transaction(() => f.store.run('UPDATE operation_rpc SET envelope_json=?,request_digest=? WHERE operation_id=?', JSON.stringify(widened), requestDigest(widened), id));
        f.store.transaction(() => f.store.run("UPDATE operation_rpc SET receipt_json=? WHERE operation_id=?", JSON.stringify({operationId: id, requestDigest: requestDigest(widened), baseRevision: widened.expected_revision, baseDigest: widened.expected_digest, acceptedRevision: widened.policy.revision, acceptedDigest: policyDigest(widened.policy), outcome: 'applied', current: true}), id));
        f.store.transaction(() => settleSchedule(f.store, op(f, id), {state: 'confirmed', error: null, confirmedAt: f.now(), now: f.now()}));
        assert.equal(op(f, id).state, 'confirmed'); assert.equal(op(f, id).confirmed_at, null); assert.equal(op(f, id).error, 'schedule_set_unverified');
        assert.deepEqual(committed(f), [night]);
    } finally { f.cleanup(); }
});

const cross = (n: number): Window[] => Array.from({length: n}, (_, i) => ({id: `c${i}`, weekdays: ['Mon'], start: '22:00', stop: '06:00'}));
const plain = (n: number, from = 0): Window[] => Array.from({length: n}, (_, i) => ({id: `p${from + i}`, weekdays: ['Tue'], start: '09:00', stop: '10:00'}));
test('expansion counts devices times windows, a cross-midnight window twice', () => {
    const p = (windows: Window[]) => normalizePolicy({version: 1, revision: 0, people: [{id: 'pilot', macs: Array.from({length: 8}, (_, i) => macOf(i))}], pauses: [], schedules: windows.map(w => ({person: 'pilot', ...w}))});
    assert.equal(expandedWindows(p(cross(4))), 64); assert.equal(expandedWindows(p([...cross(1), ...plain(1)])), 24); assert.equal(expandedWindows(p(plain(5))), 40);
});
test('expansion limit: 32 devices with 4 cross-midnight windows is exactly 256 and confirms', async () => {
    const f = world(32);
    try {
        await f.observe(); const id = queue(f, cross(4)); await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.equal(op(f, id).confirmed_at, f.now()); assert.equal(committed(f).length, 4);
    } finally { f.cleanup(); }
});
test('expansion limit: 32 devices with 8 plain windows is exactly 256 and confirms', async () => {
    const f = world(32);
    try {
        await f.observe(); const id = queue(f, plain(8)); await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.equal(committed(f).length, 8);
    } finally { f.cleanup(); }
});
test('expansion limit: one over (4 cross-midnight plus 1 plain at 32 devices = 288) cannot be built as an envelope, and a raw one settles without promotion', async () => {
    const f = world(32);
    try {
        await f.observe();
        assert.throws(() => queue(f, [...cross(4), ...plain(1)]), /expanded_schedule_limit|invalid/);
        // Raw rows (no producer could write them): the seam still settles, withholds the claim, and promotes nothing.
        const o = f.store.observation().value!, id = randomUUID(), windows = [...cross(4), ...plain(1)].map(w => ({person: 'pilot', ...w}));
        const raw = {rpc_version: 1, generation: o.generation, operation_id: id, expected_revision: 0, expected_digest: o.policyDigest, policy: {...o.acceptedPolicy, revision: 1, schedules: windows}};
        f.store.transaction(() => {
            f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES(?,'operator','pilot','schedule_update',1,'pending','{}','{}','{}',?,?,?)", id, 'k_' + id, f.now(), f.now());
            f.store.run("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase,receipt_json) VALUES(?,?,?,?,?,'queued',?)", id, o.generation, o.policyDigest, 'a'.repeat(64), JSON.stringify(raw), JSON.stringify({operationId: id}));
            settleSchedule(f.store, op(f, id), {state: 'confirmed', error: null, confirmedAt: f.now(), now: f.now()});
        });
        assert.equal(op(f, id).state, 'confirmed'); assert.equal(op(f, id).confirmed_at, null); assert.deepEqual(committed(f), []);
        assert.equal(expandedWindows(raw.policy as RouterPolicy), 288);
    } finally { f.cleanup(); }
});

test('flag off: a schedule operation settles through the unchanged path and the store is identical with the key absent or false', async () => {
    const dumps: string[] = [];
    for (const flag of [undefined, false]) {
        const f = world(1, flag);
        try {
            await f.observe(); const id = queue(f, [night]);
            f.router.failure = new RouterTransportError('test_spawn_failed', 'not_delivered'); await apply(f, id);
            assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'test_spawn_failed');
            assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM schedule_windows')!.n, 0);
            dumps.push(storeDump(f.store));
        } finally { f.cleanup(); }
    }
    assert.equal(dumps[0], dumps[1]);
});
test('flag on: a non-schedule operation never reaches the seam', async () => {
    const f = world();
    try {
        await f.observe(); const id = f.pause(f.now() + 60).result.operation.id; await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.deepEqual(committed(f), []);
    } finally { f.cleanup(); }
});

const other: Window = {id: 'other', weekdays: ['Fri'], start: '21:00', stop: '23:00'};
const state = (f: Fixture) => f.store.integrationState();
test('exact historical receipt settles even when a third schedule set now sits on the router; health and token are withheld', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response'); await apply(f, id);
        f.router.afterApplyFailure = null; f.advance(70);
        f.router.policy = withWindows(withWindows(f.router.policy, [night]), [other]);
        await receipt(f, id);
        assert.equal(op(f, id).state, 'conflict'); assert.equal(op(f, id).error, 'router_receipt_historical');
        assert.deepEqual(committed(f), [night]); assert.equal(active(f), null);
        assert.notEqual(state(f).observation_error, null); assert.equal(f.policy.people(actor).revisionToken, null);
        assert.equal(f.policy.people(actor).people[0]!.observationHealth, 'unreachable');
    } finally { f.cleanup(); }
});
test('router already holding the staged windows before dispatch never publishes health or a token over the old committed set', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.policy = withWindows(f.router.policy, [night]);
        f.advance(1); await f.observe();
        assert.equal(op(f, id).state, 'conflict'); assert.deepEqual(committed(f), []); assert.equal(active(f), null);
        assert.notEqual(state(f).observation_error, null); assert.equal(f.policy.people(actor).revisionToken, null);
    } finally { f.cleanup(); }
});
test('an accepted receipt whose promotion fails stays recoverable: not confirmed, still active, no health, no token', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, plain(9)); await apply(f, id);
        assert.deepEqual(committed(f), []); assert.notEqual(op(f, id).state, 'confirmed'); assert.equal(op(f, id).confirmed_at, null);
        assert.equal(op(f, id).error, 'schedule_promotion_failed'); assert.equal(active(f), id);
        const people = f.policy.people(actor); assert.equal(people.revisionToken, null); assert.equal(people.people[0]!.latestOperation?.currentHealthy, false);
        // The staged windows are not committed: the observation is never published, so no health and no confirmed revision.
        assert.notEqual(state(f).observation_error, null); assert.equal(people.people[0]!.observationHealth, 'unreachable');
        assert.equal(f.store.observation().value?.acceptedPolicy.schedules.length ?? 0, 0); assert.equal(f.policy.people(actor).routerConfirmedRevision, null);
    } finally { f.cleanup(); }
});
test('exact historical receipt settles before device ownership: a later router policy with a foreign device still promotes, but is not published', async () => {
    const f = world();
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response'); await apply(f, id);
        assert.equal(op(f, id).state, 'unknown');
        f.router.afterApplyFailure = null; f.advance(70);
        const mine = withWindows(f.router.policy, [night]);
        f.router.policy = normalizePolicy({...mine, revision: mine.revision + 1, people: [{id: 'pilot', macs: [...mine.people[0]!.macs, '02:10:20:30:41:ee']}]});
        await receipt(f, id);
        assert.notEqual(op(f, id).state, 'unknown'); assert.deepEqual(committed(f), [night]); assert.equal(active(f), null);
        assert.notEqual(state(f).observation_error, null); assert.equal(f.policy.people(actor).revisionToken, null);
        assert.equal(f.policy.people(actor).people[0]!.observationHealth, 'unreachable');
    } finally { f.cleanup(); }
});
