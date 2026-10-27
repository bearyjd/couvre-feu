import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { rmSync } from 'node:fs';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { ChildAdmin } from '../src/admin-children.ts';
import type { ChildAction } from '../src/admin-children.ts';
import { BulkOps, bulkPolicy } from '../src/integration-bulk.ts';
import type { BulkAction } from '../src/integration-bulk.ts';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { TestAuthenticator } from './authenticator.ts';
import { appServer } from '../src/http.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { PRE_WRITE_REJECTIONS, movePolicy } from '../src/integration-children.ts';
import { TimeRequestService } from '../src/time-requests.ts';
import { IntegrationGrants } from '../src/integration-allowance.ts';

// Placeholder, locally administered unicast MACs only.
const SEED = '02:10:20:30:40:50', PROTECTED = '02:10:20:30:40:51', K2 = '02:10:20:30:40:62', K3 = '02:10:20:30:40:63';
const origin = 'http://localhost:4273';
const code = (expected: string) => (error: {code?: string}) => error.code === expected;
const ALL = ['kid2', 'kid3', 'pilot'];

/** Three children on the router (pilot, kid2, kid3), an operator who manages all of them and a parent who manages pilot and kid2. */
function world(opts: {automatic?: boolean} = {}) {
    const f = integrationFixture();
    if (opts.automatic) f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const admin = new ChildAdmin(auth, f.policy), bulk = new BulkOps(auth, f.policy);
    const created = f.now();
    for (const [id, mac] of [['kid2', K2], ['kid3', K3]]) {
        f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES(?,?,'child',1,?)", id, `Kid ${id}`, created);
        f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',?)", `d_${id}`, id, `Device ${id}`, mac, created);
    }
    const setScope = (account: string, ids: string[]) => f.store.run('UPDATE accounts SET person_ids=? WHERE id=?', JSON.stringify(ids), account);
    setScope('operator', ALL); setScope('parent', ['pilot', 'kid2']);
    const policyOf = (revision: number, over: Partial<RouterPolicy> = {}): RouterPolicy => normalizePolicy({version: 1, revision, people: [{id: 'pilot', macs: [SEED]}, {id: 'kid2', macs: [K2]}, {id: 'kid3', macs: [K3]}],
        pauses: [], schedules: [], ...over}, f.config.protectedMacs);
    f.router.policy = policyOf(1);
    const wide: Actor = {...actor, personIds: ALL};
    const token = () => f.policy.people(wide).revisionToken!;
    async function signIn(account: string) {
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, account, f.now())}, browser);
        const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, cookie: `cf_session=${result.token}; cf_browser=${browser}`, session: () => auth.session(result.token, browser)};
    }
    type Who = Awaited<ReturnType<typeof signIn>>;
    async function bulkStepUp(who: Who, action: BulkAction, params: Record<string, unknown>) {
        const options = await bulk.stepUpOptions(who.session(), {action, params});
        return {challengeId: options.challengeId, response: who.key.login(options.options, origin)};
    }
    async function block(who: Who, action: BulkAction, params: Record<string, unknown> = {}, key = `bulk_${randomBytes(8).toString('hex')}`) {
        const body = {...(action === 'pause_all' ? {until: 0} : {}), precondition: token(), ...params};
        const {precondition, until} = body as {precondition: string; until?: number};
        return bulk.perform(who.session(), action, key, {...body, stepUp: await bulkStepUp(who, action, {precondition, ...(until === undefined ? {} : {until})})}) as Promise<{status: number; body: Record<string, any>}>;
    }
    async function move(who: Who, device: string, to: string, params: Record<string, unknown> = {}) {
        const p = {to, precondition: token(), ...params};
        const options = await admin.stepUpOptions(who.session(), {action: 'device_move' as ChildAction, target: device, params: p});
        return admin.perform(who.session(), 'device_move' as ChildAction, device, {...p, stepUp: {challengeId: options.challengeId, response: who.key.login(options.options, origin)}}) as Promise<{status: number; body: Record<string, any>}>;
    }
    async function dispatch(id: string) { const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256); }
    const applies = () => f.router.calls.filter(c => c.kind === 'apply');
    const ops = () => f.store.all<{id: string; action: string; person_id: string}>('SELECT id,action,person_id FROM operations').map(r => ({...r}));
    const rows = (op: string) => f.store.all<{person_id: string}>('SELECT person_id FROM operation_people WHERE operation_id=? ORDER BY person_id', op).map(r => r.person_id);
    return {...f, auth, admin, bulk, wide, token, signIn, block, move, dispatch, applies, ops, rows, setScope, policyOf, bulkStepUp};
}

test('bulk pause is ONE operation and ONE rpc-sync envelope with a pause for every child; resume_all lifts them in one more', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const r = await f.block(op, 'pause_all');
        assert.equal(r.status, 202); const id = r.body.operation.id;
        assert.equal(r.body.operation.action, 'pause_all');
        assert.equal(f.ops().length, 1); assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM operation_rpc')!.n, 1);
        assert.deepEqual(f.rows(id), ALL);
        assert.equal(f.store.get<{person_id: string}>('SELECT person_id FROM operations WHERE id=?', id)!.person_id, 'kid2', 'representative is the smallest id');
        await f.dispatch(id);
        assert.equal(f.applies().length, 1);
        const envelope = JSON.parse(f.applies()[0].stdin);
        assert.deepEqual(envelope.policy.pauses.map((p: {person: string}) => p.person), ALL);
        assert.deepEqual(f.router.policy.pauses.map(p => p.person), ALL);
        const done = f.policy.operation(f.wide, id);
        assert.equal(done.state, 'confirmed'); assert.equal((done as {effect?: string}).effect, 'blocking');
        f.advance(1); await f.observe();
        const resumed = await f.block(op, 'resume_all');
        assert.equal(resumed.status, 202); await f.dispatch(resumed.body.operation.id);
        assert.equal(f.applies().length, 2); assert.deepEqual(f.router.policy.pauses, []);
        assert.equal((f.policy.operation(f.wide, resumed.body.operation.id) as {effect?: string}).effect, 'unblocked');
    } finally { f.cleanup(); }
});

test('an actor with partial scope blocks only their children; an out-of-scope child is never added and keeps its own pause', async () => {
    const f = world();
    try {
        f.router.policy = f.policyOf(2, {pauses: [{person: 'kid3', until: 0}]});
        const parent = await f.signIn('parent'); await f.observe();
        const r = await f.block(parent, 'pause_all', {until: f.now() + 3600});
        assert.equal(r.status, 202); const id = r.body.operation.id;
        assert.deepEqual(f.rows(id), ['kid2', 'pilot']);
        await f.dispatch(id);
        assert.deepEqual(f.router.policy.pauses, [{person: 'kid2', until: f.now() + 3600}, {person: 'kid3', until: 0}, {person: 'pilot', until: f.now() + 3600}]);
        f.advance(1); await f.observe();
        const resumed = await f.block(parent, 'resume_all'); await f.dispatch(resumed.body.operation.id);
        assert.deepEqual(f.router.policy.pauses, [{person: 'kid3', until: 0}], 'resume_all never touches a child outside the actor scope');
        // A parent whose scope names no child on the router gets nothing queued.
        f.setScope('parent', []);
        await assert.rejects(f.bulk.stepUpOptions(parent.session(), {action: 'pause_all', params: {until: 0, precondition: f.token()}}), code('no_enrolled_children'));
    } finally { f.cleanup(); }
});

test('the step-up binds the exact affected child ids and a rebase never adds a child', async () => {
    const f = world();
    try {
        const parent = await f.signIn('parent'); await f.observe();
        // 1. Scope grows between the challenge and the commit: the challenge was bound to the old id list.
        const params = {until: 0, precondition: f.token()};
        const stale = await f.bulkStepUp(parent, 'pause_all', params);
        f.setScope('parent', ['pilot', 'kid2', 'kid3']);
        await assert.rejects(f.bulk.perform(parent.session(), 'pause_all', 'bind_key_1234567890', {...params, stepUp: stale}), code('step_up_mismatch'));
        assert.equal(f.ops().length, 0);
        f.setScope('parent', ['pilot', 'kid2']);
        // 2. Scope grows AFTER the proof verified, before the write transaction: refused, nothing queued (never recomputed upward).
        const original = f.auth.stepUpVerify.bind(f.auth);
        f.auth.stepUpVerify = async (...args) => { const proof = await original(...args); f.setScope('parent', ['pilot', 'kid2', 'kid3']); return proof; };
        await assert.rejects(f.bulk.perform(parent.session(), 'pause_all', 'bind_key_2234567890', {...params, stepUp: await f.bulkStepUp(parent, 'pause_all', params)}), code('bulk_children_changed'));
        assert.equal(f.ops().length, 0); assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM operation_people')!.n, 0);
        f.auth.stepUpVerify = original;
    } finally { f.cleanup(); }
});

test('bulkPolicy: only the bound ids change, an id the router lacks refuses, other children and allowances stay', () => {
    const f = world();
    try {
        const base = f.policyOf(4, {pauses: [{person: 'kid3', until: 0}], allowances: [{person: 'pilot', until: f.now() + 600}, {person: 'kid3', until: f.now() + 600}]});
        const paused = bulkPolicy(base, f.config, 'pause_all', ['pilot'], 0);
        assert.equal(paused.revision, 5);
        assert.deepEqual(paused.pauses, [{person: 'kid3', until: 0}, {person: 'pilot', until: 0}]);
        assert.deepEqual(paused.allowances, [{person: 'kid3', until: f.now() + 600}], 'allowances are cleared for the blocked children only');
        assert.deepEqual(bulkPolicy(base, f.config, 'resume_all', ['kid3'], null).pauses, []);
        assert.throws(() => bulkPolicy(base, f.config, 'pause_all', ['pilot', 'ghost'], 0), code('bulk_children_changed'));
        assert.throws(() => bulkPolicy(base, f.config, 'pause_all', [], 0), code('no_enrolled_children'));
    } finally { f.cleanup(); }
});

test('pause_all clears active time allowances of the blocked children (block-all semantics)', async () => {
    const f = world();
    try {
        const until = f.now() + 600;
        f.router.policy = f.policyOf(2, {allowances: [{person: 'pilot', until}, {person: 'kid3', until}]});
        const parent = await f.signIn('parent'), op = await f.signIn('operator'); await f.observe();
        const r = await f.block(parent, 'pause_all'); await f.dispatch(r.body.operation.id);
        assert.deepEqual(f.router.policy.allowances, [{person: 'kid3', until}]);
        assert.equal(f.policy.operation(f.wide, r.body.operation.id).state, 'confirmed');
        f.advance(1); await f.observe();
        const all = await f.block(op, 'pause_all', {until: 0}); await f.dispatch(all.body.operation.id);
        assert.equal(f.router.policy.allowances, undefined);
        assert.deepEqual(f.router.policy.pauses.map(p => p.person), ALL);
    } finally { f.cleanup(); }
});

test('pause_all ends an approved time-request grant end to end: the request reports grant_ended', async () => {
    const f = world();
    try {
        const service = new TimeRequestService(f.store, f.policy, f.now, undefined, new IntegrationGrants(f.policy));
        const parent = await f.signIn('parent'); await f.observe();
        const link = await service.issueLink(f.wide, 'pilot');
        service.submit(link.token, 30, 'homework', 'c');
        const id = f.store.get<{id: string}>("SELECT id FROM time_requests WHERE state='pending'")!.id;
        await service.approve(f.wide, id, 30);
        await f.dispatch(f.store.get<{grant_operation_id: string}>('SELECT grant_operation_id FROM time_requests WHERE id=?', id)!.grant_operation_id);
        await service.advance();
        assert.equal(f.store.get<{state: string}>('SELECT state FROM time_requests WHERE id=?', id)!.state, 'approved');
        f.advance(1); await f.observe();
        const r = await f.block(parent, 'pause_all'); await f.dispatch(r.body.operation.id);
        f.advance(1); await f.observe(); await service.advance();
        assert.equal(f.router.policy.allowances, undefined, 'the router no longer holds the allowance');
        const status = service.status(link.token, 'c');
        assert.equal(status.code, 'grant_ended');
        assert.equal(status.allowanceUntil, null);
    } finally { f.cleanup(); }
});

test('dispatch re-checks authorization for EVERY operation_people row, not only the representative', async () => {
    const f = world({automatic: true}), automatic = new AutomaticDispatch(f.worker);
    try {
        const parent = await f.signIn('parent'); await automatic.tick();
        const r = await f.block(parent, 'pause_all'); const id = r.body.operation.id;
        assert.equal(f.store.get<{person_id: string}>('SELECT person_id FROM operations WHERE id=?', id)!.person_id, 'kid2');
        // Lose the NON-representative child without a permission-version bump, so only the per-row check can notice.
        f.setScope('parent', ['kid2']);
        await automatic.tick();
        const op = f.policy.operation({...actor, personIds: ALL}, id);
        assert.equal(op.state, 'failed'); assert.equal(op.error, 'actor_permission_changed_before_dispatch');
        assert.equal(f.applies().length, 0); assert.deepEqual(f.router.policy.pauses, []);
        assert.equal(f.store.integrationState().active_operation_id, null);
        // Control: with the scope intact the same path dispatches.
        f.setScope('parent', ['pilot', 'kid2']); f.advance(1); await automatic.tick();
        const again = await f.block(parent, 'pause_all'); await automatic.tick();
        assert.equal(f.policy.operation(f.wide, again.body.operation.id).state, 'confirmed');
    } finally { await automatic.stop(); f.cleanup(); }
});

test('a refused rpc-sync (a device without an address) fails the whole block with no partial state', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        assert.ok(PRE_WRITE_REJECTIONS.has('incomplete_address_coverage'));
        f.router.reject = 'incomplete_address_coverage';
        const r = await f.block(op, 'pause_all'); await f.dispatch(r.body.operation.id);
        const dto = f.policy.operation(f.wide, r.body.operation.id) as {state: string; error: string; effect?: string};
        assert.equal(dto.state, 'failed'); assert.equal(dto.error, 'incomplete_address_coverage'); assert.equal(dto.effect, 'not_blocking');
        assert.equal(f.applies().length, 1); assert.deepEqual(f.router.policy.pauses, []);
        assert.equal(f.store.integrationState().active_operation_id, null);
        f.router.reject = null; f.router.runtimeError = null; f.advance(1); await f.observe();
        assert.equal(f.applies().length, 1, 'no automatic retry');
    } finally { f.cleanup(); }
});

test('accepted but not healthy is unconfirmed: a block is NOT in force, a resume MAY STILL BE blocked; no retry; a fresh healthy observation settles it', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        f.router.transform = o => ({...o, status: {...o.status, drift: true}});
        const r = await f.block(op, 'pause_all'); const id = r.body.operation.id; await f.dispatch(id);
        let dto = f.policy.operation(f.wide, id) as {state: string; error: string; effect?: string; currentHealthy?: boolean};
        assert.equal(dto.state, 'unknown'); assert.equal(dto.error, 'accepted_router_runtime_unconfirmed'); assert.equal(dto.effect, 'not_blocking'); assert.equal(dto.currentHealthy, false);
        f.advance(1); await f.observe();
        dto = f.policy.operation(f.wide, id) as typeof dto;
        assert.equal(dto.state, 'unknown', 'stays unknown while observations stay unhealthy'); assert.equal(f.applies().length, 1);
        f.router.transform = null; f.advance(1); await f.observe();
        dto = f.policy.operation(f.wide, id) as typeof dto;
        assert.equal(dto.state, 'confirmed'); assert.equal(dto.effect, 'blocking'); assert.equal(f.applies().length, 1);
        // Resume: same shape.
        f.advance(1); await f.observe();
        f.router.transform = o => ({...o, status: {...o.status, drift: true}});
        const back = await f.block(op, 'resume_all'); await f.dispatch(back.body.operation.id);
        const resumed = f.policy.operation(f.wide, back.body.operation.id) as typeof dto;
        assert.equal(resumed.state, 'unknown'); assert.equal(resumed.effect, 'may_still_be_blocked');
    } finally { f.cleanup(); }
});

test('operation visibility is "any row": a viewer sees a bulk operation through any child in scope, and personId names a child they can see', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const r = await f.block(op, 'pause_all'); const id = r.body.operation.id;
        const onlyPilot: Actor = {...actor, role: 'parent', personIds: ['pilot']};
        assert.equal(f.policy.operation(onlyPilot, id).personId, 'pilot');
        assert.throws(() => f.policy.operation({...onlyPilot, personIds: ['nobody']}, id), code('operation_not_found'));
        assert.equal(f.policy.people(onlyPilot).people[0].latestOperation?.id, id, 'the latest operation of a non-representative child is the bulk one');
        assert.equal(f.policy.people(onlyPilot).people.length, 1);
    } finally { f.cleanup(); }
});

test('idempotent replay returns the same operation; a replay after the child set changed conflicts instead of re-targeting', async () => {
    const f = world();
    try {
        const parent = await f.signIn('parent'); await f.observe();
        const precondition = f.token();
        const first = await f.block(parent, 'pause_all', {precondition}, 'replay_key_1234567890');
        const again = await f.block(parent, 'pause_all', {precondition}, 'replay_key_1234567890');
        assert.equal(again.body.operation.id, first.body.operation.id); assert.equal(f.ops().length, 1);
        f.setScope('parent', ['pilot', 'kid2', 'kid3']);
        await assert.rejects(f.block(parent, 'pause_all', {precondition}, 'replay_key_1234567890'), code('idempotency_payload_conflict'));
        assert.equal(f.ops().length, 1); assert.deepEqual(f.rows(first.body.operation.id), ['kid2', 'pilot']);
    } finally { f.cleanup(); }
});

test('bulk input is strict: unknown fields, bad key or precondition, a past or malformed until, and a non-array change are refused', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const base = {until: 0, precondition: f.token()};
        const go = async (body: Record<string, unknown>, key = 'strict_key_1234567890', action: BulkAction = 'pause_all') => f.bulk.perform(op.session(), action, key, {...base, ...body, stepUp: await f.bulkStepUp(op, action, base)});
        await assert.rejects(go({extra: 1}), code('invalid_fields'));
        await assert.rejects(go({}, 'short'), code('idempotency_key_required'));
        await assert.rejects(go({precondition: 'W/"x"'}), code('revision_precondition_required'));
        await assert.rejects(go({until: 5}), code('pause_expiry_must_be_future'));
        await assert.rejects(f.bulk.stepUpOptions(op.session(), {action: 'pause_all', params: {until: 'soon', precondition: f.token()}}), (e: {code?: string}) => typeof e.code === 'string');
        await assert.rejects(f.bulk.stepUpOptions(op.session(), {action: 'delete_all', params: {}}), code('invalid_action'));
        await assert.rejects(f.bulk.perform(op.session(), 'resume_all', 'strict_key_2234567890', {precondition: f.token(), until: 0, stepUp: await f.bulkStepUp(op, 'resume_all', {precondition: f.token()})}), (e: {code?: string}) => typeof e.code === 'string');
        assert.equal(f.ops().length, 0);
    } finally { f.cleanup(); }
});

test('move: ONE operation, build is withoutDevice(A) then withDevice(B), the row is `moving` until an OBSERVATION shows the MAC under B', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const r = await f.move(op, 'd_kid2', 'kid3');
        assert.equal(r.status, 202); const id = r.body.operation.id;
        assert.equal(r.body.operation.action, 'move');
        assert.equal(f.ops().length, 1); assert.deepEqual(f.rows(id), ['kid2', 'kid3']);
        const row = () => f.store.get<{person_id: string; state: string; move_to: string | null}>("SELECT person_id,state,move_to FROM devices WHERE id='d_kid2'")!;
        assert.deepEqual({...row()}, {person_id: 'kid2', state: 'moving', move_to: 'kid3'});
        assert.equal(f.policy.people(f.wide).people.find(p => p.id === 'kid2')!.devices[0].change, 'moving');
        // The apply happens, but the reply is lost: the receipt is not an observation, so the row stays `moving`.
        f.router.afterApplyFailure = new (await import('../src/router-transport.ts')).RouterTransportError('ssh_timeout_after_send', 'possible');
        await f.dispatch(id);
        assert.equal(f.applies().length, 1);
        assert.deepEqual({...row()}, {person_id: 'kid2', state: 'moving', move_to: 'kid3'});
        assert.equal(f.policy.operation(f.wide, id).state, 'unknown');
        f.router.afterApplyFailure = null; f.advance(1); await f.observe();
        assert.equal(f.policy.operation(f.wide, id).state, 'confirmed');
        assert.deepEqual({...row()}, {person_id: 'kid3', state: 'active', move_to: null});
        assert.deepEqual(f.router.policy.people, [{id: 'kid3', macs: [K2, K3]}, {id: 'pilot', macs: [SEED]}]);
        assert.equal(f.router.policy.revision, 2, 'one revision, not two');
        assert.equal(f.applies().length, 1);
    } finally { f.cleanup(); }
});

test('move: a receipt that is no longer current never moves the row; the observation decides (back under the old child)', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const before = f.router.policy;
        f.router.afterApply = () => { f.router.policy = normalizePolicy({...before, revision: before.revision + 5}, f.config.protectedMacs); };
        const r = await f.move(op, 'd_kid2', 'kid3'); await f.dispatch(r.body.operation.id);
        assert.equal(f.policy.operation(f.wide, r.body.operation.id).state, 'conflict');
        assert.deepEqual({...f.store.get("SELECT person_id,state,move_to FROM devices WHERE id='d_kid2'")!}, {person_id: 'kid2', state: 'active', move_to: null});
    } finally { f.cleanup(); }
});

test('move refuses a full target (409), the same child, a busy device, a protected or unknown device, and keeps MAC uniqueness', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        for (let i = 0; i < 31; i++) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'enrolling',?)", `x${i}`, 'kid3', `X${i}`, `02:10:20:30:41:${(16 + i).toString(16)}`, f.now());
        await assert.rejects(f.move(op, 'd_kid2', 'kid3'), (e: {status?: number; code?: string}) => e.code === 'child_device_limit_reached');
        await assert.rejects(f.move(op, 'd_kid2', 'kid2'), code('device_move_same_child'));
        await assert.rejects(f.move(op, 'd_kid2', 'ghost'), code('person_not_found'));
        await assert.rejects(f.move(op, 'nope', 'pilot'), code('device_not_found'));
        assert.equal(f.ops().length, 0);
        const precondition = f.token();
        const ok = await f.move(op, 'd_kid2', 'pilot', {precondition});
        await assert.rejects(f.move(op, 'd_kid2', 'pilot', {precondition}), (e: {code?: string}) => ['device_change_in_progress', 'operation_in_progress', 'revision_conflict'].includes(e.code!));
        assert.equal(ok.status, 202);
        // Pure build: the MAC appears exactly once and the router MAC list stays unique.
        const moved = movePolicy(f.policyOf(1), f.config, 'kid2', 'kid3', K2);
        assert.equal(moved.people.flatMap(p => p.macs).filter(m => m === K2).length, 1);
        assert.equal(moved.revision, 2);
        assert.throws(() => movePolicy(f.policyOf(1), f.config, 'kid2', 'kid2', K2), code('device_move_same_child'));
    } finally { f.cleanup(); }
});

test('move needs authorization on BOTH children, at request and again at dispatch', async () => {
    const f = world({automatic: true}), automatic = new AutomaticDispatch(f.worker);
    try {
        const op = await f.signIn('operator'); await automatic.tick();
        f.store.run('UPDATE accounts SET scope_all=0 WHERE id=?', 'operator'); f.setScope('operator', ['pilot', 'kid2']);
        await assert.rejects(f.move(op, 'd_kid2', 'kid3'), code('person_not_found'));
        await assert.rejects(f.move(op, 'd_kid3', 'pilot'), code('device_not_found'));
        assert.equal(f.ops().length, 0);
        const queued = await f.move(op, 'd_kid2', 'pilot');
        f.setScope('operator', ['kid2']);
        await automatic.tick();
        const dto = f.policy.operation({...actor, personIds: ALL}, queued.body.operation.id);
        assert.equal(dto.state, 'failed'); assert.equal(dto.error, 'actor_permission_changed_before_dispatch');
        assert.deepEqual({...f.store.get("SELECT person_id,state,move_to FROM devices WHERE id='d_kid2'")!}, {person_id: 'kid2', state: 'active', move_to: null});
        assert.equal(f.applies().length, 0);
    } finally { await automatic.stop(); f.cleanup(); }
});

test('moving the last device of a child with an open time request is refused like removing it', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        f.store.run("INSERT INTO request_links(id,person_id,token_hash,created_by,created_at) VALUES('l1','kid2',?,'operator',?)", 'h'.repeat(64), f.now());
        f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at) VALUES('tr1','l1','kid2',15,'homework','pending',?,?)", f.now(), f.now() + 600);
        await assert.rejects(f.move(op, 'd_kid2', 'kid3'), code('child_has_pending_requests'));
    } finally { f.cleanup(); }
});

test('integration-005 rebuilds devices in place: rows, FKs and uniqueness survive, and reopening is a no-op', () => {
    const f = world();
    try {
        const path = `${f.dir}/integration.sqlite`;
        const sql = f.store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='devices'")!.sql;
        assert.ok(sql.includes("'moving'"));
        f.store.close();
        const db = new DatabaseSync(path);
        db.exec('PRAGMA foreign_keys=OFF');
        db.exec(`CREATE TABLE devices_old (id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES people(id), label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
            identifier_kind TEXT NOT NULL CHECK(identifier_kind IN ('mac')), identifier TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('enrolling','active','removing')),
            operation_id TEXT, created_at INTEGER NOT NULL, UNIQUE(identifier_kind,identifier)) STRICT;
            INSERT INTO devices_old SELECT id,person_id,label,identifier_kind,identifier,state,operation_id,created_at FROM devices;
            DROP TABLE devices; ALTER TABLE devices_old RENAME TO devices; CREATE INDEX devices_person ON devices(person_id);`);
        db.close();
        const store = new IntegrationStore(f.config);
        try {
            assert.ok(store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='devices'")!.sql.includes("'moving'"));
            assert.deepEqual(store.all('SELECT identifier FROM devices ORDER BY identifier').map(r => (r as {identifier: string}).identifier), [SEED, K2, K3]);
            assert.deepEqual(store.all('PRAGMA foreign_key_check'), []);
            assert.throws(() => store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('dup','pilot','D','mac',?,'active',1)", K2));
            assert.throws(() => store.run("UPDATE devices SET state='moving' WHERE id='d_kid2'"), 'moving requires a target');
            store.run("UPDATE devices SET state='moving',move_to='kid3' WHERE id='d_kid2'");
        } finally { store.close(); }
        new IntegrationStore(f.config).close();
    } finally { rmSync(f.dir, {recursive: true, force: true}); }
});

test('HTTP: bulk and move routes are CSRF/Origin-checked and step-up gated; step-up options route by action', async () => {
    const f = world(), port = 36000 + process.pid % 9000, base = `http://localhost:${port}`;
    const auth = new Auth(f.store, base, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: base, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        const sign = async (account: string) => {
            const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
            const options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, account, f.now())}, browser);
            const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, base)}, browser);
            return {key, cookie: `cf_session=${result.token}; cf_browser=${browser}`, csrf: result.dto.csrfToken};
        };
        const op = await sign('operator'), parent = await sign('parent'); await f.observe();
        const call = (who: {cookie: string; csrf: string}, path: string, body: unknown, headers: Record<string, string> = {}) => fetch(base + path, {method: 'POST',
            headers: {Cookie: who.cookie, Origin: base, 'Content-Type': 'application/json', 'X-CSRF-Token': who.csrf, ...headers}, body: JSON.stringify(body)});
        const params = {until: 0, precondition: f.token()};
        assert.equal((await call(op, '/bulk/pause-all', {...params}, {'X-CSRF-Token': 'wrong'})).status, 403);
        assert.equal((await call(op, '/bulk/pause-all', {...params}, {Origin: 'http://evil.example.test'})).status, 403);
        assert.equal((await call(op, '/bulk/pause-all', {...params}, {'Idempotency-Key': 'http_key_1234567890'})).status, 403, 'no step-up proof, nothing queued');
        assert.equal((await call(op, '/bulk/pause-all', {...params, extra: 1}, {'Idempotency-Key': 'http_key_1234567890'})).status, 400);
        const options = await call(parent, '/step-up/options', {action: 'pause_all', params});
        assert.equal(options.status, 200);
        const challenge = await options.json();
        const full = await call(parent, '/bulk/pause-all', {...params, stepUp: {challengeId: challenge.challengeId, response: parent.key.login(challenge.options, base)}}, {'Idempotency-Key': 'http_key_2234567890'});
        assert.equal(full.status, 202);
        assert.equal(f.rows((await full.json()).operation.id).join(), 'kid2,pilot');
        // Move is admin-only like the other device changes.
        assert.equal((await call(parent, '/step-up/options', {action: 'device_move', target: 'd_kid2', params: {to: 'pilot', precondition: null}})).status, 403);
        assert.equal((await call(op, '/admin/devices/d_kid2/move', {to: 'pilot', precondition: null})).status, 403, 'the route exists and demands a step-up proof');
    } finally { server.close(); server.closeAllConnections(); f.cleanup(); }
});

test('a confirmed bulk operation that names a child supersedes that child\'s owed re-pause, even when the child is not its representative', async () => {
    const f = world();
    try {
        const now = f.now(), mutate: string[] = [];
        f.store.run("INSERT INTO request_links(id,person_id,token_hash,created_by,created_at,revoked_at,revoked_by) VALUES('l1','pilot',?,'operator',?,?,'operator')", 'h'.repeat(64), now - 2000, now - 100);
        f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at,decided_by,decided_at,granted_minutes,allowance_until,original_pause_until,repause_state) VALUES('req-1','l1','pilot',15,'','approved',?,?,'operator',?,15,?,0,'waiting')", now - 1500, now - 600, now - 1000, now - 10);
        const insert = (id: string, person: string, revision: number, key: string) => f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES(?,?,?,?,?,'confirmed','{}','{}','{}',?,?,?)", id, 'operator', person, person === 'pilot' ? 'resume' : 'resume_all', revision, key, now - 900, now - 900);
        insert('own', 'pilot', 3, 'tr-req-1-r1'); insert('bulk', 'kid2', 5, 'bulk_key_1234567890');
        f.store.run("INSERT INTO operation_people(operation_id,person_id) VALUES('bulk','kid2'),('bulk','pilot')");
        const policy = {people: () => { mutate.push('people'); return {people: [], revisionToken: null}; }, mutate: () => { mutate.push('mutate'); return {status: 200, result: {operation: {id: 'x', state: 'confirmed'}}}; }, now: f.now, devices: () => ({}), operation: () => ({}), reconcile: () => undefined};
        await new TimeRequestService(f.store, policy as never, f.now).advance();
        assert.equal(f.store.get<{repause_state: string}>("SELECT repause_state FROM time_requests WHERE id='req-1'")!.repause_state, 'superseded');
        assert.deepEqual(mutate, []);
    } finally { f.cleanup(); }
});

/** A child owed a re-pause after an approved allowance (pilot, originally paused indefinitely), with the service's own resume already recorded. */
function oweRepause(f: ReturnType<typeof world>) {
    const now = f.now();
    f.store.run("INSERT INTO request_links(id,person_id,token_hash,created_by,created_at,revoked_at,revoked_by) VALUES('l1','pilot',?,'operator',?,?,'operator')", 'h'.repeat(64), now - 2000, now - 100);
    f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at,decided_by,decided_at,granted_minutes,allowance_until,original_pause_until,repause_state) VALUES('req-1','l1','pilot',15,'','approved',?,?,'operator',?,15,?,0,'waiting')", now - 1500, now - 600, now - 1000, now + 5);
    const calls: string[] = [];
    const policy = {people: () => { calls.push('people'); return {people: [{id: 'pilot', manualPause: null}], revisionToken: 'x'}; },
        mutate: () => { calls.push('mutate'); return {status: 202, result: {operation: {id: 'x', state: 'pending'}}}; }, now: f.now, devices: () => ({}), operation: () => ({}), reconcile: () => undefined};
    /** The service's own earlier resume (revision 0); recorded after any queued change so that change is the LATER one. */
    const resumed = () => f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES('own','operator','pilot','resume',0,'confirmed','{}','{}','{}','tr-req-1-r1',?,?)", now - 900, now - 900);
    return {calls, resumed, advance: () => new TimeRequestService(f.store, policy as never, f.now).advance(),
        state: () => f.store.get<{repause_state: string}>("SELECT repause_state FROM time_requests WHERE id='req-1'")!.repause_state};
}

test('H1: a pending move naming a child does NOT supersede its owed re-pause', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const owed = oweRepause(f);
        assert.equal((await f.move(op, 'd_kid2', 'pilot')).status, 202);
        owed.resumed(); f.advance(10);
        await owed.advance();
        assert.notEqual(owed.state(), 'superseded');
        assert.ok(owed.calls.includes('mutate'), 'the re-pause is still attempted (the mutate itself gets operation_in_progress and the backoff retries)');
    } finally { f.cleanup(); }
});

test('H1: a pending pause_all that is later refused leaves the re-pause owed, never superseded', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const owed = oweRepause(f);
        const r = await f.block(op, 'pause_all', {until: 0});
        owed.resumed(); f.advance(10);
        await owed.advance();
        assert.notEqual(owed.state(), 'superseded');
        f.router.reject = 'incomplete_address_coverage';
        await f.dispatch(r.body.operation.id);
        assert.equal(f.policy.operation(f.wide, r.body.operation.id).state, 'failed');
        await owed.advance();
        assert.notEqual(owed.state(), 'superseded');
    } finally { f.cleanup(); }
});

test('H1: a CONFIRMED move does not supersede the re-pause either; only a confirmed pause/resume family op does', async () => {
    const f = world();
    try {
        const owed = oweRepause(f); owed.resumed(); f.advance(10);
        const insert = (id: string, action: string, revision: number, key: string) => f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES(?,'operator','pilot',?,?,'confirmed','{}','{}','{}',?,?,?)", id, action, revision, key, f.now() - 800, f.now() - 800);
        insert('mv', 'move', 4, 'move_key_1234567890'); insert('en', 'enroll', 5, 'enroll_key_123456789');
        await owed.advance();
        assert.notEqual(owed.state(), 'superseded');
        insert('ps', 'pause_all', 6, 'pause_key_123456789');
        f.store.run("UPDATE time_requests SET repause_state='waiting',next_attempt_at=NULL WHERE id='req-1'");
        await owed.advance();
        assert.equal(owed.state(), 'superseded');
    } finally { f.cleanup(); }
});

test('H2: removing a child that is the TARGET of a moving device is refused (409 device_change_in_progress)', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES('kid4','Kid 4','child',1,?)", f.now());
        f.setScope('operator', [...ALL, 'kid4']);
        const r = await f.move(op, 'd_kid2', 'kid4');
        const opts = await f.admin.stepUpOptions(op.session(), {action: 'child_remove', target: 'kid4', params: {}});
        await assert.rejects(f.admin.perform(op.session(), 'child_remove' as ChildAction, 'kid4', {stepUp: {challengeId: opts.challengeId, response: op.key.login(opts.options, origin)}}), code('device_change_in_progress'));
        assert.equal(f.store.get<{active: number}>("SELECT active FROM people WHERE id='kid4'")!.active, 1);
        await f.dispatch(r.body.operation.id);
        assert.equal(f.store.get<{person_id: string}>("SELECT person_id FROM devices WHERE id='d_kid2'")!.person_id, 'kid4');
    } finally { f.cleanup(); }
});

test('H2: at settle time a target child that became inactive gets no device; it reverts to the source with a drift error', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES('kid4','Kid 4','child',1,?)", f.now());
        f.setScope('operator', [...ALL, 'kid4']);
        const r = await f.move(op, 'd_kid2', 'kid4');
        // The target is removed while the apply is in flight (after the dispatch-time authorization), so only the settle step can catch it.
        f.router.afterApply = () => f.store.run("UPDATE people SET active=0 WHERE id='kid4'");
        await f.dispatch(r.body.operation.id);
        assert.deepEqual({...f.store.get("SELECT person_id,state,move_to FROM devices WHERE id='d_kid2'")!}, {person_id: 'kid2', state: 'active', move_to: null});
        assert.equal(f.store.get<{error: string}>('SELECT error FROM operations WHERE id=?', r.body.operation.id)!.error, 'device_move_drift');
    } finally { f.cleanup(); }
});

test('C-M2: a moved device the observation shows under NEITHER child stays active under the source with a drift error (conflict)', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const before = f.router.policy;
        f.router.afterApply = () => { f.router.policy = normalizePolicy({...before, revision: before.revision + 5, people: before.people.filter(p => p.id !== 'kid2')}, f.config.protectedMacs); };
        const r = await f.move(op, 'd_kid2', 'kid3'); await f.dispatch(r.body.operation.id);
        assert.equal(f.store.get<{state: string}>('SELECT state FROM operations WHERE id=?', r.body.operation.id)!.state, 'conflict');
        assert.deepEqual({...f.store.get("SELECT person_id,state,move_to,label FROM devices WHERE id='d_kid2'")!}, {person_id: 'kid2', state: 'active', move_to: null, label: 'Device kid2'});
        assert.equal(f.store.get<{error: string}>('SELECT error FROM operations WHERE id=?', r.body.operation.id)!.error, 'device_move_drift');
    } finally { f.cleanup(); }
});

test('M1: pause_all never shortens an existing pause: indefinite stays indefinite, a later expiry stays later', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator');
        const later = f.now() + 5000, sooner = f.now() + 100;
        f.router.policy = f.policyOf(1, {pauses: [{person: 'kid2', until: 0}, {person: 'kid3', until: later}]});
        await f.observe();
        const r = await f.block(op, 'pause_all', {until: sooner});
        await f.dispatch(r.body.operation.id);
        const pauses = Object.fromEntries(f.router.policy.pauses.map(p => [p.person, p.until]));
        assert.deepEqual(pauses, {kid2: 0, kid3: later, pilot: sooner});
        // And the other way: an indefinite pause_all extends a finite one.
        f.advance(1); await f.observe();
        const again = await f.block(op, 'pause_all', {until: 0});
        await f.dispatch(again.body.operation.id);
        assert.deepEqual(Object.fromEntries(f.router.policy.pauses.map(p => [p.person, p.until])), {kid2: 0, kid3: 0, pilot: 0});
    } finally { f.cleanup(); }
});

test('L1: the operator dispatch path also re-checks every operation_people row; a narrowed scope refuses the dispatch', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const r = await f.block(op, 'pause_all', {until: 0});
        f.setScope('operator', ['pilot', 'kid2']);
        await f.dispatch(r.body.operation.id);
        assert.equal(f.applies().length, 0);
        const dto = f.policy.operation(f.wide, r.body.operation.id);
        assert.equal(dto.state, 'failed'); assert.equal(dto.error, 'actor_permission_changed_before_dispatch');
    } finally { f.cleanup(); }
});

test('L3: the tr- idempotency-key prefix is reserved for the time-request service; client keys cannot use it', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        await assert.rejects(f.block(op, 'pause_all', {until: 0}, 'tr-req-1-r1-abcdefgh'), code('idempotency_key_required'));
        assert.equal(f.ops().length, 0);
        assert.equal((await f.block(op, 'pause_all', {until: 0}, 'trx-req-1-r1-abcdefgh')).status, 202);
    } finally { f.cleanup(); }
});
