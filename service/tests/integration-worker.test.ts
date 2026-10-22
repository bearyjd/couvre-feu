import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { integrationFixture, actor, testConfig, TestRouter } from './fixtures/integration.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { IntegrationWorker } from '../src/integration-worker.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { policyDigest, sha256 } from '../../shared/src/router-rpc.ts';

test('integration defaults make no calls; HTTP facade only queues an exact durable intent', async () => {
    const f = integrationFixture();
    try {
        assert.equal(f.store.integrationState().dispatch_stopped, 1);
        for (let n = 0; n < 4; n++) { f.policy.people(actor); f.policy.devices(actor); f.policy.reconcile(); }
        assert.throws(() => f.pause(), /revision_precondition_required/);
        assert.equal(f.router.calls.length, 0);
        await f.observe();
        const result = f.pause(f.now() + 60), id = result.result.operation.id;
        assert.equal(result.status, 202); assert.equal(result.result.operation.dispatch, 'awaiting_operator_dispatch');
        assert.equal(f.router.calls.length, 1);
        assert.equal(f.store.integrationState().active_operation_id, id);
        const e = f.policy.envelope(id);
        assert.equal(e.policy.pauses[0].until, f.now() + 60); assert.equal(e.expected_digest, policyDigest(f.config.enrollment));
        const originalToken = JSON.parse(f.store.get<{request_json: string}>('SELECT request_json FROM operations WHERE id=?', id)!.request_json).precondition;
        assert.equal(f.policy.mutate(actor, 'pilot', 'pause', {until: f.now() + 60}, originalToken, 'test_key_123456789').result.operation.id, id);
        assert.equal(f.router.calls.length, 1);
        assert.throws(() => f.policy.mutate(actor, 'pilot', 'resume', {}, originalToken, 'second_key_123456789'), /revision_conflict|operation_in_progress/);
    } finally { f.cleanup(); }
});
test('one exact approval dispatches once and 200 requires fresh exact current runtime', async () => {
    const f = integrationFixture();
    try {
        await f.observe(); const result = f.pause(), id = result.result.operation.id, plan = f.worker.prepare('apply', id);
        await assert.rejects(f.worker.execute(plan, '0'.repeat(64)), /exact_operator_approval_required/);
        assert.equal(f.router.calls.length, 1);
        await f.worker.execute(plan, plan.scriptSha256);
        assert.equal(f.policy.operation(actor, id).state, 'confirmed');
        assert.equal(f.policy.operation(actor, id).accepted, true);
        await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /dispatch_permit_already_consumed/);
        assert.equal(f.router.calls.length, 2);
        f.advance(31);
        const dto = f.policy.operation(actor, id);
        assert.equal(dto.state, 'unknown'); assert.equal(dto.currentHealthy, false); assert.equal(dto.confirmedAt, f.now() - 31);
        assert.equal(f.policy.people(actor).routerConfirmedRevision, null); assert.equal(f.policy.people(actor).revisionToken, null);
    } finally { f.cleanup(); }
});
test('changed plan payload, target, timeout and script fail before transport', async () => {
    const f = integrationFixture();
    try {
        const plan = f.worker.prepare('observe');
        for (const changed of [ {...plan, targetDigest: '0'.repeat(64)}, {...plan, invocation: {...plan.invocation, stdin: '{}'}}, {...plan, invocation: {...plan.invocation, deadlineMs: 30000}}, {...plan, script: plan.script + '\n'} ]) await assert.rejects(f.worker.execute(changed, plan.scriptSha256));
        assert.equal(f.router.calls.length, 0);
        f.advance(901); await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /dispatch_plan_stale_or_changed/);
    } finally { f.cleanup(); }
});
test('deferred I/O releases SQLite and competing processes cannot consume an invocation twice', async () => {
    const f = integrationFixture(); let release!: () => void;
    const second = new IntegrationStore(f.config), competing = new IntegrationWorker(second, new TestRouter(second, f.now), f.now);
    try {
        await f.observe(); const id = f.pause().result.operation.id, plan = f.worker.prepare('apply', id);
        f.router.defer = new Promise<void>(resolve => {release = resolve;});
        const work = f.worker.execute(plan, plan.scriptSha256);
        assert.equal(f.store.db.isTransaction, false);
        second.transaction(() => second.run("INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES('operator','parallel_local_write',?,'ok')", f.now()));
        await assert.rejects(competing.execute(plan, plan.scriptSha256), /dispatch_permit_already_consumed/);
        assert.equal(f.router.calls.length, 2); release(); await work;
        assert.equal(f.policy.operation(actor, id).state, 'confirmed');
    } finally { second.close(); f.cleanup(); }
});
test('disconnect after acceptance persists unknown and exact receipt resolves without replay or renewed expiry', async () => {
    const f = integrationFixture();
    try {
        await f.observe(); const until = f.now() + 60, id = f.pause(until).result.operation.id, plan = f.worker.prepare('apply', id);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response');
        await f.worker.execute(plan, plan.scriptSha256);
        assert.equal(f.policy.operation(actor, id).state, 'unknown'); assert.equal(f.store.integrationState().active_operation_id, id);
        f.advance(1); const replay = f.worker.prepare('apply', id);
        await assert.rejects(f.worker.execute(replay, replay.scriptSha256), /operation_dispatch_not_eligible/);
        assert.equal(f.router.calls.length, 2);
        f.advance(70); f.router.afterApplyFailure = null;
        const receipt = f.worker.prepare('receipt', id); await f.worker.execute(receipt, receipt.scriptSha256);
        assert.equal(f.router.calls.length, 3); assert.equal(f.policy.operation(actor, id).state, 'confirmed');
        assert.equal(f.policy.envelope(id).policy.pauses[0].until, until); assert.deepEqual(f.router.policy.pauses, [{person: 'pilot', until}]);
        assert.deepEqual(f.policy.people(actor).people[0].effectiveManualPause, null);
    } finally { f.cleanup(); }
});
test('receipt absence and lease expiry cannot authorize reapply; late callbacks cannot replace newer observations', async () => {
    const f = integrationFixture(); let release!: () => void;
    try {
        await f.observe(); const id = f.pause().result.operation.id, plan = f.worker.prepare('apply', id);
        f.router.defer = new Promise<void>(resolve => {release = resolve;}); const work = f.worker.execute(plan, plan.scriptSha256);
        f.advance(18); f.router.defer = null;
        const receipt = f.worker.prepare('receipt', id); await f.worker.execute(receipt, receipt.scriptSha256);
        assert.equal(f.policy.operation(actor, id).state, 'unknown'); assert.equal(f.store.integrationState().active_operation_id, id);
        assert.equal(f.store.observation().value!.acceptedPolicy.revision, 0);
        release(); await work;
        assert.equal(f.store.observation().value!.acceptedPolicy.revision, 0);
        const retry = f.worker.prepare('apply', id); await assert.rejects(f.worker.execute(retry, retry.scriptSha256), /operation_dispatch_not_eligible/);
        f.advance(1); const resolved = f.worker.prepare('receipt', id); await f.worker.execute(resolved, resolved.scriptSha256);
        assert.equal(f.policy.operation(actor, id).state, 'confirmed');
    } finally { f.cleanup(); }
});
test('shutdown fences late replies and old permits without any autonomous transport', async () => {
    const f = integrationFixture(); let release!: () => void;
    try {
        await f.observe(); const id = f.pause().result.operation.id, old = f.worker.prepare('apply', id);
        f.router.defer = new Promise<void>(resolve => {release = resolve;}); const work = f.worker.execute(old, old.scriptSha256);
        f.store.stopDispatch(f.now()); release(); await work;
        assert.equal(f.policy.operation(actor, id).state, 'unknown'); assert.equal(f.store.observation().value!.acceptedPolicy.revision, 0);
        await assert.rejects(f.worker.execute(old, old.scriptSha256), /dispatch_plan_stale_or_changed/);
        assert.equal(f.router.calls.length, 2);
    } finally { f.cleanup(); }
});
test('actual child crash after durable consumption remains unresolved across restart', async () => {
    const f = integrationFixture();
    try {
        await f.observe(); const id = f.pause(f.now() + 60).result.operation.id;
        const crash = spawnSync(process.execPath, ['service/tests/fixtures/integration-crash.ts', f.dir, id], {encoding: 'utf8'});
        assert.equal(crash.status, 23, crash.stderr);
        const claim = f.store.get<{attempt_count: number; phase: string; delivery: string}>('SELECT * FROM operation_rpc WHERE operation_id=?', id)!;
        assert.equal(claim.attempt_count, 1); assert.equal(claim.delivery, 'possible'); assert.equal(claim.phase, 'claimed');
        f.advance(18);
        const reopened = new IntegrationStore(testConfig(f.dir));
        try {
            const w = new IntegrationWorker(reopened, new TestRouter(reopened, f.now), f.now), plan = w.prepare('apply', id);
            await assert.rejects(w.execute(plan, plan.scriptSha256), /operation_dispatch_not_eligible/);
            assert.equal(reopened.integrationState().active_operation_id, id);
            assert.equal(f.policy.envelope(id).policy.pauses[0].until, f.now() + 42);
        } finally { reopened.close(); }
    } finally { f.cleanup(); }
});
test('missing runtime coverage, native, conntrack and IPv6 witnesses never confirm acceptance', async () => {
    for (const capability of ['addressCoverageComplete', 'nativeKernelConfirmed', 'conntrack', 'ipv6'] as const) {
        const f = integrationFixture();
        try {
            await f.observe(); const id = f.pause().result.operation.id;
            f.router.transform = o => ({...o, status: {...o.status, capabilities: {...o.status.capabilities, [capability]: false}}});
            const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256);
            const dto = f.policy.operation(actor, id); assert.equal(dto.state, 'unknown', capability); assert.equal(dto.accepted, true); assert.equal(dto.confirmedAt, null);
            assert.equal(f.policy.people(actor).packetAcceptance, 'unmeasured');
        } finally { f.cleanup(); }
    }
});
test('never-delivered transport failure is explicit, with a new deliberate intent allowed at the same CAS revision', async () => {
    const f = integrationFixture();
    try {
        await f.observe(); const id = f.pause().result.operation.id, plan = f.worker.prepare('apply', id);
        f.router.failure = new RouterTransportError('test_spawn_failed', 'not_delivered'); await f.worker.execute(plan, plan.scriptSha256);
        assert.equal(f.policy.operation(actor, id).state, 'failed'); assert.equal(f.store.integrationState().active_operation_id, null);
        f.router.failure = null; f.advance(1); await f.observe();
        const next = f.pause(0, 'new_intent_123456789'); assert.notEqual(next.result.operation.id, id); assert.equal(next.result.operation.revision, 1);
    } finally { f.cleanup(); }
});
test('queued same-revision changed policy conflicts before dispatch and invalid generation never overwrites cache', async () => {
    const f = integrationFixture();
    try {
        await f.observe(); const id = f.pause().result.operation.id, plan = f.worker.prepare('apply', id);
        f.router.policy = {...f.router.policy, doh: {ipv4: ['1.1.1.1'], ipv6: []}};
        f.advance(1); await f.observe();
        assert.equal(f.policy.operation(actor, id).state, 'conflict');
        await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /operation_dispatch_not_eligible/);
        const before = JSON.stringify(f.store.observation());
        f.router.transform = o => ({...o, generation: 'f'.repeat(64)}); f.advance(1); await f.observe();
        assert.equal(JSON.stringify(f.store.observation()), before); assert.equal(f.store.integrationState().observation_error, 'router_generation_changed');
    } finally { f.cleanup(); }
});
test('restart revokes old permits but preserves a never-dispatched queued identity and exact payload', async () => {
    const f = integrationFixture();
    try {
        await f.observe(); const id = f.pause(f.now() + 60).result.operation.id, old = f.worker.prepare('apply', id), envelope = JSON.stringify(f.policy.envelope(id));
        f.store.stopDispatch(f.now());
        assert.equal(f.policy.operation(actor, id).state, 'pending');
        await assert.rejects(f.worker.execute(old, old.scriptSha256), /dispatch_plan_stale_or_changed/);
        const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256);
        assert.equal(f.policy.operation(actor, id).state, 'confirmed'); assert.equal(JSON.stringify(f.policy.envelope(id)), envelope);
    } finally { f.cleanup(); }
});
test('a fresh superseding local policy makes historical confirmation conflict, and permits a new deliberate intent', async () => {
    const f = integrationFixture();
    try {
        await f.observe(); const id = f.pause().result.operation.id, plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256);
        f.router.policy = {...f.router.policy, revision: 2, pauses: []}; f.advance(1); await f.observe();
        const prior = f.policy.operation(actor, id); assert.equal(prior.state, 'conflict'); assert.equal(prior.currentHealthy, false); assert.equal(prior.accepted, true); assert.notEqual(prior.confirmedAt, null);
        assert.equal(f.policy.people(actor).people[0].status, 'conflict'); assert.notEqual(f.policy.people(actor).revisionToken, null);
        const next = f.pause(0, 'next_intent_123456789'); assert.equal(next.result.operation.revision, 3); assert.equal(next.status, 202);
    } finally { f.cleanup(); }
});
test('an empty installed policy can be observed but cannot falsely enable the configured device before enrollment', async () => {
    const f = integrationFixture();
    try {
        f.router.policy = {...f.router.policy, people: []}; await f.observe();
        const people = f.policy.people(actor); assert.equal(people.people[0].status, 'unknown'); assert.equal(people.revisionToken, null); assert.ok(people.errors.includes('pilot_device_not_enrolled'));
    } finally { f.cleanup(); }
});
// Only the router's own pre-write refusal of this attempt (one of the four codes, base unchanged, no receipt, not named
// current) fails a change; anything else stays unknown because the outcome cannot be proven.
const PRE_WRITE = ['incomplete_address_coverage', 'incomplete_transition_address_coverage', 'rpc_scope_overlap', 'protected_mac_overlap'];
async function refusedApply(reject: string, transform: ((o: any, id: string) => any) | null, before?: (f: ReturnType<typeof integrationFixture>) => void) {
    const f = integrationFixture();
    try {
        await f.observe(); const id = f.pause().result.operation.id, plan = f.worker.prepare('apply', id);
        before?.(f);
        f.router.reject = reject; f.router.transform = transform && (o => transform(o, id));
        await f.worker.execute(plan, plan.scriptSha256);
        return {op: f.policy.operation(actor, id), active: f.store.integrationState().active_operation_id, id};
    } finally { f.cleanup(); }
}
test('each pre-write router refusal of this attempt fails the change and clears the active operation', async () => {
    for (const code of PRE_WRITE) {
        const r = await refusedApply(code, null);
        assert.equal(r.op.state, 'failed', code); assert.equal(r.op.error, code); assert.equal(r.active, null, code);
    }
});
test('a refusal that is not provably pre-write stays unknown, never failed', async () => {
    const unknown = (r: Awaited<ReturnType<typeof refusedApply>>, label: string) => {
        assert.equal(r.op.state, 'unknown', label); assert.equal(r.op.error, 'receipt_missing_remote_outcome_unknown', label); assert.equal(r.active, r.id, label);
    };
    unknown(await refusedApply('apply_failed', null), 'other code');
    unknown(await refusedApply('rpc_scope_overlap', null, f => { f.router.policy = {...f.router.policy, doh: {ipv4: ['1.1.1.1'], ipv6: []}}; }), 'base changed');
    unknown(await refusedApply('rpc_scope_overlap', o => ({...o, errors: ['incomplete_address_coverage', 'apply_failed']})), 'mixed codes');
    unknown(await refusedApply('rpc_scope_overlap', (o, id) => ({...o, currentOperationId: id})), 'router names it current');
    unknown(await refusedApply('rpc_scope_overlap', o => ({...o, receipt: {operationId: 'op_other', requestDigest: 'a'.repeat(64), baseRevision: 0, baseDigest: 'b'.repeat(64), acceptedRevision: 1, acceptedDigest: 'c'.repeat(64), outcome: 'accepted', current: false}})), 'receipt present');
    unknown(await refusedApply('rpc_scope_overlap', o => ({...o, errors: []})), 'no errors');
});
// M0 pin (tier1 plan, receipt eviction): a null receipt for the service's own attempted operation is never success and never
// provably failed. The router will evict receipts, so absence must settle as unknown and keep the operation active.
test('apply reply with a null receipt and a non-pre-write error is unknown, never confirmed', async () => {
    const r = await refusedApply('apply_failed', o => ({...o, errors: ['apply_failed'], receipt: null}));
    assert.equal(r.op.state, 'unknown'); assert.equal(r.op.error, 'receipt_missing_remote_outcome_unknown');
    assert.equal(r.op.accepted, false); assert.equal(r.op.confirmedAt, null); assert.equal(r.active, r.id);
});
test('receipt poll returning null after eviction while policy moved on is unknown, not success', async () => {
    const f = integrationFixture();
    try {
        await f.observe(); const id = f.pause(f.now() + 60).result.operation.id, plan = f.worker.prepare('apply', id);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response');
        await f.worker.execute(plan, plan.scriptSha256);
        assert.equal(f.policy.operation(actor, id).state, 'unknown');
        f.router.afterApplyFailure = null; f.router.policy = {...f.router.policy, revision: 2, pauses: []};
        f.router.transform = o => ({...o, receipt: null}); f.advance(70);
        const receipt = f.worker.prepare('receipt', id); await f.worker.execute(receipt, receipt.scriptSha256);
        const op = f.policy.operation(actor, id);
        assert.equal(op.state, 'unknown'); assert.equal(op.accepted, false); assert.equal(op.confirmedAt, null);
        assert.equal(f.store.integrationState().active_operation_id, id);
    } finally { f.cleanup(); }
});

test('S3: an observation whose scope holds a protected MAC, or misses a floor MAC, is invalid and changes nothing', async () => {
    const f = integrationFixture();
    try {
        const SEED = '02:10:20:30:40:50', PROTECTED = f.config.protectedMacs[0], OTHER = '02:10:20:30:40:52';
        (f.config as {routerScope?: string[]}).routerScope = [SEED];
        const shaOf = (scope: string[]) => sha256(scope.join('\n') + '\n');
        f.router.transform = o => ({...o, scope: [SEED], scopeSha: shaOf([SEED])}); await f.observe();
        const observedScope = () => JSON.stringify(f.store.get('SELECT * FROM router_scope_observed'));
        const before = observedScope();
        for (const scope of [[SEED, PROTECTED], [OTHER]]) {
            f.advance(1); f.router.transform = o => ({...o, scope, scopeSha: shaOf(scope)}); await f.observe();
            assert.equal(f.store.integrationState().observation_error, 'router_observation_invalid', JSON.stringify(scope));
            assert.equal(f.policy.fresh(), false);
            assert.equal(observedScope(), before);
        }
    } finally { f.cleanup(); }
});
