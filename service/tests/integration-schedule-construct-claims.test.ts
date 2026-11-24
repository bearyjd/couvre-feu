import test from 'node:test';
import assert from 'node:assert/strict';
import { RouterTransportError } from '../src/router-transport.ts';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { IntegrationPolicy } from '../src/integration-policy.ts';
import { rebindIntegration } from '../src/integration-rebind.ts';
import { actor } from './fixtures/integration.ts';
import { active, applies, apply, applyLease, at, editId, night, op, openSteps, rebind, routerChange, world } from './fixtures/schedule-settle.ts';
import type { World } from './fixtures/schedule-settle.ts';

// Roadmap item 2, S2a (schedules.editable, off; unverified on this router): the write claim across crashes. Each case manipulates the
// stored claim rows the way a crash or a lost write would leave them, then drives the real worker.

/** Starts an apply whose invocation waits until `release()`; the claim is committed when this returns. */
function heldApply(f: World, id: string): {release: () => void; done: Promise<void>} {
    const plan = f.worker.prepare('apply', id);
    let release: () => void = () => {};
    f.router.defer = new Promise<void>(resolve => { release = resolve; });
    const done = f.worker.execute(plan, plan.scriptSha256);
    f.router.defer = null;
    return {release, done};
}
async function unseenApply(f: World, id: string): Promise<void> {
    f.router.failure = new RouterTransportError('invalid_router_response');
    await apply(f, id); f.router.failure = null;
}
/** The operation_rpc row as it was before the claim (a crash that lost its update); the apply step survives. */
function revertRpcClaim(f: World, id: string): void {
    f.store.run("UPDATE operation_rpc SET phase='queued',claim_token=NULL,claim_epoch=NULL,lease_until=NULL,attempt_count=0,delivery='not_dispatched' WHERE operation_id=?", id);
    f.store.run("UPDATE operations SET state='pending',error='awaiting_operator_dispatch' WHERE id=?", id);
}
/** Runs `hook` on the first router.invocation() call: inside run(), after the outer validate read the envelope, before the claim. */
function beforeClaim(f: World, hook: () => void): void {
    const original = f.router.invocation.bind(f.router);
    let calls = 0;
    f.router.invocation = (...args: Parameters<typeof original>) => { if (++calls === 1) hook(); return original(...args); };
}
const corruptRpc: Record<string, (f: World, id: string) => void> = {
    'missing rpc row': (f, id) => { f.store.run('DELETE FROM operation_rpc WHERE operation_id=?', id); },
    'malformed envelope': (f, id) => { f.store.run("UPDATE operation_rpc SET envelope_json='{' WHERE operation_id=?", id); },
};

test('C1 S0 while our write is in flight keeps the claim: no rebind until the fence, then the edit ends and rebind is possible', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]), held = heldApply(f, id), lease = applyLease(f, id);
        f.store.run('UPDATE operations SET request_json=? WHERE id=?', JSON.stringify({person: 'pilot', action: 'schedule_update', windows: [], precondition: null}), id);
        assert.throws(() => f.worker.prepare('apply', id), /schedule_payload_inadmissible/);
        assert.deepEqual([op(f, id).state, op(f, id).error, active(f)], ['unknown', 'schedule_payload_inadmissible', id]);
        assert.ok(openSteps(f, id) > 0);
        f.store.stopDispatch(f.now());
        assert.throws(() => rebind(f), /rebind_operation_in_progress|rebind_uncertain_claim/);
        held.release(); await held.done; // the old write lands now
        assert.equal(applies(f), 1);
        at(f, lease + 599); await f.observe();
        assert.equal(active(f), id);
        at(f, lease + 600); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error, active(f)], ['conflict', 'schedule_payload_inadmissible', null]);
        assert.equal(openSteps(f, id), 0);
        rebind(f);
    } finally { f.cleanup(); }
});
test('C1g S0 after an attempt ends before the fence only on a reply from another generation (rpc.sh refuses the old one)', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        await unseenApply(f, id);
        f.store.run('UPDATE operations SET request_json=? WHERE id=?', JSON.stringify({person: 'pilot', action: 'schedule_update', windows: [], precondition: null}), id);
        f.advance(5); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error, active(f)], ['unknown', 'schedule_payload_inadmissible', id]);
        f.router.transform = o => ({...o, generation: 'f'.repeat(64)});
        f.advance(5); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error, active(f)], ['conflict', 'schedule_payload_inadmissible', null]);
        assert.equal(openSteps(f, id), 0);
    } finally { f.cleanup(); }
});
test('C2 a reverted operation_rpc row with a surviving apply step never allows a second claim', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]), held = heldApply(f, id);
        revertRpcClaim(f, id);
        f.store.stopDispatch(f.now()); // the restart fence: it sees no attempt on operation_rpc, so the edit stays pending
        assert.equal(op(f, id).state, 'pending');
        const plan = f.worker.prepare('apply', id);
        await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /operation_dispatch_not_eligible/);
        assert.equal(applies(f), 1);
        held.release(); await held.done;
    } finally { f.cleanup(); }
});
test('C3 automatic polling reads our exact receipt when only the apply step records the claim', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response');
        await apply(f, id); f.router.afterApplyFailure = null; // landed, reply lost
        revertRpcClaim(f, id);
        routerChange(f, p => ({schedules: p.schedules.filter(s => s.person !== 'pilot')})); // our receipt is now historical
        f.advance(5);
        f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
        const automatic = new AutomaticDispatch(f.worker);
        await automatic.tick();
        assert.ok(f.router.calls.some(c => c.kind === 'receipt' && c.operationId === id));
        assert.deepEqual([op(f, id).state, op(f, id).error, active(f)], ['conflict', 'router_receipt_historical', null]);
        assert.equal(applies(f), 1);
    } finally { f.cleanup(); }
});
test('C4 automatic polling never attempts a second apply when only the apply step records the claim', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        await unseenApply(f, id);
        f.advance(20);
        f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
        const automatic = new AutomaticDispatch(f.worker);
        // The rows revert between the cycle's read and its apply check (the read leaves the edit unknown and the observation fresh).
        const original = f.worker.executeAutomatic.bind(f.worker);
        f.worker.executeAutomatic = async (kind, owner, operationId) => { await original(kind, owner, operationId); if (kind !== 'apply') revertRpcClaim(f, id); };
        await automatic.tick();
        assert.equal(f.store.integrationState().observation_error, null);
        assert.equal(applies(f), 1);
        assert.equal(active(f), id);
    } finally { f.cleanup(); }
});
test('C5 repeat admission runs before the claim transaction reads the envelope: a lost or malformed rpc row there fails the edit', async () => {
    for (const [name, corrupt] of Object.entries(corruptRpc)) {
        const f = world(true);
        try {
            await f.observe();
            const id = editId(f, [night]), plan = f.worker.prepare('apply', id);
            beforeClaim(f, () => corrupt(f, id));
            await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /schedule_payload_inadmissible/, name);
            assert.deepEqual([op(f, id).state, op(f, id).error, active(f)], ['failed', 'schedule_payload_inadmissible', null], name);
            assert.equal(applies(f), 0); assert.equal(openSteps(f, id), 0);
        } finally { f.cleanup(); }
    }
});
test('C6 a read that detects a late schedule apply resolves its step and keeps the error, so a later clean read leaves rebind possible', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        f.router.failure = new RouterTransportError('test_not_delivered', 'not_delivered');
        await apply(f, id); f.router.failure = null;
        assert.deepEqual([op(f, id).state, active(f)], ['failed', null]);
        await f.router.invoke(f.router.invocation('apply', f.policy.envelope(id))); // the write lands late after all
        f.advance(5); await f.observe();
        assert.equal(f.store.integrationState().observation_error, 'router_late_schedule_apply');
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM dispatch_steps WHERE kind<>'apply' AND state<>'resolved'")!.n, 0);
        routerChange(f, p => ({schedules: p.schedules.filter(s => s.person !== 'pilot')}));
        f.advance(5); await f.observe();
        assert.equal(f.store.integrationState().observation_error, null);
        rebind(f);
    } finally { f.cleanup(); }
});
test('C7 an S0-settled edit with a missing or malformed rpc row stays readable after a rebind to flag off', async () => {
    for (const [name, corrupt] of Object.entries(corruptRpc)) {
        const f = world(true);
        try {
            await f.observe();
            const id = editId(f, [night]);
            corrupt(f, id);
            f.advance(5); await f.observe();
            assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'schedule_payload_inadmissible'], name);
            f.store.stopDispatch(f.now());
            const next = {...f.config, manifestDigest: 'e'.repeat(64), schedules: {editable: false}};
            rebindIntegration(f.store, next, f.config.manifestDigest, next.manifestDigest, f.now());
            const store = new IntegrationStore(next);
            try {
                const policy = new IntegrationPolicy(store, f.now);
                assert.equal(policy.operation(actor, id).state, 'failed', name);
                assert.equal(policy.people(actor).people.length > 0, true, name);
            } finally { store.close(); }
        } finally { f.cleanup(); }
    }
});
