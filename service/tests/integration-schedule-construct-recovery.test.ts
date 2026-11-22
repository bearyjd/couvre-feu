import test from 'node:test';
import assert from 'node:assert/strict';
import { RouterTransportError } from '../src/router-transport.ts';
import { policyDigest, scopeDigest } from '../../shared/src/router-rpc.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { actor, observation } from './fixtures/integration.ts';
import { PILOT_MAC, active, applies, apply, applyLease, at, committed, edit, editId, night, op, openSteps, rebind, receipt, study, world } from './fixtures/schedule-settle.ts';
import type { World } from './fixtures/schedule-settle.ts';

// Roadmap item 2, S2a (schedules.editable, off; unverified on this router): recovery when a read fails, a claim record is lost, the TTL
// passes during an outage or between admission and claim, a reply names another generation or reuses our id, and the scope audit.

async function unseenApply(f: World, id: string): Promise<void> {
    f.router.failure = new RouterTransportError('invalid_router_response');
    await apply(f, id); f.router.failure = null;
}
async function failedObserve(f: World): Promise<void> {
    f.router.failure = new RouterTransportError('invalid_router_response');
    await f.observe(); f.router.failure = null;
}
/** Runs `hook` on the first router.invocation() call after this point: inside run(), after the pre-claim admission, before the claim. */
function beforeClaim(f: World, hook: () => void): void {
    const original = f.router.invocation.bind(f.router);
    let calls = 0;
    f.router.invocation = (...args: Parameters<typeof original>) => { if (++calls === 1) hook(); return original(...args); };
}
/** The router now holds another request under our id (rpc.sh keeps one receipt per id), current, on a moved base. */
function foreignRequestUnderOurId(f: World, id: string): void {
    const base = f.router.policy, next = normalizePolicy({...base, revision: base.revision + 1, pauses: [{person: 'pilot', until: 0}]});
    f.router.policy = next;
    f.router.receipts.set(id, {operationId: id, requestDigest: 'f'.repeat(64), baseRevision: base.revision, baseDigest: policyDigest(base),
        acceptedRevision: next.revision, acceptedDigest: policyDigest(next), outcome: 'accepted', current: true});
}

test('R1 a failed read resolves its own step and keeps the observation error, so a later confirmation leaves rebind possible', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response');
        await apply(f, id); f.router.afterApplyFailure = null;
        f.advance(5); await failedObserve(f);
        assert.equal(f.store.integrationState().observation_error, 'invalid_router_response');
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM dispatch_steps WHERE kind<>'apply' AND state<>'resolved'")!.n, 0);
        f.advance(5); await receipt(f, id);
        assert.deepEqual([op(f, id).state, op(f, id).error], ['confirmed', null]);
        rebind(f);
    } finally { f.cleanup(); }
});
test('R2 a lost operation_rpc row after the claim still counts as an attempt (conflict, not a pre-dispatch failure), on observe and on prepare', async () => {
    for (const path of ['observe', 'prepare'] as const) {
        const f = world(true);
        try {
            await f.observe();
            const id = editId(f, [night]);
            await unseenApply(f, id);
            f.store.run('DELETE FROM operation_rpc WHERE operation_id=?', id);
            f.advance(5);
            if (path === 'observe') await f.observe();
            else assert.throws(() => f.worker.prepare('apply', id), /schedule_payload_inadmissible/);
            assert.deepEqual([op(f, id).state, op(f, id).error], ['conflict', 'schedule_payload_inadmissible'], path);
            assert.equal(active(f), null);
        } finally { f.cleanup(); }
    }
});
test('R3 a lost apply step after the claim keeps the fence: the claim\'s own lease on operation_rpc ends the edit after 600 s', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        await unseenApply(f, id);
        const lease = applyLease(f, id);
        f.store.run("DELETE FROM dispatch_steps WHERE operation_id=? AND kind='apply'", id);
        at(f, lease + 599); await f.observe();
        assert.equal(op(f, id).state, 'unknown');
        at(f, lease + 600); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'router_apply_unobserved_after_fence']);
        assert.equal(active(f), null);
    } finally { f.cleanup(); }
});
test('R4 S6 during an outage: a failed read past the TTL ends a never-dispatched edit', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]), created = op(f, id).created_at;
        at(f, created + 119); await failedObserve(f);
        assert.equal(active(f), id);
        at(f, created + 120); await failedObserve(f);
        assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'schedule_not_dispatched']);
        assert.equal(active(f), null); assert.equal(applies(f), 0);
    } finally { f.cleanup(); }
});
test('R5 S6 before the claim: an edit past the TTL is refused on a still-fresh observation, at prepare and inside the claim', async () => {
    for (const where of ['prepare', 'claim'] as const) {
        const f = world(true);
        try {
            await f.observe();
            const id = editId(f, [night]), created = op(f, id).created_at;
            at(f, created + 100); await f.observe();
            if (where === 'prepare') {
                at(f, created + 121);
                assert.throws(() => f.worker.prepare('apply', id), /schedule_not_dispatched/);
            } else {
                const plan = f.worker.prepare('apply', id);
                beforeClaim(f, () => at(f, created + 121));
                await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /schedule_not_dispatched/);
            }
            assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'schedule_not_dispatched'], where);
            assert.equal(active(f), null); assert.equal(applies(f), 0);
        } finally { f.cleanup(); }
    }
});
test('R6 admission inside the claim: a request rewritten after the pre-claim check is refused and the refusal is committed', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]), plan = f.worker.prepare('apply', id);
        beforeClaim(f, () => {
            const request = JSON.parse(op(f, id).request_json) as {windows: unknown[]};
            f.store.run('UPDATE operations SET request_json=? WHERE id=?', JSON.stringify({...request, windows: [{person: 'pilot', ...study}]}), id);
        });
        await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /schedule_payload_inadmissible/);
        assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'schedule_payload_inadmissible']);
        assert.equal(active(f), null); assert.equal(applies(f), 0); assert.equal(openSteps(f, id), 0);
    } finally { f.cleanup(); }
});
test('R7 a DTO never derives health from an envelope naming another operation', async () => {
    const f = world(true);
    try {
        await f.observe();
        const earlier = f.pause(0).result.operation.id;
        await apply(f, earlier);
        assert.equal(f.policy.operation(actor, earlier).currentHealthy, true);
        const id = edit(f, [night]).result.operation.id;
        f.store.run('UPDATE operation_rpc SET envelope_json=(SELECT envelope_json FROM operation_rpc WHERE operation_id=?) WHERE operation_id=?', earlier, id);
        assert.equal(f.policy.operation(actor, id).currentHealthy, false);
    } finally { f.cleanup(); }
});
test('R8 a reply from a new generation that omits an old floor address ends the edit as a generation conflict', async () => {
    const f = world(true);
    try {
        const extra = '02:10:20:30:43:01', floor = [PILOT_MAC, extra].sort();
        f.config.routerScope = floor;
        f.router.transform = o => ({...o, scope: floor, scopeSha: scopeDigest(floor)});
        await f.observe();
        const id = editId(f, [night]);
        f.router.transform = o => {
            const fresh = observation(f.config, normalizePolicy({version: 1, revision: 0, people: [{id: 'pilot', macs: [PILOT_MAC]}], pauses: [], schedules: []}), o.routerTime);
            return {...fresh, generation: 'f'.repeat(64), scope: [PILOT_MAC], scopeSha: scopeDigest([PILOT_MAC])};
        };
        f.advance(5); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error], ['conflict', 'router_generation_changed_before_dispatch']);
        assert.equal(active(f), null);
        rebind(f);
    } finally { f.cleanup(); }
});
test('R9 a lookup returning a current receipt for our id with another request digest is an operation-id conflict', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        await unseenApply(f, id);
        foreignRequestUnderOurId(f, id);
        f.advance(5); await receipt(f, id);
        assert.deepEqual([op(f, id).state, op(f, id).error], ['conflict', 'router_operation_id_conflict']);
        assert.equal(active(f), null); assert.deepEqual(committed(f), []);
        rebind(f);
    } finally { f.cleanup(); }
});
test('R10 S7a holds only while the router\'s current policy is our envelope\'s: a foreign request under our id falls through to S7', async () => {
    const f = world(true);
    try {
        await f.observe();
        const earlier = f.pause(0).result.operation.id;
        await apply(f, earlier);
        f.advance(5); await f.observe();
        const id = editId(f, [night]);
        await unseenApply(f, id);
        foreignRequestUnderOurId(f, id);
        f.advance(5); await receipt(f, earlier);
        assert.deepEqual([op(f, id).state, op(f, id).error], ['conflict', 'router_base_changed_after_dispatch']);
        assert.equal(active(f), null); assert.deepEqual(committed(f), []);
    } finally { f.cleanup(); }
});
test('R11 flag on: the scope-change audit holds counts and request ids, never addresses (the scope tables keep them)', async () => {
    const f = world(true);
    try {
        const grown = [PILOT_MAC, '02:10:20:30:43:02'].sort();
        f.router.transform = o => ({...o, scope: grown, scopeSha: scopeDigest(grown)});
        await f.observe();
        const rows = f.store.all<{outcome: string}>("SELECT outcome FROM audit WHERE action='router_scope_change'");
        assert.equal(rows.length, 1);
        assert.doesNotMatch(rows[0].outcome, /([0-9a-f]{2}:){5}[0-9a-f]{2}/);
        assert.deepEqual([JSON.parse(rows[0].outcome).added, JSON.parse(rows[0].outcome).removed], [1, 0]);
        assert.match(f.store.get<{added_json: string}>('SELECT added_json FROM scope_changes')!.added_json, /02:10:20:30:43:02/);
    } finally { f.cleanup(); }
});
