import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { RouterTransportError } from '../src/router-transport.ts';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { requestDigest } from '../../shared/src/router-rpc.ts';
import { normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import { actor } from './fixtures/integration.ts';
import { active, applies, apply, applyLease, at, committed, editId, night, op, openSteps, rebind, receipt, routerChange, rpcPhase, world } from './fixtures/schedule-settle.ts';
import type { World } from './fixtures/schedule-settle.ts';

// Roadmap item 2, S2a (schedules.editable, off; unverified on this router): settlement S0, S1, S1g, S2 (historical), S6, S7 and the fixed codes.

/** An apply whose reply is lost before the router saw it (possible delivery, nothing written). */
async function unseenApply(f: World, id: string): Promise<void> {
    f.router.failure = new RouterTransportError('invalid_router_response');
    await apply(f, id); f.router.failure = null;
}
test('T10 S7: a crash after the claim and before the spawn resolves only after the fence, measured from the apply step lease', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]), plan = f.worker.prepare('apply', id);
        f.router.defer = new Promise<void>(() => {});
        void f.worker.execute(plan, plan.scriptSha256); // the process "dies" here: the claim committed, the invocation never returns
        f.router.defer = null;
        const lease = applyLease(f, id);
        at(f, lease + 1); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error], ['unknown', 'receipt_missing_remote_outcome_unknown']);
        at(f, lease + 599); await f.observe();
        assert.equal(op(f, id).state, 'unknown');
        at(f, lease + 600); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'router_apply_unobserved_after_fence']);
        assert.equal(active(f), null); assert.equal(openSteps(f, id), 0); assert.equal(applies(f), 1);
    } finally { f.cleanup(); }
});
test('T11 S7: a base that moved after our dispatch ends the operation as a conflict at once (the revision only rises)', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        await unseenApply(f, id);
        routerChange(f, () => ({pauses: [{person: 'pilot', until: 0}]}));
        f.advance(5); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error], ['conflict', 'router_base_changed_after_dispatch']);
        assert.equal(active(f), null); assert.deepEqual(committed(f), []); assert.equal(rpcPhase(f, id), 'resolved');
    } finally { f.cleanup(); }
});
test('T12 S2: a historical exact receipt is a conflict and promotes nothing', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response');
        await apply(f, id); f.router.afterApplyFailure = null;
        routerChange(f, () => ({pauses: [{person: 'pilot', until: 0}]}));
        f.advance(5); await receipt(f, id);
        assert.deepEqual([op(f, id).state, op(f, id).error], ['conflict', 'router_receipt_historical']);
        assert.deepEqual(committed(f), []); assert.equal(active(f), null);
    } finally { f.cleanup(); }
});
test('T13 S6: a queued edit that was never dispatched fails after the dispatch TTL, not before', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]), created = op(f, id).created_at;
        at(f, created + 119); await f.observe();
        assert.equal(op(f, id).state, 'pending'); assert.equal(active(f), id);
        at(f, created + 120); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'schedule_not_dispatched']);
        assert.equal(active(f), null); assert.equal(applies(f), 0);
    } finally { f.cleanup(); }
});
const corruptions: Record<string, (f: World, id: string) => void> = {
    'malformed envelope': (f, id) => f.store.run(`UPDATE operation_rpc SET envelope_json='{"rpc_version":1}' WHERE operation_id=?`, id),
    'missing rpc row': (f, id) => f.store.run('DELETE FROM operation_rpc WHERE operation_id=?', id),
    'tampered base_json': (f, id) => f.store.run('UPDATE operations SET base_json=? WHERE id=?', policyJSON(normalizePolicy({version: 1, revision: 5, people: [], pauses: [], schedules: []})), id),
};
test('T14 admission before validate(plan): corrupt rows fail the operation before any dispatch, via execute and automatic; reads stay total', async () => {
    for (const [name, corrupt] of Object.entries(corruptions)) for (const path of ['execute', 'automatic'] as const) {
        const f = world(true);
        try {
            await f.observe();
            const id = editId(f, [night]), plan = f.worker.prepare('apply', id);
            corrupt(f, id);
            if (path === 'execute') await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /schedule_payload_inadmissible/, name);
            else {
                f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
                const automatic = new AutomaticDispatch(f.worker);
                await assert.rejects(f.worker.executeAutomatic('apply', automatic.owner, id), /schedule_payload_inadmissible/, name);
            }
            assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'schedule_payload_inadmissible'], `${name} ${path}`);
            assert.equal(active(f), null); assert.equal(applies(f), 0);
            assert.equal(f.policy.operation(actor, id).state, 'failed');
            assert.ok(Array.isArray(f.policy.people(actor).people));
        } finally { f.cleanup(); }
    }
});
const rebinding: Record<string, (e: Record<string, unknown>) => Record<string, unknown>> = {
    'other operation id': e => ({...e, operation_id: randomUUID()}),
    'other base digest': e => ({...e, expected_digest: 'f'.repeat(64)}),
    'other generation': e => ({...e, generation: 'f'.repeat(64)}),
};
test('T15 binding: an envelope for another id, base digest or generation is refused even with a recomputed valid request digest', async () => {
    for (const [name, change] of Object.entries(rebinding)) {
        const f = world(true);
        try {
            await f.observe();
            const id = editId(f, [night]), row = f.store.get<{envelope_json: string}>('SELECT envelope_json FROM operation_rpc WHERE operation_id=?', id)!;
            const e = change(JSON.parse(row.envelope_json));
            f.store.run('UPDATE operation_rpc SET envelope_json=?,request_digest=?,generation=? WHERE operation_id=?', JSON.stringify(e), requestDigest(e as never), String(e.generation), id);
            assert.throws(() => f.worker.prepare('apply', id), /schedule_payload_inadmissible/, name);
            assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'schedule_payload_inadmissible'], name);
            assert.equal(applies(f), 0);
        } finally { f.cleanup(); }
    }
});
test('T16 fixed codes: router text cached before the flag flip is never served, and is never stored once the flag is on', async () => {
    const f = world(false);
    try {
        f.router.transform = o => ({...o, errors: ['router said 192.0.2.7 kid-phone'], status: {...o.status, errors: ['free text here', 'incomplete_address_coverage']}});
        await f.observe();
        assert.match(f.store.get<{observation_json: string}>('SELECT observation_json FROM service_state')!.observation_json, /kid-phone/);
        f.config.schedules = {editable: true};
        const served = f.store.observation().value!;
        assert.deepEqual(served.errors, ['router_error_unrecognized']);
        assert.deepEqual(served.status.errors, ['router_error_unrecognized', 'incomplete_address_coverage']);
        assert.doesNotMatch(JSON.stringify(f.policy.people(actor)), /kid-phone|free text|192\.0\.2\.7/);
        f.advance(5); await f.observe();
        assert.doesNotMatch(f.store.get<{observation_json: string}>('SELECT observation_json FROM service_state')!.observation_json, /kid-phone|free text/);
    } finally { f.cleanup(); }
});
test('T17 terminal-write rule: a not_delivered apply fails, resolves its step and rpc row, and rebind passes', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        f.router.failure = new RouterTransportError('private_transport_configuration_unavailable', 'not_delivered');
        await apply(f, id); f.router.failure = null;
        assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'router_apply_not_delivered']);
        assert.equal(openSteps(f, id), 0); assert.equal(rpcPhase(f, id), 'resolved'); assert.equal(active(f), null);
        rebind(f);
    } finally { f.cleanup(); }
});
test('T18 S1g: a changed router generation ends the operation, before and after dispatch', async () => {
    for (const dispatched of [false, true]) {
        const f = world(true);
        try {
            await f.observe();
            const id = editId(f, [night]);
            if (dispatched) await unseenApply(f, id);
            f.router.transform = o => ({...o, generation: 'f'.repeat(64)});
            f.advance(5); await f.observe();
            assert.deepEqual([op(f, id).state, op(f, id).error], ['conflict', dispatched ? 'router_generation_changed_after_dispatch' : 'router_generation_changed_before_dispatch']);
            assert.equal(active(f), null); assert.equal(openSteps(f, id), 0);
            rebind(f);
        } finally { f.cleanup(); }
    }
});
test('T19 closed codes: main\'s claim scope refusal and stopDispatch write members of SCHEDULE_CODES on a schedule operation', async () => {
    const scope = world(true), stopped = world(true);
    try {
        await scope.observe();
        const id = editId(scope, [night]);
        scope.store.run("UPDATE accounts SET person_ids='[]' WHERE id='operator'");
        await apply(scope, id);
        assert.deepEqual([op(scope, id).state, op(scope, id).error], ['failed', 'actor_permission_changed_before_dispatch']);
        assert.equal(active(scope), null); assert.equal(applies(scope), 0);
        await stopped.observe();
        const other = editId(stopped, [night]);
        await unseenApply(stopped, other);
        stopped.store.stopDispatch(stopped.now());
        assert.deepEqual([op(stopped, other).state, op(stopped, other).error], ['unknown', 'dispatch_stopped_remote_outcome_unknown']);
    } finally { scope.cleanup(); stopped.cleanup(); }
});
