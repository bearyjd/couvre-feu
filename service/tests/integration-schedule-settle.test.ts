import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { actor } from './fixtures/integration.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { policyDigest, requestDigest } from '../../shared/src/router-rpc.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { applyOp, receiptOp } from './fixtures/schedule-parity-script.ts';
import { active, applies, audits, committed, night, op, queue, sequence, withWindows, world } from './fixtures/schedule-settle.ts';
// Schedule settlement core, worker level (roadmap item 2, S2a; schedules.editable, off; unverified on this router). T1-T6 of the S2a design.
const lost = () => new RouterTransportError('test_lost_response');

test('T1 lost reply, then a receipt read with the router at the payload: confirmed and promoted (deferred ownership)', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApplyFailure = lost(); await applyOp(f, id);
        assert.equal(op(f, id).state, 'unknown'); assert.equal(op(f, id).error, 'router_outcome_unknown'); assert.deepEqual(committed(f), []); assert.equal(active(f), id);
        f.router.afterApplyFailure = null; f.advance(5); await receiptOp(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.equal(op(f, id).error, null); assert.equal(op(f, id).confirmed_at, f.now());
        assert.deepEqual(committed(f), [night]); assert.equal(active(f), null);
        assert.equal(f.store.integrationState().observation_error, null);
        assert.deepEqual(f.store.observation().value!.acceptedPolicy.schedules.map(s => s.id), ['night']);
        assert.notEqual(f.policy.people(actor).revisionToken, null);
    } finally { f.cleanup(); }
});
test('T2 router at the payload before dispatch: conflict, nothing promoted, not published; with the base unchanged (E7) still not published', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]), before = sequence(f);
        f.router.policy = withWindows(f.router.policy, [night]);
        f.advance(1); await f.observe();
        assert.equal(op(f, id).state, 'conflict'); assert.equal(op(f, id).error, 'router_base_changed_before_dispatch');
        assert.deepEqual(committed(f), []); assert.equal(active(f), null);
        assert.equal(sequence(f), before); assert.notEqual(f.store.integrationState().observation_error, null);
    } finally { f.cleanup(); }
    const g = world(true);
    try {
        await g.observe();
        // A foreign writer put the windows on the router; our queued operation's base IS that router state (E7: no receipt, no attempt, base unchanged).
        const foreign = normalizePolicy({...g.router.policy, revision: 1, schedules: [{person: 'pilot', ...night}]});
        g.router.policy = foreign;
        const id = queue(g, [night], {base: foreign}), before = sequence(g);
        g.advance(1); await g.observe();
        assert.equal(op(g, id).state, 'pending'); assert.equal(active(g), id); assert.deepEqual(committed(g), []);
        assert.equal(sequence(g), before); assert.notEqual(g.store.integrationState().observation_error, null);
        assert.equal(g.policy.people(actor).revisionToken, null);
    } finally { g.cleanup(); }
});
test('I5 an observation checked with ownership deferred is not published when the schedule operation is no longer active at finish', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]), before = sequence(f);
        // The worker's first clock read after the reply is the staleness check, which follows the transport ownership check:
        // the operation stops being active exactly between that check and finish.
        let armed = false;
        const clock = f.worker.now;
        Object.defineProperty(f.worker, 'now', {value: () => {
            if (armed) { armed = false; f.store.run('UPDATE integration_state SET active_operation_id=NULL WHERE singleton=1'); }
            return clock();
        }});
        f.router.afterApply = () => { armed = true; };
        await applyOp(f, id);
        assert.equal(armed, false);
        assert.equal(sequence(f), before); assert.equal(f.store.integrationState().observation_error, 'owner_schedule_configuration_changed');
        assert.deepEqual(committed(f), []); assert.equal(f.policy.people(actor).revisionToken, null);
    } finally { f.cleanup(); }
});
test('T3 a receipt for another operation, request digest or policy never promotes', async () => {
    for (const tamper of [{operationId: randomUUID()}, {requestDigest: 'f'.repeat(64)}, {acceptedDigest: 'e'.repeat(64)}]) {
        const f = world(true);
        try {
            await f.observe(); const id = queue(f, [night]);
            f.router.transform = o => o.receipt ? {...o, receipt: {...o.receipt, ...tamper}} : o;
            await applyOp(f, id);
            assert.equal(op(f, id).state, 'unknown', JSON.stringify(tamper));
            assert.match(op(f, id).error!, /^(receipt_missing_remote_outcome_unknown|router_outcome_unknown)$/, JSON.stringify(tamper));
            assert.deepEqual(committed(f), []); assert.equal(op(f, id).confirmed_at, null); assert.equal(active(f), id);
        } finally { f.cleanup(); }
    }
});
test('T3 an operation_rpc row whose request digest or generation does not match its envelope is refused when preparing, and again at the claim', async () => {
    for (const late of [false, true]) {
        for (const column of ['request_digest', 'generation']) {
            const f = world(true), label = `${column} late=${late}`;
            try {
                await f.observe(); const id = queue(f, [night]);
                const tamper = () => f.store.transaction(() => f.store.run(`UPDATE operation_rpc SET ${column}=? WHERE operation_id=?`, 'f'.repeat(64), id));
                if (late) {
                    // Admitted when the plan was prepared, changed before the claim: the claim's own admission refuses (E0 at claim).
                    const plan = f.worker.prepare('apply', id); tamper(); await f.worker.execute(plan, plan.scriptSha256);
                } else {
                    tamper(); await assert.rejects(applyOp(f, id), /schedule_payload_inadmissible/, label);
                }
                assert.equal(applies(f), 0, label); assert.equal(op(f, id).state, 'failed', label); assert.equal(op(f, id).error, 'schedule_payload_inadmissible', label);
                assert.deepEqual(committed(f), []); assert.equal(active(f), null, label);
            } finally { f.cleanup(); }
        }
    }
});
test('T4 a forged stored receipt_json plus an observation without a receipt: unknown (E8), nothing promoted', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApplyFailure = lost(); await applyOp(f, id); f.router.afterApplyFailure = null;
        const e = f.policy.envelope(id);
        const forged = {operationId: id, requestDigest: requestDigest(e), baseRevision: e.expected_revision, baseDigest: e.expected_digest, acceptedRevision: e.policy.revision, acceptedDigest: policyDigest(e.policy), outcome: 'accepted', current: true};
        f.store.transaction(() => f.store.run("UPDATE operation_rpc SET receipt_json=?,delivery='accepted' WHERE operation_id=?", JSON.stringify(forged), id));
        f.router.transform = o => ({...o, receipt: null, currentOperationId: null});
        f.advance(5); await f.observe();
        assert.equal(op(f, id).state, 'unknown'); assert.equal(op(f, id).error, 'receipt_missing_remote_outcome_unknown');
        assert.deepEqual(committed(f), []); assert.equal(active(f), id); assert.equal(op(f, id).confirmed_at, null);
    } finally { f.cleanup(); }
});
test('T5 the same exact, current, unhealthy observation twice writes one audit row and leaves rows unchanged', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApply = () => { f.router.runtimeError = 'test_runtime'; };
        await applyOp(f, id);
        assert.equal(op(f, id).state, 'unknown'); assert.equal(op(f, id).error, 'accepted_router_runtime_unconfirmed');
        assert.deepEqual(committed(f), [night]); assert.equal(active(f), id); assert.equal(audits(f, id), 1);
        const row = JSON.stringify(op(f, id));
        f.advance(5); await receiptOp(f, id);
        assert.equal(audits(f, id), 1); assert.equal(JSON.stringify(op(f, id)), row); assert.deepEqual(committed(f), [night]); assert.equal(active(f), id);
    } finally { f.cleanup(); }
});
test('T6 a refusal before write stores a fixed code; neither the operation DTO nor /people\'s operation entries carry the router text', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.reject = 'incomplete_address_coverage';
        f.router.transform = o => ({...o, status: {...o.status, errors: [...o.status.errors, 'private.example']}});
        await applyOp(f, id);
        assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'router_refused_before_write');
        assert.deepEqual(committed(f), []); assert.equal(active(f), null);
        // The operation (its DTO and /people's latestOperation) carries only the fixed code. /people's top-level `errors` repeats the
        // published observation's router codes, but an observation published while a schedule operation settles keeps only codes this
        // service knows: any other router text becomes one fixed code before it is stored (I6).
        const dto = JSON.stringify(f.policy.result(op(f, id), actor)), people = f.policy.people(actor);
        assert.doesNotMatch(dto, /incomplete_address_coverage|private\.example/);
        assert.equal(people.people[0]!.latestOperation?.error, 'router_refused_before_write');
        assert.doesNotMatch(JSON.stringify(people.people), /incomplete_address_coverage/);
        assert.doesNotMatch(JSON.stringify(people), /private\.example/);
        assert.doesNotMatch(JSON.stringify(f.store.observation().value), /private\.example/);
        assert.ok(people.errors.includes('router_error_unrecognized'));
    } finally { f.cleanup(); }
});
test('T6 an exact, current, unhealthy receipt (E3) carrying router text: neither the stored observation nor /people repeat it', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.transform = o => o.receipt ? {...o, status: {...o.status, ok: false, errors: ['private.example']}} : o;
        await applyOp(f, id);
        assert.equal(op(f, id).state, 'unknown'); assert.equal(op(f, id).error, 'accepted_router_runtime_unconfirmed');
        assert.deepEqual(committed(f), [night]); assert.equal(active(f), id);
        const people = f.policy.people(actor);
        assert.doesNotMatch(JSON.stringify(people), /private\.example/);
        assert.doesNotMatch(JSON.stringify(f.store.observation().value), /private\.example/);
        // Mapped, never dropped: the observation stays unhealthy.
        assert.ok(people.errors.includes('router_error_unrecognized')); assert.equal(people.revisionToken, null);
        assert.equal(f.store.observation().value!.status.errors.length, 1);
    } finally { f.cleanup(); }
});
test('E5 a policy_conflict reply to our own apply (base moved under the router lock, nothing written): failed with the fixed code, not active', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        // A foreign change lands after the stored observation: the claim still passes, the router refuses before any write.
        f.router.policy = normalizePolicy({...f.router.policy, revision: 1, pauses: [{person: 'pilot', until: f.now() + 600}]});
        f.router.reject = 'policy_conflict';
        await applyOp(f, id);
        assert.equal(applies(f), 1);
        assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'router_refused_before_write');
        assert.deepEqual(committed(f), []); assert.equal(active(f), null);
    } finally { f.cleanup(); }
});
test('E5 policy_conflict with the base unchanged, or on a read that is not our apply, is not taken as a refusal', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.reject = 'policy_conflict';
        await applyOp(f, id);
        assert.equal(op(f, id).state, 'unknown'); assert.equal(op(f, id).error, 'receipt_missing_remote_outcome_unknown'); assert.equal(active(f), id);
    } finally { f.cleanup(); }
});
