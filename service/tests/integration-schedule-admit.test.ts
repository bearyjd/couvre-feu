import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { RouterTransportError } from '../src/router-transport.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { applyOp, receiptOp } from './fixtures/schedule-parity-script.ts';
import { active, applies, committed, cross, insertRaw, night, op, other, plain, queue, sequence, world } from './fixtures/schedule-settle.ts';

// Schedule settlement core: admission and the remaining evidence rules (roadmap item 2, S2a; schedules.editable, off; unverified on this router). T7-T11.

test('T7 nine windows for the child: the claim refuses, the router is never called, the operation fails and is not active', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, plain(9));
        await applyOp(f, id);
        assert.equal(applies(f), 0); assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'schedule_payload_inadmissible');
        assert.equal(active(f), null); assert.deepEqual(committed(f), []);
    } finally { f.cleanup(); }
});
test('T7 an expansion of 288 (32 devices, 4 cross-midnight + 1 plain) cannot be dispatched and fails on the next observation', async () => {
    const f = world(true, 32);
    try {
        await f.observe();
        const o = f.store.observation().value!, id = randomUUID();
        const raw = {rpc_version: 1, generation: o.generation, operation_id: id, expected_revision: o.acceptedPolicy.revision, expected_digest: o.policyDigest,
            policy: {...o.acceptedPolicy, revision: o.acceptedPolicy.revision + 1, schedules: [...cross(4), ...plain(1)].map(w => ({person: 'pilot', ...w}))}};
        insertRaw(f, id, JSON.stringify(raw), 'a'.repeat(64));
        await assert.rejects(applyOp(f, id));
        assert.equal(applies(f), 0);
        f.advance(1); await f.observe();
        assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'schedule_payload_inadmissible'); assert.equal(active(f), null);
        assert.deepEqual(committed(f), []); assert.equal(applies(f), 0);
    } finally { f.cleanup(); }
});
test('T8 a malformed envelope_json plus a changed base: the operation fails and the observation is still stored', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]), before = sequence(f);
        f.store.transaction(() => f.store.run("UPDATE operation_rpc SET envelope_json='{\"broken\":' WHERE operation_id=?", id));
        f.router.policy = normalizePolicy({...f.router.policy, revision: 1, pauses: [{person: 'pilot', until: f.now() + 600}]});
        f.advance(1); await f.observe();
        assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'schedule_payload_inadmissible'); assert.equal(active(f), null);
        assert.equal(sequence(f), before + 1); assert.equal(f.store.integrationState().observation_error, null);
        assert.equal(f.store.observation().value!.acceptedPolicy.revision, 1);
    } finally { f.cleanup(); }
});
test('T9 a child with windows and no routed devices keeps its rows while another child\'s operation confirms', async () => {
    const f = world(true);
    try {
        f.store.transaction(() => {
            f.store.run("INSERT INTO people(id,name,active,created_at) VALUES('second','Second child',1,2)");
            f.store.run("INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES('second',?,?,?,?)", other.id, other.weekdays.join(','), other.start, other.stop);
        });
        await f.observe(); const id = queue(f, [night]);
        await applyOp(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.deepEqual(committed(f), [night]); assert.deepEqual(committed(f, 'second'), [other]);
        assert.equal(f.store.integrationState().observation_error, null);
    } finally { f.cleanup(); }
});
test('T10 a historical receipt: conflict, nothing promoted (E4)', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response'); await applyOp(f, id); f.router.afterApplyFailure = null;
        f.advance(70);
        f.router.policy = normalizePolicy({...f.router.policy, revision: f.router.policy.revision + 1, pauses: [{person: 'pilot', until: f.now() + 600}]});
        await receiptOp(f, id);
        assert.equal(op(f, id).state, 'conflict'); assert.equal(op(f, id).error, 'router_receipt_historical');
        assert.deepEqual(committed(f), []); assert.equal(active(f), null); assert.notEqual(f.store.integrationState().observation_error, null);
    } finally { f.cleanup(); }
});
test('T11 not delivered: failed with a fixed code, nothing promoted, not active', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.failure = new RouterTransportError('test_spawn_failed', 'not_delivered'); await applyOp(f, id);
        assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'router_apply_not_delivered');
        assert.deepEqual(committed(f), []); assert.equal(active(f), null);
    } finally { f.cleanup(); }
});
test('T11 possibly delivered: unknown, nothing promoted, still active; another read kind failing changes nothing', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.failure = new RouterTransportError('test_timeout'); await applyOp(f, id);
        assert.equal(op(f, id).state, 'unknown'); assert.equal(op(f, id).error, 'router_outcome_unknown');
        assert.deepEqual(committed(f), []); assert.equal(active(f), id);
        const row = JSON.stringify(op(f, id));
        f.advance(1); f.router.failure = new RouterTransportError('test_read_failed'); await f.observe();
        assert.equal(JSON.stringify(op(f, id)), row); assert.equal(active(f), id);
    } finally { f.cleanup(); }
});
test('T11 an inactive child promotes normally; a later delete promotes the empty set (I3)', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.router.afterApply = () => f.store.transaction(() => f.store.run("UPDATE people SET active=0 WHERE id='pilot'"));
        await applyOp(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.deepEqual(committed(f), [night]); assert.equal(active(f), null);
        f.router.afterApply = null; f.store.transaction(() => f.store.run("UPDATE people SET active=1 WHERE id='pilot'"));
        f.advance(1); await f.observe(); const gone = queue(f, [], {action: 'schedule_delete'}); await applyOp(f, gone);
        assert.equal(op(f, gone).state, 'confirmed'); assert.deepEqual(committed(f), []);
    } finally { f.cleanup(); }
});
