import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { RouterTransportError } from '../src/router-transport.ts';
import { normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { requestDigest } from '../../shared/src/router-rpc.ts';
import { actor } from './fixtures/integration.ts';
import { applyOp, receiptOp } from './fixtures/schedule-parity-script.ts';
import { active, applies, committed, cross, insertRaw, night, op, other, plain, queue, sequence, world } from './fixtures/schedule-settle.ts';

// Schedule settlement core: admission and the remaining evidence rules (roadmap item 2, S2a; schedules.editable, off; unverified on this router). T7-T11.

test('T7 nine windows for the child: preparing the apply refuses, the router is never called, the operation fails and is not active', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, plain(9));
        await assert.rejects(applyOp(f, id), /schedule_payload_inadmissible/);
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
        // Admission runs before prepare parses the envelope: preparing the apply already fails the operation (E0), with no dispatch.
        await assert.rejects(applyOp(f, id), /schedule_payload_inadmissible/);
        assert.equal(applies(f), 0);
        assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'schedule_payload_inadmissible'); assert.equal(active(f), null);
        assert.deepEqual(committed(f), []);
        assert.equal(f.policy.result(op(f, id), actor).result.operation.error, 'schedule_payload_inadmissible');
        assert.doesNotThrow(() => f.policy.people(actor));
    } finally { f.cleanup(); }
});
test('T7 a malformed envelope_json: preparing the apply fails the operation (E0) and frees the active slot; DTO and /people stay readable', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]);
        f.store.transaction(() => f.store.run("UPDATE operation_rpc SET envelope_json='{\"broken\":' WHERE operation_id=?", id));
        await assert.rejects(applyOp(f, id), /schedule_payload_inadmissible/);
        assert.equal(applies(f), 0); assert.equal(op(f, id).state, 'failed'); assert.equal(op(f, id).error, 'schedule_payload_inadmissible'); assert.equal(active(f), null);
        assert.equal(f.policy.result(op(f, id), actor).result.operation.state, 'failed');
        assert.equal(f.policy.people(actor).people[0]!.latestOperation?.error, 'schedule_payload_inadmissible');
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
        // The DTO and /people read the operation without reparsing a usable envelope: both stay total.
        assert.equal(f.policy.result(op(f, id), actor).result.operation.error, 'schedule_payload_inadmissible');
        assert.equal(f.policy.people(actor).people[0]!.latestOperation?.error, 'schedule_payload_inadmissible');
    } finally { f.cleanup(); }
});
const bMacs = ['02:10:20:30:42:01', '02:10:20:30:42:02'];
/** Children A (pilot) and B (second) both routed, B with two devices and one committed window, observed by the service. */
async function twoRouted(f: ReturnType<typeof world>): Promise<RouterPolicy> {
    f.store.transaction(() => {
        f.store.run("INSERT INTO people(id,name,active,created_at) VALUES('second','Second child',1,2)");
        for (const [i, mac] of bMacs.entries()) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,'second',?,'mac',?,'active',2)", `dB${i}`, `Device B${i}`, mac);
        f.store.run("INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES('second',?,?,?,?)", other.id, other.weekdays.join(','), other.start, other.stop);
    });
    f.router.policy = normalizePolicy({...f.router.policy, people: [...f.router.policy.people, {id: 'second', macs: bMacs}], schedules: [{person: 'second', ...other}]});
    await f.observe();
    assert.equal(f.store.integrationState().observation_error, null);
    return f.store.observation().value!.acceptedPolicy;
}
/** Inserts an operation for A with this exact payload and base_json (the envelope's expected base is always the real observed one). */
function queueExact(f: ReturnType<typeof world>, policy: RouterPolicy, baseJson: string): string {
    const o = f.store.observation().value!, id = randomUUID();
    const envelope = {rpc_version: 1 as const, generation: o.generation, operation_id: id, expected_revision: o.acceptedPolicy.revision, expected_digest: o.policyDigest, policy};
    insertRaw(f, id, JSON.stringify(envelope), requestDigest(envelope), {policy: policyJSON(policy), base: baseJson, revision: policy.revision});
    return id;
}
test('T9 with A and B routed, an edit for A that omits B, drops one of B\'s devices, or rides on a forged base is refused; B keeps its rows and routing', async () => {
    const cases: Record<string, (base: RouterPolicy) => {policy: RouterPolicy; baseJson: string}> = {
        'omits B': base => ({policy: normalizePolicy({...base, revision: base.revision + 1, people: base.people.filter(p => p.id !== 'second'), schedules: [{person: 'pilot', ...night}]}), baseJson: policyJSON(base)}),
        'drops a B device': base => ({policy: normalizePolicy({...base, revision: base.revision + 1, people: base.people.map(p => p.id === 'second' ? {...p, macs: [bMacs[0]!]} : p), schedules: [...base.schedules, {person: 'pilot', ...night}]}), baseJson: policyJSON(base)}),
        // The payload omits B and base_json is forged to agree with it: only the digest binding of base_json to the envelope catches it.
        'forged base': base => {
            const forged = normalizePolicy({...base, people: base.people.filter(p => p.id !== 'second'), schedules: []});
            return {policy: normalizePolicy({...forged, revision: base.revision + 1, schedules: [{person: 'pilot', ...night}]}), baseJson: policyJSON(forged)};
        },
    };
    for (const [label, build] of Object.entries(cases)) {
        const f = world(true);
        try {
            const {policy, baseJson} = build(await twoRouted(f)), id = queueExact(f, policy, baseJson);
            await assert.rejects(applyOp(f, id), /schedule_payload_inadmissible/, label);
            assert.equal(applies(f), 0, label); assert.equal(op(f, id).state, 'failed', label); assert.equal(op(f, id).error, 'schedule_payload_inadmissible', label);
            assert.equal(active(f), null, label); assert.deepEqual(committed(f), [], label); assert.deepEqual(committed(f, 'second'), [other], label);
            assert.deepEqual(f.router.policy.people.find(p => p.id === 'second')?.macs, bMacs, label);
        } finally { f.cleanup(); }
    }
});
test('T9 with A and B routed, an edit for A that keeps B exactly confirms and leaves B\'s rows untouched (positive control)', async () => {
    const f = world(true);
    try {
        await twoRouted(f); const id = queue(f, [night]);
        await applyOp(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.deepEqual(committed(f), [night]); assert.deepEqual(committed(f, 'second'), [other]);
        assert.equal(f.store.integrationState().observation_error, null);
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
test('T11 a failed observe while the schedule operation is still queued changes nothing (E1 applies to our own apply only)', async () => {
    const f = world(true);
    try {
        await f.observe(); const id = queue(f, [night]), row = JSON.stringify(op(f, id));
        f.advance(1); f.router.failure = new RouterTransportError('test_read_failed'); await f.observe();
        assert.equal(JSON.stringify(op(f, id)), row); assert.equal(op(f, id).state, 'pending'); assert.equal(active(f), id);
        f.router.failure = null; f.advance(1); await f.observe(); await applyOp(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.deepEqual(committed(f), [night]);
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
