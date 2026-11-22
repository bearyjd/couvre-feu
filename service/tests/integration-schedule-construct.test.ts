import test from 'node:test';
import assert from 'node:assert/strict';
import { RouterTransportError } from '../src/router-transport.ts';
import { policyDigest } from '../../shared/src/router-rpc.ts';
import { PRE_WRITE_ROUTER_CODES } from '../src/integration-router-codes.ts';
import { actor } from './fixtures/integration.ts';
import { PEER_MAC, PILOT_MAC, active, applies, apply, applyLease, at, audits, committed, cross, edit, editId, night, op, openSteps, operations, plain,
    rebind, receipt, routerChange, rpcPhase, sequence, sha, study, token, world } from './fixtures/schedule-settle.ts';

// Roadmap item 2, S2a (schedules.editable, off; unverified on this router): construction, admission at queue time and settlement S2/S3/S7.
// Each test names the guard it pins; the PR body records the mutation that makes it fail.

test('T1 construction: an edit for pilot copies the peer\'s pause, allowance, DoH and windows from the base; only pilot\'s windows change', async () => {
    const f = world(true, {peer: true});
    try {
        await f.observe();
        const until = f.router.policy.allowances![0].until, id = editId(f, [night]);
        const e = JSON.parse(f.store.get<{envelope_json: string}>('SELECT envelope_json FROM operation_rpc WHERE operation_id=?', id)!.envelope_json);
        const canonical = `V\t1\nR\t1\nA\tpeer\t0\nD4\t9.9.9.9\nP\tpeer\t${PEER_MAC}\nP\tpilot\t${PILOT_MAC}\nS\tpeer\tstudy\tWed\t16:00\t18:00\nS\tpilot\tnight\tMon,Tue\t20:30\t07:00\nU\tpeer\t${until}\n`;
        assert.equal(policyDigest(e.policy), sha(canonical));
        await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed');
        assert.deepEqual(committed(f), [night]); assert.deepEqual(committed(f, 'peer'), [study]);
    } finally { f.cleanup(); }
});
test('T2 candidate set: an observation whose peer windows differ from the committed rows is never published', async () => {
    const f = world(true, {peer: true});
    try {
        await f.observe();
        editId(f, [night]);
        const before = sequence(f), stored = f.store.observation().value;
        routerChange(f, p => ({schedules: [...p.schedules.filter(s => s.person !== 'peer'), {person: 'peer', ...night}]}));
        f.advance(5); await f.observe();
        assert.equal(sequence(f), before);
        assert.deepEqual(f.store.observation().value, stored);
        assert.equal(f.store.integrationState().observation_error, 'router_observation_invalid');
    } finally { f.cleanup(); }
});
test('T3 check 1: a child the router does not hold is refused at queue time; no operation row and no window write', async () => {
    const f = world(true);
    try {
        await f.observe();
        f.store.run('INSERT INTO people(id,name,active,created_at) VALUES(?,?,1,?)', 'ghost', 'Unrouted test child', 2);
        const wide = {...actor, personIds: ['pilot', 'ghost']};
        assert.throws(() => edit(f, [night], {person: 'ghost', as: wide, precondition: token(f)}), /person_has_no_enrolled_device/);
        assert.equal(operations(f), 0); assert.equal(f.writes(), 0); assert.equal(active(f), null);
    } finally { f.cleanup(); }
});
test('T4 checks 2-3: nine windows, and 17 addresses x 8 cross-midnight windows (272 > 256 expanded), are inadmissible; nothing is applied', async () => {
    const nine = world(true), wide = world(true, {devices: 17});
    try {
        await nine.observe();
        assert.throws(() => edit(nine, plain(9)), /schedule_payload_inadmissible/);
        assert.equal(operations(nine), 0);
        await wide.observe();
        assert.equal(wide.router.policy.people[0].macs.length, 17);
        assert.throws(() => edit(wide, cross(8)), /schedule_payload_inadmissible/);
        assert.equal(operations(wide), 0); assert.equal(applies(nine) + applies(wide), 0);
    } finally { nine.cleanup(); wide.cleanup(); }
});
test('T5 check 4: the planned windows need a scheduleClock; deleting every window (empty set) is admitted', async () => {
    const noClock = world(true, {clock: false}), owned = world(true, {pilotWindows: [night]});
    try {
        await noClock.observe();
        assert.throws(() => edit(noClock, [night]), /owner_schedule_clock_required/);
        assert.equal(operations(noClock), 0);
        await owned.observe();
        const id = editId(owned, []);
        assert.equal(op(owned, id).state, 'pending');
        await apply(owned, id);
        assert.equal(op(owned, id).state, 'confirmed'); assert.deepEqual(committed(owned), []);
    } finally { noClock.cleanup(); owned.cleanup(); }
});
test('T6 queue: a stale token is refused, a replay returns the first operation, the same key with other windows conflicts', async () => {
    const f = world(true);
    try {
        await f.observe();
        const stale = token(f).replace(/-r0-/, '-r7-');
        assert.throws(() => edit(f, [night], {precondition: stale}), /revision_conflict/);
        assert.equal(operations(f), 0);
        const first = edit(f, [night], {key: 'replay_key_0000001'}).result.operation.id;
        const precondition = f.store.get<{request_json: string}>('SELECT request_json FROM operations WHERE id=?', first)!.request_json;
        const again = edit(f, [night], {key: 'replay_key_0000001', precondition: JSON.parse(precondition).precondition}).result.operation.id;
        assert.equal(again, first);
        assert.throws(() => edit(f, [study], {key: 'replay_key_0000001', precondition: JSON.parse(precondition).precondition}), /idempotency_payload_conflict/);
        assert.equal(operations(f), 1);
    } finally { f.cleanup(); }
});
test('T7 S2 write-on-change: lost reply, then exact reads promote pilot\'s windows once; repeats write nothing and add no audit row', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response');
        await apply(f, id); f.router.afterApplyFailure = null;
        assert.equal(op(f, id).state, 'unknown'); assert.equal(op(f, id).error, 'router_outcome_unknown'); assert.equal(f.writes(), 0);
        f.router.runtimeError = 'incomplete_transition_address_coverage';
        f.advance(5); await receipt(f, id);
        assert.equal(op(f, id).error, 'accepted_router_runtime_unconfirmed'); assert.equal(f.writes(), 1);
        const rows = audits(f, id);
        f.advance(5); await receipt(f, id);
        assert.equal(f.writes(), 1); assert.equal(audits(f, id), rows);
        f.router.runtimeError = null;
        f.advance(5); await receipt(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.equal(f.writes(), 1); assert.equal(audits(f, id, 'confirmed'), 1);
        f.advance(5); await receipt(f, id);
        assert.equal(f.writes(), 1); assert.equal(audits(f, id, 'confirmed'), 1); assert.deepEqual(committed(f), [night]);
    } finally { f.cleanup(); }
});
test('T8 S3: every pre-write refusal of our own apply is terminal, resolves the step and unblocks rebind; a later read changes nothing', async () => {
    for (const code of [...PRE_WRITE_ROUTER_CODES, 'policy_conflict']) {
        const f = world(true);
        try {
            await f.observe();
            const id = editId(f, [night]);
            if (code === 'policy_conflict') routerChange(f, () => ({pauses: [{person: 'pilot', until: 0}]}));
            f.router.reject = code;
            await apply(f, id); f.router.reject = null; f.router.runtimeError = null;
            const row = op(f, id);
            assert.deepEqual([row.state, row.error], code === 'policy_conflict' ? ['conflict', 'router_base_changed_before_write'] : ['failed', 'router_refused_before_write'], code);
            assert.equal(active(f), null, code); assert.equal(openSteps(f, id), 0, code); assert.equal(rpcPhase(f, id), 'resolved', code);
            assert.deepEqual(committed(f), [], code); assert.equal(applies(f), 1, code);
            f.advance(5); await f.observe();
            assert.deepEqual(op(f, id), row, code);
            rebind(f);
        } finally { f.cleanup(); }
    }
});
test('T9 S7 fence: a reply-shaped failure on our apply stays unknown until the fence passes in service AND router time, then fails; one apply', async () => {
    const f = world(true);
    try {
        await f.observe();
        const id = editId(f, [night]);
        f.router.failure = new RouterTransportError('invalid_router_response');
        await apply(f, id); f.router.failure = null;
        assert.deepEqual([op(f, id).state, op(f, id).error], ['unknown', 'router_outcome_unknown']);
        const fence = applyLease(f, id) + 600;
        f.advance(5); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error], ['unknown', 'receipt_missing_remote_outcome_unknown']);
        at(f, fence - 1); await f.observe();
        assert.equal(op(f, id).state, 'unknown');
        at(f, fence); await f.observe();
        assert.deepEqual([op(f, id).state, op(f, id).error], ['failed', 'router_apply_unobserved_after_fence']);
        assert.equal(active(f), null); assert.equal(openSteps(f, id), 0); assert.equal(applies(f), 1); assert.deepEqual(committed(f), []);
        rebind(f);
    } finally { f.cleanup(); }
});
test('T20 DoH: a schedule edit never reconciles the static DoH list, with dnsHardening.dohList on or explicitly off; queue and admission agree', async () => {
    for (const dohList of [true, false]) {
        const f = world(true);
        try {
            (f.config as unknown as {dnsHardening: unknown}).dnsHardening = {dohList};
            // On: the base lacks the static list. Off: the base holds one list address and one retired address.
            const held = dohList ? {ipv4: ['192.0.2.53'], ipv6: []} : {ipv4: ['1.0.0.1', '192.0.2.53', '194.242.2.2'], ipv6: []};
            routerChange(f, () => ({doh: held}));
            await f.observe();
            const base = f.router.policy.doh, id = editId(f, [night]);
            const e = JSON.parse(f.store.get<{envelope_json: string}>('SELECT envelope_json FROM operation_rpc WHERE operation_id=?', id)!.envelope_json);
            assert.deepEqual(e.policy.doh, base, `dohList=${dohList} envelope`);
            assert.deepEqual(JSON.parse(op(f, id).payload_json).doh, base, `dohList=${dohList} payload`);
            await apply(f, id);
            assert.deepEqual([op(f, id).state, op(f, id).error], ['confirmed', null], `dohList=${dohList}`);
            assert.deepEqual(f.router.policy.doh, base, `dohList=${dohList} router`);
            assert.deepEqual(committed(f), [night]);
        } finally { f.cleanup(); }
    }
});
