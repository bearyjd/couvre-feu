import test from 'node:test';
import assert from 'node:assert/strict';
import type { ScheduleAction } from '../../shared/src/schedule-edit.ts';
import { actor } from './fixtures/integration.ts';
import { active, apply, committed, freshKey, night, op, operations, plain, study, token, world } from './fixtures/schedule-settle.ts';
import type { Window, World } from './fixtures/schedule-settle.ts';

// Roadmap item 2, S2m (schedules.editable, off; unverified on this router): scheduleMutate folds ONE create/update/delete into the child's
// committed window set and hands the whole set to scheduleEdit's admission. Each test names the guard it pins; the PR records the mutations.
const body = (w: Window) => ({id: w.id, weekdays: w.weekdays, start: w.start, stop: w.stop});
const patch = (w: Window) => ({weekdays: w.weekdays, start: w.start, stop: w.stop});
function mutate(f: World, action: ScheduleAction, input: unknown, id?: string, o: {key?: string; person?: string; as?: typeof actor; precondition?: string} = {}) {
    return f.policy.scheduleMutate!(o.as ?? actor, o.person ?? 'pilot', action, input, id, o.precondition ?? token(f), o.key ?? freshKey());
}
const create = (f: World, w: Window, o = {}) => mutate(f, 'schedule_create', body(w), undefined, o);
const update = (f: World, w: Window, o = {}) => mutate(f, 'schedule_update', patch(w), w.id, o);
const remove = (f: World, id: string, o = {}) => mutate(f, 'schedule_delete', {}, id, o);
const envelopeWindows = (f: World, id: string) => (JSON.parse(f.store.get<{envelope_json: string}>('SELECT envelope_json FROM operation_rpc WHERE operation_id=?', id)!.envelope_json).policy.schedules as {person: string}[]);
const auditRows = (f: World) => f.store.all<{action: string; person_id: string | null; operation_id: string | null; result: string}>('SELECT action,person_id,operation_id,result FROM parent_audit ORDER BY id').map(r => ({...r}));

test('M1 create: one window is added to the committed set, applied and promoted', async () => {
    const f = world(true, {pilotWindows: [night]});
    try {
        await f.observe();
        const r = create(f, study), id = r.result.operation.id;
        assert.equal(r.status, 202); assert.equal(op(f, id).action, 'schedule_update');
        assert.deepEqual(envelopeWindows(f, id).map(s => s.person), ['pilot', 'pilot']);
        await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed');
        assert.deepEqual(committed(f), [night, study]);
    } finally { f.cleanup(); }
});
test('M2 update: only the named window changes; the other keeps its rows; peer windows are untouched', async () => {
    const f = world(true, {pilotWindows: [night, study], peer: true});
    try {
        await f.observe();
        const moved = {...study, start: '15:00', stop: '17:30'}, id = update(f, moved).result.operation.id;
        await apply(f, id);
        assert.deepEqual(committed(f), [night, moved]); assert.deepEqual(committed(f, 'peer'), [study]);
    } finally { f.cleanup(); }
});
test('M3 delete: removing the last window queues an empty set and clears the rows', async () => {
    const f = world(true, {pilotWindows: [night]});
    try {
        await f.observe();
        const id = remove(f, 'night').result.operation.id;
        assert.equal(envelopeWindows(f, id).length, 0);
        await apply(f, id);
        assert.equal(op(f, id).state, 'confirmed'); assert.deepEqual(committed(f), []);
    } finally { f.cleanup(); }
});
test('M5 cap: a ninth window is inadmissible and queues nothing', async () => {
    const f = world(true, {pilotWindows: plain(8)});
    try {
        await f.observe();
        assert.throws(() => create(f, night), /schedule_payload_inadmissible/);
        assert.equal(operations(f), 0); assert.equal(active(f), null);
        // an update at the cap is still admitted
        assert.equal(update(f, {...plain(1)[0], stop: '11:00'}).status, 202);
    } finally { f.cleanup(); }
});
test('M6 stale precondition: 409 revision_conflict beats a schedule_not_found fold error; nothing is queued', async () => {
    const f = world(true, {pilotWindows: [night]});
    try {
        await f.observe();
        const stale = token(f).replace(/-r0-/, '-r7-');
        assert.throws(() => remove(f, 'missing', {precondition: stale}), /revision_conflict/);
        assert.throws(() => update(f, study, {precondition: stale}), /revision_conflict/);
        assert.equal(operations(f), 0);
    } finally { f.cleanup(); }
});
test('M7 fold errors: duplicate id 409, unknown id 404, bad body 400; none queues', async () => {
    const f = world(true, {pilotWindows: [night]});
    try {
        await f.observe();
        assert.throws(() => create(f, night), /schedule_id_exists/);
        assert.throws(() => update(f, study), /schedule_not_found/);
        assert.throws(() => remove(f, 'study'), /schedule_not_found/);
        assert.throws(() => mutate(f, 'schedule_create', {...body(study), start: '16:00', stop: '16:00'}), /empty_schedule/);
        assert.throws(() => mutate(f, 'schedule_create', {...body(study), extra: 1}), /unknown_field|invalid/);
        assert.throws(() => mutate(f, 'schedule_delete', {id: 'night'}, 'night'), /unknown_field|invalid/);
        for (const key of ['short', 'tr-' + 'a'.repeat(20)]) assert.throws(() => create(f, study, {key}), /idempotency_key_required/);
        assert.throws(() => create(f, study, {precondition: 'nope'}), /revision_precondition_required/);
        assert.equal(operations(f), 0);
    } finally { f.cleanup(); }
});
test('M8 replay: the same key and body returns the first operation, also after it settled and changed the rows; other body conflicts', async () => {
    const f = world(true);
    try {
        await f.observe();
        const key = 'mutate_replay_00001', pre = token(f), first = create(f, night, {key, precondition: pre}).result.operation.id;
        assert.equal(create(f, night, {key, precondition: pre}).result.operation.id, first);
        await apply(f, first);
        assert.deepEqual(committed(f), [night]);
        assert.equal(create(f, night, {key, precondition: pre}).result.operation.id, first, 'replay after settle must not re-fold into schedule_id_exists');
        assert.throws(() => create(f, study, {key, precondition: pre}), /idempotency_payload_conflict/);
        assert.throws(() => remove(f, 'night', {key, precondition: pre}), /idempotency_payload_conflict/);
        assert.throws(() => create(f, night, {key, precondition: token(f)}), /idempotency_payload_conflict/);
        assert.equal(operations(f), 1);
    } finally { f.cleanup(); }
});
test('M9 a key first used by scheduleEdit conflicts with a mutate of the same windows', async () => {
    const f = world(true);
    try {
        await f.observe();
        const key = 'mutate_edit_key_0001', pre = token(f);
        f.policy.scheduleEdit(actor, 'pilot', [night], pre, key);
        assert.throws(() => create(f, night, {key, precondition: pre}), /idempotency_payload_conflict/);
        assert.equal(operations(f), 1);
    } finally { f.cleanup(); }
});
test('M10 scope: a child outside the actor scope, or unknown, is 404 person_not_found with no operation', async () => {
    const f = world(true, {peer: true});
    try {
        await f.observe();
        assert.throws(() => create(f, night, {person: 'peer'}), /person_not_found/);
        assert.throws(() => create(f, night, {person: 'nobody'}), /person_not_found/);
        assert.equal(operations(f), 0);
    } finally { f.cleanup(); }
});
test('M11 unrouted child: refused 409 person_has_no_enrolled_device, not local-only; no row written', async () => {
    const f = world(true);
    try {
        await f.observe();
        f.store.run('INSERT INTO people(id,name,active,created_at) VALUES(?,?,1,?)', 'ghost', 'Unrouted test child', 2);
        const wide = {...actor, personIds: ['pilot', 'ghost']};
        assert.throws(() => create(f, night, {person: 'ghost', as: wide}), /person_has_no_enrolled_device/);
        assert.throws(() => remove(f, 'nothing', {person: 'ghost', as: wide}), /person_has_no_enrolled_device/);
        assert.equal(operations(f), 0); assert.equal(f.writes(), 0); assert.deepEqual(committed(f, 'ghost'), []);
    } finally { f.cleanup(); }
});
test('M12 audit: schedule_set / schedule_loosened by coverage, ids and enums only, refusals recorded, replay adds no row', async () => {
    const f = world(true, {pilotWindows: [night]});
    f.config.auditLog = {enabled: true};
    try {
        await f.observe();
        const pre = token(f), c = create(f, study, {key: 'mutate_audit_key_001', precondition: pre}).result.operation.id;
        await apply(f, c);
        create(f, study, {key: 'mutate_audit_key_001', precondition: pre});
        f.advance(5); await f.observe();
        const widen = update(f, {...study, start: '15:00', stop: '19:00'}).result.operation.id; await apply(f, widen);
        f.advance(5); await f.observe();
        const shrink = update(f, {...study, start: '16:00', stop: '18:00'}).result.operation.id; await apply(f, shrink);
        f.advance(5); await f.observe();
        const del = remove(f, 'study').result.operation.id; await apply(f, del);
        f.advance(5); await f.observe();
        assert.throws(() => create(f, night), /schedule_id_exists/);
        assert.throws(() => remove(f, 'study'), /schedule_not_found/); // a 404 leaves no audit row
        assert.deepEqual(auditRows(f), [
            {action: 'schedule_set', person_id: 'pilot', operation_id: c, result: 'applied'},
            {action: 'schedule_set', person_id: 'pilot', operation_id: widen, result: 'applied'},
            {action: 'schedule_loosened', person_id: 'pilot', operation_id: shrink, result: 'applied'},
            {action: 'schedule_loosened', person_id: 'pilot', operation_id: del, result: 'applied'},
            {action: 'schedule_set', person_id: 'pilot', operation_id: null, result: 'refused'}]);
        const dump = JSON.stringify(f.store.all('SELECT * FROM parent_audit'));
        for (const secret of ['20:30', '16:00', 'night', 'study', 'Mon']) assert.ok(!dump.includes(secret), secret);
    } finally { f.cleanup(); }
});
test('M13 audit off: no rows; an out-of-scope probe leaves none even when on', async () => {
    const off = world(true), on = world(true, {peer: true});
    on.config.auditLog = {enabled: true};
    try {
        await off.observe(); await on.observe();
        create(off, night);
        assert.equal(auditRows(off).length, 0);
        assert.throws(() => create(on, night, {person: 'peer'}), /person_not_found/);
        assert.equal(auditRows(on).length, 0);
    } finally { off.cleanup(); on.cleanup(); }
});
test('M14 flag off (absent or false): no scheduleMutate and people output identical; flag on (positive control) fills schedules', async () => {
    const absent = world('absent'), off = world(false), on = world(true, {pilotWindows: [night]});
    try {
        assert.equal(absent.policy.scheduleMutate, undefined); assert.equal(off.policy.scheduleMutate, undefined);
        assert.equal(typeof on.policy.scheduleMutate, 'function');
        for (const f of [absent, off, on]) await f.observe();
        const a = absent.policy.people(actor), b = off.policy.people(actor);
        assert.equal(JSON.stringify(a), JSON.stringify(b));
        assert.ok(!('schedules' in a.people[0]) && !('schedulesEditable' in a.people[0]));
        const p = on.policy.people(actor).people[0];
        assert.equal(p.schedulesEditable, true); assert.deepEqual(p.schedules, [night]);
    } finally { absent.cleanup(); off.cleanup(); on.cleanup(); }
});
test('M15 people reflects committed rows after settlement and lists no other child\'s windows', async () => {
    const f = world(true, {peer: true});
    try {
        await f.observe();
        assert.deepEqual(f.policy.people(actor).people[0].schedules, []);
        const id = create(f, night).result.operation.id; await apply(f, id);
        f.advance(5); await f.observe();
        assert.deepEqual(f.policy.people(actor).people[0].schedules, [night]);
        assert.ok(!JSON.stringify(f.policy.people(actor)).includes('study'));
    } finally { f.cleanup(); }
});
