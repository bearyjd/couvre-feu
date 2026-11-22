import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { freePort } from './free-port.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { TestAuthenticator } from './authenticator.ts';
import { actor } from './fixtures/integration.ts';
import { scheduleSeam } from '../src/integration-schedule-settle.ts';
import { isLoosening } from '../src/schedule-loosening.ts';
import { ScheduleStepUp, scheduleStepUpPost } from '../src/integration-schedule-stepup.ts';
import { active, apply, committed, night, op, operations, study, token, world } from './fixtures/schedule-settle.ts';
import type { Window, World } from './fixtures/schedule-settle.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';

// Roadmap item 2, S2b (schedules.editable, off; unverified on this router): a loosening or deleting schedule edit needs a fresh passkey step-up
// bound to {child, resulting window-set digest, precondition} before anything is queued. Each test names the guard it pins; the PR records the mutations.
const w = (id: string, weekdays: string[], start: string, stop: string): Schedule => ({person: 'pilot', id, weekdays: weekdays as Schedule['weekdays'], start, stop});
const A = w('a', ['Mon', 'Tue'], '20:00', '23:00');
const classifier: [string, Schedule[], Schedule[], boolean][] = [
    ['unchanged', [A], [A], false],
    ['window added', [A], [A, w('b', ['Wed'], '10:00', '11:00')], false],
    ['first window on an empty set', [], [A], false],
    ['start earlier (longer)', [A], [{...A, start: '19:00'}], false],
    ['stop later (longer)', [A], [{...A, stop: '23:30'}], false],
    ['weekday added', [A], [{...A, weekdays: ['Mon', 'Tue', 'Wed']}], false],
    ['cross-midnight window widened', [w('c', ['Mon'], '22:00', '06:00')], [w('c', ['Mon'], '21:00', '07:00')], false],
    ['start later (shortened)', [A], [{...A, start: '20:30'}], true],
    ['stop earlier (shortened)', [A], [{...A, stop: '22:00'}], true],
    ['weekday removed (fewer weekdays)', [A], [{...A, weekdays: ['Mon']}], true],
    ['window deleted', [A, w('b', ['Wed'], '10:00', '11:00')], [A], true],
    ['last window deleted (empty set)', [A], [], true],
    ['redundant window deleted fails closed', [A, w('r', ['Mon'], '21:00', '22:00')], [A], true],
    ['shifted: frees minutes while blocking others', [A], [{...A, start: '21:00', stop: '23:30'}], true],
    ['cross-midnight tail trimmed', [w('c', ['Sun'], '22:00', '06:00')], [w('c', ['Sun'], '22:00', '05:00')], true],
    ['cross-midnight wraps Sun into Mon (kept)', [w('c', ['Sun'], '22:00', '06:00')], [w('c', ['Sun'], '22:00', '06:00'), w('d', ['Mon'], '01:00', '02:00')], false],
];
for (const [name, before, after, expected] of classifier) test(`classifier: ${name} -> ${expected ? 'loosening' : 'not loosening'}`, () => assert.equal(isLoosening(before, after), expected));

const origin = 'http://localhost:4274';
const body = (x: Window) => ({id: x.id, weekdays: x.weekdays, start: x.start, stop: x.stop});
const patch = (x: Window) => ({weekdays: x.weekdays, start: x.start, stop: x.stop});
const dump = (f: World) => JSON.stringify([f.store.all('SELECT * FROM operations'), f.store.all('SELECT * FROM audit'), f.store.all('SELECT * FROM parent_audit')]);

async function harness(flag: true | false, windows: readonly Window[] = [night, study], peer = false) {
    const f = world(flag, {pilotWindows: flag ? windows : [], peer});
    f.config.auditLog = {enabled: true};
    f.store.run('UPDATE accounts SET person_ids=? WHERE id=?', JSON.stringify(peer ? ['pilot', 'peer'] : ['pilot']), 'operator');
    const port = await freePort(), base = `http://localhost:${port}`;
    const auth = new Auth(f.store, base, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: base, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
    const reg = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, 'operator', f.now())}, browser);
    const session = await auth.registrationVerify({challengeId: reg.challengeId, response: key.register(reg.options, base)}, browser);
    const cookie = `cf_session=${session.token}; cf_browser=${browser}`, csrf = session.dto.csrfToken;
    let n = 0;
    const post = async (path: string, payload: unknown, headers: Record<string, string> = {}) => {
        const r = await fetch(base + path, {method: 'POST', headers: {Cookie: cookie, Origin: base, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, ...headers}, body: JSON.stringify(payload)});
        return {status: r.status, json: await r.json() as Record<string, any>};
    };
    const proof = async (scheduleAction: string, change: unknown, scheduleId: string | undefined, over: Record<string, unknown> = {}) => {
        const o = await post('/step-up/options', {action: 'schedule_change', person: 'pilot', scheduleAction, ...(scheduleId ? {scheduleId} : {}), precondition: token(f), change, ...over});
        assert.equal(o.status, 200, JSON.stringify(o.json));
        return {challengeId: o.json.challengeId, response: key.login(o.json.options, base)};
    };
    const send = (path: string, payload: unknown, o: {key?: string; pre?: string} = {}) =>
        post(path, payload, {'If-Match': o.pre ?? token(f), 'Idempotency-Key': o.key ?? `stepup_key_${String(++n).padStart(8, '0')}`});
    const counter = () => f.store.get<{counter: number}>("SELECT counter FROM credentials WHERE account_id='operator'")!.counter;
    await f.observe();
    return {f, proof, send, post, counter, auth, key, close: () => { server.close(); f.cleanup(); }};
}
const DEL = '/people/pilot/schedules/study/delete';
const SHRINK = '/people/pilot/schedules/study';

test('S1 loosening without a step-up: 403 step_up_required and nothing is written (no operation, audit, row or counter)', async () => {
    const h = await harness(true);
    try {
        const before = dump(h.f), c = h.counter();
        for (const r of [await h.send(DEL, {}), await h.send(SHRINK, patch({...study, start: '17:00'}))]) { assert.equal(r.status, 403); assert.equal(r.json.error?.code ?? r.json.code, 'step_up_required'); }
        assert.equal(dump(h.f), before); assert.equal(h.f.writes(), 0); assert.equal(h.counter(), c);
    } finally { h.close(); }
});
test('S2 tightening needs no step-up and spends no passkey use; the label stays schedule_set', async () => {
    const h = await harness(true);
    try {
        const c = h.counter(), pre = token(h.f), r = await h.send('/people/pilot/schedules', body({id: 'extra', weekdays: ['Fri'], start: '19:00', stop: '20:00'}), {pre});
        assert.equal(r.status, 202); assert.equal(h.counter(), c);
        assert.deepEqual(h.f.store.all<{action: string; result: string}>('SELECT action,result FROM parent_audit').map(x => ({...x})), [{action: 'schedule_set', result: 'applied'}]);
        // a step-up is not minted for it either
        const o = await h.post('/step-up/options', {action: 'schedule_change', person: 'pilot', scheduleAction: 'schedule_create', precondition: pre, change: body({id: 'x2', weekdays: ['Sat'], start: '10:00', stop: '11:00'})});
        assert.equal(o.status, 409); assert.equal(o.json.error?.code ?? o.json.code, 'step_up_not_required');
    } finally { h.close(); }
});
test('S3 a verified step-up queues the delete, spends the passkey use, writes schedule_loosened after verification, and settlement is the unchanged S2a path', async () => {
    const h = await harness(true), decide = mock.method(scheduleSeam, 'decideSchedule');
    try {
        const c = h.counter(), proof = await h.proof('schedule_delete', {}, 'study');
        const r = await h.send(DEL, {stepUp: proof}); assert.equal(r.status, 202);
        assert.ok(h.counter() > c);
        const id = r.json.operation.id;
        assert.deepEqual(h.f.store.all<{action: string; operation_id: string; result: string}>('SELECT action,operation_id,result FROM parent_audit').map(x => ({...x})), [{action: 'schedule_loosened', operation_id: id, result: 'applied'}]);
        await apply(h.f, id);
        assert.equal(op(h.f, id).state, 'confirmed'); assert.deepEqual(committed(h.f), [night]);
        assert.ok(decide.mock.callCount() > 0);
        const dumped = JSON.stringify(h.f.store.all('SELECT * FROM parent_audit'));
        for (const secret of ['study', '16:00', 'Wed', 'night']) assert.ok(!dumped.includes(secret), secret);
    } finally { decide.mock.restore(); h.close(); }
});
test('S4 replayed, consumed and garbage assertions are refused with fixed codes and write nothing', async () => {
    const h = await harness(true);
    try {
        const proof = await h.proof('schedule_delete', {}, 'study');
        assert.equal((await h.send(DEL, {stepUp: proof})).status, 202);
        await apply(h.f, active(h.f)!); h.f.advance(5); await h.f.observe();
        // the same assertion for another change (shrink night) on a new key: consumed
        const before = dump(h.f), c = h.counter();
        const r = await h.send('/people/pilot/schedules/night', patch({...night, start: '22:00'}), {}); assert.equal(r.status, 403);
        const replay = await h.send('/people/pilot/schedules/night', {...patch({...night, start: '22:00'}), stepUp: proof});
        assert.equal(replay.status, 401); assert.equal(replay.json.error?.code ?? replay.json.code, 'invalid_challenge');
        const junk = await h.send('/people/pilot/schedules/night', {...patch({...night, start: '22:00'}), stepUp: 'garbage'});
        assert.equal(junk.status, 400);
        assert.equal(dump(h.f), before); assert.equal(h.counter(), c);
    } finally { h.close(); }
});
test('S5 a stale step-up (older than its 120 s life) is refused and writes nothing', async () => {
    const h = await harness(true);
    try {
        const proof = await h.proof('schedule_delete', {}, 'study'), before = dump(h.f);
        h.f.advance(121); await h.f.observe();
        const r = await h.send(DEL, {stepUp: proof}); assert.equal(r.status, 401);
        assert.equal(r.json.error?.code ?? r.json.code, 'invalid_challenge'); assert.equal(dump(h.f), before);
    } finally { h.close(); }
});
test('S6 wrong binding: another change, another precondition and a changed committed set are all step_up_mismatch; nothing written', async () => {
    const h = await harness(true);
    try {
        const before = dump(h.f);
        // a proof for deleting night used to delete study
        const forNight = await h.proof('schedule_delete', {}, 'night');
        let r = await h.send(DEL, {stepUp: forNight}); assert.equal(r.status, 403); assert.equal(r.json.error?.code ?? r.json.code, 'step_up_mismatch');
        // same change, different precondition token than the one bound
        const bound = await h.proof('schedule_delete', {}, 'study');
        r = await h.send(DEL, {stepUp: bound}, {pre: token(h.f).replace(/-r0-/, '-r1-')}); assert.ok([403, 409].includes(r.status)); assert.notEqual(r.status, 202);
        // a different resulting set (shrink to another time) than the proof's
        const shrinkA = await h.proof('schedule_update', patch({...study, start: '17:00'}), 'study');
        r = await h.send(SHRINK, {...patch({...study, start: '17:30'}), stepUp: shrinkA}); assert.equal(r.status, 403); assert.equal(r.json.error?.code ?? r.json.code, 'step_up_mismatch');
        assert.equal(dump(h.f), before); assert.equal(operations(h.f), 0);
        // a proof for one child's change cannot be used on another (out-of-scope child is not found)
        const o = await h.post('/step-up/options', {action: 'schedule_change', person: 'peer', scheduleAction: 'schedule_delete', precondition: token(h.f), change: {}, scheduleId: 'study'});
        assert.equal(o.status, 404);
    } finally { h.close(); }
});
test('A recurring-focus step-up binds the resulting kind even when the exact blocked minutes are the same', async () => {
    const h = await harness(true);
    h.f.config.focus = {enabled: true};
    try {
        const change = patch({...study, start: '17:00'}), before = dump(h.f), counter = h.counter();
        const proof = await h.proof('schedule_update', {...change, kind: 'focus'}, study.id);
        const wrong = await h.send(SHRINK, {...change, kind: 'bedtime', stepUp: proof});
        assert.equal(wrong.status, 403);
        assert.equal(wrong.json.error?.code ?? wrong.json.code, 'step_up_mismatch');
        assert.equal(dump(h.f), before);
        assert.equal(h.counter(), counter);
        const correctProof = await h.proof('schedule_update', {...change, kind: 'focus'}, study.id);
        const right = await h.send(SHRINK, {...change, kind: 'focus', stepUp: correctProof});
        assert.equal(right.status, 202);
        assert.ok(h.counter() > counter);
        await apply(h.f, right.json.operation.id);
        assert.equal(h.f.policy.people(actor).people[0].schedules?.find(w => w.id === study.id)?.kind, 'focus');
    } finally { h.close(); }
});
test('With recurring focus off, an omitted kind cannot retain the target label, but conversion, deletion and unrelated edits work', async () => {
    const other: Window = {id: 'other', weekdays: ['Fri'], start: '20:00', stop: '21:00'};
    const h = await harness(true, [night, study, other]);
    h.f.config.focus = {enabled: false};
    try {
        h.f.store.run("UPDATE schedule_windows SET kind='focus' WHERE id IN ('night','study')");
        const narrower = patch({...study, start: '17:00'}), precondition = token(h.f);
        const options = await h.post('/step-up/options', {action: 'schedule_change', person: 'pilot', scheduleAction: 'schedule_update',
            scheduleId: study.id, precondition, change: narrower});
        assert.equal(options.status, 409);
        assert.equal(options.json.error?.code ?? options.json.code, 'recurring_focus_unavailable');
        const refused = await h.send(SHRINK, narrower);
        assert.equal(refused.status, 409);
        assert.equal(refused.json.error?.code ?? refused.json.code, 'recurring_focus_unavailable');
        assert.equal(operations(h.f), 0);

        const enlarged = await h.send('/people/pilot/schedules/other', patch({...other, stop: '21:30'}));
        assert.equal(enlarged.status, 202);
        await apply(h.f, enlarged.json.operation.id);
        const converted = await h.send(SHRINK, {...patch(study), kind: 'bedtime'});
        assert.equal(converted.status, 202);
        await apply(h.f, converted.json.operation.id);
        assert.equal(h.f.store.get<{kind: string}>("SELECT kind FROM schedule_windows WHERE id='study'")?.kind, 'bedtime');
        const proof = await h.proof('schedule_delete', {}, night.id);
        const deleted = await h.send('/people/pilot/schedules/night/delete', {stepUp: proof});
        assert.equal(deleted.status, 202);
        await apply(h.f, deleted.json.operation.id);
        assert.equal(h.f.store.get("SELECT kind FROM schedule_windows WHERE id='night'"), undefined);
    } finally { h.close(); }
});
test('S7 idempotent replay of a stepped-up request needs no second step-up and spends none; a different payload on that key is a conflict', async () => {
    const h = await harness(true);
    try {
        const proof = await h.proof('schedule_delete', {}, 'study'), pre = token(h.f), key = 'stepup_replay_key_001';
        const first = await h.send(DEL, {stepUp: proof}, {key, pre}); assert.equal(first.status, 202);
        const c = h.counter(), n = operations(h.f);
        const again = await h.send(DEL, {}, {key, pre});
        assert.equal(again.status, 202); assert.equal(again.json.operation.id, first.json.operation.id);
        assert.equal(h.counter(), c); assert.equal(operations(h.f), n);
        assert.equal(h.f.store.all('SELECT 1 FROM parent_audit').length, 1);
        const other = await h.send('/people/pilot/schedules/night/delete', {}, {key, pre}); assert.equal(other.status, 409);
    } finally { h.close(); }
});
test('S8 the in-transaction gate re-judges: a loosening with no verified proof, or a proof bound to another digest, is refused inside scheduleMutate', async () => {
    const h = await harness(true);
    try {
        const mutate = h.f.policy.scheduleMutate!, before = dump(h.f);
        const call = (gate: Parameters<typeof mutate>[7]) => mutate(actor, 'pilot', 'schedule_delete', {}, 'study', token(h.f), 'gate_key_000000001', gate);
        assert.throws(() => call({verified: null}), /step_up_required/);
        let spent = 0;
        assert.throws(() => call({verified: {digest: 'f'.repeat(64), commit: () => { spent++; }}}), /step_up_mismatch/);
        assert.equal(spent, 0); assert.equal(dump(h.f), before);
        // no gate (direct callers) keeps S2m behaviour; a tightening with a null gate is fine
        assert.equal(mutate(actor, 'pilot', 'schedule_create', body({id: 'ok', weekdays: ['Fri'], start: '19:00', stop: '20:00'}), undefined, token(h.f), 'gate_key_000000002', {verified: null}).status, 202);
    } finally { h.close(); }
});
test('S9 flag off (absent or false): the route stays 403, the step-up action is not claimed, no schedule code runs', async () => {
    const off = await harness(false), decide = mock.method(scheduleSeam, 'decideSchedule');
    try {
        assert.equal(off.f.policy.scheduleMutate, undefined);
        const r = await off.send(DEL, {}); assert.equal(r.status, 403); assert.equal(r.json.error?.code ?? r.json.code, 'schedule_editing_unavailable');
        const o = await off.post('/step-up/options', {action: 'schedule_change', person: 'pilot', scheduleAction: 'schedule_delete', precondition: 'x', change: {}});
        assert.notEqual(o.status, 200);
        const direct = new ScheduleStepUp(off.auth, off.f.policy);
        assert.equal(await scheduleStepUpPost(direct, {} as never, '/step-up/options', {action: 'schedule_change'}), null);
        await assert.rejects(direct.options({} as never, {}), /schedule_editing_unavailable|Schedules are owner-configured/);
        assert.equal(operations(off.f), 0); assert.equal(decide.mock.callCount(), 0);
    } finally { decide.mock.restore(); off.close(); }
});
test('S10 other step-up actions are not claimed by the schedule route', async () => {
    const h = await harness(true);
    try {
        assert.equal(await scheduleStepUpPost(new ScheduleStepUp(h.auth, h.f.policy), {} as never, '/step-up/options', {action: 'pause_all'}), null);
        assert.equal(await scheduleStepUpPost(null, {} as never, '/step-up/options', {action: 'schedule_change'}), null);
    } finally { h.close(); }
});
test('S11 a proof for emptying one child cannot empty another child: the binding names the person, not just the (empty) set', async () => {
    const h = await harness(true, [night], true);
    try {
        const proof = await h.proof('schedule_delete', {}, 'night'), before = dump(h.f);
        const r = await h.send('/people/peer/schedules/study/delete', {stepUp: proof});
        assert.equal(r.status, 403); assert.equal(r.json.error?.code ?? r.json.code, 'step_up_mismatch');
        assert.equal(dump(h.f), before); assert.deepEqual(committed(h.f, 'peer'), [study]);
    } finally { h.close(); }
});
