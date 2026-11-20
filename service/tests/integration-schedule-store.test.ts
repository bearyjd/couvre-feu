import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { validateManagedPolicy, withDevice } from '../src/integration-children.ts';
import { MAX_WINDOWS_PER_CHILD, policyWithWindows, replaceScheduleWindows, scheduleWindows, seedScheduleWindows, settleScheduleWindows, stageScheduleWindows } from '../src/integration-schedule-store.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';

const night: Omit<Schedule, 'person'> = {id: 'night', weekdays: ['Mon', 'Tue'], start: '20:30', stop: '07:00'};
type Fixture = ReturnType<typeof integrationFixture>;
/** Tests mutate the fixture's private config object in place (it is a plain object); production config is frozen by its loader. */
function setup(f: Fixture, flag: boolean, schedules: Schedule[] = []) {
    const config = f.config as {schedules?: {editable: boolean}; scheduleClock?: unknown; enrollment: unknown};
    if (flag) config.schedules = {editable: true};
    config.scheduleClock = {timezone: 'UTC'};
    config.enrollment = normalizePolicy({version: 1, revision: 0, people: [{id: 'pilot', macs: ['02:10:20:30:40:50']}], pauses: [], schedules});
    return f.config;
}

test('flag off: the database is never consulted and a changed schedule is still owner_schedule_configuration_changed', () => {
    const f = integrationFixture();
    try {
        const config = setup(f, false, [{person: 'pilot', ...night}]);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        assert.deepEqual(scheduleWindows(f.store), []);
        const accepted = normalizePolicy({...config.enrollment, revision: 1});
        validateManagedPolicy(accepted, config, f.store, false);
        assert.throws(() => validateManagedPolicy(normalizePolicy({...accepted, schedules: []}), config, f.store, false), /owner_schedule_configuration_changed/);
        // Even rows that exist are ignored with the flag off.
        f.store.run("INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES('pilot','other','Sat','10:00','11:00')");
        assert.deepEqual(withDevice(accepted, config, 'pilot', '02:10:20:30:40:52', f.store).schedules, [{person: 'pilot', ...night}]);
    } finally { f.cleanup(); }
});

test('flag on: manifest schedules seed the table exactly once; the database then wins', () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true, [{person: 'pilot', ...night}]);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        assert.deepEqual(scheduleWindows(f.store), [{person: 'pilot', ...night}]);
        f.store.transaction(() => replaceScheduleWindows(f.store, 'pilot', []));
        f.store.transaction(() => seedScheduleWindows(f.store, f.config)); // never re-seeds, even after the parent emptied the set
        assert.deepEqual(scheduleWindows(f.store), []);
        const accepted = normalizePolicy({...config.enrollment, revision: 1, schedules: []});
        validateManagedPolicy(accepted, config, f.store, false);
        const withManifestWindow = normalizePolicy({...accepted, schedules: [{person: 'pilot', ...night}]});
        assert.throws(() => validateManagedPolicy(withManifestWindow, config, f.store, false), /owner_schedule_configuration_changed/);
    } finally { f.cleanup(); }
});

test('flag on: a window set is validated, capped at 8 per child, and carries no free text', () => {
    const f = integrationFixture();
    try {
        setup(f, true);
        const win = (i: number) => ({id: `w${i}`, weekdays: ['Sat' as const], start: '10:00', stop: '11:00'});
        f.store.transaction(() => replaceScheduleWindows(f.store, 'pilot', Array.from({length: MAX_WINDOWS_PER_CHILD}, (_, i) => win(i))));
        assert.equal(scheduleWindows(f.store).length, 8);
        const rejects = (windows: unknown[], re: RegExp) => assert.throws(() => f.store.transaction(() => replaceScheduleWindows(f.store, 'pilot', windows as never)), re);
        rejects(Array.from({length: 9}, (_, i) => win(i)), /schedule_window_limit/);
        rejects([{...win(1), start: '10:00', stop: '10:00'}], /./);
        rejects([{...win(1), weekdays: []}], /./);
        rejects([{...win(1), label: 'Bedtime'}], /./);
        rejects([win(1), win(1)], /./);
        assert.equal(scheduleWindows(f.store).length, 8); // failed replacements roll back
        assert.throws(() => f.store.run("INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES('pilot','extra','Mon','10:00','11:00')"), /schedule_window_limit/);
        assert.deepEqual(f.store.all<{name: string}>("SELECT name FROM pragma_table_info('schedule_windows')").map(c => c.name), ['person_id', 'id', 'weekdays', 'start', 'stop']);
    } finally { f.cleanup(); }
});

const queueWindows = (f: Fixture, windows: Omit<Schedule, 'person'>[], key = 'schedule_key_0123456', tweak: (p: ReturnType<typeof normalizePolicy>) => ReturnType<typeof normalizePolicy> = p => p) => f.store.transaction(() =>
    // S2 adds a dedicated action; the queue/stage mechanics are what S1 proves.
    f.policy.queue(actor, 'pilot', 'pause', JSON.stringify({permissionVersion: actor.permissionVersion}), key, f.policy.people(actor).revisionToken!, base => tweak(policyWithWindows(base, 'pilot', windows)), id => stageScheduleWindows(f.store, 'pilot', windows, id)));
const staged = (f: Fixture) => f.store.all<{operation_id: string}>('SELECT operation_id FROM schedule_staged');

test('flag on: staged windows are tied to the operation and the committed rows change only on confirmation', async () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        await f.observe();
        assert.throws(() => queueWindows(f, [night], 'schedule_key_0123456', p => ({...p, schedules: [{person: 'pilot', ...night, stop: '08:00'}]})), /owner_schedule_configuration_changed/);
        assert.deepEqual(staged(f), []); // validation failed after staging: the staged row rolled back
        const op = queueWindows(f, [night]);
        assert.deepEqual(scheduleWindows(f.store), []); // not the truth until the router confirms
        assert.deepEqual(staged(f).map(r => r.operation_id), [op.id]);
        assert.deepEqual(JSON.parse(op.payload_json).schedules, [{person: 'pilot', ...night}]);
        // Reconciliation admits exactly the base and the proposed schedules, nothing else.
        const base = normalizePolicy({...config.enrollment, revision: 1});
        validateManagedPolicy(base, config, f.store, false);
        validateManagedPolicy(normalizePolicy({...base, schedules: [{person: 'pilot', ...night}]}), config, f.store, false);
        assert.throws(() => validateManagedPolicy(normalizePolicy({...base, schedules: [{person: 'pilot', ...night, stop: '08:00'}]}), config, f.store, false), /owner_schedule_configuration_changed/);
    } finally { f.cleanup(); }
});

function automatic() {
    const f = integrationFixture();
    setup(f, true);
    f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
    return {...f, automatic: new AutomaticDispatch(f.worker)};
}

test('flag on: automatic dispatch observes, applies and settles the staged windows on confirmation', async () => {
    const f = automatic();
    try {
        await f.automatic.tick();
        const op = queueWindows(f, [night]);
        await f.automatic.tick(); // observes the unchanged router policy against the staged rows, then applies
        assert.equal(f.store.integrationState().observation_error, null);
        assert.equal(f.policy.operation(actor, op.id).state, 'confirmed', JSON.stringify(f.policy.operation(actor, op.id)) + f.store.integrationState().observation_error);
        assert.deepEqual(scheduleWindows(f.store), [{person: 'pilot', ...night}]);
        assert.deepEqual(staged(f), []);
        assert.deepEqual(f.router.policy.schedules, [{person: 'pilot', ...night}]);
    } finally { await f.automatic.stop(); f.cleanup(); }
});

/** Runs the next apply through `arm`, leaving observations untouched; returns a function that restores the router. */
function armApply(f: ReturnType<typeof automatic>, arm: () => void): () => void {
    const original = f.router.invoke.bind(f.router);
    f.router.invoke = async i => { if (i.kind === 'apply') arm(); return original(i); };
    return () => { f.router.failure = null; f.router.reject = null; f.router.invoke = original; };
}

for (const [name, arm] of [
    ['a router refusal before any write', (f: ReturnType<typeof automatic>) => { f.router.reject = 'rpc_scope_overlap'; }],
    ['a proven nondelivery', (f: ReturnType<typeof automatic>) => { f.router.failure = new RouterTransportError('test_spawn_failed', 'not_delivered'); }],
] as const) test(`flag on: ${name} discards the staged windows and unblocks later changes`, async () => {
    const f = automatic();
    try {
        await f.automatic.tick();
        const restore = armApply(f, () => arm(f));
        const op = queueWindows(f, [night]);
        await f.automatic.tick(); // observation passes against the staged rows; the apply then fails
        assert.equal(f.policy.operation(actor, op.id).state, 'failed');
        assert.deepEqual(scheduleWindows(f.store), []);
        assert.deepEqual(staged(f), []);
        assert.equal(f.store.integrationState().active_operation_id, null);
        restore();
        await f.automatic.tick();
        queueWindows(f, [night], 'schedule_key_retry_01'); // a later change is not blocked by stale rows
    } finally { await f.automatic.stop(); f.cleanup(); }
});

test('flag on: an unknown outcome keeps the staged windows pending', async () => {
    const f = automatic();
    try {
        await f.automatic.tick();
        armApply(f, () => { f.router.failure = new RouterTransportError('ssh_timeout'); });
        const op = queueWindows(f, [night]);
        await f.automatic.tick();
        assert.equal(f.policy.operation(actor, op.id).state, 'unknown');
        assert.deepEqual(scheduleWindows(f.store), []);
        assert.deepEqual(staged(f).map(r => r.operation_id), [op.id]);
    } finally { await f.automatic.stop(); f.cleanup(); }
});

test('flag on: the outbound policy must match the operation\'s own staged proposal, not just any acceptable set', async () => {
    const f = integrationFixture();
    try {
        setup(f, true);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        await f.observe();
        // Staged proposal differs from the payload (which keeps the old, committed set): refused, nothing staged.
        assert.throws(() => queueWindows(f, [night], 'schedule_key_0123456', p => ({...p, schedules: []})), /owner_schedule_configuration_changed/);
        assert.deepEqual(staged(f), []);
        // An operation that stages nothing must carry the committed set, not another operation's proposal.
        assert.throws(() => f.store.transaction(() => f.policy.queue(actor, 'pilot', 'pause', JSON.stringify({permissionVersion: actor.permissionVersion}), 'schedule_key_plain_01', f.policy.people(actor).revisionToken!,
            base => policyWithWindows(base, 'pilot', [night]))), /owner_schedule_configuration_changed/);
    } finally { f.cleanup(); }
});

test('flag on: a never-dispatched operation whose base went stale discards its staged windows even if the router happens to hold them', async () => {
    const f = automatic();
    try {
        await f.automatic.tick();
        const op = queueWindows(f, [night]);
        // Out-of-band router change that happens to equal the staged proposal, on a newer revision (stale base).
        f.router.policy = normalizePolicy({...f.router.policy, revision: f.router.policy.revision + 1, schedules: [{person: 'pilot', ...night}]});
        await f.automatic.tick();
        // After the settling tick the cached observation holds windows the committed rows do not own: no health claim and no revision token.
        const dto = f.policy.people(actor);
        assert.equal(dto.revisionToken, null);
        assert.notEqual(dto.people[0]!.observationHealth, 'healthy');
        await f.automatic.tick();
        assert.notEqual(f.policy.operation(actor, op.id).state, 'confirmed');
        assert.deepEqual(scheduleWindows(f.store), []);
        assert.deepEqual(staged(f), []);
    } finally { await f.automatic.stop(); f.cleanup(); }
});

test('flag on at construction seeds from the manifest; reopening does not seed again', () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true, [{person: 'pilot', ...night}]);
        // The fixture store was built before the flag; a second handle on the same file opens it flag-on.
        const reopened = new IntegrationStore(config);
        try {
            assert.deepEqual(scheduleWindows(reopened), [{person: 'pilot', ...night}]);
            reopened.transaction(() => replaceScheduleWindows(reopened, 'pilot', []));
        } finally { reopened.close(); }
        const again = new IntegrationStore(config);
        try { assert.deepEqual(scheduleWindows(again), []); } finally { again.close(); }
    } finally { f.cleanup(); }
});

test('flag on: historical receipt recovery matches the held windows regardless of input order', async () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true);
        await f.observe();
        const zed = {...night, id: 'zed'}, alpha = {...night, id: 'alpha', start: '13:00', stop: '14:00'};
        const op = queueWindows(f, [zed, alpha]); // proposal in input order [zed, alpha]
        f.store.run("UPDATE operation_rpc SET delivery='accepted',receipt_json='{}',attempt_count=1 WHERE operation_id=?", op.id);
        const held = normalizePolicy({...config.enrollment, revision: 1, schedules: [alpha, zed].map(w => ({person: 'pilot', ...w}))}); // the router reports sorted by id
        assert.deepEqual(held.schedules.map(s => s.id), ['alpha', 'zed']);
        f.store.transaction(() => settleScheduleWindows(f.store, op.id, 'conflict', held));
        assert.deepEqual(scheduleWindows(f.store).map(s => s.id), ['alpha', 'zed']);
        assert.deepEqual(staged(f), []);
    } finally { f.cleanup(); }
});

test('flag on: with no router observation of the child, people() shows the committed windows, not the manifest, and enforcement stays unknown', () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true, [{person: 'pilot', id: 'manifest', weekdays: ['Sat'], start: '10:00', stop: '11:00'}]);
        f.store.transaction(() => replaceScheduleWindows(f.store, 'pilot', [night]));
        const child = f.policy.people(actor).people[0]!;
        assert.match(child.scheduleExplanation, /night/);
        assert.doesNotMatch(child.scheduleExplanation, /manifest/);
        assert.equal(child.scheduleBlocked, null);
        f.store.transaction(() => replaceScheduleWindows(f.store, 'pilot', []));
        assert.equal(f.policy.people(actor).people[0]!.scheduleExplanation, 'No owner-configured schedule.');
        assert.ok(config);
    } finally { f.cleanup(); }
});

test('migration integration-009: weekday and clock CHECKs and the owner-update cap hold under direct SQL', () => {
    const f = integrationFixture();
    try {
        setup(f, true);
        const ins = (id: string, days: string, start: string, stop: string, person = 'pilot') => f.store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', person, id, days, start, stop);
        for (const days of ['Foo', 'MonTue', 'Mon,,Tue', ',Mon,Tue', 'Mon,Tue,', 'Mo,nMon', 'mon']) assert.throws(() => ins('bad', days, '10:00', '11:00'), /CHECK/, days);
        for (const t of ['24:00', '29:59', '10:60']) { assert.throws(() => ins('bad', 'Mon', t, '11:00'), /CHECK/, t); assert.throws(() => ins('bad', 'Mon', '10:00', t), /CHECK/, t); }
        ins('ok1', 'Mon,Tue,Wed,Thu,Fri,Sat,Sun', '00:00', '23:59');
        // A ninth window cannot arrive by moving a row between owners.
        f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES('other','Other','child',1,0)");
        for (let i = 0; i < 8; i++) ins(`w${i}`, 'Mon', '10:00', '11:00', 'other');
        assert.throws(() => f.store.run("UPDATE schedule_windows SET person_id='other' WHERE person_id='pilot' AND id='ok1'"), /schedule_window_limit/);
    } finally { f.cleanup(); }
});
