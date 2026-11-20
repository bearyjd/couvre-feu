import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor, storeDump, TestRouter } from './fixtures/integration.ts';
import type { FixtureOptions } from './fixtures/integration.ts';
import { validateManagedPolicy, withDevice } from '../src/integration-children.ts';
import { canonicalSchedules, scheduleWindows, seedScheduleWindows } from '../src/integration-schedule-store.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { IntegrationPolicy } from '../src/integration-policy.ts';
import { IntegrationWorker } from '../src/integration-worker.ts';
import { rebindIntegration } from '../src/integration-rebind.ts';
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
/** Committed rows written directly: S1 has no edit path, so only the seed (or SQL in tests) changes them. */
const commit = (f: Fixture, person: string, windows: Omit<Schedule, 'person'>[]) => f.store.transaction(() => {
    f.store.run('DELETE FROM schedule_windows WHERE person_id=?', person);
    for (const w of windows) f.store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', person, w.id, w.weekdays.join(','), w.start, w.stop);
});
const nextManifest = (config: Fixture['config'], change: object) => ({...config, router: {...config.router, generation: 'e'.repeat(64)}, manifestDigest: 'f'.repeat(64), targetDigest: '9'.repeat(64), ...change});
const digest = (f: Fixture) => f.store.get<{manifest_digest: string}>('SELECT manifest_digest FROM integration_state')!.manifest_digest;

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
        commit(f, 'pilot', [{id: 'other', weekdays: ['Sat'], start: '10:00', stop: '11:00'}]);
        validateManagedPolicy(accepted, config, f.store, false);
        assert.deepEqual(withDevice(accepted, config, 'pilot', '02:10:20:30:40:52', f.store).schedules, [{person: 'pilot', ...night}]);
    } finally { f.cleanup(); }
});

test('flag on: manifest schedules seed the table exactly once; the database then wins', () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true, [{person: 'pilot', ...night}]);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        assert.deepEqual(scheduleWindows(f.store), [{person: 'pilot', ...night}]);
        commit(f, 'pilot', []);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config)); // never re-seeds, even after the set was emptied
        assert.deepEqual(scheduleWindows(f.store), []);
        const accepted = normalizePolicy({...config.enrollment, revision: 1, schedules: []});
        validateManagedPolicy(accepted, config, f.store, false);
        const withManifestWindow = normalizePolicy({...accepted, schedules: [{person: 'pilot', ...night}]});
        assert.throws(() => validateManagedPolicy(withManifestWindow, config, f.store, false), /owner_schedule_configuration_changed/);
        // The builders read the same committed rows.
        assert.deepEqual(withDevice(accepted, config, 'pilot', '02:10:20:30:40:52', f.store).schedules, []);
    } finally { f.cleanup(); }
});

test('flag on at construction seeds from the manifest; reopening does not seed again', () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true, [{person: 'pilot', ...night}]);
        // The fixture store was built before the flag; a second handle on the same file opens it flag-on.
        const reopened = new IntegrationStore(config);
        try {
            assert.deepEqual(scheduleWindows(reopened), [{person: 'pilot', ...night}]);
            reopened.run('DELETE FROM schedule_windows');
        } finally { reopened.close(); }
        const again = new IntegrationStore(config);
        try { assert.deepEqual(scheduleWindows(again), []); } finally { again.close(); }
    } finally { f.cleanup(); }
});

test('canonical comparison ignores order and never normalizes', () => {
    const a = {person: 'pilot', ...night}, b = {person: 'pilot', id: 'alpha', weekdays: ['Sun', 'Sat'] as Schedule['weekdays'], start: '13:00', stop: '14:00'};
    assert.equal(canonicalSchedules([a, b]), canonicalSchedules([b, {...a, weekdays: ['Tue', 'Mon']}]));
    assert.notEqual(canonicalSchedules([a]), canonicalSchedules([a, b]));
    assert.notEqual(canonicalSchedules([a]), canonicalSchedules([{...a, stop: '07:01'}]));
});

test('T3 flag on: ownership of a 32-device child with cross-midnight windows is owner_schedule_configuration_changed, never expanded_schedule_limit', () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true);
        const macs = Array.from({length: 32}, (_, i) => `02:10:20:30:41:${i.toString(16).padStart(2, '0')}`);
        for (const [i, mac] of macs.entries()) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',0)", `d_t3_${i}`, 'pilot', `Device ${i}`, mac);
        const cross = (i: number) => ({id: `w${i}`, weekdays: ['Mon' as const], start: '22:00', stop: '06:00'});
        // Committed: 8 cross-midnight windows (32 x 8 x 2 = 512 expanded, over the router's 256). The router holds a legal 4 (= 256).
        commit(f, 'pilot', Array.from({length: 8}, (_, i) => cross(7 - i)));
        const held = normalizePolicy({version: 1, revision: 1, people: [{id: 'pilot', macs}], pauses: [], schedules: Array.from({length: 4}, (_, i) => ({person: 'pilot', ...cross(i)}))});
        for (const policy of [held, normalizePolicy({...held, schedules: []})]) {
            assert.throws(() => validateManagedPolicy(policy, config, f.store, false), (e: {code?: string}) => e.code === 'owner_schedule_configuration_changed');
        }
        // Equal sets, stored in a different order, are owned.
        commit(f, 'pilot', [3, 1, 2, 0].map(cross));
        validateManagedPolicy(held, config, f.store, false);
    } finally { f.cleanup(); }
});

test('T2: a reply with an exact receipt plus a foreign device behaves the same with the flag on as off', async () => {
    const run = async (options: FixtureOptions) => {
        let dump = '';
        const f = integrationFixture({...options, beforeClose: s => { dump = storeDump(s); }});
        try {
            await f.observe();
            const id = f.pause(f.now() + 60).result.operation.id, plan = f.worker.prepare('apply', id);
            f.router.afterApply = () => { f.router.policy = normalizePolicy({...f.router.policy, people: f.router.policy.people.map(p => ({...p, macs: [...p.macs, '02:10:20:30:40:5a']}))}); };
            await f.worker.execute(plan, plan.scriptSha256);
            const op = f.policy.operation(actor, id), state = f.store.integrationState();
            const result = {state: op.state, error: op.error, observationError: state.observation_error, active: state.active_operation_id === id, token: f.policy.people(actor).revisionToken};
            f.cleanup();
            return {result, dump};
        } catch (error) { f.cleanup(); throw error; }
    };
    const off = await run({}), on = await run({schedules: {editable: true}});
    assert.deepEqual(on.result, off.result);
    assert.equal(off.result.observationError, 'router_policy_foreign');
    assert.equal(off.result.token, null);
    assert.equal(on.dump, off.dump);
});

test('flag-off parity: a router schedule nobody owns is rejected the same way with the flag absent, false or true', async () => {
    const results = [];
    for (const options of [{}, {schedules: {editable: false}}, {schedules: {editable: true}}] satisfies FixtureOptions[]) {
        const f = integrationFixture(options);
        try {
            (f.config as {scheduleClock?: unknown}).scheduleClock = {timezone: 'UTC'};
            await f.observe();
            const before = f.policy.people(actor).lastSuccessfulConfirmationAt;
            f.router.policy = normalizePolicy({...f.router.policy, revision: f.router.policy.revision + 1, schedules: [{person: 'pilot', ...night}]});
            f.advance(5);
            await f.observe();
            const dto = f.policy.people(actor);
            assert.equal(dto.lastSuccessfulConfirmationAt, before);
            results.push({error: f.store.integrationState().observation_error, token: dto.revisionToken, health: dto.people[0]!.observationHealth, revision: f.store.observation().value?.acceptedPolicy.revision});
        } finally { f.cleanup(); }
    }
    assert.deepEqual(results[1], results[0]);
    assert.deepEqual(results[2], results[0]);
    assert.equal(results[0]!.error, 'router_observation_invalid');
    assert.equal(results[0]!.token, null);
    assert.equal(results[0]!.revision, 0); // the unowned reply was never stored
});

test('T6 flag on: a child the router does not hold shows the committed windows, not the manifest, with enforcement unknown', async () => {
    const f = integrationFixture();
    try {
        setup(f, true, [{person: 'pilot', id: 'manifest', weekdays: ['Sat'], start: '10:00', stop: '11:00'}]);
        commit(f, 'pilot', [night]);
        // No observation at all.
        let child = f.policy.people(actor).people[0]!;
        assert.match(child.scheduleExplanation, /night/);
        assert.doesNotMatch(child.scheduleExplanation, /manifest/);
        assert.equal(child.scheduleBlocked, null);
        // The router no longer holds the child (its last device left with its schedules); the database still owns the windows.
        f.store.run("DELETE FROM devices WHERE person_id='pilot'");
        f.router.policy = normalizePolicy({version: 1, revision: 2, people: [], pauses: [], schedules: []});
        await f.observe();
        assert.equal(f.store.integrationState().observation_error, null);
        // Even with a reviewed clock and a healthy observation, windows the router does not hold are never reported as enforced.
        (f.config as {scheduleClock?: unknown}).scheduleClock = {timezone: 'UTC', conformance: {utcOffsetMinutes: 0, verifiedAt: 0, validUntil: f.now() + 86400, evidenceSha256: 'a'.repeat(64)}};
        child = f.policy.people(actor).people[0]!;
        assert.match(child.scheduleExplanation, /night/);
        assert.equal(child.scheduleBlocked, null);
        commit(f, 'pilot', []);
        assert.equal(f.policy.people(actor).people[0]!.scheduleExplanation, 'No owner-configured schedule.');
    } finally { f.cleanup(); }
});

test('T6 flag on: a child the router holds without its committed windows shows the committed windows with enforcement unknown', async () => {
    const f = integrationFixture();
    try {
        setup(f, true);
        await f.observe(); // owned: no rows, no router windows
        assert.ok(f.policy.people(actor).revisionToken);
        commit(f, 'pilot', [night]);
        f.advance(1);
        await f.observe(); // the router dropped (never had) the windows: unowned, so not stored and unhealthy
        assert.equal(f.store.integrationState().observation_error, 'router_observation_invalid');
        assert.ok(f.store.observation().value!.acceptedPolicy.people.some(p => p.id === 'pilot'));
        const dto = f.policy.people(actor), child = dto.people[0]!;
        assert.match(child.scheduleExplanation, /night/);
        assert.match(child.scheduleExplanation, /unknown/);
        assert.equal(child.scheduleBlocked, null);
        assert.notEqual(child.observationHealth, 'healthy');
        assert.equal(dto.revisionToken, null);
    } finally { f.cleanup(); }
});

test('rebind on->on: refuses to drop scheduleClock while the database owns schedule windows', async () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        await f.observe(); f.store.stopDispatch(f.now());
        const run = (n: ReturnType<typeof nextManifest>) => rebindIntegration(f.store, n, config.manifestDigest, n.manifestDigest, f.now());
        commit(f, 'pilot', [night]);
        assert.throws(() => run(nextManifest(config, {scheduleClock: undefined})), /rebind_schedule_clock_required/);
        assert.equal(digest(f), config.manifestDigest);
        run(nextManifest(config, {})); // the next manifest keeps the clock
        assert.equal(digest(f), 'f'.repeat(64));
        assert.deepEqual(scheduleWindows(f.store), [{person: 'pilot', ...night}]); // on->on keeps the committed rows
    } finally { f.cleanup(); }
});

test('rebind on->on: with no committed windows a manifest without scheduleClock is accepted', async () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        await f.observe(); f.store.stopDispatch(f.now());
        const n = nextManifest(config, {scheduleClock: undefined});
        rebindIntegration(f.store, n, config.manifestDigest, n.manifestDigest, f.now());
    } finally { f.cleanup(); }
});

test('T4 rebind on->off: refused while the committed rows diverge from the next manifest; accepted when equal, and the next observation is healthy', async () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true, [{person: 'pilot', ...night}]);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        f.router.policy = config.enrollment;
        await f.observe();
        assert.equal(f.store.integrationState().observation_error, null);
        f.store.stopDispatch(f.now());
        const run = (n: ReturnType<typeof nextManifest>) => rebindIntegration(f.store, n, config.manifestDigest, n.manifestDigest, f.now());
        const off = (schedules: Schedule[]) => nextManifest(config, {schedules: {editable: false}, enrollment: normalizePolicy({...config.enrollment, schedules})});
        assert.throws(() => run(off([])), /rebind_schedules_diverge/);
        assert.throws(() => run(off([{person: 'pilot', ...night, stop: '07:30'}])), /rebind_schedules_diverge/);
        assert.equal(digest(f), config.manifestDigest);
        const next = off([{person: 'pilot', ...night}]);
        run(next);
        assert.equal(digest(f), 'f'.repeat(64));
        // Reopen with the next manifest (flag off): the manifest owns the windows again and the router's matching policy is healthy.
        const store = new IntegrationStore(next);
        try {
            const router = new TestRouter(store, f.now), worker = new IntegrationWorker(store, router, f.now), policy = new IntegrationPolicy(store, f.now);
            router.policy = next.enrollment;
            const plan = worker.prepare('observe'); await worker.execute(plan, plan.scriptSha256);
            assert.equal(store.integrationState().observation_error, null);
            assert.equal(policy.people(actor).people[0]!.observationHealth, 'healthy');
        } finally { store.close(); }
    } finally { f.cleanup(); }
});

test('T5 rebind off->on: a stale seed marker and stale rows are forgotten so the next open seeds from the next manifest', async () => {
    const f = integrationFixture();
    try {
        const config = setup(f, false);
        // Left from an earlier flag-on period.
        commit(f, 'pilot', [{id: 'stale', weekdays: ['Sat'], start: '10:00', stop: '11:00'}]);
        f.store.run('INSERT INTO schedule_seed(singleton) VALUES(1)');
        await f.observe(); f.store.stopDispatch(f.now());
        const next = nextManifest(config, {schedules: {editable: true}, enrollment: normalizePolicy({...config.enrollment, schedules: [{person: 'pilot', ...night}]})});
        rebindIntegration(f.store, next, config.manifestDigest, next.manifestDigest, f.now());
        assert.deepEqual(scheduleWindows(f.store), []);
        assert.equal(f.store.get('SELECT 1 FROM schedule_seed'), undefined);
        const store = new IntegrationStore(next);
        try { assert.deepEqual(scheduleWindows(store), [{person: 'pilot', ...night}]); } finally { store.close(); }
    } finally { f.cleanup(); }
});

test('rebind off->off: the schedule tables are not touched', async () => {
    const f = integrationFixture();
    try {
        const config = setup(f, false);
        commit(f, 'pilot', [night]);
        await f.observe(); f.store.stopDispatch(f.now());
        const next = nextManifest(config, {scheduleClock: undefined});
        rebindIntegration(f.store, next, config.manifestDigest, next.manifestDigest, f.now());
        assert.deepEqual(scheduleWindows(f.store), [{person: 'pilot', ...night}]);
    } finally { f.cleanup(); }
});

test('migration integration-009: weekday and clock CHECKs, the 8-window cap and the owner-update cap hold under direct SQL', () => {
    const f = integrationFixture();
    try {
        setup(f, true);
        const ins = (id: string, days: string, start: string, stop: string, person = 'pilot') => f.store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', person, id, days, start, stop);
        for (const days of ['Foo', 'MonTue', 'Mon,,Tue', ',Mon,Tue', 'Mon,Tue,', 'Mo,nMon', 'mon']) assert.throws(() => ins('bad', days, '10:00', '11:00'), /CHECK/, days);
        for (const t of ['24:00', '29:59', '10:60']) { assert.throws(() => ins('bad', 'Mon', t, '11:00'), /CHECK/, t); assert.throws(() => ins('bad', 'Mon', '10:00', t), /CHECK/, t); }
        for (const days of ['Mon,Mon', 'Tue,Mon,Tue', 'Sun,Sat,Sun,Sat']) assert.throws(() => ins('bad', days, '10:00', '11:00'), /CHECK/, days);
        assert.throws(() => ins('bad', 'Mon', '10:00', '10:00'), /CHECK/);
        // An embedded NUL hides a suffix from SQLite's text functions: refused in every column.
        assert.throws(() => ins('bad\0x', 'Mon', '10:00', '11:00'), /CHECK/);
        assert.throws(() => ins('bad', 'Mon\0x', '10:00', '11:00'), /CHECK/);
        assert.throws(() => ins('bad', 'Mon', '10:00\0x', '11:00'), /CHECK/);
        assert.throws(() => ins('bad', 'Mon', '10:00', '11:00\0x'), /CHECK/);
        ins('ok1', 'Mon,Tue,Wed,Thu,Fri,Sat,Sun', '00:00', '23:59');
        // A ninth window cannot arrive by insert or by moving a row between owners.
        f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES('other','Other','child',1,0)");
        for (let i = 0; i < 8; i++) ins(`w${i}`, 'Mon', '10:00', '11:00', 'other');
        assert.throws(() => ins('w8', 'Mon', '10:00', '11:00', 'other'), /schedule_window_limit/);
        assert.throws(() => f.store.run("UPDATE schedule_windows SET person_id='other' WHERE person_id='pilot' AND id='ok1'"), /schedule_window_limit/);
        assert.deepEqual(f.store.all<{name: string}>("SELECT name FROM pragma_table_info('schedule_windows')").map(c => c.name), ['person_id', 'id', 'weekdays', 'start', 'stop']);
        assert.equal(f.store.get("SELECT 1 FROM sqlite_master WHERE name='schedule_staged'"), undefined); // S1 has no staging table
    } finally { f.cleanup(); }
});
