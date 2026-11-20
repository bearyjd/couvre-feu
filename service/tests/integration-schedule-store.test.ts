import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor, observation } from './fixtures/integration.ts';
import { validateManagedPolicy, withDevice } from '../src/integration-children.ts';
import { MAX_WINDOWS_PER_CHILD, policyWithWindows, scheduleWindows, seedScheduleWindows, stageScheduleWindows } from '../src/integration-schedule-store.ts';
import { IntegrationStore } from '../src/integration-db.ts';
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
        f.store.transaction(() => stageScheduleWindows(f.store, 'pilot', [{id: 'other', weekdays: ['Sat'], start: '10:00', stop: '11:00'}]));
        assert.deepEqual(withDevice(accepted, config, 'pilot', '02:10:20:30:40:52', f.store).schedules, [{person: 'pilot', ...night}]);
    } finally { f.cleanup(); }
});

test('flag on: manifest schedules seed the table exactly once; the database then wins', () => {
    const f = integrationFixture();
    try {
        const config = setup(f, true, [{person: 'pilot', ...night}]);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        assert.deepEqual(scheduleWindows(f.store), [{person: 'pilot', ...night}]);
        f.store.transaction(() => stageScheduleWindows(f.store, 'pilot', []));
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
        f.store.transaction(() => stageScheduleWindows(f.store, 'pilot', Array.from({length: MAX_WINDOWS_PER_CHILD}, (_, i) => win(i))));
        assert.equal(scheduleWindows(f.store).length, 8);
        const rejects = (windows: unknown[], re: RegExp) => assert.throws(() => f.store.transaction(() => stageScheduleWindows(f.store, 'pilot', windows as never)), re);
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

test('flag on: the window rows and the queued policy commit together or not at all', async () => {
    const f = integrationFixture();
    try {
        setup(f, true);
        f.store.transaction(() => seedScheduleWindows(f.store, f.config));
        await f.observe();
        const token = f.policy.people(actor).revisionToken!;
        const attempt = (windows: Omit<Schedule, 'person'>[], tweak: (p: ReturnType<typeof normalizePolicy>) => ReturnType<typeof normalizePolicy> = p => p) => f.store.transaction(() =>
            // S2 adds a dedicated action; the queue/stage mechanics are what S1 proves.
            f.policy.queue(actor, 'pilot', 'pause', '{}', 'schedule_key_0123456', token, base => tweak(policyWithWindows(base, 'pilot', windows)), () => stageScheduleWindows(f.store, 'pilot', windows)));
        assert.throws(() => attempt([night], p => ({...p, schedules: []})), /owner_schedule_configuration_changed/);
        assert.deepEqual(scheduleWindows(f.store), []); // validation failed after staging: rows rolled back
        const op = attempt([night]);
        assert.deepEqual(scheduleWindows(f.store), [{person: 'pilot', ...night}]);
        assert.deepEqual(JSON.parse(op.payload_json).schedules, [{person: 'pilot', ...night}]);
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
            reopened.transaction(() => stageScheduleWindows(reopened, 'pilot', []));
        } finally { reopened.close(); }
        const again = new IntegrationStore(config);
        try { assert.deepEqual(scheduleWindows(again), []); } finally { again.close(); }
    } finally { f.cleanup(); }
});
