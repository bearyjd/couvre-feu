import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { normalizeScheduleClock, validatePilotPolicy } from '../src/integration-config.ts';
import { integrationScheduleState } from '../src/integration-schedules.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { IntegrationPolicy } from '../src/integration-policy.ts';
import { IntegrationWorker } from '../src/integration-worker.ts';
import { testConfig, actor, TestRouter } from './fixtures/integration.ts';

const epoch = (date: string) => Date.parse(date) / 1000;
function configured(dir = '/tmp/unused') {
    const config = testConfig(dir);
    config.enrollment = normalizePolicy({...config.enrollment, schedules: [
        {person: 'pilot', id: 'bedtime', weekdays: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'], start: '21:00', stop: '07:00'},
        {person: 'pilot', id: 'weekend', weekdays: ['Sat', 'Sun'], start: '22:00', stop: '08:00'}]});
    config.scheduleClock = {timezone: 'America/New_York', conformance: {utcOffsetMinutes: -240,
        verifiedAt: epoch('2026-10-12T00:00:00Z'), validUntil: epoch('2026-10-19T00:00:00Z'), evidenceSha256: 'e'.repeat(64)}};
    return config;
}
test('owner schedules require declared timezone, a bounded exact clock record, and immutable windows', () => {
    const c = configured();
    validatePilotPolicy(c.enrollment, c, false);
    assert.deepEqual(normalizeScheduleClock(c.scheduleClock), c.scheduleClock);
    for (const timezone of ['Not/AZone', 'US/Eastern', '', 'America/New_York;reboot']) assert.throws(() => normalizeScheduleClock({timezone}));
    const r = c.scheduleClock!.conformance!;
    for (const conformance of [{...r, validUntil: r.verifiedAt}, {...r, validUntil: r.validUntil + 1}, {...r, utcOffsetMinutes: -240.5}, {...r, utcOffsetMinutes: 841}, {...r, evidenceSha256: 'bad'}, {...r, approved: true}]) assert.throws(() => normalizeScheduleClock({timezone: 'UTC', conformance}));
    assert.throws(() => validatePilotPolicy(c.enrollment, {...c, scheduleClock: undefined}), /owner_schedule_clock_required/);
    assert.throws(() => validatePilotPolicy({...c.enrollment, schedules: []}, c), /owner_schedule_configuration_changed/);
    assert.throws(() => validatePilotPolicy({...c.enrollment, schedules: [{...c.enrollment.schedules[0], start: '20:00'}]}, c), /owner_schedule_configuration_changed/);
    const large = {...c.enrollment, schedules: Array.from({length: 9}, (_, i) => ({...c.enrollment.schedules[0], id: `bed_${i}`}))};
    assert.throws(() => validatePilotPolicy(large, {...c, enrollment: large}), /owner_schedule_limit/);
});
test('conformance rejects offset transitions, including the last second, and admits a transition at the exclusive end', () => {
    const c = configured(), transition = epoch('2026-11-01T06:00:00Z'), record = c.scheduleClock!.conformance!;
    const clock = (verifiedAt: number, validUntil: number) => ({timezone: 'America/New_York', conformance: {...record, verifiedAt, validUntil}});
    assert.throws(() => normalizeScheduleClock(clock(epoch('2026-10-31T00:00:00Z'), epoch('2026-11-03T00:00:00Z'))), /schedule_conformance_offset_changed/);
    assert.throws(() => normalizeScheduleClock(clock(transition - 3601, transition + 1)), /schedule_conformance_offset_changed/);
    assert.throws(() => normalizeScheduleClock(clock(transition - 1, transition + 1)), /schedule_conformance_offset_changed/);
    assert.equal(normalizeScheduleClock(clock(transition - 3601, transition)).conformance?.validUntil, transition);
    assert.throws(() => normalizeScheduleClock({...clock(transition, transition + 3600), conformance: {...record, verifiedAt: transition, validUntil: transition + 3600}}), /schedule_conformance_offset_changed/);
});
test('router epoch uses declared local weekdays, exact start/end, previous day and multiple windows', () => {
    const c = configured();
    const state = (date: string) => integrationScheduleState(c.enrollment, c, epoch(date), true).scheduleBlocked;
    assert.equal(state('2026-10-13T00:59:59Z'), false); // Monday 20:59 EDT
    assert.equal(state('2026-10-13T01:00:00Z'), true);
    assert.equal(state('2026-10-13T10:59:59Z'), true); // Tuesday uses Monday's start
    assert.equal(state('2026-10-13T11:00:00Z'), false);
    const observed = epoch('2026-10-13T01:00:00Z');
    const expiring = integrationScheduleState(c.enrollment, c, observed, true, observed + 30);
    assert.equal(expiring.scheduleValidUntil, observed + 31); assert.equal(expiring.scheduleCheckedAt, observed + 30);
    assert.equal(integrationScheduleState(c.enrollment, c, observed, true, observed + 31).scheduleBlocked, null);
    assert.equal(state('2026-10-18T01:30:00Z'), false); // Saturday 21:30
    assert.equal(state('2026-10-18T02:00:00Z'), true);
    assert.equal(state('2026-10-18T11:59:59Z'), true);
    assert.equal(state('2026-10-18T12:00:00Z'), false);
    const sameDay = normalizePolicy({...c.enrollment, schedules: [{...c.enrollment.schedules[0], start: '18:00', stop: '19:00'}]});
    assert.equal(integrationScheduleState(sameDay, c, epoch('2026-10-12T21:59:59Z'), true).scheduleBlocked, false);
    assert.equal(integrationScheduleState(sameDay, c, epoch('2026-10-12T22:00:00Z'), true).scheduleBlocked, true);
    assert.equal(integrationScheduleState(sameDay, c, epoch('2026-10-12T23:00:00Z'), true).scheduleBlocked, false);
    const midnight = normalizePolicy({...c.enrollment, schedules: [{...c.enrollment.schedules[0], stop: '00:00'}]});
    assert.equal(integrationScheduleState(midnight, c, epoch('2026-10-13T03:59:59Z'), true).scheduleBlocked, true);
    assert.equal(integrationScheduleState(midnight, c, epoch('2026-10-13T04:00:00Z'), true).scheduleBlocked, false);
});
test('missing, future, expired, mismatched, unhealthy and DST-transition clocks are explicitly unknown', () => {
    const c = configured(), time = epoch('2026-10-13T01:00:00Z');
    assert.equal(integrationScheduleState(c.enrollment, c, null, false).scheduleBlocked, null);
    assert.equal(integrationScheduleState(c.enrollment, c, time, false).scheduleBlocked, null);
    const noRecord = {...c, scheduleClock: {timezone: c.scheduleClock!.timezone}};
    assert.equal(integrationScheduleState(c.enrollment, noRecord, time, true).scheduleBlocked, null);
    for (const now of [c.scheduleClock!.conformance!.verifiedAt - 1, c.scheduleClock!.conformance!.validUntil]) assert.equal(integrationScheduleState(c.enrollment, c, now, true).scheduleBlocked, null);
    assert.equal(integrationScheduleState(c.enrollment, c, c.scheduleClock!.conformance!.validUntil - 1, true, c.scheduleClock!.conformance!.validUntil).scheduleBlocked, null);
    const mismatch = {...c, scheduleClock: {...c.scheduleClock!, conformance: {...c.scheduleClock!.conformance!, utcOffsetMinutes: -300}}};
    assert.equal(integrationScheduleState(c.enrollment, mismatch, time, true).scheduleBlocked, null);
    const dst = {...c, scheduleClock: {...c.scheduleClock!, conformance: {...c.scheduleClock!.conformance!, verifiedAt: epoch('2026-10-31T00:00:00Z'), validUntil: epoch('2026-11-03T00:00:00Z')}}};
    assert.equal(integrationScheduleState(c.enrollment, dst, epoch('2026-11-01T05:30:00Z'), true).scheduleBlocked, true);
    const after = integrationScheduleState(c.enrollment, dst, epoch('2026-11-01T06:30:00Z'), true);
    assert.equal(after.scheduleBlocked, null); assert.match(after.scheduleExplanation, /DST support is unverified/);
    const boundaryPolicy = normalizePolicy({...c.enrollment, schedules: [{person: 'pilot', id: 'boundary', weekdays: ['Sun'], start: '02:00', stop: '03:00'}]});
    // Even a one-second-old pre-transition observation cannot support a claim now.
    const boundary = integrationScheduleState(boundaryPolicy, dst, epoch('2026-11-01T05:59:59Z'), true, epoch('2026-11-01T06:00:00Z'));
    assert.equal(boundary.scheduleBlocked, null); assert.equal(boundary.scheduleValidUntil, null);
    assert.match(boundary.scheduleExplanation, /DST support is unverified/);
});
test('resume during bedtime and fixed pause expiry preserve schedules; expired calibration leaves safe controls available', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-schedules-')), config = configured(dir), store = new IntegrationStore(config);
    let time = epoch('2026-10-13T01:00:00Z');
    const now = () => time, policy = new IntegrationPolicy(store, now), router = new TestRouter(store, now), worker = new IntegrationWorker(store, router, now);
    const execute = async (kind: 'observe' | 'apply', id?: string) => {const plan = worker.prepare(kind, id); await worker.execute(plan, plan.scriptSha256);};
    const mutate = (action: 'pause' | 'resume', body: unknown, key: string) => policy.mutate(actor, 'pilot', action, body, policy.people(actor).revisionToken!, key).result.operation.id;
    try {
        assert.equal(policy.people(actor).people[0].scheduleBlocked, null); // configured but not observed
        await execute('observe'); assert.equal(policy.people(actor).people[0].scheduleBlocked, true);
        const until = time + 60, paused = mutate('pause', {until}, 'schedules_pause_key'); await execute('apply', paused);
        time += 61; await execute('observe');
        let person = policy.people(actor).people[0];
        assert.equal(person.effectiveManualPause, null); assert.equal(person.manualPause?.until, until); assert.equal(person.scheduleBlocked, true);
        const resumed = mutate('resume', {}, 'schedules_resume_key'); await execute('apply', resumed);
        person = policy.people(actor).people[0];
        assert.equal(person.manualPause, null); assert.equal(person.scheduleBlocked, true);
        assert.deepEqual(policy.envelope(resumed).policy.schedules, config.enrollment.schedules);
        time = config.scheduleClock!.conformance!.validUntil - 1; await execute('observe');
        assert.equal(policy.people(actor).people[0].scheduleValidUntil, time + 1);
        assert.equal(policy.people(actor).people[0].scheduleWitness, 'owner-reviewed-clock');
        time += 1; // No fresh router read; its one-second-old observation stays healthy.
        assert.equal(policy.people(actor).people[0].scheduleBlocked, null); assert.ok(policy.people(actor).revisionToken);
        const newPause = mutate('pause', {until: time + 60}, 'expired_clock_pause'); await execute('apply', newPause);
        assert.equal(policy.operation(actor, newPause).currentHealthy, true);
        assert.equal(policy.people(actor).people[0].scheduleBlocked, null);
        time += 31;
        assert.equal(policy.people(actor).revisionToken, null);
        assert.throws(() => policy.mutate(actor, 'pilot', 'resume', {}, '"s0-r0-' + 'a'.repeat(64) + '"', 'stale_clock_resume'), /approved_router_observation_required/);
        router.transform = o => ({...o, status: {...o.status, capabilities: {...o.status.capabilities, nativeKernelConfirmed: false}}});
        await execute('observe'); assert.equal(policy.people(actor).people[0].scheduleBlocked, null); assert.equal(policy.people(actor).revisionToken, null);
    } finally {store.close(); rmSync(dir, {recursive: true, force: true});}
});
