import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { TimeRequestService } from '../src/time-requests.ts';
import { IntegrationGrants, MAX_GRANT_MINUTES } from '../src/integration-allowance.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { AppError } from '../../shared/src/errors.ts';

const ALL_DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] as const;
interface Row {id: string; state: string; allowance_until: number | null; granted_minutes: number | null; decision_code: string | null; grant_operation_id: string | null; repause_state: string}

/** A real IntegrationPolicy + fake router, with the router-side allowance port wired as the real path does. */
async function world(over: Partial<RouterPolicy> = {}) {
    const f = integrationFixture();
    const now = f.now();
    // Owner-reviewed clock in UTC so the integration schedule claim is evaluable; the fixture clock is 00:00 UTC.
    f.config.scheduleClock = {timezone: 'UTC', conformance: {utcOffsetMinutes: 0, verifiedAt: now - 3600, validUntil: now + 3 * 86400, evidenceSha256: 'e'.repeat(64)}};
    // Schedules on the router must be the manifest-owned ones (validateManagedPolicy).
    if (over.schedules) f.config.enrollment = normalizePolicy({...f.config.enrollment, schedules: over.schedules});
    f.router.policy = normalizePolicy({...f.config.enrollment, revision: 1, ...over}, f.config.protectedMacs);
    await f.observe();
    const grants = new IntegrationGrants(f.policy);
    const service = new TimeRequestService(f.store, f.policy, f.now, undefined, grants);
    const dispatch = async (id: string) => { const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256); };
    const link = await service.issueLink(actor, 'pilot');
    const ask = (minutes = 30) => { service.submit(link.token, minutes, 'homework', 'client-a'); return f.store.get<Row>("SELECT * FROM time_requests WHERE state='pending'")!.id; };
    const row = (id: string) => f.store.get<Row>('SELECT * FROM time_requests WHERE id=?', id)!;
    return {f, grants, service, dispatch, link, ask, row};
}
const bedtime = {schedules: [{person: 'pilot', id: 'bed', weekdays: [...ALL_DAYS], start: '00:00', stop: '23:59'}]};

test('approving while a schedule blocks writes a router allowance instead of ending unsupported', async () => {
    const w = await world(bedtime);
    try {
        const routerTime = w.f.store.observation().value!.routerTime;
        assert.equal(w.f.policy.people(actor).people[0].scheduleBlocked, true, 'precondition: the schedule blocks now');
        const id = w.ask(30);
        const dto = await w.service.approve(actor, id, 30);
        assert.equal(dto.state, 'approving', 'queued, not yet confirmed on the router: never shown as approved');
        const row = w.row(id);
        assert.ok(row.grant_operation_id, 'the allowance operation is tracked');
        assert.equal(row.allowance_until, routerTime + 30 * 60, 'until is anchored to router time, not the service clock');
        const op = w.f.store.get<{action: string; payload_json: string}>('SELECT action,payload_json FROM operations WHERE id=?', row.grant_operation_id!)!;
        assert.equal(op.action, 'allow');
        const next = JSON.parse(op.payload_json) as RouterPolicy;
        assert.deepEqual(next.allowances, [{person: 'pilot', until: routerTime + 1800}]);
        assert.deepEqual(next.schedules, w.f.router.policy.schedules, 'the schedule stays in place; the router lifts and restores it');
        await w.service.advance();
        assert.equal(w.row(id).state, 'approving', 'still unconfirmed before dispatch');
        await w.dispatch(row.grant_operation_id!);
        await w.service.advance();
        assert.equal(w.row(id).state, 'approved', 'confirmed only once the router reports the allowance in force');
        const person = w.f.policy.people(actor).people[0];
        assert.deepEqual(person.allowance, {until: routerTime + 1800});
        assert.equal(person.scheduleBlocked, false, 'a granted child is not shown as blocked by the schedule');
        assert.equal(w.service.status(w.link.token, 'client-a').state, 'approved');
    } finally { w.f.cleanup(); }
});

test('approving during a manual pause uses an allowance, not resume + re-pause', async () => {
    const w = await world({pauses: [{person: 'pilot', until: 0}]});
    try {
        const id = w.ask(15);
        await w.service.approve(actor, id, 15);
        const row = w.row(id);
        assert.equal(row.repause_state, 'none', 'no service-side restore obligation');
        assert.equal(w.f.store.get<{n: number}>("SELECT count(*) AS n FROM operations WHERE action='resume'")!.n, 0);
        await w.dispatch(row.grant_operation_id!);
        await w.service.advance();
        assert.equal(w.row(id).state, 'approved');
        assert.deepEqual(w.f.router.policy.pauses, [{person: 'pilot', until: 0}], 'the pause is kept; the router restores it at expiry');
        assert.equal(w.service.hasObligations(), false);
    } finally { w.f.cleanup(); }
});

test('pause wins: a single-child pause during a grant clears the allowance end to end; resume keeps it', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(60);
        await w.service.approve(actor, id, 60);
        await w.dispatch(w.row(id).grant_operation_id!);
        await w.service.advance();
        const resumed = w.f.policy.mutate(actor, 'pilot', 'resume', {}, w.f.policy.people(actor).revisionToken!, 'resume_key_1234567');
        assert.equal(JSON.parse(w.f.store.get<{payload_json: string}>('SELECT payload_json FROM operations WHERE id=?', resumed.result.operation.id)!.payload_json).allowances.length, 1, 'resume keeps the allowance');
        await w.dispatch(resumed.result.operation.id);
        const paused = w.f.pause(0, 'pause_key_12345678');
        const policy = JSON.parse(w.f.store.get<{payload_json: string}>('SELECT payload_json FROM operations WHERE id=?', paused.result.operation.id)!.payload_json) as RouterPolicy;
        assert.equal(policy.allowances, undefined, 'the router-facing policy drops the allowance');
        assert.deepEqual(policy.pauses, [{person: 'pilot', until: 0}]);
        await w.dispatch(paused.result.operation.id);
        await w.service.advance();
        assert.equal(w.f.policy.people(actor).people[0].allowance, null);
        assert.equal(w.row(id).decision_code, 'grant_ended');
        assert.equal(w.service.status(w.link.token, 'client-a').code, 'grant_ended');
    } finally { w.f.cleanup(); }
});

test('a grant dispatched after its deadline is inert on the router and never reported approved', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(15);
        await w.service.approve(actor, id, 15);
        w.f.advance(16 * 60);
        await w.f.observe(); // operator dispatch long after the approval
        await w.dispatch(w.row(id).grant_operation_id!);
        await w.service.advance();
        assert.equal(w.row(id).state, 'apply_failed');
        assert.equal(w.row(id).decision_code, 'grant_not_in_force');
    } finally { w.f.cleanup(); }
});

test('the allowance operation is capped at 60 minutes server-side and idempotent on replay', async () => {
    const w = await world(bedtime);
    try {
        const token = w.f.policy.people(actor).revisionToken!;
        for (const minutes of [0, -5, 61, 240, 1.5, '30']) assert.throws(() => w.grants.grant(actor, 'pilot', minutes as number, token, 'tr-x-a1'), {code: 'invalid_minutes'});
        assert.equal(MAX_GRANT_MINUTES, 60);
        assert.throws(() => w.grants.grant({...actor, personIds: []}, 'pilot', 15, token, 'tr-x-a1'), {code: 'person_not_found'});
        const first = w.grants.grant(actor, 'pilot', 20, token, 'tr-x-a1');
        w.f.advance(5);
        const replay = w.grants.grant(actor, 'pilot', 20, token, 'tr-x-a1');
        assert.deepEqual(replay, first, 'the same key returns the same operation and deadline');
        assert.throws(() => w.grants.grant(actor, 'pilot', 30, token, 'tr-x-a1'), {code: 'idempotency_payload_conflict'});
    } finally { w.f.cleanup(); }
});

test('a later grant never shortens an active one', async () => {
    const w = await world(bedtime);
    try {
        const routerTime = w.f.store.observation().value!.routerTime;
        const first = w.grants.grant(actor, 'pilot', 60, w.f.policy.people(actor).revisionToken!, 'tr-y-a1');
        await w.dispatch(first.operationId);
        const second = w.grants.grant(actor, 'pilot', 15, w.f.policy.people(actor).revisionToken!, 'tr-z-a1');
        assert.equal(second.until, routerTime + 3600);
    } finally { w.f.cleanup(); }
});

test('an approval interrupted before its operation was queued is released, never promoted to approved', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(30), now = w.f.now();
        w.f.store.run("UPDATE time_requests SET state='approving',apply_via='allowance',granted_minutes=30,allowance_until=?,attempts=1,decided_by='operator',decided_at=? WHERE id=?", now + 1800, now, id);
        await w.service.advance();
        assert.equal(w.row(id).state, 'pending', 'no witness operation: the parent can decide again');
        const again = await w.service.approve(actor, id, 30);
        assert.equal(again.state, 'approving');
        // Crash after the operation was queued but before the row recorded it: the key is the witness.
        const opId = w.row(id).grant_operation_id!;
        w.f.store.run('UPDATE time_requests SET grant_operation_id=NULL WHERE id=?', id);
        await w.service.advance();
        assert.equal(w.row(id).grant_operation_id, opId);
        assert.equal(w.row(id).state, 'approving');
    } finally { w.f.cleanup(); }
});

test('a refused grant releases the request for another try', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(30);
        // The CAS path refuses (e.g. a concurrent change moved the revision) and writes nothing.
        const refusing = new TimeRequestService(w.f.store, w.f.policy, w.f.now, undefined, {grant: () => { throw new AppError(409, 'revision_conflict'); }, outcome: w.grants.outcome.bind(w.grants)});
        await assert.rejects(refusing.approve(actor, id, 30), {code: 'revision_conflict'});
        assert.equal(w.row(id).state, 'pending');
        assert.equal(w.row(id).granted_minutes, null);
        w.f.advance(120); // stale observation: refused before any intent is recorded
        await assert.rejects(w.service.approve(actor, id, 30), {code: 'router_status_unavailable'});
        assert.equal(w.row(id).state, 'pending');
        assert.equal(w.f.store.get<{n: number}>('SELECT count(*) AS n FROM operations')!.n, 0);
    } finally { w.f.cleanup(); }
});
