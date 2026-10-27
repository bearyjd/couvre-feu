import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { Actor, OperationDTO, PeopleDTO, PersonDTO } from '../../shared/src/contracts.ts';
import { Store } from '../src/db.ts';
import { appServer } from '../src/http.ts';
import { Auth } from '../src/auth.ts';
import { ParentAlerts, PAGE_SIZE, RETENTION_SECONDS, ACTIVITY_QUIET_SECONDS } from '../src/parent-alerts.ts';
import { BYPASS_BYTES, BLOCKED_SPIKE_PACKETS, STALE_ALERT_SECONDS, PENDING_ALERT_SECONDS, enforcementUnhealthy, syncProblems, possibleBypass,
    repeatedBlockedAttempts, timeRequestPending } from '../src/alert-rules.ts';
import type { ActivityDelta } from '../src/alert-rules.ts';
import { seedAccounts } from '../src/fixtures.ts';

const now = 1791691200;
const provenance = {source: 'synthetic-fake-router' as const, routerCompatibilityVerified: false as const};
const operation = (over: Partial<OperationDTO> = {}): OperationDTO => ({...provenance, id: '00000000-0000-4000-8000-000000000001', personId: 'alex',
    action: 'pause', revision: 1, state: 'confirmed', createdAt: now - 10, updatedAt: now - 5, error: 'SECRET raw stderr', confirmedAt: now - 5, ...over});
const person = (id: string, over: Partial<PersonDTO> = {}): PersonDTO => ({id, name: id, devices: [], manualPause: null, effectiveManualPause: null,
    scheduleBlocked: false, scheduleExplanation: '', observationHealth: 'healthy', status: 'confirmed', latestOperation: null,
    operationalAlerts: {source: 'synthetic-policy', evaluatedAt: now, sourceObservedAt: now, serviceReceivedAt: null, freshUntil: now + 31, freshness: 'fresh',
        healthy: true, confirmedOperationId: null, expiryVerifiedThrough: now, conditions: []}, ...over});
const people = (list: PersonDTO[] = [person('alex'), person('blair')], over: Partial<PeopleDTO> = {}): PeopleDTO => ({...provenance, people: list,
    serviceDesiredRevision: 1, routerDesiredRevision: 1, revisionToken: null, routerConfirmedRevision: 1, observedAt: now, statusAgeSeconds: 0,
    lastSuccessfulConfirmationAt: now, errors: [], ...over});
const evidence = (p: PersonDTO, over: object) => ({...p, operationalAlerts: {...p.operationalAlerts!, ...over}});
const delta = (over: Partial<ActivityDelta> = {}): ActivityDelta => ({person: 'alex', mac: '02:00:00:00:02:01', windowStart: now - 60, windowEnd: now,
    txBytes: 0, rxBytes: 0, blockedPackets: 0, enforcementActive: true, ...over});
const actor = (over: Partial<Actor>): Actor => ({id: 'x', displayName: 'x', role: 'parent', personIds: ['alex'], permissionVersion: '1', ...over});
const parent = actor({id: 'bryn'}), admin = actor({id: 'jd', role: 'admin', personIds: ['alex', 'blair']});
const fixture = () => { const store = new Store(':memory:'); return {store, alerts: new ParentAlerts(store, null, () => now)}; };

test('enforcement_unhealthy: drift is critical, stale/unavailable only beyond the threshold, router-wide failure is a system alert', () => {
    const drifted = people([evidence(person('alex'), {conditions: [{code: 'observed-drift'}]})]);
    assert.deepEqual(enforcementUnhealthy(drifted, now).map(c => [c.personId, c.severity]), [['alex', 'critical']]);
    const mk = (age: number) => people([evidence(person('alex'), {freshness: 'stale', healthy: false, sourceObservedAt: now - age, conditions: [{code: 'observation-stale'}]})], {observedAt: now - age});
    assert.deepEqual(enforcementUnhealthy(mk(STALE_ALERT_SECONDS), now), []);
    assert.deepEqual(enforcementUnhealthy(mk(STALE_ALERT_SECONDS + 1), now).map(c => [c.personId, c.severity]), [[null, 'warning'], ['alex', 'warning']]);
    const never = people([evidence(person('alex'), {sourceObservedAt: null, conditions: [{code: 'observation-unavailable'}]})], {observedAt: null, errors: ['router_unreachable']});
    assert.equal(enforcementUnhealthy(never, now).length, 2);
    assert.deepEqual(enforcementUnhealthy(people(), now), []);
    assert.doesNotMatch(JSON.stringify(enforcementUnhealthy(never, now)), /router_unreachable/);
});

test('sync_failed and apply_pending_too_long use the latest operation, thresholds and recency, and drop raw errors', () => {
    const one = (over: Partial<OperationDTO>) => syncProblems(people([person('alex', {latestOperation: operation(over)})]), now);
    assert.deepEqual(one({state: 'confirmed'}), []);
    assert.equal(one({state: 'failed'})[0].kind, 'sync_failed');
    assert.equal(one({state: 'conflict'})[0].kind, 'sync_failed');
    assert.deepEqual(one({state: 'failed', updatedAt: now - 86401}), []);
    assert.deepEqual(one({state: 'pending', createdAt: now - PENDING_ALERT_SECONDS}), []);
    assert.equal(one({state: 'pending', createdAt: now - PENDING_ALERT_SECONDS - 1})[0].kind, 'apply_pending_too_long');
    assert.equal(one({state: 'unknown', createdAt: now - 500})[0].kind, 'apply_pending_too_long');
    assert.doesNotMatch(JSON.stringify(one({state: 'failed'})), /SECRET/);
});

test('possible_bypass requires active enforcement, valid windows and traffic strictly above the threshold; details carry no MAC', () => {
    const over = delta({txBytes: BYPASS_BYTES, rxBytes: 1});
    assert.deepEqual(possibleBypass([delta({txBytes: BYPASS_BYTES})], now), []);
    const [found] = possibleBypass([over], now);
    assert.deepEqual([found.personId, found.severity, found.details.totalBytes], ['alex', 'critical', BYPASS_BYTES + 1]);
    assert.doesNotMatch(JSON.stringify(found), /02:00/);
    assert.equal(possibleBypass([delta({txBytes: BYPASS_BYTES, rxBytes: 1, enforcementActive: false})], now).length, 0);
    assert.equal(possibleBypass([delta({txBytes: BYPASS_BYTES / 2}), delta({rxBytes: BYPASS_BYTES / 2 + 1})], now).length, 1);
    for (const bad of [{windowEnd: now - 60}, {windowStart: now}, {windowStart: now - 7200}, {txBytes: -1}, {txBytes: 1.5}, {windowEnd: now + 3600}, {person: 'Bad Name'}]) {
        assert.equal(possibleBypass([delta({txBytes: 2 * BYPASS_BYTES, ...bad})], now).length, 0, JSON.stringify(bad));
    }
});

test('repeated_blocked_attempts is info and triggers at the packet threshold; time_request_pending groups per person', () => {
    assert.equal(repeatedBlockedAttempts([delta({blockedPackets: BLOCKED_SPIKE_PACKETS - 1})], now).length, 0);
    const [spike] = repeatedBlockedAttempts([delta({blockedPackets: BLOCKED_SPIKE_PACKETS})], now);
    assert.equal(spike.severity, 'info');
    const requests = timeRequestPending([{person: 'alex', requestId: 'a', createdAt: now - 30}, {person: 'alex', requestId: 'b', createdAt: now - 90}, {person: 'blair', requestId: 'c', createdAt: now}], now);
    assert.deepEqual(requests.map(r => [r.personId, r.severity, r.details.pendingRequests, r.details.oldestAgeSeconds]), [['alex', 'info', 2, 90], ['blair', 'info', 1, 0]]);
});

test('open alerts dedupe per (kind, person), do not inflate count while held, and a resolved alert recurs as a new row', () => {
    const {store, alerts} = fixture();
    const bad = people([evidence(person('alex'), {conditions: [{code: 'observed-drift'}]})]);
    alerts.reconcile({now, people: bad}); alerts.reconcile({now, people: bad});
    alerts.reconcile({now: now + 5, people: bad});
    const rows = alerts.list(admin).alerts;
    assert.equal(rows.length, 1); assert.deepEqual([rows[0].count, rows[0].firstSeen, rows[0].lastSeen, rows[0].state], [1, now, now + 5, 'open']);
    alerts.reconcile({now: now + 10, people: people()});
    assert.deepEqual([alerts.list(admin).alerts[0].state, alerts.list(admin).alerts[0].resolvedAt], ['resolved', now + 10]);
    alerts.reconcile({now: now + 20, people: bad});
    assert.equal(alerts.list(admin).alerts.length, 2);
    assert.equal(store.get<{n: number}>("SELECT count(*) n FROM parent_alerts WHERE state='open'")!.n, 1);
    store.close();
});

test('escalating severity re-opens an acknowledged alert; a same-or-lower severity does not', () => {
    const {store, alerts} = fixture();
    const drift = (time: number) => alerts.reconcile({now: time, people: people([evidence(person('alex'), {conditions: [{code: 'observation-unavailable'}], sourceObservedAt: null})], {observedAt: now})});
    const worse = (time: number) => alerts.reconcile({now: time, people: people([evidence(person('alex'), {conditions: [{code: 'observed-drift'}]})], {observedAt: time})});
    drift(now);
    const [first] = alerts.list(parent).alerts; assert.equal(first.severity, 'warning');
    alerts.acknowledge(parent, first.id);
    drift(now + 1); assert.equal(alerts.list(parent).alerts[0].state, 'acknowledged');
    worse(now + 2);
    const [after] = alerts.list(parent).alerts;
    assert.deepEqual([after.id, after.severity, after.state, after.acknowledgedAt, after.count], [first.id, 'critical', 'open', null, 1]);
    assert.equal(alerts.list(parent).openCount, 1);
    alerts.acknowledge(parent, first.id); drift(now + 3);
    assert.equal(alerts.list(parent).alerts[0].state, 'acknowledged'); // de-escalation keeps the acknowledgement
    store.close();
});

test('the unresolved-alert index also dedupes system (NULL person) alerts', () => {
    const {store} = fixture();
    const insert = () => store.run("INSERT INTO parent_alerts(person_id,kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES(NULL,'enforcement_unhealthy','warning',1,1,1,1,'open','{}')");
    insert(); assert.throws(insert, /UNIQUE/); store.close();
});

test('acknowledged alerts stay deduped while the condition persists; resolved alerts cannot be acknowledged; unevaluated inputs never auto-resolve', () => {
    const {store, alerts} = fixture();
    alerts.reconcile({now, people: people([evidence(person('alex'), {conditions: [{code: 'observed-drift'}]})]), timeRequests: [{person: 'alex', requestId: 'r', createdAt: now}]});
    const [a] = alerts.list(parent).alerts.filter(x => x.kind === 'enforcement_unhealthy');
    assert.equal(alerts.acknowledge(parent, a.id).state, 'acknowledged');
    assert.equal(alerts.acknowledge(parent, a.id).state, 'acknowledged');
    alerts.reconcile({now: now + 5, people: people([evidence(person('alex'), {conditions: [{code: 'observed-drift'}]})])});
    assert.equal(alerts.list(parent).alerts.length, 2); // no new row; time request untouched because it was not evaluated
    assert.equal(alerts.list(parent).alerts.find(x => x.id === a.id)!.state, 'acknowledged');
    assert.equal(alerts.list(parent).openCount, 1);
    alerts.reconcile({now: now + 10, people: people(), timeRequests: []});
    assert.deepEqual(alerts.list(parent).alerts.map(x => x.state), ['resolved', 'resolved']);
    assert.throws(() => alerts.acknowledge(parent, a.id), {code: 'alert_resolved'});
    store.close();
});

test('activity alerts resolve on a clean evaluated window, or after the quiet period, never when the person was simply not evaluated', () => {
    const {store, alerts} = fixture();
    const loud = delta({txBytes: BYPASS_BYTES + 1});
    alerts.reconcile({now, activity: [loud]});
    alerts.reconcile({now: now + 60, activity: [delta({person: 'blair', windowStart: now, windowEnd: now + 60})]});
    assert.equal(alerts.list(admin).alerts[0].state, 'open');
    alerts.reconcile({now: now + 60, activity: [delta({windowStart: now, windowEnd: now + 60})]});
    assert.equal(alerts.list(admin).alerts[0].state, 'open'); // one quiet batch is not enough
    alerts.reconcile({now: now + 120, activity: [delta({windowStart: now + 60, windowEnd: now + 120})]});
    assert.equal(alerts.list(admin).alerts[0].state, 'resolved');
    alerts.reconcile({now: now + 200, activity: [loud]});
    alerts.reconcile({now: now + 200 + ACTIVITY_QUIET_SECONDS, activity: []});
    assert.equal(alerts.list(admin).alerts[0].state, 'resolved');
    store.close();
});

test('retention removes resolved alerts after 90 days and keeps unresolved ones', () => {
    const {store, alerts} = fixture();
    const drift = (id: string) => evidence(person(id), {conditions: [{code: 'observed-drift'}]});
    const at = (time: number, list: string[]) => alerts.reconcile({now: time, people: people(list.map(drift), {observedAt: time})});
    at(now, ['alex', 'blair']); at(now + 1, ['blair']);
    at(now + RETENTION_SECONDS, ['blair']);
    assert.equal(alerts.list(admin).alerts.length, 2);
    at(now + 1 + RETENTION_SECONDS + 1, ['blair']);
    assert.deepEqual(alerts.list(admin).alerts.map(a => [a.personId, a.state]), [['blair', 'open']]);
    store.close();
});

test('visibility is server-enforced: parents see assigned children only, admins also see system alerts, others get not-found on acknowledge', () => {
    const {store, alerts} = fixture();
    const bad = (id: string) => evidence(person(id), {conditions: [{code: 'observed-drift'}]});
    alerts.reconcile({now, people: people([bad('alex'), bad('blair')], {errors: ['x']})});
    assert.deepEqual(alerts.list(parent).alerts.map(a => a.personId), ['alex']);
    assert.deepEqual(alerts.list(admin).alerts.map(a => a.personId).sort(), ['alex', 'blair', null].sort());
    assert.equal(alerts.list(parent).openCount, 1); assert.equal(alerts.list(admin).openCount, 3);
    assert.deepEqual(alerts.list(actor({personIds: []})).alerts, []);
    assert.deepEqual(alerts.list(actor({role: 'admin', personIds: []})).alerts.map(a => a.personId), [null]);
    const all = alerts.list(admin).alerts;
    for (const hidden of all.filter(a => a.personId !== 'alex')) assert.throws(() => alerts.acknowledge(parent, hidden.id), {code: 'alert_not_found'});
    assert.throws(() => alerts.acknowledge(parent, 99999), {code: 'alert_not_found'});
    assert.equal(alerts.list(admin).openCount, 3);
    store.close();
});

test('list is paginated with a fixed LIMIT and a stable before-cursor', () => {
    const {store, alerts} = fixture();
    for (let index = 0; index < PAGE_SIZE + 5; index++) {
        store.run("INSERT INTO parent_alerts(person_id,kind,severity,created_at,first_seen,last_seen,count,state,resolved_at,details) VALUES('alex','sync_failed','warning',?,?,?,1,'resolved',?,'{}')", index, index, index, index);
    }
    const first = alerts.list(parent);
    assert.equal(first.alerts.length, PAGE_SIZE); assert.notEqual(first.nextBefore, null);
    const second = alerts.list(parent, first.nextBefore!);
    assert.equal(second.alerts.length, 5); assert.equal(second.nextBefore, null);
    assert.equal(new Set([...first.alerts, ...second.alerts].map(a => a.id)).size, PAGE_SIZE + 5);
    assert.ok(second.alerts[0].id < first.alerts[PAGE_SIZE - 1].id);
    store.close();
});

test('a failing people source does not clear existing state alerts', () => {
    const {store} = fixture();
    let fail = false;
    const alerts = new ParentAlerts(store, {people: () => { if (fail) throw new Error('boom'); return people([evidence(person('alex'), {conditions: [{code: 'observed-drift'}]})]); }}, () => now);
    alerts.sync(); fail = true; alerts.sync();
    assert.equal(alerts.list(parent).alerts[0].state, 'open');
    store.close();
});

test('HTTP alert routes require an authenticated session and reject malformed ids', async () => {
    const store = new Store(':memory:'); seedAccounts(store);
    const origin = 'http://localhost:45999', port = 45999;
    const alerts = new ParentAlerts(store, null, () => now);
    const server = appServer(new Auth(store, origin), {} as never, {port, origin, host: `localhost:${port}`, dataDir: '.'}, alerts);
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        for (const path of ['/alerts', '/alerts/before/5']) assert.equal((await fetch(origin + path)).status, 401);
        assert.equal((await fetch(origin + '/alerts?before=1')).status, 400);
        const post = await fetch(origin + '/alerts/1/acknowledge', {method: 'POST', headers: {Origin: origin, 'Content-Type': 'application/json'}, body: '{}'});
        assert.equal(post.status, 401);
    } finally { server.close(); store.close(); }
});

test('hidden kinds: list, openCount and acknowledge omit them for the caller only', () => {
    const {store, alerts} = fixture();
    alerts.reconcile({now, timeRequests: [{person: 'alex', requestId: 'r1', createdAt: now - 10}], people: people([person('alex', {status: 'failed'})])});
    const kindsOf = (hidden?: string[]) => alerts.list(parent, undefined, hidden).alerts.map(a => a.kind);
    assert.ok(kindsOf().includes('time_request_pending'));
    const open = alerts.list(parent).openCount;
    assert.ok(!kindsOf(['time_request_pending']).includes('time_request_pending'));
    assert.equal(alerts.list(parent, undefined, ['time_request_pending']).openCount, open - 1);
    const id = alerts.list(parent).alerts.find(a => a.kind === 'time_request_pending')!.id;
    assert.throws(() => alerts.acknowledge(parent, id, ['time_request_pending']), {message: 'alert_not_found'});
    assert.equal(alerts.acknowledge(parent, id).state, 'acknowledged');
    store.db.close();
});
