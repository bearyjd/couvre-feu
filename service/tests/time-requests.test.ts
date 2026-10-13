import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Store } from '../src/db.ts';
import { Auth, digest } from '../src/auth.ts';
import { seedAccounts, INITIAL_POLICY } from '../src/fixtures.ts';
import { PolicyService } from '../src/policy.ts';
import { appServer } from '../src/http.ts';
import { FakeRouter } from '../../demo-router/src/router.ts';
import { normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import { TimeRequestService, REQUEST_COOLDOWN_SECONDS, REQUEST_TTL_SECONDS } from '../src/time-requests.ts';
import type { ScheduleOverride } from '../src/time-requests.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { ParentAlerts, systemActor } from '../src/parent-alerts.ts';
import type { PolicyPort } from '../src/time-requests.ts';
import { AppError } from '../../shared/src/errors.ts';

const admin: Actor = {id: 'jd', displayName: 'JD', role: 'admin', personIds: ['alex', 'blair'], permissionVersion: '1'};
const parent: Actor = {id: 'bryn', displayName: 'Bryn', role: 'parent', personIds: ['alex'], permissionVersion: '1'};

/** The default fixture clock (04:00 UTC) falls inside alex's 22:00-06:30 schedule. `schedule: false` removes it. */
function fixture(options: {schedule?: boolean; override?: ScheduleOverride} = {}) {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-timereq-')), store = new Store(join(dir, 'service.sqlite'));
    seedAccounts(store);
    let now = 1791691200;
    const router = new FakeRouter(join(dir, 'fake.sqlite'), {now: () => now});
    if (options.schedule === false) {
        const open = policyJSON(normalizePolicy({...INITIAL_POLICY, schedules: []}));
        store.run('UPDATE service_state SET desired_json=? WHERE singleton=1', open);
        router.store.run('UPDATE fake_state SET policy=? WHERE singleton=1', open);
    }
    router.tick();
    const policy = new PolicyService(store, router, () => now), svc = new TimeRequestService(store, policy, () => now, options.override);
    const settle = (seconds = 1) => { now += seconds; router.tick(); policy.reconcile(); };
    const token = () => policy.people(admin).revisionToken!;
    const pause = (until: number, actor = parent) => { const r = policy.mutate(actor, 'alex', 'pause', {until}, token(), randomUUID()); settle(); return r; };
    const pauses = () => (JSON.parse(router.store.get<{policy: string}>('SELECT policy FROM fake_state')!.policy) as {pauses: {person: string; until: number}[]}).pauses;
    const ops = () => store.get<{n: number}>('SELECT count(*) n FROM operations')!.n;
    return {dir, store, router, policy, svc, settle, pause, pauses, ops, now: () => now, close: () => { store.close(); router.close(); rmSync(dir, {recursive: true}); }};
}
async function linked(f: ReturnType<typeof fixture>, person = 'alex', actor = parent) {
    return (await f.svc.issueLink(actor, person)).token;
}

test('link tokens: high entropy, hash-only storage, scoped to one child, revocable and replaceable', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        assert.match(token, /^[A-Za-z0-9_-]{43}$/);
        const row = f.store.get<{token_hash: string; person_id: string}>('SELECT * FROM request_links')!;
        assert.equal(row.token_hash, digest(token));
        assert.equal(row.person_id, 'alex');
        assert.ok(!JSON.stringify(f.store.all('SELECT * FROM request_links')).includes(token));
        assert.equal(f.svc.status(token).state, 'none');
        const second = await linked(f);
        assert.notEqual(second, token);
        assert.throws(() => f.svc.status(token), {code: 'link_invalid'});
        assert.equal(f.svc.status(second).state, 'none');
        assert.equal(f.svc.revokeLink(parent, 'alex').revoked, true);
        assert.throws(() => f.svc.status(second), {code: 'link_invalid'});
        assert.equal(f.svc.revokeLink(parent, 'alex').revoked, false);
        assert.deepEqual(f.svc.overview(parent).links, [{personId: 'alex', active: false, createdAt: null}]);
        // A parent can neither issue nor revoke for a child they are not assigned to.
        await assert.rejects(f.svc.issueLink(parent, 'blair'), {code: 'person_not_found'});
        assert.throws(() => f.svc.revokeLink(parent, 'blair'), {code: 'person_not_found'});
        await assert.rejects(f.svc.issueLink(admin, 'nobody'), {code: 'person_not_found'});
    } finally { f.close(); }
});

test('invalid and malformed tokens are indistinguishable and flood-limited without blocking valid links', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        for (const bad of [undefined, 7, '', 'short', 'x'.repeat(43), `${token.slice(0, 42)}${token.endsWith('A') ? 'B' : 'A'}`, `${token}x`]) {
            assert.throws(() => f.svc.status(bad), {code: 'link_invalid'});
        }
        for (let i = 0; i < 40; i++) try { f.svc.status('y'.repeat(43)); } catch { /* counted */ }
        assert.throws(() => f.svc.status('y'.repeat(43)), {code: 'rate_limited'});
        assert.equal(f.svc.status(token).state, 'none');
    } finally { f.close(); }
});

test('submission validation: minutes, bounded plain-text reason, one pending, cooldown', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        for (const minutes of [0, 10, 45, '30', null, undefined]) assert.throws(() => f.svc.submit(token, minutes, ''), {code: 'invalid_minutes'});
        for (const reason of ['x'.repeat(141), 'bad\u0000char', 'line\nbreak', 'rtl‮override', 5, {}]) assert.throws(() => f.svc.submit(token, 15, reason), {code: 'invalid_reason'});
        assert.equal(f.svc.status(token).state, 'none');
        const html = '<img src=x onerror=alert(1)>';
        const sent = f.svc.submit(token, 30, `  ${html}  `);
        assert.equal(sent.state, 'pending');
        assert.equal(sent.canRequest, false);
        assert.equal(f.svc.overview(parent).requests[0].reason, html, 'stored verbatim as inert text; the UI renders it with textContent');
        assert.throws(() => f.svc.submit(token, 15, ''), {code: 'request_pending'});
        const id = f.svc.overview(parent).requests[0].id;
        f.svc.decline(parent, id);
        assert.throws(() => f.svc.submit(token, 15, ''), {code: 'request_cooldown'});
        f.settle(REQUEST_COOLDOWN_SECONDS - 5);
        assert.equal(f.svc.status(token).retryAfter, 5);
        f.settle(10);
        assert.equal(f.svc.submit(token, 15, 'x'.repeat(140)).state, 'pending');
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM time_requests WHERE state='pending'")!.n, 1);
    } finally { f.close(); }
});

test('unanswered requests expire automatically and cannot be decided afterwards', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        f.svc.submit(token, 15, '');
        const id = f.svc.overview(parent).requests[0].id;
        f.settle(REQUEST_TTL_SECONDS - 1);
        assert.equal(f.svc.status(token).state, 'pending');
        f.settle(1);
        assert.equal(f.svc.status(token).state, 'expired');
        assert.equal(f.svc.status(token).canRequest, true);
        await assert.rejects(f.svc.approve(parent, id, 15), {code: 'request_not_pending'});
        assert.throws(() => f.svc.decline(parent, id), {code: 'request_not_pending'});
        assert.equal(f.store.get<{outcome: string}>("SELECT outcome FROM audit WHERE action='time_request_expire'")!.outcome, 'expired');
    } finally { f.close(); }
});

test('only parents assigned to the child can see or decide; decisions are audited with who and when', async () => {
    const f = fixture({schedule: false});
    try {
        const alexToken = await linked(f, 'alex', admin), blairToken = await linked(f, 'blair', admin);
        f.svc.submit(alexToken, 15, 'alex');
        f.svc.submit(blairToken, 30, 'blair');
        assert.deepEqual(f.svc.overview(parent).requests.map(r => r.personId), ['alex']);
        assert.deepEqual(f.svc.overview(parent).links.map(l => l.personId), ['alex']);
        const blairId = f.svc.overview(admin).requests.find(r => r.personId === 'blair')!.id;
        await assert.rejects(f.svc.approve(parent, blairId, 15), {code: 'request_not_found'});
        assert.throws(() => f.svc.decline(parent, blairId), {code: 'request_not_found'});
        await assert.rejects(f.svc.approve(parent, 'not-a-request', 15), {code: 'request_not_found'});
        await assert.rejects(f.svc.approve(admin, blairId, 90), {code: 'invalid_minutes'});
        const declined = f.svc.decline(admin, blairId);
        assert.equal(declined.state, 'declined');
        assert.equal(declined.decidedBy, 'jd');
        assert.equal(declined.decidedAt, f.now());
        const alexId = f.svc.overview(parent).requests[0].id;
        const approved = await f.svc.approve(parent, alexId, 15);
        assert.equal(approved.decidedBy, 'bryn');
        await assert.rejects(f.svc.approve(parent, alexId, 15), {code: 'request_not_pending'});
        // The child endpoint exposes only that child's own request status: no names, deciders or other children.
        const view = JSON.stringify(f.svc.status(alexToken));
        for (const leak of ['bryn', 'jd', 'blair', 'alex', 'Alex']) assert.ok(!view.includes(leak), leak);
        const trail = f.store.all<{actor_id: string; action: string}>("SELECT actor_id,action FROM audit WHERE action LIKE 'time_request%' OR action LIKE 'request_link%' ORDER BY id");
        assert.deepEqual(trail.map(t => `${t.actor_id}:${t.action}`), ['jd:request_link_issue', 'jd:request_link_issue', 'child:alex:time_request_create', 'child:blair:time_request_create', 'jd:time_request_decline', 'bryn:time_request_approve']);
    } finally { f.close(); }
});

test('approval ends a timed pause through the existing policy path and restores it when the allowance ends', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f), start = f.now();
        f.pause(start + 7200);
        assert.equal(f.pauses().length, 1);
        f.svc.submit(token, 30, 'homework');
        const id = f.svc.overview(parent).requests[0].id;
        const before = f.ops(), at = f.now();
        const approved = await f.svc.approve(parent, id, 15);
        f.settle();
        assert.equal(approved.state, 'approved');
        assert.equal(approved.repause, 'waiting');
        assert.equal(approved.grantedMinutes, 15, 'the parent may grant less than requested');
        assert.equal(f.ops(), before + 1);
        assert.deepEqual(f.pauses(), []);
        assert.equal(f.store.get<{action: string; actor_id: string}>('SELECT action,actor_id FROM operations ORDER BY revision DESC LIMIT 1')!.actor_id, 'bryn');
        const child = f.svc.status(token);
        assert.equal(child.state, 'approved');
        assert.equal(child.allowanceUntil, at + 900);
        await f.svc.advance();
        assert.deepEqual(f.pauses(), [], 'allowance still running');
        f.settle(900);
        await f.svc.advance();
        f.settle();
        assert.deepEqual(f.pauses(), [{person: 'alex', until: start + 7200}]);
        await f.svc.advance();
        assert.equal(f.svc.overview(parent).requests[0].repause, 'done');
        await f.svc.advance();
        assert.equal(f.ops(), before + 2, 'restored exactly once');
    } finally { f.close(); }
});

test('indefinite pauses are restored indefinitely; pauses that end inside the allowance are left to expire', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        f.pause(0);
        f.svc.submit(token, 15, '');
        await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 15);
        f.settle(REQUEST_COOLDOWN_SECONDS + 700);
        await f.svc.advance(); f.settle();
        assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
        const startOps = f.ops();
        f.pause(f.now() + 300);
        f.svc.submit(token, 30, '');
        const id = f.svc.overview(parent).requests[0].id;
        const approved = await f.svc.approve(parent, id, 30);
        assert.equal(approved.repause, 'not_needed');
        f.settle(1900);
        await f.svc.advance();
        assert.equal(f.ops(), startOps + 2, 'pause + resume only; no re-pause');
    } finally { f.close(); }
});

test('a pause that would have ended during the retry grace is reported as not needed, not failed', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        f.pause(f.now() + 1000);
        f.svc.submit(token, 15, '');
        const approved = await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 15);
        assert.equal(approved.repause, 'waiting');
        f.settle(1100);
        await f.svc.advance();
        assert.equal(f.svc.overview(parent).requests[0].repause, 'not_needed');
    } finally { f.close(); }
});

test('a later explicit parent change supersedes the pending re-pause', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        f.pause(0);
        f.svc.submit(token, 15, '');
        await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 15);
        f.settle();
        f.pause(f.now() + 5000);
        const before = f.ops();
        f.settle(1000);
        await f.svc.advance();
        assert.equal(f.svc.overview(parent).requests[0].repause, 'superseded');
        assert.equal(f.ops(), before);
    } finally { f.close(); }
});

test('approving when nothing blocks the child changes no policy', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        f.svc.submit(token, 15, '');
        const before = f.ops();
        const approved = await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 15);
        assert.equal(approved.state, 'approved');
        assert.equal(approved.repause, 'none');
        assert.equal(f.ops(), before);
    } finally { f.close(); }
});

test('a failed router change is not reported to the child as an effective approval', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        f.pause(0);
        f.svc.submit(token, 15, '');
        await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 15);
        f.store.run("UPDATE operations SET state='conflict' WHERE revision=(SELECT max(revision) FROM operations)");
        await f.svc.advance();
        const status = f.svc.status(token);
        assert.equal(status.state, 'apply_failed');
        assert.equal(status.code, 'approval_not_applied');
    } finally { f.close(); }
});

test('approval during a schedule block is reported as unsupported to both sides and writes no policy', async () => {
    const f = fixture();
    try {
        const token = await linked(f);
        f.pause(0);
        f.svc.submit(token, 30, '');
        const id = f.svc.overview(parent).requests[0].id, before = f.ops();
        const result = await f.svc.approve(parent, id, 30);
        assert.equal(result.state, 'unsupported');
        assert.equal(result.code, 'schedule_override_unsupported');
        assert.equal(result.grantedMinutes, null);
        assert.equal(f.ops(), before, 'neither resume nor any override was written');
        assert.equal(f.pauses().length, 1, 'the manual pause is untouched');
        const child = f.svc.status(token);
        assert.equal(child.state, 'unsupported');
        assert.equal(child.code, 'schedule_override_unsupported');
        assert.equal(child.allowanceUntil, null);
        assert.equal(f.store.get<{actor_id: string}>("SELECT actor_id FROM audit WHERE action='time_request_unsupported'")!.actor_id, 'bryn');
    } finally { f.close(); }
});

test('a schedule override hook can be plugged in later and is consulted before approval', async () => {
    const calls: string[] = [];
    const f = fixture({override: ({personId, minutes, until}) => { calls.push(`${personId}:${minutes}:${until}`); }});
    try {
        const token = await linked(f);
        f.svc.submit(token, 60, '');
        const result = await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 60);
        assert.equal(result.state, 'approved');
        assert.deepEqual(calls, [`alex:60:${f.now() + 3600}`]);
    } finally { f.close(); }
});

test('HTTP: child routes need only the body token; parent routes need session and CSRF; no cookies are set for children', async () => {
    const f = fixture({schedule: false}), port = 46000 + process.pid % 10000, origin = `http://localhost:${port}`;
    const server = appServer(new Auth(f.store, origin, () => f.now()), f.policy, {port, origin, host: `localhost:${port}`, dataDir: f.dir}, undefined, undefined, f.svc);
    server.listen(port, '127.0.0.1');
    await once(server, 'listening');
    try {
        const token = await linked(f);
        const post = (path: string, body: unknown, headers: Record<string, string> = {origin}) =>
            fetch(`${origin}${path}`, {method: 'POST', headers: {'Content-Type': 'application/json', ...headers}, body: JSON.stringify(body)});
        let r = await post('/child/status', {token});
        assert.equal(r.status, 200);
        assert.equal(r.headers.getSetCookie().length, 0);
        assert.equal((await r.json() as {state: string}).state, 'none');
        assert.equal(r.headers.get('cache-control'), 'no-store');
        assert.equal((await post('/child/status', {token}, {})).status, 403, 'origin is required');
        assert.equal((await post('/child/status', {token, extra: 1})).status, 400);
        assert.equal((await post('/child/status', {token: 'z'.repeat(43)})).status, 404);
        r = await post('/child/request', {token, minutes: 15, reason: 'please'});
        assert.equal(r.status, 200);
        assert.equal(r.headers.get('cache-control'), 'no-store');
        assert.equal((await post('/child/request', {token, minutes: 15})).status, 409);
        assert.equal((await fetch(`${origin}/child/status?token=${token}`, {headers: {origin}})).status, 400, 'tokens never travel in URLs');
        assert.equal((await fetch(`${origin}/time-requests`, {headers: {origin}})).status, 401);
        r = await post('/time-requests/00000000-0000-4000-8000-000000000000/approve', {minutes: 15});
        assert.equal(r.status, 401);
        r = await post('/people/alex/request-link', {});
        assert.equal(r.status, 401);
        assert.equal((await fetch(`${origin}/request.html`)).status, 200);
        assert.equal((await fetch(`${origin}/time-requests.js`)).status, 200);
    } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); f.close(); }
});

/** Wraps the real policy so a test can run code around, or fail, a given mutation. */
function wrapped(f: ReturnType<typeof fixture>, around: (action: string, call: () => ReturnType<PolicyPort['mutate']>) => ReturnType<PolicyPort['mutate']>): PolicyPort {
    return {people: actor => f.policy.people(actor), mutate: (actor, person, action, input, precondition, key) => around(action, () => f.policy.mutate(actor, person, action, input, precondition, key))};
}
const stateOf = (f: ReturnType<typeof fixture>) => ({...f.store.get<{state: string; repause_state: string; allowance_until: number | null; original_pause_until: number | null}>('SELECT state,repause_state,allowance_until,original_pause_until FROM time_requests')!});

test('intent is durable before the resume is attempted', async () => {
    const f = fixture({schedule: false});
    try {
        let seen = null as ReturnType<typeof stateOf> | null;
        const svc = new TimeRequestService(f.store, wrapped(f, (action, call) => { if (action === 'resume') seen = stateOf(f); return call(); }), () => f.now());
        const token = (await svc.issueLink(parent, 'alex')).token;
        f.pause(0);
        svc.submit(token, 15, '');
        await svc.approve(parent, svc.overview(parent).requests[0].id, 15);
        assert.deepEqual(seen, {state: 'approving', repause_state: 'waiting', allowance_until: stateOf(f).allowance_until, original_pause_until: 0});
        assert.notEqual(seen!.allowance_until, null);
    } finally { f.close(); }
});

test('a crash after the resume was applied still ends re-paused, including after a restart', async () => {
    const f = fixture({schedule: false});
    try {
        const crashing = new TimeRequestService(f.store, wrapped(f, async (action, call) => { const result = await call(); if (action === 'resume') throw new Error('simulated crash after apply'); return result; }), () => f.now());
        const token = (await crashing.issueLink(parent, 'alex')).token;
        f.pause(0);
        crashing.submit(token, 15, '');
        const approved = await crashing.approve(parent, crashing.overview(parent).requests[0].id, 15);
        f.settle();
        assert.equal(approved.state, 'approved');
        assert.deepEqual(f.pauses(), [], 'the resume was applied');
        const restarted = new TimeRequestService(f.store, f.policy, () => f.now());
        f.settle(900);
        await restarted.advance(); f.settle(); await restarted.advance();
        assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
        assert.equal(restarted.overview(parent).requests[0].repause, 'done');
    } finally { f.close(); }
});

test('an approving row left by a dead process is completed as approved and restored after restart', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f);
        f.pause(0);
        f.svc.submit(token, 15, '');
        await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 15);
        f.settle();
        f.store.run("UPDATE time_requests SET state='approving',resume_operation_id=NULL");
        assert.equal(f.svc.status(token).state, 'pending', 'the child is not told about an unfinished approval');
        const restarted = new TimeRequestService(f.store, f.policy, () => f.now());
        await restarted.advance();
        assert.equal(stateOf(f).state, 'approved');
        f.settle(900);
        await restarted.advance(); f.settle();
        assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
    } finally { f.close(); }
});

test('a refused mutation releases the claim; the parent can retry', async () => {
    const f = fixture({schedule: false});
    try {
        let refuse = true;
        const svc = new TimeRequestService(f.store, wrapped(f, (_action, call) => { if (refuse) throw new AppError(409, 'operation_in_progress'); return call(); }), () => f.now());
        const token = (await svc.issueLink(parent, 'alex')).token;
        f.pause(0);
        svc.submit(token, 15, '');
        const id = svc.overview(parent).requests[0].id;
        await assert.rejects(svc.approve(parent, id, 15), {code: 'operation_in_progress'});
        assert.deepEqual(stateOf(f), {state: 'pending', repause_state: 'none', allowance_until: null, original_pause_until: null});
        refuse = false;
        assert.equal((await svc.approve(parent, id, 15)).state, 'approved');
    } finally { f.close(); }
});

test('revoking the link during approval cannot cancel the approval or skip the restore', async () => {
    const f = fixture({schedule: false});
    try {
        let svc!: TimeRequestService;
        svc = new TimeRequestService(f.store, wrapped(f, (action, call) => { if (action === 'resume') svc.revokeLink(parent, 'alex'); return call(); }), () => f.now());
        const token = (await svc.issueLink(parent, 'alex')).token;
        f.pause(0);
        svc.submit(token, 15, '');
        const approved = await svc.approve(parent, svc.overview(parent).requests[0].id, 15);
        f.settle();
        assert.equal(approved.state, 'approved');
        assert.equal(svc.overview(parent).links[0].active, false);
        f.settle(900);
        await svc.advance(); f.settle();
        assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
        // A row that is still approving is likewise untouched by a revoke.
        const again = await svc.issueLink(parent, 'alex');
        f.store.run("UPDATE time_requests SET state='approving'");
        svc.revokeLink(parent, 'alex');
        assert.equal(stateOf(f).state, 'approving');
        assert.ok(again.token);
    } finally { f.close(); }
});

test('the restore retries without limit, alerts the parent while overdue, and succeeds when the router returns', async () => {
    const f = fixture({schedule: false});
    try {
        let down = true;
        const port: PolicyPort = {people: actor => { if (down) throw new AppError(503, 'router_unreachable'); return f.policy.people(actor); }, mutate: (...args) => f.policy.mutate(...args)};
        const token = await linked(f);
        f.pause(0);
        f.svc.submit(token, 15, '');
        await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 15);
        f.settle();
        const svc = new TimeRequestService(f.store, port, () => f.now());
        f.settle(900);
        for (let i = 0; i < 5; i++) { f.settle(1000); await svc.advance(); }
        const [row] = svc.overview(parent).requests;
        assert.equal(row.repause, 'waiting');
        assert.equal(row.repauseOverdue, true);
        assert.equal(row.repauseError, 'router_unreachable');
        assert.deepEqual(f.pauses(), []);
        down = false;
        f.settle(301); await svc.advance(); f.settle();
        assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
        await svc.advance();
        assert.equal(svc.overview(parent).requests[0].repauseOverdue, false);
    } finally { f.close(); }
});

test('the restore runs as an active assigned account, not the approver, and without one it keeps waiting', async () => {
    const f = fixture({schedule: false});
    try {
        const token = await linked(f, 'alex', admin);
        f.pause(0);
        f.svc.submit(token, 15, '');
        await f.svc.approve(admin, f.svc.overview(admin).requests[0].id, 15);
        f.settle();
        f.store.run("UPDATE accounts SET active=0 WHERE id='jd'");
        f.settle(900);
        await f.svc.advance(); f.settle();
        assert.equal(f.store.get<{actor_id: string}>("SELECT actor_id FROM operations WHERE idempotency_key LIKE 'tr-%-p%'")!.actor_id, 'bryn');
        assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
    } finally { f.close(); }
    const g = fixture({schedule: false});
    try {
        const token = await linked(g);
        g.pause(0);
        g.svc.submit(token, 15, '');
        await g.svc.approve(parent, g.svc.overview(parent).requests[0].id, 15);
        g.settle();
        g.store.run('UPDATE accounts SET active=0');
        g.settle(900);
        await g.svc.advance();
        assert.equal(g.store.get<{repause_state: string; repause_error: string}>('SELECT repause_state,repause_error FROM time_requests')!.repause_error, 'no_assigned_parent');
        assert.equal(stateOf(g).repause_state, 'waiting');
    } finally { g.close(); }
});

test('only pending or confirmed later operations supersede the restore; failed and conflicted ones do not', async () => {
    for (const [state, expected] of [['conflict', 'done'], ['failed', 'done'], ['confirmed', 'superseded']] as const) {
        const f = fixture({schedule: false});
        try {
            const token = await linked(f);
            f.pause(0);
            f.svc.submit(token, 15, '');
            await f.svc.approve(parent, f.svc.overview(parent).requests[0].id, 15);
            f.settle();
            f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                randomUUID(), 'bryn', 'alex', 'pause', 99999, state, '{}', '{}', '{}', `later-${state}-key-0000`, f.now(), f.now());
            f.settle(900);
            await f.svc.advance(); f.settle(); await f.svc.advance();
            assert.equal(stateOf(f).repause_state, expected, state);
            if (expected === 'done') assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
        } finally { f.close(); }
    }
});

test('an error surfaced after the write path committed still counts as approved and the pause is restored', async () => {
    const f = fixture({schedule: false});
    try {
        const svc = new TimeRequestService(f.store, wrapped(f, async (action, call) => { const result = await call(); if (action === 'resume') throw new AppError(503, 'post_commit_failure'); return result; }), () => f.now());
        const token = (await svc.issueLink(parent, 'alex')).token;
        f.pause(0);
        svc.submit(token, 15, '');
        const approved = await svc.approve(parent, svc.overview(parent).requests[0].id, 15);
        f.settle();
        assert.equal(approved.state, 'approved');
        assert.deepEqual(f.pauses(), [], 'the resume was committed');
        assert.notEqual(f.store.get<{resume_operation_id: string | null}>('SELECT resume_operation_id FROM time_requests')!.resume_operation_id, null);
        f.settle(900);
        await svc.advance(); f.settle(); await svc.advance();
        assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
        assert.equal(svc.overview(parent).requests[0].repause, 'done');
    } finally { f.close(); }
});

test('a re-pause is done only once confirmed; a failed or conflicted one is retried with an alert', async () => {
    const f = fixture({schedule: false});
    try {
        let lie = true;
        const svc = new TimeRequestService(f.store, wrapped(f, (action, call) => {
            if (action === 'pause' && lie) {
                lie = false;
                f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES('11111111-1111-4111-8111-111111111111','bryn','alex','pause',88888,'pending','{}','{}','{}','fake-pause-key-000000',?,?)", f.now(), f.now());
                return {status: 202, result: {source: 'synthetic-fake-router', routerCompatibilityVerified: false, operationUrl: '/x', operation: {id: '11111111-1111-4111-8111-111111111111', revision: 88888, state: 'pending'}}} as unknown as ReturnType<PolicyPort['mutate']>;
            }
            return call();
        }), () => f.now());
        const token = (await svc.issueLink(parent, 'alex')).token;
        f.pause(0);
        svc.submit(token, 15, '');
        await svc.approve(parent, svc.overview(parent).requests[0].id, 15);
        f.settle(900);
        await svc.advance();
        assert.equal(stateOf(f).repause_state, 'applying', 'a pending operation is not a restore');
        await svc.advance();
        assert.equal(stateOf(f).repause_state, 'applying');
        f.store.run("UPDATE operations SET state='conflict' WHERE id='11111111-1111-4111-8111-111111111111'");
        await svc.advance();
        assert.equal(stateOf(f).repause_state, 'waiting', 'backing off after the conflict');
        f.settle(31); await svc.advance();
        const retried = f.store.get<{repause_operation_id: string}>('SELECT repause_operation_id FROM time_requests')!.repause_operation_id;
        assert.notEqual(retried, '11111111-1111-4111-8111-111111111111', 'a new pause operation was issued');
        f.settle(); await svc.advance();
        assert.deepEqual(f.pauses(), [{person: 'alex', until: 0}]);
        assert.equal(svc.overview(parent).requests[0].repause, 'done');
    } finally { f.close(); }
});

test('a persistently rejected restore backs off (30 s doubling to 5 min) instead of writing every tick, and never gives up', async () => {
    const f = fixture({schedule: false});
    try {
        let calls = 0;
        const svc = new TimeRequestService(f.store, wrapped(f, (action, call) => { if (action === 'pause') { calls++; throw new AppError(409, 'revision_conflict'); } return call(); }), () => f.now());
        const token = (await svc.issueLink(parent, 'alex')).token;
        f.pause(0);
        svc.submit(token, 15, '');
        await svc.approve(parent, svc.overview(parent).requests[0].id, 15);
        f.settle(900);
        for (let i = 0; i < 6; i++) await svc.advance();
        assert.equal(calls, 1, 'one attempt per backoff window, not per tick');
        f.settle(29); await svc.advance();
        assert.equal(calls, 1);
        f.settle(1); await svc.advance();
        assert.equal(calls, 2);
        f.settle(59); await svc.advance();
        assert.equal(calls, 2, 'second window is 60 s');
        f.settle(1); await svc.advance();
        assert.equal(calls, 3);
        for (let i = 0; i < 8; i++) { f.settle(301); await svc.advance(); }
        assert.equal(calls, 11, 'unbounded: still attempting every <= 5 minutes');
        const next = f.store.get<{next_attempt_at: number}>('SELECT next_attempt_at FROM time_requests')!.next_attempt_at;
        assert.ok(next - f.now() <= 300);
        const row = svc.overview(parent).requests[0];
        assert.equal(row.repauseOverdue, true);
        assert.equal(row.repauseError, 'revision_conflict');
    } finally { f.close(); }
});

test('an applying (pending or awaiting dispatch) restore shows the overdue alert once the allowance has ended', async () => {
    const f = fixture({schedule: false});
    try {
        const svc = new TimeRequestService(f.store, wrapped(f, (action, call) => {
            if (action !== 'pause') return call();
            f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES('22222222-2222-4222-8222-222222222222','bryn','alex','pause',77777,'pending','{}','{}','{}','fake-pause-key-111111',?,?)", f.now(), f.now());
            return {status: 202, result: {operationUrl: '/x', operation: {id: '22222222-2222-4222-8222-222222222222', revision: 77777, state: 'pending'}}} as unknown as ReturnType<PolicyPort['mutate']>;
        }), () => f.now());
        const token = (await svc.issueLink(parent, 'alex')).token;
        f.pause(0);
        svc.submit(token, 15, '');
        await svc.approve(parent, svc.overview(parent).requests[0].id, 15);
        assert.equal(svc.overview(parent).requests[0].repauseOverdue, false, 'allowance still running');
        f.settle(900);
        await svc.advance();
        const row = svc.overview(parent).requests[0];
        assert.equal(row.repause, 'applying');
        assert.equal(row.repauseOverdue, true);
    } finally { f.close(); }
});

test('pending requests feed the parent-alerts time_request_pending rule and clear when answered', async () => {
    const f = fixture({schedule: false});
    try {
        const alerts = new ParentAlerts(f.store, {people: () => f.policy.people(systemActor), timeRequests: () => f.svc.pendingForAlerts()}, () => f.now());
        const token = await linked(f);
        f.svc.submit(token, 15, 'secret reason');
        alerts.sync();
        const list = alerts.list(parent).alerts.filter(a => a.kind === 'time_request_pending');
        assert.equal(list.length, 1);
        assert.equal(list[0].personId, 'alex');
        assert.ok(!JSON.stringify(list).includes('secret reason'));
        f.svc.decline(parent, f.svc.overview(parent).requests[0].id);
        f.settle();
        alerts.sync();
        assert.equal(alerts.list(parent).alerts.find(a => a.kind === 'time_request_pending')!.state, 'resolved');
    } finally { f.close(); }
});
