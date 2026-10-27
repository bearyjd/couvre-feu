import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { actor } from './fixtures/integration.ts';
import { world, bedtime } from './fixtures/grant-world.ts';
import { Auth } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { scheduleWithAllowance } from '../src/integration-allowance.ts';
import { parentPost } from '../src/time-requests-http.ts';

const allowOps = (w: Awaited<ReturnType<typeof world>>) => w.f.store.get<{n: number}>("SELECT count(*) AS n FROM operations WHERE action='allow'")!.n;

test('a parent without scope for the child cannot approve on the grant path', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(30);
        for (const personIds of [[], ['someone_else']]) {
            await assert.rejects(w.service.approve({...actor, personIds}, id, 30), {code: 'request_not_found'});
        }
        assert.equal(w.row(id).state, 'pending');
        assert.equal(allowOps(w), 0, 'nothing was queued on the router path');
    } finally { w.f.cleanup(); }
});

test('two concurrent approvals on the grant path produce exactly one allowance', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(30);
        const results = await Promise.allSettled([w.service.approve(actor, id, 30), w.service.approve(actor, id, 15)]);
        assert.deepEqual(results.map(r => r.status).sort(), ['fulfilled', 'rejected']);
        const lost = results.find(r => r.status === 'rejected') as PromiseRejectedResult;
        assert.equal(lost.reason.code, 'request_not_pending');
        assert.equal(allowOps(w), 1, 'only one allowance operation exists');
        assert.equal(w.row(id).state, 'approving');
    } finally { w.f.cleanup(); }
});

test('crafted minutes on the HTTP approve route never reach the router path', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(30);
        for (const minutes of [45, NaN, 1e9, '60', -1, 1.5, 0, null, undefined]) {
            await assert.rejects(parentPost(w.service, actor, `/time-requests/${id}/approve`, {minutes}), error => (error as {code?: string}).code === 'invalid_minutes' || (error as {status?: number}).status === 400, String(minutes));
        }
        assert.equal(w.row(id).state, 'pending');
        assert.equal(allowOps(w), 0);
        assert.equal((await parentPost(w.service, actor, `/time-requests/${id}/approve`, {minutes: 15}))!.status, 200, 'a valid value still works afterwards');
    } finally { w.f.cleanup(); }
});

test('a grant whose operation stays unknown until its deadline ends apply_failed and is never shown approved', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(15);
        await w.service.approve(actor, id, 15);
        w.f.store.run("UPDATE operations SET state='unknown' WHERE id=?", w.row(id).grant_operation_id!);
        for (let minute = 0; minute < 15; minute += 5) {
            w.f.advance(5 * 60 - 1); await w.f.observe(); await w.service.advance();
            assert.equal(w.row(id).state, 'approving');
            assert.equal(w.service.status(w.link.token, `c${minute}`).state, 'pending', 'the child is never told approved');
        }
        w.f.advance(120); await w.f.observe(); await w.service.advance();
        assert.equal(w.row(id).state, 'apply_failed');
        assert.equal(w.row(id).decision_code, 'grant_not_in_force');
        assert.equal(w.service.status(w.link.token, 'c').state, 'apply_failed');
    } finally { w.f.cleanup(); }
});

test('childStatus hides allowanceUntil until the router confirmed the grant, and after it ended', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(30);
        await w.service.approve(actor, id, 30);
        assert.equal(w.row(id).state, 'approving');
        assert.ok(w.row(id).allowance_until, 'precondition: the row holds the planned deadline');
        assert.equal(w.service.status(w.link.token, 'a').allowanceUntil, null, 'not confirmed yet: no deadline is exposed');
        await w.dispatch(w.row(id).grant_operation_id!); await w.service.advance();
        assert.equal(w.service.status(w.link.token, 'b').allowanceUntil, w.row(id).allowance_until);
        w.f.store.run("UPDATE time_requests SET decision_code='grant_ended' WHERE id=?", id);
        assert.equal(w.service.status(w.link.token, 'c').allowanceUntil, null, 'an ended grant exposes no deadline');
    } finally { w.f.cleanup(); }
});

test('status polls and submits have separate per-child budgets', async () => {
    const w = await world(bedtime);
    try {
        for (let i = 0; i < 30; i++) w.service.status(w.link.token, 'sibling');
        assert.throws(() => w.service.status(w.link.token, 'sibling'), {code: 'rate_limited'});
        assert.equal(w.service.submit(w.link.token, 15, 'ok', 'child').state, 'pending', 'a sibling polling the link cannot block a submit');
        for (let i = 0; i < 29; i++) assert.throws(() => w.service.submit(w.link.token, 15, 'again', 'child'), {code: 'request_pending'});
        assert.throws(() => w.service.submit(w.link.token, 15, 'again', 'child'), {code: 'rate_limited'}, 'submits are still limited per minute');
    } finally { w.f.cleanup(); }
});

test('stale bad-token buckets are evicted without a full scan per request and the bound holds', async () => {
    const w = await world(bedtime);
    try {
        for (let i = 0; i < 1500; i++) try { w.service.status('y'.repeat(43), `10.1.${i >> 8}.${i & 255}`); } catch { /* counted */ }
        assert.ok(w.service.badTokenClients() <= 1024);
        w.f.advance(61);
        try { w.service.status('y'.repeat(43), '10.9.9.9'); } catch { /* counted */ }
        assert.equal(w.service.badTokenClients(), 1, 'everything older than a minute was dropped');
        assert.throws(() => w.service.status('z'.repeat(43), '10.9.9.8'), {code: 'link_invalid'}, 'a new client gets its own bucket, not the exhausted overflow one');
    } finally { w.f.cleanup(); }
});

test('legacy rows map to the same child codes as before decision_code was consulted', async () => {
    const w = await world(bedtime);
    try {
        const id = w.ask(15), code = () => w.service.status(w.link.token, `l${Math.random()}`).code;
        w.f.store.run("UPDATE time_requests SET state='unsupported',decision_code=NULL WHERE id=?", id);
        assert.equal(code(), 'schedule_override_unsupported', 'a legacy unsupported row without decision_code');
        w.f.store.run("UPDATE time_requests SET state='unsupported',decision_code='schedule_override_unsupported' WHERE id=?", id);
        assert.equal(code(), 'schedule_override_unsupported', 'the same row with the code stored');
        w.f.store.run("UPDATE time_requests SET state='apply_failed',decision_code=NULL WHERE id=?", id);
        assert.equal(code(), 'approval_not_applied', 'a legacy apply_failed row without decision_code');
        w.f.store.run("UPDATE time_requests SET state='apply_failed',decision_code='grant_not_applied' WHERE id=?", id);
        assert.equal(code(), 'grant_not_applied', 'a grant row keeps its own code');
        w.f.store.run("UPDATE time_requests SET state='declined',decision_code=NULL WHERE id=?", id);
        assert.equal(code(), null);
    } finally { w.f.cleanup(); }
});

test('scheduleWithAllowance keeps an unknown schedule claim unknown', () => {
    const base = {scheduleBlocked: null as boolean | null, scheduleExplanation: 'unknown', scheduleValidUntil: null as number | null};
    assert.equal(scheduleWithAllowance(base, {until: 500}, 400).scheduleBlocked, null, 'fail safe: unknown stays unknown');
    assert.equal(scheduleWithAllowance({...base, scheduleBlocked: true}, {until: 500}, 400).scheduleBlocked, false);
    assert.equal(scheduleWithAllowance({...base, scheduleBlocked: true}, null, 400).scheduleBlocked, true);
    assert.equal(scheduleWithAllowance({...base, scheduleBlocked: false}, {until: 500}, 400).scheduleBlocked, false);
});

async function freePort(): Promise<number> {
    const probe = createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const port = (probe.address() as {port: number}).port;
    await new Promise<void>(resolve => probe.close(() => resolve()));
    return port;
}

test('flag off with grants wired: time-request routes 404 while the drain still follows an in-flight grant', async () => {
    const w = await world(bedtime);
    const port = await freePort(), origin = `http://localhost:${port}`;
    const auth = new Auth(w.f.store, origin, w.f.now, {provenance: w.f.config.provenance, rpName: 'Private integration test'});
    const ticks: (() => unknown)[] = [], realSet = globalThis.setInterval;
    globalThis.setInterval = ((handler: () => unknown, ms?: number, ...args: unknown[]) => { if (ms === 5000) { ticks.push(handler); return {unref() {}} as unknown as NodeJS.Timeout; } return realSet(handler, ms, ...args); }) as typeof setInterval;
    try {
        const id = w.ask(30);
        await w.service.approve(actor, id, 30);
        await w.dispatch(w.row(id).grant_operation_id!);
        assert.equal(w.row(id).state, 'approving', 'precondition: confirmed on the router but not yet followed');
        const server = appServer(auth, w.f.policy, {...w.f.config, port, origin, host: `localhost:${port}`, timeRequests: {enabled: false}} as never);
        try {
            server.listen(port, '127.0.0.1'); await once(server, 'listening');
            const response = await fetch(`${origin}/child/status`, {method: 'POST', headers: {'Content-Type': 'application/json', origin}, body: JSON.stringify({token: w.link.token})});
            assert.equal(response.status, 404, 'no child route even for a real token');
            assert.equal((await fetch(`${origin}/request.html`)).status, 404);
            assert.equal(ticks.length, 1, 'a drain-only timer is armed because a grant is in flight');
            await ticks[0]();
            assert.equal(w.row(id).state, 'approved', 'the drain still follows the grant to its honest state');
        } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
    } finally { globalThis.setInterval = realSet; w.f.cleanup(); }
});
