import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { TimeRequestService, normalizeReason } from '../src/time-requests.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import { Auth } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { normalizePolicy, scheduleBlocked } from '../../shared/src/router-schema.ts';

async function linked() {
    const f = integrationFixture();
    await f.observe();
    const service = new TimeRequestService(f.store, f.policy, f.now);
    const link = await service.issueLink(actor, 'pilot');
    return {f, service, token: link.token};
}

test('one hostile client flooding bad tokens cannot rate-limit other clients or any valid link', async () => {
    const {f, service, token} = await linked();
    try {
        for (let i = 0; i < 40; i++) try { service.status('y'.repeat(43), '10.0.0.66'); } catch { /* counted */ }
        assert.throws(() => service.status('y'.repeat(43), '10.0.0.66'), {code: 'rate_limited'}, 'the flooding client is limited');
        assert.throws(() => service.status('z'.repeat(43), '10.0.0.7'), {code: 'link_invalid'}, 'another client keeps its own bucket');
        assert.equal(service.status(token, '10.0.0.66').state, 'none', 'a valid link is never refused by the bad-token limiter');
        f.advance(61);
        assert.throws(() => service.status('y'.repeat(43), '10.0.0.66'), {code: 'link_invalid'}, 'the bucket drains after a minute');
    } finally { f.cleanup(); }
});

test('the bad-token buckets stay bounded under many distinct clients', async () => {
    const {f, service, token} = await linked();
    try {
        for (let i = 0; i < 5000; i++) try { service.status('y'.repeat(43), `10.${i >> 16 & 255}.${i >> 8 & 255}.${i & 255}`); } catch { /* counted */ }
        assert.ok(service.badTokenClients() <= 1024, `bounded, got ${service.badTokenClients()}`);
        assert.equal(service.status(token, '10.0.0.1').state, 'none');
    } finally { f.cleanup(); }
});

test('the per-minute limit is per child and survives reissuing the link', async () => {
    const {f, service, token} = await linked();
    try {
        for (let i = 0; i < 30; i++) service.status(token, 'c');
        assert.throws(() => service.status(token, 'c'), {code: 'rate_limited'});
        const fresh = await service.issueLink(actor, 'pilot');
        assert.throws(() => service.status(fresh.token, 'c'), {code: 'rate_limited'}, 'a new link for the same child shares the bucket');
        f.advance(61);
        assert.equal(service.status(fresh.token, 'c').state, 'none');
    } finally { f.cleanup(); }
});

test('the request message is hostile input: invisible and unpaired code points are refused, markup stays inert data', () => {
    for (const bad of ['a​b', 'a b', '﻿hi', 'x‎y', '\ud800', 'ok\udc00', 'a؜b', 'x'.repeat(141)]) assert.throws(() => normalizeReason(bad), {code: 'invalid_reason'}, JSON.stringify(bad));
    assert.equal(normalizeReason('<img src=x onerror=alert(1)>'), '<img src=x onerror=alert(1)>', 'stored verbatim; only ever rendered with textContent');
    assert.equal(normalizeReason('👨‍👩‍👧 please'), '👨‍👩‍👧 please', 'emoji joiner sequences are ordinary text');
});

test('parents get a request-pending alert on the real path, without the reason text', async () => {
    // Port 0: the OS picks a free one. No request is made to the server, so the origin is only a placeholder for Auth.
    const f = integrationFixture(), port = 0, origin = 'http://localhost:4273';
    await f.observe();
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const ticks: (() => unknown)[] = [], realSet = globalThis.setInterval;
    globalThis.setInterval = ((handler: () => unknown, ms?: number, ...args: unknown[]) => { if (ms === 5000) { ticks.push(handler); return {unref() {}} as unknown as NodeJS.Timeout; } return realSet(handler, ms, ...args); }) as typeof setInterval;
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: 'localhost:4273', timeRequests: {enabled: true}} as never, new ParentAlerts(f.store, null, f.now));
    try {
        server.listen(port, '127.0.0.1'); await once(server, 'listening');
        const service = new TimeRequestService(f.store, f.policy, f.now);
        const link = await service.issueLink(actor, 'pilot');
        service.submit(link.token, 30, '<b>secret reason</b>', 'c');
        assert.equal(ticks.length, 1);
        await ticks[0]();
        const alert = f.store.get<{kind: string; person_id: string; details: string}>("SELECT kind,person_id,details FROM parent_alerts WHERE kind='time_request_pending'");
        assert.ok(alert, 'a pending alert is recorded');
        assert.equal(alert.person_id, 'pilot');
        assert.ok(!alert.details.includes('secret'), 'no reason text in the alert');
        assert.equal(f.store.get<{n: number}>("SELECT count(*) AS n FROM parent_alerts WHERE kind<>'time_request_pending'")!.n, 0, 'no other alert kinds start reconciling on the real router');
    } finally {
        globalThis.setInterval = realSet;
        server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
        f.cleanup();
    }
});

test('the shared schedule view respects an active allowance', () => {
    const now = 1791691200;
    const policy = normalizePolicy({version: 1, revision: 1, people: [{id: 'pilot', macs: ['02:10:20:30:40:50']}], pauses: [],
        schedules: [{person: 'pilot', id: 'bed', weekdays: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], start: '00:00', stop: '23:59'}]});
    assert.equal(scheduleBlocked(policy, 'pilot', now), true);
    assert.equal(scheduleBlocked({...policy, allowances: [{person: 'pilot', until: now + 600}]}, 'pilot', now), false);
    assert.equal(scheduleBlocked({...policy, allowances: [{person: 'pilot', until: now}]}, 'pilot', now), true, 'an expired allowance is inert');
});
