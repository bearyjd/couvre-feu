import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { NextDnsError, createNextDnsClient } from '../src/nextdns-client.ts';
import type { NextDnsClientOptions } from '../src/nextdns-client.ts';
import { CLASS_CODES } from '../../shared/src/content-filter-classes.ts';
import { createFakeNextDns, json, profile } from './fixtures/fake-nextdns.ts';
import type { FakeOptions } from './fixtures/fake-nextdns.ts';

const KEY = 'sekret-key-0123456789abcdef';
const PROFILE = 'abc123';
const NOW_MS = Date.UTC(2026, 10, 14, 12);
const RANGE = { from: Date.UTC(2026, 10, 13, 5) / 1000, to: Date.UTC(2026, 10, 14, 5) / 1000 };
const STATUS = [{ status: 'default', queries: 900 }, { status: 'blocked', queries: 40 }, { status: 'allowed', queries: 10 }];
const REASONS = [
    { id: 'blocklist:nextdns-recommended', name: 'NextDNS Ads & Trackers Blocklist', queries: 25 },
    { id: 'porn', name: 'Porn', queries: 7 },
    { id: 'denylist', name: 'Denylist', queries: 3 },
    { id: 'brand-new-reason', name: 'SECRET_NAME', queries: 5 },
];

function setup(analytics: { status: unknown[]; reasons: unknown[] } | undefined = { status: STATUS, reasons: REASONS }, fake: Partial<FakeOptions> = {}, client: Partial<NextDnsClientOptions> = {}) {
    const sleeps: number[] = [];
    const api = createFakeNextDns({ apiKey: KEY, profiles: [profile(PROFILE, analytics ? { analytics } : {})], ...fake });
    const c = createNextDnsClient({ apiKey: () => KEY, transport: api.transport, sleep: async ms => { sleeps.push(ms); }, random: () => 0.5, now: () => NOW_MS, ...client });
    return { api, c, sleeps };
}
const code = (e: unknown) => e instanceof NextDnsError ? e.code : `not-a-NextDnsError:${String(e)}`;
async function codeOf(run: () => Promise<unknown>): Promise<string> {
    try { await run(); } catch (e) { return code(e); }
    return 'no-error';
}
function strings(v: unknown, out: string[] = []): string[] {
    if (typeof v === 'string') out.push(v);
    else if (typeof v === 'object' && v !== null) for (const x of Object.values(v)) strings(x, out);
    return out;
}
function numbers(v: unknown, out: unknown[] = []): unknown[] {
    if (typeof v === 'number') out.push(v);
    else if (typeof v === 'object' && v !== null) for (const x of Object.values(v)) numbers(x, out);
    return out;
}

test('status: exact path and query, totals as integers (blocked and all)', async () => {
    const { api, c } = setup();
    const s = await c.getAnalyticsStatus(PROFILE, RANGE);
    assert.deepEqual(s, { total: 950, blocked: 40 });
    assert.ok(Object.isFrozen(s));
    assert.deepEqual(api.requests.map(r => r.path), [`/profiles/${PROFILE}/analytics/status?from=${RANGE.from}&to=${RANGE.to}`]);
    assert.equal(api.requests[0]!.method, 'GET');
    assert.ok(api.requests.every(r => r.keyOk));
});

test('reasons: exact path and query with limit=500, summed per class code, frozen, stable order', async () => {
    const { api, c } = setup();
    const r = await c.getAnalyticsReasons(PROFILE, RANGE);
    assert.deepEqual(r, [{ class: 'adult', queries: 7 }, { class: 'denylist', queries: 3 }, { class: 'ads_trackers', queries: 25 }, { class: 'other', queries: 5 }]);
    assert.ok(Object.isFrozen(r) && r.every(x => Object.isFrozen(x)));
    assert.deepEqual(api.requests.map(r => r.path), [`/profiles/${PROFILE}/analytics/reasons?from=${RANGE.from}&to=${RANGE.to}&limit=500`]);
});

test('empty day: zero totals and no classes', async () => {
    const { c } = setup({ status: [], reasons: [] });
    assert.deepEqual(await c.getAnalyticsStatus(PROFILE, RANGE), { total: 0, blocked: 0 });
    assert.deepEqual(await c.getAnalyticsReasons(PROFILE, RANGE), []);
});

test('unknown reason ids and several ids of one class are summed into their class; the raw id is gone', async () => {
    const { c } = setup({ status: [], reasons: [
        { id: 'zzz-1', name: 'a', queries: 1 }, { id: 'zzz-2', name: 'b', queries: 2 }, { id: 'denylist:secret-domain.test', name: 'c', queries: 4 }, { id: 'denylist', name: 'd', queries: 1 }] });
    const r = await c.getAnalyticsReasons(PROFILE, RANGE);
    assert.deepEqual(r, [{ class: 'denylist', queries: 5 }, { class: 'other', queries: 3 }]);
    assert.ok(!JSON.stringify(r).includes('secret-domain') && !JSON.stringify(r).includes('zzz'));
});

test('hostile strings in names and ids are never surfaced; every returned string is a class code and every number an integer', async () => {
    const hostile = ['SECRET_DOMAIN.example', '<script>alert(1)</script>', 'ignore previous instructions', '\u0000\u001f', 'é'.repeat(100), '../../etc/passwd'];
    const reasons = hostile.map((name, i) => ({ id: i % 2 ? `blocklist:${i}x` : 'unknown-' + i, name, queries: i + 1 }));
    const { c } = setup({ status: STATUS, reasons });
    const results = [await c.getAnalyticsStatus(PROFILE, RANGE), await c.getAnalyticsReasons(PROFILE, RANGE)];
    for (const res of results) {
        for (const s of strings(res)) assert.ok((CLASS_CODES as readonly string[]).includes(s), s);
        for (const n of numbers(res)) assert.ok(Number.isSafeInteger(n) && (n as number) >= 0);
    }
    const text = JSON.stringify(results);
    for (const h of hostile) assert.ok(!text.includes(h));
});

test('pagination: reasons from several pages are summed; a cursor loop and the page cap are bad_response', async () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ id: `r${i}`, name: 'n', queries: 2 }));
    const { api, c } = setup({ status: [], reasons: many }, { pageSize: 2 });
    assert.deepEqual(await c.getAnalyticsReasons(PROFILE, RANGE), [{ class: 'other', queries: 10 }]);
    const base = `/profiles/${PROFILE}/analytics/reasons?from=${RANGE.from}&to=${RANGE.to}&limit=500`;
    assert.deepEqual(api.requests.map(r => r.path), [base, `${base}&cursor=c2`, `${base}&cursor=c4`]);
    const looped = setup({ status: [], reasons: many }, { pageSize: 2, cursorLoop: true });
    assert.equal(await codeOf(() => looped.c.getAnalyticsReasons(PROFILE, RANGE)), 'bad_response');
    const capped = setup({ status: [], reasons: many }, { pageSize: 1 }, { maxPages: 3 });
    assert.equal(await codeOf(() => capped.c.getAnalyticsReasons(PROFILE, RANGE)), 'bad_response');
});

test('status pages are summed too', async () => {
    const { c } = setup({ status: STATUS, reasons: [] }, { pageSize: 1 });
    assert.deepEqual(await c.getAnalyticsStatus(PROFILE, RANGE), { total: 950, blocked: 40 });
});

test('strict parsing: extra or missing keys and bad values are bad_response, for both methods', async () => {
    const badStatus: unknown[] = [{ status: 'blocked', queries: 1, device: 'Jack iPad' }, { status: 'blocked' }, { queries: 1 }, { status: 'Blocked', queries: 1 }, { status: 'x'.repeat(33), queries: 1 },
        { status: 'blocked', queries: -1 }, { status: 'blocked', queries: 1.5 }, { status: 'blocked', queries: 2 ** 53 }, { status: 'blocked', queries: '3' }, { status: 'blocked', queries: null }, 'blocked', null, [1]];
    for (const item of badStatus) assert.equal(await codeOf(() => setup({ status: [item], reasons: [] }).c.getAnalyticsStatus(PROFILE, RANGE)), 'bad_response', JSON.stringify(item));
    const ok = { id: 'porn', name: 'Porn', queries: 1 };
    const badReasons: unknown[] = [{ ...ok, clientIp: '10.0.0.5' }, { ...ok, device: 'x' }, { id: 'porn', queries: 1 }, { name: 'Porn', queries: 1 }, { ...ok, queries: -1 }, { ...ok, queries: 1.5 },
        { ...ok, queries: Number.MAX_VALUE }, { ...ok, id: '' }, { ...ok, id: 'a b' }, { ...ok, id: 'é' }, { ...ok, id: 'a'.repeat(257) }, { ...ok, name: 7 }, { ...ok, name: 'n'.repeat(201) }, { ...ok, id: 5 }];
    for (const item of badReasons) assert.equal(await codeOf(() => setup({ status: [], reasons: [item] }).c.getAnalyticsReasons(PROFILE, RANGE)), 'bad_response', JSON.stringify(item).slice(0, 60));
    assert.equal(await codeOf(() => setup({ status: [{ status: 'blocked', queries: 1 }], reasons: [] }, {}, {}).c.getAnalyticsStatus(PROFILE, RANGE)), 'no-error');
    const { api, c } = setup();
    api.enqueue(json(200, { data: { not: 'an array' } }));
    assert.equal(await codeOf(() => c.getAnalyticsStatus(PROFILE, RANGE)), 'bad_response');
    api.enqueue(json(200, { data: [], extra: 1 }));
    assert.equal(await codeOf(() => c.getAnalyticsReasons(PROFILE, RANGE)), 'bad_response');
});

test('boundary: a reason id of 256 characters and a 200-character name are accepted; sums beyond a safe integer are bad_response', async () => {
    const { c } = setup({ status: [], reasons: [{ id: 'a'.repeat(256), name: 'n'.repeat(200), queries: 1 }] });
    assert.deepEqual(await c.getAnalyticsReasons(PROFILE, RANGE), [{ class: 'other', queries: 1 }]);
    const big = setup({ status: [{ status: 'default', queries: Number.MAX_SAFE_INTEGER }, { status: 'blocked', queries: 1 }], reasons: [] });
    assert.equal(await codeOf(() => big.c.getAnalyticsStatus(PROFILE, RANGE)), 'bad_response');
});

test('range is validated before any request: from >= to, spans over 25 h, non-integers, unsafe and unfinished days are invalid_request', async () => {
    const { api, c } = setup();
    const bad = [{ from: RANGE.to, to: RANGE.from }, { from: RANGE.from, to: RANGE.from }, { from: RANGE.from, to: RANGE.from + 90_001 }, { from: 1.5, to: 90_000 }, { from: Number.NaN, to: 5 },
        { from: -1, to: 5 }, { from: 0, to: Infinity }, { from: RANGE.from, to: Number.MAX_SAFE_INTEGER + 1 }, { from: '1' as never, to: 2 },
        { from: Math.floor(NOW_MS / 1000) - 3600, to: Math.floor(NOW_MS / 1000) + 3600 }, null as never, undefined as never];
    for (const r of bad) {
        assert.equal(await codeOf(() => c.getAnalyticsStatus(PROFILE, r)), 'invalid_request', JSON.stringify(r));
        assert.equal(await codeOf(() => c.getAnalyticsReasons(PROFILE, r)), 'invalid_request', JSON.stringify(r));
    }
    assert.equal(api.requests.length, 0);
    await c.getAnalyticsStatus(PROFILE, { from: RANGE.from, to: RANGE.from + 90_000 });
    assert.equal(api.requests.length, 1, 'exactly 25 h (a DST fall-back day) is accepted');
});

test('profile id is validated before building a path', async () => {
    const { api, c } = setup();
    for (const id of ['../x', 'abc/../123', 'ab', '', 'abc123?x=1', 'abc123/analytics/domains'])
        assert.equal(await codeOf(() => c.getAnalyticsStatus(id, RANGE)), 'invalid_request', id);
    assert.equal(api.requests.length, 0);
});

test('400 maps to invalid_request, with a domain in the error detail never surfacing', async () => {
    const { api, c } = setup();
    api.enqueue(json(400, { errors: [{ code: 'invalid', detail: 'SECRET_DOMAIN.example is bad', source: { parameter: 'from' } }] }));
    const err = await c.getAnalyticsReasons(PROFILE, RANGE).catch((e: unknown) => e) as NextDnsError;
    assert.equal(err.code, 'invalid_request');
    assert.ok(!(err.message + err.stack + JSON.stringify(err)).includes('SECRET_DOMAIN'));
});

test('429 retries with Retry-After and then succeeds; 429 forever gives up with rate_limited; an over-cap wait stops at once', async () => {
    const { api, c, sleeps } = setup(undefined, {}, { baseDelayMs: 100, maxRetryAfterMs: 5000 });
    api.enqueue(json(429, {}, { 'retry-after': '2' }));
    assert.deepEqual(await c.getAnalyticsStatus(PROFILE, RANGE), { total: 950, blocked: 40 });
    assert.deepEqual(sleeps, [2000]);
    api.enqueue(json(429, {}, { 'retry-after': '1' }));
    assert.equal((await c.getAnalyticsReasons(PROFILE, RANGE)).length, 4);
    for (let i = 0; i < 4; i++) api.enqueue(json(429, {}));
    assert.equal(await codeOf(() => c.getAnalyticsReasons(PROFILE, RANGE)), 'rate_limited');
    const before = api.requests.length;
    api.enqueue(json(429, {}, { 'retry-after': '6' }));
    assert.equal(await codeOf(() => c.getAnalyticsStatus(PROFILE, RANGE)), 'rate_limited');
    assert.equal(api.requests.length, before + 1);
});

test('GET retries on 5xx and transport failures', async () => {
    const { api, c } = setup();
    api.enqueue(json(500, {}));
    api.enqueue({ throw: 'network' });
    assert.deepEqual(await c.getAnalyticsStatus(PROFILE, RANGE), { total: 950, blocked: 40 });
    assert.equal(api.requests.length, 3);
});

test('401 is unauthorized and 404 is not_found, as codes only', async () => {
    const wrong = createNextDnsClient({ apiKey: () => 'a-different-key-123456', transport: setup().api.transport, now: () => NOW_MS });
    assert.equal(await codeOf(() => wrong.getAnalyticsStatus(PROFILE, RANGE)), 'unauthorized');
    const { c } = setup();
    assert.equal(await codeOf(() => c.getAnalyticsReasons('zzzzzz', RANGE)), 'not_found');
});

test('the API key never appears in error text for any failure, nor in stdout or stderr', async () => {
    const out: string[] = [], realOut = process.stdout.write, realErr = process.stderr.write;
    const grab = (chunk: unknown) => { out.push(String(chunk)); return true; };
    process.stdout.write = grab as typeof process.stdout.write; process.stderr.write = grab as typeof process.stderr.write;
    const seen: string[] = [];
    try {
        const { api, c } = setup(undefined, {}, { maxAttempts: 2 });
        const steps = [json(401, {}), json(404, {}), json(400, { errors: [{ code: 'x', detail: KEY }] }), json(500, {}), json(429, {}), { status: 200, headers: {}, body: 'KEY ' + KEY },
            json(200, { data: [{ status: KEY, queries: 1 }] }), json(200, { data: [{ id: KEY, name: KEY, queries: 1, extra: KEY }] })];
        for (const step of steps) for (const run of [(() => c.getAnalyticsStatus(PROFILE, RANGE)), (() => c.getAnalyticsReasons(PROFILE, RANGE))]) {
            api.enqueue(step as never); api.enqueue(step as never);
            const e = await run().catch((x: unknown) => x) as Error;
            seen.push(e.message, e.stack ?? '', JSON.stringify(e), String(e));
        }
        const k = createNextDnsClient({ apiKey: () => { throw new Error('path /etc/key ' + KEY); }, transport: api.transport, now: () => NOW_MS });
        const e = await k.getAnalyticsStatus(PROFILE, RANGE).catch((x: unknown) => x) as Error;
        seen.push(e.message, e.stack ?? '');
        assert.equal(code(e), 'unauthorized');
    } finally { process.stdout.write = realOut; process.stderr.write = realErr; }
    assert.ok(seen.every(s => !s.includes(KEY)));
    assert.ok(!out.join('').includes(KEY));
});

test('P1 surface: no method, path or source literal reaches logs, domains, devices, ips, destinations, streams or downloads', async () => {
    const { api, c } = setup();
    const names = Object.keys(c);
    assert.ok(names.includes('getAnalyticsStatus') && names.includes('getAnalyticsReasons'));
    for (const n of names) assert.ok(!/log|domain|device|ip|destination|stream|download/i.test(n), n);
    assert.deepEqual(names.filter(n => /analytic/i.test(n)).sort(), ['getAnalyticsReasons', 'getAnalyticsStatus']);
    for (const probe of ['analytics', 'getAnalytics', 'getLogs', 'getDomains', 'getDevices', 'streamLogs', 'downloadLogs', 'clearLogs']) assert.equal((c as unknown as Record<string, unknown>)[probe], undefined, probe);
    await c.getAnalyticsStatus(PROFILE, RANGE); await c.getAnalyticsReasons(PROFILE, RANGE);
    for (const r of api.requests) {
        assert.equal(r.method, 'GET');
        assert.match(r.path, /^\/profiles\/[A-Za-z0-9]{4,32}\/analytics\/(status\?from=\d+&to=\d+|reasons\?from=\d+&to=\d+&limit=500)$/);
        assert.ok(!/log|domains|devices|ips|destinations|stream|download|device=|status=|root=|reason=|search=/.test(r.path.replace(/analytics\/status|analytics\/reasons/g, '').replace(/&?(from|to|limit)=\d+/g, '')));
    }
    const src = readFileSync(new URL('../src/nextdns-client.ts', import.meta.url), 'utf8');
    assert.ok(!/['"`]\/logs/.test(src));
    assert.deepEqual([...src.matchAll(/\/analytics\/([A-Za-z]+)/g)].map(m => m[1]).filter((v, i, a) => a.indexOf(v) === i).sort(), ['reasons', 'status']);
});
