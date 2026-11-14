import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture } from './fixtures/integration.ts';
import { createFakeNextDns, json, profile, SETTINGS } from './fixtures/fake-nextdns.ts';
import { createNextDnsClient } from '../src/nextdns-client.ts';
import type { Transport } from '../src/nextdns-client.ts';
import { wireContentFilter } from '../src/content-filter-wiring.ts';
import { wireIntegration } from '../src/integration-wiring.ts';
import { addDays, dayRange, localDay, localDayBounds } from '../src/content-filter-day.ts';
import { COUNTS_RETENTION_DAYS, COUNTS_WINDOW_DAYS, ContentFilterCounts, ContentFilterCountsStore, startContentFilterCounts } from '../src/content-filter-counts.ts';
import type { ContentFilterCountsOptions } from '../src/content-filter-counts.ts';
import type { IntegrationConfig } from '../src/integration-config.ts';

const KEY = 'test-api-key-0123456789';
const PILOT = 'abc123', BLAKE = 'def456', DEFAULT = 'dflt01';
const PROFILES = {pilot: PILOT, blake: BLAKE};
/** 2026-11-14 10:00 in New York (EST). Seven finished local days: 2026-11-07 .. 2026-11-13. */
const T0 = Date.UTC(2026, 10, 14, 15) / 1000;
const FIRST = '2026-11-07', LAST = '2026-11-13';
const STATUS = [{status: 'default', queries: 900}, {status: 'blocked', queries: 40}, {status: 'allowed', queries: 10}];
const REASONS = [{id: 'blocklist:nextdns-recommended', name: 'Ads', queries: 25}, {id: 'porn', name: 'Porn', queries: 7}, {id: 'denylist', name: 'Denylist', queries: 3}, {id: 'brand-new', name: 'New', queries: 5}];
const CLASSES = {adult: 7, denylist: 3, ads_trackers: 25, other: 5};
const logsOn = () => ({...structuredClone(SETTINGS), logs: {...SETTINGS.logs, enabled: true}});
const fail500 = (detail = 'Server free text') => json(500, {errors: [{code: 'boom', detail}]});

interface Over { wrap?: (next: Transport) => Transport; analytics?: {status: unknown[]; reasons: unknown[]}; options?: Partial<ContentFilterCountsOptions>; t?: number }
function world(over: Over = {}) {
    const f = integrationFixture(), clock = {t: over.t ?? T0};
    const analytics = over.analytics ?? {status: STATUS, reasons: REASONS};
    const fake = createFakeNextDns({apiKey: KEY, profiles: [PILOT, BLAKE, DEFAULT].map(id => profile(id, {settings: logsOn(), analytics}))});
    const transport: Transport = over.wrap ? over.wrap(fake.transport) : fake.transport;
    const client = createNextDnsClient({apiKey: () => KEY, transport, sleep: async () => undefined, random: () => 0, baseDelayMs: 0, maxDelayMs: 0, now: () => clock.t * 1000});
    const store = new ContentFilterCountsStore(f.store);
    const counts = new ContentFilterCounts({client, profiles: PROFILES, store, now: () => clock.t, ...over.options});
    const analyticsRequests = () => fake.requests.filter(r => r.path.includes('/analytics/'));
    const range = (r: {path: string}) => { const q = new URL(r.path, 'https://x').searchParams; return {from: Number(q.get('from')), to: Number(q.get('to'))}; };
    const rows = (person = 'pilot') => store.days(person, '2026-01-01', '2027-01-01');
    const dump = () => JSON.stringify([f.store.all('SELECT * FROM content_filter_day ORDER BY person_id, day'), f.store.all('SELECT * FROM content_filter_day_class ORDER BY person_id, day, class')]);
    return {...f, db: f.store, clock, fake, client, store, counts, analyticsRequests, range, rows, dump};
}
/** Runs `work` and returns everything written to stdout and stderr meanwhile. */
async function captured(work: () => Promise<unknown>): Promise<string> {
    const out: string[] = [], o = process.stdout.write, e = process.stderr.write;
    process.stdout.write = ((chunk: unknown) => { out.push(String(chunk)); return true; }) as typeof process.stdout.write;
    process.stderr.write = ((chunk: unknown) => { out.push(String(chunk)); return true; }) as typeof process.stderr.write;
    try { await work(); } finally { process.stdout.write = o; process.stderr.write = e; }
    return out.join('');
}

test('the window is seven days and the first pass backfills them oldest first, status then reasons, with exact local-day ranges', async () => {
    const s = world();
    try {
        assert.equal(COUNTS_WINDOW_DAYS, 7);
        await s.counts.tick();
        const expected = dayRange(FIRST, LAST).flatMap(day => ['status', 'reasons'].map(kind => ({kind, ...localDayBounds(day)})));
        const mine = (profileId: string) => s.analyticsRequests().filter(r => r.path.startsWith(`/profiles/${profileId}/`));
        for (const profileId of [PILOT, BLAKE]) {
            assert.deepEqual(mine(profileId).map(r => ({kind: r.path.includes('/status') ? 'status' : 'reasons', ...s.range(r)})), expected);
        }
        assert.deepEqual(s.rows('pilot').map(d => d.day), dayRange(FIRST, LAST));
        for (const day of s.rows('pilot')) assert.deepEqual(day, {day: day.day, state: 'ok', total: 950, blocked: 40, classes: CLASSES});
        assert.equal(s.rows('blake').length, 7);
        assert.ok(s.fake.requests.every(r => r.method === 'GET'), 'read-only');
    } finally { s.cleanup(); }
});

test('a finished day is final: a second pass makes no request and changes nothing, even if NextDNS now answers differently or fails', async () => {
    const s = world();
    try {
        await s.counts.tick();
        const before = s.dump(), requests = s.fake.requests.length;
        s.fake.profiles.get(PILOT)!.analytics = {status: [{status: 'blocked', queries: 1}], reasons: []};
        await s.counts.tick();
        assert.equal(s.fake.requests.length, requests, 'not even a settings read');
        assert.equal(s.dump(), before);
    } finally { s.cleanup(); }
});

test('today is never stored and nothing is requested past the end of the last finished day', async () => {
    const s = world();
    try {
        await s.counts.tick();
        assert.ok(s.rows('pilot').every(d => d.day <= LAST));
        const end = localDayBounds(LAST).to;
        assert.ok(s.analyticsRequests().every(r => s.range(r).to <= end));
        assert.equal(localDay(T0), '2026-11-14');
    } finally { s.cleanup(); }
});

test('a day is not read before 03:00 local time on the next day (settling margin), then it is', async () => {
    const before = world({t: Date.UTC(2026, 10, 14, 7, 59, 59) / 1000});
    try {
        await before.counts.tick();
        assert.ok(before.rows('pilot').every(d => d.day < LAST), 'the day that ended at midnight is still settling at 02:59:59');
        assert.deepEqual(before.rows('pilot').map(d => d.day), dayRange(FIRST, addDays(LAST, -1)));
        before.clock.t = Date.UTC(2026, 10, 14, 8) / 1000;
        await before.counts.tick();
        assert.ok(before.rows('pilot').some(d => d.day === LAST));
    } finally { before.cleanup(); }
});

test('days older than the window are not attempted, even when they have a gap', async () => {
    const s = world();
    try {
        s.store.markUnavailable('pilot', '2026-11-05', 1);
        await s.counts.tick();
        const oldest = localDayBounds(FIRST).from;
        assert.ok(s.analyticsRequests().every(r => s.range(r).from >= oldest));
        assert.deepEqual(s.store.days('pilot', '2026-11-05', '2026-11-05').map(d => [d.state]), [['unavailable']]);
        assert.equal(s.store.days('pilot', '2026-11-05', '2026-11-05')[0] !== undefined, true);
    } finally { s.cleanup(); }
});

test('DST: the 23 h and 25 h days are exact ranges of one row each', async () => {
    const spring = world({t: Date.UTC(2026, 2, 10, 16) / 1000}), fall = world({t: Date.UTC(2026, 10, 3, 17) / 1000});
    try {
        await spring.counts.tick(); await fall.counts.tick();
        const span = (w: typeof spring, day: string) => { const b = localDayBounds(day); return w.analyticsRequests().filter(r => w.range(r).from === b.from && w.range(r).to === b.to).length; };
        assert.equal(spring.rows('pilot').length, 7);
        assert.equal(span(spring, '2026-03-08'), 4, 'status and reasons for both children');
        assert.equal(localDayBounds('2026-03-08').to - localDayBounds('2026-03-08').from, 23 * 3600);
        assert.equal(fall.rows('pilot').length, 7);
        assert.equal(span(fall, '2026-11-01'), 4);
        assert.equal(localDayBounds('2026-11-01').to - localDayBounds('2026-11-01').from, 25 * 3600);
        assert.ok(fall.rows('pilot').some(d => d.day === '2026-11-01'));
    } finally { spring.cleanup(); fall.cleanup(); }
});

test('an unavailable day is retried and becomes ok; a failed pass leaves no partial day (status answered, reasons failed)', async () => {
    let broken = true;
    const s = world({wrap: next => async req => broken && req.path.includes('/analytics/reasons') ? fail500('SECRET_DOMAIN is down') : next(req)});
    try {
        await s.counts.tick();
        for (const person of ['pilot', 'blake']) {
            assert.deepEqual(s.rows(person), [{day: FIRST, state: 'unavailable', total: null, blocked: null, classes: {}}], 'status alone is never stored: the oldest day is a gap, the rest untried');
        }
        assert.equal(s.db.get<{n: number}>('SELECT count(*) n FROM content_filter_day_class')!.n, 0);
        assert.equal(s.db.get<{n: number}>('SELECT attempts n FROM content_filter_day WHERE person_id=?', 'pilot')!.n, 1);
        broken = false;
        await s.counts.tick();
        assert.deepEqual(s.rows('pilot').map(d => d.state), Array(7).fill('ok'));
        assert.equal(s.rows('pilot')[0]!.total, 950);
    } finally { s.cleanup(); }
});

test('one child failing does not stop the others, and the failing child stops after its first gap', async () => {
    const tried: string[] = [];
    const s = world({wrap: next => async req => { if (!req.path.startsWith(`/profiles/${PILOT}/`) || !req.path.includes('/analytics/')) return next(req); tried.push(req.path); return fail500(); }});
    try {
        await s.counts.tick();
        assert.deepEqual(s.rows('pilot').map(d => [d.day, d.state]), [[FIRST, 'unavailable']]);
        assert.deepEqual(s.rows('blake').map(d => d.state), Array(7).fill('ok'));
        assert.equal(new Set(tried.map(path => s.range({path}).from)).size, 1, 'one day tried, then the child is left until the next pass');
    } finally { s.cleanup(); }
});

test('429: the pass ends early and quietly, resumes on the next tick, and raises no alert', async () => {
    let throttled = true;
    const s = world({wrap: next => async req => throttled && req.path.includes('/analytics/') ? json(429, {errors: [{code: 'rate'}]}, {'retry-after': '0'}) : next(req)});
    try {
        const out = await captured(() => s.counts.tick());
        assert.equal(out, '');
        assert.deepEqual(s.rows('pilot').map(d => [d.day, d.state]), [[FIRST, 'unavailable']]);
        assert.deepEqual(s.rows('blake'), [], 'the pass ended: the second child was not even tried');
        assert.ok(s.fake.requests.every(r => !r.path.includes(BLAKE)));
        assert.equal(s.db.get<{n: number}>('SELECT count(*) n FROM parent_alerts')!.n, 0);
        throttled = false;
        await s.counts.tick();
        assert.deepEqual(s.rows('pilot').map(d => d.state), Array(7).fill('ok'));
        assert.deepEqual(s.rows('blake').map(d => d.state), Array(7).fill('ok'));
    } finally { s.cleanup(); }
});

test('NextDNS down, a rejected key and a garbled answer all fail quietly: no output, no alert, only a gap', async () => {
    const modes: ((next: Transport) => Transport)[] = [
        next => async req => { void next; if (req.path) throw new Error('ECONNRESET'); return next(req); },
        next => async req => req.path.includes('/settings') ? json(401, {errors: [{code: 'authRequired', detail: 'SECRET_DOMAIN'}]}) : next(req),
        next => async req => req.path.includes('/analytics/status') ? {status: 200, headers: {}, body: '<html>SECRET_DOMAIN'} : next(req),
        next => async req => req.path.includes('/analytics/status') ? json(200, {data: [{status: 'blocked', queries: -4}]}) : next(req),
    ];
    for (const wrap of modes) {
        const s = world({wrap});
        try {
            const out = await captured(() => s.counts.tick());
            assert.equal(out, '');
            assert.deepEqual(s.rows('pilot').map(d => d.state), ['unavailable']);
            assert.equal(s.db.get<{n: number}>('SELECT count(*) n FROM content_filter_day_class')!.n, 0);
            assert.equal(s.db.get<{n: number}>('SELECT count(*) n FROM parent_alerts')!.n, 0);
            assert.equal(s.db.get<{n: number}>('SELECT count(*) n FROM parent_audit')!.n, 0);
        } finally { s.cleanup(); }
    }
});

test('a pass that runs out of its time budget stops, and the next tick continues where it left off', async () => {
    const ms = {now: 0};
    const s = world({options: {monotonicMs: () => ms.now}, wrap: next => async req => { if (req.path.includes('/analytics/')) ms.now += 20_000; return next(req); }});
    try {
        await s.counts.tick();
        assert.deepEqual(s.rows('pilot').map(d => d.day), [FIRST, addDays(FIRST, 1)], 'two days of 40 s each, then the 60 s budget is spent');
        assert.deepEqual(s.rows('blake'), []);
        ms.now = 0;
        s.fake.requests.length = 0;
        await s.counts.tick();
        assert.equal(s.rows('pilot').length + s.rows('blake').length > 2, true);
        for (let i = 0; i < 6; i++) { ms.now = 0; await s.counts.tick(); }
        assert.deepEqual([s.rows('pilot').length, s.rows('blake').length], [7, 7]);
    } finally { s.cleanup(); }
});

test('the default profile and children without a profile are never requested', async () => {
    const s = world({options: {profiles: {pilot: PILOT}}});
    try {
        await s.counts.tick();
        assert.ok(s.fake.requests.length > 0);
        assert.ok(s.fake.requests.every(r => r.path.startsWith(`/profiles/${PILOT}/`)), 'only the one configured child');
        assert.ok(s.fake.requests.every(r => !r.path.includes(DEFAULT) && !r.path.includes(BLAKE)));
        assert.deepEqual(s.rows('blake'), []);
    } finally { s.cleanup(); }
    const none = world({options: {profiles: {}}});
    try { await none.counts.tick(); assert.equal(none.fake.requests.length, 0); assert.equal(none.dump(), '[[],[]]'); } finally { none.cleanup(); }
});

test('logs turned off in NextDNS: logs_off for each settled day, and no analytics call', async () => {
    const s = world();
    try {
        s.fake.profiles.get(PILOT)!.settings = structuredClone(SETTINGS);
        await s.counts.tick();
        assert.deepEqual(s.rows('pilot').map(d => [d.state, d.total, d.blocked]), Array(7).fill(['logs_off', null, null]));
        assert.ok(s.analyticsRequests().every(r => !r.path.includes(PILOT)));
        assert.equal(s.fake.requests.filter(r => r.path === `/profiles/${PILOT}/settings`).length, 1, 'settings read once per pass');
        assert.deepEqual(s.rows('blake').map(d => d.state), Array(7).fill('ok'));
    } finally { s.cleanup(); }
});

test('zero lookups while the device was online is suspect_zero, never "0 blocked"; otherwise an honest ok with zeros', async () => {
    const s = world({analytics: {status: [], reasons: []}, options: {wasOnline: (person, day) => person === 'pilot' && day === '2026-11-09'}});
    try {
        await s.counts.tick();
        assert.deepEqual(s.rows('pilot').map(d => [d.day, d.state, d.total, d.blocked]).filter(r => r[1] === 'suspect_zero'), [['2026-11-09', 'suspect_zero', 0, 0]]);
        assert.deepEqual(s.rows('pilot').filter(d => d.state === 'ok').length, 6);
        assert.deepEqual(s.rows('blake').map(d => d.state), Array(7).fill('ok'));
        assert.deepEqual(s.rows('blake')[0], {day: FIRST, state: 'ok', total: 0, blocked: 0, classes: {}});
    } finally { s.cleanup(); }
    const throwing = world({analytics: {status: [], reasons: []}, options: {wasOnline: () => { throw new Error('activity store down'); }}});
    try { await throwing.counts.tick(); assert.deepEqual(throwing.rows('pilot').map(d => d.state), Array(7).fill('ok')); } finally { throwing.cleanup(); }
    const busy = world({options: {wasOnline: () => true}});
    try { await busy.counts.tick(); assert.deepEqual(busy.rows('pilot').map(d => d.state), Array(7).fill('ok'), 'a non-zero total is never suspect'); } finally { busy.cleanup(); }
});

test('prune: days older than the retention are deleted at the end of each pass, the boundary day is kept', async () => {
    const s = world();
    try {
        assert.equal(COUNTS_RETENTION_DAYS, 56);
        const today = localDay(T0), keep = addDays(today, -COUNTS_RETENTION_DAYS), drop = addDays(today, -COUNTS_RETENTION_DAYS - 1);
        for (const day of [keep, drop]) { s.store.put('pilot', {day, state: 'ok', total: 5, blocked: 1, classes: {adult: 1}}, 1); s.store.put('blake', {day, state: 'ok', total: 5, blocked: 1, classes: {adult: 1}}, 1); }
        await s.counts.tick();
        assert.ok(s.rows('pilot').some(d => d.day === keep) && s.rows('pilot').every(d => d.day !== drop));
        assert.ok(s.rows('blake').every(d => d.day !== drop));
        assert.equal(s.fake.requests.length > 0, true);
        assert.equal(s.dump().includes(drop), false, 'class rows went with the day');
    } finally { s.cleanup(); }
});

test('prune still runs when the pass could not reach NextDNS', async () => {
    const s = world({wrap: () => async () => { throw new Error('ECONNRESET'); }});
    try {
        s.store.put('pilot', {day: addDays(localDay(T0), -100), state: 'ok', total: 5, blocked: 1, classes: {adult: 1}}, 1);
        await s.counts.tick();
        assert.ok(s.rows('pilot').every(d => d.day >= addDays(localDay(T0), -COUNTS_RETENTION_DAYS)));
    } finally { s.cleanup(); }
});

test('two overlapping ticks do the work of one', async () => {
    const s = world();
    try {
        await Promise.all([s.counts.tick(), s.counts.tick()]);
        assert.equal(s.analyticsRequests().length, 2 * 7 * 2);
        assert.equal(s.rows('pilot').length, 7);
    } finally { s.cleanup(); }
});

test('the timer runs ticks and stop() ends them; the timers never keep the process alive', async () => {
    const s = world();
    try {
        const stop = startContentFilterCounts(s.counts, 5, 1);
        await new Promise(resolve => setTimeout(resolve, 60));
        stop();
        assert.equal(s.rows('pilot').length, 7);
        const seen = s.fake.requests.length;
        s.store.markUnavailable('pilot', '2026-11-12', 1);
        await new Promise(resolve => setTimeout(resolve, 40));
        assert.equal(s.fake.requests.length, seen, 'stopped');
        const cold = world(), idle = startContentFilterCounts(cold.counts, 10_000, 10_000);
        idle();
        assert.equal(cold.fake.requests.length, 0);
        cold.cleanup();
    } finally { s.cleanup(); }
});

test('privacy (G7): hostile reason ids, names and error text never reach the tables, stdout or stderr, alerts or audit rows', async () => {
    const hostile = [{id: 'denylist:SECRET_DOMAIN.example', name: 'SECRET_DOMAIN name', queries: 3}, {id: 'SECRET_DOMAIN-unknown', name: 'DEVICE_SENTINEL', queries: 2},
        {id: 'blocklist:SECRET_DOMAIN', name: 'x', queries: 4}, {id: 'porn', name: 'SECRET_DOMAIN', queries: 1}];
    const s = world({analytics: {status: STATUS, reasons: hostile}, wrap: next => async req => req.path.startsWith(`/profiles/${BLAKE}/`) && req.path.includes('/analytics/reasons') ? fail500(`SECRET_DOMAIN DEVICE_SENTINEL ${BLAKE} ${KEY}`) : next(req)});
    try {
        const out = await captured(() => s.counts.tick());
        const haystack = [out, s.dump(), JSON.stringify(s.db.all('SELECT * FROM parent_alerts')), JSON.stringify(s.db.all('SELECT * FROM parent_audit'))].join('\n');
        for (const secret of ['SECRET_DOMAIN', 'DEVICE_SENTINEL', 'secret_domain', PILOT, BLAKE, DEFAULT, KEY, 'nextdns', 'api.nextdns']) assert.equal(haystack.includes(secret), false, secret);
        assert.deepEqual(s.rows('pilot')[0]!.classes, {adult: 1, denylist: 3, ads_trackers: 4, other: 2});
    } finally { s.cleanup(); }
});

// ---- wiring: the flag ----
const setting = (counts?: {enabled: boolean}, mode: 'off' | 'owner' = 'owner'): NonNullable<IntegrationConfig['contentFilter']> =>
    ({mode, apiKeyFile: '/nonexistent-dir/never-read.key', defaultProfile: DEFAULT, profiles: PROFILES, ...(counts ? {counts} : {})});

test('flag off: absent, enabled false and mode off build no fetcher, start no timer, and make no NextDNS call', async () => {
    const f = integrationFixture();
    try {
        const fake = createFakeNextDns({apiKey: KEY, profiles: [profile(PILOT, {settings: logsOn(), analytics: {status: STATUS, reasons: REASONS}})]});
        for (const contentFilter of [setting(), setting({enabled: false}), setting({enabled: true}, 'off')]) {
            f.config.contentFilter = contentFilter;
            const wired = wireContentFilter(f.config, f.store, {}, undefined, {transport: fake.transport, apiKey: () => KEY});
            assert.equal(wired?.counts ?? null, null, JSON.stringify(contentFilter));
            const integration = wireIntegration(f.config, f.store, f.router, {});
            assert.equal(integration.startCounts(), null);
        }
        await new Promise(resolve => setTimeout(resolve, 20));
        assert.equal(fake.requests.length, 0, 'the fake server saw nothing');
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM content_filter_day')!.n, 0);
    } finally { f.cleanup(); }
});

test('flag on: the fetcher is built over the manifest profiles and the wired client, and a pass stores finished days', async () => {
    const f = integrationFixture();
    try {
        const fake = createFakeNextDns({apiKey: KEY, profiles: [profile(PILOT, {settings: logsOn(), analytics: {status: STATUS, reasons: REASONS}})]});
        f.config.contentFilter = {...setting({enabled: true}), profiles: {pilot: PILOT}};
        const wired = wireContentFilter(f.config, f.store, {}, undefined, {transport: fake.transport, apiKey: () => KEY});
        assert.ok(wired?.counts);
        await wired.counts.tick();
        const rows = f.store.all<{day: string; state: string}>("SELECT day,state FROM content_filter_day WHERE person_id='pilot'");
        assert.ok(rows.length >= 6 && rows.every(r => r.state === 'ok'));
        assert.ok(fake.requests.every(r => r.path.startsWith(`/profiles/${PILOT}/`)));
        const stop = wireIntegration(f.config, f.store, f.router, {}).startCounts();
        assert.equal(typeof stop, 'function'); stop!();
    } finally { f.cleanup(); }
});
