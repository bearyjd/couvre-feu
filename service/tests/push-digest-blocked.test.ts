import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import type { IncomingMessage, Server } from 'node:http';
import { integrationFixture } from './fixtures/integration.ts';
import { CLASS_CODES } from '../../shared/src/content-filter-classes.ts';
import { dayRange } from '../src/content-filter-day.ts';
import { ContentFilterCountsStore } from '../src/content-filter-counts.ts';
import type { DayCounts } from '../src/content-filter-counts.ts';
import { householdWeek } from '../src/digest-blocked.ts';
import { digestTick } from '../src/digest.ts';
import { pushText } from '../src/push-sender.ts';
import { startNotifications, weeklyCounts } from '../src/push-runtime.ts';
import type { ContentFilterConfig } from '../src/content-filter-config.ts';

const TOPIC = 'couvre_topic_abc123456789', TOKEN = 'tk_secrettoken123456';
const HOSTILE_A = 'zed-bobby-the-hostile', HOSTILE_B = 'quinn-secret-child';
const BASE = 'Last 7 days: 0 requests, 0 grants, 0 pauses.';
const utc = (...a: [number, number, number, number, number?]) => Date.UTC(a[0], a[1] - 1, a[2], a[3], a[4] ?? 0) / 1000;
const SLOT = utc(2026, 11, 8, 23); // Sunday 2026-11-08 18:00 EST; the week is Sun 11-01 (a 25 hour day) to Sat 11-07
const WEEK = dayRange('2026-11-01', '2026-11-07');
const okDay = (day: string, classes: DayCounts['classes'] = {adult: 2, social: 1, ads_trackers: 500, security: 9}): DayCounts => ({day, state: 'ok', total: 1000, blocked: 3, classes});
const suspect = (day: string): DayCounts => ({day, state: 'suspect_zero', total: 0, blocked: 0, classes: {}});
const logsOff = (day: string): DayCounts => ({day, state: 'logs_off', total: null, blocked: null, classes: {}});
const filter = (counts: boolean | undefined): ContentFilterConfig => ({mode: 'owner', apiKeyFile: '/etc/x/key', defaultProfile: 'abcd1234', profiles: {[HOSTILE_A]: 'abcd0001', [HOSTILE_B]: 'abcd0002'}, ...(counts === undefined ? {} : {counts: {enabled: counts}})});

function world() {
    const f = integrationFixture(), counts = new ContentFilterCountsStore(f.store), people = [HOSTILE_A, HOSTILE_B];
    const fill = (days: readonly string[], make: (day: string) => DayCounts = okDay, who: readonly string[] = people) => { for (const person of who) for (const day of days) counts.put(person, make(day), 1); };
    const week = (slot = SLOT) => householdWeek(counts, people, slot);
    return {...f, counts, people, fill, week};
}
async function fakeNtfy() {
    const seen: {url: string; headers: IncomingMessage['headers']; body: string}[] = [];
    const server: Server = createServer((req, res) => {
        let body = ''; req.on('data', chunk => { body += chunk; });
        req.on('end', () => { seen.push({url: req.url!, headers: req.headers, body}); res.statusCode = 200; res.end('{}'); });
    });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const url = `http://127.0.0.1:${(server.address() as {port: number}).port}`;
    return {seen, env: {COUVRE_NTFY_URL: url, COUVRE_NTFY_TOPIC: TOPIC, COUVRE_NTFY_TOKEN: TOKEN}, close: () => { server.closeAllConnections(); server.close(); }};
}
const text = (blocked?: {count: number; daysCounted: number}) => pushText({kind: 'digest', counts: {requests: 0, grants: 0, pauses: 0, ...(blocked ? {blocked} : {})}});

test('exact strings: absent, full week, partial week, zero counted days', () => {
    assert.deepEqual(text(), {title: 'Couvre-feu weekly summary', body: BASE});
    assert.equal(text({count: 63, daysCounted: 7}).body, `${BASE}\n63 blocked lookups last week.`);
    assert.equal(text({count: 63, daysCounted: 5}).body, `${BASE}\n63 blocked lookups last week (5 of 7 days counted).`);
    assert.equal(text({count: 0, daysCounted: 7}).body, `${BASE}\n0 blocked lookups last week.`);
    assert.equal(text({count: 63, daysCounted: 0}).body, BASE, 'no counted day: the line is omitted');
    assert.equal(text({count: -4, daysCounted: 99}).body, `${BASE}\n0 blocked lookups last week.`, 'coerced like the other numbers');
    assert.equal(text({count: 1, daysCounted: 7}).title, 'Couvre-feu weekly summary', 'counts never reach the title');
});

test('the line is words and integers only, and never uses the forbidden verbs or a class word', () => {
    const body = text({count: 12345, daysCounted: 3}).body;
    assert.match(body, /^[A-Za-z0-9 ,.:()\n-]+$/);
    assert.ok(!/monitor|catch|track|spy|watch/i.test(body));
    for (const code of CLASS_CODES) assert.ok(!new RegExp(`\\b${code}\\b`, 'i').test(body), code);
});

test('householdWeek: a full week sums headline classes of every child, never background classes', () => {
    const w = world();
    try {
        w.fill(WEEK);
        // per child per day: adult 2 + social 1 = 3 headline; ads_trackers and security excluded; 2 children, 7 days
        assert.deepEqual(w.week(), {count: 3 * 2 * 7, daysCounted: 7});
    } finally { w.cleanup(); }
});

test('partial week: days without an ok answer are not counted, and the number reflects only counted days', () => {
    const w = world();
    try {
        w.fill(WEEK.slice(0, 5));
        assert.deepEqual(w.week(), {count: 3 * 2 * 5, daysCounted: 5});
        assert.equal(text(w.week()).body, `${BASE}\n30 blocked lookups last week (5 of 7 days counted).`);
    } finally { w.cleanup(); }
});

test('zero counted days: no line at all', () => {
    const w = world();
    try {
        assert.deepEqual(w.week(), {count: 0, daysCounted: 0});
        w.fill(WEEK.slice(0, 3), suspect); w.fill(WEEK.slice(3, 5), logsOff);
        w.counts.markUnavailable(HOSTILE_A, WEEK[5]!, 1);
        const week = w.week();
        assert.equal(week.daysCounted, 0);
        assert.equal(text(week).body, BASE);
    } finally { w.cleanup(); }
});

test('suspect_zero, logs_off and gap days do not count', () => {
    const w = world();
    try {
        w.fill(WEEK.slice(0, 4));
        w.fill([WEEK[4]!], suspect); w.fill([WEEK[5]!], logsOff);
        // WEEK[6] has no row for anyone
        assert.deepEqual(w.week(), {count: 3 * 2 * 4, daysCounted: 4});
    } finally { w.cleanup(); }
});

test('a day counts only when every configured child has an ok answer for it', () => {
    const w = world();
    try {
        w.fill(WEEK);
        w.counts.put(HOSTILE_B, suspect(WEEK[2]!), 2);
        w.counts.put(HOSTILE_B, logsOff(WEEK[4]!), 2);
        // the surviving child's rows for the two uncounted days are left out of the integer too
        assert.deepEqual(w.week(), {count: 3 * 2 * 5, daysCounted: 5});
    } finally { w.cleanup(); }
});

test('week boundary: Sunday..Saturday before the slot, the Saturday before and the slot Sunday itself are outside', () => {
    const w = world();
    try {
        const outside = ['2026-10-31', '2026-11-08', '2026-11-09'];
        w.fill(outside, day => okDay(day, {adult: 1000}));
        w.fill(WEEK);
        assert.deepEqual(w.week(), {count: 42, daysCounted: 7});
        // the previous slot's week is Sun 10-25..Sat 10-31: only the Saturday row exists there
        assert.deepEqual(w.week(SLOT - 7 * 86400), {count: 2000, daysCounted: 1});
        // the Monday after is not part of any finished week for this slot, and the next slot's week starts on the slot Sunday
        assert.deepEqual(w.week(SLOT + 7 * 86400), {count: 4000, daysCounted: 2});
    } finally { w.cleanup(); }
});

test('DST weeks: the spring-forward week (Sun 03-08 is 23 hours) and the fall-back week both span exactly 7 local days', () => {
    const w = world();
    try {
        const spring = utc(2026, 3, 15, 22), springDays = dayRange('2026-03-08', '2026-03-14');
        assert.equal(springDays.length, 7);
        w.fill(springDays); w.fill(['2026-03-07', '2026-03-15'], day => okDay(day, {adult: 777}));
        assert.deepEqual(w.week(spring), {count: 42, daysCounted: 7});
        const fall = utc(2026, 11, 8, 23);
        w.fill(WEEK);
        assert.deepEqual(w.week(fall), {count: 42, daysCounted: 7});
    } finally { w.cleanup(); }
});

test('a deferred Monday 07:00 send uses the same Sunday..Saturday week as an on-time send', async () => {
    const w = world(), sent: string[] = [];
    try {
        w.fill(WEEK); w.fill(['2026-11-09'], day => okDay(day, {adult: 1000}));
        let written = 0;
        const deps = (now: number) => ({now: () => now, counts: (from: number, to: number) => weeklyCounts(w.store, from, to, slot => w.week(slot)),
            send: async (m: Parameters<typeof pushText>[0]) => { sent.push(pushText(m).body); return {ok: true, attempts: 1, reason: 'sent'}; }, state: {read: () => written, write: (n: number) => { written = n; }}, log: () => undefined});
        assert.equal(await digestTick(deps(utc(2026, 11, 8, 23, 30) + 60 * 60 * 3)), 'deferred'); // 21:30 EST
        assert.equal(await digestTick(deps(utc(2026, 11, 9, 12))), 'sent'); // Monday 07:00 EST
        assert.deepEqual(sent, [`${BASE}\n42 blocked lookups last week.`]);
    } finally { w.cleanup(); }
});

test('weeklyCounts: a failing counts read costs the line, never the digest', () => {
    const w = world();
    try {
        const counts = weeklyCounts(w.store, SLOT - 7 * 86400, SLOT, () => { throw new Error('counts store unreadable SECRET'); });
        assert.deepEqual(Object.keys(counts).sort(), ['grants', 'pauses', 'requests']);
    } finally { w.cleanup(); }
});

test('flag matrix: digest body is byte-identical unless digest AND counts are both on, and the counts store is not even read otherwise', async () => {
    const results = new Map<string, string>();
    for (const [name, contentFilter, digestOn] of [['no contentFilter', undefined, true], ['counts absent', filter(undefined), true], ['counts off', filter(false), true], ['counts on, digest off', filter(true), false], ['both on', filter(true), true]] as const) {
        const w = world(), ntfy = await fakeNtfy();
        try {
            w.fill(WEEK);
            let reads = 0, clock = utc(2026, 11, 8, 22);
            const n = startNotifications({...w.config, push: {enabled: true}, ...(digestOn ? {digest: {enabled: true}} : {}), ...(contentFilter ? {contentFilter} : {})}, w.store,
                {env: ntfy.env, now: () => clock, blocked: slot => { reads++; return w.week(slot); }, options: {sleep: async () => undefined, log: () => undefined}})!;
            await n.tick(); clock = SLOT; await n.tick(); await n.stop();
            results.set(name, ntfy.seen.map(s => s.body).join('|'));
            if (name !== 'both on') assert.equal(reads, 0, `${name}: store not read`);
        } finally { ntfy.close(); w.cleanup(); }
    }
    for (const name of ['no contentFilter', 'counts absent', 'counts off']) assert.equal(results.get(name), BASE, name);
    assert.equal(results.get('counts on, digest off'), '', 'digest off: no digest at all');
    assert.equal(results.get('both on'), `${BASE}\n42 blocked lookups last week.`);
});

test('counts on but contentFilter mode off: counts are ignored, the digest is unchanged', async () => {
    const w = world(), ntfy = await fakeNtfy();
    try {
        w.fill(WEEK);
        let clock = utc(2026, 11, 8, 22);
        const n = startNotifications({...w.config, push: {enabled: true}, digest: {enabled: true}, contentFilter: {mode: 'off', counts: {enabled: true}}}, w.store,
            {env: ntfy.env, now: () => clock, blocked: slot => w.week(slot), options: {sleep: async () => undefined, log: () => undefined}})!;
        await n.tick(); clock = SLOT; await n.tick(); await n.stop();
        assert.deepEqual(ntfy.seen.map(s => s.body), [BASE]);
    } finally { ntfy.close(); w.cleanup(); }
});

test('the exact payload that leaves the host: fixed headers, one integer line, no child name, id, class or per-child number', async () => {
    const w = world(), ntfy = await fakeNtfy();
    try {
        // Distinct per-child numbers: neither may appear on the wire, only the household sum.
        w.fill(WEEK, day => okDay(day, {adult: 4, gambling: 1}), [HOSTILE_A]);
        w.fill(WEEK, day => okDay(day, {social: 2}), [HOSTILE_B]);
        w.fill(['2026-10-31'], day => okDay(day, {dating: 9999}));
        let clock = utc(2026, 11, 8, 22);
        const n = startNotifications({...w.config, push: {enabled: true}, digest: {enabled: true}, contentFilter: filter(true),
            accounts: [{id: 'operator', displayName: HOSTILE_A, role: 'admin', personIds: ['pilot']}]}, w.store,
        {env: ntfy.env, now: () => clock, blocked: slot => w.week(slot), options: {sleep: async () => undefined, log: () => undefined}})!;
        await n.tick(); clock = SLOT; await n.tick(); await n.stop();
        assert.equal(ntfy.seen.length, 1);
        const [seen] = ntfy.seen;
        assert.equal(seen!.url, `/${TOPIC}`);
        assert.equal(seen!.body, `${BASE}\n${7 * (5 + 2)} blocked lookups last week.`);
        const headers = Object.fromEntries(Object.entries(seen!.headers).filter(([k]) => !['host', 'connection', 'content-length', 'accept', 'accept-language', 'sec-fetch-mode', 'user-agent', 'accept-encoding'].includes(k)));
        assert.deepEqual(headers, {title: 'Couvre-feu weekly summary', click: 'http://localhost:4273/', 'content-type': 'text/plain; charset=utf-8', authorization: `Bearer ${TOKEN}`});
        assert.ok(!('tags' in seen!.headers) && !('priority' in seen!.headers));
        const wire = JSON.stringify({headers: seen!.headers, body: seen!.body, url: seen!.url}).toLowerCase();
        for (const forbidden of [HOSTILE_A, HOSTILE_B, 'zed', 'bobby', 'quinn', 'hostile', 'pilot', 'phone', 'abcd0001', 'abcd0002', 'abcd1234', ...CLASS_CODES, '9999', '28', '14 ']) {
            assert.ok(!wire.includes(forbidden), `wire contains ${forbidden}`);
        }
        // not the per-child numbers (4+1)*7=35 and 2*7=14 as separate figures either
        assert.ok(!/\b35\b|\b14\b/.test(seen!.body));
    } finally { ntfy.close(); w.cleanup(); }
});
