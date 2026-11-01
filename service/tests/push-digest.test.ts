import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { actor, integrationFixture } from './fixtures/integration.ts';
import { NtfyPush, ntfySettings, pushText } from '../src/push-sender.ts';
import { startNotifications, weeklyCounts } from '../src/push-runtime.ts';
import { digestTick, inQuietHours, latestDigestSlot } from '../src/digest.ts';
import type { DigestDeps } from '../src/digest.ts';

const HOSTILE = 'Zed<script>alert(1)</script>Bobby';
const TOKEN = 'tk_secrettoken123456', TOPIC = 'couvre_topic_abc123';
interface Seen { url: string; headers: IncomingMessage['headers']; body: string }
async function fakeNtfy(handler: (seen: Seen, n: number, res: ServerResponse) => void = (_s, _n, res) => { res.statusCode = 200; res.end('{}'); }) {
    const seen: Seen[] = [];
    const server: Server = createServer((req, res) => {
        let body = ''; req.on('data', chunk => { body += chunk; });
        req.on('end', () => { seen.push({url: req.url!, headers: req.headers, body}); handler(seen[seen.length - 1], seen.length, res); });
    });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const url = `http://127.0.0.1:${(server.address() as {port: number}).port}`;
    return {seen, url, env: {COUVRE_NTFY_URL: url, COUVRE_NTFY_TOPIC: TOPIC, COUVRE_NTFY_TOKEN: TOKEN}, close: () => { server.closeAllConnections(); server.close(); }};
}
const utc = (...a: [number, number, number, number, number?]) => Date.UTC(a[0], a[1] - 1, a[2], a[3], a[4] ?? 0) / 1000;
const noSleep = async () => undefined;

test('ntfy settings are validated and never echoed', () => {
    assert.deepEqual(ntfySettings({COUVRE_NTFY_URL: 'http://127.0.0.1:2586', COUVRE_NTFY_TOPIC: TOPIC}), {baseUrl: 'http://127.0.0.1:2586', topic: TOPIC, token: null});
    for (const env of [{}, {COUVRE_NTFY_URL: 'ftp://x', COUVRE_NTFY_TOPIC: TOPIC}, {COUVRE_NTFY_URL: 'https://u:p@h/', COUVRE_NTFY_TOPIC: TOPIC}, {COUVRE_NTFY_URL: 'https://h/x', COUVRE_NTFY_TOPIC: TOPIC},
        {COUVRE_NTFY_URL: 'https://h', COUVRE_NTFY_TOPIC: 'a/b'}, {COUVRE_NTFY_URL: 'https://h', COUVRE_NTFY_TOPIC: 'short'}, {COUVRE_NTFY_URL: 'https://h', COUVRE_NTFY_TOPIC: TOPIC, COUVRE_NTFY_TOKEN: 'bad token\n'}]) {
        assert.throws(() => ntfySettings(env), error => /^invalid_ntfy_(url|topic|token)$/.test((error as Error).message) && !(error as Error).message.includes(TOPIC));
    }
});

test('payloads are content-free: fixed alert text, digest numbers only', async () => {
    const f = integrationFixture(), ntfy = await fakeNtfy();
    try {
        // Hostile child, account, request-reason and alert-detail text all exist in the database.
        f.store.run('INSERT INTO request_links(id,person_id,token_hash,created_by,created_at) VALUES(?,?,?,?,?)', 'l1', 'pilot', 'h', 'operator', f.now());
        f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at,decided_at) VALUES('r1','l1','pilot',15,?,'approved',?,?,?)", HOSTILE, f.now() - 10, f.now() + 900, f.now() - 5);
        f.store.run("INSERT INTO parent_alerts(person_id,kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES('pilot','enforcement_unhealthy','warning',?,?,?,1,'open',?)", f.now(), f.now(), f.now(), JSON.stringify({note: HOSTILE}));
        const n = startNotifications({...f.config, push: {enabled: true}, digest: {enabled: false}}, f.store, {env: ntfy.env, options: {sleep: noSleep, log: () => undefined}})!;
        // Enabling starts from the current alert high-water mark: the existing alert is history, not a push.
        await n.tick(); assert.equal(ntfy.seen.length, 0);
        f.store.run("INSERT INTO parent_alerts(person_id,kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES('pilot','possible_bypass','warning',?,?,?,1,'open',?)", f.now(), f.now(), f.now(), JSON.stringify({note: HOSTILE}));
        await n.tick(); await n.tick();
        n.stop();
        assert.equal(ntfy.seen.length, 1, 'one push for the new alert, none repeated');
        const all = JSON.stringify(ntfy.seen[0]);
        for (const forbidden of [HOSTILE, 'Zed', 'Bobby', 'script', 'pilot', 'operator', 'Explicit test', 'possible_bypass', 'enforcement']) assert.ok(!all.includes(forbidden), forbidden);
        assert.equal(ntfy.seen[0].body, 'New alert. Open the app to see it.');
        assert.equal(ntfy.seen[0].url, '/' + TOPIC);
        assert.equal(ntfy.seen[0].headers.authorization, `Bearer ${TOKEN}`);
        assert.equal(ntfy.seen[0].headers.click, 'http://localhost:4273/');
        // Digest counts are bare integers drawn from the hostile database.
        const counts = weeklyCounts(f.store, f.now() - 86400, f.now() + 1);
        assert.deepEqual(counts, {requests: 1, grants: 1, pauses: 0});
        await f.observe(); f.pause();
        assert.equal(weeklyCounts(f.store, f.now() - 86400, f.now() + 1).pauses, 1);
        const text = pushText({kind: 'digest', counts: {requests: 3, grants: 2, pauses: 1}});
        assert.equal(text.body, 'Last 7 days: 3 requests, 2 grants, 1 pauses.');
        assert.equal(pushText({kind: 'digest', counts: {requests: -1, grants: NaN, pauses: 1.5}}).body, 'Last 7 days: 0 requests, 0 grants, 0 pauses.');
    } finally { ntfy.close(); f.cleanup(); }
});

test('retries: 5xx retried and bounded, 4xx not, success stops, token never logged', async () => {
    const logs: string[] = [];
    const flaky = await fakeNtfy((_s, n, res) => { res.statusCode = n < 3 ? 503 : 200; res.end('boom'); });
    const refused = await fakeNtfy((_s, _n, res) => { res.statusCode = 403; res.end(); });
    const down = await fakeNtfy((_s, _n, res) => { res.statusCode = 500; res.end(); });
    const make = (s: Awaited<ReturnType<typeof fakeNtfy>>) => new NtfyPush(ntfySettings(s.env), 'http://localhost:4273', {sleep: noSleep, log: line => logs.push(String(line))});
    try {
        assert.deepEqual(await make(flaky).send({kind: 'alert'}), {ok: true, attempts: 3, reason: 'sent'});
        assert.deepEqual(await make(refused).send({kind: 'alert'}), {ok: false, attempts: 1, reason: 'http_403'});
        assert.deepEqual(await make(down).send({kind: 'alert'}), {ok: false, attempts: 3, reason: 'http_500'});
        assert.equal(down.seen.length, 3);
        const out = logs.join('');
        assert.match(out, /push_failed http_403 attempts=1/);
        for (const secret of [TOKEN, TOPIC, '127.0.0.1']) assert.ok(!out.includes(secret));
    } finally { flaky.close(); refused.close(); down.close(); }
});

test('a hung endpoint times out and a dead one fails without throwing', async () => {
    const hang = await fakeNtfy(() => undefined), logs: string[] = [];
    try {
        const push = new NtfyPush(ntfySettings(hang.env), 'http://localhost:4273', {timeoutMs: 50, maxAttempts: 2, sleep: noSleep, log: line => logs.push(String(line))});
        assert.deepEqual(await push.send({kind: 'alert'}), {ok: false, attempts: 2, reason: 'timeout'});
        const url = hang.url; hang.close();
        const dead = new NtfyPush(ntfySettings({...hang.env, COUVRE_NTFY_URL: url}), 'http://localhost:4273', {timeoutMs: 200, maxAttempts: 2, sleep: noSleep, log: () => undefined});
        assert.equal((await dead.send({kind: 'alert'})).reason, 'network_error');
    } finally { hang.close(); }
});

test('a failing push never throws out of the notification pass', async () => {
    const f = integrationFixture(), down = await fakeNtfy((_s, _n, res) => { res.statusCode = 500; res.end(); });
    try {
        const n = startNotifications({...f.config, push: {enabled: true}}, f.store, {env: down.env, options: {sleep: noSleep, log: () => undefined}})!;
        f.store.run("INSERT INTO parent_alerts(person_id,kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES('pilot','possible_bypass','warning',?,?,?,1,'open','{}')", f.now(), f.now(), f.now());
        await n.tick(); n.stop();
        assert.equal(down.seen.length, 3);
        assert.ok(f.policy.people(actor), 'policy reads are unaffected');
    } finally { down.close(); f.cleanup(); }
});

test('flags off: no network call, no timer, no table', async () => {
    const f = integrationFixture(), ntfy = await fakeNtfy(), real = globalThis.fetch;
    globalThis.fetch = (() => { throw new Error('network call with push off'); }) as typeof fetch;
    try {
        for (const config of [f.config, {...f.config, push: {enabled: false}}, {...f.config, digest: {enabled: true}}]) assert.equal(startNotifications(config, f.store, {env: ntfy.env}), null);
        assert.equal(f.store.get("SELECT name FROM sqlite_master WHERE name='notify_state'"), undefined);
        assert.equal(ntfy.seen.length, 0);
    } finally { globalThis.fetch = real; ntfy.close(); f.cleanup(); }
});

test('push enabled with a bad ntfy setting refuses at startup', () => {
    const f = integrationFixture();
    try { assert.throws(() => startNotifications({...f.config, push: {enabled: true}}, f.store, {env: {}}), /invalid_ntfy_url/); } finally { f.cleanup(); }
});

test('quiet hours: 21:00 to 07:00 New York, across DST', () => {
    // EDT (UTC-4): 20:59:59 open, 21:00 quiet, 06:59:59 quiet, 07:00 open.
    assert.equal(inQuietHours(utc(2026, 10, 29, 0, 59) + 59), false);
    assert.equal(inQuietHours(utc(2026, 10, 29, 1, 0)), true);
    assert.equal(inQuietHours(utc(2026, 10, 29, 10, 59) + 59), true);
    assert.equal(inQuietHours(utc(2026, 10, 29, 11, 0)), false);
    // EST (UTC-5) after the fall-back.
    assert.equal(inQuietHours(utc(2026, 11, 2, 1, 59) + 59), false);
    assert.equal(inQuietHours(utc(2026, 11, 2, 2, 0)), true);
    assert.equal(inQuietHours(utc(2026, 11, 2, 11, 59) + 59), true);
    assert.equal(inQuietHours(utc(2026, 11, 2, 12, 0)), false);
});

test('digest slot is Sunday 18:00 New York on both DST change Sundays', () => {
    // Fall back 2026-11-01: that Sunday 18:00 is EST = 23:00Z; the Sunday before is EDT = 22:00Z.
    assert.equal(latestDigestSlot(utc(2026, 11, 1, 23, 0)), utc(2026, 11, 1, 23, 0));
    assert.equal(latestDigestSlot(utc(2026, 11, 1, 22, 59) + 59), utc(2026, 10, 25, 22, 0));
    assert.equal(latestDigestSlot(utc(2026, 11, 7, 12, 0)), utc(2026, 11, 1, 23, 0));
    // Spring forward 2026-03-08: 18:00 EDT = 22:00Z; the Sunday before is EST = 23:00Z.
    assert.equal(latestDigestSlot(utc(2026, 3, 8, 22, 0)), utc(2026, 3, 8, 22, 0));
    assert.equal(latestDigestSlot(utc(2026, 3, 8, 21, 59) + 59), utc(2026, 3, 1, 23, 0));
    // Ordinary EDT Sunday.
    assert.equal(latestDigestSlot(utc(2026, 10, 25, 22, 0)), utc(2026, 10, 25, 22, 0));
});

function digestHarness(start: number) {
    let clock = start, stored = latestDigestSlot(start), fail = false;
    const sent: unknown[] = [], logs: string[] = [], windows: [number, number][] = [];
    const deps: DigestDeps = {now: () => clock, log: line => logs.push(String(line)), state: {read: () => stored, write: v => { stored = v; }},
        counts: (from, to) => { windows.push([from, to]); return {requests: 4, grants: 2, pauses: 1}; },
        send: async message => { sent.push(message); return fail ? {ok: false, attempts: 3, reason: 'http_500'} : {ok: true, attempts: 1, reason: 'sent'}; }};
    return {deps, sent, logs, windows, set: (t: number) => { clock = t; }, failing: (v: boolean) => { fail = v; }, stored: () => stored};
}

test('digest sends once at Sunday 18:00, not before, not twice', async () => {
    const h = digestHarness(utc(2026, 11, 1, 22, 0));
    assert.equal(await digestTick(h.deps), 'not_due'); // the previous Sunday's slot is already recorded
    h.set(utc(2026, 11, 1, 23, 0)); assert.equal(await digestTick(h.deps), 'sent');
    assert.equal(h.sent.length, 1);
    assert.deepEqual(h.windows[0], [utc(2026, 11, 1, 23, 0) - 7 * 86400, utc(2026, 11, 1, 23, 0)]);
    h.set(utc(2026, 11, 1, 23, 30)); assert.equal(await digestTick(h.deps), 'not_due');
    assert.equal(h.sent.length, 1);
});

test('a digest due in quiet hours is deferred to 07:00, not dropped', async () => {
    const h = digestHarness(utc(2026, 11, 1, 22, 0));
    h.set(utc(2026, 11, 2, 3, 0)); // Sunday 22:00 EST: service was down at 18:00
    assert.equal(await digestTick(h.deps), 'deferred');
    h.set(utc(2026, 11, 2, 11, 59)); assert.equal(await digestTick(h.deps), 'deferred'); // 06:59
    assert.equal(h.sent.length, 0); assert.match(h.logs.join(''), /digest_deferred/);
    h.set(utc(2026, 11, 2, 12, 0)); assert.equal(await digestTick(h.deps), 'sent'); // Monday 07:00
    assert.equal(h.sent.length, 1);
    assert.equal(h.stored(), utc(2026, 11, 1, 23, 0));
});

test('a failed digest send is retried until it lands, and weeks missed collapse to one', async () => {
    const h = digestHarness(utc(2026, 11, 1, 22, 0));
    h.failing(true); h.set(utc(2026, 11, 1, 23, 5));
    assert.equal(await digestTick(h.deps), 'failed'); assert.equal(h.stored() < utc(2026, 11, 1, 23, 0), true);
    h.failing(false); h.set(utc(2026, 11, 1, 23, 20));
    assert.equal(await digestTick(h.deps), 'sent');
    h.set(utc(2026, 11, 23, 15, 0)); // three Sundays later
    assert.equal(await digestTick(h.deps), 'sent'); assert.equal(h.sent.length, 3, 'one failed attempt, then two landed: one per slot, three missed weeks collapsed');
});
