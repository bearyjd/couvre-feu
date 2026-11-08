import test from 'node:test';
import assert from 'node:assert/strict';
import { NextDnsError, NEXTDNS_ERROR_CODES, createFetchTransport, createNextDnsClient } from '../src/nextdns-client.ts';
import type { NextDnsClient, NextDnsClientOptions, Transport } from '../src/nextdns-client.ts';
import { createFakeNextDns, json, profile, SETTINGS } from './fixtures/fake-nextdns.ts';
import type { FakeOptions } from './fixtures/fake-nextdns.ts';

const KEY = 'sekret-key-0123456789abcdef';
const OK_PATH = /^\/profiles(\/[A-Za-z0-9]{4,32}(\/(settings|denylist|allowlist|parentalControl(\/(services|categories))?))?)?(\?cursor=[A-Za-z0-9_.=-]+)?$/;

function setup(fake: Partial<FakeOptions> = {}, client: Partial<NextDnsClientOptions> = {}) {
    const sleeps: number[] = [];
    const api = createFakeNextDns({ apiKey: KEY, ...fake });
    const c = createNextDnsClient({ apiKey: () => KEY, transport: api.transport, sleep: async ms => { sleeps.push(ms); }, random: () => 0.5, now: () => 1_000_000, ...client });
    return { api, c, sleeps };
}
const code = (e: unknown) => e instanceof NextDnsError ? e.code : `not-a-NextDnsError:${String(e)}`;
async function codeOf(run: () => Promise<unknown>): Promise<string> {
    try { await run(); } catch (e) { return code(e); }
    return 'no-error';
}

test('reads parental control, lists and settings as frozen, validated values', async () => {
    const { c } = setup();
    const pc = await c.getParentalControl('abc123');
    assert.deepEqual(pc.categories, [{ id: 'porn', active: true }]);
    assert.equal(pc.safeSearch, true);
    assert.ok(Object.isFrozen(pc) && Object.isFrozen(pc.services) && Object.isFrozen(pc.services[0]));
    assert.deepEqual(await c.getList('abc123', 'denylist'), [{ id: 'bad.example', active: true }]);
    assert.deepEqual(await c.getList('abc123', 'allowlist'), [{ id: 'good.example', active: true }]);
    const settings = await c.getSettings('abc123');
    assert.equal(settings.logs.enabled, false);
    assert.ok(Object.isFrozen(settings.logs.drop));
    assert.deepEqual(await c.listProfiles(), [{ id: 'abc123', name: 'Child abc123' }]);
});

test('writes flags and lists, sends the key header, does not mutate its inputs', async () => {
    const { api, c } = setup();
    await c.setParentalControl('abc123', { safeSearch: false });
    assert.equal(api.profiles.get('abc123')!.parentalControl.safeSearch, false);
    const entries = Object.freeze([Object.freeze({ id: 'new.example', active: true })]);
    await c.setList('abc123', 'denylist', entries);
    assert.deepEqual(api.profiles.get('abc123')!.denylist, [{ id: 'new.example', active: true }]);
    assert.deepEqual(entries, [{ id: 'new.example', active: true }]);
    assert.ok(api.requests.every(r => r.keyOk));
    assert.deepEqual(api.requests.map(r => r.method), ['PATCH', 'PUT']);
});

test('hex-encoded service ids round-trip; hostile ids are rejected before any request', async () => {
    const { api, c } = setup();
    await c.setList('abc123', 'services', [{ id: '6d6f7a696c6c61', active: true }]);
    assert.deepEqual((await c.getParentalControl('abc123')).services, [{ id: '6d6f7a696c6c61', active: true }]);
    const before = api.requests.length;
    for (const id of ['Tik Tok', 'a/b', '../x', '', 'x'.repeat(65)]) assert.equal(await codeOf(() => c.setList('abc123', 'services', [{ id, active: true }])), 'invalid_request', id);
    assert.equal(await codeOf(() => c.setList('abc123', 'denylist', [{ id: 'bad host!', active: true }])), 'invalid_request');
    assert.equal(api.requests.length, before);
});

test('profile ids are validated before building a path; only /profiles paths are requested', async () => {
    const { api, c } = setup();
    for (const id of ['../x', '..', 'abc/../123', '%2e%2e', 'a%2fb', 'abc123/settings', 'ab', '', 'abc 123', 'abc123?x=1', 'abc\n123'])
        assert.equal(await codeOf(() => c.getSettings(id)), 'invalid_request', JSON.stringify(id));
    assert.equal(api.requests.length, 0);
    await c.getSettings('abc123'); await c.listProfiles(); await c.getList('abc123', 'services');
    assert.equal(api.requests.length, 3);
    assert.ok(api.requests.every(r => OK_PATH.test(r.path)), api.requests.map(r => r.path).join());
});

test('401 maps to unauthorized, 404 to not_found, with fixed messages', async () => {
    const wrong = createNextDnsClient({ apiKey: () => 'a-different-key-123456', transport: setup().api.transport });
    assert.equal(await codeOf(() => wrong.getSettings('abc123')), 'unauthorized');
    const { c } = setup();
    const err = await c.getSettings('zzzzzz').catch((e: unknown) => e) as NextDnsError;
    assert.equal(err.code, 'not_found');
    assert.equal(err.message, 'not_found');
    assert.ok(!/unknown profile/.test(JSON.stringify(err) + err.stack));
});

test('400 maps to invalid_request without server text; a 200 carrying errors does too', async () => {
    const { api, c } = setup();
    api.enqueue(json(400, { errors: [{ code: 'invalid', detail: 'LEAK-ME', source: { pointer: '/safeSearch' } }] }));
    const err = await c.setParentalControl('abc123', { safeSearch: true }).catch((e: unknown) => e) as NextDnsError;
    assert.equal(err.code, 'invalid_request');
    assert.ok(!(err.message + err.stack).includes('LEAK-ME'));
    api.enqueue(json(200, { errors: [{ code: 'invalid', detail: 'x', source: { parameter: 'limit' } }] }));
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'invalid_request');
    api.enqueue(json(400, { errors: [{ code: 'invalid', surprise: 1 }] }));
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response');
    api.enqueue(json(400, 'not an object'));
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response');
});

test('429 then success retries with backoff, honours Retry-After seconds and dates, capped', async () => {
    const { api, c, sleeps } = setup({}, { baseDelayMs: 100, maxRetryAfterMs: 5000 });
    api.enqueue(json(429, {}, { 'retry-after': '2' }));
    await c.getSettings('abc123');
    assert.deepEqual(sleeps, [2000]);
    api.enqueue(json(429, {}, { 'Retry-After': new Date(1_000_000 + 3000).toUTCString() }));
    await c.getSettings('abc123');
    assert.ok(sleeps[1]! >= 2000 && sleeps[1]! <= 3000, String(sleeps[1]));
    api.enqueue(json(429, {}, { 'retry-after': '999999' }));
    await c.getSettings('abc123');
    assert.equal(sleeps[2], 5000);
    api.enqueue(json(429, {}));
    await c.getSettings('abc123');
    assert.equal(sleeps[3], 75, 'no header: exponential backoff with jitter (base 100, random 0.5)');
});

test('429 forever gives up with rate_limited after maxAttempts', async () => {
    const { api, c, sleeps } = setup({}, { maxAttempts: 3 });
    for (let i = 0; i < 5; i++) api.enqueue(json(429, {}));
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'rate_limited');
    assert.equal(api.requests.length, 3);
    assert.equal(sleeps.length, 2);
});

test('writes retry only on 429; 5xx and transport failures on writes are not retried, on reads they are', async () => {
    const { api, c } = setup({}, { maxAttempts: 3 });
    api.enqueue(json(429, {}));
    await c.setParentalControl('abc123', { safeSearch: true });
    assert.equal(api.requests.length, 2);
    api.enqueue(json(503, {}));
    assert.equal(await codeOf(() => c.setParentalControl('abc123', { safeSearch: true })), 'server');
    api.enqueue({ throw: 'network' });
    assert.equal(await codeOf(() => c.setList('abc123', 'denylist', [])), 'transport');
    assert.equal(api.requests.length, 4);
    api.enqueue(json(503, {})); api.enqueue({ throw: 'network' });
    await c.getSettings('abc123');
    assert.equal(api.requests.length, 7);
});

test('pagination follows cursors across pages, with page and loop caps', async () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ id: `site${i}.example`, active: true }));
    const { api, c } = setup({ pageSize: 2, profiles: [profile('abc123', { denylist: many })] });
    assert.deepEqual(await c.getList('abc123', 'denylist'), many);
    assert.deepEqual(api.requests.map(r => r.path), ['/profiles/abc123/denylist', '/profiles/abc123/denylist?cursor=c2', '/profiles/abc123/denylist?cursor=c4']);
    const looped = setup({ pageSize: 2, cursorLoop: true, profiles: [profile('abc123', { denylist: many })] });
    assert.equal(await codeOf(() => looped.c.getList('abc123', 'denylist')), 'bad_response');
    assert.ok(looped.api.requests.length <= 3);
    const capped = setup({ pageSize: 1, profiles: [profile('abc123', { denylist: many })] }, { maxPages: 3 });
    assert.equal(await codeOf(() => capped.c.getList('abc123', 'denylist')), 'bad_response');
    assert.equal(capped.api.requests.length, 3);
});

test('malformed or unexpected responses are bad_response', async () => {
    const { api, c } = setup();
    const bad: [string, unknown][] = [
        ['malformed json', { status: 200, headers: {}, body: '{"data":' }],
        ['empty body', { status: 200, headers: {}, body: '' }],
        ['top-level extra key', json(200, { data: SETTINGS, extra: 1 })],
        ['nested extra key', json(200, { data: { ...SETTINGS, logs: { ...SETTINGS.logs, surprise: true } } })],
        ['missing key', json(200, { data: { ...SETTINGS, web3: undefined } })],
        ['wrong type', json(200, { data: { ...SETTINGS, web3: 'no' } })],
        ['__proto__ key', { status: 200, headers: {}, body: '{"data":{"__proto__":{"x":1}}}' }],
        ['redirect', { status: 302, headers: { location: 'https://evil.example/' }, body: '' }],
        ['unexpected status', json(418, {})],
    ];
    for (const [name, res] of bad) { api.enqueue(res as never); assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response', name); }
    api.enqueue(json(200, { data: { services: [], categories: [], safeSearch: true, youtubeRestrictedMode: true, recreation: {} } }));
    assert.equal(await codeOf(() => c.getParentalControl('abc123')), 'bad_response');
    api.enqueue(json(200, { data: [{ id: 'UPPER CASE', active: true }] }));
    assert.equal(await codeOf(() => c.getList('abc123', 'services')), 'bad_response');
    api.enqueue(json(200, { data: [{ id: 'ok.example', active: true, note: 'x' }] }));
    assert.equal(await codeOf(() => c.getList('abc123', 'denylist')), 'bad_response');
    api.enqueue(json(200, { data: Array.from({ length: 1001 }, (_, i) => ({ id: `s${i}.example`, active: true })) }));
    assert.equal(await codeOf(() => c.getList('abc123', 'denylist')), 'bad_response');
    api.enqueue(json(200, { data: [], meta: { pagination: { cursor: 'has space' } } }));
    assert.equal(await codeOf(() => c.getList('abc123', 'denylist')), 'bad_response');
});

test('oversize bodies from any transport are bad_response', async () => {
    const huge: Transport = async () => ({ status: 200, headers: {}, body: 'x'.repeat(2_000_000) });
    const c = createNextDnsClient({ apiKey: () => KEY, transport: huge });
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response');
});

test('transport timeouts and failures are typed, and errors never carry the key', async () => {
    const { api, c } = setup({}, { maxAttempts: 1 });
    api.enqueue({ throw: 'timeout' });
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'transport');
    const timing: Transport = async () => { throw new NextDnsError('timeout'); };
    assert.equal(await codeOf(() => createNextDnsClient({ apiKey: () => KEY, transport: timing, maxAttempts: 1 }).getSettings('abc123')), 'timeout');
    const leaky: Transport = async req => { throw new Error(`boom ${req.headers['x-api-key']}`); };
    const err = await createNextDnsClient({ apiKey: () => KEY, transport: leaky, maxAttempts: 1 }).getSettings('abc123').catch((e: unknown) => e) as NextDnsError;
    assert.equal(err.code, 'transport');
    assert.ok(!(err.message + err.stack + JSON.stringify(err)).includes(KEY));
    assert.ok((NEXTDNS_ERROR_CODES as readonly string[]).includes(err.code));
});

test('the key never appears in errors, client object output, stdout or stderr', async () => {
    const out: string[] = [], realOut = process.stdout.write, realErr = process.stderr.write;
    const grab = (chunk: unknown) => { out.push(String(chunk)); return true; };
    process.stdout.write = grab as typeof process.stdout.write; process.stderr.write = grab as typeof process.stderr.write;
    const seen: string[] = [];
    try {
        const { api, c } = setup({}, { maxAttempts: 2 });
        seen.push(JSON.stringify(c), String(c), Object.keys(c).join(), String(Object.getOwnPropertySymbols(c).length));
        for (const step of [json(401, {}), json(404, {}), json(400, { errors: [] }), json(500, {}), json(429, {}), { status: 200, headers: {}, body: 'KEY ' + KEY }]) {
            api.enqueue(step as never); api.enqueue(step as never);
            const e = await c.getSettings('abc123').catch((x: unknown) => x) as Error;
            seen.push(e.message, e.stack ?? '', JSON.stringify(e), String(e));
        }
    } finally { process.stdout.write = realOut; process.stderr.write = realErr; }
    assert.ok(seen.every(s => !s.includes(KEY)));
    assert.ok(!out.join('').includes(KEY));
});

test('the key getter is read per request and a missing key is unauthorized without a request', async () => {
    let key = KEY;
    const api = createFakeNextDns({ apiKey: KEY });
    const c: NextDnsClient = createNextDnsClient({ apiKey: () => key, transport: api.transport });
    await c.getSettings('abc123');
    key = '';
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'unauthorized');
    key = 'bad key with spaces';
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'unauthorized');
    assert.equal(api.requests.length, 1);
});

test('default fetch transport: host pinned, redirects not followed, timeout and size cap enforced, no key in errors', async () => {
    const seen: { url: string; init: RequestInit }[] = [];
    const mk = (fn: (url: string, init: RequestInit) => Promise<Response>) => createFetchTransport({ fetch: (async (u: URL, i: RequestInit) => { seen.push({ url: String(u), init: i }); return fn(String(u), i); }) as typeof fetch, maxBytes: 100, timeoutMs: 50 });
    const req = { method: 'GET', path: '/profiles/abc123/settings', headers: { 'x-api-key': KEY } } as const;
    const ok = await mk(async () => new Response('{"data":1}', { status: 200, headers: { 'Retry-After': '3' } }))(req);
    assert.deepEqual([ok.status, ok.body, ok.headers['retry-after']], [200, '{"data":1}', '3']);
    assert.equal(seen[0]!.url, 'https://api.nextdns.io/profiles/abc123/settings');
    assert.equal(seen[0]!.init.redirect, 'manual');
    assert.ok(seen[0]!.init.signal instanceof AbortSignal);
    for (const path of ['//evil.example/x', 'https://evil.example/x', '/\\evil.example'])
        assert.equal(await codeOf(() => mk(async () => new Response('{}'))({ ...req, path })), 'transport', path);
    assert.equal(seen.length, 1, 'the host check runs before fetch');
    const redirect = await mk(async () => new Response(null, { status: 302, headers: { location: 'https://evil.example/' } }))(req);
    assert.deepEqual([redirect.status, redirect.body], [302, '']);
    assert.equal(await codeOf(() => mk(async () => new Response('x'.repeat(101)))(req)), 'bad_response');
    const abortable = mk((_u, init) => new Promise((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason))));
    const keepAlive = setTimeout(() => undefined, 2000); // AbortSignal.timeout timers are unref'd
    try { assert.equal(await codeOf(() => abortable(req)), 'timeout'); } finally { clearTimeout(keepAlive); }
    const failing = await mk(async () => { throw new Error(`connect failed ${KEY}`); })(req).catch((e: unknown) => e) as NextDnsError;
    assert.equal(failing.code, 'transport');
    assert.ok(!(failing.message + failing.stack).includes(KEY));
});
