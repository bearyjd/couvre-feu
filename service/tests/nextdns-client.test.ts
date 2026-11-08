import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { NextDnsError, NextDnsEnvironmentError, NEXTDNS_ERROR_CODES, DEFAULT_DEADLINE_MS, DEFAULT_FETCH_TIMEOUT_MS, MAX_RESPONSE_BYTES, abortableSleep, assertSafeNextDnsEnvironment, createFetchTransport, createNextDnsClient } from '../src/nextdns-client.ts';
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
        ['own __proto__ key beside valid settings', { status: 200, headers: {}, body: `{"data":${JSON.stringify(SETTINGS).slice(0, -1)},"__proto__":{"polluted":1}}}` }],
        ['constructor key beside valid settings', { status: 200, headers: {}, body: `{"data":${JSON.stringify(SETTINGS).slice(0, -1)},"constructor":{}}}` }],
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

test('transport failures are typed, and errors never carry the key', async () => {
    const { api, c } = setup({}, { maxAttempts: 1 });
    api.enqueue({ throw: 'timeout' });
    assert.equal(await codeOf(() => c.getSettings('abc123')), 'transport', 'a plain thrown error is a transport failure');
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
        seen.push(JSON.stringify(c), String(c), Object.getOwnPropertyNames(c).join(), Object.getOwnPropertySymbols(c).map(String).join(), inspect(c, { showHidden: true, depth: 8 }), inspect(Object.getPrototypeOf(c), { showHidden: true }));
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

// ---------------------------------------------------------------- review hardening ----
const keepAlive = <T>(run: () => Promise<T>): Promise<T> => { const t = setTimeout(() => undefined, 3000); return run().finally(() => clearTimeout(t)); }; // AbortSignal.timeout timers are unref'd
const fetchWith = (fn: (url: string, init: RequestInit) => Promise<Response>, opts: { maxBytes?: number; timeoutMs?: number } = {}) =>
    createFetchTransport({ fetch: (async (u: URL, i: RequestInit) => fn(String(u), i)) as typeof fetch, ...opts });
const GET = { method: 'GET', path: '/profiles/abc123/settings', headers: { 'x-api-key': KEY } } as const;
const many = (n: number, prefix = 's') => Array.from({ length: n }, (_, i) => ({ id: `${prefix}${i}.example`, active: true }));
const statusOf = async (c: NextDnsClient, run: (c: NextDnsClient) => Promise<unknown>) => codeOf(() => run(c));

test('flags are read once: a getter that flips cannot change the body after validation', async () => {
    const { api, c } = setup();
    let reads = 0;
    const flags = { get safeSearch() { return reads++ === 0 ? true : 'x'; } };
    await c.setParentalControl('abc123', flags as never);
    assert.equal(api.requests[0]!.body, '{"safeSearch":true}');
    let idReads = 0;
    const entry = { get id() { return idReads++ === 0 ? 'ok.example' : 'BAD HOST!'; }, active: true };
    await c.setList('abc123', 'denylist', [entry]);
    assert.equal(api.requests[1]!.body, '[{"id":"ok.example","active":true}]');
});

test('invalid caller input is invalid_request and sends nothing', async () => {
    const { api, c } = setup();
    for (const flags of [{ safeSearch: 'x' }, { unknownFlag: true }, { blockBypass: 1 }, null, []])
        assert.equal(await codeOf(() => c.setParentalControl('abc123', flags as never)), 'invalid_request', JSON.stringify(flags));
    assert.equal(await codeOf(() => c.setList('abc123', 'denylist', many(5001))), 'invalid_request');
    assert.equal(api.requests.length, 0);
    await c.setList('abc123', 'denylist', many(5000));
    assert.equal(api.requests.length, 1);
});

test('profile id length bounds: 3 and 33 characters are refused, 4 and 32 reach the server', async () => {
    const { api, c } = setup();
    for (const id of ['abc', 'a'.repeat(33)]) assert.equal(await codeOf(() => c.getSettings(id)), 'invalid_request', id);
    assert.equal(api.requests.length, 0);
    for (const id of ['abcd', 'a'.repeat(32)]) assert.equal(await codeOf(() => c.getSettings(id)), 'not_found', id);
});

test('every error code is reachable', async () => {
    const reached = new Set<string>();
    const note = async (run: () => Promise<unknown>) => { reached.add(await codeOf(run)); };
    const { api, c } = setup({}, { maxAttempts: 1 });
    api.enqueue({ throw: 'network' }); await note(() => c.getSettings('abc123'));
    await note(() => createNextDnsClient({ apiKey: () => KEY, transport: async () => { throw new NextDnsError('timeout'); }, maxAttempts: 1 }).getSettings('abc123'));
    api.enqueue(json(429, {})); await note(() => c.getSettings('abc123'));
    api.enqueue(json(403, {})); await note(() => c.getSettings('abc123'));
    await note(() => c.getSettings('zzzzzz'));
    await note(() => c.setParentalControl('abc123', { safeSearch: 'x' } as never));
    api.enqueue({ status: 200, headers: {}, body: '{' }); await note(() => c.getSettings('abc123'));
    api.enqueue(json(503, {})); await note(() => c.getSettings('abc123'));
    assert.deepEqual([...reached].sort(), [...NEXTDNS_ERROR_CODES].sort());
});

test('status mapping: 403 is unauthorized, 201 on a read is bad_response', async () => {
    const { api, c } = setup();
    api.enqueue(json(403, {})); assert.equal(await codeOf(() => c.getSettings('abc123')), 'unauthorized');
    api.enqueue(json(201, { data: SETTINGS })); assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response');
});

test('write answers: only empty, {} or {"data":null} succeed; errors map to invalid_request', async () => {
    const { api, c } = setup();
    const put = () => c.setParentalControl('abc123', { safeSearch: true });
    for (const body of ['', '{}', '{"data":null}']) { api.enqueue({ status: 200, headers: {}, body }); await put(); }
    api.enqueue(json(200, { data: { x: 1 } })); assert.equal(await codeOf(put), 'bad_response');
    api.enqueue(json(200, { foo: 1 })); assert.equal(await codeOf(put), 'bad_response');
    api.enqueue(json(200, { errors: [{ code: 'invalid' }] })); assert.equal(await codeOf(put), 'invalid_request');
});

test('strict shapes: an extra key at any level is bad_response', async () => {
    const { api, c } = setup();
    const withSettings = (f: (s: any) => void) => { const s = structuredClone(SETTINGS); f(s); return json(200, { data: s }); };
    const cases: [string, ReturnType<typeof json>][] = [
        ['settings root', withSettings(s => { s.x = 1; })], ['logs', withSettings(s => { s.logs.x = 1; })], ['logs.drop', withSettings(s => { s.logs.drop.x = 1; })],
        ['performance', withSettings(s => { s.performance.x = 1; })], ['blockPage', withSettings(s => { s.blockPage.x = 1; })],
        ['retention -1', withSettings(s => { s.logs.retention = -1; })], ['retention 1.5', withSettings(s => { s.logs.retention = 1.5; })],
        ['retention string', withSettings(s => { (s.logs as any).retention = 'x'; })], ['location', withSettings(s => { s.logs.location = 'EU/../'; })],
    ];
    for (const [name, res] of cases) { api.enqueue(res); assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response', name); }
    api.enqueue(json(200, { data: [{ id: 'abc123', name: 'n', x: 1 }] })); assert.equal(await codeOf(() => c.listProfiles()), 'bad_response', 'profile item');
    api.enqueue(json(200, { data: [], meta: { pagination: { cursor: null }, x: 1 } })); assert.equal(await codeOf(() => c.listProfiles()), 'bad_response', 'meta');
    api.enqueue(json(200, { data: [], meta: { pagination: { cursor: null, x: 1 } } })); assert.equal(await codeOf(() => c.listProfiles()), 'bad_response', 'pagination');
    api.enqueue(json(200, { errors: [], x: 1 })); assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response', '200 error envelope');
    api.enqueue(json(400, { errors: [], x: 1 })); assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response', '400 error envelope');
    api.enqueue(json(400, { errors: [{ code: 'invalid', source: { pointer: '/a', x: 1 } }] })); assert.equal(await codeOf(() => c.getSettings('abc123')), 'bad_response', 'source');
    api.enqueue(json(400, { errors: [] })); assert.equal(await codeOf(() => c.getSettings('abc123')), 'invalid_request', 'a well-formed empty errors array');
    api.enqueue(json(200, { data: { services: [], categories: [], safeSearch: true, youtubeRestrictedMode: true, blockBypass: 'yes' } }));
    assert.equal(await codeOf(() => c.getParentalControl('abc123')), 'bad_response', 'blockBypass');
});

test('profile names: control characters and 101 characters are refused, 100 accepted', async () => {
    const { api, c } = setup();
    for (const name of ['bad\u0007name', 'x'.repeat(101), 'line\nbreak']) { api.enqueue(json(200, { data: [{ id: 'abc123', name }] })); assert.equal(await codeOf(() => c.listProfiles()), 'bad_response'); }
    api.enqueue(json(200, { data: [{ id: 'abc123', name: 'x'.repeat(100) }] }));
    assert.equal((await c.listProfiles())[0]!.name.length, 100);
});

test('cursors are URI-encoded', async () => {
    const { api, c } = setup();
    api.enqueue(json(200, { data: [], meta: { pagination: { cursor: 'a=b.c' } } })); api.enqueue(json(200, { data: [] }));
    await c.getList('abc123', 'denylist');
    assert.equal(api.requests[1]!.path, '/profiles/abc123/denylist?cursor=a%3Db.c');
});

test('more than 5000 items across pages is bad_response', async () => {
    const { api, c } = setup({ pageSize: 1000, profiles: [profile('abc123', { denylist: many(6000) })] });
    assert.equal(await codeOf(() => c.getList('abc123', 'denylist')), 'bad_response');
    assert.equal(api.requests.length, 6);
});

test('defaults: four attempts, exponential backoff from 500 ms capped at 10 s, Retry-After capped at 30 s', async () => {
    const four = setup();
    for (let i = 0; i < 9; i++) four.api.enqueue(json(429, {}));
    assert.equal(await codeOf(() => four.c.getSettings('abc123')), 'rate_limited');
    assert.equal(four.api.requests.length, 4);
    assert.deepEqual(four.sleeps, [375, 750, 1500]);
    const long = setup({}, { maxAttempts: 8 });
    for (let i = 0; i < 8; i++) long.api.enqueue(json(429, {}));
    await codeOf(() => long.c.getSettings('abc123'));
    assert.deepEqual(long.sleeps, [375, 750, 1500, 3000, 6000, 7500, 7500]);
    const custom = setup({}, { maxAttempts: 8, baseDelayMs: 100, maxDelayMs: 1000 });
    for (let i = 0; i < 8; i++) custom.api.enqueue(json(429, {}));
    await codeOf(() => custom.c.getSettings('abc123'));
    assert.deepEqual(custom.sleeps, [75, 150, 300, 600, 750, 750, 750]);
    const capped = setup();
    capped.api.enqueue(json(429, {}, { 'retry-after': '999999' }));
    await capped.c.getSettings('abc123');
    assert.deepEqual(capped.sleeps, [30000]);
});

test('Retry-After edge cases: a past date sleeps 0, an absurd number falls back to jitter', async () => {
    const past = setup();
    past.api.enqueue(json(429, {}, { 'retry-after': new Date(1_000_000 - 5000).toUTCString() }));
    await past.c.getSettings('abc123');
    assert.deepEqual(past.sleeps, [0]);
    const absurd = setup();
    absurd.api.enqueue(json(429, {}, { 'retry-after': '9999999999999' }));
    await absurd.c.getSettings('abc123');
    assert.deepEqual(absurd.sleeps, [375]);
});

test('a GET retries after one timeout and then succeeds', async () => {
    const api = createFakeNextDns({ apiKey: KEY });
    let first = true;
    const transport: Transport = async req => { if (first) { first = false; throw new NextDnsError('timeout'); } return api.transport(req); };
    const c = createNextDnsClient({ apiKey: () => KEY, transport, sleep: async () => undefined });
    assert.equal((await c.getSettings('abc123')).web3, false);
    assert.equal(api.requests.length, 1);
});

test('content-type is sent on PUT and PATCH, not on GET', async () => {
    const api = createFakeNextDns({ apiKey: KEY }), seen: Record<string, Record<string, string>> = {};
    const transport: Transport = async req => { seen[req.method] = { ...req.headers }; return api.transport(req); };
    const c = createNextDnsClient({ apiKey: () => KEY, transport });
    await c.getSettings('abc123'); await c.setParentalControl('abc123', { safeSearch: true }); await c.setList('abc123', 'denylist', []);
    assert.equal(seen.GET!['content-type'], undefined);
    assert.equal(seen.PATCH!['content-type'], 'application/json');
    assert.equal(seen.PUT!['content-type'], 'application/json');
});

test('client byte cap: more than 1 MiB is refused even from a transport with no cap, counting bytes not characters', async () => {
    const serve = (body: string): Transport => async () => ({ status: 200, headers: {}, body });
    for (const body of ['x'.repeat(MAX_RESPONSE_BYTES + 1), 'é'.repeat(600_000)])
        assert.equal(await codeOf(() => createNextDnsClient({ apiKey: () => KEY, transport: serve(body) }).getSettings('abc123')), 'bad_response', String(body.length));
    // Status 503 would map to `server` unless the byte cap fires first: 600k two-byte characters are 1.2 MB but only 600k UTF-16 units.
    const overBytes: Transport = async () => ({ status: 503, headers: {}, body: '\u00e9'.repeat(600_000) });
    assert.equal(await codeOf(() => createNextDnsClient({ apiKey: () => KEY, transport: overBytes, maxAttempts: 1 }).getSettings('abc123')), 'bad_response');
    const fits = JSON.stringify({ data: SETTINGS });
    assert.equal((await createNextDnsClient({ apiKey: () => KEY, transport: serve(fits) }).getSettings('abc123')).web3, false);
});

test('deadline: Retry-After beyond the budget stops with timeout; the default budget is 60 s', async () => {
    let t = 1_000_000;
    const slept: number[] = [];
    const api = createFakeNextDns({ apiKey: KEY });
    const mk = (extra: Partial<NextDnsClientOptions>) => createNextDnsClient({ apiKey: () => KEY, transport: api.transport, now: () => t, sleep: async ms => { slept.push(ms); t += ms; }, ...extra });
    api.enqueue(json(429, {}, { 'retry-after': '5' }));
    assert.equal(await codeOf(() => mk({ deadlineMs: 1000 }).getSettings('abc123')), 'timeout');
    assert.deepEqual(slept, []);
    assert.equal(DEFAULT_DEADLINE_MS, 60_000);
    for (let i = 0; i < 9; i++) api.enqueue(json(429, {}, { 'retry-after': '30' }));
    const before = api.requests.length;
    assert.equal(await codeOf(() => mk({ maxAttempts: 10 }).getSettings('abc123')), 'timeout');
    assert.deepEqual(slept, [30000, 30000]);
    assert.equal(api.requests.length - before, 3);
});

test('deadline covers pagination: slow pages stop with timeout', async () => {
    let t = 0;
    const api = createFakeNextDns({ apiKey: KEY, pageSize: 1, profiles: [profile('abc123', { denylist: many(10) })] });
    const transport: Transport = async req => { t += 400; return api.transport(req); };
    const c = createNextDnsClient({ apiKey: () => KEY, transport, now: () => t, deadlineMs: 1000 });
    assert.equal(await codeOf(() => c.getList('abc123', 'denylist')), 'timeout');
    assert.equal(api.requests.length, 3);
});

test('cancellation: a pre-aborted signal sends nothing; aborting during a retry sleep stops promptly', async () => {
    const api = createFakeNextDns({ apiKey: KEY });
    const pre = AbortSignal.abort();
    assert.equal(await codeOf(() => createNextDnsClient({ apiKey: () => KEY, transport: api.transport, signal: pre }).getSettings('abc123')), 'transport');
    assert.equal(api.requests.length, 0);
    api.enqueue(json(429, {}, { 'retry-after': '20' }));
    const c = createNextDnsClient({ apiKey: () => KEY, transport: api.transport });
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 20);
    const started = Date.now();
    assert.equal(await codeOf(() => c.getSettings('abc123', { signal: controller.signal })), 'transport');
    assert.ok(Date.now() - started < 5000);
    assert.equal(api.requests.length, 1);
});

test('abortableSleep resolves, rejects when aborted, and holds an unref\'d timer', async () => {
    const real = globalThis.setTimeout; let timer: ReturnType<typeof setTimeout> | undefined;
    const spy = mock.method(globalThis, 'setTimeout', ((...a: Parameters<typeof setTimeout>) => { timer = real(...a); return timer; }) as typeof setTimeout);
    try { await keepAlive(() => abortableSleep(1)); } finally { spy.mock.restore(); }
    assert.equal(timer!.hasRef(), false);
    assert.equal(await codeOf(() => abortableSleep(10_000, AbortSignal.abort())), 'transport');
    const c = new AbortController(); setTimeout(() => c.abort(), 5);
    assert.equal(await codeOf(() => abortableSleep(10_000, c.signal)), 'transport');
});

test('assertSafeNextDnsEnvironment refuses unsafe TLS and proxy settings without echoing values', () => {
    const reason = (env: Record<string, string>) => { try { assertSafeNextDnsEnvironment(env); return 'ok'; } catch (e) { return e instanceof NextDnsEnvironmentError ? e.reason : 'wrong-error'; } };
    assert.equal(reason({}), 'ok');
    assert.equal(reason({ NODE_TLS_REJECT_UNAUTHORIZED: '1', NODE_USE_ENV_PROXY: '0', HTTPS_PROXY: 'http://p:1' }), 'ok');
    assert.equal(reason({ NODE_USE_ENV_PROXY: '', https_proxy: 'http://p:1' }), 'ok');
    assert.equal(reason({ NODE_TLS_REJECT_UNAUTHORIZED: '0' }), 'tls_verification_disabled');
    assert.equal(reason({ NODE_USE_ENV_PROXY: '1' }), 'env_proxy_enabled');
    assert.equal(reason({ NODE_USE_ENV_PROXY: 'true' }), 'env_proxy_enabled');
    assert.equal(reason({ NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: 'http://secret-host:1' }), 'https_proxy_set');
    assert.equal(reason({ NODE_USE_ENV_PROXY: '1', https_proxy: 'http://secret-host:1' }), 'https_proxy_set');
    try { assertSafeNextDnsEnvironment({ NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: 'http://secret-host:1' }); } catch (e) { assert.ok(!String((e as Error).stack).includes('secret-host')); }
    assert.doesNotThrow(() => assertSafeNextDnsEnvironment());
});

test('fetch transport: relative paths, 3xx bodies, declared and streamed sizes, invalid UTF-8', async () => {
    let calls = 0;
    const t = (fn: () => Response, opts = {}) => fetchWith(async () => { calls++; return fn(); }, { maxBytes: 100, ...opts });
    assert.equal(await codeOf(() => t(() => new Response('{}'))({ ...GET, path: 'profiles/abc123' })), 'transport');
    assert.equal(calls, 0, 'refused before fetch');
    let cancelled = false;
    const stream = () => new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(10)); }, cancel() { cancelled = true; } });
    const redirect = await t(() => new Response(stream(), { status: 302, headers: { location: 'https://evil.example/' } }))(GET);
    assert.deepEqual([redirect.status, redirect.body, cancelled], [302, '', true]);
    cancelled = false;
    assert.equal(await codeOf(() => t(() => new Response(stream(), { headers: { 'content-length': '10000' } }))(GET)), 'bad_response');
    assert.equal(cancelled, true, 'a declared oversize body is cancelled, not read');
    assert.equal(await codeOf(() => t(() => new Response('{}', { headers: { 'content-length': '10000' } }))(GET)), 'bad_response');
    assert.equal(await codeOf(() => t(() => new Response(new Uint8Array([0xff, 0xfe, 0xfd])))(GET)), 'bad_response');
    const big = fetchWith(async () => new Response('x'.repeat(MAX_RESPONSE_BYTES)));
    assert.equal((await big(GET)).body.length, MAX_RESPONSE_BYTES);
    assert.equal(await codeOf(() => fetchWith(async () => new Response('x'.repeat(MAX_RESPONSE_BYTES + 1)))(GET)), 'bad_response');
});

test('fetch transport: the default timeout is 10 s, and a stalled body or request surfaces as timeout', async () => {
    assert.equal(DEFAULT_FETCH_TIMEOUT_MS, 10_000);
    const spy = mock.method(AbortSignal, 'timeout');
    try { await fetchWith(async () => new Response('{}'))(GET); } finally { spy.mock.restore(); }
    assert.equal(spy.mock.calls[0]!.arguments[0], 10_000);
    const stalled = new Response(new ReadableStream({ pull: () => new Promise(() => undefined) }));
    assert.equal(await keepAlive(() => codeOf(() => fetchWith(async () => stalled, { timeoutMs: 30 })(GET))), 'timeout');
    const never = fetchWith((_u, init) => new Promise((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason))), { timeoutMs: 30 });
    const c = createNextDnsClient({ apiKey: () => KEY, transport: never, maxAttempts: 1 });
    assert.equal(await keepAlive(() => statusOf(c, x => x.getSettings('abc123'))), 'timeout');
});
