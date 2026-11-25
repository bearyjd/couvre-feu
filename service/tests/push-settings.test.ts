import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { freePort } from './free-port.ts';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { PushSettings, TEST_COOLDOWN_SECONDS } from '../src/push-settings.ts';
import { NtfyPush, ntfySettings, pushText } from '../src/push-sender.ts';
import { TestAuthenticator } from './authenticator.ts';

const TOKEN = 'tk_secrettoken123456', TOPIC = 'couvre_topic_abc123456789', URL_TEXT = 'http://127.0.0.1:2586', RESPONSE_TEXT = 'ntfy-internal-detail-xyz';
const SECRETS = [TOKEN, TOPIC, URL_TEXT, '127.0.0.1:2586', RESPONSE_TEXT];
const utc = (...a: [number, number, number, number]) => Date.UTC(a[0], a[1] - 1, a[2], a[3]) / 1000;
const DAYTIME = utc(2026, 11, 25, 17), NIGHT = utc(2026, 11, 25, 5);

interface Sent { url: string; body: string; headers: Record<string, string> }
async function world(options: {enabled?: boolean; configured?: boolean; status?: number; now?: {value: number}} = {}) {
    const f = integrationFixture(), port = await freePort(), origin = `http://localhost:${port}`;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const sent: Sent[] = [], logs: string[] = [], clock = options.now ?? {value: DAYTIME};
    const fakeFetch = (async (url: string, init: RequestInit) => {
        sent.push({url, body: String(init.body), headers: init.headers as Record<string, string>});
        return new Response(RESPONSE_TEXT, {status: options.status ?? 200});
    }) as unknown as typeof fetch;
    const sender = options.configured === false ? null : new NtfyPush(ntfySettings({COUVRE_NTFY_URL: URL_TEXT, COUVRE_NTFY_TOPIC: TOPIC, COUVRE_NTFY_TOKEN: TOKEN}), origin, {fetch: fakeFetch, maxAttempts: 1, log: line => logs.push(String(line))});
    const push = options.enabled === false ? undefined : new PushSettings(sender, () => clock.value);
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`}, undefined, undefined, undefined, f.worker.inventory, undefined, undefined, push);
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    async function client(account: string) {
        const jar = new Map<string, string>(); let csrf = '';
        const call = async (method: string, path: string, input?: unknown, omit: string[] = []) => {
            const headers: Record<string, string> = {Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), 'X-CSRF-Token': csrf, 'Content-Type': 'application/json'};
            for (const key of omit) delete headers[key];
            const response = await fetch(origin + path, {method, headers, ...(input === undefined ? {} : {body: JSON.stringify(input)})});
            for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); jar.set(k, v); }
            const text = await response.text(), body = JSON.parse(text) as Record<string, any>;
            if (body.csrfToken) csrf = body.csrfToken;
            return {status: response.status, body, text};
        };
        const key = new TestAuthenticator(), reg = await call('POST', '/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
        assert.equal((await call('POST', '/auth/register/verify', {challengeId: reg.body.challengeId, response: key.register(reg.body.options, origin)})).status, 200);
        return {call, get: () => call('GET', '/push/settings'), test: (omit: string[] = []) => call('POST', '/push/test', {}, omit)};
    }
    const cleanup = async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); f.cleanup(); };
    return {client, sent, logs, clock, cleanup};
}
const noSecrets = (text: string) => { for (const s of SECRETS) assert.ok(!text.includes(s), `leaked ${s}`); assert.ok(!/delivered/i.test(text)); };

test('push disabled: both routes do not exist', async () => {
    const w = await world({enabled: false});
    try {
        const admin = await w.client('operator');
        assert.equal((await admin.get()).status, 404);
        assert.equal((await admin.test()).status, 404);
        assert.equal(w.sent.length, 0);
    } finally { await w.cleanup(); }
});

test('a non-admin is refused on both routes and nothing is sent', async () => {
    const w = await world();
    try {
        const parent = await w.client('parent');
        assert.equal((await parent.get()).status, 403);
        assert.equal((await parent.test()).status, 403);
        assert.equal(w.sent.length, 0);
    } finally { await w.cleanup(); }
});

test('GET snapshot: fixed shape, held kinds imported, no secrets', async () => {
    const w = await world();
    try {
        const admin = await w.client('operator'), r = await admin.get();
        assert.equal(r.status, 200);
        const {push} = r.body;
        assert.deepEqual(push, {provider: 'ntfy', configured: true,
            quietHours: {start: '21:00', end: '07:00', zone: 'America/New_York', activeNow: false}, heldKinds: ['time_request_pending', 'repeated_blocked_attempts'],
            digest: {audience: 'admins', day: 'sunday', time: '18:00', zone: 'America/New_York'}});
        noSecrets(r.text);
        w.clock.value = NIGHT;
        assert.equal((await admin.get()).body.push.quietHours.activeNow, true);
    } finally { await w.cleanup(); }
});

test('GET reports configured:false when ntfy settings are absent', async () => {
    const w = await world({configured: false});
    try { assert.equal((await (await w.client('operator')).get()).body.push.configured, false); } finally { await w.cleanup(); }
});

test('POST needs CSRF', async () => {
    const w = await world();
    try {
        const admin = await w.client('operator');
        assert.equal((await admin.test(['X-CSRF-Token'])).status, 403);
        assert.equal(w.sent.length, 0);
    } finally { await w.cleanup(); }
});

test('POST sends only the fixed test text and reports sent_to_push_service', async () => {
    const w = await world();
    try {
        const admin = await w.client('operator'), r = await admin.test();
        assert.equal(r.status, 200);
        assert.equal(r.body.result, 'sent_to_push_service');
        assert.equal(w.sent.length, 1);
        assert.equal(w.sent[0].body, pushText({kind: 'test'}).body);
        assert.equal(w.sent[0].headers.Title, 'Couvre-feu');
        noSecrets(r.text + w.logs.join(''));
        assert.ok(!/[0-9a-f]{2}(:[0-9a-f]{2}){5}|\d+\.\d+\.\d+\.\d+|operator|Test operator|Test parent|pilot/i.test(w.sent[0].body + w.sent[0].headers.Title));
    } finally { await w.cleanup(); }
});

test('POST failure is a tag only; response text, url, topic and token stay out of response and log', async () => {
    const w = await world({status: 500});
    try {
        const admin = await w.client('operator'), r = await admin.test();
        assert.equal(r.status, 200);
        assert.equal(r.body.result, 'push_failed:http_500');
        assert.equal(w.sent.length, 1);
        noSecrets(r.text + w.logs.join(''));
        assert.ok(w.logs.length > 0);
    } finally { await w.cleanup(); }
});

test('POST without ntfy settings reports not_configured and sends nothing', async () => {
    const w = await world({configured: false});
    try {
        const r = await (await w.client('operator')).test();
        assert.equal(r.status, 200);
        assert.equal(r.body.result, 'not_configured');
        assert.equal(w.sent.length, 0);
    } finally { await w.cleanup(); }
});

test('POST has a per-account cooldown', async () => {
    const w = await world();
    try {
        const admin = await w.client('operator');
        assert.equal((await admin.test()).status, 200);
        const again = await admin.test();
        assert.equal(again.status, 429);
        assert.equal(again.body.error.code, 'push_test_cooldown');
        assert.equal(w.sent.length, 1);
        w.clock.value += TEST_COOLDOWN_SECONDS;
        assert.equal((await admin.test()).status, 200);
        assert.equal(w.sent.length, 2);
    } finally { await w.cleanup(); }
});

test('pushText covers the test kind with fixed text', () => {
    assert.deepEqual(pushText({kind: 'test'}), {title: 'Couvre-feu', body: 'Test notification. Nothing needs your attention.'});
});
