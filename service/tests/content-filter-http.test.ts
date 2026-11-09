import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { AppError } from '../../shared/src/errors.ts';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { TestAuthenticator } from './authenticator.ts';
import { ContentFilterReconciler } from '../src/content-filter-reconcile.ts';
import { ContentFilterRoutes, PUTS_PER_MINUTE } from '../src/content-filter-http.ts';
import { ContentFilterStore, parseDesired } from '../src/content-filter-state.ts';
import type { FilterRecord } from '../src/content-filter-state.ts';
import type { ContentFilterMode } from '../src/content-filter-config.ts';
import type { Transport } from '../src/nextdns-client.ts';
import { API_KEY, DESIRED, PROFILE_ID, SECRET_ALLOWED, SECRET_DOMAIN, fakeWorld, input, json } from './fixtures/content-filter.ts';

async function freePort(): Promise<number> {
    const probe = createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const port = (probe.address() as {port: number}).port;
    await new Promise<void>(resolve => probe.close(() => resolve()));
    return port;
}
class RacyStore extends ContentFilterStore {
    script: (FilterRecord | undefined)[] = [];
    override get(person: string) { return this.script.length ? this.script.shift() : super.get(person); }
}
interface Options { mode?: ContentFilterMode; profiles?: Record<string, string>; wrap?: (next: Transport) => Transport; audit?: boolean; service?: boolean; authorize?: (actor: unknown, person: string) => void }
async function world(options: Options = {}) {
    const f = integrationFixture(), fake = fakeWorld(options.wrap);
    f.config.ownerAccountId = 'operator';
    if (options.audit !== false) f.config.auditLog = {enabled: true};
    f.store.run("INSERT INTO people(id,name,created_at) VALUES('other','Other child',0)");
    const port = await freePort(), origin = `http://localhost:${port}`, auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance});
    const filters = new RacyStore(f.store, f.now), reconciler = new ContentFilterReconciler({client: fake.client, profiles: options.profiles ?? {pilot: PROFILE_ID, other: PROFILE_ID, ghost: PROFILE_ID}, store: filters});
    const routes = new ContentFilterRoutes({auth, filters, reconciler, mode: options.mode ?? 'owner', ownerAccountId: 'operator', authorize: (actor, person) => { options.authorize?.(actor, person); f.policy.authorized(actor, person); }});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`}, undefined, undefined, undefined, undefined, options.service === false ? undefined : routes);
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    function client() {
        const jar = new Map<string, string>(); let csrf = '';
        async function call(method: string, path: string, input?: unknown, extra: Record<string, string> = {}, omit: string[] = []) {
            const headers: Record<string, string> = {Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), 'X-CSRF-Token': csrf, 'Content-Type': 'application/json', ...extra};
            for (const key of omit) delete headers[key];
            const response = await fetch(origin + path, {method, headers, ...(input === undefined ? {} : {body: JSON.stringify(input)})});
            for (const entry of response.headers.getSetCookie()) { const [key, value] = entry.split(';')[0].split('='); jar.set(key, value); }
            const text = await response.text(), body = JSON.parse(text);
            if (body.csrfToken) csrf = body.csrfToken;
            return {status: response.status, body, text};
        }
        const api = {
            call, get: (person: string) => call('GET', `/people/${person}/filter`), put: (person: string, desired: unknown, stepUp?: unknown) => call('PUT', `/people/${person}/filter`, stepUp === undefined ? {desired} : {desired, stepUp}),
            async signIn(account: string) {
                const key = new TestAuthenticator(), token = issueOperatorBootstrap(f.store, account, f.now());
                const o = await call('POST', '/auth/register/options', {token}); assert.equal(o.status, 200);
                assert.equal((await call('POST', '/auth/register/verify', {challengeId: o.body.challengeId, response: key.register(o.body.options, origin)})).status, 200);
                return key;
            },
            async proof(key: TestAuthenticator, person: string, desired: unknown) {
                const o = await call('POST', '/step-up/options', {action: 'content_filter_set', person, desired});
                assert.equal(o.status, 200, o.text);
                return {challengeId: o.body.challengeId, response: key.login(o.body.options, origin)};
            },
        };
        return api;
    }
    const audit = () => f.store.all<Record<string, unknown>>('SELECT * FROM parent_audit ORDER BY id').map(r => ({...r}));
    return {...f, auth, fake, filters, routes, client, audit, origin, cleanup: async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); f.cleanup(); }};
}
type W = Awaited<ReturnType<typeof world>>;
const err = (r: {status: number; body: {error?: {code: string}}}, status: number, code: string) => { assert.equal(r.status, status, JSON.stringify(r.body)); assert.equal(r.body.error?.code, code); };
async function seeded(w: W, account = 'operator') {
    const c = w.client(), key = await c.signIn(account);
    const first = await c.put('pilot', DESIRED, await c.proof(key, 'pilot', DESIRED));
    assert.equal(first.status, 200, first.text);
    return {c, key};
}

test('PUT then GET: stored, reconciled against the fake, state applied, note present, no profile id or key in the answer', async () => {
    const w = await world();
    try {
        const c = w.client(), key = await c.signIn('operator');
        err(await c.get('pilot'), 404, 'filter_not_set');
        const put = await c.put('pilot', input({categories: ['porn', 'gambling', 'porn']}), await c.proof(key, 'pilot', input({categories: ['porn', 'gambling', 'porn']})));
        assert.equal(put.status, 200, put.text);
        assert.deepEqual(Object.keys(put.body).filter(k => !['source', 'integrationScope', 'routerCompatibilityVerified'].includes(k)).sort(), ['desired', 'note', 'revision', 'state', 'stateAt']);
        assert.equal(put.body.revision, 1); assert.equal(put.body.state, 'applied'); assert.equal(put.body.note, 'unverified on this router');
        assert.deepEqual(put.body.desired, DESIRED);
        const got = await c.get('pilot');
        assert.equal(got.status, 200); assert.deepEqual({...got.body, stateAt: 0}, {...put.body, stateAt: 0});
        for (const text of [put.text, got.text]) { assert.ok(!text.includes(PROFILE_ID)); assert.ok(!text.includes(API_KEY)); }
        assert.deepEqual(w.fake.profile.denylist, [{id: SECRET_DOMAIN, active: true}]);
    } finally { await w.cleanup(); }
});

test('reconcile outcomes reach the caller as honest states: pending, drift and not_confirmed are never shown as applied', async () => {
    let w2!: W;
    for (const [name, wrap, expected] of [
        ['rate limited', (next: Transport): Transport => async req => req.method === 'GET' ? next(req) : json(429, {errors: [{code: 'r'}]}), 'pending'],
        ['read-back fails', (next: Transport): Transport => async req => req.method === 'GET' ? json(500, {errors: [{code: 'x'}]}) : next(req), 'not_confirmed'],
        ['drift', (next: Transport): Transport => async req => { const res = await next(req); if (req.method === 'PUT' && req.path.endsWith('/allowlist')) w2.fake.profile.allowlist.length = 0; return res; }, 'drift'],
    ] as const) {
        const w = w2 = await world({wrap});
        try {
            const {c} = await (async () => { const c = w.client(), key = await c.signIn('operator'); const r = await c.put('pilot', DESIRED, await c.proof(key, 'pilot', DESIRED)); assert.equal(r.status, 200); assert.equal(r.body.state, expected, name); return {c}; })();
            assert.equal((await c.get('pilot')).body.state, expected, name);
        } finally { await w.cleanup(); }
    }
});

test('mode off, an absent service and an excluded actor all answer as if the route did not exist', async () => {
    for (const options of [{mode: 'off'} as Options, {service: false}]) {
        const w = await world(options);
        try {
            const c = w.client(), key = await c.signIn('operator');
            err(await c.get('pilot'), 404, 'route_not_found');
            err(await c.put('pilot', DESIRED), 405, 'method_not_allowed');
            const o = await c.call('POST', '/step-up/options', {action: 'content_filter_set', person: 'pilot', desired: DESIRED});
            assert.notEqual(o.status, 200); void key;
            assert.equal(w.filters.get('pilot'), undefined); assert.equal(w.fake.fake.requests.length, 0);
        } finally { await w.cleanup(); }
    }
});

test('owner mode: only the owner account; parents mode: any parent in scope', async () => {
    const owner = await world({mode: 'owner'});
    try {
        await seeded(owner);
        const p = owner.client(); await p.signIn('parent');
        err(await p.get('pilot'), 404, 'route_not_found'); err(await p.put('pilot', DESIRED), 405, 'method_not_allowed');
        assert.equal((await p.call('POST', '/step-up/options', {action: 'content_filter_set', person: 'pilot', desired: DESIRED})).status, 400);
        assert.equal(owner.filters.get('pilot')!.revision, 1);
    } finally { await owner.cleanup(); }
    const parents = await world({mode: 'parents'});
    try {
        const p = parents.client(), key = await p.signIn('parent');
        const r = await p.put('pilot', DESIRED, await p.proof(key, 'pilot', DESIRED));
        assert.equal(r.status, 200, r.text); assert.equal((await p.get('pilot')).status, 200);
        assert.equal(parents.filters.get('pilot')!.revision, 1);
    } finally { await parents.cleanup(); }
});

test('person scoping: unknown, out-of-scope and unmapped children get one identical 404, on GET, PUT and step-up', async () => {
    const mapped = await world({mode: 'parents'}), unmapped = await world({mode: 'parents', profiles: {other: PROFILE_ID}});
    try {
        const bodies: string[] = [], clients = new Map([[mapped, mapped.client()], [unmapped, unmapped.client()]]);
        for (const c of clients.values()) await c.signIn('parent');
        for (const [w, person] of [[mapped, 'nobody'], [mapped, 'other'], [unmapped, 'pilot'], [mapped, 'ghost']] as const) {
            const c = clients.get(w)!;
            for (const r of [await c.get(person), await c.put(person, DESIRED), await c.call('POST', '/step-up/options', {action: 'content_filter_set', person, desired: DESIRED})]) {
                err(r, 404, 'person_not_found'); bodies.push(JSON.stringify(r.body.error));
            }
        }
        assert.equal(new Set(bodies).size, 1);
        assert.equal(mapped.filters.get('other'), undefined); assert.equal(mapped.fake.fake.requests.length + unmapped.fake.fake.requests.length, 0, 'no NextDNS call for a child that is not visible');
        assert.deepEqual(mapped.audit(), []);
    } finally { await mapped.cleanup(); await unmapped.cleanup(); }
});

test('the body is strict: unknown, missing and malformed fields are refused before anything is stored', async () => {
    const w = await world();
    try {
        const c = w.client(), key = await c.signIn('operator'), proof = await c.proof(key, 'pilot', DESIRED);
        err(await c.call('PUT', '/people/pilot/filter', {desired: DESIRED, extra: 1}), 400, 'invalid_fields');
        err(await c.call('PUT', '/people/pilot/filter', {}), 400, 'invalid_fields');
        err(await c.call('PUT', '/people/pilot/filter', {desired: {...DESIRED, extra: 1}}), 400, 'invalid_filter');
        err(await c.put('pilot', input({safeSearch: 'yes'})), 400, 'invalid_filter');
        err(await c.put('pilot', input({denylist: [`${SECRET_DOMAIN}/x`]})), 400, 'invalid_filter');
        err(await c.put('pilot', input({allowlist: [`*.${SECRET_ALLOWED}`]})), 400, 'invalid_filter');
        err(await c.put('pilot', input({categories: ['PORN']})), 400, 'invalid_filter');
        err(await c.call('PUT', '/people/pilot/filter', 'text'), 400, 'invalid_object');
        err(await c.call('PUT', '/people/pilot/filter', {desired: DESIRED}, {'Content-Type': 'text/plain'}), 415, 'json_required');
        err(await c.call('PUT', '/people/pilot/filter', {desired: input({denylist: Array.from({length: 4000}, (_, n) => `host${n}.example.test`)})}), 413, 'body_too_large');
        assert.equal(w.filters.get('pilot'), undefined);
        assert.equal((await c.put('pilot', DESIRED, proof)).status, 200, 'the proof was untouched by the refused attempts');
    } finally { await w.cleanup(); }
});

test('origin, session and CSRF gates cover PUT and the step-up options', async () => {
    const w = await world();
    try {
        const c = w.client(); await c.signIn('operator');
        for (const [method, path, body] of [['PUT', '/people/pilot/filter', {desired: DESIRED}], ['POST', '/step-up/options', {action: 'content_filter_set', person: 'pilot', desired: DESIRED}]] as const) {
            for (const [extra, omit] of [[{Origin: 'https://elsewhere.invalid'}, []], [{}, ['X-CSRF-Token']], [{}, ['Cookie']]] as const) {
                const r = await c.call(method, path, body, extra, [...omit]);
                assert.ok([401, 403].includes(r.status), `${method} ${path}: ${r.status}`);
            }
        }
        const other = await c.call('DELETE', '/people/pilot/filter', undefined);
        err(other, 405, 'method_not_allowed');
        assert.equal(w.filters.get('pilot'), undefined);
    } finally { await w.cleanup(); }
});

test('loosening requires a fresh step-up bound to {child, filter}: missing, other filter, other child, replayed and garbage proofs are refused', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c, key} = await seeded(w, 'parent');
        const loose = input({categories: ['porn']}), tight = input({categories: ['porn', 'gambling', 'social']});
        err(await c.put('pilot', loose), 403, 'step_up_required');
        err(await c.put('pilot', loose, {challengeId: 'x'.repeat(43), response: {}}), 401, 'invalid_challenge');
        err(await c.put('pilot', loose, 'garbage'), 400, 'invalid_object');
        err(await c.put('pilot', loose, await c.proof(key, 'pilot', DESIRED)), 403, 'step_up_mismatch');
        err(await c.put('pilot', loose, await c.proof(key, 'pilot', input({categories: ['gambling']}))), 403, 'step_up_mismatch');
        const forOther = await c.call('POST', '/step-up/options', {action: 'content_filter_set', person: 'other', desired: loose}); err(forOther, 404, 'person_not_found');
        assert.equal(w.filters.get('pilot')!.revision, 1, 'nothing was stored by any refusal');
        const good = await c.proof(key, 'pilot', loose);
        assert.equal((await c.put('pilot', loose, good)).status, 200);
        err(await c.put('pilot', input({categories: []}), good), 401, 'invalid_challenge');
        assert.equal(w.filters.get('pilot')!.revision, 2);
    } finally { await w.cleanup(); }
});

test('a proven loosening commits the passkey use: the credential counter advances in the same transaction', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c, key} = await seeded(w, 'operator');
        const counter = () => w.store.get<{counter: number}>("SELECT counter FROM credentials WHERE account_id='operator'")!.counter;
        const before = counter(), loose = input({categories: ['porn']});
        assert.equal((await c.put('pilot', loose, await c.proof(key, 'pilot', loose))).status, 200);
        assert.ok(counter() > before, 'commitStepUp stored the new authenticator counter');
        const tighten = input({categories: ['porn', 'social']}), after = counter();
        assert.equal((await c.put('pilot', tighten)).status, 200);
        assert.equal(counter(), after, 'a tightening PUT uses no passkey');
    } finally { await w.cleanup(); }
});

test('a step-up for one child cannot loosen another child with the very same filter', async () => {
    const w = await world({mode: 'parents'});
    try {
        w.store.run("UPDATE accounts SET person_ids='[\"pilot\",\"other\"]' WHERE id='parent'");
        const c = w.client(), key = await c.signIn('parent'), loose = input({categories: ['porn']});
        for (const person of ['pilot', 'other']) assert.equal((await c.put(person, DESIRED, await c.proof(key, person, DESIRED))).status, 200);
        const forPilot = await c.proof(key, 'pilot', loose);
        err(await c.put('other', loose, forPilot), 403, 'step_up_mismatch');
        assert.equal(w.filters.get('other')!.revision, 1);
        assert.equal((await c.put('pilot', loose, await c.proof(key, 'pilot', loose))).status, 200);
    } finally { await w.cleanup(); }
});

test('a step-up from another account or session is not accepted', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c: theirs} = await seeded(w, 'operator'), mine = w.client(), myKey = await mine.signIn('parent');
        const loose = input({categories: ['porn']});
        const stolen = await theirs.call('POST', '/step-up/options', {action: 'content_filter_set', person: 'pilot', desired: loose});
        assert.equal(stolen.status, 200);
        const response = myKey.login(stolen.body.options, w.origin);
        err(await mine.put('pilot', loose, {challengeId: stolen.body.challengeId, response}), 403, 'step_up_mismatch');
        assert.equal(w.filters.get('pilot')!.revision, 1);
    } finally { await w.cleanup(); }
});

test('tightening needs no step-up: more categories, a new denylist entry, a removed allowlist entry, flags turned on', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c} = await seeded(w, 'parent');
        const steps = [input({categories: ['gambling', 'porn', 'social']}), input({categories: ['gambling', 'porn', 'social'], denylist: [SECRET_DOMAIN, 'second-example.test']}),
            input({categories: ['gambling', 'porn', 'social'], denylist: [SECRET_DOMAIN, 'second-example.test'], allowlist: []})];
        for (const [n, desired] of steps.entries()) { const r = await c.put('pilot', desired); assert.equal(r.status, 200, r.text); assert.equal(r.body.revision, n + 2); assert.equal(r.body.state, 'applied'); }
        const same = await c.put('pilot', steps[2]); assert.equal(same.status, 200); assert.equal(same.body.revision, 5);
    } finally { await w.cleanup(); }
});

test('every loosening rule is refused over HTTP without a proof, and the stored filter is untouched', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c} = await seeded(w, 'parent');
        const before = JSON.stringify(w.filters.get('pilot'));
        for (const over of [{categories: ['porn']}, {services: []}, {denylist: []}, {allowlist: [SECRET_ALLOWED, 'more-example.test']}, {safeSearch: false}, {youtubeRestrictedMode: false}, {blockBypass: false}]) {
            err(await c.put('pilot', input(over)), 403, 'step_up_required');
        }
        assert.equal(JSON.stringify(w.filters.get('pilot')), before);
    } finally { await w.cleanup(); }
});

test('the first PUT for a child has no stored baseline and counts as loosening (fail closed)', async () => {
    const w = await world();
    try { const c = w.client(); await c.signIn('operator'); err(await c.put('pilot', DESIRED), 403, 'step_up_required'); assert.equal(w.filters.get('pilot'), undefined); } finally { await w.cleanup(); }
});

test('loosening is judged again inside the commit: a stored state that changed after the pre-check cannot slip through unproven', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c} = await seeded(w, 'parent'), stored = w.filters.get('pilot')!;
        const weaker = {...stored, desired: parseDesired(input({categories: []})), revision: 1};
        const next = input({categories: ['porn']});
        w.filters.script = [weaker, stored];
        err(await c.put('pilot', next), 403, 'step_up_required');
        assert.equal(w.filters.get('pilot')!.revision, 1);
    } finally { await w.cleanup(); }
});

test('audit rows carry an action type and the child only: set for tightening, loosened for a proven loosening; refusals leave none', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c, key} = await seeded(w, 'parent');
        await c.put('pilot', input({categories: ['gambling', 'porn', 'social']}));
        err(await c.put('pilot', input({categories: []})), 403, 'step_up_required');
        const loose = input({categories: [], denylist: []});
        assert.equal((await c.put('pilot', loose, await c.proof(key, 'pilot', loose))).status, 200);
        const rows = w.audit();
        assert.deepEqual(rows.map(r => [r.actor_id, r.action, r.person_id, r.operation_id, r.result]), [['parent', 'content_filter_loosened', 'pilot', null, 'applied'], ['parent', 'content_filter_set', 'pilot', null, 'applied'], ['parent', 'content_filter_loosened', 'pilot', null, 'applied']]);
        const dump = JSON.stringify([rows, w.store.all('SELECT * FROM audit')]);
        for (const secret of [SECRET_DOMAIN, SECRET_ALLOWED, 'second-example', 'porn', 'gambling', 'tiktok', PROFILE_ID, API_KEY, w.config.person.device.mac]) assert.ok(!dump.includes(secret), secret);
        const page = await c.call('GET', '/audit'); assert.equal(page.status, 200);
        assert.deepEqual(page.body.entries.map((e: {action: string}) => e.action), ['content_filter_loosened', 'content_filter_set', 'content_filter_loosened']);
    } finally { await w.cleanup(); }
});

test('the audit row is part of the change: if it cannot be written the PUT fails and nothing is stored', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c, key} = await seeded(w, 'operator'), before = JSON.stringify(w.filters.get('pilot')), auditBefore = w.audit().length;
        w.store.db.exec("CREATE TRIGGER audit_refuses BEFORE INSERT ON parent_audit BEGIN SELECT RAISE(ABORT, 'audit down'); END");
        const loose = input({categories: ['porn']}), proof = await c.proof(key, 'pilot', loose);
        const r = await c.put('pilot', loose, proof);
        assert.ok(r.status >= 500, r.text); assert.ok(!r.text.includes('audit down'));
        const tight = await c.put('pilot', input({categories: ['gambling', 'porn', 'social']}));
        assert.ok(tight.status >= 500);
        assert.equal(JSON.stringify(w.filters.get('pilot')), before, 'neither change was stored');
        assert.equal(w.audit().length, auditBefore);
        w.store.db.exec('DROP TRIGGER audit_refuses');
        assert.equal((await c.put('pilot', loose, await c.proof(key, 'pilot', loose))).status, 200);
        assert.equal(w.audit().at(-1)!.action, 'content_filter_loosened');
    } finally { await w.cleanup(); }
});

test('the child is authorised again at commit: deactivated or re-scoped during the step-up window means refused, nothing stored', async () => {
    let calls = 0, revoke = false;
    const w = await world({mode: 'parents', authorize: () => { calls++; if (revoke) throw new AppError(404, 'person_not_found'); }});
    try {
        const {c, key} = await seeded(w, 'operator'), loose = input({categories: ['porn']}), proof = await c.proof(key, 'pilot', loose);
        const callsBefore = calls;
        // The pre-check passes; the child disappears after it (during the await of the passkey check) and before the commit.
        const original = w.auth.stepUpVerify.bind(w.auth);
        w.auth.stepUpVerify = async (...args: Parameters<typeof original>) => { const result = await original(...args); revoke = true; return result; };
        err(await c.put('pilot', loose, proof), 404, 'person_not_found');
        assert.ok(calls > callsBefore + 1, 'authorize ran again inside the commit');
        assert.equal(w.filters.get('pilot')!.revision, 1);
    } finally { await w.cleanup(); }
});

test('G7: parent-chosen domains, the key, the profile id and MACs never reach stdout, stderr, audit rows or error bodies; the authorised GET does return the domains', async () => {
    const captured: string[] = [], out = process.stdout.write.bind(process.stdout), errW = process.stderr.write.bind(process.stderr);
    const w = await world({mode: 'parents', wrap: next => async req => {
        if (req.method === 'PUT' && req.path.endsWith('/denylist') && req.body?.includes('trouble')) return json(400, {errors: [{code: 'invalid', detail: `no ${SECRET_DOMAIN}`, source: {pointer: `/${SECRET_DOMAIN}`}}]});
        return next(req);
    }});
    // Record and pass through, so a reporter sharing this process (test-isolation=none) is not swallowed.
    process.stdout.write = ((chunk: unknown, ...rest: unknown[]) => { captured.push(String(chunk)); return (out as (...a: unknown[]) => boolean)(chunk, ...rest); }) as typeof process.stdout.write;
    process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => { captured.push(String(chunk)); return (errW as (...a: unknown[]) => boolean)(chunk, ...rest); }) as typeof process.stderr.write;
    const responses: string[] = [];
    let auditDump = '';
    try {
        const c = w.client(), key = await c.signIn('parent');
        // Only the 200 answers to the authorised parent may carry the parent's own domains; every refusal body is checked.
        const record = async (r: {status: number; text: string}) => { if (r.status !== 200) responses.push(r.text); return r; };
        await record(await c.put('pilot', DESIRED, await c.proof(key, 'pilot', DESIRED)));
        for (const bad of [input({denylist: [`${SECRET_DOMAIN}/x`]}), input({denylist: [SECRET_DOMAIN.toUpperCase().replace('.TEST', '.123')]}), {...DESIRED, [SECRET_DOMAIN]: true}]) await record(await c.put('pilot', bad));
        await record(await c.put('pilot', input({denylist: [SECRET_DOMAIN, 'trouble-example.test']})));
        await record(await c.call('PUT', '/people/pilot/filter', {desired: DESIRED, [SECRET_DOMAIN]: 1}));
        await record(await c.call('PUT', '/people/pilot/filter', {desired: DESIRED, stepUp: {challengeId: SECRET_DOMAIN, response: SECRET_DOMAIN}}));
        await record(await c.get('other'));
        const got = await c.get('pilot');
        assert.ok(got.text.includes(SECRET_DOMAIN) && got.text.includes(SECRET_ALLOWED), 'the authorised parent sees what they configured');
        auditDump = JSON.stringify([w.audit(), w.store.all('SELECT * FROM audit')]);
    } finally { process.stdout.write = out; process.stderr.write = errW; await w.cleanup(); }
    assert.ok(responses.length >= 6, 'the refusal bodies were collected');
    const haystack = [...captured, ...responses, auditDump].join('\n');
    for (const secret of [SECRET_DOMAIN, 'trouble-example', API_KEY, PROFILE_ID, '02:10:20:30:40:50', 'localhost']) assert.ok(!haystack.includes(secret), `leaked ${secret}`);
});

test('PUT is rate limited per actor', async () => {
    const w = await world({mode: 'parents'});
    try {
        const {c} = await seeded(w, 'operator');
        const grow = (n: number) => input({categories: ['gambling', 'porn', ...Array.from({length: n}, (_, k) => `extra${String(k).padStart(2, '0')}`)]});
        for (let n = 1; n < PUTS_PER_MINUTE; n++) assert.equal((await c.put('pilot', grow(n))).status, 200, String(n));
        err(await c.put('pilot', grow(PUTS_PER_MINUTE)), 429, 'content_filter_rate_limited');
        w.advance(61);
        assert.equal((await c.put('pilot', grow(PUTS_PER_MINUTE))).status, 200);
    } finally { await w.cleanup(); }
});
