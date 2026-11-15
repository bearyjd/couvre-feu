import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { TestAuthenticator } from './authenticator.ts';
import { ContentFilterReconciler } from '../src/content-filter-reconcile.ts';
import { ContentFilterRoutes } from '../src/content-filter-http.ts';
import { ContentFilterStore } from '../src/content-filter-state.ts';
import { ContentFilterCountsStore } from '../src/content-filter-counts.ts';
import { addDays, localDay } from '../src/content-filter-day.ts';
import { CLASS_CODES } from '../../shared/src/content-filter-classes.ts';
import type { ContentFilterMode } from '../src/content-filter-config.ts';
import { PROFILE_ID, fakeWorld } from './fixtures/content-filter.ts';

async function freePort(): Promise<number> {
    const probe = createServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const port = (probe.address() as {port: number}).port;
    await new Promise<void>(resolve => probe.close(() => resolve()));
    return port;
}
const HOSTILE = '<img src=x onerror=alert(1)>';
interface Options { mode?: ContentFilterMode; counts?: boolean; profiles?: Record<string, string> }
async function world(options: Options = {}) {
    const f = integrationFixture(), fake = fakeWorld();
    f.config.ownerAccountId = 'operator';
    f.store.run('INSERT INTO people(id,name,created_at) VALUES(?,?,0)', 'other', HOSTILE);
    f.store.run('UPDATE people SET name=? WHERE id=?', HOSTILE, 'pilot');
    const port = await freePort(), origin = `http://localhost:${port}`, auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance});
    const counts = new ContentFilterCountsStore(f.store);
    const filters = new ContentFilterStore(f.store, f.now), reconciler = new ContentFilterReconciler({client: fake.client, profiles: options.profiles ?? {pilot: PROFILE_ID, other: PROFILE_ID}, store: filters});
    const routes = new ContentFilterRoutes({auth, filters, reconciler, mode: options.mode ?? 'owner', ownerAccountId: 'operator', ...(options.counts === false ? {} : {counts}), authorize: (actor, person) => { f.policy.authorized(actor, person); }});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`}, undefined, undefined, undefined, undefined, routes);
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    const jar = new Map<string, string>(); let csrf = '';
    async function call(method: string, path: string, extra: Record<string, string> = {}, omit: string[] = []) {
        const headers: Record<string, string> = {Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), 'X-CSRF-Token': csrf, 'Content-Type': 'application/json', ...extra};
        for (const key of omit) delete headers[key];
        const response = await fetch(origin + path, {method, headers});
        for (const entry of response.headers.getSetCookie()) { const [key, value] = entry.split(';')[0].split('='); jar.set(key, value); }
        const text = await response.text(), body = JSON.parse(text);
        if (body.csrfToken) csrf = body.csrfToken;
        return {status: response.status, body, text, headers: response.headers};
    }
    const api = {
        call, get: (person: string, extra: Record<string, string> = {}, omit: string[] = []) => call('GET', `/people/${person}/filter/counts`, extra, omit),
        async signIn(account: string) {
            const key = new TestAuthenticator(), token = issueOperatorBootstrap(f.store, account, f.now());
            const post = async (path: string, body: unknown) => {
                const response = await fetch(origin + path, {method: 'POST', headers: {Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), 'Content-Type': 'application/json'}, body: JSON.stringify(body)});
                for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); jar.set(k, v); }
                const text = await response.text(), parsed = JSON.parse(text);
                if (parsed.csrfToken) csrf = parsed.csrfToken;
                return {status: response.status, body: parsed};
            };
            const o = await post('/auth/register/options', {token}); assert.equal(o.status, 200);
            assert.equal((await post('/auth/register/verify', {challengeId: o.body.challengeId, response: key.register(o.body.options, origin)})).status, 200);
        },
    };
    const yesterday = addDays(localDay(f.now()), -1);
    return {...f, counts, api, yesterday, cleanup: async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); f.cleanup(); }};
}
type W = Awaited<ReturnType<typeof world>>;
/** The server spreads its provenance (source, scope) into every answer; the counts route adds only the three keys below. */
const own = (body: Record<string, unknown>) => { const {source: _s, integrationScope: _i, routerCompatibilityVerified: _r, ...rest} = body; return rest; };
const err = (r: {status: number; body: {error?: {code: string}}}, status: number, code: string) => { assert.equal(r.status, status, JSON.stringify(r.body)); assert.equal(r.body.error?.code, code); };
function seed(w: W, person = 'pilot') {
    const d = (n: number) => addDays(w.yesterday, -n), now = w.now();
    w.counts.put(person, {day: d(0), state: 'ok', total: 4210, blocked: 63, classes: {adult: 2, social: 11, apps: 9, bypass: 1, ads_trackers: 40}}, now);
    w.counts.put(person, {day: d(1), state: 'suspect_zero', total: 0, blocked: 0, classes: {}}, now);
    w.counts.put(person, {day: d(2), state: 'logs_off', total: null, blocked: null, classes: {}}, now);
    w.counts.markUnavailable(person, d(3), now);
    // d(4) has no row at all; d(5), d(6) are ok with nothing blocked
    w.counts.put(person, {day: d(5), state: 'ok', total: 10, blocked: 0, classes: {}}, now);
    w.counts.put(person, {day: d(6), state: 'ok', total: 12, blocked: 1, classes: {gambling: 1}}, now);
    w.counts.put(person, {day: addDays(d(6), -1), state: 'ok', total: 5, blocked: 5, classes: {adult: 5}}, now); // outside the window
}

test('shape: last 7 finished days, integers and class codes only, gaps named, no profile id, no-store', async () => {
    const w = await world();
    try {
        seed(w); await w.api.signIn('operator');
        const r = await w.api.get('pilot');
        assert.equal(r.status, 200, r.text);
        assert.equal(r.headers.get('cache-control'), 'no-store');
        const days = r.body.days as {day: string; state: string; total?: number; blocked?: number; classes?: Record<string, number>}[];
        assert.equal(days.length, 7);
        assert.deepEqual(days.map(d => d.day), [6, 5, 4, 3, 2, 1, 0].map(n => addDays(w.yesterday, -n)));
        assert.deepEqual(days.map(d => d.state), ['ok', 'ok', 'gap', 'gap', 'logs_off', 'suspect_zero', 'ok']);
        assert.deepEqual(days[6], {day: w.yesterday, state: 'ok', total: 4210, blocked: 63, classes: {adult: 2, social: 11, apps: 9, bypass: 1, ads_trackers: 40}});
        assert.deepEqual(days[5], {day: addDays(w.yesterday, -1), state: 'suspect_zero', total: 0, blocked: 0, classes: {}});
        assert.deepEqual(days[4], {day: addDays(w.yesterday, -2), state: 'logs_off'});
        assert.deepEqual(days[2], {day: addDays(w.yesterday, -4), state: 'gap'});
        assert.deepEqual(Object.keys(own(r.body)).sort(), ['days', 'note', 'week']);
        assert.equal(r.body.note, 'unverified on this router');
        assert.deepEqual(r.body.week, {filterBlocked: 24, background: 40, okDays: 3, days: 7});
        for (const d of days) for (const [code, n] of Object.entries(d.classes ?? {})) { assert.ok((CLASS_CODES as readonly string[]).includes(code)); assert.ok(Number.isInteger(n)); }
        assert.ok(r.text.length < 4096);
        assert.ok(!r.text.includes(PROFILE_ID));
    } finally { await w.cleanup(); }
});

test('privacy: no domain, device, MAC, vendor or name strings in any answer; a hostile person name is not echoed', async () => {
    const w = await world();
    try {
        seed(w); await w.api.signIn('operator');
        const bodies = [(await w.api.get('pilot')).text, (await w.api.get('other')).text, (await w.api.get('nobody')).text];
        for (const text of bodies) {
            assert.ok(!text.includes('<img') && !text.includes('onerror'), text);
            assert.ok(!/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i.test(text), text);
            assert.ok(!/\.(test|com|net)\b/.test(text), text);
            assert.ok(!text.includes(PROFILE_ID), text);
        }
        const strings = JSON.stringify(own(JSON.parse(bodies[0]))).match(/"[^"]*"/g)!.map(s => s.slice(1, -1));
        const allowed = new Set<string>([...CLASS_CODES, 'note', 'days', 'week', 'day', 'state', 'total', 'blocked', 'classes', 'filterBlocked', 'background', 'okDays', 'unverified on this router', 'ok', 'gap', 'logs_off', 'suspect_zero']);
        for (const s of strings) assert.ok(allowed.has(s) || /^\d{4}-\d{2}-\d{2}$/.test(s), `unexpected string ${s}`);
    } finally { await w.cleanup(); }
});

test('flag off (no counts store): the route does not exist, exactly like an unknown path', async () => {
    const w = await world({counts: false});
    try {
        seed(w); await w.api.signIn('operator');
        const off = await w.api.get('pilot'), unknown = await w.api.call('GET', '/people/pilot/filter/nothing');
        assert.equal(off.status, unknown.status); assert.deepEqual(off.body, unknown.body);
        assert.equal(off.status, 404);
    } finally { await w.cleanup(); }
});

test('guards: signed out and a foreign Origin are refused; mode exclusion hides the route; owner mode hides it from a parent', async () => {
    const w = await world({mode: 'owner'});
    try {
        seed(w);
        assert.notEqual((await w.api.get('pilot')).status, 200); // signed out
        await w.api.signIn('operator');
        assert.equal((await w.api.get('pilot')).status, 200);
        err(await w.api.get('pilot', {Origin: 'https://evil.test'}), 403, 'origin_rejected'); // as every other GET
        assert.equal((await w.api.get('pilot', {}, ['Origin'])).status, 200); // a same-origin GET carries no Origin: the session cookie decides, as for the filter GET
    } finally { await w.cleanup(); }
    const parent = await world({mode: 'owner'});
    try {
        seed(parent); await parent.api.signIn('parent');
        err(await parent.api.get('pilot'), 404, 'route_not_found');
    } finally { await parent.cleanup(); }
    const off = await world({mode: 'off'});
    try {
        seed(off); await off.api.signIn('operator');
        err(await off.api.get('pilot'), 404, 'route_not_found');
    } finally { await off.cleanup(); }
});

test('person scoping: unknown, out-of-scope and unmapped children answer one identical 404', async () => {
    const w = await world({mode: 'parents', profiles: {other: PROFILE_ID}});
    try {
        seed(w); await w.api.signIn('parent');
        const bodies = [await w.api.get('nobody'), await w.api.get('other'), await w.api.get('pilot')];
        for (const r of bodies) err(r, 404, 'person_not_found');
        assert.equal(new Set(bodies.map(r => r.text)).size, 1);
    } finally { await w.cleanup(); }
});

test('a child with no stored days answers 200 with seven gaps and zero sums', async () => {
    const w = await world();
    try {
        await w.api.signIn('operator');
        const r = await w.api.get('pilot');
        assert.equal(r.status, 200);
        assert.deepEqual((r.body.days as {state: string}[]).map(d => d.state), Array(7).fill('gap'));
        assert.deepEqual(r.body.week, {filterBlocked: 0, background: 0, okDays: 0, days: 7});
    } finally { await w.cleanup(); }
});

test('the web block carries the same class labels as the shared table', async () => {
    const {readFileSync} = await import('node:fs');
    const {CLASS_LABELS} = await import('../../shared/src/content-filter-classes.ts');
    const source = readFileSync(new URL('../../web/public/content-filter.js', import.meta.url), 'utf8');
    const literal = /export const CLASS_LABELS = \{([^}]*)\};/.exec(source)![1];
    const web = Object.fromEntries([...literal.matchAll(/(\w+): '([^']*)'/g)].map(m => [m[1], m[2]]));
    assert.deepEqual(web, {...CLASS_LABELS});
});
