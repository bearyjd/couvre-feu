import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { world } from './fixtures/grant-world.ts';
import { TestAuthenticator } from './authenticator.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { auditFor } from '../src/parent-audit.ts';
import { appServer } from '../src/http.ts';

type W = Awaited<ReturnType<typeof world>>;
let ports = 31000 + process.pid % 5000;

/** Serves the app with the config as it is now (the gates are read from it at startup) and signs one account in. */
async function serve(w: W, account: string) {
    const port = ports++, o = `http://localhost:${port}`, f = w.f;
    const auth = new Auth(f.store, o, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: o, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    const cookies = new Map<string, string>();
    const get = async (path: string) => {
        const response = await fetch(o + path, {headers: {Origin: o, Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join(';')}});
        for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); cookies.set(k, v); }
        return {status: response.status, text: await response.text()};
    };
    const json = async (method: string, path: string, input: unknown) => {
        const response = await fetch(o + path, {method, headers: {Origin: o, 'Content-Type': 'application/json', Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join(';')}, body: JSON.stringify(input)});
        for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); cookies.set(k, v); }
        return {status: response.status, body: await response.json() as Record<string, any>};
    };
    const key = new TestAuthenticator();
    const options = await json('POST', '/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
    assert.equal((await json('POST', '/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, o)})).status, 200);
    return {o, get, close: async () => { server.closeAllConnections(); server.close(); await once(server, 'close'); }};
}

test('HTTP: GET /people carries a read-only auditLog boolean exactly when GET /audit would answer for that viewer', async () => {
    const cases: {name: string; audit: boolean; mode?: 'off' | 'owner' | 'parents'; account: string}[] = [
        {name: 'flag absent', audit: false, mode: 'parents', account: 'operator'},
        {name: 'flag on, admin', audit: true, mode: 'parents', account: 'operator'},
        {name: 'flag on, scoped parent', audit: true, mode: 'parents', account: 'parent'},
        {name: 'flag on, time requests off: audit is independent of timeRequests', audit: true, mode: 'off', account: 'operator'},
        {name: 'flag on, owner mode, the owner', audit: true, mode: 'owner', account: 'operator'},
        {name: 'flag on, owner mode, a non-owner parent: audit is not owner-gated', audit: true, mode: 'owner', account: 'parent'}];
    for (const c of cases) {
        const w = await world();
        if (c.audit) w.f.config.auditLog = {enabled: true};
        if (c.mode) w.f.config.timeRequests = {mode: c.mode};
        if (c.mode === 'owner') w.f.config.ownerAccountId = 'operator';
        const s = await serve(w, c.account);
        try {
            const route = (await s.get('/audit')).status, people = JSON.parse((await s.get('/people')).text);
            assert.equal(route, c.audit ? 200 : 404, `${c.name}: the route`);
            if (c.audit) assert.equal(people.auditLog, true, c.name); else assert.ok(!('auditLog' in people), `${c.name}: no trace of the feature`);
            assert.ok(people.people.every((p: Record<string, unknown>) => !('auditLog' in p)), `${c.name}: not per child`);
        } finally { await s.close(); w.f.cleanup(); }
    }
});

test('HTTP: the audit page script and the service worker (cache name bumped, audit.js cached) are served', async () => {
    const w = await world(), s = await serve(w, 'operator');
    try {
        const script = await s.get('/audit.js');
        assert.equal(script.status, 200);
        assert.match(script.text, /createAuditLog/);
        const sw = await s.get('/sw.js');
        assert.match(sw.text, /cf-shell-integration-[^']*-v4'/);
        assert.match(sw.text, /'\/audit\.js'/);
    } finally { await s.close(); w.f.cleanup(); }
});

test('HTTP: audit availability is independent of timeRequests and owner mode, and only admins see no-child rows', async () => {
    for (const mode of ['off', 'owner'] as const) {
        for (const account of ['operator', 'parent']) {
            const w = await world();
            w.f.config.auditLog = {enabled: true}; w.f.config.timeRequests = {mode};
            if (mode === 'owner') w.f.config.ownerAccountId = 'operator';
            auditFor(w.f.store).record({actor: 'operator', action: 'pause_all', people: [], result: 'refused'});
            const s = await serve(w, account);
            try {
                const r = await s.get('/audit');
                assert.equal(r.status, 200, `${mode}/${account}: GET /audit answers`);
                const rows = JSON.parse(r.text).entries as {personId: string | null}[];
                assert.equal(rows.some(e => e.personId === null), account === 'operator', `${mode}/${account}: no-child rows are admin-only`);
            } finally { await s.close(); w.f.cleanup(); }
        }
    }
});
