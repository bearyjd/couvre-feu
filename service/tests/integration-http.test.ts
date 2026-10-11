import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, digest } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { TestAuthenticator } from './authenticator.ts';

test('real integration HTTP preserves WebAuthn, scope, CSRF and role guards; GET, POST and polls never launch SSH', async () => {
    const f = integrationFixture(), port = 35000 + process.pid % 10000, origin = `http://localhost:${port}`;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    const cookies = new Map<string, string>(); let csrf = '';
    async function request(path: string, input?: unknown, headers: Record<string, string> = {}) {
        const response = await fetch(origin + path, {method: input === undefined ? 'GET' : 'POST', headers: {Origin: origin, Cookie: [...cookies].map(([k,v]) => `${k}=${v}`).join('; '), ...(csrf ? {'X-CSRF-Token': csrf} : {}), ...(input === undefined ? {} : {'Content-Type': 'application/json'}), ...headers}, ...(input === undefined ? {} : {body: JSON.stringify(input)})});
        for (const entry of response.headers.getSetCookie()) { const [k,v] = entry.split(';')[0].split('='); cookies.set(k,v); }
        return {status: response.status, body: await response.json()};
    }
    try {
        const html = await (await fetch(origin)).text(); assert.match(html, /data-source="real-router-integration"/); assert.match(html, /Private router integration/); assert.doesNotMatch(html, /fictional account|Synthetic demo/);
        assert.match(await (await fetch(origin + '/sw.js')).text(), /cf-shell-integration-dddd/);
        assert.equal((await request('/people')).status, 401);
        const token = randomBytes(32).toString('base64url');
        f.store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at) VALUES(?,?,?)', digest(token), 'parent', f.now() + 600);
        assert.equal((await request('/auth/register/options', {token, role: 'admin'})).status, 400);
        const options = await request('/auth/register/options', {token}), key = new TestAuthenticator(); assert.equal(options.status, 200);
        assert.equal(options.body.options.rp.name, 'Private integration test');
        const verified = await request('/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, origin)}); assert.equal(verified.status, 200);
        assert.equal(verified.body.source, 'real-router-integration'); assert.equal(verified.body.integrationScope, f.config.provenance.integrationScope);
        assert.equal(verified.body.actor.role, 'parent'); csrf = verified.body.csrfToken;
        assert.equal((await request('/devices')).status, 403);
        assert.equal((await request('/people', undefined, {'X-Cf-Actor': 'operator'})).status, 400);
        assert.equal((await request('/people/other/pause', {until: 0}, {'If-Match': '"s0-r0-' + 'a'.repeat(64) + '"', 'Idempotency-Key': 'wrong_person_123456'})).status, 404);
        assert.equal(f.router.calls.length, 0);
        await f.observe();
        const people = await request('/people'); assert.equal(people.body.people[0].name, 'Explicit test person'); assert.equal(people.body.packetAcceptance, 'unmeasured');
        const headers = {'If-Match': people.body.revisionToken, 'Idempotency-Key': 'http_private_intent_1234'};
        assert.equal((await request('/people/pilot/pause', {until: 0}, {...headers, 'X-CSRF-Token': 'wrong'})).status, 403);
        const result = await request('/people/pilot/pause', {until: 0}, headers); assert.equal(result.status, 202); assert.equal(result.body.operation.dispatch, 'awaiting_operator_dispatch');
        for (let i = 0; i < 3; i++) { const operation = await request('/operations/' + result.body.operation.id); assert.equal(operation.body.state, 'pending'); assert.equal(operation.body.source, 'real-router-integration'); assert.equal((await request('/people')).status, 200); }
        assert.equal(f.router.calls.length, 1);
        assert.equal((await request('/operations/00000000-0000-0000-0000-000000000000')).status, 404);
        f.store.run("UPDATE accounts SET permission_version=permission_version+1 WHERE id='parent'"); assert.equal((await request('/people')).status, 401);
        assert.equal(f.router.calls.length, 1);
    } finally { server.close(); await once(server, 'close'); f.cleanup(); }
});
