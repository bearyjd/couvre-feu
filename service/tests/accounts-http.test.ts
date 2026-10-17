import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, digest } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { TestAuthenticator } from './authenticator.ts';

test('account and passkey routes over HTTP: admin-only, CSRF and Origin enforced, step-up required, pending enrollment issues no session', async () => {
    const f = integrationFixture(), port = 36000 + process.pid % 10000, origin = `http://localhost:${port}`;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    function client() {
        const jar = new Map<string, string>(); let csrf = '';
        const call = async (path: string, input?: unknown, headers: Record<string, string> = {}) => {
            const response = await fetch(origin + path, {method: input === undefined ? 'GET' : 'POST', headers: {Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), ...(csrf ? {'X-CSRF-Token': csrf} : {}), ...(input === undefined ? {} : {'Content-Type': 'application/json'}), ...headers}, body: input === undefined ? undefined : JSON.stringify(input)});
            const cookies = response.headers.getSetCookie();
            for (const entry of cookies) { const [k, v] = entry.split(';')[0].split('='); jar.set(k, v); }
            const body = await response.json();
            if (body.csrfToken) csrf = body.csrfToken;
            return {status: response.status, body, cookies};
        };
        return {call, jar};
    }
    const key = new TestAuthenticator(), operator = client(), parent = client();
    async function enroll(who: ReturnType<typeof client>, account: string, authenticator: TestAuthenticator) {
        const token = randomBytes(32).toString('base64url');
        f.store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at) VALUES(?,?,?)', digest(token), account, f.now() + 600);
        const options = await who.call('/auth/register/options', {token});
        return who.call('/auth/register/verify', {challengeId: options.body.challengeId, response: authenticator.register(options.body.options, origin)});
    }
    async function stepped(who: ReturnType<typeof client>, action: string, target: string, params: Record<string, unknown>) {
        const options = await who.call('/step-up/options', {action, target, params});
        assert.equal(options.status, 200);
        return {...params, stepUp: {challengeId: options.body.challengeId, response: key.login(options.body.options, origin)}};
    }
    try {
        assert.equal((await enroll(operator, 'operator', key)).status, 200);
        assert.equal((await enroll(parent, 'parent', new TestAuthenticator())).status, 200);
        assert.equal((await parent.call('/admin/accounts')).status, 403);
        assert.equal((await parent.call('/step-up/options', {action: 'account_create', target: '', params: {displayName: 'X', role: 'admin', personIds: ['pilot']}})).status, 403);
        assert.equal((await parent.call('/account/passkeys')).status, 200);
        const listed = await operator.call('/admin/accounts');
        assert.equal(listed.status, 200);
        assert.deepEqual(listed.body.accounts.map((a: {id: string}) => a.id).sort(), ['operator', 'parent']);
        const create = {displayName: 'New parent', role: 'parent', personIds: ['pilot']};
        assert.equal((await operator.call('/step-up/options', {action: 'account_create', target: '', params: create}, {'X-CSRF-Token': 'wrong'})).status, 403);
        assert.equal((await operator.call('/step-up/options', {action: 'account_create', target: '', params: create}, {Origin: 'https://evil.example.test'})).status, 403);
        const missing = await operator.call('/admin/accounts', create);
        assert.equal(missing.status, 403); assert.equal(missing.body.error.code, 'step_up_required');
        const created = await operator.call('/admin/accounts', await stepped(operator, 'account_create', '', create));
        assert.equal(created.status, 200);
        const id = created.body.account.id as string;
        const issued = await operator.call(`/admin/accounts/${id}/tokens`, await stepped(operator, 'token_issue', id, {label: 'Phone'}));
        assert.equal(issued.status, 200); assert.match(issued.body.token, /^[A-Za-z0-9_-]{43}$/);
        const device = client(), deviceKey = new TestAuthenticator();
        const options = await device.call('/auth/register/options', {token: issued.body.token});
        const pending = await device.call('/auth/register/verify', {challengeId: options.body.challengeId, response: deviceKey.register(options.body.options, origin)});
        assert.equal(pending.status, 202);
        assert.equal(pending.body.pending, true); assert.match(pending.body.pairingCode, /^[A-Z2-7]{6}$/);
        assert.ok(!pending.cookies.some(c => c.startsWith('cf_session=')));
        assert.equal((await device.call('/account/passkeys')).status, 401);
        const credentialId = deviceKey.credentialId.toString('base64url');
        const shown = (await operator.call('/admin/accounts')).body.accounts.find((a: {id: string}) => a.id === id);
        assert.equal(shown.passkeys[0].pairingCode, pending.body.pairingCode);
        assert.equal((await parent.call(`/admin/passkeys/${credentialId}/approve`, {stepUp: {challengeId: 'x'.repeat(43), response: {}}})).status, 403);
        assert.equal((await operator.call(`/admin/passkeys/${credentialId}/approve`, await stepped(operator, 'passkey_approve', credentialId, {}))).status, 200);
        const login = await device.call('/auth/login/options', {});
        const signedIn = await device.call('/auth/login/verify', {challengeId: login.body.challengeId, response: deviceKey.login(login.body.options, origin)});
        assert.equal(signedIn.status, 200); assert.equal(signedIn.body.actor.id, id);
        const mine = await device.call('/account/passkeys');
        assert.deepEqual(mine.body.passkeys.map((p: {id: string; current: boolean}) => [p.id, p.current]), [[credentialId, true]]);
        assert.equal((await operator.call(`/admin/passkeys/${credentialId}/revoke`, await stepped(operator, 'passkey_revoke', credentialId, {}))).status, 200);
        assert.equal((await device.call('/account/passkeys')).status, 401);
    } finally { server.close(); await once(server, 'close'); f.cleanup(); }
});
