import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, digest } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { TestAuthenticator } from './authenticator.ts';

/** The owner-account guard is wired by http.ts only in real-router owner mode: the same admin request is allowed in parents mode and refused in owner mode. */
async function issueTokenFor(mode: 'owner' | 'parents', portOffset: number): Promise<{status: number; error?: string}> {
    const f = integrationFixture(), port = 36000 + (process.pid + portOffset) % 10000, origin = `http://localhost:${port}`;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`, timeRequests: {mode}, ownerAccountId: 'parent'} as typeof f.config);
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        const jar = new Map<string, string>(); let csrf = '';
        const call = async (path: string, input: unknown) => {
            const response = await fetch(origin + path, {method: 'POST', headers: {Origin: origin, Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), ...(csrf ? {'X-CSRF-Token': csrf} : {}), 'Content-Type': 'application/json'}, body: JSON.stringify(input)});
            for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); jar.set(k, v); }
            const body = await response.json();
            if (body.csrfToken) csrf = body.csrfToken;
            return {status: response.status, body};
        };
        const key = new TestAuthenticator(), token = randomBytes(32).toString('base64url');
        f.store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at,first_enrollment) VALUES(?,?,?,1)', digest(token), 'operator', f.now() + 600);
        const options = await call('/auth/register/options', {token});
        assert.equal((await call('/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, origin)})).status, 200);
        const params = {label: 'Phone'}, step = await call('/step-up/options', {action: 'token_issue', target: 'parent', params});
        assert.equal(step.status, 200);
        const result = await call('/admin/accounts/parent/tokens', {...params, stepUp: {challengeId: step.body.challengeId, response: key.login(step.body.options, origin)}});
        return {status: result.status, error: result.body.error?.code ?? result.body.code ?? result.body.error};
    } finally { server.close(); f.cleanup(); }
}

test('HTTP: another admin issuing a token for the owner account is allowed in parents mode and refused in owner mode', async () => {
    assert.equal((await issueTokenFor('parents', 1)).status, 200);
    const refused = await issueTokenFor('owner', 2);
    assert.equal(refused.status, 403);
    assert.equal(refused.error, 'owner_account_protected');
});
