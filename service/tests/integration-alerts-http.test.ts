import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import { TestAuthenticator } from './authenticator.ts';
import { sha256 } from '../../shared/src/router-rpc.ts';

const SEED = '02:10:20:30:40:50', LAPTOP = '02:10:20:30:40:53';
const shaOf = (scope: string[]) => sha256(scope.join('\n') + '\n');

test('S1: the integration entry point serves /alerts (ParentAlerts wired, no scheduled sources)', () => {
    const main = readFileSync(new URL('../src/integration-main.ts', import.meta.url), 'utf8');
    assert.match(main, /new ParentAlerts\(store, null\)/);
    assert.doesNotMatch(main, /appServer\([^;]*, undefined, activity\)/);
});

test('S1: an admin sees the router_scope_change alert over HTTP, a parent does not', async () => {
    const f = integrationFixture(), port = 25000 + process.pid % 10000, origin = `http://localhost:${port}`;
    (f.config as {routerScope?: string[]}).routerScope = [SEED];
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`}, new ParentAlerts(f.store, null, f.now));
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    async function client(account: string) {
        const cookies = new Map<string, string>(); let csrf = '';
        const call = async (path: string, input?: unknown) => {
            const response = await fetch(origin + path, {method: input === undefined ? 'GET' : 'POST', headers: {Origin: origin, Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; '), ...(csrf ? {'X-CSRF-Token': csrf} : {}), ...(input === undefined ? {} : {'Content-Type': 'application/json'})}, ...(input === undefined ? {} : {body: JSON.stringify(input)})});
            for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); cookies.set(k, v); }
            return {status: response.status, body: await response.json() as Record<string, any>};
        };
        const key = new TestAuthenticator(), options = await call('/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
        const verified = await call('/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, origin)});
        assert.equal(verified.status, 200); csrf = verified.body.csrfToken;
        return call;
    }
    try {
        assert.equal(f.store.get<{role: string}>("SELECT role FROM accounts WHERE id='operator'")!.role, 'admin');
        assert.equal(f.store.get<{role: string}>("SELECT role FROM accounts WHERE id='parent'")!.role, 'parent');
        f.router.transform = o => ({...o, scope: [SEED], scopeSha: shaOf([SEED])}); await f.observe();
        f.advance(1); f.router.transform = o => ({...o, scope: [SEED, LAPTOP], scopeSha: shaOf([SEED, LAPTOP])}); await f.observe();
        const admin = await client('operator'), parent = await client('parent');
        const seen = await admin('/alerts');
        assert.equal(seen.status, 200);
        assert.deepEqual(seen.body.alerts.map((a: {kind: string}) => a.kind), ['router_scope_change']);
        assert.doesNotMatch(JSON.stringify(seen.body), /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/);
        const other = await parent('/alerts');
        assert.equal(other.status, 200); assert.deepEqual(other.body.alerts, []);
    } finally { server.close(); await once(server, 'close'); f.cleanup(); }
});
