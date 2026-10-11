import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { Auth, issueBootstrap } from '../src/auth.ts';
import { TestAuthenticator } from './authenticator.ts';
import { seedAccounts } from '../src/fixtures.ts';
import { FakeRouter } from '../../demo-router/src/router.ts';
import { PolicyService } from '../src/policy.ts';
import { appServer } from '../src/http.ts';
import { demoConfig } from '../src/config.ts';
test('genuine authenticated HTTP controls enforce Host, identity, scope, CSRF, origin, expiry and revocation', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-http-')), port = 45000 + process.pid % 10000, origin = `http://localhost:${port}`;
    const store = new Store(join(dir, 'service.sqlite'));
    seedAccounts(store);
    let now = 1791691200;
    const router = new FakeRouter(join(dir, 'fake.sqlite'), {
        now: () => now, delay: 1
    });
    router.tick();
    const auth = new Auth(store, origin, () => now), policy = new PolicyService(store, router, () => now), server = appServer(auth, policy, {
        port, origin, host: `localhost:${port}`, dataDir: dir
    });
    server.listen(port, '127.0.0.1');
    await once(server, 'listening');
    let cookie = '', csrf = '';
    const request = async (path: string, input?: unknown, headers: Record<string, string> = {}, raw?: string) => {
        const response = await fetch(`${origin}${path}`, {
            method: input === undefined ? 'GET' : 'POST', headers: {
                Origin: origin, ...(input === undefined ? {} : {
                    'Content-Type': 'application/json'
                }), ...(cookie ? {
                    Cookie: cookie
                } : {}), ...(csrf ? {
                    'X-CSRF-Token': csrf
                } : {}), ...headers
            }, ...(input === undefined ? {} : {
                body: raw ?? JSON.stringify(input)
            })
        });
        assert.equal(response.headers.get('cache-control'), 'no-store');
        const cookies = response.headers.getSetCookie();
        if (cookies.length) {
            const jar = new Map(cookie.split('; ').filter(Boolean).map(c => c.split('=') as [
                string,
                string
            ]));
            for (const set of cookies) {
                assert.match(set, /HttpOnly/);
                assert.match(set, /SameSite=Strict/);
                const [key, value] = set.split(';')[0].split('=');
                if (value) {
                    jar.set(key, value);
                }
                else {
                    jar.delete(key);
                }
            }
            cookie = [...jar].map(([key, value]) => `${key}=${value}`).join('; ');
        }
        return {
            status: response.status, body: await response.json()
        };
    };
    try {
        assert.equal((await request('/people')).status, 401);
        assert.equal((await request('/people', undefined, {
            'X-Cf-Actor': 'jd'
        })).status, 400);
        const invalidHost = await new Promise<number>((resolve, reject) => {
            const raw = httpRequest(`${origin}/people`, {
                headers: {
                    Host: 'evil.example'
                }
            }, response => {
                response.resume();
                resolve(response.statusCode!);
            });
            raw.on('error', reject);
            raw.end();
        });
        assert.equal(invalidHost, 403);
        assert.equal((await request('/people', undefined, OriginHeader('http://evil.example'))).status, 403);
        assert.equal((await request('/auth/register/options', {
            token: 'bad'
        }, {}, '{"token":"a","token":"b"}')).status, 400);
        assert.equal((await request('/auth/login/options', {}, {
            'Content-Type': 'text/plain'
        })).status, 415);
        assert.equal((await request('/auth/login/options', {}, {}, JSON.stringify({
            oversized: 'x'.repeat(65536)
        }))).status, 413);
        const token = issueBootstrap(store, 'bryn', now);
        assert.equal((await request('/auth/register/options', {
            token, role: 'admin'
        })).status, 400);
        const options = await request('/auth/register/options', {
            token
        });
        assert.equal(options.status, 200);
        const key = new TestAuthenticator(), verified = await request('/auth/register/verify', {
            challengeId: options.body.challengeId, response: key.register(options.body.options, origin)
        });
        assert.equal(verified.status, 200);
        csrf = verified.body.csrfToken;
        assert.equal(verified.body.actor.id, 'bryn');
        assert.equal(verified.body.actor.role, 'parent');
        const people = await request('/people');
        assert.equal(people.status, 200);
        assert.deepEqual(people.body.people.map((p: {
            id: string;
        }) => p.id), ['alex']);
        assert.equal((await request('/devices')).status, 403);
        assert.equal((await request('/people/blair/pause', {
            until: 0
        }, {
            'If-Match': people.body.revisionToken, 'Idempotency-Key': 'http_blair_key_002'
        })).status, 404);
        assert.equal((await request('/people/alex/pause', {
            until: 0
        }, {
            'If-Match': people.body.revisionToken, 'Idempotency-Key': 'http_alex_key_002', 'X-CSRF-Token': 'wrong'
        })).status, 403);
        assert.equal((await request('/people/alex/pause', {
            until: 0
        }, {
            'If-Match': people.body.revisionToken, 'Idempotency-Key': 'http_alex_key_002', Origin: 'http://evil.example'
        })).status, 403);
        const accepted = await request('/people/alex/pause', {
            until: 0
        }, {
            'If-Match': people.body.revisionToken, 'Idempotency-Key': 'http_alex_key_002'
        });
        assert.equal(accepted.status, 202);
        now += 2;
        router.tick();
        const operation = await request(accepted.body.operationUrl);
        assert.equal(operation.status, 200);
        assert.equal(operation.body.state, 'confirmed');
        assert.equal((await request('/people/alex/pause', {
            until: 0
        }, {
            'If-Match': people.body.revisionToken, 'Idempotency-Key': 'http_alex_key_002'
        })).status, 200);
        const savedCookie = cookie, savedCsrf = csrf;
        assert.equal((await request('/auth/logout', {})).status, 200);
        cookie = savedCookie;
        csrf = savedCsrf;
        assert.equal((await request('/people')).status, 401);
        const login = await request('/auth/login/options', {}), signed = key.login(login.body.options, origin), session = await request('/auth/login/verify', {
            challengeId: login.body.challengeId, response: signed
        });
        assert.equal(session.status, 200);
        csrf = session.body.csrfToken;
        assert.equal((await request('/auth/login/verify', {
            challengeId: login.body.challengeId, response: signed
        })).status, 401);
        store.run('UPDATE accounts SET permission_version=permission_version+1 WHERE id=?', 'bryn');
        assert.equal((await request('/people')).status, 401);
        const freshOptions = await request('/auth/login/options', {}), fresh = await request('/auth/login/verify', {
            challengeId: freshOptions.body.challengeId, response: key.login(freshOptions.body.options, origin)
        });
        assert.equal(fresh.status, 200);
        now += 3601;
        assert.equal((await request('/people')).status, 401);
    }
    finally {
        await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
        router.close();
        store.close();
        rmSync(dir, {
            recursive: true
        });
    }
});
function OriginHeader(origin: string) {
    return {
        Origin: origin
    };
}
test('demo rejects production target/auth bypass configuration and cannot bind a nonloopback target', () => {
    for (const key of ['CF_ROUTER_HOST', 'CF_SSH_KEY', 'CF_TARGET', 'CF_PRODUCTION', 'CF_AUTH_BYPASS', 'CF_TEST_IDENTITY']) {
        assert.throws(() => demoConfig({
            [key]: 'anything'
        }), /production_configuration_forbidden/);
    }
    assert.equal(demoConfig({}).host, 'localhost:4173');
    for (const value of ['0', '80', '65536', '4173;echo bad', 'evil.example']) {
        assert.throws(() => demoConfig({
            CF_DEMO_PORT: value
        }), /invalid_demo_port/);
    }
});
