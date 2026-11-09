import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture } from './fixtures/integration.ts';
import { wireIntegration } from '../src/integration-wiring.ts';
import { wireContentFilter } from '../src/content-filter-wiring.ts';
import { NextDnsEnvironmentError } from '../src/nextdns-client.ts';
import { createFakeNextDns, profile } from './fixtures/fake-nextdns.ts';
import { API_KEY, DESIRED, PROFILE_ID, SECRET_ALLOWED, SECRET_DOMAIN, fakeWorld } from './fixtures/content-filter.ts';
import type { IntegrationConfig } from '../src/integration-config.ts';

const setting = (mode: 'off' | 'owner' | 'parents'): NonNullable<IntegrationConfig['contentFilter']> =>
    ({mode, apiKeyFile: '/nonexistent-dir/never-read.key', defaultProfile: 'dflt01', profiles: {pilot: 'abc123'}});
const UNSAFE = {NODE_TLS_REJECT_UNAUTHORIZED: '0'}, PROXY = {NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: 'http://proxy.invalid:3128'};

test('the environment is checked once at startup, only when filtering is on', () => {
    const f = integrationFixture();
    try {
        for (const env of [UNSAFE, PROXY, {ALL_PROXY: 'socks5://p.invalid'}]) {
            for (const mode of ['owner', 'parents'] as const) {
                f.config.contentFilter = setting(mode);
                assert.throws(() => wireIntegration(f.config, f.store, f.router, env), (e: unknown) => e instanceof NextDnsEnvironmentError);
            }
            for (const off of [undefined, setting('off')]) {
                if (off) f.config.contentFilter = off; else delete f.config.contentFilter;
                assert.doesNotThrow(() => wireIntegration(f.config, f.store, f.router, env));
            }
        }
    } finally { f.cleanup(); }
});

test('a safe environment wires the routes without reading the key file; off wires nothing', () => {
    const f = integrationFixture();
    try {
        f.config.contentFilter = setting('owner');
        const wired = wireContentFilter(f.config, f.store, {});
        assert.ok(wired, 'the key path does not exist and nothing read it');
        assert.ok(typeof wired.routes === 'function');
        f.config.contentFilter = setting('off'); assert.equal(wireContentFilter(f.config, f.store, UNSAFE), null);
        delete f.config.contentFilter; assert.equal(wireContentFilter(f.config, f.store, UNSAFE), null);
    } finally { f.cleanup(); }
});

test('the client built without allowDomainLists refuses denylist and allowlist calls but parental-control calls work', async () => {
    const { createNextDnsClient } = await import('../src/nextdns-client.ts');
    const { createFakeNextDns } = await import('./fixtures/fake-nextdns.ts');
    const fake = createFakeNextDns({apiKey: API_KEY, profiles: [profile(PROFILE_ID)]});
    const client = createNextDnsClient({apiKey: () => API_KEY, transport: fake.transport, sleep: async () => undefined});
    for (const list of ['denylist', 'allowlist'] as const) {
        await assert.rejects(client.setList(PROFILE_ID, list, [{id: 'a.example.test', active: true}]), (e: unknown) => (e as {code?: string}).code === 'invalid_request');
        await assert.rejects(client.getList(PROFILE_ID, list), (e: unknown) => (e as {code?: string}).code === 'invalid_request');
    }
    await client.setParentalControl(PROFILE_ID, {safeSearch: true, youtubeRestrictedMode: true, blockBypass: true});
    await client.setList(PROFILE_ID, 'categories', [{id: 'porn', active: true}]);
    assert.ok(fake.requests.every(r => !r.path.includes('denylist') && !r.path.includes('allowlist')));
});

test('the real wiring path builds a client that reconciles a filter with denylist and allowlist entries', async () => {
    const f = integrationFixture();
    try {
        const fake = fakeWorld();
        f.config.contentFilter = {mode: 'parents', apiKeyFile: '/nonexistent-dir/never-read.key', defaultProfile: 'dflt01', profiles: {pilot: PROFILE_ID}};
        const wired = wireContentFilter(f.config, f.store, {}, undefined, {transport: fake.fake.transport, apiKey: () => API_KEY})!;
        wired.filters.put('pilot', DESIRED, 'operator');
        assert.equal((await wired.reconciler.reconcile('pilot'))!.state, 'applied');
        assert.deepEqual(fake.profile.allowlist, [{id: SECRET_ALLOWED, active: true}]);
        assert.deepEqual(fake.profile.denylist, [{id: SECRET_DOMAIN, active: true}]);
    } finally { f.cleanup(); }
});
