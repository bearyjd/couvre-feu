import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture } from './fixtures/integration.ts';
import { wireIntegration } from '../src/integration-wiring.ts';
import { wireContentFilter } from '../src/content-filter-wiring.ts';
import { NextDnsEnvironmentError } from '../src/nextdns-client.ts';
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
