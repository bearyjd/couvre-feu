import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { DOH_IPV4, DOH_IPV6, DOH_PROVIDERS, mergeStaticDoh, protectedAddressesOf } from '../src/doh-list.ts';
import { integrationConfig } from '../src/integration-config.ts';
import { canonicalIPv6, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { integrationFixture, testConfig } from './fixtures/integration.ts';

const v4 = (ip: string) => ip.split('.').reduce((n, p) => n * 256 + Number(p), 0);
/** Not globally routable unicast: this, private, CGNAT, loopback, link-local, TEST-NETs, benchmarking, multicast, reserved. */
function nonPublicV4(ip: string): boolean {
    const n = v4(ip), inside = (base: string, bits: number) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(v4(base) / 2 ** (32 - bits));
    return [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
        ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]].some(([b, bits]) => inside(b as string, bits as number));
}
function nonPublicV6(ip: string): boolean {
    const first = parseInt(ip.split(':')[0] || '0', 16);
    return ip === '::' || ip === '::1' || (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00 || ip.startsWith('2001:db8:') || ip.startsWith('::ffff:') || first >>> 13 !== 1;
}

test('list invariants: sorted, unique, canonical, within the per-family cap', () => {
    for (const list of [DOH_IPV4, DOH_IPV6]) {
        assert.ok(Object.isFrozen(list));
        assert.ok(list.length > 0 && list.length <= 256);
        assert.deepEqual([...list], [...list].sort());
        assert.equal(new Set(list).size, list.length);
    }
    assert.ok(DOH_IPV4.every(ip => /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(ip) && ip.split('.').every(p => +p <= 255)));
    assert.ok(DOH_IPV6.every(ip => canonicalIPv6(ip) === ip));
    assert.ok(Object.isFrozen(DOH_PROVIDERS));
});

test('every entry is public unicast: no private, loopback, link-local, ULA or documentation space', () => {
    assert.deepEqual(DOH_IPV4.filter(nonPublicV4), []);
    assert.deepEqual(DOH_IPV6.filter(nonPublicV6), []);
    // The checker itself must reject what it claims to.
    for (const ip of ['10.0.0.1', '192.168.1.1', '127.0.0.1', '169.254.1.1', '172.16.0.1', '100.64.0.1']) assert.ok(nonPublicV4(ip), ip);
    for (const ip of ['::1', 'fe80::1', 'fd00::1', '2001:db8::1']) assert.ok(nonPublicV6(ip), ip);
});

test('every provider carries an official source URL and a verification date, and its addresses are in the lists', () => {
    for (const p of DOH_PROVIDERS) {
        assert.match(p.source, /^https:\/\//);
        assert.match(p.verified, /^2026-10-2[0-9]$/);
        for (const ip of p.ipv4) assert.ok(DOH_IPV4.includes(ip), ip);
        for (const ip of p.ipv6) assert.ok(DOH_IPV6.includes(ip), ip);
    }
    assert.deepEqual([...DOH_IPV4].sort(), [...new Set(DOH_PROVIDERS.flatMap(p => p.ipv4))].sort());
    assert.deepEqual([...DOH_IPV6].sort(), [...new Set(DOH_PROVIDERS.flatMap(p => p.ipv6))].sort());
});

test('well-known providers are present, NextDNS included (blocked like the others)', () => {
    for (const ip of ['1.1.1.1', '1.0.0.1', '1.1.1.2', '1.1.1.3', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15', '185.228.168.168', '45.90.28.0', '45.90.30.0']) assert.ok(DOH_IPV4.includes(ip), ip);
    for (const ip of ['2606:4700:4700::1111', '2001:4860:4860::8888', '2620:fe::fe', '2a10:50c0::ad1:ff', '2a0d:2a00:1::', '2a07:a8c0::', '2a07:a8c1::']) assert.ok(DOH_IPV6.includes(ip), ip);
    assert.ok(DOH_PROVIDERS.some(p => p.name === 'NextDNS'));
});

const empty = {ipv4: [] as string[], ipv6: [] as string[]};
test('merge: adds the list, never removes an existing entry, is idempotent and normalised', () => {
    const existing = {ipv4: ['192.0.2.53', '1.1.1.1'], ipv6: ['2001:db8::53']};
    const once = mergeStaticDoh(existing, []);
    assert.equal(once.refused, 0);
    for (const ip of existing.ipv4) assert.ok(once.doh.ipv4.includes(ip));
    assert.ok(once.doh.ipv6.includes('2001:db8::53'));
    for (const ip of DOH_IPV4) assert.ok(once.doh.ipv4.includes(ip));
    for (const ip of DOH_IPV6) assert.ok(once.doh.ipv6.includes(ip));
    assert.deepEqual(once.doh.ipv4, [...once.doh.ipv4].sort());
    assert.equal(new Set(once.doh.ipv4).size, once.doh.ipv4.length);
    assert.deepEqual(mergeStaticDoh(once.doh, []).doh, once.doh);
    assert.deepEqual(existing, {ipv4: ['192.0.2.53', '1.1.1.1'], ipv6: ['2001:db8::53']}, 'input is not mutated');
});

test('merge: a near-full policy keeps every existing entry and stops at the cap', () => {
    const full = {ipv4: Array.from({length: 250}, (_, i) => `198.51.${Math.floor(i / 200)}.${i % 200 + 1}`), ipv6: Array.from({length: 256}, (_, i) => `2001:db8::${(i + 1).toString(16)}`)};
    const out = mergeStaticDoh(full, []);
    assert.ok(out.doh.ipv4.length <= 256 && out.doh.ipv6.length <= 256);
    for (const ip of full.ipv4) assert.ok(out.doh.ipv4.includes(ip));
    assert.deepEqual(out.doh.ipv6, [...full.ipv6].sort(), 'a full family gains nothing and loses nothing');
    const policy = normalizePolicy({version: 1, revision: 1, people: [], pauses: [], schedules: [], doh: out.doh});
    assert.ok(policy.doh.ipv4.length <= 256);
});

test('merge: a list entry equal to or inside a protected address is refused, counted, and the tag carries no address', () => {
    const out = mergeStaticDoh(empty, ['1.1.1.1', '8.8.0.0/16', '2606:4700:4700::1111', '192.168.1.1']);
    assert.ok(!out.doh.ipv4.includes('1.1.1.1') && !out.doh.ipv4.includes('8.8.8.8') && !out.doh.ipv4.includes('8.8.4.4'));
    assert.ok(!out.doh.ipv6.includes('2606:4700:4700::1111'));
    assert.ok(out.doh.ipv4.includes('1.0.0.1') && out.doh.ipv6.includes('2606:4700:4700::1001'));
    assert.equal(out.refused, 4);
    assert.match(out.tag, /^[a-z_]+$/);
    // A protected address the service already holds is never removed by the merge.
    assert.ok(mergeStaticDoh({ipv4: ['1.1.1.1'], ipv6: []}, ['1.1.1.1']).doh.ipv4.includes('1.1.1.1'));
    assert.throws(() => mergeStaticDoh(empty, ['not an address']), /invalid_protected_address/);
});

test('no list entry falls inside the addresses the manifest protects (router, listener, proxies)', () => {
    const config = testConfig('/tmp/unused');
    config.listen = {host: '192.168.1.5', port: 4273}; config.trustedProxies = ['192.168.1.6'];
    const protectedAddresses = protectedAddressesOf(config);
    assert.deepEqual([...protectedAddresses].sort(), ['192.168.1.1', '192.168.1.5', '192.168.1.6']);
    assert.equal(mergeStaticDoh(empty, protectedAddresses).refused, 0);
});

function policyWith(doh: RouterPolicy['doh']): RouterPolicy {
    return normalizePolicy({version: 1, revision: 1, people: [{id: 'pilot', macs: ['02:10:20:30:40:50']}], pauses: [], schedules: [], doh});
}
async function queued(flag: unknown, doh: RouterPolicy['doh'] = {ipv4: ['192.0.2.53'], ipv6: []}) {
    const f = integrationFixture();
    if (flag !== undefined) (f.config as unknown as {dnsHardening: unknown}).dnsHardening = flag;
    f.router.policy = policyWith(doh);
    await f.observe();
    const out = f.pause(0);
    const payload = JSON.parse(f.store.get<{payload_json: string}>('SELECT payload_json FROM operations WHERE id=?', out.result.operation.id)!.payload_json) as RouterPolicy;
    const envelope = JSON.parse(f.store.get<{envelope_json: string}>('SELECT envelope_json FROM operation_rpc WHERE operation_id=?', out.result.operation.id)!.envelope_json) as {policy: RouterPolicy};
    return {f, id: out.result.operation.id, payload, envelope};
}

test('flag absent or off: the submitted policy is byte-identical to today (existing doh preserved, nothing added)', async () => {
    const absent = await queued(undefined), off = await queued({dohList: false});
    try {
        assert.deepEqual(absent.payload.doh, {ipv4: ['192.0.2.53'], ipv6: []});
        assert.equal(JSON.stringify(absent.payload), JSON.stringify(off.payload));
        assert.equal(JSON.stringify(absent.envelope.policy), JSON.stringify(off.envelope.policy));
    } finally { absent.f.cleanup(); off.f.cleanup(); }
});

test('flag on: the submitted policy and RPC envelope carry existing doh plus the static list and pass normalizePolicy', async () => {
    const on = await queued({dohList: true});
    try {
        for (const policy of [on.payload, on.envelope.policy]) {
            assert.deepEqual(normalizePolicy(policy), policy);
            assert.ok(policy.doh.ipv4.includes('192.0.2.53'));
            for (const ip of DOH_IPV4) assert.ok(policy.doh.ipv4.includes(ip), ip);
            for (const ip of DOH_IPV6) assert.ok(policy.doh.ipv6.includes(ip), ip);
        }
        assert.equal(on.payload.pauses.length, 1, 'the requested change is still made');
    } finally { on.f.cleanup(); }
});

test('flag on with a router-protected address equal to a list entry: that entry is not merged', async () => {
    const f = integrationFixture();
    f.config.router.host = '1.1.1.1';
    (f.config as unknown as {dnsHardening: unknown}).dnsHardening = {dohList: true};
    f.router.policy = policyWith({ipv4: [], ipv6: []});
    await f.observe();
    const out = f.pause(0);
    const payload = JSON.parse(f.store.get<{payload_json: string}>('SELECT payload_json FROM operations WHERE id=?', out.result.operation.id)!.payload_json) as RouterPolicy;
    try {
        assert.ok(!payload.doh.ipv4.includes('1.1.1.1'));
        assert.ok(payload.doh.ipv4.includes('1.0.0.1'));
    } finally { f.cleanup(); }
});

test('the list is sticky: once the router holds it, turning the flag off does not remove it from later submissions', async () => {
    const on = await queued({dohList: true});
    try {
        const plan = on.f.worker.prepare('apply', on.id); await on.f.worker.execute(plan, plan.scriptSha256);
        (on.f.config as unknown as {dnsHardening: unknown}).dnsHardening = {dohList: false};
        on.f.advance(1); await on.f.observe();
        const next = on.f.policy.mutate({id: 'operator', displayName: 'Test operator', role: 'admin', personIds: ['pilot'], permissionVersion: '1'}, 'pilot', 'resume', {}, on.f.policy.people({id: 'operator', displayName: 'Test operator', role: 'admin', personIds: ['pilot'], permissionVersion: '1'}).revisionToken!, 'second_key_123456789');
        const payload = JSON.parse(on.f.store.get<{payload_json: string}>('SELECT payload_json FROM operations WHERE id=?', next.result.operation.id)!.payload_json) as RouterPolicy;
        assert.deepEqual(payload.doh.ipv4, on.payload.doh.ipv4);
        assert.deepEqual(payload.doh.ipv6, on.payload.doh.ipv6);
    } finally { on.f.cleanup(); }
});

test('manifest dnsHardening: absent is OFF; strict {dohList: boolean}', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-doh-config-test-')), sample = testConfig(dir), socket = createServer();
    socket.listen(sample.router.agentSocket); await once(socket, 'listening'); chmodSync(sample.router.agentSocket, 0o600);
    const data = Buffer.concat([Buffer.from([0,0,0,11]), Buffer.from('ssh-ed25519'), Buffer.from([0,0,0,32]), Buffer.alloc(32, 1)]), blob = data.toString('base64'), fp = 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
    writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n`, {mode: 0o600});
    writeFileSync(sample.router.publicIdentity, `ssh-ed25519 ${blob} test-public-key\n`, {mode: 0o600});
    const {origin: _o, host: _h, manifestDigest: _m, targetDigest: _t, provenance: _p, ...manifest} = sample;
    manifest.router.hostFingerprint = fp; manifest.router.publicKeyFingerprint = fp;
    const path = join(dir, 'manifest.json');
    const save = (value: unknown) => writeFileSync(path, JSON.stringify(value), {mode: 0o600});
    try {
        save(manifest);
        const base = integrationConfig(path);
        assert.equal(base.dnsHardening, undefined, 'DNS hardening is off unless explicitly enabled');
        for (const dohList of [true, false]) {
            save({...manifest, dnsHardening: {dohList}});
            const c = integrationConfig(path);
            assert.deepEqual(c.dnsHardening, {dohList});
            assert.equal(c.targetDigest, base.targetDigest, 'the flag does not change the router target digest');
        }
        for (const dnsHardening of [{dohList: 'true'}, {dohList: 1}, {}, {dohList: true, extra: 1}, {enabled: true}, true, null, []]) { save({...manifest, dnsHardening}); assert.throws(() => integrationConfig(path)); }
    } finally { socket.close(); rmSync(dir, {recursive: true, force: true}); }
});
