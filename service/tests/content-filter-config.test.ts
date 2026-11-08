import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, chmodSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { integrationConfig } from '../src/integration-config.ts';
import { PROFILE_ID_PATTERN, parseContentFilter, readContentFilterKey, ContentFilterKeyError } from '../src/content-filter-config.ts';
import { testConfig } from './fixtures/integration.ts';

const FAKE_KEY = 'nxk_TESTKEY_do_not_log_0123456789';
const valid = {mode: 'owner', apiKeyFile: '/etc/couvre-feu/nextdns.key', defaultProfile: 'abc123', profiles: {pilot: 'def456'}};
const code = (fn: () => unknown): string => { try { fn(); } catch (error) { return (error as Error).message; } return 'no_error'; };

test('profile id pattern is the single documented constant', () => {
    assert.equal(PROFILE_ID_PATTERN.source, '^[A-Za-z0-9]{4,32}$');
});

test('contentFilter parses valid shapes and treats absent as off', () => {
    assert.equal(parseContentFilter(undefined), undefined);
    assert.deepEqual(parseContentFilter(valid), valid);
    assert.deepEqual(parseContentFilter({...valid, mode: 'parents'}), {...valid, mode: 'parents'});
    assert.deepEqual(parseContentFilter({mode: 'off'}), {mode: 'off'});
    assert.deepEqual(parseContentFilter({mode: 'off', defaultProfile: 'abc123', profiles: {}}), {mode: 'off', defaultProfile: 'abc123', profiles: {}});
});

test('contentFilter is strict: unknown keys, wrong types, and missing required fields are rejected', () => {
    const bad: unknown[] = [
        {...valid, extra: 1}, {...valid, apiKey: FAKE_KEY}, {...valid, key: FAKE_KEY}, {...valid, secret: FAKE_KEY},
        {mode: 'everyone'}, {mode: 1}, {}, null, true, [], 'owner',
        {...valid, apiKeyFile: 5}, {...valid, defaultProfile: 5}, {...valid, profiles: []}, {...valid, profiles: 'x'}, {...valid, profiles: {pilot: 5}},
        // required once enabled
        {mode: 'owner', defaultProfile: 'abc123', profiles: {pilot: 'def456'}}, {mode: 'owner', apiKeyFile: valid.apiKeyFile, profiles: {pilot: 'def456'}},
        {mode: 'owner', apiKeyFile: valid.apiKeyFile, defaultProfile: 'abc123'}, {...valid, profiles: {}}, {...valid, mode: 'parents', profiles: {}},
        // present-but-invalid is rejected even when off
        {mode: 'off', apiKeyFile: 'relative'}, {mode: 'off', defaultProfile: 'a'}, {mode: 'off', profiles: {pilot: 'x'}},
    ];
    for (const value of bad) assert.throws(() => parseContentFilter(value), /^Error: invalid_content_filter$|invalid_/, JSON.stringify(value));
});

test('apiKeyFile must be an absolute, normalized, charset-bound path of at most 255 characters', () => {
    const files = ['relative/key', '/a/../b', '/a/./b', '/a//b', '/a/b/', '/', '', '/a/b c', '/a/ü', '/a/b\n', '/a/b;rm', '/a/' + 'x'.repeat(253), '/..', '/a/..'];
    for (const apiKeyFile of files) assert.throws(() => parseContentFilter({...valid, apiKeyFile}), /invalid_content_filter/, apiKeyFile);
    assert.equal(parseContentFilter({...valid, apiKeyFile: '/a/' + 'x'.repeat(252)})?.apiKeyFile?.length, 255);
    assert.equal(parseContentFilter({...valid, apiKeyFile: '/run/secrets/next-dns_1.key'})?.apiKeyFile, '/run/secrets/next-dns_1.key');
});

test('profile ids and person ids are shape-checked and the map is bounded to 64', () => {
    for (const p of ['abc', 'a'.repeat(33), 'ab_cd', 'ab-cd', 'ab cd', '', 'ünïc0de', 'abc\n']) {
        assert.throws(() => parseContentFilter({...valid, defaultProfile: p}), /invalid_content_filter/, p);
        assert.throws(() => parseContentFilter({...valid, profiles: {pilot: p}}), /invalid_content_filter/, p);
    }
    assert.equal(parseContentFilter({...valid, defaultProfile: 'a'.repeat(32)})?.defaultProfile, 'a'.repeat(32));
    for (const person of ['Pilot', '1pilot', '__proto__', 'a b', '', 'x'.repeat(33)]) assert.throws(() => parseContentFilter({...valid, profiles: {[person]: 'def456'}}), /invalid_content_filter/, person);
    const many = (n: number) => Object.fromEntries(Array.from({length: n}, (_, i) => [`kid${i}`, 'def456']));
    assert.equal(Object.keys(parseContentFilter({...valid, profiles: many(64)})?.profiles ?? {}).length, 64);
    assert.throws(() => parseContentFilter({...valid, profiles: many(65)}), /invalid_content_filter/);
});

function keyFile(dir: string, body: string | Buffer, mode = 0o600): string {
    const path = join(dir, `key-${Math.random().toString(36).slice(2)}`);
    writeFileSync(path, body); chmodSync(path, mode); return path;
}

test('key reader returns the trimmed key and refuses unsafe or invalid files with closed codes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-key-test-'));
    try {
        assert.equal(readContentFilterKey(keyFile(dir, FAKE_KEY)), FAKE_KEY);
        assert.equal(readContentFilterKey(keyFile(dir, FAKE_KEY + '\n', 0o400)), FAKE_KEY);
        const expect = (path: string, want: string) => { try { readContentFilterKey(path); assert.fail('expected throw'); } catch (error) { assert.ok(error instanceof ContentFilterKeyError); assert.equal(error.code, want); assert.equal(error.message, want); } };
        expect(join(dir, 'absent'), 'key_file_missing');
        expect(keyFile(dir, FAKE_KEY, 0o640), 'key_file_unsafe');
        expect(keyFile(dir, FAKE_KEY, 0o604), 'key_file_unsafe');
        expect(keyFile(dir, FAKE_KEY, 0o660), 'key_file_unsafe');
        const target = keyFile(dir, FAKE_KEY), link = join(dir, 'link'); symlinkSync(target, link);
        expect(link, 'key_file_unsafe');
        const sub = join(dir, 'sub'); mkdirSync(sub); expect(sub, 'key_file_unsafe');
        expect(keyFile(dir, 'k'.repeat(257)), 'key_file_invalid');
        assert.equal(readContentFilterKey(keyFile(dir, 'k'.repeat(256))), 'k'.repeat(256));
        expect(keyFile(dir, ''), 'key_file_invalid');
        expect(keyFile(dir, '\n'), 'key_file_invalid');
        expect(keyFile(dir, 'ab cd'), 'key_file_invalid');
        expect(keyFile(dir, 'abcd\n\n'), 'key_file_invalid');
        expect(keyFile(dir, 'ab\tcd'), 'key_file_invalid');
        expect(keyFile(dir, 'ab\x00cd'), 'key_file_invalid');
        expect(keyFile(dir, Buffer.from([0x61, 0xc3, 0xa9])), 'key_file_invalid');
        expect(keyFile(dir, 'abc\r\n'), 'key_file_invalid');
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('key reader uses injected fs and never touches the disk beyond it', () => {
    const stat = {isFile: () => true, isSymbolicLink: () => false, mode: 0o100600, size: 4, uid: process.getuid?.()};
    assert.equal(readContentFilterKey('/x/key', {lstat: () => stat as never, readFile: () => Buffer.from('abcd\n')}), 'abcd');
    assert.throws(() => readContentFilterKey('/x/key', {lstat: () => ({...stat, uid: (stat.uid ?? 0) + 1}) as never, readFile: () => Buffer.from('abcd')}), /key_file_unsafe/);
    const reader = (over: object, body = 'abcd') => () => readContentFilterKey('/x/key', {lstat: () => ({...stat, ...over}) as never, readFile: () => Buffer.from(body)});
    assert.throws(reader({}, 'a'.repeat(300)), /key_file_invalid/, 'size is re-checked after the read');
    assert.throws(reader({}, 'a'.repeat(256) + '\n'), /key_file_invalid/, 'the 256 byte cap counts the newline');
    assert.throws(reader({size: 257}), /key_file_invalid/, 'the stat size cap holds on its own');
    assert.throws(reader({isSymbolicLink: () => true}), /key_file_unsafe/, 'a symlink is refused on its own');
    assert.throws(reader({isFile: () => false}), /key_file_unsafe/, 'a non-regular file is refused on its own');
    assert.throws(reader({mode: 0o100040}), /key_file_unsafe/);
    assert.throws(reader({mode: 0o100004}), /key_file_unsafe/);
});

async function withManifest(fn: (save: (extra: unknown, raw?: string) => void, path: string, dir: string) => void | Promise<void>): Promise<void> {
    const dir = mkdtempSync(join(tmpdir(), 'cf-cf-manifest-test-')), sample = testConfig(dir), socket = createServer();
    socket.listen(sample.router.agentSocket); await once(socket, 'listening'); chmodSync(sample.router.agentSocket, 0o600);
    const data = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), Buffer.alloc(32, 1)]), blob = data.toString('base64'), fp = 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
    writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n`, {mode: 0o600});
    writeFileSync(sample.router.publicIdentity, `ssh-ed25519 ${blob} test-public-key\n`, {mode: 0o600});
    const {origin: _o, host: _h, manifestDigest: _m, targetDigest: _t, provenance: _p, ...manifest} = sample;
    manifest.router.hostFingerprint = fp; manifest.router.publicKeyFingerprint = fp;
    const path = join(dir, 'manifest.json');
    const save = (extra: unknown, raw?: string) => writeFileSync(path, raw ?? JSON.stringify({...manifest, ...(extra as object)}), {mode: 0o600});
    try { await fn(save, path, dir); } finally { socket.close(); await once(socket, 'close'); rmSync(dir, {recursive: true, force: true}); }
}

test('manifest: contentFilter is optional, strict, owner mode needs ownerAccountId, and duplicate keys are refused', async () => {
    await withManifest((save, path) => {
        save({}); const base = integrationConfig(path);
        assert.equal(base.contentFilter, undefined); assert.equal('contentFilter' in base, false);
        save({contentFilter: {...valid, mode: 'parents'}}); const on = integrationConfig(path);
        assert.deepEqual(on.contentFilter, {...valid, mode: 'parents'}); assert.notEqual(on.manifestDigest, base.manifestDigest);
        save({contentFilter: valid, ownerAccountId: 'parent'}); assert.equal(integrationConfig(path).contentFilter?.mode, 'owner');
        save({contentFilter: valid}); assert.throws(() => integrationConfig(path), /owner_account_required/);
        save({contentFilter: {mode: 'off'}}); assert.deepEqual(integrationConfig(path).contentFilter, {mode: 'off'});
        for (const contentFilter of [{...valid, apiKey: FAKE_KEY}, {...valid, extra: 1}, {mode: 'x'}, {}, null, []]) { save({contentFilter, ownerAccountId: 'parent'}); assert.throws(() => integrationConfig(path)); }
        save(undefined, JSON.stringify({contentFilter: valid}).replace('{"mode"', '{"mode":"off","mode"'));
        assert.throws(() => integrationConfig(path));
    });
});

function capture<T>(fn: () => T): {out: string; result: T} {
    const chunks: string[] = [], saved = {err: process.stderr.write, out: process.stdout.write, con: {} as Record<string, unknown>};
    const sink = ((chunk: unknown) => { chunks.push(String(chunk)); return true; }) as typeof process.stderr.write;
    const methods = ['log', 'info', 'warn', 'error', 'debug', 'trace'] as const;
    process.stderr.write = sink; process.stdout.write = sink;
    for (const m of methods) { saved.con[m] = console[m]; console[m] = (...args: unknown[]) => { chunks.push(args.map(String).join(' ')); }; }
    try { const result = fn(); return {out: chunks.join(''), result}; } finally {
        process.stderr.write = saved.err; process.stdout.write = saved.out;
        for (const m of methods) console[m] = saved.con[m] as never;
    }
}

test('snapshot: no failure or success path leaks the key, its file path, or key material to output, errors or the parsed manifest', async () => {
    await withManifest((save, path, dir) => {
        const secretDir = join(dir, 'SECRET_PATH_MARKER'); mkdirSync(secretDir, {mode: 0o700});
        const file = (body: string | Buffer, mode = 0o600) => keyFile(secretDir, body, mode);
        const target = file(FAKE_KEY), link = join(secretDir, 'link'); symlinkSync(target, link);
        const readers = [
            () => readContentFilterKey(file(FAKE_KEY)), () => readContentFilterKey(file(FAKE_KEY + '\n', 0o400)),
            () => readContentFilterKey(join(secretDir, 'missing')), () => readContentFilterKey(file(FAKE_KEY, 0o644)), () => readContentFilterKey(link),
            () => readContentFilterKey(file(FAKE_KEY + 'x'.repeat(300))), () => readContentFilterKey(file(FAKE_KEY + ' tail')), () => readContentFilterKey(file(FAKE_KEY + '\x01')),
        ];
        const keyPath = join(secretDir, 'nextdns.key');
        const cf = {...valid, apiKeyFile: keyPath};
        const manifests: unknown[] = [{contentFilter: cf, ownerAccountId: 'parent'}, {contentFilter: {...cf, mode: 'nope'}}, {contentFilter: {...cf, apiKey: FAKE_KEY}}, {contentFilter: {...cf, secret: FAKE_KEY}}, {contentFilter: {...cf, apiKeyFile: keyPath + '/../x'}}, {contentFilter: {...cf, profiles: {}}}, {contentFilter: {...cf, defaultProfile: FAKE_KEY}}, {contentFilter: {...cf, profiles: {pilot: FAKE_KEY}}}, {contentFilter: {...cf, profiles: {[FAKE_KEY]: 'abc123'}}}];
        const parsers = manifests.map(extra => () => { save(extra); return integrationConfig(path); });
        const errors: string[] = []; let parsed: unknown;
        const { out } = capture(() => {
            for (const run of [...readers, ...parsers]) {
                try { const r = run(); if (typeof r === 'object') parsed = r; } catch (error) { const e = error as Error; errors.push(e.message, String(e), JSON.stringify(e), e.stack ?? '', JSON.stringify({...e})); }
            }
        });
        assert.ok(errors.length >= readers.length - 2 + manifests.length - 1, 'every failure path ran');
        const seen = [out, ...errors].join('\n'), material = JSON.stringify(parsed);
        for (const forbidden of [FAKE_KEY, 'TESTKEY', 'SECRET_PATH_MARKER', secretDir, keyPath]) assert.equal(seen.includes(forbidden), false, `leaked ${forbidden} to output or errors`);
        for (const forbidden of [FAKE_KEY, 'TESTKEY']) assert.equal(material.includes(forbidden), false, 'key material in parsed manifest');
        assert.ok(material.includes('contentFilter'), 'the success path parsed a manifest');
        assert.equal(out, '', 'nothing is written to stdout, stderr or console');
        assert.equal(readContentFilterKey(target), FAKE_KEY);
    });
});
