import test from 'node:test';
import assert from 'node:assert/strict';
import fs, { constants, mkdtempSync, mkdirSync, rmSync, writeFileSync, chmodSync, symlinkSync, linkSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { integrationConfig, requirePrivatePath } from '../src/integration-config.ts';
import { PROFILE_ID_PATTERN, parseContentFilter, readContentFilterKey, ContentFilterKeyError, defaultKeyFs } from '../src/content-filter-config.ts';
import type { ContentFilterKeyDeps } from '../src/content-filter-config.ts';
import { testConfig } from './fixtures/integration.ts';

const FAKE_KEY = 'nxk_TESTKEY_do_not_log_0123456789';
const valid = {mode: 'owner', apiKeyFile: '/etc/couvre-feu/nextdns.key', defaultProfile: 'abc123', profiles: {pilot: 'def456'}};
/** Compares by value: the profiles map is deliberately a frozen null-prototype object. */
const plain = (value: unknown): unknown => value === undefined ? undefined : JSON.parse(JSON.stringify(value));
const code = (fn: () => unknown): string => { try { fn(); } catch (error) { return (error as Error).message; } return 'no_error'; };

test('profile id pattern is the single documented constant', () => {
    assert.equal(PROFILE_ID_PATTERN.source, '^[A-Za-z0-9]{4,32}$');
});

test('contentFilter parses valid shapes and treats absent as off', () => {
    assert.equal(parseContentFilter(undefined), undefined);
    assert.deepEqual(plain(parseContentFilter(valid)), valid);
    assert.deepEqual(plain(parseContentFilter({...valid, mode: 'parents'})), {...valid, mode: 'parents'});
    assert.deepEqual(plain(parseContentFilter({mode: 'off'})), {mode: 'off'});
    assert.deepEqual(plain(parseContentFilter({mode: 'off', defaultProfile: 'abc123', profiles: {}})), {mode: 'off', defaultProfile: 'abc123', profiles: {}});
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
    for (const value of bad) assert.throws(() => parseContentFilter(value), {message: 'invalid_content_filter'}, JSON.stringify(value));
});

test('apiKeyFile must be an absolute, normalized, charset-bound path of at most 255 characters', () => {
    const files = ['relative/key', '/a/../b', '/a/./b', '/a//b', '/a/b/', '/', '', '/a/b c', '/a/ü', '/a/b\n', '/a/b;rm', '/a/' + 'x'.repeat(253), '/..', '/a/..'];
    for (const apiKeyFile of files) assert.throws(() => parseContentFilter({...valid, apiKeyFile}), {message: 'invalid_content_filter'}, apiKeyFile);
    assert.equal(parseContentFilter({...valid, apiKeyFile: '/a/' + 'x'.repeat(252)})?.apiKeyFile?.length, 255);
    assert.equal(parseContentFilter({...valid, apiKeyFile: '/run/secrets/next-dns_1.key'})?.apiKeyFile, '/run/secrets/next-dns_1.key');
});

test('profile ids and person ids are shape-checked and the map is bounded to 64', () => {
    for (const p of ['abc', 'a'.repeat(33), 'ab_cd', 'ab-cd', 'ab cd', '', 'ünïc0de', 'abc\n']) {
        assert.throws(() => parseContentFilter({...valid, defaultProfile: p}), {message: 'invalid_content_filter'}, p);
        assert.throws(() => parseContentFilter({...valid, profiles: {pilot: p}}), {message: 'invalid_content_filter'}, p);
    }
    assert.equal(parseContentFilter({...valid, defaultProfile: 'a'.repeat(32)})?.defaultProfile, 'a'.repeat(32));
    for (const person of ['Pilot', '1pilot', '__proto__', 'valueOf', 'toString', 'hasOwnProperty', 'a b', '', 'x'.repeat(33)]) assert.throws(() => parseContentFilter({...valid, profiles: {[person]: 'def456'}}), {message: 'invalid_content_filter'}, person);
    const mapped = parseContentFilter({...valid, profiles: {pilot: 'def456'}})?.profiles as Record<string, string>;
    assert.equal(Object.getPrototypeOf(mapped), null); assert.equal(Object.isFrozen(mapped), true);
    for (const name of ['constructor', 'valueOf', 'toString', 'hasOwnProperty', '__proto__']) { assert.equal(mapped[name], undefined, name); assert.equal(Object.hasOwn(mapped, name), false, name); }
    const configured = parseContentFilter({...valid, profiles: {constructor: 'def456'}})?.profiles as Record<string, string>;
    assert.equal(Object.hasOwn(configured, 'constructor'), true); assert.equal(configured.constructor, 'def456'); assert.equal(Object.hasOwn(configured, 'valueof'), false);
    assert.throws(() => { (mapped as Record<string, string>).pilot = 'zzzz99'; }, TypeError, 'frozen');
    const many = (n: number) => Object.fromEntries(Array.from({length: n}, (_, i) => [`kid${i}`, 'def456']));
    assert.equal(Object.keys(parseContentFilter({...valid, profiles: many(64)})?.profiles ?? {}).length, 64);
    assert.throws(() => parseContentFilter({...valid, profiles: many(65)}), {message: 'invalid_content_filter'});
});

let counter = 0;
function keyFile(dir: string, body: string | Buffer, mode = 0o600): string {
    const path = join(dir, `key-${counter++}`);
    writeFileSync(path, body); chmodSync(path, mode); return path;
}
/** Real fs with the parent-directory check stubbed, so file-level guards are tested independent of where the temp dir lives. */
const noDirCheck: ContentFilterKeyDeps = {...defaultKeyFs, requirePrivateDir: () => undefined};
const readerCode = (path: string, deps: ContentFilterKeyDeps = noDirCheck): string => {
    try { readContentFilterKey(path, deps); } catch (error) { assert.ok(error instanceof ContentFilterKeyError); assert.equal(error.message, error.code); assert.equal(error.cause, undefined); return error.code; }
    return 'no_error';
};
const tmpPrivate = (): string => mkdtempSync(join(tmpdir(), 'cf-key-test-'));

test('key reader returns the trimmed key and refuses unsafe or invalid real files with closed codes', () => {
    const dir = tmpPrivate();
    try {
        assert.equal(readContentFilterKey(keyFile(dir, FAKE_KEY), noDirCheck), FAKE_KEY);
        assert.equal(readContentFilterKey(keyFile(dir, FAKE_KEY + '\n', 0o400), noDirCheck), FAKE_KEY);
        assert.equal(readerCode(join(dir, 'absent')), 'key_file_missing');
        for (const mode of [0o640, 0o604, 0o660, 0o644, 0o666]) assert.equal(readerCode(keyFile(dir, FAKE_KEY, mode)), 'key_file_unsafe', mode.toString(8));
        const sub = join(dir, 'sub'); mkdirSync(sub); assert.equal(readerCode(sub), 'key_file_unsafe');
        assert.equal(readerCode(keyFile(dir, 'k'.repeat(257))), 'key_file_invalid');
        assert.equal(readContentFilterKey(keyFile(dir, 'k'.repeat(256)), noDirCheck), 'k'.repeat(256));
        for (const body of ['', '\n', 'ab cd', 'abcd\n\n', 'ab\tcd', 'ab\x00cd', 'abc\r\n', Buffer.from([0x61, 0xc3, 0xa9])]) assert.equal(readerCode(keyFile(dir, body)), 'key_file_invalid', JSON.stringify(String(body)));
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('the real reader refuses a symlink to a valid key file (O_NOFOLLOW, no lstat to lean on), a hard link and a FIFO without hanging', { timeout: 10000 }, t => {
    const dir = tmpPrivate();
    try {
        const target = keyFile(dir, FAKE_KEY), link = join(dir, 'link'); symlinkSync(target, link);
        assert.equal(readerCode(link), 'key_file_unsafe');
        assert.equal(readContentFilterKey(target, noDirCheck), FAKE_KEY);
        const hard = join(dir, 'hard'); linkSync(target, hard);
        assert.equal(readerCode(hard), 'key_file_unsafe', 'nlink 2');
        assert.equal(readerCode(target), 'key_file_unsafe', 'the original is also now linked twice');
        const fifo = join(dir, 'fifo');
        try { execFileSync('mkfifo', [fifo]); } catch { t.diagnostic('mkfifo unavailable: FIFO case covered only by the injected fstat test'); return; }
        assert.equal(readerCode(fifo), 'key_file_unsafe');
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('the key file must sit in a private directory, checked with the manifest path rule', t => {
    const dir = tmpPrivate();
    try {
        const open = join(dir, 'open'); mkdirSync(open); const file = keyFile(open, FAKE_KEY);
        chmodSync(open, 0o777); assert.equal(readerCode(file, defaultKeyFs), 'key_file_unsafe');
        chmodSync(open, 0o770); assert.equal(readerCode(file, defaultKeyFs), 'key_file_unsafe');
        assert.equal(readerCode(join(dir, 'nodir', 'key'), defaultKeyFs), 'key_file_missing');
        chmodSync(open, 0o700);
        try { requirePrivatePath(open, 'directory'); } catch { t.diagnostic('temp ancestors are not private here: default-deps success case skipped'); return; }
        assert.equal(readContentFilterKey(file), FAKE_KEY);
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

const okStat = {isFile: () => true, mode: 0o100600, size: 4, uid: process.getuid?.() ?? -1, nlink: 1};
function fakeFs(over: Partial<typeof okStat> = {}, chunks: Buffer[] = [Buffer.from('abcd\n')]) {
    const calls = {flags: [] as number[], closed: 0, reads: 0}, queue = [...chunks];
    const deps: ContentFilterKeyDeps = {
        open: (_path, flags) => { calls.flags.push(flags); return 7; },
        fstat: () => ({...okStat, ...over}) as never,
        read: (_fd, buffer, offset, length) => { calls.reads++; const next = queue.shift(); return next ? next.copy(buffer, offset, 0, length) : 0; },
        close: () => { calls.closed++; },
        requirePrivateDir: () => undefined,
    };
    return {deps, calls};
}

test('key reader decides on the opened fd (injected races), always closes it and bounds the read', () => {
    const ok = fakeFs(); assert.equal(readContentFilterKey('/x/key', ok.deps), 'abcd'); assert.equal(ok.calls.closed, 1);
    for (const flag of ['O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK'] as const) assert.equal((ok.calls.flags[0] & constants[flag]) === constants[flag], true, flag);
    assert.equal(ok.calls.flags[0] & (constants.O_WRONLY | constants.O_RDWR), 0);
    const cases: [string, Partial<typeof okStat>, string][] = [
        ['fifo or device', {isFile: () => false}, 'key_file_unsafe'], ['other owner', {uid: okStat.uid + 1}, 'key_file_unsafe'], ['two links', {nlink: 2}, 'key_file_unsafe'],
        ['group readable', {mode: 0o100640}, 'key_file_unsafe'], ['other readable', {mode: 0o100604}, 'key_file_unsafe'], ['oversize', {size: 257}, 'key_file_invalid'],
    ];
    for (const [name, over, want] of cases) { const f = fakeFs(over); assert.equal(readerCode('/x/key', f.deps), want, name); assert.equal(f.calls.closed, 1, `${name}: fd closed`); assert.equal(f.calls.reads, 0, `${name}: nothing read`); }
    const grows = fakeFs({}, Array.from({length: 50}, () => Buffer.alloc(100, 97)));
    assert.equal(readerCode('/x/key', grows.deps), 'key_file_invalid'); assert.ok(grows.calls.reads <= 4, `bounded read, got ${grows.calls.reads} reads`); assert.equal(grows.calls.closed, 1);
    assert.equal(readerCode('/x/key', fakeFs({}, [Buffer.from('a'.repeat(256) + '\n')]).deps), 'key_file_invalid', 'the 256 byte cap counts the newline');
    const chunked = fakeFs({}, [Buffer.from('ab'), Buffer.from('cd\n')]); assert.equal(readContentFilterKey('/x/key', chunked.deps), 'abcd');
    const throwing = fakeFs(); throwing.deps.read = () => { throw Object.assign(new Error('EIO /secret/path'), {code: 'EIO'}); };
    assert.equal(readerCode('/x/key', throwing.deps), 'key_file_unsafe'); assert.equal(throwing.calls.closed, 1);
    const openFails: ContentFilterKeyDeps = {...ok.deps, open: () => { throw Object.assign(new Error('ELOOP'), {code: 'ELOOP'}); }};
    assert.equal(readerCode('/x/key', openFails), 'key_file_unsafe');
    assert.equal(readerCode('/x/key', {...ok.deps, open: () => { throw Object.assign(new Error('ENOENT'), {code: 'ENOENT'}); }}), 'key_file_missing');
    assert.equal(readerCode('/x/key', {...ok.deps, requirePrivateDir: () => { throw new Error('unsafe_private_ancestor'); }}), 'key_file_unsafe');
});

test('key reader fails closed when the process uid is unavailable', () => {
    const saved = process.getuid; (process as {getuid?: unknown}).getuid = undefined;
    try { assert.equal(readerCode('/x/key', fakeFs().deps), 'key_file_unsafe'); } finally { process.getuid = saved; }
});

async function withManifest(fn: (save: (extra: unknown, rewrite?: (json: string) => string) => void, path: string, dir: string) => void | Promise<void>): Promise<void> {
    const dir = mkdtempSync(join(tmpdir(), 'cf-cf-manifest-test-')), sample = testConfig(dir), socket = createServer();
    socket.listen(sample.router.agentSocket); await once(socket, 'listening'); chmodSync(sample.router.agentSocket, 0o600);
    const data = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), Buffer.alloc(32, 1)]), blob = data.toString('base64'), fp = 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
    writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n`, {mode: 0o600});
    writeFileSync(sample.router.publicIdentity, `ssh-ed25519 ${blob} test-public-key\n`, {mode: 0o600});
    const {origin: _o, host: _h, manifestDigest: _m, targetDigest: _t, provenance: _p, ...manifest} = sample;
    manifest.router.hostFingerprint = fp; manifest.router.publicKeyFingerprint = fp;
    const path = join(dir, 'manifest.json');
    const save = (extra: unknown, rewrite: (json: string) => string = json => json) => writeFileSync(path, rewrite(JSON.stringify({...manifest, ...(extra as object)})), {mode: 0o600});
    try { await fn(save, path, dir); } finally { socket.close(); await once(socket, 'close'); rmSync(dir, {recursive: true, force: true}); }
}

test('manifest: contentFilter is optional, strict, owner mode needs ownerAccountId, and duplicate keys are refused', async () => {
    await withManifest((save, path) => {
        save({}); const base = integrationConfig(path);
        assert.equal(base.contentFilter, undefined); assert.equal('contentFilter' in base, false);
        save({contentFilter: {...valid, mode: 'parents'}}); const on = integrationConfig(path);
        assert.deepEqual(plain(on.contentFilter), {...valid, mode: 'parents'}); assert.notEqual(on.manifestDigest, base.manifestDigest);
        save({contentFilter: valid, ownerAccountId: 'parent'}); assert.equal(integrationConfig(path).contentFilter?.mode, 'owner');
        save({contentFilter: valid}); assert.throws(() => integrationConfig(path), /owner_account_required/);
        save({contentFilter: {mode: 'parents', ...{apiKeyFile: valid.apiKeyFile, defaultProfile: valid.defaultProfile, profiles: valid.profiles}}}); assert.equal(integrationConfig(path).contentFilter?.mode, 'parents', 'parents mode needs no owner account');
        save({contentFilter: {mode: 'off'}}); assert.deepEqual(plain(integrationConfig(path).contentFilter), {mode: 'off'});
        for (const contentFilter of [{...valid, apiKey: FAKE_KEY}, {...valid, extra: 1}, {mode: 'x'}, {}, null, []]) { save({contentFilter, ownerAccountId: 'parent'}); assert.throws(() => integrationConfig(path), {message: 'invalid_content_filter'}); }
        // A duplicate key inside an otherwise valid contentFilter (owner account present) is refused by the shared JSON parser.
        save({contentFilter: valid, ownerAccountId: 'parent'}, json => json.replace('"mode":"owner"', '"mode":"owner","mode":"off"'));
        assert.throws(() => integrationConfig(path), {message: 'invalid_json'});
        save({contentFilter: valid, ownerAccountId: 'parent'}); assert.equal(integrationConfig(path).contentFilter?.mode, 'owner', 'the same manifest without the duplicate is accepted');
    });
});

function capture<T>(fn: () => T): {out: string; result: T} {
    const chunks: string[] = [], saved = {err: process.stderr.write, out: process.stdout.write, warn: process.emitWarning, sync: fs.writeSync, con: {} as Record<string, unknown>};
    const sink = ((chunk: unknown) => { chunks.push(String(chunk)); return true; }) as typeof process.stderr.write;
    const methods = ['log', 'info', 'warn', 'error', 'debug', 'trace'] as const;
    process.stderr.write = sink; process.stdout.write = sink;
    process.emitWarning = ((warning: unknown) => { chunks.push(`warning:${String(warning)}`); }) as typeof process.emitWarning;
    // Only terminal writes count: the test's own manifest and key file writes go through writeSync with a higher fd.
    fs.writeSync = ((fd: number, data: unknown, ...rest: unknown[]) => { if (fd <= 2) { chunks.push(`writeSync(${fd}):${String(data)}`); return String(data).length; } return (saved.sync as (...args: unknown[]) => number)(fd, data, ...rest); }) as typeof fs.writeSync; syncBuiltinESMExports();
    for (const m of methods) { saved.con[m] = console[m]; console[m] = (...args: unknown[]) => { chunks.push(args.map(String).join(' ')); }; }
    try { const result = fn(); return {out: chunks.join(''), result}; } finally {
        process.stderr.write = saved.err; process.stdout.write = saved.out; process.emitWarning = saved.warn; fs.writeSync = saved.sync; syncBuiltinESMExports();
        for (const m of methods) console[m] = saved.con[m] as never;
    }
}

test('snapshot: no failure or success path leaks the key, its file path, or key material to output, errors or the parsed manifest', async () => {
    await withManifest((save, path, dir) => {
        const secretDir = join(dir, 'SECRET_PATH_MARKER'); mkdirSync(secretDir, {mode: 0o700});
        const file = (body: string | Buffer, mode = 0o600) => keyFile(secretDir, body, mode);
        const target = file(FAKE_KEY), link = join(secretDir, 'link'); symlinkSync(target, link);
        const keyPath = join(secretDir, 'nextdns.key'), read = (path: string) => () => readContentFilterKey(path, noDirCheck);
        const hard = join(secretDir, 'hard'); linkSync(file(FAKE_KEY), hard);
        const readers = [
            read(file(FAKE_KEY)), read(file(FAKE_KEY + '\n', 0o400)),
            read(join(secretDir, 'missing')), read(keyPath), read(file(FAKE_KEY, 0o644)), read(link), read(hard), read(secretDir),
            read(file(FAKE_KEY + 'x'.repeat(300))), read(file(FAKE_KEY + ' tail')), read(file(FAKE_KEY + '\x01')),
            () => readContentFilterKey(keyPath, {...noDirCheck, requirePrivateDir: () => { throw new Error(`unsafe_private_ancestor ${secretDir}`); }}),
        ];
        const writeKeyPath = () => { writeFileSync(keyPath, FAKE_KEY, {mode: 0o644}); };
        const cf = {...valid, apiKeyFile: keyPath};
        const manifests: unknown[] = [{contentFilter: cf, ownerAccountId: 'parent'}, {contentFilter: {...cf, mode: 'nope'}}, {contentFilter: {...cf, apiKey: FAKE_KEY}}, {contentFilter: {...cf, secret: FAKE_KEY}}, {contentFilter: {...cf, apiKeyFile: keyPath + '/../x'}}, {contentFilter: {...cf, profiles: {}}}, {contentFilter: {...cf, defaultProfile: FAKE_KEY}}, {contentFilter: {...cf, profiles: {pilot: FAKE_KEY}}}, {contentFilter: {...cf, profiles: {[FAKE_KEY]: 'abc123'}}}];
        const parsers = manifests.map(extra => () => { save(extra); return integrationConfig(path); });
        const errors: string[] = []; let parsed: unknown;
        const { out } = capture(() => {
            for (const run of [...readers.slice(0, 4), () => writeKeyPath(), ...readers.slice(4), ...parsers]) {
                try { const r = run(); if (typeof r === 'object') parsed = r; } catch (error) { const e = error as Error; assert.equal(e.cause, undefined, 'no cause chain'); errors.push(e.message, String(e), JSON.stringify(e), e.stack ?? '', JSON.stringify({...e})); }
            }
        });
        assert.ok(errors.length >= (readers.length - 2 + manifests.length - 1) * 5, 'every failure path ran');
        const seen = [out, ...errors].join('\n'), material = JSON.stringify(parsed);
        for (const forbidden of [FAKE_KEY, 'TESTKEY', 'SECRET_PATH_MARKER', secretDir, keyPath]) assert.equal(seen.includes(forbidden), false, `leaked ${forbidden} to output or errors`);
        for (const forbidden of [FAKE_KEY, 'TESTKEY']) assert.equal(material.includes(forbidden), false, 'key material in parsed manifest');
        assert.ok(material.includes('contentFilter'), 'the success path parsed a manifest');
        assert.equal(out, '', 'nothing is written to stdout, stderr or console');
        assert.equal(readContentFilterKey(target), FAKE_KEY);
    });
});
