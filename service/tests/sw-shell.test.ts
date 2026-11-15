import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildServiceWorker } from '../src/sw-shell.ts';

const REAL = fileURLToPath(new URL('../../web/public/', import.meta.url));
const NAME = /cf-shell-[0-9a-f]{10}/;

function copyPublic(): string {
    const dir = mkdtempSync(join(tmpdir(), 'cf-sw-'));
    cpSync(REAL, dir, {recursive: true});
    return dir;
}

test('the checked-in sw.js carries only the placeholder, and the served one has a content-hash name instead', () => {
    assert.match(readFileSync(join(REAL, 'sw.js'), 'utf8'), /'cf-shell-dev'/);
    const built = buildServiceWorker(REAL);
    assert.match(built.name, /^cf-shell-[0-9a-f]{10}$/);
    assert.ok(built.source.includes(`'${built.name}'`));
    assert.ok(!built.source.includes('cf-shell-dev'));
    assert.match(built.source, NAME);
});

test('the name is stable for unchanged files and changes when any shipped asset byte or sw.js changes', () => {
    const dir = copyPublic();
    try {
        const first = buildServiceWorker(dir).name;
        assert.equal(buildServiceWorker(dir).name, first);
        const assets = [...readFileSync(join(dir, 'sw.js'), 'utf8').matchAll(/'(\/[^']*)'/g)].map((m) => m[1]);
        assert.ok(assets.length > 10);
        for (const asset of assets) {
            const file = join(dir, asset === '/' ? 'index.html' : asset.slice(1));
            const original = readFileSync(file);
            writeFileSync(file, Buffer.concat([original, Buffer.from(' ')]));
            assert.notEqual(buildServiceWorker(dir).name, first, `${asset} must feed the hash`);
            writeFileSync(file, original);
            assert.equal(buildServiceWorker(dir).name, first);
        }
        const sw = readFileSync(join(dir, 'sw.js'), 'utf8');
        writeFileSync(join(dir, 'sw.js'), sw + '\n// changed\n');
        assert.notEqual(buildServiceWorker(dir).name, first, 'sw.js itself must feed the hash');
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('the integration variant keeps its own cache name but still carries the content hash', () => {
    const plain = buildServiceWorker(REAL), integration = buildServiceWorker(REAL, 'integration-dddd');
    assert.equal(integration.name, `${plain.name}-integration-dddd`);
    assert.match(integration.source, NAME);
    assert.ok(!integration.source.includes('cf-shell-dev'));
});

test('a missing asset or a missing placeholder fails fast instead of hashing fewer files', () => {
    const dir = copyPublic();
    try {
        rmSync(join(dir, 'tabs.js'));
        assert.throws(() => buildServiceWorker(dir), /tabs\.js/);
        writeFileSync(join(dir, 'tabs.js'), '');
        const sw = readFileSync(join(dir, 'sw.js'), 'utf8');
        writeFileSync(join(dir, 'sw.js'), sw.replace("'cf-shell-dev'", "'cf-shell-v15'"));
        assert.throws(() => buildServiceWorker(dir), /placeholder/);
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
