import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const MAIN = new URL('../src/integration-main.ts', import.meta.url).pathname;
const RUN_MS = 60_000;
const EX_CONFIG = 78;

function start(manifest: string) {
    return spawnSync(process.execPath, [MAIN, manifest], {encoding: 'utf8', timeout: RUN_MS});
}

test('a missing manifest is a deterministic refusal that exits 78', () => {
    const r = start('/nonexistent/couvrefeu-manifest.json');
    assert.equal(r.status, EX_CONFIG, r.stderr);
    assert.match(r.stderr, /startup_refused/);
});

test('an unparsable manifest is a deterministic refusal that exits 78', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-main-'));
    try {
        const manifest = join(dir, 'manifest.json');
        writeFileSync(manifest, '{not json', {mode: 0o600});
        assert.equal(start(manifest).status, EX_CONFIG);
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('the usage error is not reported as a config refusal', () => {
    const r = spawnSync(process.execPath, [MAIN], {encoding: 'utf8', timeout: RUN_MS});
    assert.notEqual(r.status, 0);
    assert.notEqual(r.status, EX_CONFIG);
});
