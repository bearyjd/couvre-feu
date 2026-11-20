import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MAX_ALLOWANCE_SECONDS, MIN_VALID_ROUTER_TIME } from '../src/router-schema.ts';

const core = readFileSync(fileURLToPath(new URL('../../router/lib/core.sh', import.meta.url)), 'utf8');

test('router core.sh CF_ALLOWANCE_HORIZON equals MAX_ALLOWANCE_SECONDS (drift test)', () => {
    const match = /^CF_ALLOWANCE_HORIZON=(\d+)\s*$/m.exec(core);
    assert.ok(match, 'CF_ALLOWANCE_HORIZON not found in core.sh');
    assert.equal(Number(match![1]), MAX_ALLOWANCE_SECONDS);
});

test('every minimum-clock literal in router core.sh equals MIN_VALID_ROUTER_TIME (drift test)', () => {
    const clockLiterals = [...core.matchAll(/(?:-ge|>=)\s*(\d{10})\b/g)].map(m => Number(m[1]));
    assert.ok(clockLiterals.length >= 3, 'expected the clock-floor literals in core.sh');
    for (const literal of clockLiterals) assert.equal(literal, MIN_VALID_ROUTER_TIME);
    assert.equal((core.match(/\b1577836800\b/g) ?? []).length, clockLiterals.length, 'a 1577836800 literal is not a recognized clock floor');
});
