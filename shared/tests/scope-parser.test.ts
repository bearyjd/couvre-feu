import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeObservation, parseObservation, policyDigest, sha256, FORMAT_ONLY } from '../src/router-rpc.ts';
import { normalizePolicy } from '../src/router-schema.ts';
import { testConfig, observation } from '../../service/tests/fixtures/integration.ts';

// Fictional, locally administered unicast MACs only.
const SEED = '02:10:20:30:40:50', PROTECTED = '02:10:20:30:40:51', TABLET = '02:10:20:30:40:52', LAPTOP = '02:10:20:30:40:53';
const NOW = 1791691200;
const scopeSha = (scope: string[]) => sha256(scope.join('\n') + '\n');
const c = testConfig('/tmp/unused');
const context = {protectedMacs: c.protectedMacs, floor: [SEED]};
const withScope = (scope: string[], over: Record<string, unknown> = {}) => ({...observation(c, c.enrollment, NOW), scope, scopeSha: Array.isArray(scope) && scope.every(e => typeof e === 'string') ? scopeSha(scope) : 'a'.repeat(64), ...over});
const macN = (n: number) => `02:00:00:00:${(n >> 8).toString(16).padStart(2, '0')}:${(n & 255).toString(16).padStart(2, '0')}`;

test('a valid scope and its digest are accepted and returned; absent scope stays absent', () => {
    assert.equal(c.protectedMacs[0], PROTECTED);
    const scope = [SEED, TABLET], o = normalizeObservation(withScope(scope), context);
    assert.deepEqual(o.scope, scope);
    assert.equal(o.scopeSha, scopeSha(scope));
    // Old routers send neither key: the observation is exactly as before, with no scope keys at all.
    const legacy = normalizeObservation(observation(c, c.enrollment, NOW), context);
    assert.equal(Object.hasOwn(legacy, 'scope'), false);
    assert.equal(Object.hasOwn(legacy, 'scopeSha'), false);
    // Parsing the text form with the same context behaves the same.
    assert.deepEqual(parseObservation(JSON.stringify(withScope(scope)), context).scope, scope);
    // 256 entries is the limit.
    const full = [SEED, ...Array.from({length: 255}, (_, i) => macN(i + 1))].sort();
    assert.equal(normalizeObservation(withScope(full), context).scope!.length, 256);
});

test('scope and scopeSha must appear together, never null', () => {
    const o = withScope([SEED]), {scopeSha: _s, ...noSha} = o, {scope: _c, ...noScope} = o;
    assert.throws(() => normalizeObservation(noSha, context), /invalid_router_rpc/);
    assert.throws(() => normalizeObservation(noScope, context), /invalid_router_rpc/);
    assert.throws(() => normalizeObservation({...o, scope: null}, context), /invalid_router_rpc/);
    assert.throws(() => normalizeObservation({...o, scopeSha: null}, context), /invalid_router_rpc/);
    assert.throws(() => normalizeObservation({...o, scope: undefined}, context), /invalid_router_rpc/);
});

test('scope rejects non-arrays, empty, oversize, non-canonical, unsorted and duplicate lists', () => {
    for (const bad of ['x', {}, 5, [], [5], [null], [SEED.toUpperCase()], [SEED.replaceAll(':', '-')], ['02:10:20:30:40:5'], ['03:10:20:30:40:50'], ['00:00:00:00:00:00'], [SEED + ' ']]) {
        assert.throws(() => normalizeObservation(withScope(bad as string[], {scopeSha: 'a'.repeat(64)}), context), /invalid_router_rpc/, JSON.stringify(bad));
    }
    assert.throws(() => normalizeObservation(withScope([TABLET, SEED]), context), /invalid_router_rpc/, 'descending');
    assert.throws(() => normalizeObservation(withScope([SEED, SEED]), context), /invalid_router_rpc/, 'duplicate');
    const over = [SEED, ...Array.from({length: 256}, (_, i) => macN(i + 1))].sort();
    assert.equal(over.length, 257);
    assert.throws(() => normalizeObservation(withScope(over), context), /invalid_router_rpc/, '257 entries');
});

test('scopeSha must be 64 lowercase hex and equal sha256(scope.join LF + LF)', () => {
    const scope = [SEED, TABLET];
    assert.throws(() => normalizeObservation(withScope(scope, {scopeSha: 'a'.repeat(64)}), context), /invalid_router_rpc/);
    assert.throws(() => normalizeObservation(withScope(scope, {scopeSha: scopeSha(scope).toUpperCase()}), context), /invalid_router_rpc/);
    assert.throws(() => normalizeObservation(withScope(scope, {scopeSha: scopeSha(scope).slice(1)}), context), /invalid_router_rpc/);
    // The digest of the list without the trailing LF, or of another list, does not pass.
    assert.throws(() => normalizeObservation(withScope(scope, {scopeSha: sha256(scope.join('\n'))}), context), /invalid_router_rpc/);
    assert.throws(() => normalizeObservation(withScope(scope, {scopeSha: scopeSha([SEED])}), context), /invalid_router_rpc/);
});

test('scope overlapping a protected MAC is rejected', () => {
    assert.throws(() => normalizeObservation(withScope([SEED, PROTECTED]), context), /invalid_router_rpc/);
    // The protected set comes from the manifest, so without that context the parser cannot know; the worker always passes it.
    assert.deepEqual(normalizeObservation(withScope([SEED, PROTECTED]), FORMAT_ONLY).scope, [SEED, PROTECTED]);
});

test('scope that does not contain the manifest floor is rejected', () => {
    // An empty accepted policy isolates the floor rule from the policy rule.
    const empty = normalizePolicy({version: 1, revision: 0, people: [], pauses: [], schedules: []});
    const make = (scope: string[]) => ({...observation(c, empty, NOW), scope, scopeSha: scopeSha(scope)});
    assert.throws(() => normalizeObservation(make([TABLET]), context), /invalid_router_rpc/);
    assert.throws(() => normalizeObservation(make([TABLET, LAPTOP]), {...context, floor: [SEED, TABLET]}), /invalid_router_rpc/);
    assert.equal(normalizeObservation(make([SEED, TABLET, LAPTOP]), {...context, floor: [SEED, TABLET]}).scope!.length, 3);
    // No floor in the context (a context-free parse) cannot judge it.
    assert.deepEqual(normalizeObservation(make([TABLET]), FORMAT_ONLY).scope, [TABLET]);
});

test('scope that omits a MAC of the accepted policy is rejected', () => {
    const policy = normalizePolicy({version: 1, revision: 0, people: [{id: 'pilot', macs: [SEED, TABLET]}], pauses: [], schedules: []});
    const o = {...observation(c, policy, NOW)};
    const make = (scope: string[]) => ({...o, scope, scopeSha: scopeSha(scope)});
    assert.equal(o.policyDigest, policyDigest(policy));
    assert.throws(() => normalizeObservation(make([SEED]), context), /invalid_router_rpc/);
    assert.deepEqual(normalizeObservation(make([SEED, TABLET]), context).scope, [SEED, TABLET]);
    // Absent scope is not checked against the policy (old router).
    assert.equal(normalizeObservation(o, context).scope, undefined);
});

test('the strict parser still rejects unknown keys everywhere else', () => {
    const o = withScope([SEED]);
    assert.throws(() => normalizeObservation({...o, extra: 1}, context), /invalid_fields/);
    assert.throws(() => normalizeObservation({...o, scopes: [SEED]}, context), /invalid_fields/);
    assert.throws(() => normalizeObservation({...o, status: {...o.status, scope: [SEED]}}, context), /invalid_fields/);
});
