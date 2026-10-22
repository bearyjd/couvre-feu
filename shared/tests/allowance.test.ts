import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { normalizePolicy, policyJSON, effectiveAllowances, allowanceWithinHorizon, healthyConfirmation, effectivePauses, MAX_ALLOWANCE_SECONDS } from '../src/router-schema.ts';
import type { RouterPolicy, RouterStatus } from '../src/router-schema.ts';
import { canonicalPolicyRecords, policyDigest, normalizeObservation, FORMAT_ONLY } from '../src/router-rpc.ts';

const NOW = 1791691200;
const base = {version: 1, revision: 3, people: [{id: 'zed', macs: []}, {id: 'alex', macs: ['02:00:00:00:00:20']}], pauses: [{person: 'alex', until: 0}], schedules: [], doh: {ipv4: [], ipv6: []}};

function awkRecords(input: unknown) {
    return spawnSync('awk', ['-f', 'router/lib/json.awk'], {input: JSON.stringify(input), encoding: 'utf8', env: {PATH: '/usr/bin:/bin', LC_ALL: 'C'}});
}
function status(policy: RouterPolicy, now: number, overrides: Partial<RouterStatus> = {}): RouterStatus {
    const allowed = new Set(effectiveAllowances(policy, now).map(a => a.person));
    const paused = effectivePauses(policy, now).filter(p => !allowed.has(p.person)).flatMap(p => policy.people.find(x => x.id === p.person)!.macs).sort();
    return {ok: true, desiredRevision: policy.revision, confirmedRevision: policy.revision, desiredPauses: policy.pauses, effectivePauses: effectivePauses(policy, now),
        desiredAllowances: policy.allowances ?? [], effectiveAllowances: effectiveAllowances(policy, now), observed: {kids: policy.people.flatMap(p => p.macs).sort(), paused},
        drift: false, errors: [], capabilities: {ipv6: true, conntrack: true, nativeKernelConfirmed: true, addressCoverageComplete: true, routerCompatibilityVerified: false}, ...overrides};
}

test('allowances normalize sorted, are omitted when empty and match router awk records and digest', () => {
    assert.equal('allowances' in normalizePolicy(base), false);
    assert.equal('allowances' in normalizePolicy({...base, allowances: []}), false);
    const input = {...base, allowances: [{person: 'zed', until: NOW + 60}, {person: 'alex', until: NOW + 30}]};
    const p = normalizePolicy(input);
    assert.deepEqual(p.allowances, [{person: 'alex', until: NOW + 30}, {person: 'zed', until: NOW + 60}]);
    assert.deepEqual(normalizePolicy(JSON.parse(policyJSON(p))), p);
    const child = awkRecords(input);
    assert.equal(child.status, 0, child.stderr);
    const rows = child.stdout.trimEnd().split('\n'), canonical = ['V\t1', 'R\t3', ...rows.filter(row => !/^[VR]\t/.test(row)).sort()].join('\n') + '\n';
    assert.match(canonical, /^U\talex\t1791691230$/m);
    assert.equal(canonicalPolicyRecords(p), canonical);
    const hash = spawnSync('sha256sum', [], {input: canonical, encoding: 'utf8'});
    assert.equal(policyDigest(p), hash.stdout.split(' ')[0]);
    // An absent key keeps legacy digests byte-identical.
    assert.doesNotMatch(canonicalPolicyRecords(normalizePolicy(base)), /^U\t/m);
});

test('allowance schema rejects duplicate, unknown, zero, overflow, fractional and extra-field records like the router', () => {
    for (const allowances of [
        [{person: 'alex', until: NOW}, {person: 'alex', until: NOW + 1}], [{person: 'bob', until: NOW}], [{person: 'alex', until: 0}],
        [{person: 'alex', until: 2147483648}], [{person: 'alex', until: NOW + 0.5}], [{person: 'alex', until: String(NOW)}],
        [{person: 'alex', until: NOW, extra: 1}], [{person: 'alex'}], {person: 'alex', until: NOW},
        Array.from({length: 65}, (_, i) => ({person: 'alex', until: NOW + i}))
    ]) {
        assert.throws(() => normalizePolicy({...base, allowances}));
        assert.notEqual(awkRecords({...base, allowances}).status, 0, JSON.stringify(allowances).slice(0, 60));
    }
});

test('effective allowances require a valid clock, an unexpired deadline and the router horizon', () => {
    const p = normalizePolicy({...base, allowances: [{person: 'alex', until: NOW + 60}]});
    assert.deepEqual(effectiveAllowances(p, NOW), [{person: 'alex', until: NOW + 60, remaining: 60}]);
    assert.deepEqual(effectiveAllowances(p, NOW + 60), []);
    assert.deepEqual(effectiveAllowances(p, 1500000000), []);
    assert.deepEqual(effectiveAllowances(p, Number.NaN), []);
    assert.deepEqual(effectiveAllowances(p, NOW + 60 - MAX_ALLOWANCE_SECONDS - 1), []);
    assert.equal(allowanceWithinHorizon(NOW + MAX_ALLOWANCE_SECONDS, NOW), true);
    assert.equal(allowanceWithinHorizon(NOW + MAX_ALLOWANCE_SECONDS + 1, NOW), false);
    assert.equal(allowanceWithinHorizon(NOW, NOW), false);
    assert.equal(allowanceWithinHorizon(NOW + 60, 1500000000), false);
});

test('healthy confirmation excludes overridden pauses and requires the router to report active allowances', () => {
    const p = normalizePolicy({...base, allowances: [{person: 'alex', until: NOW + 60}]});
    assert.equal(healthyConfirmation(status(p, NOW), p, NOW), true);
    assert.equal(healthyConfirmation(status(p, NOW, {effectiveAllowances: undefined}), p, NOW), false);
    assert.equal(healthyConfirmation(status(p, NOW, {observed: {kids: ['02:00:00:00:00:20'], paused: ['02:00:00:00:00:20']}}), p, NOW), false);
    // Router remaining is computed from its highwater epoch; only person/until must agree.
    assert.equal(healthyConfirmation(status(p, NOW, {effectiveAllowances: [{person: 'alex', until: NOW + 60, remaining: 59}]}), p, NOW), true);
    // After expiry the pause re-applies.
    assert.equal(healthyConfirmation(status(p, NOW, {}), p, NOW + 61), false);
    assert.equal(healthyConfirmation(status(p, NOW + 61), p, NOW + 61), true);
    assert.deepEqual(status(p, NOW + 61).observed.paused, ['02:00:00:00:00:20']);
});

test('RPC observation accepts reported allowances and rejects fabricated or out-of-policy ones', () => {
    const p = normalizePolicy({...base, allowances: [{person: 'alex', until: NOW + 60}]});
    const o = {rpc_version: 1, generation: 'a'.repeat(64), acceptedPolicy: p, policyDigest: policyDigest(p), currentOperationId: null, routerTime: NOW, receipt: null, errors: [], status: status(p, NOW)};
    assert.deepEqual(normalizeObservation(o, FORMAT_ONLY).status.effectiveAllowances, [{person: 'alex', until: NOW + 60, remaining: 60}]);
    const legacy = normalizePolicy(base), {desiredAllowances: _d, effectiveAllowances: _e, ...legacyStatus} = status(legacy, NOW);
    assert.equal(normalizeObservation({...o, acceptedPolicy: legacy, policyDigest: policyDigest(legacy), status: legacyStatus}, FORMAT_ONLY).status.desiredAllowances, undefined);
    assert.throws(() => normalizeObservation({...o, status: {...o.status, desiredAllowances: []}}, FORMAT_ONLY));
    assert.throws(() => normalizeObservation({...o, status: {...o.status, effectiveAllowances: [{person: 'zed', until: NOW + 60, remaining: 60}]}}, FORMAT_ONLY));
    assert.throws(() => normalizeObservation({...o, status: {...o.status, effectiveAllowances: [{person: 'alex', until: NOW + 60, remaining: MAX_ALLOWANCE_SECONDS + 1}]}}, FORMAT_ONLY));
    assert.throws(() => normalizeObservation({...o, status: {...o.status, effectiveAllowances: [{person: 'alex', until: NOW + 60}]}}, FORMAT_ONLY));
});
