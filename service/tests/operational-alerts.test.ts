import test from 'node:test';
import assert from 'node:assert/strict';
import { operationalAlerts } from '../src/operational-alerts.ts';
import { integrationFixture, actor } from './fixtures/integration.ts';
import type { OperationDTO } from '../../shared/src/contracts.ts';

const now = 1791691200;
const operation: OperationDTO = {source: 'real-router-integration', routerCompatibilityVerified: false,
    id: '00000000-0000-4000-8000-000000000000', personId: 'pilot', action: 'pause', revision: 1, state: 'unknown',
    createdAt: now, updatedAt: now, error: 'SECRET raw diagnostic', confirmedAt: null};
const base = {source: 'router-policy' as const, now, sourceObservedAt: now, serviceReceivedAt: now, generationMatches: true,
    readError: false, healthy: true, drift: false, pauseUntil: null, expiredEffectivePause: false, operation: null, operationHealthy: false};

test('projection uses exact freshness boundary and never substitutes evaluation for source time', () => {
    for (const age of [0, 30, 31]) {
        const result = operationalAlerts({...base, now: now + age});
        assert.equal(result.freshness, age <= 30 ? 'fresh' : 'stale');
        assert.equal(result.healthy, age <= 30);
        assert.equal(result.sourceObservedAt, now); assert.equal(result.evaluatedAt, now + age);
        assert.deepEqual(result.conditions, age <= 30 ? [] : [{code: 'observation-stale'}]);
    }
    for (const change of [{sourceObservedAt: null}, {serviceReceivedAt: null}, {sourceObservedAt: now + 1},
        {serviceReceivedAt: now + 1}, {now: NaN}, {sourceObservedAt: 1}, {sourceObservedAt: now + 0.5}, {generationMatches: false}, {readError: true}]) {
        const result = operationalAlerts({...base, ...change});
        assert.equal(result.healthy, false); assert.equal(result.freshness, 'unknown');
        assert.deepEqual(result.conditions, [{code: 'observation-unavailable'}]); assert.equal(result.confirmedOperationId, null);
    }
    assert.equal(operationalAlerts({...base, sourceObservedAt: null}).sourceObservedAt, null);
    assert.equal(operationalAlerts({...base, source: 'synthetic-policy', serviceReceivedAt: null}).healthy, true);
});

test('fresh drift, unknown requests and finite accepted expiry carry only allowlisted fields', () => {
    assert.deepEqual(operationalAlerts({...base, healthy: false, drift: true}).conditions, [{code: 'observed-drift'}]);
    assert.ok(!operationalAlerts({...base, healthy: false, drift: true, now: now + 31}).conditions.some(signal => signal.code === 'observed-drift'));
    for (const state of ['unknown', 'failed', 'conflict'] as const) {
        const result = operationalAlerts({...base, operation: {...operation, state}});
        assert.deepEqual(result.conditions, [{code: 'control-verification-unavailable', operationId: operation.id}]);
        assert.ok(!JSON.stringify(result).includes('SECRET'));
    }
    assert.deepEqual(operationalAlerts({...base, operation: {...operation, state: 'pending'}}).conditions, []);
    const unverified = operationalAlerts({...base, now: now + 1, pauseUntil: now + 1});
    assert.deepEqual(unverified.conditions, [{code: 'pause-expiry-unverified', pauseUntil: now + 1}]);
    assert.deepEqual(operationalAlerts({...base, pauseUntil: now}).conditions, []);
    assert.equal(operationalAlerts({...base, pauseUntil: now, expiredEffectivePause: true}).conditions[0].code, 'pause-expiry-unverified');
    for (const pauseUntil of [0, null, now + 2]) assert.deepEqual(operationalAlerts({...base, pauseUntil}).conditions, []);
    assert.equal(operationalAlerts({...base, operation, operationHealthy: true}).confirmedOperationId, operation.id);
});

test('existing status projections filter assignments before alerts and make no transport calls', async () => {
    const f = integrationFixture();
    try {
        const first = f.policy.people(actor).people[0].operationalAlerts!;
        assert.equal(first.sourceObservedAt, null); assert.equal(first.conditions[0].code, 'observation-unavailable');
        await f.observe(); const calls = f.router.calls.length;
        assert.equal(f.policy.people(actor).people[0].operationalAlerts!.healthy, true);
        assert.deepEqual(f.policy.people({...actor, personIds: ['adult', 'unknown']}).people, []);
        assert.deepEqual(f.policy.people({...actor, personIds: []}).people, []);
        f.advance(31); assert.equal(f.policy.people(actor).people[0].operationalAlerts!.conditions[0].code, 'observation-stale');
        f.store.run("UPDATE integration_state SET observation_error='SECRET raw stderr' WHERE singleton=1");
        const json = JSON.stringify(f.policy.people(actor).people[0].operationalAlerts);
        assert.ok(!json.includes('SECRET')); assert.ok(!json.includes(f.config.person.device.mac)); assert.ok(!json.includes(f.config.protectedMacs[0]));
        assert.equal(f.router.calls.length, calls);
    } finally { f.cleanup(); }
});

test('accepted timed pause expiry stays unverified until an actual post-expiry witness, with fresh drift kept separate', async () => {
    const f = integrationFixture();
    try {
        await f.observe();
        const operation = f.pause(f.now() + 2).result.operation;
        const plan = f.worker.prepare('apply', operation.id); await f.worker.execute(plan, plan.scriptSha256);
        assert.equal(f.policy.people(actor).people[0].operationalAlerts!.confirmedOperationId, operation.id);
        f.advance(2);
        const expired = f.policy.people(actor).people[0].operationalAlerts!;
        assert.deepEqual(expired.conditions, [{code: 'pause-expiry-unverified', pauseUntil: f.now()}]);
        assert.equal(expired.sourceObservedAt, f.now() - 2);
        await f.observe();
        const verified = f.policy.people(actor).people[0].operationalAlerts!;
        assert.deepEqual(verified.conditions, []); assert.equal(verified.expiryVerifiedThrough, f.now());
        f.advance(1); f.router.transform = o => ({...o, status: {...o.status, drift: true}}); await f.observe();
        const calls = f.router.calls.length, drift = f.policy.people(actor).people[0].operationalAlerts!;
        assert.equal(drift.healthy, false); assert.ok(drift.conditions.some(signal => signal.code === 'observed-drift'));
        f.advance(31);
        assert.ok(!f.policy.people(actor).people[0].operationalAlerts!.conditions.some(signal => signal.code === 'observed-drift'));
        assert.equal(f.router.calls.length, calls);
    } finally { f.cleanup(); }
});
