import test from 'node:test';
import assert from 'node:assert/strict';
import { deviceEvidence } from '../src/device-evidence.ts';
import { integrationFixture, actor, observation } from './fixtures/integration.ts';

function input() {
    const f = integrationFixture();
    const o = observation(f.config, f.config.enrollment, f.now());
    const value = {source: 'router-policy' as const, now: f.now(), sourceObservedAt: f.now(), serviceReceivedAt: f.now(),
        personId: 'pilot', mac: f.config.person.device.mac, configuredMacs: [f.config.person.device.mac], policy: o.acceptedPolicy, status: o.status, readError: false};
    f.cleanup(); return value;
}
test('device enrollment uses both clocks with an exclusive 31-second deadline and preserves history', () => {
    const base = input();
    assert.equal(deviceEvidence(base).enrollment, 'included');
    const delayed = {...base, sourceObservedAt: base.now - 5};
    assert.equal(deviceEvidence(delayed).freshUntil, base.now + 26);
    for (const offset of [29, 30, 31]) {
        const e = deviceEvidence({...base, now: base.now + offset});
        assert.equal(e.freshness, offset <= 30 ? 'fresh' : 'stale');
        assert.equal(e.enrollment, 'included'); assert.equal(e.sourceObservedAt, base.sourceObservedAt);
    }
    const demo = deviceEvidence({...base, source: 'synthetic-policy', serviceReceivedAt: null});
    assert.equal(demo.freshness, 'fresh'); assert.equal(demo.serviceReceivedAt, null);
});
test('missing, invalid and future clocks cannot bless enrollment', () => {
    const base = input();
    for (const change of [{sourceObservedAt: null}, {serviceReceivedAt: null}, {sourceObservedAt: base.now + 1},
        {serviceReceivedAt: base.now + 1}, {now: NaN}, {sourceObservedAt: 0}, {sourceObservedAt: base.now + 0.5}, {serviceReceivedAt: Infinity}]) {
        const e = deviceEvidence({...base, ...change});
        assert.equal(e.freshness, 'unknown'); assert.equal(e.enrollment, 'unknown'); assert.equal(e.freshUntil, null);
    }
});
test('read errors, generation/revision mismatch, and conflicting memberships remain unknown', () => {
    const base = input();
    for (const change of [{readError: true}, {generationMatches: false}, {policy: null}, {status: null},
        {status: {...base.status, errors: ['read_failure']}}, {status: {...base.status, drift: true}},
        {status: {...base.status, confirmedRevision: null}}, {status: {...base.status, observed: {...base.status.observed, kids: []}}},
        {policy: {...base.policy, people: [{id: 'adult', macs: [base.mac]}]}},
        {policy: {...base.policy, people: [{id: 'pilot', macs: [base.mac, '02:10:20:30:40:51']}]}}]) {
        const e = deviceEvidence({...base, ...change}); assert.equal(e.freshness, 'unknown'); assert.equal(e.enrollment, 'unknown');
    }
    const absent = deviceEvidence({...base, policy: {...base.policy, people: []}, status: {...base.status, observed: {kids: [], paused: []}}});
    assert.equal(absent.enrollment, 'not-included'); assert.equal(absent.freshness, 'fresh');
});
test('integration projects only assignment, reads cached evidence, and never dispatches for status', async () => {
    const f = integrationFixture();
    try {
        assert.equal(f.policy.people(actor).people[0].devices[0].evidence!.freshness, 'unknown');
        await f.observe(); const calls = f.router.calls.length;
        const parent = {...actor, role: 'parent' as const};
        const get = () => f.policy.people(parent).people[0].devices[0].evidence!;
        assert.equal(get().enrollment, 'included');
        f.advance(30); assert.equal(get().freshness, 'fresh');
        f.advance(1); assert.equal(get().freshness, 'stale');
        assert.deepEqual(f.policy.people({...parent, personIds: ['adult', 'unknown']}).people, []);
        assert.deepEqual(f.policy.people({...parent, personIds: []}).people, []);
        assert.throws(() => f.policy.devices(parent), /admin_required/);
        const json = JSON.stringify(f.policy.people(parent));
        assert.ok(!json.includes(f.config.person.device.mac)); assert.ok(!json.includes(f.config.protectedMacs[0]));
        f.store.run("UPDATE integration_state SET observation_error='read_failed' WHERE singleton=1");
        assert.equal(get().enrollment, 'unknown');
        f.store.run('UPDATE integration_state SET observation_error=NULL WHERE singleton=1');
        const o = f.store.observation().value!; o.generation = 'f'.repeat(64);
        f.store.run('UPDATE service_state SET observation_json=? WHERE singleton=1', JSON.stringify(o));
        assert.equal(get().enrollment, 'unknown'); assert.equal(f.router.calls.length, calls);
    } finally {f.cleanup();}
});
