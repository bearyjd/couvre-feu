import test from 'node:test';
import assert from 'node:assert/strict';

const model = await import(new URL('../../web/public/kids-model.js', import.meta.url).href);
const row = (over: Record<string, unknown>) => ({ hostname: 'pixel-jack', mac: '02:aa:00:00:00:01', presence: 'online', personName: null, flags: { unassigned: true, private: true }, ...over });

test('status: a queued change is "sent" until the router confirms; unknown and missing are their own words', () => {
    assert.equal(model.deviceStatus({ state: 'enrolling', onRouter: false }), 'sent');
    assert.equal(model.deviceStatus({ state: 'removing', onRouter: true }), 'sent');
    assert.equal(model.deviceStatus({ state: 'moving', onRouter: true }), 'sent');
    assert.equal(model.deviceStatus({ state: 'active', onRouter: true }), 'on_router');
    assert.equal(model.deviceStatus({ state: 'active', onRouter: false }), 'missing');
    assert.equal(model.deviceStatus({ state: 'active', onRouter: null }), 'unknown');
});

test('ageText never prints a negative or unknown age', () => {
    assert.equal(model.ageText(10), 'just now');
    assert.equal(model.ageText(600), '10 min ago');
    assert.equal(model.ageText(7200), '2 h ago');
    assert.equal(model.ageText(3 * 86400), '3 d ago');
    assert.equal(model.ageText(Number.NaN), 'just now');
});

test('replacedMacs: a quiet enrolled device and exactly one active private new row with the same name', () => {
    const old = row({ mac: '02:aa:00:00:00:02', presence: 'quiet', personName: 'Jack', flags: { unassigned: false, private: true } });
    assert.deepEqual([...model.replacedMacs([old, row({})])], ['02:aa:00:00:00:02']);
    assert.deepEqual([...model.replacedMacs([old, row({ hostname: 'PIXEL-JACK' })])], ['02:aa:00:00:00:02'], 'case-insensitive');
    assert.deepEqual([...model.replacedMacs([old])], [], 'no candidate');
    assert.deepEqual([...model.replacedMacs([old, row({}), row({ mac: '02:aa:00:00:00:03' })])], [], 'two candidates are ambiguous');
    assert.deepEqual([...model.replacedMacs([old, row({ presence: 'quiet' })])], [], 'the new row must be active');
    assert.deepEqual([...model.replacedMacs([{ ...old, presence: 'online' }, row({})])], [], 'the old one must be quiet');
    assert.deepEqual([...model.replacedMacs([{ ...old, hostname: 'android' }, row({ hostname: 'android' })])], [], 'generic names say nothing');
    assert.deepEqual([...model.replacedMacs([old, row({ flags: { unassigned: true, private: false } })])], [], 'a fixed address does not rotate');
});
