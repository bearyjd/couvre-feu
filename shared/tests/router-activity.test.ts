import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRouterActivity, normalizeRouterActivity, MAX_ACTIVITY_DEVICES } from '../src/router-activity.ts';

const device = (n = 1) => ({person: 'alex', mac: `02:00:00:00:02:${n.toString(16).padStart(2, '0')}`, ip: '192.168.8.20', neighbor: 'REACHABLE', tx_bytes: 10, rx_bytes: 20, tx_packets: 1, rx_packets: 2, blocked_packets: 0});
const sample = (over: Record<string, unknown> = {}) => ({version: 1, router_epoch: 3, counter_epoch: 7, offload: 'off', devices: [device()], errors: [], ...over});

test('accepts the exact contract and returns a fresh copy', () => {
    const input = sample(), parsed = parseRouterActivity(JSON.stringify(input));
    assert.deepEqual(parsed, input);
    assert.notEqual(normalizeRouterActivity(input).devices[0], input.devices[0]);
    assert.equal(parseRouterActivity(JSON.stringify(sample({devices: [{...device(), ip: null, neighbor: 'ABSENT'}], errors: ['conntrack_unavailable']}))).devices[0].ip, null);
});
test('rejects unknown, missing and mistyped fields at every level', () => {
    const bad = [sample({extra: 1}), sample({version: 2}), sample({offload: 'maybe'}), sample({router_epoch: -1}), sample({counter_epoch: 1.5}), sample({devices: 'x'}), sample({errors: [5]}), sample({errors: ['Bad Code']}),
        sample({devices: [{...device(), extra: 1}]}), sample({devices: [{...device(), tx_bytes: '1'}]}), sample({devices: [{...device(), neighbor: 'UP'}]}),
        sample({devices: [{...device(), ip: '256.1.1.1'}]}), sample({devices: [{...device(), ip: '1.2.3'}]}), sample({devices: [{...device(), ip: '01.2.3.4'}]}), sample({devices: [{...device(), person: 'Alex'}]})];
    for (const value of bad) assert.throws(() => normalizeRouterActivity(value));
    const {offload: _omit, ...missing} = sample();
    assert.throws(() => normalizeRouterActivity(missing));
    const {blocked_packets: _b, ...short} = device();
    assert.throws(() => normalizeRouterActivity(sample({devices: [short]})));
});
test('canonical MACs only, no duplicates, no multicast or zero address', () => {
    for (const m of ['02:00:00:00:02:AA', '02-00-00-00-02-01', '0200.0000.0201', '02:00:00:00:02', '01:00:5e:00:00:01', '00:00:00:00:00:00']) assert.throws(() => normalizeRouterActivity(sample({devices: [{...device(), mac: m}]})), m);
    assert.throws(() => normalizeRouterActivity(sample({devices: [device(1), device(1)]})));
});
test('integers are bounded to exactly representable values', () => {
    assert.equal(parseRouterActivity(JSON.stringify(sample({devices: [{...device(), tx_bytes: Number.MAX_SAFE_INTEGER}]}))).devices[0].tx_bytes, Number.MAX_SAFE_INTEGER);
    assert.throws(() => parseRouterActivity(`{"version":1,"router_epoch":9007199254740992,"counter_epoch":1,"offload":"on","devices":[],"errors":[]}`));
    assert.throws(() => parseRouterActivity(`{"version":1,"router_epoch":1e3,"counter_epoch":1,"offload":"on","devices":[],"errors":[]}`));
    assert.throws(() => parseRouterActivity(`{"version":1,"router_epoch":-0,"counter_epoch":-1,"offload":"on","devices":[],"errors":[]}`));
});
test('device count is bounded and the wire form rejects duplicates, trailing text and oversize input', () => {
    const many = (n: number) => Array.from({length: n}, (_, i) => ({...device(), mac: `02:00:00:00:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`}));
    assert.equal(parseRouterActivity(JSON.stringify(sample({devices: many(MAX_ACTIVITY_DEVICES)}))).devices.length, MAX_ACTIVITY_DEVICES);
    assert.throws(() => parseRouterActivity(JSON.stringify(sample({devices: many(MAX_ACTIVITY_DEVICES + 1)}))));
    assert.throws(() => parseRouterActivity(`{"version":1,"version":1,"router_epoch":1,"counter_epoch":1,"offload":"on","devices":[],"errors":[]}`));
    assert.throws(() => parseRouterActivity(JSON.stringify(sample()) + ' x'));
    assert.throws(() => parseRouterActivity('x'.repeat(200000)));
    assert.throws(() => parseRouterActivity(JSON.stringify(sample({errors: Array(17).fill('e')}))));
});
