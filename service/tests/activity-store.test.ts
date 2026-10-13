import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db.ts';
import { INITIAL_POLICY, seedAccounts } from '../src/fixtures.ts';
import { ActivityStore, retentionDays, DEFAULT_RETENTION_DAYS, MAX_SAMPLE_INTERVAL_SECONDS } from '../src/activity-store.ts';
import { ACTIVE_MINUTE_THRESHOLD_BYTES } from '../src/activity-report.ts';
import { normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { FakeRouter } from '../../demo-router/src/router.ts';
import { normalizeRouterActivity } from '../../shared/src/router-activity.ts';

const ALEX = '02:00:00:00:02:01', BLAIR = '02:00:00:00:02:02', STRANGER = '02:00:00:00:09:09';
const DAY = Math.floor(1791691200 / 86400) * 86400, NOON = DAY + 12 * 3600;
const bryn: Actor = {id: 'bryn', displayName: 'Bryn', role: 'parent', personIds: ['alex'], permissionVersion: '1'};
const poll = (devices: {person: string; mac: string; tx?: number; rx?: number; blocked?: number}[], over: Record<string, unknown> = {}) => ({
    version: 1, router_epoch: 1, counter_epoch: 1, offload: 'off', errors: [], ...over,
    devices: devices.map(d => ({person: d.person, mac: d.mac, ip: null, neighbor: 'REACHABLE', tx_bytes: d.tx ?? 0, rx_bytes: d.rx ?? 0, tx_packets: 0, rx_packets: 0, blocked_packets: d.blocked ?? 0}))});
function fixture(retention?: number) {
    const store = new Store(':memory:'); seedAccounts(store);
    let clock = NOON + 1200;
    const activity = new ActivityStore(store, {retentionDays: retention, now: () => clock});
    return {store, activity, at: (t: number) => { clock = t; }};
}
const samples = (store: Store) => store.all<Record<string, number | string | null>>('SELECT * FROM activity_samples ORDER BY mac,sampled_at');

test('deltas come from consecutive counters; the first sample is only a baseline', () => {
    const f = fixture();
    f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 1000, rx: 9000, blocked: 4}]), NOON);
    f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 21000, rx: 59000, blocked: 9}]), NOON + 30);
    const [first, second] = samples(f.store);
    assert.deepEqual([first.delta_state, first.delta_bytes], ['baseline', null]);
    assert.deepEqual([second.delta_state, second.interval_seconds, second.delta_bytes, second.delta_blocked], ['valid', 30, 70000, 5]);
});
test('counter_epoch change, router_epoch change or any decrease is a reset with no negative delta', () => {
    const f = fixture();
    let t = NOON;
    const send = (over: Record<string, unknown>, tx: number, blocked = 0) => f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx, blocked}], over), t += 30);
    send({}, 5000);
    send({}, 9000);
    send({counter_epoch: 2}, 100);
    send({counter_epoch: 2}, 700);
    send({counter_epoch: 2}, 600);
    send({counter_epoch: 2}, 900, 0);
    send({counter_epoch: 2, router_epoch: 2}, 1200);
    send({counter_epoch: 2, router_epoch: 2}, 1500, 3);
    send({counter_epoch: 2, router_epoch: 2}, 1600, 1);
    const rows = samples(f.store);
    assert.deepEqual(rows.map(r => r.delta_state), ['baseline', 'valid', 'reset', 'valid', 'reset', 'valid', 'reset', 'valid', 'reset']);
    assert.ok(rows.every(r => r.delta_bytes === null || (r.delta_bytes as number) >= 0 && (r.delta_blocked as number) >= 0));
    assert.deepEqual(rows.filter(r => r.delta_state === 'valid').map(r => r.delta_bytes), [4000, 600, 300, 300]);
});
test('long spacing between samples is a gap, and old or duplicate sample times are dropped', () => {
    const f = fixture();
    f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 1}]), NOON);
    f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 2}]), NOON + MAX_SAMPLE_INTERVAL_SECONDS + 1);
    f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 3}]), NOON + MAX_SAMPLE_INTERVAL_SECONDS + 31);
    assert.deepEqual(samples(f.store).map(r => r.delta_state), ['baseline', 'gap', 'valid']);
    assert.equal(f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 4}]), NOON + MAX_SAMPLE_INTERVAL_SECONDS + 31).dropped, 1);
    assert.equal(f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 4}]), NOON).dropped, 1);
    assert.equal(samples(f.store).length, 3);
    assert.throws(() => f.activity.ingest(poll([]), 5), /invalid_sample_time/);
});
test('only devices assigned to a child in the current policy are stored; others are dropped before any write', () => {
    const f = fixture();
    const result = f.activity.ingest(poll([{person: 'alex', mac: ALEX}, {person: 'alex', mac: STRANGER}, {person: 'parent', mac: '02:00:00:00:09:08'}, {person: 'blair', mac: BLAIR}]), NOON);
    assert.deepEqual([result.stored, result.dropped], [2, 2]);
    // A MAC enrolled for one child is refused when the router attributes it to another person.
    assert.equal(f.activity.ingest(poll([{person: 'blair', mac: ALEX}]), NOON + 30).dropped, 1);
    assert.deepEqual(samples(f.store).map(r => [r.person_id, r.mac]), [['alex', ALEX], ['blair', BLAIR]]);
    // Unenrolling a device stops storage immediately.
    const policy = normalizePolicy({...INITIAL_POLICY, people: [{id: 'alex', macs: []}, {id: 'blair', macs: [BLAIR]}]});
    f.store.run('UPDATE service_state SET desired_json=? WHERE singleton=1', policyJSON(policy));
    assert.equal(f.activity.ingest(poll([{person: 'alex', mac: ALEX}]), NOON + 30).stored, 0);
});
test('a poll that reports router errors, or violates the contract, stores nothing', () => {
    const f = fixture();
    assert.deepEqual(f.activity.ingest(poll([{person: 'alex', mac: ALEX}], {errors: ['conntrack_unavailable']}), NOON), {stored: 0, dropped: 1, skipped: 'router_reported_errors'});
    assert.throws(() => f.activity.ingest({...poll([{person: 'alex', mac: ALEX}]), extra: true}, NOON));
    assert.throws(() => f.activity.ingest(poll([{person: 'alex', mac: ALEX}], {offload: 'maybe'}), NOON));
    assert.equal(samples(f.store).length, 0);
});
test('retention prunes only expired samples and is configurable and bounded', () => {
    const f = fixture();
    assert.equal(f.activity.retentionDays, DEFAULT_RETENTION_DAYS);
    const now = NOON + 1200, old = now - 30 * 86400 - 1, edge = now - 30 * 86400;
    f.activity.ingest(poll([{person: 'alex', mac: ALEX}]), old);
    f.activity.ingest(poll([{person: 'alex', mac: ALEX}]), edge);
    f.activity.ingest(poll([{person: 'alex', mac: ALEX}]), now);
    assert.equal(f.activity.prune(now), 1);
    assert.deepEqual(samples(f.store).map(r => r.sampled_at), [edge, now]);
    const short = fixture(2);
    for (const age of [3 * 86400, 2 * 86400 + 60, 86400]) short.activity.ingest(poll([{person: 'alex', mac: ALEX}]), NOON + 1200 - age);
    assert.equal(short.activity.prune(), 2);
    assert.equal(short.activity.report(bryn, 'alex').retentionDays, 2);
    for (const bad of [0, 366, 1.5]) assert.throws(() => new ActivityStore(f.store, {retentionDays: bad}), /invalid_activity_retention_days/);
    assert.equal(retentionDays({}), 30);
    assert.equal(retentionDays({CF_ACTIVITY_RETENTION_DAYS: '7'}), 7);
    for (const bad of ['0', '366', '1e1', '', 'x']) assert.throws(() => retentionDays({CF_ACTIVITY_RETENTION_DAYS: bad}), /invalid_activity_retention_days/);
});
// 30 second polls. Poll k reports the interval ending at start+30k; it belongs to minute (k-1)>>1. Missing minutes have no polls.
function feedMinutes(f: ReturnType<typeof fixture>, plan: ('quiet' | 'busy' | 'missing')[], opts: {mac?: string; person?: string; offload?: string; blockedEach?: number; start?: number} = {}) {
    let tx = 0, blocked = 0;
    const start = opts.start ?? NOON, mac = opts.mac ?? ALEX, person = opts.person ?? 'alex', offload = opts.offload ?? 'off';
    f.activity.ingest(poll([{person, mac, tx, blocked}], {offload}), start);
    for (let k = 1; k <= plan.length * 2; k++) {
        const kind = plan[(k - 1) >> 1];
        tx += kind === 'busy' ? 200000 : 2000; blocked += opts.blockedEach ?? 0;
        if (kind !== 'missing') f.activity.ingest(poll([{person, mac, tx, blocked}], {offload}), start + 30 * k);
    }
}
test('online minutes count covered minutes above the byte threshold; missing minutes are unknown, never zero', () => {
    const f = fixture();
    feedMinutes(f, ['quiet', 'busy', 'busy', 'missing', 'missing', 'quiet', 'busy', 'quiet']);
    const day = f.activity.report(bryn, 'alex').days.at(-1)!;
    assert.equal(day.date, new Date(DAY * 1000).toISOString().slice(0, 10));
    assert.equal(day.expectedMinutes, (NOON + 1200 - DAY) / 60);
    // Minutes 3 and 4 have no samples. Minute 5 follows a gap, so only its second half is observed (exactly the 30 s minimum).
    assert.equal(day.coveredMinutes, 6);
    assert.equal(day.estimatedOnlineMinutes, 3);
    assert.equal(day.unknownMinutes, day.expectedMinutes - 6);
    assert.equal(day.coverage, 'partial');
    assert.ok(day.gaps.some(g => g.start === NOON + 3 * 60 && g.end === NOON + 5 * 60));
    assert.equal(day.totalBytes, 1210000);
    assert.ok(2000 * 2 < ACTIVE_MINUTE_THRESHOLD_BYTES && 400000 > ACTIVE_MINUTE_THRESHOLD_BYTES);
});
test('days without any sample are unknown (null), not zero, and cover the last eight UTC days', () => {
    const f = fixture();
    const report = f.activity.report(bryn, 'alex');
    assert.equal(report.days.length, 8);
    assert.equal(report.disclaimer, 'Estimated network activity — not app use, websites or screen time');
    for (const day of report.days) assert.deepEqual([day.coverage, day.coveredMinutes, day.estimatedOnlineMinutes, day.totalBytes, day.blockedAttempts, day.offload, day.possiblyUndercounted], ['none', 0, null, null, null, null, false]);
    assert.equal(report.days[0].start, DAY - 7 * 86400);
    // Samples that are only baselines or resets still do not make a day known.
    f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 10}]), NOON);
    f.activity.ingest(poll([{person: 'alex', mac: ALEX, tx: 1}], {counter_epoch: 2}), NOON + 30);
    assert.equal(f.activity.report(bryn, 'alex').days.at(-1)!.estimatedOnlineMinutes, null);
});
test('blocked attempts come from blocked_packets deltas and survive a reset without going negative', () => {
    const f = fixture();
    feedMinutes(f, ['quiet', 'quiet', 'quiet'], {blockedEach: 2});
    assert.equal(f.activity.report(bryn, 'alex').days.at(-1)!.blockedAttempts, 6 * 2);
    f.activity.ingest(poll([{person: 'alex', mac: ALEX, blocked: 0}], {counter_epoch: 9}), NOON + 600);
    assert.equal(f.activity.report(bryn, 'alex').days.at(-1)!.blockedAttempts, 12);
});
test('offload on or unknown marks a day possibly undercounted; off does not', () => {
    for (const [offload, flagged] of [['off', false], ['on', true], ['unknown', true]] as const) {
        const f = fixture();
        feedMinutes(f, ['busy', 'busy'], {offload});
        const day = f.activity.report(bryn, 'alex').days.at(-1)!;
        assert.deepEqual([day.offload, day.possiblyUndercounted], [offload, flagged]);
    }
});
test('a minute is covered only when every assigned device is covered', () => {
    const f = fixture();
    const policy = normalizePolicy({...INITIAL_POLICY, people: [{id: 'alex', macs: [ALEX, '02:00:00:00:02:03']}, {id: 'blair', macs: [BLAIR]}]});
    f.store.run('UPDATE service_state SET desired_json=? WHERE singleton=1', policyJSON(policy));
    feedMinutes(f, ['busy', 'busy', 'busy']);
    assert.equal(f.activity.report(bryn, 'alex').days.at(-1)!.coveredMinutes, 0);
    feedMinutes(f, ['quiet', 'quiet', 'quiet'], {mac: '02:00:00:00:02:03'});
    const day = f.activity.report(bryn, 'alex').days.at(-1)!;
    assert.equal(day.coveredMinutes, 3);
    assert.equal(day.estimatedOnlineMinutes, 3);
});
test('reports are limited to assigned people who are enrolled children in the current policy', () => {
    const f = fixture();
    feedMinutes(f, ['busy'], {person: 'blair', mac: BLAIR});
    assert.equal(f.activity.report(bryn, 'alex').personId, 'alex');
    for (const person of ['blair', 'nobody', 'Alex', '']) assert.throws(() => f.activity.report(bryn, person), /person_not_found/);
    assert.throws(() => f.activity.report({...bryn, personIds: ['alex', 'ghost']}, 'ghost'), /person_not_found/);
    // Blair's samples never leak into Alex's report.
    assert.equal(f.activity.report(bryn, 'alex').days.at(-1)!.totalBytes, null);
    const admin: Actor = {...bryn, id: 'jd', role: 'admin', personIds: ['alex', 'blair']};
    assert.ok(f.activity.report(admin, 'blair').days.at(-1)!.totalBytes! > 0);
});
test('the fictional demo router emits contract-valid, monotonic counters that ingest end to end and reset weekly', () => {
    const clock = {t: NOON}, router = new FakeRouter(':memory:', {now: () => clock.t}), f = fixture();
    for (let k = 0; k <= 40; k++) {
        clock.t = NOON + 60 * k;
        const a = normalizeRouterActivity(router.activity());
        assert.deepEqual(a.devices.map(d => d.mac).sort(), [ALEX, BLAIR]);
        assert.equal(f.activity.ingest(a, clock.t).stored, 2);
    }
    f.at(NOON + 2400);
    const day = f.activity.report(bryn, 'alex').days.at(-1)!;
    assert.ok(day.coveredMinutes >= 39 && day.totalBytes! > 0 && day.estimatedOnlineMinutes !== null);
    assert.deepEqual(new Set(samples(f.store).map(r => r.delta_state)), new Set(['baseline', 'valid']));
    // Counters never decrease within a counter epoch and restart in the next one.
    const boundary = Math.ceil(NOON / 604800) * 604800, before = (clock.t = boundary - 60, router.activity()), after = (clock.t = boundary + 60, router.activity());
    assert.equal(after.counter_epoch, before.counter_epoch + 1);
    assert.ok(after.devices[0].tx_bytes < before.devices[0].tx_bytes);
    f.activity.ingest(before, boundary - 60); f.activity.ingest(after, boundary);
    assert.equal(samples(f.store).at(-1)!.delta_state, 'reset');
});
test('samples of a MAC or person that stops being an assigned child are deleted promptly, on ingest, report and prune', () => {
    const setPolicy = (f: ReturnType<typeof fixture>, people: {id: string; macs: string[]}[]) => f.store.run('UPDATE service_state SET desired_json=? WHERE singleton=1', policyJSON(normalizePolicy({...INITIAL_POLICY, people, schedules: []})));
    const seed = (f: ReturnType<typeof fixture>) => { f.activity.ingest(poll([{person: 'alex', mac: ALEX}, {person: 'blair', mac: BLAIR}]), NOON); f.activity.ingest(poll([{person: 'alex', mac: ALEX}, {person: 'blair', mac: BLAIR}]), NOON + 30); };
    const macs = (f: ReturnType<typeof fixture>) => [...new Set(samples(f.store).map(r => r.mac))];
    // MAC removed from a person: removed on the next ingest of another device.
    let f = fixture(); seed(f);
    setPolicy(f, [{id: 'alex', macs: []}, {id: 'blair', macs: [BLAIR]}]);
    f.activity.ingest(poll([{person: 'blair', mac: BLAIR}]), NOON + 60);
    assert.deepEqual(macs(f), [BLAIR]);
    // Person removed entirely: removed by report (read) and by the prune job.
    f = fixture(); seed(f);
    setPolicy(f, [{id: 'alex', macs: [ALEX]}]);
    f.activity.report(bryn, 'alex');
    assert.deepEqual(macs(f), [ALEX]);
    f = fixture(); seed(f);
    setPolicy(f, [{id: 'blair', macs: [BLAIR]}]);
    assert.equal(f.activity.prune(), 0);
    assert.deepEqual(macs(f), [BLAIR]);
    // A MAC moved to another person no longer keeps the old person's history.
    f = fixture(); seed(f);
    setPolicy(f, [{id: 'alex', macs: []}, {id: 'blair', macs: [ALEX, BLAIR]}]);
    assert.equal(f.activity.purgeUnenrolled(), 2);
    assert.deepEqual(samples(f.store).map(r => [r.person_id, r.mac]), [['blair', BLAIR], ['blair', BLAIR]]);
});
