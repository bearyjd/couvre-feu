import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { InventoryStore, inventoryFailureLabel, inventoryRetentionDays } from '../src/inventory-store.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import type { RouterInventory, InventoryDevice } from '../../shared/src/router-inventory.ts';
import type { Actor } from '../../shared/src/contracts.ts';

// RFC 7042 documentation MACs (globally administered) and RFC 5737 addresses; 02:... are locally administered placeholders.
const m = (n: number) => `00:00:5e:00:${(n >> 8 & 255).toString(16).padStart(2, '0')}:${(n & 255).toString(16).padStart(2, '0')}`;
const dev = (n: number, over: Partial<InventoryDevice> = {}): InventoryDevice => ({mac: m(n), ipv4: [`192.0.2.${n % 250}`], hostname: `host-${n}`, source: 'both', ...over});
const parent: Actor = {...actor, id: 'parent', role: 'parent'};
const DAY = 86400;

function world(retentionDays?: number) {
    const f = integrationFixture();
    const alerts = new ParentAlerts(f.store, null, f.now), inv = new InventoryStore(f.store, alerts, f.now, retentionDays);
    const poll = (devices: InventoryDevice[], over: Partial<RouterInventory> = {}) => inv.ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices, truncated: false, errors: [], ...over}, f.now());
    const alertRows = () => f.store.all<{count: number; details: string; state: string}>("SELECT count,details,state FROM parent_alerts WHERE kind='new_device'");
    const raised = () => alertRows().reduce((n, r) => n + r.count, 0);
    const flags = (mac: string) => inv.list(actor).devices.find(d => d.mac === mac)?.flags;
    return {...f, alerts, inv, poll, alertRows, raised, flags};
}

test('the first complete poll is a SILENT baseline; a later new MAC raises exactly one coalesced alert', () => {
    const f = world();
    try {
        f.poll([dev(1), dev(2), dev(3)]);
        assert.equal(f.raised(), 0); assert.equal(f.inv.list(actor).status.baselineAt, f.now());
        assert.deepEqual(f.inv.list(actor).devices.map(d => d.flags.new), [false, false, false]);
        f.advance(60); f.poll([dev(1), dev(2), dev(3), dev(4)]);
        assert.equal(f.raised(), 1); assert.deepEqual(JSON.parse(f.alertRows()[0].details), {count: 1});
        assert.equal(f.flags(m(4))!.new, true); assert.equal(f.flags(m(1))!.new, false);
        f.advance(60); f.poll([dev(1), dev(2), dev(3), dev(4)]);
        assert.equal(f.raised(), 1, 'a device is alerted once');
    } finally { f.cleanup(); }
});
test('several new devices in one poll are ONE alert carrying a count only', () => {
    const f = world();
    try {
        f.poll([dev(1)]); f.advance(60); f.poll([dev(1), dev(2), dev(3), dev(4)]);
        assert.equal(f.raised(), 1); assert.deepEqual(JSON.parse(f.alertRows()[0].details), {count: 3});
    } finally { f.cleanup(); }
});
test('acknowledging clears New for that device only, records the admin, and is idempotent', () => {
    const f = world();
    try {
        f.poll([dev(1)]); f.advance(60); f.poll([dev(1), dev(2), dev(3)]);
        assert.equal(f.inv.acknowledge(actor, m(2)).flags.new, false);
        assert.equal(f.flags(m(3))!.new, true);
        assert.equal(f.store.get<{by: string}>('SELECT acknowledged_by by FROM inventory_devices WHERE mac=?', m(2))!.by, 'operator');
        f.advance(5); f.inv.acknowledge(actor, m(2));
        assert.equal(f.store.get<{at: number}>('SELECT acknowledged_at at FROM inventory_devices WHERE mac=?', m(2))!.at, f.now() - 5, 'idempotent: first acknowledgement stands');
        assert.throws(() => f.inv.acknowledge(actor, m(99)), (e: {code?: string; status?: number}) => e.status === 404 && e.code === 'inventory_device_not_found');
        for (const bad of ['', 'zz', m(2).toUpperCase(), m(2).replaceAll(':', '-'), `${m(2)} `]) assert.throws(() => f.inv.acknowledge(actor, bad), (e: {status?: number}) => e.status === 400, bad);
        assert.throws(() => f.inv.acknowledge(parent, m(3)), (e: {status?: number}) => e.status === 403);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM audit WHERE action='inventory_acknowledge'")!.n, 1);
    } finally { f.cleanup(); }
});
test('a TRUNCATED poll never baselines: truncated subset, then complete superset gives zero alerts and baseline = the second poll', () => {
    const f = world();
    try {
        f.poll([dev(1), dev(2)], {truncated: true});
        assert.equal(f.inv.list(actor).status.baselineAt, null); assert.equal(f.inv.list(actor).devices.length, 0, 'an incomplete poll stores no new device');
        f.advance(60); f.poll([dev(1), dev(2), dev(3), dev(4)]);
        assert.equal(f.raised(), 0); assert.equal(f.inv.list(actor).status.baselineAt, f.now());
        assert.deepEqual(f.inv.list(actor).devices.map(d => d.flags.new), [false, false, false, false]);
    } finally { f.cleanup(); }
});
test('a poll with errors never baselines or alerts, and records the incomplete state', () => {
    const f = world();
    try {
        f.poll([dev(1)], {errors: ['inventory_unreadable'], routerTime: 0});
        assert.equal(f.inv.list(actor).status.baselineAt, null); assert.equal(f.inv.list(actor).status.lastError, 'inventory_incomplete:inventory_unreadable');
        f.poll([], {errors: ['inventory_refused']}); assert.equal(f.inv.list(actor).status.lastOkAt, null);
    } finally { f.cleanup(); }
});
test('a truncated reply never implies gone or New: absent devices stay, unseen ones are not stored, a later complete poll alerts once', () => {
    const f = world();
    try {
        f.poll([dev(1), dev(2), dev(3)]); f.advance(60);
        f.poll([dev(1), dev(9)], {truncated: true});
        const list = f.inv.list(actor).devices;
        assert.deepEqual(list.map(d => d.mac).sort(), [m(1), m(2), m(3)], 'nothing removed, the unseen MAC not stored');
        assert.ok(list.every(d => !d.flags.new)); assert.equal(f.raised(), 0);
        assert.equal(f.store.get<{last_seen: number}>('SELECT last_seen FROM inventory_devices WHERE mac=?', m(1))!.last_seen, f.now(), 'a listed known device still refreshes');
        f.advance(60); f.poll([dev(1), dev(2), dev(3), dev(9)]);
        assert.equal(f.raised(), 1); assert.equal(f.flags(m(9))!.new, true);
    } finally { f.cleanup(); }
});
test('last_seen advances only for neigh/both; lease-only refreshes addresses and name but not presence', () => {
    const f = world();
    try {
        f.poll([dev(1, {source: 'neigh'}), dev(2, {source: 'lease'})]); const t0 = f.now();
        f.advance(120); f.poll([dev(1, {source: 'lease', ipv4: ['192.0.2.77']}), dev(2, {source: 'lease', hostname: 'renamed'})]);
        const row = (n: number) => f.store.get<{last_seen: number; ipv4_json: string; hostname: string; source: string}>('SELECT last_seen,ipv4_json,hostname,source FROM inventory_devices WHERE mac=?', m(n))!;
        assert.equal(row(1).last_seen, t0); assert.equal(row(2).last_seen, t0); assert.equal(row(1).ipv4_json, '["192.0.2.77"]'); assert.equal(row(2).hostname, 'renamed');
        f.advance(60); f.poll([dev(1, {source: 'both'}), dev(2, {source: 'lease'})]);
        assert.equal(row(1).last_seen, f.now()); assert.equal(row(2).last_seen, t0);
    } finally { f.cleanup(); }
});
test('alert coalescing: at most 1 per hour, at most 12 per day, and a suppressed device alerts on a later poll', () => {
    const f = world();
    try {
        f.poll([dev(1)]); let n = 2;
        const next = (minutes: number) => { f.advance(minutes * 60); const all = Array.from({length: n}, (_, i) => dev(i + 1)); n++; f.poll(all); };
        next(1); assert.equal(f.raised(), 1);
        next(30); assert.equal(f.raised(), 1, 'within the hour: suppressed');
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices WHERE alerted_at IS NULL AND first_seen > (SELECT baseline_at FROM inventory_state)')!.n, 1);
        next(31); assert.equal(f.raised(), 2, 'an hour after the first: the suppressed device is now covered');
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices WHERE alerted_at IS NULL AND first_seen > (SELECT baseline_at FROM inventory_state)')!.n, 0);
        for (let i = 0; i < 20; i++) next(61);
        assert.equal(f.store.get<{n: number}>('SELECT alert_day_count n FROM inventory_state')!.n, 12, 'the daily cap holds: no more than 12 alert events');
        assert.equal(f.raised(), 22, 'past the cap the existing alert row only counts the occurrence (SL-2)');
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices WHERE alerted_at IS NULL AND first_seen > (SELECT baseline_at FROM inventory_state)')!.n, 0, 'capped devices are consumed, not re-counted');
        f.advance(DAY); next(1); assert.equal(f.raised(), 23, 'the next day alerts normally again');
    } finally { f.cleanup(); }
});
test('re-baseline over an existing baseline (emptied store, or last_ok_at older than the retention) is a counted alert, never silent (SM-1b)', () => {
    const f = world();
    try {
        f.poll([dev(1)]); f.advance(60); f.store.run('DELETE FROM inventory_devices');
        f.poll([dev(1), dev(2)]); assert.equal(f.raised(), 1); assert.equal(f.inv.list(actor).status.baselineAt, f.now());
        assert.deepEqual(JSON.parse(f.alertRows()[0].details), {count: 2, rebaselined: true});
        f.advance(31 * DAY); f.poll([dev(1), dev(2), dev(3)]);
        assert.equal(f.raised(), 2, 'last_ok_at older than 30 days: counted'); assert.equal(f.inv.list(actor).status.baselineAt, f.now());
        assert.deepEqual(f.inv.list(actor).devices.map(d => d.flags.new), [false, false, false], 'accepted devices are not New');
        f.advance(60); f.poll([dev(1), dev(2), dev(3), dev(4)]); assert.equal(f.raised(), 3);
    } finally { f.cleanup(); }
});
test('retention: default 30 days, configurable up to 90; stale rows are pruned', () => {
    assert.equal(inventoryRetentionDays({}), 30); assert.equal(inventoryRetentionDays({CF_INVENTORY_RETENTION_DAYS: '90'}), 90); assert.equal(inventoryRetentionDays({CF_INVENTORY_RETENTION_DAYS: '1'}), 1);
    for (const bad of ['0', '91', '365', '-1', '1.5', 'x', '030', '']) assert.throws(() => inventoryRetentionDays({CF_INVENTORY_RETENTION_DAYS: bad}), /invalid_inventory_retention_days/, bad);
    const f = integrationFixture();
    try {
        for (const bad of [0, 91, 1.5]) assert.throws(() => new InventoryStore(f.store, new ParentAlerts(f.store, null, f.now), f.now, bad), /invalid_inventory_retention_days/);
    } finally { f.cleanup(); }
    const w = world(7);
    try {
        w.poll([dev(1), dev(2)]); w.advance(6 * DAY); w.poll([dev(1)]); w.advance(2 * DAY); w.poll([dev(1)]);
        assert.deepEqual(w.inv.list(actor).devices.map(d => d.mac), [m(1)], 'device 2 unseen for 8 days is pruned');
        w.advance(DAY); w.inv.prune();
    } finally { w.cleanup(); }
});
test('rotation is never merged, transferred or used to suppress: a new MAC with the old hostname is New and alerts; hostnames reach no alert or audit row', () => {
    const f = world();
    try {
        f.poll([dev(1, {hostname: 'secretname'})]); f.advance(60);
        f.poll([dev(1, {hostname: 'secretname'}), dev(2, {hostname: 'secretname'})]);
        assert.equal(f.flags(m(2))!.new, true); assert.equal(f.raised(), 1); assert.equal(f.inv.list(actor).devices.length, 2);
        f.inv.acknowledge(actor, m(2));
        f.advance(3600); f.poll([dev(2, {hostname: 'secretname'}), dev(3, {hostname: 'secretname'})]);
        assert.equal(f.flags(m(3))!.new, true, 'acknowledging one MAC does not cover a rotated one'); assert.equal(f.raised(), 2);
        const dump = JSON.stringify([f.store.all('SELECT * FROM parent_alerts'), f.store.all('SELECT * FROM audit'), f.store.all('SELECT * FROM inventory_state')]);
        assert.ok(!dump.includes('secretname'));
    } finally { f.cleanup(); }
});
test('the list: Private-address and Unassigned flags (against current assignments), reportedByDevice hostnames, protected MACs never shown', () => {
    const f = world();
    try {
        const assigned = f.config.person.device.mac, priv = '02:00:00:00:00:09', protectedMac = f.config.protectedMacs[0];
        const devices = [dev(5), {mac: assigned, ipv4: ['192.0.2.50'], hostname: null, source: 'neigh' as const}, {mac: priv, ipv4: [], hostname: 'phone', source: 'lease' as const}].sort((a, b) => a.mac < b.mac ? -1 : 1);
        f.poll(devices);
        f.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'both',1,1)", f.config.router.generation, protectedMac);
        const byMac = new Map(f.inv.list(actor).devices.map(d => [d.mac, d]));
        assert.equal(byMac.has(protectedMac), false); assert.equal(byMac.size, 3);
        assert.deepEqual(byMac.get(assigned)!.flags, {new: false, private: true, unassigned: false}, 'assigned, and 02:... has the locally-administered bit');
        assert.deepEqual(byMac.get(priv)!.flags, {new: false, private: true, unassigned: true});
        assert.deepEqual(byMac.get(m(5))!.flags, {new: false, private: false, unassigned: true});
        assert.equal(byMac.get(priv)!.reportedByDevice, true); assert.equal(byMac.get(priv)!.hostname, 'phone'); assert.equal(byMac.get(assigned)!.hostname, null);
        // A device row assigned through the children admin also counts as assigned.
        f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d9','pilot','Laptop','mac',?,'enrolling',1)", priv);
        assert.equal(f.flags(priv)!.unassigned, false);
        assert.throws(() => f.inv.list(parent), (e: {status?: number}) => e.status === 403);
    } finally { f.cleanup(); }
});
test('the 1024-row cap evicts the longest-unseen rows instead of failing the poll', () => {
    const f = world();
    try {
        const batch = (from: number) => Array.from({length: 200}, (_, i) => dev(from + i, {ipv4: []}));
        for (let k = 0; k < 6; k++) { f.poll(batch(1 + k * 200)); f.advance(60); }
        const n = f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices')!.n;
        assert.equal(n, 1024);
        assert.ok(f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices WHERE mac=?', m(1200))!.n === 1);
        assert.ok(f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices WHERE mac=?', m(1))!.n === 0, 'the oldest was evicted');
    } finally { f.cleanup(); }
});
test('refresh: sets refresh_requested_at only, 1 per 10 s across admins, 409 when dispatch is off, parents refused', () => {
    const off = world();
    try { assert.throws(() => off.inv.requestRefresh(actor), (e: {status?: number; code?: string}) => e.status === 409 && e.code === 'inventory_dispatch_disabled'); } finally { off.cleanup(); }
    const f = world(); f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8}; const automatic = new AutomaticDispatch(f.worker);
    try {
        f.store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('admin2','Second','admin','[]','u2')");
        f.inv.recordAttempt(f.now()); f.advance(1);
        assert.equal(f.inv.due(), false);
        f.inv.requestRefresh(actor);
        const st = () => f.store.get<{refresh_requested_at: number; last_attempt_at: number; last_ok_at: number | null}>('SELECT refresh_requested_at,last_attempt_at,last_ok_at FROM inventory_state')!;
        assert.equal(st().refresh_requested_at, f.now()); assert.equal(f.inv.due(), true, 'a requested refresh makes the next cycle poll');
        f.advance(9); assert.throws(() => f.inv.requestRefresh({...actor, id: 'admin2'}), (e: {status?: number; code?: string}) => e.status === 429 && e.code === 'inventory_refresh_rate_limited');
        f.advance(1); f.inv.requestRefresh({...actor, id: 'admin2'});
        assert.throws(() => f.inv.requestRefresh(parent), (e: {status?: number}) => e.status === 403);
        assert.equal(f.router.calls.length, 0, 'refresh never opens SSH'); assert.equal(st().last_ok_at, null);
        f.inv.recordAttempt(f.now()); assert.equal(f.inv.due(), false, 'the attempt consumes the request');
        f.advance(60); assert.equal(f.inv.due(), true, 'cadence: every 60 s');
    } finally { void automatic.stop(); f.cleanup(); }
});
test('generation change (rebind) starts a fresh silent baseline; other generations stay out of the list', () => {
    const f = world();
    try {
        f.poll([dev(1)]);
        (f.config.router as {generation: string}).generation = 'c'.repeat(64);
        f.advance(60); f.inv.ingest({inventory_version: 1, generation: 'c'.repeat(64), routerTime: f.now(), devices: [dev(1), dev(2)], truncated: false, errors: []}, f.now());
        assert.equal(f.raised(), 0); assert.equal(f.inv.list(actor).devices.length, 2);
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices')!.n, 3);
    } finally { f.cleanup(); }
});
test('failure labels: reply problems keep inventory_unavailable:<code>; ssh 255 stays distinct; nothing touches observation_error', () => {
    assert.equal(inventoryFailureLabel('inventory_unavailable:old_router'), 'inventory_unavailable:old_router');
    assert.equal(inventoryFailureLabel('ssh_timeout'), 'inventory_unavailable:ssh_timeout');
    assert.equal(inventoryFailureLabel('ssh_exit_255'), 'inventory_transport_error:ssh_exit_255');
    const f = world();
    try {
        f.inv.recordFailure('inventory_unavailable:old_router');
        assert.equal(f.inv.list(actor).status.lastError, 'inventory_unavailable:old_router');
        assert.equal(f.store.integrationState().observation_error, null);
        f.poll([dev(1)]); assert.equal(f.inv.list(actor).status.lastError, null, 'a complete poll clears the error');
    } finally { f.cleanup(); }
});
