import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { InventoryStore, INVENTORY_ROW_CAP } from '../src/inventory-store.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import type { RouterInventory, InventoryDevice } from '../../shared/src/router-inventory.ts';

// RFC 7042 documentation MACs (globally administered) and RFC 5737 addresses.
const m = (n: number) => `00:00:5e:00:${(n >> 8 & 255).toString(16).padStart(2, '0')}:${(n & 255).toString(16).padStart(2, '0')}`;
const dev = (n: number, over: Partial<InventoryDevice> = {}): InventoryDevice => ({mac: m(n), ipv4: [`192.0.2.${n % 250}`], hostname: `host-${n}`, source: 'both', ...over});
const range = (from: number, to: number) => Array.from({length: to - from + 1}, (_, i) => dev(from + i));
const DAY = 86400, HOUR = 3600;

function world(retentionDays?: number) {
    const f = integrationFixture();
    const alerts = new ParentAlerts(f.store, null, f.now), inv = new InventoryStore(f.store, alerts, f.now, retentionDays);
    const poll = (devices: InventoryDevice[], over: Partial<RouterInventory> = {}) => inv.ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices, truncated: false, errors: [], ...over}, f.now());
    const rows = (kind: string) => f.store.all<{id: number; count: number; details: string; state: string}>('SELECT id,count,details,state FROM parent_alerts WHERE kind=? ORDER BY id', kind);
    const has = (n: number) => Boolean(f.store.get('SELECT mac FROM inventory_devices WHERE mac=?', m(n)));
    const lastError = () => inv.list(actor).status.lastError;
    return {...f, alerts, inv, poll, rows, has, lastError};
}

// ---- SM-1 ----
test('SM-1a: no complete poll for 30 minutes raises ONE inventory_stalled alert (counts only), at most once per 6 hours', () => {
    const f = world();
    try {
        f.poll([dev(1)]);
        let t = 0;
        for (; t < 1800 - 60; t += 60) { f.advance(60); f.poll([dev(1)], {truncated: true}); }
        assert.equal(f.rows('inventory_stalled').length, 0, 'not before 30 minutes');
        f.advance(60); t += 60; f.poll([dev(1)], {truncated: true});
        assert.equal(f.rows('inventory_stalled').length, 1); assert.equal(f.rows('inventory_stalled')[0].count, 1);
        assert.doesNotMatch(f.rows('inventory_stalled')[0].details, /00:00:5e|192\.0\.2|host-/, 'counts only');
        for (; t < 6 * HOUR - 60; t += 60) { f.advance(60); f.poll([dev(1)], {truncated: true}); }
        assert.equal(f.rows('inventory_stalled')[0].count, 1, 'rate limited to once per 6 h');
        f.advance(1900); f.poll([dev(1)], {truncated: true});
        assert.equal(f.rows('inventory_stalled')[0].count, 2, 'again after 6 h');
    } finally { f.cleanup(); }
});
test('SM-1a: transport failures stall the inventory the same way, and a complete poll ends the stall', () => {
    const f = world();
    try {
        f.poll([dev(1)]);
        for (let i = 0; i < 31; i++) { f.advance(60); f.inv.recordFailure('inventory_unavailable:ssh_timeout'); }
        assert.equal(f.rows('inventory_stalled').length, 1);
        f.advance(60); f.poll([dev(1)]);
        f.advance(60); f.inv.recordFailure('inventory_unavailable:ssh_timeout');
        for (let i = 0; i < 20; i++) { f.advance(60); f.inv.recordFailure('inventory_unavailable:ssh_timeout'); }
        assert.equal(f.rows('inventory_stalled')[0].count, 1, 'the clock restarted at the complete poll');
    } finally { f.cleanup(); }
});
test('SM-1b: a stale or emptied re-baseline raises a counted new_device alert instead of staying silent; the first baseline stays silent', () => {
    const f = world(30);
    try {
        f.poll([dev(1), dev(2)]);
        assert.equal(f.rows('new_device').length, 0, 'the very first baseline is silent');
        f.advance(31 * DAY); f.poll([dev(1), dev(2), dev(3)]);
        const alert = f.rows('new_device');
        assert.equal(alert.length, 1); assert.deepEqual(JSON.parse(alert[0].details), {count: 3, rebaselined: true});
        assert.equal(f.inv.list(actor).status.baselineAt, f.now());
    } finally { f.cleanup(); }
});

// ---- CM-2 ----
test('CM-2: invalid_clock alone is not structural: devices ingest with the service clock and the poll can baseline; any other code stays incomplete', () => {
    const f = world();
    try {
        f.poll([dev(1)], {errors: ['invalid_clock'], routerTime: 0});
        const s = f.inv.list(actor);
        assert.equal(s.status.baselineAt, f.now()); assert.equal(s.devices[0].firstSeen, f.now()); assert.equal(s.devices[0].lastSeen, f.now());
        f.advance(60); f.poll([dev(1), dev(2)], {errors: ['invalid_clock'], routerTime: 0});
        assert.equal(f.rows('new_device').length, 1, 'a complete-but-clockless poll can alert');
        f.advance(60); f.poll([dev(1), dev(2), dev(3)], {errors: ['invalid_clock', 'inventory_refused'], routerTime: 0});
        assert.equal(f.has(3), false, 'any other code: incomplete, nothing new stored');
        assert.equal(f.lastError(), 'inventory_incomplete:inventory_refused');
    } finally { f.cleanup(); }
});
test('CM-2: an invalid_clock refusal with no devices is not a baseline', () => {
    const f = world();
    try {
        f.poll([], {errors: ['invalid_clock'], routerTime: 0});
        assert.equal(f.inv.list(actor).status.baselineAt, null); assert.equal(f.inv.list(actor).status.lastOkAt, null);
    } finally { f.cleanup(); }
});

// ---- CM-3 ----
test('CM-3: the owning child is listed for the viewer only, never a protected count', () => {
    const f = world();
    try {
        const owned = f.config.person.device.mac;
        f.poll([{...dev(1), mac: owned}, dev(2)]);
        const seen = f.inv.list(actor).devices;
        const mine = seen.find(d => d.mac === owned)!, other = seen.find(d => d.mac === m(2))!;
        assert.equal(mine.personId, 'pilot'); assert.equal(mine.personName, f.config.person.name); assert.equal(mine.flags.unassigned, false);
        assert.equal(other.personId, null); assert.equal(other.personName, null); assert.equal(other.flags.unassigned, true);
        const blind = f.inv.list({...actor, personIds: []}).devices.find(d => d.mac === owned)!;
        assert.equal(blind.personId, null); assert.equal(blind.personName, null); assert.equal(blind.flags.unassigned, false, 'still assigned, just not visible');
        assert.equal('protectedCount' in f.inv.list(actor).status, false);
    } finally { f.cleanup(); }
});
test('LOW: a corrupt desired policy never turns the list into a 500', () => {
    const f = world();
    try {
        f.poll([dev(1)]);
        f.store.run("UPDATE service_state SET desired_json='{' WHERE singleton=1");
        assert.equal(f.inv.list(actor).devices.length, 1);
    } finally { f.cleanup(); }
});

// ---- SL-1 (and survived mutation M4) ----
test('M4: rows a reply lists are never evicted to make room', () => {
    const f = world();
    try {
        f.poll(range(1, INVENTORY_ROW_CAP));
        f.advance(60); f.poll([dev(1), dev(3000)]);
        assert.equal(f.has(1), true, 'listed, so kept even though it sorts first'); assert.equal(f.has(2), false); assert.equal(f.has(3000), true);
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices')!.n, INVENTORY_ROW_CAP);
    } finally { f.cleanup(); }
});
test('SL-1: acknowledged rows and not-yet-alerted New rows are never evicted; at the cap nothing new is stored and one rate-limited alert is raised', () => {
    const f = world();
    try {
        f.poll(range(1, INVENTORY_ROW_CAP - 1));
        f.store.run("UPDATE inventory_devices SET acknowledged_at=1,acknowledged_by='operator'");
        f.advance(60); f.poll([dev(5000)]);                       // fills the table; alerted at once
        assert.equal(f.rows('new_device').length, 1);
        f.advance(60); f.poll([dev(5001)]);                       // evicts the alerted 5000; its own alert is held back (hourly limit)
        assert.equal(f.has(5000), false); assert.equal(f.has(5001), true);
        assert.equal(f.store.get<{a: number | null}>('SELECT alerted_at a FROM inventory_devices WHERE mac=?', m(5001))!.a, null);
        f.advance(60); f.poll([dev(5002)]);                       // nothing evictable: 5001 is unalerted New, everything else acknowledged
        assert.equal(f.has(5001), true, 'not-yet-alerted New row survives'); assert.equal(f.has(5002), false, 'nothing new is stored at the cap');
        assert.equal(f.has(1), true, 'acknowledged rows survive');
        assert.equal(f.lastError(), 'inventory_row_cap');
        assert.equal(f.rows('inventory_stalled').length, 1); assert.match(f.rows('inventory_stalled')[0].details, /row_cap/);
        f.advance(60); f.poll([dev(5003)]);
        assert.equal(f.rows('inventory_stalled')[0].count, 1, 'rate limited');
    } finally { f.cleanup(); }
});

// ---- SL-2 ----
test('SL-2: once the daily cap is reached the existing alert row counts the occurrence without being re-opened', () => {
    const f = world();
    try {
        f.poll([dev(1)]);
        const seen = [dev(1)];
        for (let i = 0; i < 12; i++) { f.advance(HOUR + 1); seen.push(dev(100 + i)); f.poll(seen); }
        assert.equal(f.rows('new_device')[0].count, 12);
        f.store.run("UPDATE parent_alerts SET state='acknowledged' WHERE kind='new_device'");
        f.advance(HOUR + 1); seen.push(dev(200)); f.poll(seen);
        const row = f.rows('new_device')[0];
        assert.equal(row.state, 'acknowledged', 'not re-opened'); assert.equal(row.count, 13, 'but counted');
        f.advance(60); f.poll(seen);
        assert.equal(f.rows('new_device')[0].count, 13, 'the device is consumed, not counted every poll');
        assert.equal(f.inv.list(actor).devices.find(d => d.mac === m(200))!.flags.new, true);
    } finally { f.cleanup(); }
});

// ---- SL-5 ----
test('SL-5: the audit row never carries the MAC', () => {
    const f = world();
    try {
        f.poll([dev(1)]); f.advance(60); f.poll([dev(1), dev(2)]);
        f.inv.acknowledge(actor, m(2));
        const outcome = f.store.get<{outcome: string}>("SELECT outcome FROM audit WHERE action='inventory_acknowledge'")!.outcome;
        assert.ok(outcome.length > 0); assert.ok(!outcome.includes(m(2)) && !/00:00:5e/.test(outcome));
    } finally { f.cleanup(); }
});
test('SL-5: rows of protected MACs are purged at startup and on every ingest', () => {
    const f = world();
    try {
        const protectedMac = f.config.protectedMacs[0], seed = () => f.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'both',1,?)", f.config.router.generation, protectedMac, f.now());
        const count = () => f.store.get<{n: number}>('SELECT count(*) n FROM inventory_devices WHERE mac=?', protectedMac)!.n;
        seed(); assert.equal(count(), 1);
        new InventoryStore(f.store, f.alerts, f.now);
        assert.equal(count(), 0, 'startup');
        seed(); f.poll([dev(1)]);
        assert.equal(count(), 0, 'ingest');
    } finally { f.cleanup(); }
});

// ---- M11 ----
test('M11: a protected MAC can never be acknowledged, even if a row for it exists', () => {
    const f = world();
    try {
        const protectedMac = f.config.protectedMacs[0];
        f.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'both',1,1)", f.config.router.generation, protectedMac);
        assert.throws(() => f.inv.acknowledge(actor, protectedMac), (e: {status?: number; code?: string}) => e.status === 404 && e.code === 'inventory_device_not_found');
        assert.equal(f.store.get<{a: number | null}>('SELECT acknowledged_at a FROM inventory_devices WHERE mac=?', protectedMac)!.a, null);
    } finally { f.cleanup(); }
});
