import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { InventoryStore } from '../src/inventory-store.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import type { InventoryDevice, RouterInventory } from '../../shared/src/router-inventory.ts';
import type { Actor } from '../../shared/src/contracts.ts';

const parent: Actor = {...actor, id: 'parent', role: 'parent'};
const APPLE = '00:03:93:00:00:01', PI = 'b8:27:eb:00:00:02', PRIV_A = '02:00:00:00:00:0a', PRIV_B = '0a:00:00:00:00:0b';
const dev = (mac: string, hostname: string | null, over: Partial<InventoryDevice> = {}): InventoryDevice => ({mac, ipv4: ['192.0.2.9'], hostname, source: 'both', ...over});

function world() {
    const f = integrationFixture();
    const alerts = new ParentAlerts(f.store, null, f.now), inv = new InventoryStore(f.store, alerts, f.now);
    const poll = (devices: InventoryDevice[]) => inv.ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices: [...devices].sort((a, b) => a.mac < b.mac ? -1 : 1), truncated: false, errors: []} as RouterInventory, f.now());
    const byMac = (mac: string) => inv.list(actor).devices.find(d => d.mac === mac)!;
    return {...f, alerts, inv, poll, byMac};
}

test('DTO: vendor, kind, presence and a row id are added; vendor is absent (not null) when unknown or randomized', () => {
    const f = world();
    try {
        f.poll([dev(APPLE, 'Jacks-iPhone'), dev(PI, 'raspberrypi'), dev(PRIV_A, null, {source: 'lease'})]);
        const apple = f.byMac(APPLE), pi = f.byMac(PI), priv = f.byMac(PRIV_A);
        assert.deepEqual([apple.vendor, apple.kind, apple.presence], ['Apple', 'phone', 'online']);
        assert.deepEqual([pi.vendor, pi.kind], ['Raspberry Pi', 'computer']);
        assert.deepEqual([priv.kind, priv.presence], ['unknown', 'lease_only']); assert.ok(!('vendor' in priv));
        assert.ok(!('suggestedReplaces' in apple));
        assert.equal(typeof apple.id, 'number'); assert.equal(new Set([apple.id, pi.id, priv.id]).size, 3);
    } finally { f.cleanup(); }
});
test('DTO: presence follows the service clock across polls (online -> recent -> quiet)', () => {
    const f = world();
    try {
        f.poll([dev(APPLE, 'a-phone')]);
        assert.equal(f.byMac(APPLE).presence, 'online');
        f.advance(121); assert.equal(f.byMac(APPLE).presence, 'recent');
        f.advance(800); assert.equal(f.byMac(APPLE).presence, 'quiet');
        f.poll([dev(APPLE, 'a-phone')]); assert.equal(f.byMac(APPLE).presence, 'online');
    } finally { f.cleanup(); }
});
test('suggestedReplaces: a rotated phone points at the quiet row by ROW ID, never a MAC; clears when the old one returns', () => {
    const f = world();
    try {
        f.poll([dev(APPLE, 'Jacks-Pixel-9')]); f.advance(3600);
        f.poll([dev(PRIV_A, 'jacks-pixel-9')]);
        const fresh = f.byMac(PRIV_A), old = f.byMac(APPLE);
        assert.equal(fresh.suggestedReplaces, old.id); assert.ok(!('suggestedReplaces' in old));
        assert.ok(!JSON.stringify(fresh.suggestedReplaces).includes(':'));
        f.advance(60); f.poll([dev(APPLE, 'Jacks-Pixel-9'), dev(PRIV_A, 'jacks-pixel-9')]);
        assert.ok(!('suggestedReplaces' in f.byMac(PRIV_A)), 'old row is live again: not a replacement');
    } finally { f.cleanup(); }
});
test('suggestedReplaces: generic names never link', () => {
    const f = world();
    try { f.poll([dev(APPLE, 'iPhone')]); f.advance(3600); f.poll([dev(PRIV_A, 'iPhone')]); assert.ok(!('suggestedReplaces' in f.byMac(PRIV_A))); } finally { f.cleanup(); }
});
test('suggestedReplaces: protected rows never link on either side (config is read live; a poll would purge them, so mark them after it)', () => {
    for (const side of [APPLE, PRIV_B]) {
        const f = world();
        try {
            f.poll([dev(APPLE, 'jacks-pixel-9')]); f.advance(3600); f.poll([dev(PRIV_B, 'jacks-pixel-9')]);
            assert.ok(f.byMac(PRIV_B).suggestedReplaces !== undefined, 'precondition');
            f.config.protectedMacs.push(side);
            const shown = f.inv.list(actor).devices;
            assert.ok(!shown.some(d => d.mac === side), 'the protected row is hidden');
            assert.ok(!shown.some(d => d.suggestedReplaces !== undefined), `protected ${side}`);
        } finally { f.cleanup(); }
    }
});
test('suggestedReplaces: enrolled child devices never link, as predecessor or as the new row, in list and acknowledge', () => {
    const enrol = (f: ReturnType<typeof world>, mac: string) => f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',?)", 'dev-x', f.config.person.id, 'x', mac, f.now());
    const control = world();
    try { control.poll([dev(APPLE, 'jacks-pixel-9')]); control.advance(3600); control.poll([dev(PRIV_B, 'jacks-pixel-9')]); assert.ok(control.byMac(PRIV_B).suggestedReplaces !== undefined, 'precondition'); } finally { control.cleanup(); }
    for (const enrolled of [APPLE, PRIV_B]) {
        const f = world();
        try {
            enrol(f, enrolled);
            f.poll([dev(APPLE, 'jacks-pixel-9')]); f.advance(3600); f.poll([dev(PRIV_B, 'jacks-pixel-9')]);
            assert.ok(!f.inv.list(actor).devices.some(d => d.suggestedReplaces !== undefined), `enrolled ${enrolled}`);
            assert.ok(!('suggestedReplaces' in f.inv.acknowledge(actor, PRIV_B)), 'acknowledge agrees');
        } finally { f.cleanup(); }
    }
});
test('acknowledge carries the suggestion exactly like the list, from one clock', () => {
    const f = world();
    try {
        f.poll([dev(APPLE, 'jacks-pixel-9')]); f.advance(3600); f.poll([dev(PRIV_B, 'jacks-pixel-9')]);
        assert.deepEqual(f.inv.acknowledge(actor, PRIV_B), f.byMac(PRIV_B));
        assert.equal(f.inv.acknowledge(actor, PRIV_B).suggestedReplaces, f.byMac(APPLE).id);
    } finally { f.cleanup(); }
});
test('acknowledge returns the same enriched DTO', () => {
    const f = world();
    try {
        f.poll([dev(PI, 'raspberrypi')]); f.advance(60); f.poll([dev(PI, 'raspberrypi'), dev(APPLE, 'Jacks-iPhone')]);
        const ack = f.inv.acknowledge(actor, APPLE);
        assert.deepEqual([ack.vendor, ack.kind, ack.presence, ack.id], ['Apple', 'phone', 'online', f.byMac(APPLE).id]);
    } finally { f.cleanup(); }
});
test('a parent never receives the enriched DTO', () => {
    const f = world();
    try { f.poll([dev(APPLE, 'x-iphone')]); assert.throws(() => f.inv.list(parent), (e: {status?: number}) => e.status === 403); } finally { f.cleanup(); }
});
test('LEAK: vendor, kind, presence and suggestions never reach audit rows, parent audit, alerts, inventory state or logs', () => {
    const f = world();
    const writes: string[] = [], real = { out: process.stdout.write, err: process.stderr.write };
    const spy = ((chunk: unknown) => { writes.push(String(chunk)); return true; }) as typeof process.stdout.write;
    const consoles = (['log', 'info', 'warn', 'error', 'debug'] as const).map(k => [k, console[k]] as const);
    process.stdout.write = spy; process.stderr.write = spy;
    for (const [k] of consoles) console[k] = ((...a: unknown[]) => { writes.push(a.map(String).join(' ')); }) as never;
    try {
        f.poll([dev(PI, 'raspberrypi')]); f.advance(3600); f.poll([dev(PI, 'raspberrypi'), dev(APPLE, 'Jacks-Pixel-9')]);
        f.advance(3600); f.poll([dev(PI, 'raspberrypi'), dev(PRIV_A, 'jacks-pixel-9')]);
        assert.ok(f.byMac(PRIV_A).suggestedReplaces !== undefined, 'precondition: a suggestion exists');
        f.inv.acknowledge(actor, APPLE); f.inv.list(actor);
        const dump = JSON.stringify([f.store.all('SELECT * FROM audit'), f.store.all('SELECT * FROM parent_alerts'), f.store.all('SELECT * FROM inventory_state'),
            f.store.all('SELECT * FROM parent_audit'), writes]);
        for (const needle of ['Apple', 'Raspberry', 'phone', 'computer', 'online', 'lease_only', 'quiet', 'suggestedReplaces', 'vendor', 'presence', 'jacks-pixel-9', 'Jacks-Pixel-9'])
            assert.ok(!dump.toLowerCase().includes(needle.toLowerCase()), `leaked ${needle}`);
        const outcomes = f.store.all<{outcome: string}>("SELECT outcome FROM audit WHERE action='inventory_acknowledge'").map(r => r.outcome);
        assert.ok(outcomes.length === 1 && /^inventory_row:\d+$/.test(outcomes[0]));
    } finally {
        process.stdout.write = real.out; process.stderr.write = real.err;
        for (const [k, fn] of consoles) console[k] = fn;
        f.cleanup();
    }
});
