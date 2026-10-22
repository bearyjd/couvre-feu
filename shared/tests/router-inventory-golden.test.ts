import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { classifyInventoryReply, MAX_INVENTORY_BYTES, parseRouterInventory } from '../src/router-inventory.ts';

// Raw replies produced by the router fixture (tests/test-inventory.py GoldenTests), generation normalised. Parsed byte for byte.
const dir = new URL('../../tests/fixtures/inventory-golden/', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('manifest.json', dir), 'utf8')) as
    {generation: string; protectedMacs: string[]; replies: Record<string, {file: string; exit: number}>};
const context = {generation: manifest.generation, protectedMacs: manifest.protectedMacs};
const reply = (name: string) => readFileSync(new URL(manifest.replies[name].file, dir), 'utf8');

test('every golden router reply is accepted by the real service parser', () => {
    assert.deepEqual(Object.keys(manifest.replies).sort(), ['baseline', 'dropped-row', 'invalid-clock', 'mixed', 'refusal', 'truncated']);
    for (const name of Object.keys(manifest.replies)) {
        const text = reply(name);
        assert.ok(Buffer.byteLength(text) < MAX_INVENTORY_BYTES, name);
        const result = classifyInventoryReply(text, context);
        assert.equal(result.ok, true, `${name}: ${JSON.stringify(result)}`);
    }
});

test('golden contents: ordering, sources, hostnames, truncation and error codes', () => {
    const baseline = parseRouterInventory(reply('baseline'), context);
    assert.deepEqual(baseline.devices.map(d => [d.mac, d.ipv4, d.hostname, d.source]),
        [['02:00:00:00:00:01', ['192.168.1.20', '192.168.1.21'], 'fixture', 'both'], ['02:00:00:00:00:02', ['192.168.1.22'], 'fixture2', 'both']]);
    assert.deepEqual([baseline.truncated, baseline.errors], [false, []]);
    const mixed = parseRouterInventory(reply('mixed'), context);
    assert.deepEqual(mixed.devices.map(d => [d.mac, d.ipv4, d.hostname, d.source]), [
        ['02:00:00:00:00:01', ['192.168.1.10', '192.168.1.9'], 'host-a', 'both'],
        ['02:00:00:00:00:02', ['192.168.1.51'], null, 'lease'],
        ['0a:00:00:00:00:03', ['192.168.1.52'], null, 'lease'],
        ['f2:00:00:00:00:05', ['192.168.1.53'], 'printer.lan', 'lease']]);
    const clock = parseRouterInventory(reply('invalid-clock'), context);
    assert.deepEqual([clock.routerTime, clock.errors, clock.devices.length], [0, ['invalid_clock'], 2]);
    assert.deepEqual(parseRouterInventory(reply('dropped-row'), context).errors, ['inventory_row_dropped']);
    const truncated = parseRouterInventory(reply('truncated'), context);
    assert.deepEqual([truncated.truncated, truncated.devices.length], [true, 256]);
    const refusal = parseRouterInventory(reply('refusal'), context);
    assert.deepEqual([refusal.devices, refusal.errors, refusal.routerTime], [[], ['inactive_generation'], 0]);
});

test('the parser is really checking the goldens (generation and protected MACs bind)', () => {
    assert.deepEqual(classifyInventoryReply(reply('baseline'), {...context, generation: 'b'.repeat(64)}), {ok: false, code: 'invalid_router_inventory'});
    assert.deepEqual(classifyInventoryReply(reply('baseline'), {...context, protectedMacs: ['02:00:00:00:00:02']}), {ok: false, code: 'protected_mac_listed'});
});
