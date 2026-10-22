import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyInventoryReply, isPrivateAddress, parseRouterInventory, MAX_INVENTORY_BYTES } from '../src/router-inventory.ts';

const GEN = 'a'.repeat(64);
// RFC 7042 documentation MACs and RFC 5737 documentation addresses only.
const dev = (over: Record<string, unknown> = {}) => ({mac: '00:00:5e:00:53:01', ipv4: ['192.0.2.10'], hostname: 'host-a', source: 'both', ...over});
const reply = (over: Record<string, unknown> = {}) => ({inventory_version: 1, generation: GEN, routerTime: 1791691200, devices: [dev()], truncated: false, errors: [], ...over});
const ctx = {generation: GEN, protectedMacs: ['00:00:5e:00:53:ff']};
const text = (o: unknown) => JSON.stringify(o);
const rejects = (o: unknown, c = ctx) => assert.throws(() => parseRouterInventory(typeof o === 'string' ? o : text(o), c));

test('a complete v1 reply parses to a fresh normalized copy', () => {
    const r = parseRouterInventory(text(reply({devices: [dev(), dev({mac: '00:00:5e:00:53:02', ipv4: [], hostname: null, source: 'lease'})]})), ctx);
    assert.equal(r.devices.length, 2); assert.equal(r.devices[1].hostname, null); assert.equal(r.truncated, false); assert.deepEqual(r.errors, []);
    assert.equal(r.routerTime, 1791691200);
});
test('the unknown-version check runs BEFORE the strict key check', () => {
    assert.throws(() => parseRouterInventory(text({...reply(), inventory_version: 2, future_field: 1}), ctx), (e: {code?: string}) => e.code === 'unknown_inventory_version');
    assert.throws(() => parseRouterInventory(text({...reply(), future_field: 1}), ctx), (e: {code?: string}) => e.code === 'invalid_router_inventory');
    assert.throws(() => parseRouterInventory(text({inventory_version: '1'}), ctx), (e: {code?: string}) => e.code === 'unknown_inventory_version');
});
test('every strict-shape reject case', () => {
    const {errors: _e, ...missing} = reply();
    for (const bad of [missing, {...reply(), extra: 1}, reply({generation: 'b'.repeat(64)}), reply({generation: 'A'.repeat(64)}), reply({generation: 'a'.repeat(63)}),
        reply({routerTime: -1}), reply({routerTime: 1.5}), reply({routerTime: '1'}), reply({truncated: 'false'}), reply({truncated: 0}),
        reply({devices: 'x'}), reply({errors: 'x'}), reply({errors: ['Bad']}), reply({errors: ['1bad']}), reply({errors: ['a'.repeat(65)]}), reply({errors: Array.from({length: 17}, () => 'e')}),
        reply({devices: [{...dev(), extra: 1}]}), reply({devices: [{mac: dev().mac, ipv4: [], hostname: null}]}),
        reply({devices: [dev({source: 'static'})]}), reply({devices: [dev({source: null})]}),
        reply({devices: [dev({mac: '00:00:5E:00:53:01'})]}), reply({devices: [dev({mac: '00-00-5e-00-53-01'})]}), reply({devices: [dev({mac: '01:00:5e:00:53:01'})]}),
        reply({devices: [dev({mac: '00:00:00:00:00:00'})]}), reply({devices: [dev({mac: 'ff:ff:ff:ff:ff:ff'})]}),
        reply({devices: [dev(), dev()]}), reply({devices: [dev({mac: '00:00:5e:00:53:02'}), dev({mac: '00:00:5e:00:53:01'})]}),
        reply({devices: Array.from({length: 257}, (_, i) => dev({mac: `00:00:5e:00:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`, ipv4: []}))}),
        reply({devices: [dev({ipv4: ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4', '192.0.2.5']})]}),
        reply({devices: [dev({ipv4: ['192.0.2.2', '192.0.2.1']})]}), reply({devices: [dev({ipv4: ['192.0.2.1', '192.0.2.1']})]}),
        reply({devices: [dev({ipv4: ['192.0.2.010']})]}), reply({devices: [dev({ipv4: ['192.0.2.256']})]}), reply({devices: [dev({ipv4: ['192.0.2']})]}), reply({devices: [dev({ipv4: ['::1']})]}), reply({devices: [dev({ipv4: 'x'})]}),
        reply({devices: [dev({ipv4: [1]})]})]) rejects(bad);
    rejects('{"inventory_version":1'); rejects('[]'); rejects('null'); rejects('');
    rejects('{"inventory_version":1,"inventory_version":1}');
});
test('ipv4 is sorted C-locale lexicographically, the order sort -u emits', () => {
    parseRouterInventory(text(reply({devices: [dev({ipv4: ['192.0.2.10', '192.0.2.9']})]})), ctx);
    rejects(reply({devices: [dev({ipv4: ['192.0.2.9', '192.0.2.10']})]}));
});
test('hostnames: only [A-Za-z0-9._-]{1,63} starting alphanumeric or null; any violation rejects the WHOLE reply', () => {
    for (const ok of ['a', 'Host-1.local', 'x_y', '9lives', 'a'.repeat(63)]) parseRouterInventory(text(reply({devices: [dev({hostname: ok})]})), ctx);
    for (const bad of ['', '-lead', '.lead', '_lead', 'a'.repeat(64), 'has space', '<script>alert(1)</script>', 'a"b', "a'b", 'a;b', 'a`b', '$(id)', 'a\nb', 'a\u0000b', 'été', 'a\\b', '*', 'a/b', 'a&b', 'a=b', 5, false, ['a']]) {
        rejects(reply({devices: [dev({mac: '00:00:5e:00:53:09'}), dev({hostname: bad})].sort((a, b) => a.mac < b.mac ? -1 : 1)}));
    }
});
test('a protected MAC in the reply is a contract violation that rejects the whole reply', () => {
    rejects(reply({devices: [dev({mac: '00:00:5e:00:53:ff'})]}));
    assert.throws(() => parseRouterInventory(text(reply({devices: [dev({mac: '00:00:5e:00:53:ff'})]})), ctx), (e: {code?: string}) => e.code === 'protected_mac_listed');
});
test('size: a reply of 131072 bytes or more is rejected', () => {
    assert.equal(MAX_INVENTORY_BYTES, 131072);
    rejects(text(reply()) + ' '.repeat(MAX_INVENTORY_BYTES));
    rejects(text(reply()) + ' '.repeat(MAX_INVENTORY_BYTES - text(reply()).length));
    parseRouterInventory(text(reply()) + ' '.repeat(MAX_INVENTORY_BYTES - text(reply()).length - 1), ctx);
});
test('a refusal body keeps the keys with empty devices and carries its code in errors', () => {
    const r = parseRouterInventory(text(reply({devices: [], errors: ['inventory_refused'], routerTime: 0})), ctx);
    assert.deepEqual(r.devices, []); assert.deepEqual(r.errors, ['inventory_refused']);
});
test('classifyInventoryReply maps both old-router shapes and every failure to a code, never throwing', () => {
    assert.deepEqual(classifyInventoryReply('{"ok":false,"errors":["invalid_command"]}', ctx), {ok: false, code: 'invalid_command'});
    assert.deepEqual(classifyInventoryReply('', ctx), {ok: false, code: 'empty_reply'});
    assert.deepEqual(classifyInventoryReply('garbage', ctx), {ok: false, code: 'invalid_router_inventory'});
    assert.deepEqual(classifyInventoryReply(text({...reply(), inventory_version: 2}), ctx), {ok: false, code: 'unknown_inventory_version'});
    assert.deepEqual(classifyInventoryReply('{"ok":false,"errors":["other"]}', ctx), {ok: false, code: 'unknown_inventory_version'});
    assert.deepEqual(classifyInventoryReply('{"ok":true,"errors":["invalid_command"]}', ctx), {ok: false, code: 'unknown_inventory_version'});
    assert.deepEqual(classifyInventoryReply(text(reply({generation: 'b'.repeat(64)})), ctx), {ok: false, code: 'invalid_router_inventory'});
    const good = classifyInventoryReply(text(reply()), ctx); assert.equal(good.ok, true);
});
test('isPrivateAddress is the locally-administered bit: second hex digit in 2367abef', () => {
    for (const d of '2367abef') assert.equal(isPrivateAddress(`0${d}:00:5e:00:53:01`), true, d);
    for (const d of '014589cd') assert.equal(isPrivateAddress(`0${d}:00:5e:00:53:01`), false, d);
    assert.equal(isPrivateAddress('00:00:5e:00:53:01'), false); assert.equal(isPrivateAddress('02:00:00:00:00:01'), true);
});
