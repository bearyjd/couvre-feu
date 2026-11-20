import test from 'node:test';
import assert from 'node:assert/strict';
import { lookupVendor, OUI_PREFIX_COUNT } from '../src/oui.ts';
import { OUI_VENDORS } from '../src/oui-table.ts';

// Documented prefixes only (IEEE registry via hwdata); a vendor here is a HINT derived from the first three octets.
test('known globally-administered prefixes resolve to a brand, case-insensitively and for any suffix', () => {
    assert.equal(lookupVendor('b8:27:eb:00:00:01'), 'Raspberry Pi');
    assert.equal(lookupVendor('B8:27:EB:12:34:56'), 'Raspberry Pi');
    assert.equal(lookupVendor('bc:24:11:aa:bb:cc'), 'Proxmox');
    assert.equal(lookupVendor('00:03:93:00:00:00'), 'Apple');
});
test('locally-administered (randomized) addresses never get a vendor, even when the other octets look like a registered prefix', () => {
    assert.equal(lookupVendor('ba:27:eb:00:00:01'), undefined); // b8 -> ba sets the local bit; same last two octets as a Raspberry Pi prefix
    assert.equal(lookupVendor('02:00:00:00:00:01'), undefined);
    assert.equal(lookupVendor('fe:ff:ff:ff:ff:ff'), undefined);
});
test('QEMU/KVM default 52:54:00 is the one documented locally-administered convention that is named', () => {
    assert.equal(lookupVendor('52:54:00:12:34:56'), 'QEMU/KVM (virtual)');
    assert.equal(lookupVendor('52:54:01:12:34:56'), undefined);
});
test('unknown prefixes, malformed input and non-strings are undefined, never a guess', () => {
    assert.equal(lookupVendor('00:00:5e:00:00:01'), undefined);
    for (const bad of ['', 'zz', 'b8:27:eb', 'b8-27-eb-00-00-01', 'b8:27:eb:00:00:0', 'b8:27:eb:00:00:01:02', ' b8:27:eb:00:00:01']) assert.equal(lookupVendor(bad), undefined, bad);
    assert.equal(lookupVendor(undefined as unknown as string), undefined);
    assert.equal(lookupVendor(null as unknown as string), undefined);
});
test('the vendored table is well formed: 6 lowercase hex digits, globally administered, no prefix listed twice, brand names are plain text', () => {
    const seen = new Set<string>();
    for (const [vendor, prefixes] of OUI_VENDORS) {
        assert.match(vendor, /^[A-Za-z0-9 .()\/&+-]{2,40}$/);
        for (const p of prefixes) {
            assert.match(p, /^[0-9a-f]{6}$/);
            assert.equal(parseInt(p.slice(0, 2), 16) & 3, 0, `${p} is multicast or locally administered`);
            assert.ok(!seen.has(p), `${p} duplicated`); seen.add(p);
        }
    }
    assert.equal(seen.size, OUI_PREFIX_COUNT);
    assert.ok(OUI_PREFIX_COUNT > 1000 && OUI_PREFIX_COUNT < 20000, 'a trimmed table, not the whole registry');
    for (const brand of ['Apple', 'Samsung', 'Google', 'Amazon', 'Sonos', 'Roku', 'Nintendo', 'Sony', 'Microsoft', 'Xiaomi', 'Huawei', 'Raspberry Pi', 'Proxmox', 'TP-Link', 'Netgear', 'GL.iNet', 'Intel', 'Realtek', 'Espressif'])
        assert.ok(OUI_VENDORS.some(([v]) => v === brand), brand);
});
