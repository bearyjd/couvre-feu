import test from 'node:test';
import assert from 'node:assert/strict';
import { kindHint, presenceOf, suggestReplacements, ONLINE_SECONDS, RECENT_SECONDS, INVENTORY_POLL_SECONDS, isGenericHostname } from '../src/inventory-hints.ts';
import type { HintRow } from '../src/inventory-hints.ts';

const kind = (hostname: string | null, vendor?: string) => kindHint({hostname, vendor});

test('kindHint: transparent hostname rules', () => {
    const cases: [string, string][] = [
        ['Jacks-iPhone', 'phone'], ['Pixel-7-Pro', 'phone'], ['Galaxy-S23', 'phone'], ['android-1a2b3c4d5e6f7a8b', 'phone'],
        ['iPad-Air', 'tablet'], ['Galaxy-Tab-A9', 'tablet'], ['pixel-tablet', 'tablet'],
        ['Penns-MacBook-Pro', 'computer'], ['DESKTOP-AB12CD3', 'computer'], ['raspberrypi', 'computer'],
        ['Xbox', 'console'], ['PS5-1234', 'console'], ['Nintendo-Switch', 'console'], ['Switch', 'console'],
        ['Living-Room-TV', 'tv'], ['Roku-Express', 'tv'], ['Chromecast', 'tv'], ['AppleTV', 'tv'],
        ['Google-Home-Mini', 'speaker'], ['echo-dot-4', 'speaker'], ['Sonos-Kitchen', 'speaker'], ['HomePod', 'speaker'],
        ['HP-LaserJet-printer', 'appliance'], ['ESP_1A2B3C', 'appliance'], ['fridge', 'appliance'], ['Ring-Doorbell', 'appliance'],
        ['pve1', 'virtual'], ['qemu-guest', 'virtual'], ['openwrt', 'network'], ['switch-garage', 'network'],
        ['zzzz', 'unknown'], ['', 'unknown'],
    ];
    for (const [hostname, expected] of cases) assert.equal(kind(hostname), expected, hostname);
    assert.equal(kind(null), 'unknown');
});
test('kindHint: word boundaries keep substrings from firing', () => {
    for (const hostname of ['stable', 'tablecloth', 'staband', 'mypixelated', 'television-less', 'microchip']) assert.equal(kind(hostname), 'unknown', hostname);
});
test('kindHint: hostname outranks vendor, vendor is only a fallback, and big phone makers say nothing alone', () => {
    assert.equal(kind('Pixel-7', 'TP-Link'), 'phone');
    assert.equal(kind(null, 'Sonos'), 'speaker');
    assert.equal(kind(null, 'Nintendo'), 'console');
    assert.equal(kind(null, 'Proxmox'), 'virtual');
    assert.equal(kind(null, 'QEMU/KVM (virtual)'), 'virtual');
    assert.equal(kind(null, 'Netgear'), 'network');
    assert.equal(kind(null, 'Raspberry Pi'), 'computer');
    assert.equal(kind(null, 'Espressif'), 'appliance');
    for (const v of ['Apple', 'Samsung', 'Google', 'Amazon', 'Sony', 'Microsoft', 'Xiaomi', 'Huawei', 'Intel', undefined]) assert.equal(kind(null, v), 'unknown', String(v));
});
test('kindHint never throws on hostile text and returns only the closed set', () => {
    const allowed = ['phone', 'tablet', 'computer', 'console', 'tv', 'speaker', 'appliance', 'virtual', 'network', 'unknown'];
    for (const h of ['<script>', 'a'.repeat(5000), '\u0000', '(((', '__proto__', 'constructor']) assert.ok(allowed.includes(kind(h, h)), h);
});

const T = 1_000_000;
test('presenceOf: precise boundaries', () => {
    const p = (source: 'lease' | 'neigh' | 'both', age: number) => presenceOf({source, lastSeen: T - age, now: T});
    assert.deepEqual([INVENTORY_POLL_SECONDS, ONLINE_SECONDS, RECENT_SECONDS], [60, 120, 900]);
    assert.equal(p('both', 0), 'online'); assert.equal(p('neigh', 120), 'online'); assert.equal(p('neigh', 121), 'recent');
    assert.equal(p('both', 900), 'recent'); assert.equal(p('both', 901), 'quiet');
    assert.equal(p('lease', 0), 'lease_only'); assert.equal(p('lease', 900), 'lease_only'); assert.equal(p('lease', 901), 'quiet');
    assert.equal(p('lease', 5000), 'quiet'); assert.equal(p('both', 86400 * 3), 'quiet');
});
test('presenceOf: a last_seen in the future (clock skew) counts as just now, not as an error', () => {
    assert.equal(presenceOf({source: 'both', lastSeen: T + 50, now: T}), 'online');
    assert.equal(presenceOf({source: 'lease', lastSeen: T + 50, now: T}), 'lease_only');
});

let n = 0;
const row = (over: Partial<HintRow> & {hostname: string | null}): HintRow => ({id: ++n, mac: `02:00:00:00:00:${n.toString(16).padStart(2, '0')}`, firstSeen: T - 10000, lastSeen: T - 10000, source: 'both', protectedRow: false, ...over});
const old = (hostname: string | null, over: Partial<HintRow> = {}) => row({hostname, mac: `00:00:5e:00:00:${(++n).toString(16).padStart(2, '0')}`, ...over});
const fresh = (hostname: string | null, over: Partial<HintRow> = {}) => row({hostname, firstSeen: T - 100, lastSeen: T - 30, ...over});

test('suggestReplacements: a randomized row with a unique hostname that a quiet older row had is linked by ROW ID', () => {
    const a = old('Jacks-Pixel-7'), b = fresh('jacks-pixel-7');
    const map = suggestReplacements([a, b], T);
    assert.deepEqual([...map], [[b.id, a.id]]);
});
test('suggestReplacements: the immediate predecessor wins when there were several rotations', () => {
    const a = old('jacks-tab', {lastSeen: T - 50000}), b = old('jacks-tab', {firstSeen: T - 40000, lastSeen: T - 9000}), c = fresh('jacks-tab');
    assert.deepEqual([...suggestReplacements([a, b, c], T)], [[c.id, b.id]]);
});
test('suggestReplacements: false-positive guards', () => {
    const cases: [string, HintRow[]][] = [];
    for (const generic of ['android', 'iphone', 'iPhone', 'localhost', 'localhost.localdomain', 'unknown', 'iPhone-12', 'Pixel-7-Pro', 'Galaxy-S23', 'iPad', 'MacBook-Pro', 'abc'])
        cases.push([`generic ${generic}`, [old(generic), fresh(generic)]]);
    cases.push(['empty hostname', [old(''), fresh('')]], ['null hostname', [old(null), fresh(null)]]);
    cases.push(['new row is not randomized', [old('jacks-pixel'), fresh('jacks-pixel', {mac: '00:00:5e:00:99:99'})]]);
    cases.push(['old row still online', [old('jacks-pixel', {lastSeen: T - 10}), fresh('jacks-pixel')]]);
    cases.push(['old row only recent', [old('jacks-pixel', {lastSeen: T - 500}), fresh('jacks-pixel')]]);
    cases.push(['old row is lease-only and recent', [old('jacks-pixel', {source: 'lease', lastSeen: T - 500}), fresh('jacks-pixel')]]);
    cases.push(['old row is protected', [old('jacks-pixel', {protectedRow: true}), fresh('jacks-pixel')]]);
    cases.push(['new row is protected', [old('jacks-pixel'), fresh('jacks-pixel', {protectedRow: true})]]);
    cases.push(['old row is newer than the new one', [old('jacks-pixel', {firstSeen: T - 10}), fresh('jacks-pixel', {firstSeen: T - 100})]]);
    cases.push(['new row is itself quiet', [old('jacks-pixel'), fresh('jacks-pixel', {lastSeen: T - 5000})]]);
    cases.push(['two live randomized rows share the name', [old('jacks-pixel'), fresh('jacks-pixel'), fresh('jacks-pixel')]]);
    cases.push(['two equally recent quiet predecessors are ambiguous', [old('jacks-pixel'), old('jacks-pixel'), fresh('jacks-pixel')]]);
    cases.push(['different hostname', [old('jacks-pixel'), fresh('jacks-pixel-2')]]);
    cases.push(['same MAC cannot replace itself', [(() => { const r = fresh('jacks-pixel'); return r; })()]]);
    for (const [name, rows] of cases) assert.equal(suggestReplacements(rows, T).size, 0, name);
});
test('suggestReplacements: two quiet predecessors last seen at the SAME second tie -> no suggestion; a later one wins; two active randomized rows -> none', () => {
    assert.equal(suggestReplacements([old('jacks-pixel'), old('jacks-pixel'), fresh('jacks-pixel')], T).size, 0);
    const a = old('jacks-pixel', {lastSeen: T - 5000}), b = old('jacks-pixel', {lastSeen: T - 4999}), c = fresh('jacks-pixel');
    assert.deepEqual([...suggestReplacements([a, b, c], T)], [[c.id, b.id]]);
    assert.equal(suggestReplacements([old('jacks-pixel'), fresh('jacks-pixel'), fresh('jacks-pixel')], T).size, 0);
});
test('isGenericHostname', () => {
    for (const g of ['android', 'IPHONE', 'localhost', 'iPhone-13-Pro-Max', 'Galaxy-S23-Ultra', 'pixel', 'ab', '']) assert.equal(isGenericHostname(g), true, g);
    for (const g of ['Jacks-iPhone', 'jacks-pixel-7', 'DESKTOP-AB12CD3', 'android-1a2b3c4d5e6f7a8b']) assert.equal(isGenericHostname(g), false, g);
});
