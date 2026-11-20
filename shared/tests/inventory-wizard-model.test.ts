import test from 'node:test';
import assert from 'node:assert/strict';

const modulePath = new URL('../../web/public/inventory-wizard-model.js', import.meta.url).href;
const { deviceName, osLines, diffPresence, snapshotOf, justConnected } = await import(modulePath);
const dev = (id: number, over: Record<string, unknown> = {}) => ({ id, hostname: null, vendor: undefined, kind: 'unknown', role: 'new', presence: 'online', firstSeen: 0, lastSeen: 100, flags: { unassigned: true, private: false, new: true }, ...over });

test('deviceName: first meaningful hostname token, else kind, else maker, else device; possessive; 64 characters', () => {
  assert.equal(deviceName('Jack', dev(1, { hostname: 'Pixel-7-Pro' })), "Jack's Pixel");
  assert.equal(deviceName('James', dev(1, { hostname: 'Galaxy_S23' })), "James' Galaxy");
  assert.equal(deviceName('Jack', dev(1, { hostname: 'localhost', kind: 'tablet' })), "Jack's tablet");
  assert.equal(deviceName('Jack', dev(1, { hostname: 'android-8f3a9c1d2b', kind: 'unknown', vendor: 'Samsung Electronics' })), "Jack's Samsung");
  assert.equal(deviceName('Jack', dev(1)), "Jack's device");
  assert.equal(deviceName('Jack', dev(1, { hostname: '<img src=x onerror=1>' })).includes('<'), false);
  assert.ok(deviceName('J'.repeat(80), dev(1, { hostname: 'Pixel' })).length <= 64);
});

test('osLines: both for an unknown maker, one for a known phone maker, a generic line for PCs, consoles and TVs', () => {
  assert.equal(osLines(dev(1)).length, 2);
  assert.match(osLines(dev(1, { vendor: 'Apple' }))[0], /Private Wi-Fi Address: OFF/);
  assert.match(osLines(dev(1, { vendor: 'Google' }))[0], /Use device MAC/);
  assert.deepEqual(osLines(dev(1, { kind: 'tv', vendor: 'Apple' })), ['Turn off any private or random address option in its Wi-Fi settings.']);
});

test('diffPresence: quiet needs on-at-Start; a finished scan that did not see it counts; new rows are "new", never "back"', () => {
  const start = [dev(1), dev(2, { presence: 'recent' })], snap = snapshotOf(start, 1000);
  // a scan finished after Start, device 1 not seen (lastSeen unchanged) although its age still says online
  let r = diffPresence(snap, [], [dev(1), dev(2, { presence: 'recent' }), dev(3)], 1060);
  assert.equal(r.states.get(1), 'quiet'); assert.equal(r.states.has(2), false, 'quiet at Start is not tracked'); assert.equal(r.states.get(3), 'new');
  // no scan since Start: nothing is claimed
  assert.equal(diffPresence(snap, [], start, 1000).states.size, 0);
  // seen again with a newer last-seen time
  r = diffPresence(snap, r.quiet, [dev(1, { lastSeen: 170 }), dev(2, { presence: 'recent' })], 1120);
  assert.equal(r.states.get(1), 'back');
});

test('justConnected: first seen within 10 minutes, newest first', () => {
  const rows = [dev(1, { firstSeen: 100 }), dev(2, { firstSeen: 500 }), dev(3, { firstSeen: -1000 })];
  assert.deepEqual(justConnected(rows, 600).map((d: { id: number }) => d.id), [2, 1]);
});
