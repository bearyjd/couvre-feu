import test from 'node:test';
import assert from 'node:assert/strict';
import { localDayBounds, STATS_TIME_ZONE } from '../src/content-filter-day.ts';

test('the zone is the digest zone', () => assert.equal(STATS_TIME_ZONE, 'America/New_York'));

test('an ordinary winter day is 24 h from local midnight (EST, UTC-5)', () => {
    assert.deepEqual(localDayBounds('2026-01-14'), { from: Date.UTC(2026, 0, 14, 5) / 1000, to: Date.UTC(2026, 0, 15, 5) / 1000 });
});

test('a summer day uses EDT (UTC-4)', () => {
    assert.deepEqual(localDayBounds('2026-07-04'), { from: Date.UTC(2026, 6, 4, 4) / 1000, to: Date.UTC(2026, 6, 5, 4) / 1000 });
});

test('DST days are 23 h and 25 h, and stay within the client span limit', () => {
    const spring = localDayBounds('2026-03-08'), fall = localDayBounds('2026-11-01');
    assert.equal(spring.to - spring.from, 23 * 3600);
    assert.equal(fall.to - fall.from, 25 * 3600);
    assert.ok(fall.to - fall.from <= 90000);
});

test('month and year rollovers', () => {
    assert.equal(localDayBounds('2026-12-31').to, localDayBounds('2027-01-01').from);
    assert.equal(localDayBounds('2028-02-28').to, localDayBounds('2028-02-29').from);
});

test('anything but a real calendar day is refused', () => {
    for (const d of ['2026-02-30', '2026-13-01', '2026-1-1', '', '2026-01-01T00:00', ' 2026-01-01', '2026-00-10']) assert.throws(() => localDayBounds(d), RangeError, d);
});
