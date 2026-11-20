import test from 'node:test';
import assert from 'node:assert/strict';
import { addDays, dayRange, localDay, localDayBounds, STATS_TIME_ZONE } from '../src/content-filter-day.ts';

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

test('localDay names the local calendar day of an instant, across midnight, DST and New Year', () => {
    const at = (y: number, m: number, d: number, h: number, min = 0) => Date.UTC(y, m - 1, d, h, min) / 1000;
    assert.equal(localDay(at(2026, 1, 15, 4, 59)), '2026-01-14');
    assert.equal(localDay(at(2026, 1, 15, 5, 0)), '2026-01-15');
    assert.equal(localDay(at(2026, 3, 8, 4, 59)), '2026-03-07', 'EST midnight is 05:00Z');
    assert.equal(localDay(at(2026, 3, 8, 5, 0)), '2026-03-08');
    assert.equal(localDay(at(2026, 3, 9, 3, 59)), '2026-03-08', 'EDT midnight is 04:00Z');
    assert.equal(localDay(at(2026, 11, 1, 3, 59)), '2026-10-31');
    assert.equal(localDay(at(2026, 11, 2, 4, 59)), '2026-11-01', 'the 25 h day ends at 05:00Z');
    assert.equal(localDay(at(2026, 11, 2, 5, 0)), '2026-11-02');
    assert.equal(localDay(at(2027, 1, 1, 4, 59)), '2026-12-31');
    assert.equal(localDay(localDayBounds('2026-03-08').to), '2026-03-09');
    assert.equal(localDay(localDayBounds('2026-11-01').to - 1), '2026-11-01');
    assert.throws(() => localDay(NaN), RangeError);
});

test('addDays and dayRange are calendar arithmetic', () => {
    assert.equal(addDays('2026-03-01', 7), '2026-03-08');
    assert.equal(addDays('2026-01-01', -1), '2025-12-31');
    assert.equal(addDays('2028-02-28', 1), '2028-02-29');
    assert.equal(addDays('2026-11-01', 0), '2026-11-01');
    assert.deepEqual(dayRange('2026-12-30', '2027-01-02'), ['2026-12-30', '2026-12-31', '2027-01-01', '2027-01-02']);
    assert.deepEqual(dayRange('2026-03-08', '2026-03-08'), ['2026-03-08']);
    assert.deepEqual(dayRange('2026-03-09', '2026-03-08'), []);
    assert.throws(() => addDays('2026-02-30', 1), RangeError);
    assert.throws(() => dayRange('x', '2026-01-01'), RangeError);
});
