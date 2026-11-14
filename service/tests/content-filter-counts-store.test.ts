import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture } from './fixtures/integration.ts';
import { CLASS_CODES } from '../../shared/src/content-filter-classes.ts';
import { COUNTS_RETENTION_DAYS, ContentFilterCountsStore } from '../src/content-filter-counts.ts';
import type { DayCounts } from '../src/content-filter-counts.ts';

const ok = (day: string, classes: DayCounts['classes'] = {}, total = 100, blocked = 5): DayCounts => ({day, state: 'ok', total, blocked, classes});
function world() {
    const f = integrationFixture(), counts = new ContentFilterCountsStore(f.store);
    const dump = () => JSON.stringify([f.store.all('SELECT * FROM content_filter_day ORDER BY person_id, day'), f.store.all('SELECT * FROM content_filter_day_class ORDER BY person_id, day, class')]);
    return {...f, counts, dump};
}

test('retention is the plan default of 56 days, a constant', () => assert.equal(COUNTS_RETENTION_DAYS, 56));

test('put stores a finished day and days reads it back, frozen, with zero classes omitted', () => {
    const s = world();
    try {
        s.counts.put('pilot', ok('2026-11-10', {adult: 2, social: 11, apps: 0, ads_trackers: 40}), 1000);
        const [day] = s.counts.days('pilot', '2026-11-10', '2026-11-10');
        assert.deepEqual(day, ok('2026-11-10', {adult: 2, social: 11, ads_trackers: 40}));
        assert.ok(Object.isFrozen(day) && Object.isFrozen(day!.classes));
        assert.deepEqual(s.counts.days('pilot', '2026-11-11', '2026-11-12'), []);
        assert.deepEqual(s.counts.days('blake', '2026-11-10', '2026-11-10'), []);
    } finally { s.cleanup(); }
});

test('put is idempotent: the same day twice is one row, and a changed answer replaces the classes (no stale class)', () => {
    const s = world();
    try {
        const first = ok('2026-11-10', {adult: 2, social: 11});
        s.counts.put('pilot', first, 1); const once = s.dump();
        s.counts.put('pilot', first, 1);
        assert.equal(s.dump(), once, 'byte-identical after a repeat');
        s.counts.put('pilot', ok('2026-11-10', {social: 3}, 50, 3), 2);
        assert.deepEqual(s.counts.days('pilot', '2026-11-10', '2026-11-10'), [ok('2026-11-10', {social: 3}, 50, 3)]);
        assert.equal(s.store.get<{n: number}>('SELECT count(*) n FROM content_filter_day')!.n, 1);
        assert.equal(s.store.get<{n: number}>('SELECT count(*) n FROM content_filter_day_class')!.n, 1);
    } finally { s.cleanup(); }
});

test('logs_off and suspect_zero rows keep their shape; unavailable can only come from markUnavailable', () => {
    const s = world();
    try {
        s.counts.put('pilot', {day: '2026-11-09', state: 'logs_off', total: null, blocked: null, classes: {}}, 1);
        s.counts.put('pilot', {day: '2026-11-10', state: 'suspect_zero', total: 0, blocked: 0, classes: {}}, 1);
        assert.deepEqual(s.counts.days('pilot', '2026-11-09', '2026-11-10').map(d => [d.day, d.state, d.total, d.blocked]), [['2026-11-09', 'logs_off', null, null], ['2026-11-10', 'suspect_zero', 0, 0]]);
        assert.throws(() => s.counts.put('pilot', {day: '2026-11-11', state: 'unavailable', total: null, blocked: null, classes: {}}, 1));
        assert.throws(() => s.counts.put('pilot', {day: '2026-11-11', state: 'logs_off', total: null, blocked: null, classes: {adult: 1}}, 1), 'a logs_off day has no counts');
        assert.throws(() => s.counts.put('pilot', {day: '2026-11-11', state: 'ok', total: null, blocked: null, classes: {}}, 1));
    } finally { s.cleanup(); }
});

test('put refuses anything that is not an integer count of a known class on a real local day; nothing is written', () => {
    const s = world();
    try {
        const refused: DayCounts[] = [
            ok('2026-11-10', {adult: -1}), ok('2026-11-10', {adult: 1.5}), ok('2026-11-10', {adult: Number.MAX_SAFE_INTEGER + 2}), ok('2026-11-10', {adult: NaN}),
            ok('2026-11-10', {['porn' as never]: 1}), ok('2026-11-10', {['denylist:secret-domain.test' as never]: 1}),
            ok('2026-11-10', {}, -1), ok('2026-11-10', {}, 1.2), ok('2026-11-10', {}, 10, 11), ok('2026-02-30'), ok('2026-1-1'), ok('2026-11-10T00:00'),
        ];
        for (const counts of refused) assert.throws(() => s.counts.put('pilot', counts, 1), /invalid_counts|invalid_day/, JSON.stringify(counts));
        assert.throws(() => s.counts.put('', ok('2026-11-10'), 1));
        assert.throws(() => s.counts.put('x'.repeat(65), ok('2026-11-10'), 1));
        assert.equal(s.dump(), '[[],[]]');
    } finally { s.cleanup(); }
});

test('a failed class insert rolls the whole day back: no partial day', () => {
    const s = world();
    try {
        s.counts.put('pilot', ok('2026-11-10', {adult: 2}), 1);
        const before = s.dump();
        s.store.run("CREATE TRIGGER boom BEFORE INSERT ON content_filter_day_class WHEN NEW.class='social' BEGIN SELECT RAISE(ABORT, 'boom'); END");
        assert.throws(() => s.counts.put('pilot', ok('2026-11-10', {adult: 9, social: 1}, 9, 9), 2), /boom/);
        assert.equal(s.dump(), before);
    } finally { s.cleanup(); }
});

test('markUnavailable records a gap, counts attempts, and never overwrites a finished day', () => {
    const s = world();
    try {
        s.counts.markUnavailable('pilot', '2026-11-10', 5); s.counts.markUnavailable('pilot', '2026-11-10', 6);
        assert.deepEqual(s.store.all('SELECT state,total,blocked,attempts,fetched_at FROM content_filter_day').map(r => ({...(r as object)})), [{state: 'unavailable', total: null, blocked: null, attempts: 2, fetched_at: 6}]);
        assert.deepEqual(s.counts.days('pilot', '2026-11-10', '2026-11-10'), [{day: '2026-11-10', state: 'unavailable', total: null, blocked: null, classes: {}}]);
        s.counts.put('pilot', ok('2026-11-10', {adult: 2}), 7);
        const finished = s.dump();
        s.counts.markUnavailable('pilot', '2026-11-10', 8);
        assert.equal(s.dump(), finished, 'an ok day is final');
        s.counts.put('pilot', {day: '2026-11-11', state: 'logs_off', total: null, blocked: null, classes: {}}, 7);
        const logsOff = s.dump();
        s.counts.markUnavailable('pilot', '2026-11-11', 9);
        assert.equal(s.dump(), logsOff);
        assert.throws(() => s.counts.markUnavailable('pilot', 'not-a-day', 1));
    } finally { s.cleanup(); }
});

test('weekSums counts headline classes over ok days only; background is ads and security; household sums the children', () => {
    const s = world();
    try {
        s.counts.put('pilot', ok('2026-11-08', {adult: 2, social: 11, apps: 9, bypass: 1, ads_trackers: 40, security: 3, other: 7}), 1);
        s.counts.put('pilot', ok('2026-11-09', {denylist: 4}), 1);
        s.counts.markUnavailable('pilot', '2026-11-10', 1);
        s.counts.put('pilot', {day: '2026-11-11', state: 'logs_off', total: null, blocked: null, classes: {}}, 1);
        s.counts.put('pilot', {day: '2026-11-12', state: 'suspect_zero', total: 0, blocked: 0, classes: {}}, 1);
        s.counts.put('blake', ok('2026-11-08', {gambling: 5, ads_trackers: 1}), 1);
        s.counts.put('outside', ok('2026-11-08', {gambling: 500}), 1);
        s.counts.put('pilot', ok('2026-11-01', {adult: 900}), 1);
        assert.deepEqual(s.counts.weekSums('pilot', '2026-11-08', '2026-11-14'), {filterBlocked: 27, background: 43, okDays: 2, days: 7});
        assert.deepEqual(s.counts.householdBlocked(['pilot', 'blake'], '2026-11-08', '2026-11-14'), {blocked: 32, okDays: 3, expectedDays: 14});
        assert.deepEqual(s.counts.householdBlocked([], '2026-11-08', '2026-11-14'), {blocked: 0, okDays: 0, expectedDays: 0});
    } finally { s.cleanup(); }
});

test('prune deletes days before the cut-off (and their class rows), keeps the cut-off day, and says how many', () => {
    const s = world();
    try {
        for (const day of ['2026-09-17', '2026-09-18', '2026-09-19', '2026-11-13']) s.counts.put('pilot', ok(day, {adult: 1, social: 2}), 1);
        s.counts.markUnavailable('blake', '2026-09-01', 1);
        assert.equal(s.counts.prune('2026-09-19'), 3);
        assert.deepEqual(s.store.all<{day: string}>('SELECT day FROM content_filter_day ORDER BY day').map(r => r.day), ['2026-09-19', '2026-11-13']);
        assert.deepEqual([...new Set(s.store.all<{day: string}>('SELECT day FROM content_filter_day_class').map(r => r.day))].sort(), ['2026-09-19', '2026-11-13']);
        assert.equal(s.counts.prune('2026-09-19'), 0);
        assert.throws(() => s.counts.prune('later'));
    } finally { s.cleanup(); }
});

test('the stored data is integers and class codes only, and the schema has no column finer than a day', () => {
    const s = world();
    try {
        s.counts.put('pilot', ok('2026-11-10', {adult: 2, social: 11, other: 7}), 1);
        const cells = [...s.store.all<Record<string, unknown>>('SELECT * FROM content_filter_day'), ...s.store.all<Record<string, unknown>>('SELECT * FROM content_filter_day_class')].flatMap(r => Object.values(r));
        for (const cell of cells) assert.ok(typeof cell === 'number' || ['pilot', 'ok', '2026-11-10', ...CLASS_CODES].includes(cell as never), String(cell));
        assert.deepEqual(s.store.all<{name: string}>("SELECT name FROM pragma_table_info('content_filter_day')").map(c => c.name), ['person_id', 'day', 'state', 'total', 'blocked', 'attempts', 'fetched_at']);
        assert.deepEqual(s.store.all<{name: string}>("SELECT name FROM pragma_table_info('content_filter_day_class')").map(c => c.name), ['person_id', 'day', 'class', 'queries']);
    } finally { s.cleanup(); }
});
