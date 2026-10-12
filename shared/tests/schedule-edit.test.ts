import test from 'node:test';
import assert from 'node:assert/strict';
import { parseScheduleChange, applyScheduleChange } from '../src/schedule-edit.ts';
import { normalizePolicy } from '../src/router-schema.ts';
import { INITIAL_POLICY } from '../../service/src/fixtures.ts';

const window = { id: 'bedtime', weekdays: ['Tue', 'Mon'], start: '22:00', stop: '06:30' };
test('parseScheduleChange canonicalizes weekdays and enforces the shared field bounds', () => {
    assert.deepEqual(parseScheduleChange('schedule_create', window), { action: 'schedule_create', window: { ...window, weekdays: ['Mon', 'Tue'] } });
    assert.deepEqual(parseScheduleChange('schedule_update', { weekdays: ['Sun'], start: '00:00', stop: '23:59' }, 'bedtime'), { action: 'schedule_update', window: { id: 'bedtime', weekdays: ['Sun'], start: '00:00', stop: '23:59' } });
    assert.deepEqual(parseScheduleChange('schedule_delete', {}, 'bedtime'), { action: 'schedule_delete', id: 'bedtime' });
    const rejected: [unknown, RegExp][] = [
        [{ ...window, id: 'Bad' }, /invalid_id/], [{ ...window, id: 'a'.repeat(33) }, /invalid_id/], [{ ...window, weekdays: [] }, /empty_weekdays/],
        [{ ...window, weekdays: ['Mon', 'Mon'] }, /duplicate_value/], [{ ...window, weekdays: ['Monday'] }, /invalid_weekday/], [{ ...window, weekdays: Array(8).fill('Mon') }, /array_limit/],
        [{ ...window, start: '24:00' }, /invalid_clock/], [{ ...window, stop: '6:30' }, /invalid_clock/], [{ ...window, stop: '22:00' }, /empty_schedule/],
        [{ ...window, extra: 1 }, /invalid_fields/], [{ id: 'x' }, /invalid_fields/],
    ];
    for (const [input, pattern] of rejected) assert.throws(() => parseScheduleChange('schedule_create', input), pattern);
    assert.throws(() => parseScheduleChange('schedule_update', window, 'bedtime'), /invalid_fields/);
    assert.throws(() => parseScheduleChange('schedule_delete', { x: 1 }, 'bedtime'), /invalid_fields/);
});
test('applyScheduleChange is immutable, scoped to one person, and rejects missing or duplicate ids', () => {
    const before = INITIAL_POLICY.schedules, snapshot = JSON.stringify(before);
    const created = applyScheduleChange(before, 'blair', parseScheduleChange('schedule_create', { ...window, id: 'school_nights' }));
    assert.equal(created.length, 2, 'the same id is allowed for a different person');
    assert.throws(() => applyScheduleChange(before, 'alex', parseScheduleChange('schedule_create', { ...window, id: 'school_nights' })), /schedule_id_exists/);
    assert.throws(() => applyScheduleChange(before, 'alex', parseScheduleChange('schedule_update', { weekdays: ['Mon'], start: '01:00', stop: '02:00' }, 'nope')), /schedule_not_found/);
    assert.throws(() => applyScheduleChange(before, 'blair', parseScheduleChange('schedule_delete', {}, 'school_nights')), /schedule_not_found/);
    const updated = applyScheduleChange(before, 'alex', parseScheduleChange('schedule_update', { weekdays: ['Mon'], start: '01:00', stop: '02:00' }, 'school_nights'));
    assert.deepEqual(updated, [{ person: 'alex', id: 'school_nights', weekdays: ['Mon'], start: '01:00', stop: '02:00' }]);
    assert.deepEqual(applyScheduleChange(before, 'alex', parseScheduleChange('schedule_delete', {}, 'school_nights')), []);
    assert.equal(JSON.stringify(before), snapshot);
});
test('the expanded native-window limit (256) is enforced by the full policy; overlaps are permitted', () => {
    const macs = INITIAL_POLICY.people[0].macs.length, crossing = (index: number) => ({ person: 'alex', id: `w${index}`, weekdays: ['Mon'], start: '22:00', stop: '06:30' });
    const fits = Array.from({ length: Math.floor(256 / (2 * macs)) }, (_, index) => crossing(index));
    assert.doesNotThrow(() => normalizePolicy({ ...INITIAL_POLICY, schedules: fits }));
    assert.throws(() => normalizePolicy({ ...INITIAL_POLICY, schedules: [...fits, crossing(999)] }), /expanded_schedule_limit/);
    assert.throws(() => normalizePolicy({ ...INITIAL_POLICY, schedules: Array.from({ length: 257 }, (_, index) => ({ ...crossing(index), stop: '23:00', start: '22:00' })) }), /array_limit/);
    const overlapping = [crossing(1), { ...crossing(2), start: '23:00', stop: '07:00' }];
    assert.equal(normalizePolicy({ ...INITIAL_POLICY, schedules: overlapping }).schedules.length, 2);
});
test('browser-side validation and previews agree with the shared contract', async () => {
    const client = await import(new URL('../../web/public/schedule-editor.js', import.meta.url).href) as {
        validateDraft: (draft: unknown, context: unknown) => Record<string, string>; previewWindows: (days: string[], start: string, stop: string) => string[]; overlaps: (a: unknown, b: unknown) => boolean;
    };
    assert.deepEqual(client.previewWindows(['Sun', 'Mon'], '22:00', '06:30'), ['Mon 22:00 → Tue 06:30', 'Sun 22:00 → Mon 06:30']);
    assert.deepEqual(client.previewWindows(['Mon'], '08:00', '15:00'), ['Mon 08:00 → Mon 15:00']);
    assert.deepEqual(client.previewWindows(['Mon'], '08:00', '08:00'), []);
    const context = { schedules: [{ id: 'taken', weekdays: ['Mon'], start: '01:00', stop: '02:00' }], editingId: null, deviceCount: 1 };
    const cases = [window, { ...window, id: 'Bad' }, { ...window, weekdays: [] }, { ...window, start: '24:00' }, { ...window, stop: '22:00' }, { ...window, id: 'x'.repeat(33) }, { ...window, id: '9a' }, { ...window, start: '' }, { ...window, stop: '00:00' }];
    for (const draft of cases) {
        let serverOk = true;
        try { parseScheduleChange('schedule_create', draft); } catch { serverOk = false; }
        assert.equal(Object.keys(client.validateDraft(draft, context)).length === 0, serverOk, JSON.stringify(draft));
    }
    assert.match(client.validateDraft({ ...window, id: 'taken' }, context).id, /already exists/);
    assert.equal(Object.keys(client.validateDraft({ ...window, id: 'taken' }, { ...context, editingId: 'taken' })).length, 0);
    const heavy = { schedules: Array.from({ length: 128 }, (_, index) => ({ id: `w${index}`, weekdays: ['Mon'], start: '22:00', stop: '06:30' })), editingId: null, deviceCount: 1 };
    assert.match(client.validateDraft(window, heavy).form, /256/);
    assert.deepEqual(client.validateDraft({ ...window, id: 'daytime', start: '08:00', stop: '15:00' }, { ...heavy, schedules: heavy.schedules.slice(1) }), {});
    assert.equal(client.overlaps({ weekdays: ['Mon'], start: '22:00', stop: '06:30' }, { weekdays: ['Tue'], start: '05:00', stop: '07:00' }), true);
    assert.equal(client.overlaps({ weekdays: ['Mon'], start: '22:00', stop: '06:30' }, { weekdays: ['Tue'], start: '06:30', stop: '07:00' }), false);
    assert.equal(client.overlaps({ weekdays: ['Sun'], start: '22:00', stop: '06:30' }, { weekdays: ['Mon'], start: '01:00', stop: '02:00' }), true);
});
