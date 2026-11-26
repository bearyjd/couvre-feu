import test from 'node:test';
import assert from 'node:assert/strict';

type Part = { weekdays: string[]; start: string; stop: string };
const templates = await import(new URL('../../web/public/schedule-templates.js', import.meta.url).href) as {
    BANDS: string[]; PARTS: string[]; templatePart: (band: string, part: string) => Part | null;
};
const editor = await import(new URL('../../web/public/schedule-editor.js', import.meta.url).href) as {
    validateDraft: (draft: unknown, context: unknown) => Record<string, string>; overlaps: (a: unknown, b: unknown) => boolean;
    BAND_LABELS: Record<string, string>; PART_LABELS: Record<string, string>;
};
const EXPECTED: Record<string, [string, string, string, string]> = {
    under10: ['19:30', '07:00', '20:30', '07:30'], '10to12': ['20:30', '07:00', '21:30', '08:00'],
    '13to15': ['21:30', '07:00', '22:30', '08:00'], '16to17': ['22:30', '07:00', '23:30', '08:00'],
};

test('four bands with a school-night and a weekend part carrying the D1 times', () => {
    assert.deepEqual(templates.BANDS, Object.keys(EXPECTED));
    assert.deepEqual(templates.PARTS, ['schoolNight', 'weekend']);
    for (const [band, [nightStart, nightStop, endStart, endStop]] of Object.entries(EXPECTED)) {
        assert.deepEqual(templates.templatePart(band, 'schoolNight'), { weekdays: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu'], start: nightStart, stop: nightStop });
        assert.deepEqual(templates.templatePart(band, 'weekend'), { weekdays: ['Fri', 'Sat'], start: endStart, stop: endStop });
    }
});

test('every band and part has a chooser label', () => {
    assert.deepEqual(Object.keys(editor.BAND_LABELS), templates.BANDS);
    assert.deepEqual(Object.keys(editor.PART_LABELS), templates.PARTS);
});

test('every part crosses midnight, validates, and a band parts never overlap', () => {
    for (const band of templates.BANDS) {
        const parts = templates.PARTS.map((part) => templates.templatePart(band, part) as Part);
        for (const part of parts) {
            assert.ok(part.start > part.stop, `${band} crosses midnight`);
            assert.deepEqual(editor.validateDraft({ id: 'window_1', ...part }, { schedules: [], editingId: null, deviceCount: 1 }), {});
        }
        assert.equal(editor.overlaps(parts[0], parts[1]), false, band);
    }
});

test('unknown band or part is null; results are new frozen objects', () => {
    for (const [band, part] of [['nope', 'weekend'], ['under10', 'nope'], ['toString', 'weekend'], ['under10', 'constructor'], ['', ''], [undefined, undefined]]) {
        assert.equal(templates.templatePart(band as string, part as string), null, `${band}/${part}`);
    }
    const first = templates.templatePart('under10', 'weekend') as Part, second = templates.templatePart('under10', 'weekend') as Part;
    assert.notEqual(first, second);
    assert.ok(Object.isFrozen(first) && Object.isFrozen(first.weekdays));
    assert.throws(() => { 'use strict'; (first.weekdays as string[]).push('Mon'); }, TypeError);
    assert.equal((templates.templatePart('under10', 'weekend') as Part).weekdays.length, 2);
});
