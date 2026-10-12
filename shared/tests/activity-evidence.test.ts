import test from 'node:test';
import assert from 'node:assert/strict';
import { ActivityEvidenceValidationError, evaluateActivityEvidence } from '../src/activity-evidence.ts';
import type { ActivityEvidenceInput, ActivityInterval, FocusInterval } from '../src/activity-evidence.ts';

const assignment = 'synthetic-assignment-01', clock = 'synthetic-clock-01';
function coverage(start: number, end: number, overrides: Partial<ActivityInterval> = {}): ActivityInterval {
    return {start, end, assignmentEpoch: assignment, clockEpoch: clock, ...overrides};
}
function focus(start: number, end: number, domain = 'study.example.invalid', overrides: Partial<FocusInterval> = {}): FocusInterval {
    return {...coverage(start, end), domain, ...overrides};
}
function sample(overrides: Partial<ActivityEvidenceInput> = {}): ActivityEvidenceInput {
    return {version: 1, source: 'synthetic-browser-focus', deviceId: 'synthetic-device-01',
        query: {start: 0, end: 1000}, context: {assignmentEpoch: assignment, clockEpoch: clock},
        coverage: [coverage(0, 1000)], focus: [], ...overrides};
}
function reject(input: unknown): void {
    assert.throws(() => evaluateActivityEvidence(input), error => error instanceof ActivityEvidenceValidationError
        && error.name === 'ActivityEvidenceValidationError' && error.message === 'invalid_activity_evidence');
}
function conserved(input: ActivityEvidenceInput): void {
    const result = evaluateActivityEvidence(input);
    assert.ok(result.coveredMs >= 0 && result.coveredMs <= input.query.end - input.query.start);
    if (result.activity) {
        assert.ok(result.activity.estimatedObservedFocusedMs <= result.coveredMs);
        assert.equal(result.activity.domains.reduce((total, item) => total + item.estimatedObservedFocusedMs, 0), result.activity.estimatedObservedFocusedMs);
    } else assert.equal(result.coveredMs, 0);
}

test('positive clipping reports only covered focused time and sorted synthetic domains', () => {
    const input = sample({query: {start: 100, end: 1000}, coverage: [coverage(0, 1500)],
        focus: [focus(0, 200, 'study.example.invalid'), focus(800, 1200, 'games.example.invalid')]});
    assert.deepEqual(evaluateActivityEvidence(input), {source: 'synthetic-browser-focus', scope: 'focused-browser',
        coverageState: 'complete', coveredMs: 900, reasons: [], activity: {estimatedObservedFocusedMs: 300,
            domains: [{domain: 'games.example.invalid', estimatedObservedFocusedMs: 200}, {domain: 'study.example.invalid', estimatedObservedFocusedMs: 100}]}});
    conserved(input);
});

test('explicit observer coverage with no focus is known browser-idle zero; missing coverage is null', () => {
    assert.deepEqual(evaluateActivityEvidence(sample()).activity, {estimatedObservedFocusedMs: 0, domains: []});
    assert.equal(evaluateActivityEvidence(sample()).coverageState, 'complete');
    const missing = evaluateActivityEvidence(sample({coverage: [], focus: [focus(0, 1000)]}));
    assert.equal(missing.activity, null); assert.equal(missing.coveredMs, 0); assert.equal(missing.coverageState, 'unavailable');
    assert.deepEqual(missing.reasons, ['observer_coverage_missing']);
    const partialIdle = evaluateActivityEvidence(sample({coverage: [coverage(100, 300)]}));
    assert.equal(partialIdle.coverageState, 'partial'); assert.equal(partialIdle.coveredMs, 200);
    assert.deepEqual(partialIdle.activity, {estimatedObservedFocusedMs: 0, domains: []});
});

test('coverage union, gaps, focus duplicates, overlap and touching intervals conserve exact arithmetic', () => {
    const input = sample({coverage: [coverage(0, 300), coverage(200, 600), coverage(700, 1000), coverage(0, 300)],
        focus: [focus(0, 250), focus(200, 500), focus(500, 550), focus(200, 500), focus(700, 850),
            focus(850, 1200, 'games.example.invalid')]});
    const result = evaluateActivityEvidence(input);
    assert.equal(result.coveredMs, 900); assert.equal(result.coverageState, 'partial');
    assert.deepEqual(result.reasons, ['observer_coverage_missing']);
    assert.deepEqual(result.activity, {estimatedObservedFocusedMs: 850,
        domains: [{domain: 'games.example.invalid', estimatedObservedFocusedMs: 150}, {domain: 'study.example.invalid', estimatedObservedFocusedMs: 700}]});
    conserved(input);
});

test('different-domain contradictions remove ambiguous segments from coverage and retain valid portions', () => {
    const input = sample({focus: [focus(100, 700), focus(400, 900, 'games.example.invalid')]});
    const result = evaluateActivityEvidence(input);
    assert.equal(result.coveredMs, 700); assert.equal(result.coverageState, 'partial');
    assert.deepEqual(result.reasons, ['domain_conflict']);
    assert.deepEqual(result.activity, {estimatedObservedFocusedMs: 500,
        domains: [{domain: 'games.example.invalid', estimatedObservedFocusedMs: 200}, {domain: 'study.example.invalid', estimatedObservedFocusedMs: 300}]});
    conserved(input);
    const ambiguous = evaluateActivityEvidence(sample({focus: [focus(0, 1000), focus(0, 1000, 'games.example.invalid')]}));
    assert.equal(ambiguous.coverageState, 'unavailable'); assert.equal(ambiguous.coveredMs, 0); assert.equal(ambiguous.activity, null);
    assert.deepEqual(ambiguous.reasons, ['domain_conflict']);
});

test('half-open boundaries and query-first clipping prevent external conflicts or mismatches poisoning evidence', () => {
    const input = sample({query: {start: 100, end: 200}, coverage: [coverage(0, 300), coverage(200, 300, {assignmentEpoch: null})],
        focus: [focus(0, 100, 'games.example.invalid'), focus(100, 150), focus(150, 200, 'games.example.invalid'),
            focus(200, 300), focus(200, 300, 'games.example.invalid', {clockEpoch: 'synthetic-clock-02'})]});
    const result = evaluateActivityEvidence(input);
    assert.equal(result.coverageState, 'complete'); assert.equal(result.coveredMs, 100); assert.deepEqual(result.reasons, []);
    assert.equal(result.activity?.estimatedObservedFocusedMs, 100);
    assert.equal(evaluateActivityEvidence(sample({coverage: [coverage(1000, 1100)], focus: [focus(1000, 1100)]})).activity, null);
    conserved(input);
});

test('assignment and clock qualification exclude every disqualified segment, including focus under valid idle coverage', () => {
    const variants: [Partial<ActivityInterval>, string][] = [
        [{assignmentEpoch: null}, 'assignment_unknown'], [{assignmentEpoch: 'synthetic-assignment-02'}, 'assignment_epoch_mismatch'],
        [{clockEpoch: null}, 'clock_unknown'], [{clockEpoch: 'synthetic-clock-02'}, 'clock_epoch_mismatch'],
    ];
    for (const [metadata, reason] of variants) {
        for (const input of [sample({coverage: [coverage(0, 1000, metadata)]}),
            sample({coverage: [coverage(0, 1000), coverage(0, 1000, metadata)]}), sample({focus: [focus(0, 1000, undefined, metadata)]})]) {
            const result = evaluateActivityEvidence(input);
            assert.equal(result.activity, null); assert.equal(result.coveredMs, 0); assert.equal(result.coverageState, 'unavailable');
            assert.deepEqual(result.reasons, [reason]); conserved(input);
        }
        const partial = sample({focus: [focus(100, 500), focus(400, 700, undefined, metadata)]});
        const result = evaluateActivityEvidence(partial);
        assert.equal(result.coveredMs, 700); assert.equal(result.coverageState, 'partial');
        assert.equal(result.activity?.estimatedObservedFocusedMs, 300); assert.deepEqual(result.reasons, [reason]);
        conserved(partial);
    }
});

test('caller context cannot reattribute historical epochs; unknown assignment cannot claim idle', () => {
    for (const input of [sample({context: {assignmentEpoch: null, clockEpoch: clock}}),
        sample({context: {assignmentEpoch: 'synthetic-assignment-02', clockEpoch: clock}}),
        sample({context: {assignmentEpoch: assignment, clockEpoch: 'synthetic-clock-02'}})]) {
        assert.equal(evaluateActivityEvidence(input).activity, null); assert.equal(evaluateActivityEvidence(input).coveredMs, 0);
    }
    const afterReassignment = sample({context: {assignmentEpoch: 'synthetic-assignment-02', clockEpoch: clock},
        coverage: [coverage(0, 500), coverage(500, 1000, {assignmentEpoch: 'synthetic-assignment-02'})],
        focus: [focus(0, 500), focus(500, 800, 'games.example.invalid', {assignmentEpoch: 'synthetic-assignment-02'})]});
    const result = evaluateActivityEvidence(afterReassignment);
    assert.equal(result.coveredMs, 500); assert.equal(result.activity?.estimatedObservedFocusedMs, 300);
    assert.deepEqual(result.reasons, ['assignment_epoch_mismatch']); conserved(afterReassignment);
});

test('fixed permutations and retransmission duplicates produce byte-identical results without mutating frozen input', () => {
    const input = sample({coverage: [coverage(0, 600), coverage(700, 1000), coverage(200, 400, {clockEpoch: null})],
        focus: [focus(100, 500), focus(300, 800, 'games.example.invalid'), focus(700, 900, 'video.example.invalid'),
            focus(800, 1000, undefined, {assignmentEpoch: null})]});
    const before = JSON.stringify(input), expected = evaluateActivityEvidence(input);
    for (const coverageOrder of [input.coverage, [...input.coverage].reverse(), [input.coverage[1], input.coverage[2], input.coverage[0]]]) {
        for (const focusOrder of [input.focus, [...input.focus].reverse(), [input.focus[2], input.focus[0], input.focus[3], input.focus[1]]]) {
            assert.deepEqual(evaluateActivityEvidence({...input, coverage: coverageOrder, focus: focusOrder}), expected);
            assert.deepEqual(evaluateActivityEvidence({...input, coverage: [...coverageOrder, ...coverageOrder], focus: [...focusOrder, ...focusOrder]}), expected);
        }
    }
    function freeze(value: unknown): void {
        if (value !== null && typeof value === 'object') { for (const nested of Object.values(value)) freeze(nested); Object.freeze(value); }
    }
    freeze(input); assert.deepEqual(evaluateActivityEvidence(input), expected); assert.equal(JSON.stringify(input), before);
    assert.equal(JSON.stringify(expected).includes(input.deviceId), false);
    assert.equal(JSON.stringify(expected).includes(assignment), false); assert.equal(JSON.stringify(expected).includes(clock), false);
    conserved(input);
});

test('runtime validation rejects exact-shape, version, provenance, identity and epoch violations generically', () => {
    const input = sample();
    for (const malformed of [null, [], {}, {...input, version: 2}, {...input, source: 'browser-focus'},
        {...input, personName: 'PRIVATE'}, {...input, deviceId: 'PRIVATE'}, {...input, deviceId: '02:11:22:33:44:55'},
        {...input, deviceId: `synthetic-device-${'a'.repeat(33)}`}, {...input, context: {...input.context, clockEpoch: null}},
        {...input, context: {assignmentEpoch: assignment}}, {...input, context: {...input.context, assignmentEpoch: 'adult-profile'}},
        {...input, coverage: [{...coverage(0, 1000), url: 'PRIVATE'}]}, {...input, coverage: [{start: 0, end: 1000}]},
        {...input, focus: [{...focus(0, 1000), clockEpoch: undefined}]}, {...input, query: {...input.query, extra: true}}]) reject(malformed);
    const accessor = {...input}; Object.defineProperty(accessor, 'deviceId', {enumerable: true, get() { throw new Error('PRIVATE'); }}); reject(accessor);
    reject({...input, [Symbol('PRIVATE')]: true});
    reject(new Proxy(input, {getPrototypeOf() { throw new Error('PRIVATE'); }}));
    const hidden = {...input}; Object.defineProperty(hidden, 'hidden', {value: 'PRIVATE'}); reject(hidden);
    const sparse = new Array(1); reject({...input, focus: sparse});
    const extra = [coverage(0, 1000)]; Object.defineProperty(extra, 'extra', {value: true}); reject({...input, coverage: extra});
    const arrayAccessor = [coverage(0, 1000)]; Object.defineProperty(arrayAccessor, '0', {enumerable: true, get() { throw new Error('PRIVATE'); }});
    reject({...input, coverage: arrayAccessor});
});

test('only bounded normalized .invalid hostnames are accepted; full URLs and private metadata are rejected', () => {
    for (const domain of ['example.com', 'invalid', '.invalid', 'EXAMPLE.invalid', 'https://study.example.invalid',
        'study.example.invalid/path', 'study.example.invalid?token=PRIVATE', 'study.example.invalid#title',
        'study.example.invalid:443', 'study..invalid', '-study.invalid', 'study-.invalid', 'study.invalid.',
        'study_thing.invalid', 'é.invalid', `${'a'.repeat(64)}.invalid`, `${'a'.repeat(63)}.${'b'.repeat(63)}.invalid`]) {
        reject(sample({focus: [focus(0, 1000, domain)]}));
    }
    assert.equal(evaluateActivityEvidence(sample({focus: [focus(0, 1000, 'a-1.invalid')]})).activity?.estimatedObservedFocusedMs, 1000);
});

test('all payload records are validated even outside query and when qualification is unknown', () => {
    reject(sample({focus: [focus(1000, 2000, 'https://PRIVATE')]}));
    reject(sample({context: {assignmentEpoch: null, clockEpoch: clock}, coverage: [coverage(1000, 2000, {clockEpoch: 'PRIVATE'})]}));
    reject(sample({coverage: [], focus: [focus(1000, 2000, undefined, {start: NaN})]}));
});

test('safe integer times, strict positive windows, 24-hour query, aggregate count and total input bounds', () => {
    for (const bad of [-1, NaN, Infinity, -Infinity, 0.5, Number.MAX_SAFE_INTEGER + 1, '0', null]) {
        reject(sample({query: {start: bad as number, end: 1000}}));
        reject(sample({coverage: [{...coverage(0, 1000), start: bad as number}]}));
        reject(sample({focus: [{...focus(0, 1000), end: bad as number}]}));
    }
    reject(sample({query: {start: 1000, end: 1000}})); reject(sample({query: {start: 1001, end: 1000}}));
    reject(sample({coverage: [coverage(10, 10)]})); reject(sample({focus: [focus(10, 9)]}));
    reject(sample({query: {start: 0, end: 86400001}}));
    const high = Number.MAX_SAFE_INTEGER;
    assert.equal(evaluateActivityEvidence(sample({query: {start: high - 86400000, end: high}, coverage: [coverage(high - 86400000, high)],
        focus: [focus(high - 10, high)]})).activity?.estimatedObservedFocusedMs, 10);
    const boundary = sample({coverage: Array.from({length: 128}, () => coverage(0, 1000)), focus: Array.from({length: 128}, () => focus(0, 1000))});
    assert.equal(evaluateActivityEvidence(boundary).activity?.estimatedObservedFocusedMs, 1000);
    reject({...boundary, focus: [...boundary.focus, focus(0, 1000)]});
    reject(sample({coverage: Array.from({length: 257}, () => coverage(0, 1000))}));
    const longAssignment = `synthetic-assignment-${'a'.repeat(32)}`, longClock = `synthetic-clock-${'b'.repeat(32)}`;
    const oversized = sample({coverage: [coverage(0, 1000)], focus: Array.from({length: 255}, () =>
        focus(0, 1000, `${'a'.repeat(63)}.${'b'.repeat(56)}.invalid`, {assignmentEpoch: longAssignment, clockEpoch: longClock}))});
    assert.ok(JSON.stringify(oversized).length > 65536); reject(oversized);
});
