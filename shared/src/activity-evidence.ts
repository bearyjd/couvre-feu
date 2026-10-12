/** Offline fictional browser-focus arithmetic; no collector or authenticity claim. */
export interface ActivityInterval {
    start: number;
    end: number;
    assignmentEpoch: string | null;
    clockEpoch: string | null;
}
export interface FocusInterval extends ActivityInterval { domain: string }
export interface ActivityEvidenceInput {
    version: 1;
    source: 'synthetic-browser-focus';
    deviceId: string;
    query: {start: number; end: number};
    context: {assignmentEpoch: string | null; clockEpoch: string};
    coverage: ActivityInterval[];
    focus: FocusInterval[];
}
export type ActivityEvidenceReason = 'assignment_unknown' | 'assignment_epoch_mismatch'
    | 'clock_unknown' | 'clock_epoch_mismatch' | 'observer_coverage_missing' | 'domain_conflict';
export interface ActivityEvidenceResult {
    source: 'synthetic-browser-focus';
    scope: 'focused-browser';
    coverageState: 'complete' | 'partial' | 'unavailable';
    coveredMs: number;
    reasons: ActivityEvidenceReason[];
    activity: {
        estimatedObservedFocusedMs: number;
        domains: {domain: string; estimatedObservedFocusedMs: number}[];
    } | null;
}

const MAX_INTERVALS = 256, MAX_INPUT_BYTES = 65536, MAX_QUERY_MS = 86400000;
const REASONS: ActivityEvidenceReason[] = ['assignment_unknown', 'assignment_epoch_mismatch',
    'clock_unknown', 'clock_epoch_mismatch', 'observer_coverage_missing', 'domain_conflict'];

/** Stable generic error: never includes supplied metadata. */
export class ActivityEvidenceValidationError extends Error {
    constructor() {
        super('invalid_activity_evidence');
        this.name = 'ActivityEvidenceValidationError';
    }
}
function invalid(): never { throw new ActivityEvidenceValidationError(); }

function object(input: unknown, keys: string[]): Record<string, unknown> {
    if (input === null || typeof input !== 'object' || Object.getPrototypeOf(input) !== Object.prototype) invalid();
    const ownKeys = Reflect.ownKeys(input);
    if (ownKeys.length !== keys.length || ownKeys.some(key => typeof key !== 'string' || !keys.includes(key))) invalid();
    const result: Record<string, unknown> = {};
    for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(input, key);
        if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) invalid();
        result[key] = descriptor.value;
    }
    return result;
}
function intervals(input: unknown): unknown[] {
    if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype || input.length > MAX_INTERVALS) invalid();
    if (Reflect.ownKeys(input).length !== input.length + 1) invalid();
    const result: unknown[] = [];
    for (let i = 0; i < input.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(input, String(i));
        if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) invalid();
        result.push(descriptor.value);
    }
    return result;
}
function identifier(input: unknown, kind: 'device' | 'assignment' | 'clock'): string {
    if (typeof input !== 'string' || input.length > 53 || !new RegExp(`^synthetic-${kind}-[0-9a-f]{1,32}$`).test(input)) invalid();
    return input;
}
function epoch(input: unknown, kind: 'assignment' | 'clock'): string | null {
    return input === null ? null : identifier(input, kind);
}
function window(input: Record<string, unknown>): {start: number; end: number} {
    const {start, end} = input;
    if (typeof start !== 'number' || typeof end !== 'number' || !Number.isSafeInteger(start) || !Number.isSafeInteger(end)
        || start < 0 || end <= start) invalid();
    return {start, end};
}
function interval(input: unknown, focused: false): ActivityInterval;
function interval(input: unknown, focused: true): FocusInterval;
function interval(input: unknown, focused: boolean): ActivityInterval | FocusInterval {
    const value = object(input, ['start', 'end', 'assignmentEpoch', 'clockEpoch', ...(focused ? ['domain'] : [])]);
    const result = {...window(value), assignmentEpoch: epoch(value.assignmentEpoch, 'assignment'), clockEpoch: epoch(value.clockEpoch, 'clock')};
    if (!focused) return result;
    const domain = value.domain;
    if (typeof domain !== 'string' || domain.length > 128 || !domain.endsWith('.invalid')) invalid();
    const labels = domain.split('.');
    if (labels.length < 2 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) invalid();
    return {...result, domain};
}
function validate(input: unknown): ActivityEvidenceInput {
    const value = object(input, ['version', 'source', 'deviceId', 'query', 'context', 'coverage', 'focus']);
    if (value.version !== 1 || value.source !== 'synthetic-browser-focus') invalid();
    const query = window(object(value.query, ['start', 'end']));
    if (query.end - query.start > MAX_QUERY_MS) invalid();
    const context = object(value.context, ['assignmentEpoch', 'clockEpoch']);
    const coverage = intervals(value.coverage), focus = intervals(value.focus);
    if (coverage.length + focus.length > MAX_INTERVALS) invalid();
    const result: ActivityEvidenceInput = {
        version: 1, source: 'synthetic-browser-focus', deviceId: identifier(value.deviceId, 'device'), query,
        context: {assignmentEpoch: epoch(context.assignmentEpoch, 'assignment'), clockEpoch: identifier(context.clockEpoch, 'clock')},
        coverage: coverage.map(record => interval(record, false)), focus: focus.map(record => interval(record, true)),
    };
    // Every validated string is ASCII; serialized length equals UTF-8 bytes. No input toJSON is invoked.
    if (JSON.stringify(result).length > MAX_INPUT_BYTES) invalid();
    return result;
}

/** Evaluate supplied fictional intervals in one caller-declared assignment and uninterrupted clock epoch. */
export function evaluateActivityEvidence(input: unknown): ActivityEvidenceResult {
    let data: ActivityEvidenceInput;
    try { data = validate(input); } catch { invalid(); }
    const reasons = new Set<ActivityEvidenceReason>();
    if (data.context.assignmentEpoch === null) reasons.add('assignment_unknown');
    function clip<T extends ActivityInterval>(record: T): (T & {qualified: boolean})[] {
        const start = Math.max(record.start, data.query.start), end = Math.min(record.end, data.query.end);
        if (end <= start) return [];
        let qualified = true;
        if (record.assignmentEpoch === null || data.context.assignmentEpoch === null) {
            reasons.add('assignment_unknown'); qualified = false;
        } else if (record.assignmentEpoch !== data.context.assignmentEpoch) {
            reasons.add('assignment_epoch_mismatch'); qualified = false;
        }
        if (record.clockEpoch === null) {
            reasons.add('clock_unknown'); qualified = false;
        } else if (record.clockEpoch !== data.context.clockEpoch) {
            reasons.add('clock_epoch_mismatch'); qualified = false;
        }
        return [{...record, start, end, qualified}];
    }
    const coverage = data.coverage.flatMap(record => clip(record)), focus = data.focus.flatMap(record => clip(record));
    const edges = [...new Set([data.query.start, data.query.end, ...coverage.flatMap(record => [record.start, record.end]),
        ...focus.flatMap(record => [record.start, record.end])])].sort((a, b) => a - b);
    const totals = new Map<string, number>();
    let coveredMs = 0, estimatedObservedFocusedMs = 0;
    // At most 256 records and 514 edges. Atomic segments union duplicates and touching intervals naturally.
    for (let i = 1; i < edges.length; i++) {
        const start = edges[i - 1], end = edges[i];
        const observers = coverage.filter(record => record.start <= start && end <= record.end);
        if (!observers.length) { reasons.add('observer_coverage_missing'); continue; }
        const focused = focus.filter(record => record.start <= start && end <= record.end);
        if (observers.some(record => !record.qualified) || focused.some(record => !record.qualified)) continue;
        const domains = new Set(focused.map(record => record.domain));
        if (domains.size > 1) { reasons.add('domain_conflict'); continue; }
        const duration = end - start;
        coveredMs += duration;
        for (const domain of domains) {
            totals.set(domain, (totals.get(domain) ?? 0) + duration);
            estimatedObservedFocusedMs += duration;
        }
    }
    return {
        source: 'synthetic-browser-focus', scope: 'focused-browser',
        coverageState: coveredMs === 0 ? 'unavailable' : coveredMs === data.query.end - data.query.start ? 'complete' : 'partial',
        coveredMs, reasons: REASONS.filter(reason => reasons.has(reason)),
        activity: coveredMs === 0 ? null : {estimatedObservedFocusedMs,
            domains: [...totals].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
                .map(([domain, total]) => ({domain, estimatedObservedFocusedMs: total}))},
    };
}
