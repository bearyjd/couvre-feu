import { CLASS_CODES, HEADLINE_CLASSES, isClassCode } from '../../shared/src/content-filter-classes.ts';
import type { ClassCode } from '../../shared/src/content-filter-classes.ts';
import type { Store } from './db.ts';
import { addDays, dayRange, localDay, localDayBounds } from './content-filter-day.ts';
import { NextDnsError } from './nextdns-client.ts';
import type { NextDnsClient } from './nextdns-client.ts';

/** Daily counts older than this many local days are deleted (plan open decision O2; the roadmap's 8-week rule). */
export const COUNTS_RETENTION_DAYS = 56;
/** The last seven finished local days are kept current: the same window the weekly digest and the app read. */
export const COUNTS_WINDOW_DAYS = 7;
/** A day is read only this long after it ended, so NextDNS has settled its aggregation (lag UNVERIFIED, plan C0). */
export const COUNTS_SETTLE_SECONDS = 3 * 3600;
export const COUNTS_INTERVAL_SECONDS = 3600;
/** One pass stops (and the next tick continues) after this long; one call is bounded by its own deadline. */
export const COUNTS_PASS_BUDGET_MS = 60_000;
export const COUNTS_CALL_BUDGET_MS = 20_000;

export type DayState = 'ok' | 'unavailable' | 'logs_off' | 'suspect_zero';
/** Integers and fixed codes only: nothing from NextDNS but numbers, sorted into the closed class set before it gets here. */
export interface DayCounts {
    readonly day: string; readonly state: DayState; readonly total: number | null; readonly blocked: number | null;
    readonly classes: Readonly<Partial<Record<ClassCode, number>>>;
}
export interface WindowSums { readonly filterBlocked: number; readonly background: number; readonly okDays: number; readonly days: number }
const bad = (): never => { throw new Error('invalid_counts'); };
const count = (value: unknown): number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : bad();
const FINAL_STATES: readonly DayState[] = ['ok', 'logs_off', 'suspect_zero'];

/** Validated and frozen: the one shape that is written. A day is all or nothing. */
function checked(person: string, counts: DayCounts): DayCounts {
    if (typeof person !== 'string' || person.length < 1 || person.length > 64) bad();
    localDayBounds(counts.day);
    if (!FINAL_STATES.includes(counts.state)) bad();
    const classes = Object.entries(counts.classes).map(([code, queries]) => [isClassCode(code) ? code : bad(), count(queries)] as const).filter(([, queries]) => queries > 0);
    const hasTotals = counts.state !== 'logs_off';
    if (hasTotals ? count(counts.total) < count(counts.blocked) : counts.total !== null || counts.blocked !== null || classes.length > 0) bad();
    if (counts.state === 'suspect_zero' && (counts.total !== 0 || classes.length > 0)) bad();
    return Object.freeze({day: counts.day, state: counts.state, total: counts.total, blocked: counts.blocked,
        classes: Object.freeze(Object.fromEntries(CLASS_CODES.flatMap(code => classes.filter(([c]) => c === code))))});
}

/**
 * PRP phase C (plan 4.3): per child, per local day, per class, integers only. Rows are written by the fetcher; the app and the digest read them
 * and never call NextDNS. No raw id, name, domain, device or profile id exists here to store.
 */
export class ContentFilterCountsStore {
    private readonly store: Store;
    constructor(store: Store) { this.store = store; }

    /** Writes (or replaces) one finished day and its classes in one transaction, so a day is never half there. Repeating it changes nothing. */
    put(person: string, counts: DayCounts, now: number): void {
        const day = checked(person, counts), at = count(now);
        const write = () => {
            this.store.run(`INSERT INTO content_filter_day(person_id,day,state,total,blocked,attempts,fetched_at) VALUES(?,?,?,?,?,0,?)
                ON CONFLICT(person_id,day) DO UPDATE SET state=excluded.state,total=excluded.total,blocked=excluded.blocked,fetched_at=excluded.fetched_at`,
            person, day.day, day.state, day.total, day.blocked, at);
            this.store.run('DELETE FROM content_filter_day_class WHERE person_id=? AND day=?', person, day.day);
            for (const [code, queries] of Object.entries(day.classes)) this.store.run('INSERT INTO content_filter_day_class(person_id,day,class,queries) VALUES(?,?,?,?)', person, day.day, code, queries!);
        };
        if (this.store.db.isTransaction) write(); else this.store.transaction(write);
    }

    /** Records (or counts another try at) a gap. A day that already has an answer, ok or not, is final and is left exactly as it is. */
    markUnavailable(person: string, day: string, now: number): void {
        if (typeof person !== 'string' || person.length < 1 || person.length > 64) bad();
        localDayBounds(day);
        this.store.run(`INSERT INTO content_filter_day(person_id,day,state,attempts,fetched_at) VALUES(?,?,'unavailable',1,?)
            ON CONFLICT(person_id,day) DO UPDATE SET attempts=attempts+1,fetched_at=excluded.fetched_at WHERE state='unavailable'`, person, day, count(now));
    }

    /** Stored days from `from` to `to`, both inclusive, oldest first. A day with no row is simply absent. */
    days(person: string, from: string, to: string): readonly DayCounts[] {
        localDayBounds(from); localDayBounds(to);
        const classes = new Map<string, Partial<Record<ClassCode, number>>>();
        for (const r of this.store.all<{day: string; class: string; queries: number}>('SELECT day,class,queries FROM content_filter_day_class WHERE person_id=? AND day BETWEEN ? AND ?', person, from, to)) {
            classes.set(r.day, {...classes.get(r.day), [r.class]: r.queries});
        }
        return Object.freeze(this.store.all<{day: string; state: DayState; total: number | null; blocked: number | null}>(
            'SELECT day,state,total,blocked FROM content_filter_day WHERE person_id=? AND day BETWEEN ? AND ? ORDER BY day', person, from, to,
        ).map(r => Object.freeze({day: r.day, state: r.state, total: r.total, blocked: r.blocked, classes: Object.freeze({...classes.get(r.day)})})));
    }

    /** What a window adds up to: headline classes (what the filter blocked) and background classes, over ok days only. */
    weekSums(person: string, from: string, to: string): WindowSums {
        let filterBlocked = 0, background = 0, okDays = 0;
        for (const day of this.days(person, from, to)) {
            if (day.state !== 'ok') continue;
            okDays++;
            for (const [code, queries] of Object.entries(day.classes)) {
                if ((HEADLINE_CLASSES as readonly string[]).includes(code)) filterBlocked += queries!;
                else if (code === 'ads_trackers' || code === 'security') background += queries!;
            }
        }
        return Object.freeze({filterBlocked, background, okDays, days: dayRange(from, to).length});
    }

    /** One household integer over the given children (units are child-days: expectedDays is children times days). */
    householdBlocked(people: readonly string[], from: string, to: string): {blocked: number; okDays: number; expectedDays: number} {
        const sums = people.map(person => this.weekSums(person, from, to));
        return {blocked: sums.reduce((n, s) => n + s.filterBlocked, 0), okDays: sums.reduce((n, s) => n + s.okDays, 0), expectedDays: sums.reduce((n, s) => n + s.days, 0)};
    }

    /** Deletes every day before `oldestKeptDay` (classes go with it). Returns how many days went. */
    prune(oldestKeptDay: string): number {
        localDayBounds(oldestKeptDay);
        return Number(this.store.run('DELETE FROM content_filter_day WHERE day < ?', oldestKeptDay).changes);
    }
}

export interface ContentFilterCountsOptions {
    readonly client: Pick<NextDnsClient, 'getSettings' | 'getAnalyticsStatus' | 'getAnalyticsReasons'>;
    /** Person id to NextDNS profile id, from the manifest: a child without an entry is never read, and neither is the default profile. */
    readonly profiles: Readonly<Record<string, string>>;
    readonly store: ContentFilterCountsStore;
    /** Unix seconds. Injected, so day boundaries and DST are testable. */
    readonly now?: () => number;
    readonly monotonicMs?: () => number;
    readonly budgetMs?: number;
    /** Was this child's network active that day (activity feature)? A day with zero lookups is `suspect_zero` unless this says no. Absent or failing: suspect (unknown is not clean). */
    readonly wasOnline?: (person: string, day: string) => boolean;
}
const wholeDay = (day: string): {readonly from: number; readonly to: number} => localDayBounds(day);

/**
 * Plan 5.2: once an hour, for each child with a NextDNS profile, read each missing or unavailable finished local day of the last seven (never
 * today, never before 03:00 local on the next day), oldest first, and store integers by class. All or nothing per day. Failure of any kind is a
 * quiet gap (retried on the next pass while the day is in the window), never an alert, and nothing is logged. The default profile is never read.
 */
export class ContentFilterCounts {
    private readonly options: ContentFilterCountsOptions;
    private running = false;
    constructor(options: ContentFilterCountsOptions) { this.options = options; }

    async tick(): Promise<void> {
        if (this.running) return;
        this.running = true;
        try {
            const now = this.clock(), today = localDay(now), monotonic = this.options.monotonicMs ?? (() => performance.now());
            const deadline = monotonic() + (this.options.budgetMs ?? COUNTS_PASS_BUDGET_MS);
            try {
                for (const person of Object.keys(this.options.profiles)) {
                    if (await this.child(person, today, now, () => monotonic() >= deadline) === 'stop') break;
                }
            } catch { /* a store failure ends this pass only; the next hourly pass tries again */ }
            try { this.options.store.prune(addDays(today, -COUNTS_RETENTION_DAYS)); } catch { /* retention is retried next pass */ }
        } catch { /* an unreadable clock: nothing to do this pass */ } finally { this.running = false; }
    }

    private clock(): number { return (this.options.now ?? (() => Math.floor(Date.now() / 1000)))(); }

    /**
     * 'stop' ends the whole pass (rate limit, budget spent); 'next' moves on to the next child. A failed day is a gap and the child's newer days
     * are still tried; only an error that every later day of this child would share (key rejected, profile unknown) ends the child early.
     * The budget is checked between days, so a pass can overrun it by up to one day's calls: two calls, each bounded by COUNTS_CALL_BUDGET_MS (about 40 s).
     */
    private async child(person: string, today: string, now: number, spent: () => boolean): Promise<'stop' | 'next'> {
        const {store, client, profiles} = this.options, profile = profiles[person]!;
        const window = store.days(person, addDays(today, -COUNTS_WINDOW_DAYS), addDays(today, -1)), have = new Map(window.map(d => [d.day, d.state]));
        // A day with no answer, a gap, or a logs_off stamp is read (again): logs_off is retryable, so a stamp never hides a day logs covered.
        const wanted = dayRange(addDays(today, -COUNTS_WINDOW_DAYS), addDays(today, -1))
            .filter(day => now >= wholeDay(day).to + COUNTS_SETTLE_SECONDS && ['unavailable', 'logs_off'].includes(have.get(day) ?? 'unavailable'));
        if (wanted.length === 0) return 'next';
        const call = () => ({signal: AbortSignal.timeout(COUNTS_CALL_BUDGET_MS)});
        let logsOn: boolean;
        try { logsOn = (await client.getSettings(profile, call())).logs.enabled; } catch (error) { return this.fate(person, wanted[0]!, now, error) === 'stop' ? 'stop' : 'next'; }
        // Logs are off now. Only days after the newest answered day can be "logging was off"; an earlier day may have been logged (service down), so it stays a gap.
        const lastAnswered = window.filter(d => d.state === 'ok' || d.state === 'suspect_zero').map(d => d.day).sort().pop() ?? '';
        for (const day of wanted) {
            if (!logsOn) {
                try {
                    if (day > lastAnswered) store.put(person, {day, state: 'logs_off', total: null, blocked: null, classes: {}}, now);
                    else if (!have.has(day)) store.markUnavailable(person, day, now);
                } catch { /* the next pass sees the day as it was */ }
                continue;
            }
            if (spent()) return 'stop';
            try {
                const range = wholeDay(day);
                // Both answers or neither: nothing is written until the second one is in.
                const status = await client.getAnalyticsStatus(profile, range, call()), reasons = await client.getAnalyticsReasons(profile, range, call());
                // A day with no lookups at all reads like a clean day and may be a bypass, a paused filter or the plan limit: it is suspect
                // unless the activity callback (when wired) says the child's network was quiet that day.
                const state = status.total === 0 && this.online(person, day) ? 'suspect_zero' : 'ok';
                store.put(person, {day, state, total: status.total, blocked: status.blocked, classes: Object.fromEntries(reasons.map(r => [r.class, r.queries]))}, now);
            } catch (error) {
                const fate = this.fate(person, day, now, error);
                if (fate !== 'continue') return fate;
            }
        }
        return 'next';
    }

    /** Unknown means suspect: no callback, or one that fails, says the child may have been online. */
    private online(person: string, day: string): boolean {
        const wasOnline = this.options.wasOnline;
        if (wasOnline === undefined) return true;
        try { return wasOnline(person, day); } catch { return true; }
    }

    /** Records the gap (best effort) and says what to do next: a rate limit ends the pass, a rejected key or unknown profile ends this child, anything else goes on to the next day. */
    private fate(person: string, day: string, now: number, error: unknown): 'stop' | 'next' | 'continue' {
        try { this.options.store.markUnavailable(person, day, now); } catch { /* the next pass sees the day as missing */ }
        if (!(error instanceof NextDnsError)) return 'continue';
        return error.code === 'rate_limited' ? 'stop' : error.code === 'unauthorized' || error.code === 'not_found' ? 'next' : 'continue';
    }
}

/** Starts the hourly pass; the first one runs after `firstDelayMs`. The timers never keep the process alive. Returns a stop function. */
export function startContentFilterCounts(counts: ContentFilterCounts, intervalMs = COUNTS_INTERVAL_SECONDS * 1000, firstDelayMs = 300_000): () => void {
    const run = () => { counts.tick().catch(() => undefined); };
    const first = setTimeout(run, firstDelayMs), every = setInterval(run, intervalMs);
    first.unref(); every.unref();
    return () => { clearTimeout(first); clearInterval(every); };
}
