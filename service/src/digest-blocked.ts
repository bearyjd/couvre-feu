import { HEADLINE_CLASSES } from '../../shared/src/content-filter-classes.ts';
import { addDays, dayRange, localDay } from './content-filter-day.ts';
import type { ContentFilterCountsStore } from './content-filter-counts.ts';

/** The weekly digest's only counts-derived data: one household integer and how many of the seven days it covers. No child, class or day is kept. */
export interface BlockedWeek { readonly count: number; readonly daysCounted: number }
export const DIGEST_WEEK_DAYS = 7;
const HEADLINE: readonly string[] = HEADLINE_CLASSES;

/**
 * Plan 7.1, owner decisions O4 and O9: the Sunday..Saturday local days before the digest slot's Sunday (a deferred Monday send has the same slot, so the same week).
 * A day is counted only when every configured child has an `ok` answer for it (suspect_zero, logs_off and gaps are not counted); the integer sums headline
 * classes over counted days only. Reads the store, never NextDNS; the per-child rows stay inside this function.
 */
export function householdWeek(store: Pick<ContentFilterCountsStore, 'days'>, people: readonly string[], slot: number): BlockedWeek {
    const last = addDays(localDay(slot), -1), first = addDays(last, -(DIGEST_WEEK_DAYS - 1));
    const perChild = people.map(person => new Map(store.days(person, first, last).map(d => [d.day, d])));
    let count = 0, daysCounted = 0;
    for (const day of dayRange(first, last)) {
        const rows = perChild.map(days => days.get(day));
        if (rows.length === 0 || rows.some(row => row?.state !== 'ok')) continue;
        daysCounted++;
        for (const row of rows) for (const [code, queries] of Object.entries(row!.classes)) if (HEADLINE.includes(code)) count += queries!;
    }
    return Object.freeze({count, daysCounted});
}
