import { DAYS } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import { createHash } from 'node:crypto';
import { canonicalSchedules } from './integration-schedule-store.ts';

/**
 * Pure classifier for schedule edits (roadmap item 2, S2b; flag schedules.editable, off; unverified on this router). One child's window
 * sets only; it reads clocks and weekdays, never names.
 */
/** sha256 of the canonical (sorted, week-ordered) form of one child's window set: what a step-up is bound to. */
export const windowSetDigest = (windows: readonly Schedule[]): string => createHash('sha256').update(canonicalSchedules(windows)).digest('hex');
const minutes =(clock: string): number => Number(clock.slice(0, 2)) * 60 + Number(clock.slice(3));
/** Every minute of the week (Mon=0) that some window blocks; a window that crosses midnight runs into the next day (Sun into Mon). */
export function coveredMinutes(windows: readonly Schedule[]): Set<number> {
    const set = new Set<number>(), week = 7 * 1440;
    for (const w of windows) for (const day of w.weekdays) {
        const from = DAYS.indexOf(day) * 1440 + minutes(w.start), to = DAYS.indexOf(day) * 1440 + minutes(w.stop) + (minutes(w.stop) > minutes(w.start) ? 0 : 1440);
        for (let m = from; m < to; m++) set.add(m % week);
    }
    return set;
}
/**
 * Loosening = the new set blocks less than the committed set anywhere: a window id that is gone (deleting the last window included, and a
 * redundant window too: fail closed), or any minute of the week that was blocked and is not. A shift that frees some minutes while
 * blocking others is loosening. Adding a window or blocking more is not.
 */
export function isLoosening(before: readonly Schedule[], after: readonly Schedule[]): boolean {
    const kept = new Set(after.map(w => w.id));
    if (before.some(w => !kept.has(w.id))) return true;
    const now = coveredMinutes(after);
    for (const m of coveredMinutes(before)) if (!now.has(m)) return true;
    return false;
}
