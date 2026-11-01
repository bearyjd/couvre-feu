import type { DigestCounts, PushMessage, PushResult } from './push-sender.ts';

/** Weekly counts-only digest: Sundays 18:00 America/New_York, held back during quiet hours 21:00-07:00 local (deferred, never dropped). */
export const DIGEST_ZONE = 'America/New_York';
export const DIGEST_HOUR = 18;
export const QUIET_START_HOUR = 21;
export const QUIET_END_HOUR = 7;
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

const formatter = new Intl.DateTimeFormat('en-US', {timeZone: DIGEST_ZONE, weekday: 'short', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'});
interface Local { year: number; month: number; day: number; hour: number; minute: number; weekday: number; offsetMinutes: number }
function local(epoch: number): Local {
    const parts = formatter.formatToParts(new Date(epoch * 1000)), n = (type: Intl.DateTimeFormatPartTypes) => parts.find(p => p.type === type)!.value;
    const [year, month, day, hour, minute] = [+n('year'), +n('month'), +n('day'), +n('hour'), +n('minute')];
    return {year, month, day, hour, minute, weekday: DAYS.indexOf(n('weekday')), offsetMinutes: (Date.UTC(year, month - 1, day, hour, minute) / 1000 - Math.floor(epoch / 60) * 60) / 60};
}
/** Epoch of a wall-clock time in the zone. Sunday 18:00 is never inside a DST gap or overlap (changes happen at 02:00), so two passes settle the offset. */
function zoned(year: number, month: number, day: number, hour: number): number {
    const wall = Date.UTC(year, month - 1, day, hour) / 1000;
    const first = wall - local(wall).offsetMinutes * 60;
    return wall - local(first).offsetMinutes * 60;
}
/** True from 21:00 up to (not including) 07:00 New York time. */
export function inQuietHours(epoch: number): boolean {
    const hour = local(epoch).hour;
    return hour >= QUIET_START_HOUR || hour < QUIET_END_HOUR;
}
/** The latest Sunday 18:00 New York time at or before `epoch`. Specified for modern dates only (years 1970 and later). Walks local calendar days, so a 23 or 25 hour day cannot skip or repeat one. */
export function latestDigestSlot(epoch: number): number {
    const today = local(epoch);
    for (let back = 0; back <= 7; back++) {
        const day = new Date(Date.UTC(today.year, today.month - 1, today.day - back));
        if (day.getUTCDay() !== 0) continue;
        const slot = zoned(day.getUTCFullYear(), day.getUTCMonth() + 1, day.getUTCDate(), DIGEST_HOUR);
        if (slot <= epoch) return slot;
    }
    throw new Error('digest_slot_not_found');
}

export interface DigestStateStore { read(): number; write(slot: number): void }
/** `deferralLogged` remembers the slot whose deferral was already logged, so a long quiet night logs it once. */
export interface DigestDeps { now: () => number; slot?: (epoch: number) => number; deferralLogged?: {slot: number}; counts: (from: number, to: number) => DigestCounts; send: (message: PushMessage) => Promise<PushResult>; state: DigestStateStore; log?: (line: string) => unknown }
export type DigestOutcome = 'not_due' | 'deferred' | 'sent' | 'failed';

/**
 * One scheduling pass. A slot not yet sent is due until it is sent; during quiet hours it waits (logged once per pass as a tag) and goes out at 07:00.
 * Missed slots (service down for weeks) collapse to the latest one. A failed send leaves the slot unsent, so the next pass retries it until the following slot supersedes it.
 */
export async function digestTick(deps: DigestDeps): Promise<DigestOutcome> {
    const now = deps.now(), slotOf = deps.slot ?? latestDigestSlot, slot = slotOf(now), log = deps.log ?? (line => process.stderr.write(line));
    if (deps.state.read() >= slot) return 'not_due';
    if (inQuietHours(now)) {
        if (deps.deferralLogged?.slot !== slot) { log('digest_deferred quiet_hours\n'); if (deps.deferralLogged) deps.deferralLogged.slot = slot; }
        return 'deferred';
    }
    // The window runs from the previous slot, so DST weeks (167 or 169 hours) neither double-count nor miss rows.
    const result = await deps.send({kind: 'digest', counts: deps.counts(slotOf(slot - 1), slot)});
    if (!result.ok) return 'failed';
    deps.state.write(slot);
    return 'sent';
}
