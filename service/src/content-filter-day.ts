/** The digest's zone (phase-c-digest plan section 0): counts are per America/New_York calendar day. */
export const STATS_TIME_ZONE = 'America/New_York';

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;
const fmt = new Intl.DateTimeFormat('en-US', { timeZone: STATS_TIME_ZONE, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric',
    hour: 'numeric', minute: 'numeric', second: 'numeric' });

/** Offset of the zone from UTC, in ms, at the instant `ms`. */
function offsetAt(ms: number): number {
    const p = Object.fromEntries(fmt.formatToParts(new Date(ms)).map(x => [x.type, Number(x.value)]));
    return Date.UTC(p.year!, p.month! - 1, p.day!, p.hour!, p.minute!, p.second!) - Math.floor(ms / 1000) * 1000;
}
/** Epoch seconds of 00:00 local time on y-m-d. Local midnight never falls in a DST gap in this zone (changes happen at 02:00). */
function localMidnight(y: number, m: number, d: number): number {
    const wall = Date.UTC(y, m - 1, d);
    const first = wall - offsetAt(wall);
    return (wall - offsetAt(first)) / 1000;
}

/** [from, to) in Unix seconds of one local calendar day `YYYY-MM-DD`; a DST day is 23 or 25 hours. Throws RangeError on a non-day. */
export function localDayBounds(day: string): { readonly from: number; readonly to: number } {
    const m = DAY.exec(typeof day === 'string' ? day : '');
    if (!m) throw new RangeError('invalid_day');
    const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const check = new Date(Date.UTC(y, mo - 1, d));
    if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d) throw new RangeError('invalid_day');
    const next = new Date(Date.UTC(y, mo - 1, d + 1));
    return Object.freeze({ from: localMidnight(y, mo, d), to: localMidnight(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate()) });
}
