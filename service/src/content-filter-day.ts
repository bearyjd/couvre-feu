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

const parts = (epochSeconds: number) => Object.fromEntries(fmt.formatToParts(new Date(epochSeconds * 1000)).map(x => [x.type, Number(x.value)]));
const iso = (y: number, m: number, d: number): string => `${String(y).padStart(4, '0')}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;

/** The local calendar day `YYYY-MM-DD` that contains the instant (Unix seconds). Throws RangeError on a non-finite instant. */
export function localDay(epochSeconds: number): string {
    if (!Number.isFinite(epochSeconds)) throw new RangeError('invalid_instant');
    const p = parts(epochSeconds);
    return iso(p.year!, p.month!, p.day!);
}

/** `day` moved by `delta` calendar days (negative goes back). Pure calendar arithmetic, so DST never matters. Throws RangeError on a non-day. */
export function addDays(day: string, delta: number): string {
    localDayBounds(day);
    const next = new Date(Date.UTC(Number(day.slice(0, 4)), Number(day.slice(5, 7)) - 1, Number(day.slice(8, 10)) + delta));
    return iso(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate());
}

/** Every local day from `from` to `to`, both inclusive, oldest first; empty when `to` is before `from`. */
export function dayRange(from: string, to: string): readonly string[] {
    localDayBounds(from); localDayBounds(to);
    const days: string[] = [];
    for (let day = from; day <= to; day = addDays(day, 1)) days.push(day);
    return Object.freeze(days);
}
