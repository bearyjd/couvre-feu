import type { ActivityDayDTO } from '../../shared/src/contracts.ts';

export const BUCKET_SECONDS = 60;
export const REPORT_DAYS = 8;
/** A minute counts as online when the child's devices moved more than this many bytes (tx+rx) in it. A heuristic, not calibrated. */
export const ACTIVE_MINUTE_THRESHOLD_BYTES = 30000;
/** A device covers a minute only when valid sample intervals overlap it for at least this many seconds. */
export const COVERED_MINUTE_SECONDS = 30;
const MAX_GAPS = 8;
/** One sample with a valid delta; it describes counter movement during the interval (t - interval, t]. */
export interface SampleRow { t: number; mac: string; interval: number; bytes: number; blocked: number; offload_rank: number }
const OFFLOADS = ['off', 'unknown', 'on'] as const;
interface Cell { covered: number; bytes: number }

/**
 * Pure evaluation of up to REPORT_DAYS UTC days. Each sample interval is split across the minutes it overlaps, with bytes
 * apportioned by overlap. A minute is covered only if EVERY currently assigned device has coverage; anything else is
 * unknown and is never converted into zero activity.
 */
export function buildDays(rows: readonly SampleRow[], macs: readonly string[], now: number, retentionDays: number): ActivityDayDTO[] {
    const byMinute = new Map<number, Map<string, Cell>>();
    for (const row of rows) {
        if (!macs.includes(row.mac) || row.interval <= 0) continue;
        const begin = row.t - row.interval;
        for (let minute = Math.floor(begin / BUCKET_SECONDS); minute * BUCKET_SECONDS < row.t; minute++) {
            const overlap = Math.min(row.t, (minute + 1) * BUCKET_SECONDS) - Math.max(begin, minute * BUCKET_SECONDS);
            let devices = byMinute.get(minute);
            if (!devices) byMinute.set(minute, devices = new Map());
            const cell = devices.get(row.mac) ?? {covered: 0, bytes: 0};
            cell.covered += overlap; cell.bytes += row.bytes * overlap / row.interval;
            devices.set(row.mac, cell);
        }
    }
    const today = Math.floor(now / 86400), floorMinute = Math.ceil((now - retentionDays * 86400) / BUCKET_SECONDS), lastMinute = Math.floor(now / BUCKET_SECONDS);
    const days: ActivityDayDTO[] = [];
    for (let index = REPORT_DAYS - 1; index >= 0; index--) {
        const start = (today - index) * 86400, startMinute = Math.max(start / BUCKET_SECONDS, floorMinute), endMinute = Math.min(start / BUCKET_SECONDS + 1440, lastMinute);
        let covered = 0, online = 0, expected = 0, bytes = 0, blocked = 0, observed = false, rank = -1;
        const runs: {start: number; end: number}[] = [];
        for (const row of rows) {
            if (!macs.includes(row.mac) || row.t <= start || row.t > start + 86400) continue;
            observed = true; bytes += row.bytes; blocked += row.blocked; rank = Math.max(rank, row.offload_rank);
        }
        for (let minute = startMinute; minute < endMinute; minute++) {
            expected++;
            const devices = byMinute.get(minute);
            if (macs.length > 0 && devices && macs.every(mac => (devices.get(mac)?.covered ?? 0) >= COVERED_MINUTE_SECONDS)) {
                covered++;
                if ([...devices.values()].reduce((sum, cell) => sum + cell.bytes, 0) > ACTIVE_MINUTE_THRESHOLD_BYTES) online++;
            } else {
                const last = runs[runs.length - 1];
                if (last && last.end === minute * BUCKET_SECONDS) last.end += BUCKET_SECONDS; else runs.push({start: minute * BUCKET_SECONDS, end: (minute + 1) * BUCKET_SECONDS});
            }
        }
        const longest = [...runs].sort((a, b) => (b.end - b.start) - (a.end - a.start)).slice(0, MAX_GAPS).sort((a, b) => a.start - b.start);
        const offload = rank < 0 ? null : OFFLOADS[rank];
        days.push({date: new Date(start * 1000).toISOString().slice(0, 10), start, end: Math.max(start, endMinute * BUCKET_SECONDS), expectedMinutes: expected, coveredMinutes: covered, unknownMinutes: expected - covered,
            coverage: covered === 0 ? 'none' : covered === expected ? 'complete' : 'partial',
            estimatedOnlineMinutes: covered === 0 ? null : online, totalBytes: observed ? bytes : null, blockedAttempts: observed ? blocked : null,
            offload, possiblyUndercounted: offload === 'on' || offload === 'unknown', gaps: longest, gapsTruncated: runs.length > MAX_GAPS});
    }
    return days;
}
