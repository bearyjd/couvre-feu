import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { DAYS } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';

/**
 * The windows of one schedule edit (roadmap item 2, S2a; flag schedules.editable, off; unverified on this router), in canonical form: sorted
 * by id, weekdays in week order, fixed key order. Only the shape is checked here (400 invalid_schedules); clock formats, ids, the 8-window cap
 * and the router limits are checked when the policy is built inside queue(). A whole-set replace: an empty array removes every window.
 */
export function scheduleRequestWindows(person: string, input: unknown): Schedule[] {
    if (!Array.isArray(input) || input.length > 64) throw new AppError(400, 'invalid_schedules');
    const windows = input.map(item => {
        let w: Record<string, unknown>;
        try { w = object(item, ['id', 'weekdays', 'start', 'stop']); } catch { throw new AppError(400, 'invalid_schedules'); }
        const days = w.weekdays;
        if (typeof w.id !== 'string' || typeof w.start !== 'string' || typeof w.stop !== 'string' || !Array.isArray(days) || days.length === 0 ||
            days.some(d => typeof d !== 'string' || !(DAYS as readonly string[]).includes(d)) || new Set(days).size !== days.length) throw new AppError(400, 'invalid_schedules');
        return {person, id: w.id, weekdays: DAYS.filter(d => days.includes(d)), start: w.start, stop: w.stop};
    });
    return windows.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}
