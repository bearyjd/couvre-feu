import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { DAYS } from '../../shared/src/router-schema.ts';
import type { RouterPolicy, Schedule } from '../../shared/src/router-schema.ts';
import type { IntegrationManifest } from './integration-config.ts';
import { childrenSeam } from './integration-children.ts';
import { MAX_WINDOWS_PER_CHILD } from './integration-schedule-store.ts';

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

/**
 * The queue() build step shared by every schedule edit: the child must be on the router (check 1), at most 8 windows (check 2) and the router
 * limits and main's validation (checks 3 and 4, via withScheduleWindows). `failure` is an earlier error (a fold refusal) raised after check 1.
 */
export function scheduleBuild(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs'>, person: string, windows: readonly Schedule[], failure: unknown = null): RouterPolicy {
    if (!base.people.some(p => p.id === person)) throw new AppError(409, 'person_has_no_enrolled_device');
    if (failure) throw failure;
    if (windows.length > MAX_WINDOWS_PER_CHILD) throw new AppError(409, 'schedule_payload_inadmissible');
    try { return childrenSeam.withScheduleWindows(base, config, person, windows); } catch { throw new AppError(409, 'schedule_payload_inadmissible'); }
}
