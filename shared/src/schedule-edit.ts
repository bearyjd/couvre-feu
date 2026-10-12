import { AppError } from './errors.ts';
import { object } from './json.ts';
import { DAYS, clock, id } from './router-schema.ts';
import type { Day, Schedule } from './router-schema.ts';

export type ScheduleAction = 'schedule_create' | 'schedule_update' | 'schedule_delete';
export interface ScheduleWindow {
    id: string;
    weekdays: Day[];
    start: string;
    stop: string;
}
export type ScheduleChange = {
    action: 'schedule_create' | 'schedule_update';
    window: ScheduleWindow;
} | {
    action: 'schedule_delete';
    id: string;
};
const bad = (message: string): never => {
    throw new AppError(400, message);
};
function weekdays(value: unknown): Day[] {
    if (!Array.isArray(value) || value.length > 7) {
        bad('array_limit');
    }
    const days = (value as unknown[]).map(day => DAYS.includes(day as Day) ? day as Day : bad('invalid_weekday'));
    if (new Set(days).size !== days.length) {
        bad('duplicate_value');
    }
    if (!days.length) {
        bad('empty_weekdays');
    }
    return DAYS.filter(day => days.includes(day));
}
/** Same field bounds as normalizePolicy; the full policy is re-validated authoritatively on apply. */
export function parseScheduleChange(action: ScheduleAction, input: unknown, pathId?: string): ScheduleChange {
    if (action === 'schedule_delete') {
        object(input, []);
        return { action, id: id(pathId) };
    }
    const body = object(input, action === 'schedule_create' ? ['id', 'weekdays', 'start', 'stop'] : ['weekdays', 'start', 'stop']);
    const start = clock(body.start), stop = clock(body.stop);
    if (start === stop) {
        bad('empty_schedule');
    }
    return { action, window: { id: id(action === 'schedule_create' ? body.id : pathId), weekdays: weekdays(body.weekdays), start, stop } };
}
/** Returns a new schedule list; overlapping windows are allowed because the router blocks while any window is active. */
export function applyScheduleChange(schedules: Schedule[], person: string, change: ScheduleChange): Schedule[] {
    const target = change.action === 'schedule_delete' ? change.id : change.window.id;
    const exists = schedules.some(s => s.person === person && s.id === target);
    if (change.action === 'schedule_create') {
        if (exists) {
            throw new AppError(409, 'schedule_id_exists');
        }
        return [...schedules, { person, ...change.window }];
    }
    if (!exists) {
        throw new AppError(404, 'schedule_not_found');
    }
    return change.action === 'schedule_delete'
        ? schedules.filter(s => !(s.person === person && s.id === target))
        : schedules.map(s => s.person === person && s.id === target ? { person, ...change.window } : s);
}
