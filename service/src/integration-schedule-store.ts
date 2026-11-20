import { DAYS, clock, id, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { Day, RouterPolicy, Schedule } from '../../shared/src/router-schema.ts';
import { AppError } from '../../shared/src/errors.ts';
import type { IntegrationManifest } from './integration-config.ts';
import type { Store } from './db.ts';

/** Product cap, also enforced by the schedule_windows insert trigger (migration integration-009). */
export const MAX_WINDOWS_PER_CHILD = 8;
export type ScheduleWindow = Omit<Schedule, 'person'>;
interface Row { person_id: string; id: string; weekdays: string; start: string; stop: string }

/** Flag schedules.editable (absent = off, unverified on this router): the database, not the manifest, owns the schedule set. */
export const schedulesInDatabase = (config: Pick<IntegrationManifest, 'schedules'>): boolean => config.schedules?.editable === true;

/** Every stored window as router schedules (window clocks and weekday sets only). */
export function scheduleWindows(store: Store): Schedule[] {
    return store.all<Row>('SELECT person_id,id,weekdays,start,stop FROM schedule_windows ORDER BY person_id,id')
        .map(r => ({person: r.person_id, id: r.id, weekdays: DAYS.filter(d => r.weekdays.split(',').includes(d)), start: r.start, stop: r.stop}));
}
/** Seeds the table once from the manifest enrollment schedules; only when the flag is on. The marker row makes a later empty set stay empty. */
export function seedScheduleWindows(store: Store, config: Pick<IntegrationManifest, 'schedules' | 'enrollment'>): void {
    if (!store.db.isTransaction) throw new Error('seed_requires_transaction');
    if (!schedulesInDatabase(config) || store.get('SELECT 1 FROM schedule_seed')) return;
    for (const s of normalizePolicy(config.enrollment).schedules) insert(store, s.person, s);
    store.run('INSERT INTO schedule_seed(singleton) VALUES(1)');
}
function insert(store: Store, person: string, w: ScheduleWindow): void {
    store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', person, w.id, w.weekdays.join(','), w.start, w.stop);
}
/** Strict shape: exactly id, weekdays, start, stop. Anything else (a label, a note) is refused. */
function checked(value: unknown): ScheduleWindow {
    const w = value as Record<string, unknown>;
    if (typeof value !== 'object' || value === null || Object.keys(w).sort().join() !== 'id,start,stop,weekdays' || !Array.isArray(w.weekdays)) throw new AppError(400, 'invalid_schedule_window');
    const days = w.weekdays as unknown[];
    if (!days.length || days.length > 7 || days.some(d => !DAYS.includes(d as Day)) || new Set(days).size !== days.length) throw new AppError(400, 'invalid_schedule_window');
    const start = clock(w.start), stop = clock(w.stop);
    if (start === stop) throw new AppError(400, 'invalid_schedule_window');
    return {id: id(w.id), weekdays: DAYS.filter(d => days.includes(d)), start, stop};
}
/**
 * Replaces one child's window set inside the caller's transaction (the same one that queues the policy; see
 * IntegrationPolicy.queue `stage`). A throw anywhere rolls the rows back with the operation.
 */
export function stageScheduleWindows(store: Store, person: string, windows: readonly ScheduleWindow[]): void {
    if (!store.db.isTransaction) throw new Error('schedule_stage_requires_transaction');
    if (windows.length > MAX_WINDOWS_PER_CHILD) throw new AppError(409, 'schedule_window_limit');
    const next = windows.map(checked);
    if (new Set(next.map(w => w.id)).size !== next.length) throw new AppError(400, 'invalid_schedule_window');
    store.run('DELETE FROM schedule_windows WHERE person_id=?', id(person));
    for (const w of next) insert(store, person, w);
}
/** Next policy with one child's windows replaced; every other child's schedules are kept as the router holds them. */
export function policyWithWindows(base: RouterPolicy, person: string, windows: readonly ScheduleWindow[]): RouterPolicy {
    const schedules = [...base.schedules.filter(s => s.person !== person), ...windows.map(w => ({person, ...w}))];
    return normalizePolicy({...base, revision: base.revision + 1, schedules});
}
