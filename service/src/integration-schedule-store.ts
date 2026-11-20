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
/** Validates a window set (count, shape, unique ids) without writing it. */
function checkedSet(windows: readonly ScheduleWindow[]): ScheduleWindow[] {
    if (windows.length > MAX_WINDOWS_PER_CHILD) throw new AppError(409, 'schedule_window_limit');
    const next = windows.map(checked);
    if (new Set(next.map(w => w.id)).size !== next.length) throw new AppError(400, 'invalid_schedule_window');
    return next;
}
/** Replaces one child's committed window set inside the caller's transaction. */
export function replaceScheduleWindows(store: Store, person: string, windows: readonly ScheduleWindow[]): void {
    if (!store.db.isTransaction) throw new Error('schedule_replace_requires_transaction');
    const next = checkedSet(windows);
    store.run('DELETE FROM schedule_windows WHERE person_id=?', id(person));
    for (const w of next) insert(store, person, w);
}
/**
 * Records a child's proposed window set against the operation that queues it (the same transaction as IntegrationPolicy.queue `stage`).
 * The committed rows are untouched until settleScheduleWindows sees the router confirm; a throw anywhere rolls the staged row back.
 */
export function stageScheduleWindows(store: Store, person: string, windows: readonly ScheduleWindow[], operationId: string): void {
    if (!store.db.isTransaction) throw new Error('schedule_stage_requires_transaction');
    store.run('INSERT INTO schedule_staged(operation_id,person_id,windows_json) VALUES(?,?,?)', operationId, id(person), JSON.stringify(checkedSet(windows)));
}
/** Order-independent form for comparing window sets: sorted by id, keys in a fixed order. */
const canonical = (windows: readonly ScheduleWindow[] | undefined): string => JSON.stringify([...(windows ?? [])].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map(w => ({id: w.id, weekdays: w.weekdays, start: w.start, stop: w.stop})));
interface Staged { operation_id: string; person_id: string; windows_json: string }
/**
 * Every schedule set reconciliation may meet: the committed rows (base) and, per staged operation, the rows with that proposal applied.
 * With an operationId: only that operation's proposal (or the committed rows when it staged nothing).
 */
export function acceptableSchedules(store: Store, operationId?: string): Schedule[][] {
    const committed = scheduleWindows(store);
    if (operationId !== undefined && !store.get('SELECT 1 FROM schedule_staged WHERE operation_id=?', operationId)) return [committed];
    const proposals = (operationId === undefined ? store.all<Staged>('SELECT * FROM schedule_staged ORDER BY operation_id') : store.all<Staged>('SELECT * FROM schedule_staged WHERE operation_id=?', operationId)).map(row => [...committed.filter(s => s.person !== row.person_id),
        ...(JSON.parse(row.windows_json) as ScheduleWindow[]).map(w => ({person: row.person_id, ...w}))]);
    return operationId === undefined ? [committed, ...proposals] : proposals;
}
/**
 * Settles an operation's staged windows with it, in the caller's transaction. Confirmed promotes them to the committed rows; failed discards
 * them; unknown keeps them pending. A conflict promotes only with an exact stored receipt for this operation (delivery accepted, so it was
 * dispatched and the router did accept it, later superseded) AND a stored observation holding exactly the proposed windows for that child.
 * A conflict proven before dispatch (no receipt) discards: a coincident out-of-band router change is not this operation's.
 */
export function settleScheduleWindows(store: Store, operationId: string, state: 'confirmed' | 'unknown' | 'failed' | 'conflict', observed: RouterPolicy | null): void {
    if (state === 'unknown') return;
    const row = store.get<Staged>('SELECT * FROM schedule_staged WHERE operation_id=?', operationId);
    if (!row) return;
    const proposal = JSON.parse(row.windows_json) as ScheduleWindow[];
    const held = observed?.schedules.filter(s => s.person === row.person_id).map(({person: _person, ...w}) => w);
    const receipt = store.get<{attempt_count: number}>("SELECT attempt_count FROM operation_rpc WHERE operation_id=? AND delivery='accepted' AND receipt_json IS NOT NULL", operationId);
    const promote = state === 'confirmed' || (state === 'conflict' && receipt !== undefined && receipt !== null && receipt.attempt_count > 0 && canonical(held) === canonical(proposal));
    if (promote) replaceScheduleWindows(store, row.person_id, proposal);
    store.run('DELETE FROM schedule_staged WHERE operation_id=?', operationId);
}
/** Next policy with one child's windows replaced; every other child's schedules are kept as the router holds them. */
export function policyWithWindows(base: RouterPolicy, person: string, windows: readonly ScheduleWindow[]): RouterPolicy {
    const schedules = [...base.schedules.filter(s => s.person !== person), ...windows.map(w => ({person, ...w}))];
    return normalizePolicy({...base, revision: base.revision + 1, schedules});
}
