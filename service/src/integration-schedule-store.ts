import { DAYS, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import type { ScheduleKind, ScheduleWindowDTO } from '../../shared/src/contracts.ts';
import type { IntegrationManifest } from './integration-config.ts';
import type { Store } from './db.ts';

/** Product cap, also enforced by the schedule_windows insert trigger (migration integration-009) and the manifest loader. */
export const MAX_WINDOWS_PER_CHILD = 8;
interface Row { person_id: string; id: string; weekdays: string; start: string; stop: string }
const windowFields = (row: Omit<Row, 'person_id'>) =>
    ({id: row.id, weekdays: DAYS.filter(d => row.weekdays.split(',').includes(d)), start: row.start, stop: row.stop});

/** Flag schedules.editable (absent = off, unverified on this router): the database, not the manifest, owns the schedule set. */
export const schedulesInDatabase = (config: Pick<IntegrationManifest, 'schedules'>): boolean => config.schedules?.editable === true;
export const recurringFocusEnabled = (config: Pick<IntegrationManifest, 'schedules' | 'focus'>): boolean =>
    schedulesInDatabase(config) && config.focus?.enabled === true;

/** Every committed window as router schedules (window clocks and weekday sets only). */
export function scheduleWindows(store: Store): Schedule[] {
    return store.all<Row>('SELECT person_id,id,weekdays,start,stop FROM schedule_windows ORDER BY person_id,id')
        .map(r => ({person: r.person_id, ...windowFields(r)}));
}
/** Service metadata for one child. Wire-facing readers use scheduleWindows. */
export function scheduleKinds(store: Store, person: string): Map<string, ScheduleKind> {
    return new Map(store.all<{id: string; kind: ScheduleKind}>('SELECT id,kind FROM schedule_windows WHERE person_id=? ORDER BY id', person).map(row => [row.id, row.kind]));
}
/** Read a child's committed windows and, when requested, labels from the same database snapshot. */
export function scheduleWindowsForDTO(store: Store, person: string, labels: boolean): ScheduleWindowDTO[] {
    const columns = labels ? 'id,weekdays,start,stop,kind' : 'id,weekdays,start,stop';
    return store.all<Omit<Row, 'person_id'> & {kind?: ScheduleKind}>(`SELECT ${columns} FROM schedule_windows WHERE person_id=? ORDER BY id`, person)
        .map(row => ({...windowFields(row), ...(labels ? {kind: row.kind} : {})}));
}
/**
 * Seeds the table once from the manifest enrollment schedules; only when the flag is on. The marker row makes a later empty set stay empty.
 * The identity marker is re-checked inside the seeding transaction: a rebind that moved the database to another manifest after this
 * store's open check must not receive rows from the old one (it throws integration_database_identity_mismatch and writes nothing).
 */
export function seedScheduleWindows(store: Store & {assertIdentity(): void}, config: Pick<IntegrationManifest, 'schedules' | 'enrollment'>): void {
    if (!store.db.isTransaction) throw new Error('seed_requires_transaction');
    if (!schedulesInDatabase(config)) return;
    store.assertIdentity();
    if (store.get('SELECT 1 FROM schedule_seed')) return;
    for (const s of normalizePolicy(config.enrollment).schedules) store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', s.person, s.id, s.weekdays.join(','), s.start, s.stop);
    store.run('INSERT INTO schedule_seed(singleton) VALUES(1)');
}
const before = (a: Schedule, b: Schedule): number => a.person < b.person ? -1 : a.person > b.person ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
/**
 * Order-independent text form of a schedule set (sorted by person then id, weekdays in week order, fixed key order). A pure comparison:
 * it never normalizes a policy, so it cannot throw for router limits and does not depend on device counts.
 */
export function canonicalSchedules(schedules: readonly Schedule[]): string {
    return JSON.stringify([...schedules].sort(before).map(s => ({person: s.person, id: s.id, weekdays: DAYS.filter(d => s.weekdays.includes(d)), start: s.start, stop: s.stop})));
}
