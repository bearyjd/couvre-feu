import { DAYS, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import type { IntegrationManifest } from './integration-config.ts';
import type { Store } from './db.ts';

/** Product cap, also enforced by the schedule_windows insert trigger (migration integration-009) and the manifest loader. */
export const MAX_WINDOWS_PER_CHILD = 8;
interface Row { person_id: string; id: string; weekdays: string; start: string; stop: string }

/** Flag schedules.editable (absent = off, unverified on this router): the database, not the manifest, owns the schedule set. */
export const schedulesInDatabase = (config: Pick<IntegrationManifest, 'schedules'>): boolean => config.schedules?.editable === true;

/** Every committed window as router schedules (window clocks and weekday sets only). */
export function scheduleWindows(store: Store): Schedule[] {
    return store.all<Row>('SELECT person_id,id,weekdays,start,stop FROM schedule_windows ORDER BY person_id,id')
        .map(r => ({person: r.person_id, id: r.id, weekdays: DAYS.filter(d => r.weekdays.split(',').includes(d)), start: r.start, stop: r.stop}));
}
/** Seeds the table once from the manifest enrollment schedules; only when the flag is on. The marker row makes a later empty set stay empty. */
export function seedScheduleWindows(store: Store, config: Pick<IntegrationManifest, 'schedules' | 'enrollment'>): void {
    if (!store.db.isTransaction) throw new Error('seed_requires_transaction');
    if (!schedulesInDatabase(config) || store.get('SELECT 1 FROM schedule_seed')) return;
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
