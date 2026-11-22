import { createHash } from 'node:crypto';
import type { ScheduleKind } from '../../shared/src/contracts.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import type { Store } from './db.ts';
import { scheduleKinds } from './integration-schedule-store.ts';
import { windowSetDigest } from './schedule-loosening.ts';

export type WindowKinds = readonly (readonly [id: string, kind: ScheduleKind])[];
const hash = (value: string): string => createHash('sha256').update(value).digest('hex');
const intentDigest = (id: string, request: string): string => hash(JSON.stringify([id, request]));
export const isScheduleKind = (value: unknown): value is ScheduleKind => value === 'bedtime' || value === 'focus';

export function planWindowKinds(store: Store, person: string, windows: readonly Schedule[], override?: readonly [string, ScheduleKind]): WindowKinds {
    const saved = scheduleKinds(store, person);
    if (override) saved.set(...override);
    return windows.map(w => [w.id, saved.get(w.id) ?? 'bedtime']);
}

/** An all-bedtime set keeps the old proof binding, including pre-deploy challenges. */
export function labeledWindowDigest(windows: readonly Schedule[], kinds: WindowKinds): string {
    const wire = windowSetDigest(windows);
    return kinds.some(([, kind]) => kind === 'focus') ? hash(JSON.stringify([wire, kinds])) : wire;
}

/** Written in the queue transaction. It binds the local label snapshot to this exact operation request. */
export function saveScheduleKindIntent(store: Store, id: string, request: string): void {
    store.run('INSERT INTO schedule_kind_intents(operation_id,digest) VALUES(?,?)', id, intentDigest(id, request));
}

/** Null means a legacy edit, undefined is malformed or missing evidence for a new edit. */
export function admitWindowKinds(store: Store, id: string, requestText: string,
    request: {windowKinds?: unknown; change?: unknown}, windows: readonly Schedule[]): WindowKinds | null | undefined {
    const saved = store.get<{digest: string}>('SELECT digest FROM schedule_kind_intents WHERE operation_id=?', id);
    if (!saved && !Object.hasOwn(request, 'windowKinds')) {
        return request.change && typeof request.change === 'object' && Object.hasOwn(request.change, 'kind') ? undefined : null;
    }
    const kinds = request.windowKinds;
    if (!saved || !Array.isArray(kinds) || kinds.length !== windows.length ||
        kinds.some((pair, i) => !Array.isArray(pair) || pair.length !== 2 || pair[0] !== windows[i].id || !isScheduleKind(pair[1])) ||
        saved.digest !== intentDigest(id, requestText)) return undefined;
    return kinds as WindowKinds;
}
