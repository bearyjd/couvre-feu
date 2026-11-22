import { AppError } from '../../shared/src/errors.ts';
import { DAYS } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import { applyScheduleChange, parseScheduleChange } from '../../shared/src/schedule-edit.ts';
import type { ScheduleAction, ScheduleChange } from '../../shared/src/schedule-edit.ts';
import type { Actor, OperationResult } from '../../shared/src/contracts.ts';
import type { IntegrationOperation, IntegrationPolicy } from './integration-policy.ts';
import { CLIENT_KEY, TOKEN } from './integration-children.ts';
import { isLoosening, windowSetDigest } from './schedule-loosening.ts';
import { scheduleBuild } from './integration-schedule-request.ts';
import { scheduleWindows } from './integration-schedule-store.ts';
import { audited } from './parent-audit.ts';
import type { AuditAction } from './parent-audit.ts';

/**
 * Schedule create/update/delete for integration installs (roadmap item 2, S2m; flag schedules.editable, off; unverified on this router).
 * One change is folded into the child's committed schedule_windows rows (never the router) and the whole set goes through the same queue()
 * admission as scheduleEdit. No policy is built here and nothing about settlement changes.
 */
type Outcome = {status: number; result: OperationResult};
const byId = (a: Schedule, b: Schedule): number => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

/** The child's committed windows with the change applied, in the canonical form scheduleRequestWindows produces. */
export function fold(committed: readonly Schedule[], person: string, change: ScheduleChange): Schedule[] {
    return applyScheduleChange([...committed], person, change)
        .map(w => ({person, id: w.id, weekdays: DAYS.filter(d => w.weekdays.includes(d)), start: w.start, stop: w.stop})).sort(byId);
}
/** schedule_loosened when isLoosening says so (a deleted window or a freed minute); otherwise schedule_set. Best effort: a failure reads as schedule_set. */
function auditAction(committed: readonly Schedule[], person: string, change: ScheduleChange): AuditAction {
    try {
        if (isLoosening(committed, fold(committed, person, change))) return 'schedule_loosened';
    } catch { /* the work itself refuses; the label stays schedule_set */ }
    return 'schedule_set';
}
/** What a replay must repeat: who, which single change, against which token and permission version. */
const identity = (person: unknown, change: unknown, precondition: unknown, permissionVersion: unknown): string => JSON.stringify({person, change, precondition, permissionVersion});
function storedIdentity(op: IntegrationOperation): string | null {
    try {
        const r = JSON.parse(op.request_json) as {person: unknown; change?: unknown; precondition: unknown; permissionVersion: unknown};
        return r.change === undefined ? null : identity(r.person, r.change, r.precondition, r.permissionVersion);
    } catch { return null; }
}

/**
 * S2b: the HTTP route always passes a gate. `verified` is the step-up the caller already checked (its bound window-set digest and the commit
 * that spends the passkey use inside this transaction), or null when none was needed or given. Without a gate (direct callers, S2m tests)
 * nothing is required.
 */
export interface ScheduleGate { verified: {digest: string; commit: () => void} | null }

export function scheduleMutate(policy: IntegrationPolicy, actor: Actor, person: string, action: ScheduleAction, input: unknown, scheduleId: string | undefined, precondition: string | undefined, key: string | undefined, gate?: ScheduleGate): Outcome {
    const store = policy.store;
    policy.authorized(actor, person);
    const label = (): AuditAction => {
        // A replay keeps the label its first call was recorded under, whatever the rows say now.
        const first = key ? store.get<{action: AuditAction}>('SELECT action FROM parent_audit WHERE operation_id=(SELECT id FROM operations WHERE actor_id=? AND idempotency_key=?) LIMIT 1', actor.id, key) : undefined;
        if (first) return first.action;
        try { return auditAction(scheduleWindows(store).filter(w => w.person === person), person, parseScheduleChange(action, input, scheduleId)); } catch { return 'schedule_set'; }
    };
    return audited(store, {actor: actor.id, action: label(), now: policy.now, people: () => [person], done: r => ({operationId: r.result.operation.id})}, () => {
        if (!key || !CLIENT_KEY.test(key)) throw new AppError(400, 'idempotency_key_required');
        if (!precondition || !TOKEN.test(precondition)) throw new AppError(428, 'revision_precondition_required');
        const change = parseScheduleChange(action, input, scheduleId), mine = identity(person, change, precondition, actor.permissionVersion);
        const op = store.transaction(() => {
            store.assertIdentity();
            const prior = store.get<IntegrationOperation>('SELECT * FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key);
            if (prior) { if (storedIdentity(prior) !== mine) throw new AppError(409, 'idempotency_payload_conflict'); return prior; }
            // Folded here, refused inside queue()'s build so a stale token or a busy router is reported before a fold error.
            let windows: Schedule[] = [], failure: unknown = null;
            const committed = scheduleWindows(store).filter(w => w.person === person);
            try { windows = fold(committed, person, change); } catch (error) { failure = error; }
            // S2b: judged again inside the write transaction. Before queue(), so a refusal here queues, settles and audits nothing (403 leaves no audit row).
            if (gate && !failure && isLoosening(committed, windows)) {
                if (!gate.verified) throw new AppError(403, 'step_up_required');
                if (gate.verified.digest !== windowSetDigest(windows)) throw new AppError(403, 'step_up_mismatch');
                gate.verified.commit();
            }
            const request = JSON.stringify({person, action: 'schedule_update', windows, change, precondition, permissionVersion: actor.permissionVersion});
            return policy.queue(actor, person, 'schedule_update', request, key, precondition, base => scheduleBuild(base, store.config, person, windows, failure), undefined, [person], {person, windows});
        });
        return policy.result(op);
    });
}
