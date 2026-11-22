import { AppError } from '../../shared/src/errors.ts';
import { normalizeEnvelope, policyDigest, requestDigest } from '../../shared/src/router-rpc.ts';
import type { RPCEnvelope } from '../../shared/src/router-rpc.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import type { IntegrationStore } from './integration-db.ts';
import type { IntegrationOperation } from './integration-policy.ts';
import { childrenSeam } from './integration-children.ts';
import { MAX_WINDOWS_PER_CHILD, schedulesInDatabase } from './integration-schedule-store.ts';
import { scheduleSeam } from './integration-schedule-settle.ts';
import type { ScheduleCode } from './integration-schedule-settle.ts';
import { applyScheduleDecision, attemptEvidence } from './integration-schedule-apply.ts';
import { admitWindowKinds } from './integration-schedule-kind.ts';
import type { WindowKinds } from './integration-schedule-kind.ts';

/** Roadmap item 2, S2a (flag schedules.editable, off; unverified on this router). */
export const isScheduleAction = (action: string): boolean => action === 'schedule_create' || action === 'schedule_update' || action === 'schedule_delete';
interface RpcRow { generation: string; request_digest: string; envelope_json: string; attempt_count: number }
interface ScheduleRequest { person: string; action: string; windows: Schedule[]; windowKinds?: unknown; change?: unknown }
interface AdmittedSchedule { envelope: RPCEnvelope; kinds: WindowKinds | null }

/**
 * The operation's envelope when its stored rows bind together, else null. Total: never throws. Rebuilding the policy from the request and
 * the base binds request, base and envelope; schedule_windows is never read. Cost is bounded by the policy size (256 entries or fewer).
 */
export function admitSchedule(store: IntegrationStore, op: IntegrationOperation): AdmittedSchedule | null {
    try {
        const config = store.config, rpc = store.get<RpcRow>('SELECT * FROM operation_rpc WHERE operation_id=?', op.id);
        if (!rpc) return null;
        const e = normalizeEnvelope(JSON.parse(rpc.envelope_json));
        if (e.operation_id !== op.id || e.generation !== rpc.generation || rpc.generation !== config.router.generation || requestDigest(e) !== rpc.request_digest) return null;
        const base = normalizePolicy(JSON.parse(op.base_json));
        if (base.revision !== e.expected_revision || policyDigest(base) !== e.expected_digest) return null;
        if (op.request_json.length > 8192) return null;
        const request = JSON.parse(op.request_json) as ScheduleRequest;
        if (request.action !== op.action || request.person !== op.person_id || !Array.isArray(request.windows) || request.windows.length > MAX_WINDOWS_PER_CHILD) return null;
        if (request.windows.some(w => w.person !== op.person_id)) return null;
        // No static DoH reconciliation: queue() copies DoH from the base for every schedule action, so the rebuild does too.
        const rebuilt = childrenSeam.withScheduleWindows(base, config, op.person_id, request.windows);
        if (policyDigest(rebuilt) !== policyDigest(e.policy)) return null;
        if (e.policy.schedules.length > 0 && !config.scheduleClock) return null;
        const kinds = admitWindowKinds(store, op.id, op.request_json, request, request.windows);
        return kinds === undefined ? null : {envelope: e, kinds};
    } catch {
        return null;
    }
}
/**
 * Inside the caller's transaction, for an apply about to be prepared or claimed (flag on; else null without a read). An active schedule
 * operation whose rows do not bind (S0), or that is past the dispatch TTL with no attempt in either claim record (S6), is settled here and
 * its code returned; the caller commits that settlement and then refuses the dispatch with the code.
 */
export function scheduleClaimRefusal(store: IntegrationStore, id: unknown, now: number): ScheduleCode | null {
    if (!store.db.isTransaction) throw new Error('schedule_claim_requires_transaction');
    if (!schedulesInDatabase(store.config) || typeof id !== 'string') return null;
    const op = store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id);
    if (!op || !isScheduleAction(op.action) || store.integrationState().active_operation_id !== id || !['pending', 'unknown'].includes(op.state)) return null;
    // With no reply, decideSchedule settles only S0 (rows do not bind) and S6 (no attempt, TTL passed); anything else returns null.
    const admitted = admitSchedule(store, op);
    const d = scheduleSeam.decideSchedule({envelope: admitted?.envelope ?? null, person: op.person_id, ...attemptEvidence(store, id), ownApply: false,
        transport: null, observation: null, now, createdAt: op.created_at});
    applyScheduleDecision(store, op, d, now, admitted?.kinds ?? null);
    return d?.error ?? null;
}
/**
 * Flag on (else false without a read): a schedule operation whose apply was claimed by EITHER record (operation_rpc's counter or its apply
 * dispatch step). A crash or restore that reverts the rpc row to queued leaves the step, so this still refuses a second claim and still
 * selects the operation's own receipt for automatic polling.
 */
export function scheduleAttempted(store: IntegrationStore, id: string): boolean {
    if (!schedulesInDatabase(store.config)) return false;
    const op = store.get<{action: string}>('SELECT action FROM operations WHERE id=?', id);
    return Boolean(op && isScheduleAction(op.action)) && attemptEvidence(store, id).attemptCount > 0;
}
/**
 * Before any dispatch (prepare, and the top of run() before the plan is validated): scheduleClaimRefusal in its own committed transaction,
 * then the refusal. The claim transaction repeats it, so rows changed in between are refused too. Flag off: returns at once.
 */
export function refuseInadmissibleSchedule(store: IntegrationStore, id: unknown, now: number): void {
    if (!schedulesInDatabase(store.config) || typeof id !== 'string') return;
    const refused = store.transaction(() => { store.assertIdentity(); return scheduleClaimRefusal(store, id, now); });
    if (refused) throw new AppError(409, refused);
}
