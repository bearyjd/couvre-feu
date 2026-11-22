import { exactHealthy, exactReceipt } from '../../shared/src/router-rpc.ts';
import type { RPCEnvelope, RPCObservation, RPCReceipt } from '../../shared/src/router-rpc.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';

/**
 * Settlement of a schedule operation (roadmap item 2, S2a; flag schedules.editable, off; unverified on this router). Pure: rules S0-S7 of
 * the S2a design, first match wins. Every outcome carries one of the fixed codes below, never router text. Decisions read only fields the
 * router binds by digest (receipt, revision, digest, generation, currentOperationId), never the policy contents or the devices table.
 */
export const SCHEDULE_CODES = [
    'awaiting_operator_dispatch', 'awaiting_automatic_dispatch', 'awaiting_exact_router_receipt',
    'schedule_payload_inadmissible', 'router_apply_not_delivered', 'router_outcome_unknown',
    'router_generation_changed_before_dispatch', 'router_generation_changed_after_dispatch',
    'accepted_router_runtime_unconfirmed', 'router_receipt_historical',
    'router_base_changed_before_write', 'router_refused_before_write', 'router_operation_id_conflict',
    'router_base_changed_before_dispatch', 'schedule_not_dispatched',
    'router_base_changed_after_dispatch', 'router_apply_unobserved_after_fence', 'receipt_missing_remote_outcome_unknown',
] as const;
export type ScheduleCode = typeof SCHEDULE_CODES[number];
export type ScheduleState = 'confirmed' | 'unknown' | 'failed' | 'conflict';
/** S6: a queued operation with no attempt (attempt_count 0 proves nothing was dispatched) fails after this many seconds. */
export const DISPATCH_TTL_SECONDS = 120;
/** S7: the read-only fence after the apply step's lease, in service time AND router time. A margin, not a proof (see the contract). */
export const APPLY_FENCE_SECONDS = 600;

export interface ScheduleEvidence {
    /** admitSchedule's result: the envelope, or null when the stored rows do not bind together. */
    envelope: RPCEnvelope | null;
    person: string; attemptCount: number;
    /** The settling invocation is this operation's own (single) apply. */
    ownApply: boolean;
    transport: {code: string; delivery: 'not_delivered' | 'possible'} | null;
    observation: RPCObservation | null;
    now: number; createdAt: number;
    /** lease_until of this operation's apply step; null when there was no attempt. */
    applyLeaseUntil: number | null;
}
export interface ScheduleDecision {
    state: ScheduleState; error: ScheduleCode | null; terminal: boolean; confirmedAt: number | null;
    delivery: 'not_delivered' | 'possible' | 'accepted' | null; receipt: RPCReceipt | null;
    /** The envelope's windows for the target child; promoted only on an exact current receipt. */
    promote: readonly Schedule[] | null;
}
const decision = (state: ScheduleState, error: ScheduleCode | null, terminal: boolean, extra: Partial<ScheduleDecision> = {}): ScheduleDecision =>
    ({state, error, terminal, confirmedAt: null, delivery: null, receipt: null, promote: null, ...extra});
const baseMoved = (o: RPCObservation, e: RPCEnvelope): boolean => o.acceptedPolicy.revision !== e.expected_revision || o.policyDigest !== e.expected_digest;

/** S2: the router's exact receipt for this request. Promote only when it is current; a historical one ends the operation with no promotion. */
function exact(o: RPCObservation, e: RPCEnvelope, person: string): ScheduleDecision {
    const accepted = {delivery: 'accepted' as const, receipt: o.receipt};
    if (!o.receipt!.current) return decision('conflict', 'router_receipt_historical', true, accepted);
    const promote = e.policy.schedules.filter(s => s.person === person);
    return exactHealthy(o, e) ? decision('confirmed', null, true, {...accepted, promote, confirmedAt: o.routerTime})
        : decision('unknown', 'accepted_router_runtime_unconfirmed', false, {...accepted, promote});
}
/**
 * S3: our own apply answered with a full reply, no receipt for our id and exactly one error. After rpc.sh:169 the receipt field describes our
 * id, cf_rpc_response reloads state under the lock, and the only policy write (:193) adds our receipt row in the same rename: so this reply
 * proves nothing was written. policy_conflict (:176) must show a moved base; every other code must show the unchanged base. Anything else
 * on our own apply is ambiguous (S7).
 */
function refusedBeforeWrite(o: RPCObservation, e: RPCEnvelope): ScheduleDecision | null {
    if (o.receipt !== null || o.currentOperationId === e.operation_id || o.errors.length !== 1) return null;
    if (o.errors[0] === 'policy_conflict') return baseMoved(o, e) ? decision('conflict', 'router_base_changed_before_write', true) : null;
    return baseMoved(o, e) ? null : decision('failed', 'router_refused_before_write', true);
}
/** Our id is already recorded with another request digest (rpc.sh:173). */
const operationIdConflict = (o: RPCObservation, e: RPCEnvelope): boolean =>
    o.receipt !== null && o.receipt.operationId === e.operation_id && o.errors.length === 1 && o.errors[0] === 'operation_conflict';

function transportStep(input: ScheduleEvidence, t: NonNullable<ScheduleEvidence['transport']>): ScheduleDecision | null {
    // S1g: rpc.sh:168 refuses every request of an old generation, so nothing of ours can land later; terminal, which keeps rebind possible.
    if (t.code === 'router_generation_changed') return decision('conflict', input.attemptCount > 0 ? 'router_generation_changed_after_dispatch' : 'router_generation_changed_before_dispatch', true);
    if (!input.ownApply) return null;
    // S1: not_delivered is constructed before any spawn (ssh-router.ts); anything else may have reached the router.
    return t.delivery === 'not_delivered' ? decision('failed', 'router_apply_not_delivered', true, {delivery: 'not_delivered'})
        : decision('unknown', 'router_outcome_unknown', false, {delivery: 'possible'});
}
/** S7: an attempt was made and no exact receipt is seen. Read-only: there is never a second apply. */
function afterDispatch(input: ScheduleEvidence, o: RPCObservation, e: RPCEnvelope): ScheduleDecision {
    // The router revision only rises within a generation (rpc.sh:185, core.sh:743/751, cf_sync_read's stale/conflicting refusals), so a moved
    // base never returns and a delayed apply is refused at rpc.sh:176.
    if (baseMoved(o, e)) return decision('conflict', 'router_base_changed_after_dispatch', true);
    const fence = input.applyLeaseUntil === null ? null : input.applyLeaseUntil + APPLY_FENCE_SECONDS;
    if (fence !== null && input.now >= fence && o.routerTime >= fence) return decision('failed', 'router_apply_unobserved_after_fence', true);
    return decision('unknown', 'receipt_missing_remote_outcome_unknown', false);
}
/** One settlement step; null means the evidence changes nothing. */
export function decideSchedule(input: ScheduleEvidence): ScheduleDecision | null {
    const e = input.envelope, o = input.observation;
    // S0: the stored rows do not bind together; nothing is promoted.
    if (!e) return decision(input.attemptCount > 0 ? 'conflict' : 'failed', 'schedule_payload_inadmissible', true);
    if (input.transport) return transportStep(input, input.transport);
    if (!o) return null;
    if (o.generation !== e.generation) return decision('conflict', input.attemptCount > 0 ? 'router_generation_changed_after_dispatch' : 'router_generation_changed_before_dispatch', true);
    if (exactReceipt(o, e)) return exact(o, e, input.person);
    if (input.ownApply) {
        const refused = refusedBeforeWrite(o, e);
        if (refused) return refused;
        if (operationIdConflict(o, e)) return decision('conflict', 'router_operation_id_conflict', true);
    }
    if (input.attemptCount === 0) {
        // S5 / S6: attempt_count 0 is the local witness that nothing was dispatched.
        if (baseMoved(o, e)) return decision('conflict', 'router_base_changed_before_dispatch', true);
        return input.now >= input.createdAt + DISPATCH_TTL_SECONDS ? decision('failed', 'schedule_not_dispatched', true) : null;
    }
    return afterDispatch(input, o, e);
}
/** The worker calls decideSchedule through this object, so a test can count calls (flag off must read 0). */
export const scheduleSeam = {decideSchedule};
