import { exactHealthy, exactReceipt, normalizeEnvelope, policyDigest, requestDigest } from '../../shared/src/router-rpc.ts';
import type { RPCEnvelope, RPCObservation, RPCReceipt } from '../../shared/src/router-rpc.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import type { IntegrationStore } from './integration-db.ts';
import type { IntegrationOperation } from './integration-policy.ts';
import { PRE_WRITE_REJECTIONS } from './integration-children.ts';
import { BENIGN_ROUTER_ERRORS } from './inventory-store.ts';
import { MAX_WINDOWS_PER_CHILD, canonicalSchedules, scheduleWindows } from './integration-schedule-store.ts';

/**
 * Settlement core of a schedule operation (roadmap item 2, S2a; flag schedules.editable, off; unverified on this router). Used only with
 * the flag on and a schedule_* operation active. Refuse on doubt: admission is checked before any dispatch (I4), the decision reads only
 * the CURRENT observation, never the stored receipt_json (I2), windows are promoted only on an exact current receipt (I3), and every
 * operation error is one of the fixed codes below, never router text (I6).
 */
export const SCHEDULE_INADMISSIBLE = 'schedule_payload_inadmissible';
export type ScheduleState = 'confirmed' | 'unknown' | 'failed' | 'conflict';
export type Admission = {ok: true; envelope: RPCEnvelope} | {ok: false; code: typeof SCHEDULE_INADMISSIBLE};
const REFUSED: Admission = {ok: false, code: SCHEDULE_INADMISSIBLE};
interface RpcRow { generation: string; request_digest: string; envelope_json: string }

/**
 * Total: never throws. The envelope must normalize (the router's own limits, 256 expanded windows included), name this operation, the
 * installation generation and the stored request digest; the child must exist and get at most 8 windows. The routed children come from
 * the operation's base (operations.base_json, bound to the envelope's expected revision and digest), never from the payload: the payload
 * must route exactly the base's children and devices, and every routed child other than this one must carry exactly its committed
 * windows. Together these make a later promotion unable to fail, and an edit for one child can never drop another child's enforcement.
 */
export function admitScheduleOperation(store: IntegrationStore, op: IntegrationOperation): Admission {
    try {
        const rpc = store.get<RpcRow>('SELECT generation,request_digest,envelope_json FROM operation_rpc WHERE operation_id=?', op.id);
        if (!rpc) return REFUSED;
        const e = normalizeEnvelope(JSON.parse(rpc.envelope_json));
        if (e.operation_id !== op.id || e.generation !== rpc.generation || e.generation !== store.config.router.generation || requestDigest(e) !== rpc.request_digest) return REFUSED;
        const base = normalizePolicy(JSON.parse(op.base_json));
        if (base.revision !== e.expected_revision || policyDigest(base) !== e.expected_digest || JSON.stringify(e.policy.people) !== JSON.stringify(base.people)) return REFUSED;
        if (!store.get('SELECT id FROM people WHERE id=?', op.person_id)) return REFUSED;
        if (e.policy.schedules.filter(s => s.person === op.person_id).length > MAX_WINDOWS_PER_CHILD) return REFUSED;
        const routed = new Set(base.people.map(p => p.id).filter(id => id !== op.person_id));
        const others = (set: readonly Schedule[]) => canonicalSchedules(set.filter(s => routed.has(s.person)));
        return others(e.policy.schedules) === others(scheduleWindows(store)) ? {ok: true, envelope: e} : REFUSED;
    } catch {
        return REFUSED;
    }
}

export interface ScheduleInput {
    admission: Admission; person: string; observation: RPCObservation | null;
    transport: {delivery: 'not_delivered' | 'possible'} | null; ownApply: boolean; attemptCount: number;
}
/** One settlement step; null means the evidence changes nothing (E7, or a failed read of another kind). */
export interface ScheduleStep {
    state: ScheduleState; error: string | null; confirmedAt: number | null; terminal: boolean; phase: 'resolved' | 'uncertain';
    delivery: 'not_delivered' | 'possible' | 'accepted' | null; receipt: RPCReceipt | null; promote: readonly Schedule[] | null;
}
const step = (state: ScheduleState, error: string | null, terminal: boolean, extra: Partial<ScheduleStep> = {}): ScheduleStep =>
    ({state, error, confirmedAt: null, terminal, phase: terminal ? 'resolved' : 'uncertain', delivery: null, receipt: null, promote: null, ...extra});
const refusedBeforeWrite = (o: RPCObservation, e: RPCEnvelope): boolean => o.receipt === null && o.currentOperationId !== e.operation_id && o.generation === e.generation &&
    o.acceptedPolicy.revision === e.expected_revision && o.policyDigest === e.expected_digest && o.errors.length > 0 && o.errors.every(code => PRE_WRITE_REJECTIONS.has(code));
/**
 * The router's reply to our single apply attempt when its base check failed under the lock (router/lib/rpc.sh: no receipt for this
 * request, base revision or digest moved, `policy_conflict`): it refused before writing anything, so the change failed (E5).
 */
const conflictBeforeWrite = (o: RPCObservation, e: RPCEnvelope): boolean => o.receipt === null && o.currentOperationId !== e.operation_id && o.generation === e.generation &&
    (o.acceptedPolicy.revision !== e.expected_revision || o.policyDigest !== e.expected_digest) && o.errors.length === 1 && o.errors[0] === 'policy_conflict';

/** Pure: rules E0-E8 of the S2a design, first match wins. */
export function decideSchedule(input: ScheduleInput): ScheduleStep | null {
    const {admission, observation: o, transport} = input;
    if (!admission.ok) return step(input.attemptCount > 0 ? 'conflict' : 'failed', SCHEDULE_INADMISSIBLE, true);
    const e = admission.envelope;
    if (transport) {
        if (!input.ownApply) return null;
        return transport.delivery === 'not_delivered' ? step('failed', 'router_apply_not_delivered', true, {delivery: 'not_delivered'}) : step('unknown', 'router_outcome_unknown', false, {delivery: 'possible'});
    }
    if (!o) return null;
    if (exactReceipt(o, e)) {
        const accepted = {delivery: 'accepted' as const, receipt: o.receipt};
        if (!o.receipt!.current) return step('conflict', 'router_receipt_historical', true, accepted);
        const promote = e.policy.schedules.filter(s => s.person === input.person);
        return exactHealthy(o, e) ? step('confirmed', null, true, {...accepted, promote, confirmedAt: o.routerTime}) : step('unknown', 'accepted_router_runtime_unconfirmed', false, {...accepted, promote});
    }
    if (input.ownApply && (refusedBeforeWrite(o, e) || conflictBeforeWrite(o, e))) return step('failed', 'router_refused_before_write', true);
    if (input.attemptCount === 0) return o.acceptedPolicy.revision !== e.expected_revision || o.policyDigest !== e.expected_digest ? step('conflict', 'router_base_changed_before_dispatch', true) : null;
    return step('unknown', 'receipt_missing_remote_outcome_unknown', false);
}

/** Replaces only this child's committed rows, and only when they differ, so repeating a promotion changes nothing (I3). */
function promote(store: IntegrationStore, person: string, windows: readonly Schedule[]): void {
    if (canonicalSchedules(scheduleWindows(store).filter(s => s.person === person)) === canonicalSchedules(windows)) return;
    store.run('DELETE FROM schedule_windows WHERE person_id=?', person);
    for (const w of windows) store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', person, w.id, w.weekdays.join(','), w.start, w.stop);
}
/** Writes one step inside the caller's transaction. The operation row and one audit row change only when state, error or confirmed_at do. */
export function applyScheduleDecision(store: IntegrationStore, op: IntegrationOperation, decision: ScheduleStep | null, now: number): void {
    if (!store.db.isTransaction) throw new Error('schedule_settlement_requires_transaction');
    if (!decision) return;
    const d = decision;
    store.run('UPDATE operation_rpc SET phase=?,delivery=COALESCE(?,delivery),receipt_json=COALESCE(?,receipt_json) WHERE operation_id=?', d.phase, d.delivery, d.receipt && JSON.stringify(d.receipt), op.id);
    if (d.promote) promote(store, op.person_id, d.promote);
    const current = store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', op.id)!;
    const changed = current.state !== d.state || current.error !== d.error || (d.confirmedAt !== null && current.confirmed_at !== d.confirmedAt);
    if (changed) {
        store.run('UPDATE operations SET state=?,error=?,confirmed_at=COALESCE(?,confirmed_at),updated_at=? WHERE id=?', d.state, d.error, d.confirmedAt, now, op.id);
        store.run('INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,?)', op.actor_id, op.id, op.action, op.revision, now, d.state);
    }
    if (d.terminal) store.run('UPDATE integration_state SET active_operation_id=NULL WHERE singleton=1');
}
/** Router error codes this service reads; any other router string is diagnostic text and is never stored while a schedule operation settles. */
const KNOWN_ROUTER_CODES: ReadonlySet<string> = new Set([...PRE_WRITE_REJECTIONS, ...BENIGN_ROUTER_ERRORS, 'policy_conflict', 'previous_apply_failed']);
export const ROUTER_ERROR_UNRECOGNIZED = 'router_error_unrecognized';
/**
 * The observation as it may be stored and served (I6): every router error entry is a known code or ROUTER_ERROR_UNRECOGNIZED. Entries are
 * mapped one for one, never dropped, so an observation with errors stays unhealthy.
 */
export function withFixedErrorCodes(o: RPCObservation): RPCObservation {
    const fixed = (codes: readonly string[]) => codes.map(code => KNOWN_ROUTER_CODES.has(code) ? code : ROUTER_ERROR_UNRECOGNIZED);
    return {...o, errors: fixed(o.errors), status: {...o.status, errors: fixed(o.status.errors)}};
}
/** The worker calls decideSchedule through this object, so a test can count calls (flag off must read 0). */
export const scheduleSeam = {decideSchedule};
