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
import { applyScheduleDecision, applyLeaseUntil } from './integration-schedule-apply.ts';

/** Roadmap item 2, S2a (flag schedules.editable, off; unverified on this router). */
export const isScheduleAction = (action: string): boolean => action === 'schedule_create' || action === 'schedule_update' || action === 'schedule_delete';
interface RpcRow { generation: string; request_digest: string; envelope_json: string; attempt_count: number }
interface ScheduleRequest { person: string; action: string; windows: Schedule[] }

/**
 * The operation's envelope when its stored rows bind together, else null. Total: never throws. Rebuilding the policy from the request and
 * the base binds request, base and envelope; schedule_windows is never read. Cost is bounded by the policy size (256 entries or fewer).
 */
export function admitSchedule(store: IntegrationStore, op: IntegrationOperation): RPCEnvelope | null {
    try {
        const config = store.config, rpc = store.get<RpcRow>('SELECT * FROM operation_rpc WHERE operation_id=?', op.id);
        if (!rpc) return null;
        const e = normalizeEnvelope(JSON.parse(rpc.envelope_json));
        if (e.operation_id !== op.id || e.generation !== rpc.generation || rpc.generation !== config.router.generation || requestDigest(e) !== rpc.request_digest) return null;
        const base = normalizePolicy(JSON.parse(op.base_json));
        if (base.revision !== e.expected_revision || policyDigest(base) !== e.expected_digest) return null;
        const request = JSON.parse(op.request_json) as ScheduleRequest;
        if (request.action !== op.action || request.person !== op.person_id || !Array.isArray(request.windows) || request.windows.length > MAX_WINDOWS_PER_CHILD) return null;
        if (request.windows.some(w => w.person !== op.person_id)) return null;
        // No static DoH reconciliation: queue() copies DoH from the base for every schedule action, so the rebuild does too.
        const rebuilt = childrenSeam.withScheduleWindows(base, config, op.person_id, request.windows);
        if (policyDigest(rebuilt) !== policyDigest(e.policy)) return null;
        if (e.policy.schedules.length > 0 && !config.scheduleClock) return null;
        return e;
    } catch {
        return null;
    }
}
/**
 * Before any dispatch (prepare, and the top of run() before the plan is validated): an active schedule operation whose rows do not bind is
 * settled in its own committed transaction (S0: failed, slot cleared, step resolved) and the dispatch is refused. Flag off: returns at once.
 */
export function refuseInadmissibleSchedule(store: IntegrationStore, id: unknown, now: number): void {
    if (!schedulesInDatabase(store.config) || typeof id !== 'string') return;
    const refused = store.transaction(() => {
        store.assertIdentity();
        const op = store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id);
        if (!op || !isScheduleAction(op.action) || store.integrationState().active_operation_id !== id || !['pending', 'unknown'].includes(op.state)) return false;
        if (admitSchedule(store, op)) return false;
        const rpc = store.get<RpcRow>('SELECT * FROM operation_rpc WHERE operation_id=?', id);
        applyScheduleDecision(store, op, scheduleSeam.decideSchedule({envelope: null, person: op.person_id, attemptCount: rpc?.attempt_count ?? 0, ownApply: false,
            transport: null, observation: null, now, createdAt: op.created_at, applyLeaseUntil: applyLeaseUntil(store, id)}), now);
        return true;
    });
    if (refused) throw new AppError(409, 'schedule_payload_inadmissible');
}
