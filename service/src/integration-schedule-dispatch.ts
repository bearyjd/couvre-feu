import { AppError } from '../../shared/src/errors.ts';
import { FORMAT_ONLY, normalizeObservation } from '../../shared/src/router-rpc.ts';
import type { RPCObservation } from '../../shared/src/router-rpc.ts';
import { healthyConfirmation, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { IntegrationStore } from './integration-db.ts';
import type { IntegrationOperation } from './integration-policy.ts';
import type { ActivityStore } from './activity-store.ts';
import type { ScopeTracker } from './integration-scope.ts';
import { routerScopeOf } from './integration-config.ts';
import { validateManagedPolicy } from './integration-children.ts';
import { RouterTransportError } from './router-transport.ts';
import type { AsyncRouter, FrozenInvocation } from './router-transport.ts';
import { schedulesInDatabase } from './integration-schedule-store.ts';
import { scheduleSeam } from './integration-schedule-settle.ts';
import type { ScheduleDecision } from './integration-schedule-settle.ts';
import { admitSchedule, isScheduleAction } from './integration-schedule-admit.ts';
import { applyScheduleDecision, attemptEvidence } from './integration-schedule-apply.ts';
import { withFixedErrorCodes } from './integration-router-codes.ts';

/**
 * Dispatch and settlement while a schedule operation is active (roadmap item 2, S2a; flag schedules.editable, off; unverified on this router).
 * The transport keeps the normalized observation even when ownership fails; settlement decides from digest-bound fields only; the
 * observation is published only if main's full ownership check passes against the committed rows (after any promotion).
 */
export interface ScheduleWorker { store: IntegrationStore; router: AsyncRouter; now: () => number; activity: ActivityStore; scope: ScopeTracker }
const STALE_SECONDS = 30;

/** Flag on and the active operation is a schedule operation. Flag off: false without reading the operation. */
export function scheduleOperationActive(store: IntegrationStore): boolean {
    if (!schedulesInDatabase(store.config)) return false;
    const id = store.integrationState().active_operation_id, op = id ? store.get<{action: string}>('SELECT action FROM operations WHERE id=?', id) : undefined;
    return Boolean(op && isScheduleAction(op.action));
}
/** The router reports a schedule operation the service already ended (failed or conflict) as current, and the policy is not owned. */
export function lateScheduleApply(store: IntegrationStore, o: RPCObservation): boolean {
    if (!schedulesInDatabase(store.config) || !o.currentOperationId) return false;
    const op = store.get<{action: string; state: string}>('SELECT action,state FROM operations WHERE id=?', o.currentOperationId);
    if (!op || !isScheduleAction(op.action) || !['failed', 'conflict'].includes(op.state)) return false;
    try { validateManagedPolicy(o.acceptedPolicy, store.config, store); return false; } catch { return true; }
}
export async function runScheduleDispatch(w: ScheduleWorker, batchId: string, token: string, epoch: number, invocation: FrozenInvocation): Promise<void> {
    let o: RPCObservation | null = null, failure: RouterTransportError | null = null;
    try {
        if (w.store.db.isTransaction) throw new Error('network_inside_transaction');
        // The generation is read from the format-checked reply first: a new generation answers to its own manifest, not to the old floor.
        const config = w.store.config, raw = normalizeObservation(await w.router.invoke(invocation), FORMAT_ONLY);
        if (raw.generation !== config.router.generation) throw new RouterTransportError('router_generation_changed');
        const seen = normalizeObservation(raw, {protectedMacs: config.protectedMacs, floor: routerScopeOf(config)});
        normalizePolicy(seen.acceptedPolicy, config.protectedMacs);
        if (seen.routerTime > w.now() + 1 || w.now() - seen.routerTime > STALE_SECONDS) throw new RouterTransportError('router_clock_or_observation_stale');
        o = seen;
    } catch (error) {
        failure = error instanceof RouterTransportError ? error : new RouterTransportError('router_observation_invalid');
    }
    finishSchedule(w, batchId, token, epoch, invocation, o, failure);
}
function settle(w: ScheduleWorker, invocation: FrozenInvocation, o: RPCObservation | null, failure: RouterTransportError | null): ScheduleDecision | null {
    const store = w.store, id = store.integrationState().active_operation_id;
    const op = id ? store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id) : undefined;
    if (!op || !isScheduleAction(op.action)) return null;
    const admitted = admitSchedule(store, op);
    const decision = scheduleSeam.decideSchedule({envelope: admitted?.envelope ?? null, person: op.person_id, ...attemptEvidence(store, op.id),
        ownApply: invocation.kind === 'apply' && invocation.operationId === op.id, transport: failure && {code: failure.code, delivery: failure.delivery},
        observation: o, now: w.now(), createdAt: op.created_at});
    applyScheduleDecision(store, op, decision, w.now(), admitted?.kinds ?? null);
    return decision;
}
/** Main's publication, after main's full ownership check; a refused observation leaves only a fixed code in observation_error. */
function publish(w: ScheduleWorker, o: RPCObservation): void {
    const store = w.store;
    try { validateManagedPolicy(o.acceptedPolicy, store.config, store); }
    catch (error) {
        const code = lateScheduleApply(store, o) ? 'router_late_schedule_apply' : error instanceof AppError && error.code === 'router_policy_foreign' ? 'router_policy_foreign' : 'router_observation_invalid';
        store.run('UPDATE integration_state SET observation_error=? WHERE singleton=1', code);
        return;
    }
    const clean = withFixedErrorCodes(o);
    store.run('UPDATE service_state SET observation_json=?,observed_at=? WHERE singleton=1', JSON.stringify(clean), w.now());
    store.run('UPDATE integration_state SET observation_sequence=observation_sequence+1 WHERE singleton=1');
    w.activity.purgeUnenrolled();
    w.scope.observe(clean);
    if (clean.errors.length === 0 && healthyConfirmation(clean.status, clean.acceptedPolicy, clean.routerTime)) store.run('UPDATE service_state SET last_confirmation_at=MAX(COALESCE(last_confirmation_at,0),?) WHERE singleton=1', clean.routerTime);
}
/** Main finish()'s claim checks and bookkeeping, then the schedule settlement, then publication. */
export function finishSchedule(w: ScheduleWorker, batchId: string, token: string, epoch: number, invocation: FrozenInvocation, o: RPCObservation | null, failure: RouterTransportError | null): void {
    const store = w.store;
    store.transaction(() => {
        try {
            const s = store.integrationState(), step = store.get<{claim_token: string; state: string; lease_until: number}>('SELECT claim_token,state,lease_until FROM dispatch_steps WHERE batch_id=? AND ordinal=1', batchId);
            if (!step || step.claim_token !== token || step.state !== 'consumed' || s.dispatch_epoch !== epoch || s.generation !== store.config.router.generation || s.dispatch_stopped || step.lease_until < w.now()) return;
            // Only a failed WRITE leaves its step uncertain. A read has no remote effect: its step is resolved and the failure stays in
            // observation_error, so a lingering read step never blocks a rebind that a later confirmation allows.
            store.run('UPDATE dispatch_steps SET state=? WHERE batch_id=? AND ordinal=1 AND claim_token=?', failure && invocation.kind === 'apply' ? 'uncertain' : 'resolved', batchId, token);
            store.run("UPDATE dispatch_batches SET state='spent' WHERE id=?", batchId);
            store.run('UPDATE integration_state SET dispatch_stopped=1,observation_error=? WHERE singleton=1', failure?.code ?? null);
            if (store.get('SELECT batch_id FROM automatic_read_polls WHERE batch_id=?', batchId)) store.run('UPDATE automatic_read_summary SET completed_at=?,outcome=? WHERE kind=?', w.now(), failure?.code ?? 'observed', invocation.kind);
            settle(w, invocation, o, failure);
            if (o) publish(w, o);
        } finally {
            store.pruneAutomaticReads();
        }
    });
}
