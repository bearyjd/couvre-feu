import { AppError } from '../../shared/src/errors.ts';
import { allowanceWithinHorizon, healthyConfirmation, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { RPCObservation } from '../../shared/src/router-rpc.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import type { IntegrationOperation, IntegrationPolicy } from './integration-policy.ts';
import type { GrantOutcome, GrantPort, GrantReceipt } from './time-requests.ts';

/** Owner decision (2026-10-26): one grant lifts at most an hour, far inside the router's 4 h admission horizon. */
export const MAX_GRANT_MINUTES = 60;
const GRANT_KEY = /^tr-[A-Za-z0-9_-]{1,124}$/;

/**
 * The next policy with a router-side allowance for `person` ending at `until`. Pauses and schedules are left in place: the router
 * lifts them while the allowance is active and restores them at `until` on its own (core.sh cf_enforced_policy / cf_gated_plan).
 * An active longer allowance is never shortened; other people's allowances, including expired inert ones, are kept as accepted.
 */
export function allowancePolicy(base: RouterPolicy, protectedMacs: string[], person: string, until: number): RouterPolicy {
    if (!base.people.some(p => p.id === person)) throw new AppError(409, 'person_has_no_enrolled_device');
    const prior = base.allowances?.find(a => a.person === person)?.until ?? 0;
    return normalizePolicy({...base, revision: base.revision + 1,
        allowances: [...(base.allowances ?? []).filter(a => a.person !== person), {person, until: Math.max(prior, until)}]}, protectedMacs);
}
/** The allowance the router reports in force for `person`, from a healthy observation only. */
export function allowanceView(o: RPCObservation | null, healthy: boolean, person: string): {until: number} | null {
    const found = healthy && o ? (o.status.effectiveAllowances ?? []).find(a => a.person === person) : undefined;
    return found ? {until: found.until} : null;
}
interface ScheduleClaim { scheduleBlocked: boolean | null; scheduleExplanation: string; scheduleValidUntil: number | null }
/** A router-confirmed allowance lifts the schedule: the child is not shown as schedule-blocked until it ends (or the claim lapses). */
export function scheduleWithAllowance<T extends ScheduleClaim>(schedule: T, allowance: {until: number} | null, validUntil: number): T {
    // Unknown stays unknown (fail safe): an allowance never turns a missing schedule claim into "not blocked".
    if (!allowance || schedule.scheduleBlocked !== true) return schedule;
    return {...schedule, scheduleBlocked: false, scheduleValidUntil: Math.min(allowance.until, validUntil, schedule.scheduleValidUntil ?? Number.MAX_SAFE_INTEGER),
        scheduleExplanation: `${schedule.scheduleExplanation} Extra time is active (router-confirmed allowance); the schedule applies again when it ends.`};
}

/** Writes and follows ask-for-time grants through the one CAS path (IntegrationPolicy.queue). No router access of its own. */
export class IntegrationGrants implements GrantPort {
    readonly policy: IntegrationPolicy;
    constructor(policy: IntegrationPolicy) { this.policy = policy; }
    grant(actor: Actor, person: string, minutes: number, precondition: string | undefined, key: string): GrantReceipt {
        this.policy.authorized(actor, person);
        if (!Number.isInteger(minutes) || minutes < 1 || minutes > MAX_GRANT_MINUTES) throw new AppError(400, 'invalid_minutes');
        if (!GRANT_KEY.test(key)) throw new AppError(400, 'idempotency_key_required');
        const store = this.policy.store;
        // Router time is not part of the replay identity: a retry with the same key returns the first operation and deadline.
        const request = JSON.stringify({person, action: 'allow', minutes, precondition: precondition ?? null, permissionVersion: actor.permissionVersion});
        const op = store.transaction(() => {
            store.assertIdentity();
            const prior = store.get<IntegrationOperation>('SELECT * FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key);
            if (prior) { if (prior.request_json !== request) throw new AppError(409, 'idempotency_payload_conflict'); return prior; }
            return this.policy.queue(actor, person, 'allow', request, key, precondition ?? null, base => {
                // queue() has already required a fresh healthy observation; the horizon is checked against ROUTER time, as admission does.
                const observed = store.observation().value;
                if (!observed) throw new AppError(503, 'approved_router_observation_required');
                const routerTime = observed.routerTime, until = routerTime + minutes * 60;
                if (!allowanceWithinHorizon(until, routerTime)) throw new AppError(409, 'allowance_beyond_horizon');
                return allowancePolicy(base, store.config.protectedMacs, person, until);
            });
        });
        const until = (JSON.parse(op.payload_json) as RouterPolicy).allowances?.find(a => a.person === person)?.until;
        if (until === undefined) throw new AppError(409, 'idempotency_payload_conflict');
        return {operationId: op.id, revision: op.revision, until};
    }
    /**
     * Honest state of a grant: `confirmed` only when its operation is confirmed AND a fresh healthy observation reports the allowance in
     * force; `ended` when the router's accepted policy no longer holds it before its deadline (a pause, bulk pause or unenrol removed it).
     */
    outcome(operationId: string, person: string, until: number): GrantOutcome {
        const store = this.policy.store, op = store.get<{state: string}>('SELECT state FROM operations WHERE id=?', operationId);
        if (!op || op.state === 'failed' || op.state === 'conflict') return 'failed';
        const o = store.observation().value;
        if (op.state !== 'confirmed' || !o || !this.policy.fresh() || o.errors.length || !healthyConfirmation(o.status, o.acceptedPolicy, o.routerTime)) return 'pending';
        if ((o.status.effectiveAllowances ?? []).some(a => a.person === person && a.until >= until)) return 'confirmed';
        const held = (o.acceptedPolicy.allowances ?? []).some(a => a.person === person && a.until >= until);
        return !held && until > o.routerTime ? 'ended' : 'pending';
    }
}
