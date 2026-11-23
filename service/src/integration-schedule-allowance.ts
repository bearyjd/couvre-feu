import type { Actor, OperationResult } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { allowanceWithinHorizon, effectivePauses } from '../../shared/src/router-schema.ts';
import { allowancePolicy, MAX_GRANT_MINUTES } from './integration-allowance.ts';
import { CLIENT_KEY, TOKEN } from './integration-children.ts';
import type { IntegrationConfig } from './integration-config.ts';
import type { IntegrationOperation, IntegrationPolicy } from './integration-policy.ts';
import { schedulesInDatabase } from './integration-schedule-store.ts';
import { activeScheduleEnd } from './integration-schedules.ts';
import { audited } from './parent-audit.ts';
import { scheduleClockReader } from './schedule-clock.ts';

type Action = 'schedule_extra_time' | 'schedule_skip_tonight';
const EXTRA_MINUTES: readonly number[] = [15, 30, MAX_GRANT_MINUTES];

/** The skip deadline or the refusal shared by status and the authoritative write. */
export function scheduleSkipDeadline(config: Pick<IntegrationConfig, 'scheduleClock'>, routerTime: number, windowEnd: number, currentUntil: number):
    number | 'schedule_allowance_cap_exceeded' | 'schedule_clock_unverified' {
    const cap = routerTime + MAX_GRANT_MINUTES * 60, until = Math.min(windowEnd, cap);
    const retainedUntil = Math.max(until, currentUntil);
    if (retainedUntil > cap) return 'schedule_allowance_cap_exceeded';
    const clock = config.scheduleClock, calibration = clock?.conformance;
    if (!calibration || until >= calibration.validUntil || scheduleClockReader(clock.timezone)(until).utcOffsetMinutes !== calibration.utcOffsetMinutes) {
        return 'schedule_clock_unverified';
    }
    return retainedUntil;
}

/** One allowance against the accepted base, under the same authorization and CAS as schedule edits. */
export function scheduleAllowance(policy: IntegrationPolicy, actor: Actor, person: string, action: Action,
    input: unknown, precondition: string | undefined, key: string | undefined): {status: number; result: OperationResult} {
    const store = policy.store, config = store.config;
    if (!schedulesInDatabase(config)) throw new AppError(404, 'route_not_found');
    policy.authorized(actor, person);
    return audited(store, {actor: actor.id, action, now: policy.now, people: () => [person], done: out => ({operationId: out.result.operation.id})}, () => {
        if (!key || !CLIENT_KEY.test(key)) throw new AppError(400, 'idempotency_key_required');
        if (!precondition || !TOKEN.test(precondition)) throw new AppError(428, 'revision_precondition_required');
        const extra = action === 'schedule_extra_time';
        const body = object(input, extra ? ['minutes'] : []);
        const minutes = extra ? body.minutes : null;
        if (extra && (typeof minutes !== 'number' || !EXTRA_MINUTES.includes(minutes))) throw new AppError(400, 'invalid_minutes');
        const request = JSON.stringify({person, action: 'allow', scheduleAllowance: action, minutes, precondition, permissionVersion: actor.permissionVersion});
        const op = store.transaction(() => {
            store.assertIdentity();
            const prior = store.get<IntegrationOperation>('SELECT * FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key);
            if (prior) {
                if (prior.request_json !== request) throw new AppError(409, 'idempotency_payload_conflict');
                return prior;
            }
            return policy.queue(actor, person, 'allow', request, key, precondition, base => {
                if (!base.people.some(p => p.id === person)) throw new AppError(409, 'person_has_no_enrolled_device');
                const {routerTime} = store.observation().value!;
                if (effectivePauses(base, routerTime).some(p => p.person === person)) throw new AppError(409, 'child_paused');
                const now = policy.now(), windowEnd = activeScheduleEnd(base, config, person, routerTime, now);
                if (windowEnd === undefined) throw new AppError(409, 'schedule_clock_unverified');
                if (windowEnd === null || windowEnd <= now) throw new AppError(409, 'schedule_not_active');

                const currentUntil = base.allowances?.find(a => a.person === person)?.until ?? 0;
                const until = typeof minutes === 'number'
                    ? Math.max(currentUntil, routerTime) + minutes * 60
                    : scheduleSkipDeadline(config, routerTime, windowEnd, currentUntil);
                if (typeof until !== 'number') throw new AppError(409, until);
                if (typeof minutes === 'number' && until > routerTime + MAX_GRANT_MINUTES * 60) throw new AppError(409, 'schedule_allowance_cap_exceeded');
                if (!allowanceWithinHorizon(until, routerTime)) throw new AppError(409, 'allowance_beyond_horizon');
                return allowancePolicy(base, config.protectedMacs, person, until);
            }, undefined, [person], undefined, {preserveDoh: true});
        });
        return policy.result(op, actor);
    });
}
