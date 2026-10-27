import { deviceEvidence } from './device-evidence.ts';
import { operationalAlerts } from './operational-alerts.ts';
import { randomUUID } from 'node:crypto';
import { digest } from './auth.ts';
import type { Actor, OperationAction, OperationDTO, OperationState, OperationResult, PeopleDTO } from '../../shared/src/contracts.ts';
import { provenance } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { integer, normalizePolicy, policyJSON, MAX_INTEGER, healthyConfirmation, scheduleBlocked, effectivePauses } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { applyScheduleChange, parseScheduleChange } from '../../shared/src/schedule-edit.ts';
import type { ScheduleAction } from '../../shared/src/schedule-edit.ts';
import type { FakeRouter, RouterObservation } from '../../demo-router/src/router.ts';
import { FICTIONAL_PEOPLE, PROTECTED_MACS } from './fixtures.ts';
import type { Store } from './db.ts';
interface StateRow {
    desired_json: string;
    highwater: number;
    observation_json: string | null;
    observed_at: number | null;
    last_confirmation_at: number | null;
}
interface OperationRow {
    id: string;
    actor_id: string;
    person_id: string;
    action: OperationAction;
    revision: number;
    state: OperationState;
    payload_json: string;
    base_json: string;
    request_json: string;
    idempotency_key: string;
    created_at: number;
    updated_at: number;
    error: string | null;
    confirmed_at: number | null;
}
export class PolicyService {
    readonly store: Store;
    readonly router: FakeRouter;
    readonly now: () => number;
    private lastReadError: string | null = null;
    private observedHighwater = 0;
    constructor(store: Store, router: FakeRouter, now = () => Math.floor(Date.now() / 1000)) {
        this.store = store;
        this.router = router;
        this.now = now;
    }
    private state() {
        return this.store.get<StateRow>('SELECT * FROM service_state WHERE singleton=1')!;
    }
    private authorize(actor: Actor, person: string) {
        if (!actor.personIds.includes(person) || !FICTIONAL_PEOPLE.some(p => p.id === person)) {
            throw new AppError(404, 'person_not_found');
        }
    }
    private dto(op: OperationRow): OperationDTO {
        return {
            ...provenance, id: op.id, personId: op.person_id, action: op.action, revision: op.revision, state: op.state, createdAt: op.created_at, updatedAt: op.updated_at, error: op.error, confirmedAt: op.confirmed_at
        };
    }
    operation(actor: Actor, id: string): OperationDTO {
        const row = this.store.get<OperationRow>('SELECT * FROM operations WHERE id=?', id);
        if (!row || !actor.personIds.includes(row.person_id)) {
            throw new AppError(404, 'operation_not_found');
        }
        return this.dto(row);
    }
    private fresh(observation: RouterObservation): boolean {
        return observation.routerTime <= this.now() + 1 && this.now() - observation.routerTime <= 3;
    }
    private revisionToken(highwater: number, policy: RouterPolicy): string {
        return `"s${highwater}-r${policy.revision}-${digest(policyJSON(policy))}"`;
    }
    private observe(): RouterObservation {
        const observation = this.router.observe();
        if (!this.fresh(observation)) {
            this.lastReadError = 'synthetic_router_heartbeat_stale';
            throw new AppError(503, this.lastReadError);
        }
        this.store.transaction(() => {
            const state = this.state();
            this.observedHighwater = Math.max(state.highwater, observation.policy.revision);
            this.store.run('UPDATE service_state SET observation_json=?,observed_at=?,highwater=? WHERE singleton=1', JSON.stringify(observation), observation.routerTime, Math.max(state.highwater, observation.policy.revision));
            if (policyJSON(observation.policy) === state.desired_json && healthyConfirmation(observation.status, observation.policy, observation.routerTime)) {
                this.store.run('UPDATE service_state SET last_confirmation_at=MAX(COALESCE(last_confirmation_at,0),?) WHERE singleton=1', observation.routerTime);
            }
        });
        this.lastReadError = null;
        return observation;
    }
    private update(op: OperationRow, state: OperationState, error: string | null, confirmedAt: number | null = null) {
        this.store.transaction(() => this.updateInside(op, state, error, confirmedAt));
    }
    private updateInside(op: OperationRow, state: OperationState, error: string | null, confirmedAt: number | null = null) {
        const current = this.store.get<OperationRow>('SELECT * FROM operations WHERE id=?', op.id)!;
        if (!['pending', 'unknown'].includes(current.state) || (current.state === state && current.error === error)) return;
        this.store.run('UPDATE operations SET state=?,error=?,updated_at=?,confirmed_at=? WHERE id=?', state, error, this.now(), confirmedAt, op.id);
        this.store.run('INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,?)', op.actor_id, op.id, op.action, op.revision, this.now(), state);
    }
    private applyOperation(op: OperationRow): void {
        // Synchronous local fake only: service -> fake lock order, no await or network under either lock.
        // Eligibility, apply, and outcome serialize across service processes. RPC needs a different design.
        this.store.transaction(() => {
            const current = this.store.get<OperationRow>('SELECT * FROM operations WHERE id=?', op.id)!;
            if (!['pending', 'unknown'].includes(current.state)) return;
            try {
                this.router.apply(normalizePolicy(JSON.parse(current.payload_json)), current.id, { revision: normalizePolicy(JSON.parse(current.base_json)).revision, policyJSON: current.base_json });
                this.updateInside(current, 'pending', 'awaiting_exact_confirmation');
            } catch (error) {
                const code = error instanceof AppError ? error.code : 'router_apply_failed';
                const state = error instanceof AppError && error.status === 409 ? 'conflict' : error instanceof AppError && error.status === 502 ? 'failed' : 'unknown';
                this.updateInside(current, state, code);
            }
        });
    }
    reconcile(): void {
        let observation: RouterObservation;
        try {
            observation = this.observe();
        }
        catch (error) {
            this.lastReadError = error instanceof AppError ? error.code : 'router_observation_failed';
            for (const op of this.store.all<OperationRow>("SELECT * FROM operations WHERE state IN ('pending','unknown')")) {
                this.update(op, 'unknown', this.lastReadError);
            }
            return;
        }
        for (const op of this.store.all<OperationRow>("SELECT * FROM operations WHERE state IN ('pending','unknown')")) {
            const payload = normalizePolicy(JSON.parse(op.payload_json));
            if (observation.policy.revision > op.revision || (observation.policy.revision === op.revision && (policyJSON(observation.policy) !== op.payload_json || observation.appliedOperationId !== op.id))) {
                this.update(op, 'conflict', 'router_local_or_competing_change');
                continue;
            }
            if (observation.policy.revision === op.revision) {
                if (healthyConfirmation(observation.status, payload, observation.routerTime)) {
                    this.update(op, 'confirmed', null, observation.routerTime);
                }
                else if (op.state !== 'unknown') {
                    this.update(op, 'pending', observation.status.errors[0] ?? (observation.status.drift ? 'router_drift' : 'awaiting_exact_confirmation'));
                }
                continue;
            }
            // A persisted pending operation can replay only its exact original payload after a fresh observation.
            // Expired metadata is retained; the independent router clock decides effective membership.
            this.applyOperation(op);
        }
    }
    private writeHeaders(precondition: string | undefined, key: string | undefined): [string, string] {
        if (!key || !/^[A-Za-z0-9_-]{16,128}$/.test(key)) {
            throw new AppError(400, 'idempotency_key_required');
        }
        if (!precondition || !/^"s(?:0|[1-9][0-9]{0,9})-r(?:0|[1-9][0-9]{0,9})-[0-9a-f]{64}"$/.test(precondition)) {
            throw new AppError(428, 'revision_precondition_required');
        }
        return [precondition, key];
    }
    /** The demo policy is never audited: `_auditAs` only keeps the signature of PolicyPort. */
    mutate(actor: Actor, person: string, action: 'pause' | 'resume', input: unknown, precondition: string | undefined, key: string | undefined, _auditAs?: string | null): {
        status: number;
        result: OperationResult;
    } {
        this.authorize(actor, person);
        const body = object(input, action === 'pause' ? ['until'] : []), until = action === 'pause' ? integer(body.until) : null;
        const [token, idempotencyKey] = this.writeHeaders(precondition, key);
        const request = JSON.stringify({
            person, action, until, precondition: token
        });
        return this.submit(actor, person, action, request, token, idempotencyKey, () => {
            if (until !== null && until !== 0 && until <= this.now()) {
                throw new AppError(400, 'pause_expiry_must_be_future');
            }
        }, observed => ({
            pauses: [...observed.pauses.filter(p => p.person !== person), ...(action === 'pause' ? [{
                        person, until: until!
                    }] : [])]
        }));
    }
    /** Weekly schedule create/edit/delete through the same revision-CAS and durable-intent path as pauses. */
    scheduleMutate(actor: Actor, person: string, action: ScheduleAction, input: unknown, scheduleId: string | undefined, precondition: string | undefined, key: string | undefined): {
        status: number;
        result: OperationResult;
    } {
        this.authorize(actor, person);
        const change = parseScheduleChange(action, input, scheduleId);
        const [token, idempotencyKey] = this.writeHeaders(precondition, key);
        const request = JSON.stringify({
            person, action, schedule: change.action === 'schedule_delete' ? { id: change.id } : change.window, precondition: token
        });
        return this.submit(actor, person, action, request, token, idempotencyKey, () => { }, observed => ({
            schedules: applyScheduleChange(observed.schedules, person, change)
        }));
    }
    private submit(actor: Actor, person: string, action: OperationAction, request: string, precondition: string, key: string, preflight: () => void, change: (observed: RouterPolicy) => Partial<Pick<RouterPolicy, 'pauses' | 'schedules'>>): {
        status: number;
        result: OperationResult;
    } {
        const prior = this.store.get<OperationRow>('SELECT * FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key);
        if (prior) {
            if (prior.request_json !== request) {
                throw new AppError(409, 'idempotency_payload_conflict');
            }
            this.reconcile();
            return this.result(this.store.get<OperationRow>('SELECT * FROM operations WHERE id=?', prior.id)!);
        }
        preflight();
        let observation: RouterObservation;
        try {
            observation = this.observe();
        }
        catch {
            throw new AppError(503, this.lastReadError ?? 'router_unreachable');
        }
        const op = this.store.transaction(() => {
            const duplicate = this.store.get<OperationRow>('SELECT * FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key);
            if (duplicate) {
                if (duplicate.request_json !== request) {
                    throw new AppError(409, 'idempotency_payload_conflict');
                }
                return duplicate;
            }
            const state = this.state();
            if (precondition !== this.revisionToken(state.highwater, observation.policy) || state.highwater !== this.observedHighwater) {
                throw new AppError(409, 'revision_conflict', 'Refresh status before another deliberate action.');
            }
            if (this.store.get("SELECT id FROM operations WHERE state IN ('pending','unknown') LIMIT 1")) {
                throw new AppError(409, 'operation_in_progress');
            }
            const revision = Math.max(state.highwater, observation.policy.revision) + 1;
            if (revision > MAX_INTEGER) {
                throw new AppError(409, 'revision_exhausted');
            }
            const policy: RouterPolicy = normalizePolicy({
                ...observation.policy, revision, ...change(observation.policy)
            }, PROTECTED_MACS);
            const id = randomUUID(), now = this.now(), payload = policyJSON(policy);
            this.store.run('INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES(?,?,?,?,?,\'pending\',?,?,?,?,?,?)', id, actor.id, person, action, revision, payload, policyJSON(observation.policy), request, key, now, now);
            this.store.run('UPDATE service_state SET desired_json=?,highwater=? WHERE singleton=1', payload, revision);
            this.store.run('INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,?)', actor.id, id, action, revision, now, 'pending');
            return this.store.get<OperationRow>('SELECT * FROM operations WHERE id=?', id)!;
        });
        if (op.state === 'pending') this.applyOperation(op);
        this.reconcile();
        return this.result(this.store.get<OperationRow>('SELECT * FROM operations WHERE id=?', op.id)!);
    }
    private result(op: OperationRow) {
        const state = this.state(), observation = state.observation_json ? JSON.parse(state.observation_json) as RouterObservation : null;
        const exact = observation && !this.lastReadError && this.fresh(observation) && observation.appliedOperationId === op.id && policyJSON(observation.policy) === op.payload_json && healthyConfirmation(observation.status, observation.policy, observation.routerTime);
        return {
            status: op.state === 'confirmed' && exact ? 200 : op.state === 'failed' ? 502 : op.state === 'conflict' ? 409 : 202, result: {
                ...provenance, operation: this.dto(op), operationUrl: `/operations/${op.id}`
            }
        };
    }
    people(actor: Actor): PeopleDTO {
        this.reconcile();
        const state = this.state(), observation = state.observation_json ? JSON.parse(state.observation_json) as RouterObservation : null;
        const policy = observation?.policy ?? normalizePolicy(JSON.parse(state.desired_json));
        const now = observation?.routerTime ?? this.now(), healthy = !this.lastReadError && observation !== null && healthyConfirmation(observation.status, policy, now);
        return {
            ...provenance, people: FICTIONAL_PEOPLE.filter(p => actor.personIds.includes(p.id)).map(p => {
                const row = this.store.get<OperationRow>('SELECT * FROM operations WHERE person_id=? ORDER BY revision DESC LIMIT 1', p.id), schedule = scheduleBlocked(policy, p.id, now);
                const operation = row ? this.dto(row) : null;
                return {
                    id: p.id, name: p.name, devices: p.devices.map(d => ({
                        id: d.id, label: d.label, evidence: deviceEvidence({source: 'synthetic-policy', now: this.now(), sourceObservedAt: observation?.routerTime ?? null,
                            serviceReceivedAt: null, personId: p.id, mac: d.mac, configuredMacs: p.devices.map(device => device.mac),
                            policy: observation?.policy ?? null, status: observation?.status ?? null, readError: this.lastReadError !== null})
                    })), manualPause: policy.pauses.find(pause => pause.person === p.id) ?? null,
                    effectiveManualPause: effectivePauses(policy, now).find(pause => pause.person === p.id) ?? null, scheduleBlocked: schedule,
                    schedules: policy.schedules.filter(s => s.person === p.id).map(({ id, weekdays, start, stop }) => ({ id, weekdays, start, stop })), schedulesEditable: true,
                    scheduleExplanation: schedule ? 'A fictional UTC schedule window still blocks access. Resume clears only the manual pause.' : 'No fictional UTC schedule window is active.',
                    observationHealth: this.lastReadError ? 'unreachable' : healthy ? 'healthy' : 'unconfirmed', status: this.lastReadError ? 'unknown' : row?.state ?? (healthy ? 'confirmed' : 'unknown'), latestOperation: operation,
                    operationalAlerts: operationalAlerts({source: 'synthetic-policy', now: this.now(), sourceObservedAt: observation?.routerTime ?? null, serviceReceivedAt: null,
                        generationMatches: true, readError: this.lastReadError !== null, healthy, drift: observation?.status.drift === true,
                        pauseUntil: observation?.policy.pauses.find(pause => pause.person === p.id)?.until ?? null,
                        expiredEffectivePause: Boolean(observation?.status.effectivePauses.some(pause => pause.person === p.id && pause.until > 0 && pause.until <= now)),
                        operation, operationHealthy: Boolean(row && observation && observation.appliedOperationId === row.id && policyJSON(observation.policy) === row.payload_json && healthy)})
                };
            }), serviceDesiredRevision: normalizePolicy(JSON.parse(state.desired_json)).revision, routerDesiredRevision: observation?.status.desiredRevision ?? null, revisionToken: !this.lastReadError && observation ? this.revisionToken(state.highwater, observation.policy) : null,
            routerConfirmedRevision: observation?.status.confirmedRevision ?? null, observedAt: state.observed_at, statusAgeSeconds: state.observed_at === null ? null : Math.max(0, this.now() - state.observed_at), lastSuccessfulConfirmationAt: state.last_confirmation_at,
            errors: this.lastReadError ? [this.lastReadError] : (observation?.status.errors ?? [])
        };
    }
    devices(actor: Actor) {
        if (actor.role !== 'admin') {
            throw new AppError(403, 'admin_required');
        }
        return {
            ...provenance, devices: FICTIONAL_PEOPLE.flatMap(p => p.devices.map(d => ({
                ...d, personId: p.id
            })))
        };
    }
}
