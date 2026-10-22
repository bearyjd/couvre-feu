import { deviceEvidence } from './device-evidence.ts';
import { operationalAlerts } from './operational-alerts.ts';
import { randomUUID } from 'node:crypto';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { integer, normalizePolicy, policyJSON, healthyConfirmation } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { RPCObservation } from '../../shared/src/router-rpc.ts';
import { exactHealthy, normalizeEnvelope, policyDigest, requestDigest } from '../../shared/src/router-rpc.ts';
import type { RPCEnvelope } from '../../shared/src/router-rpc.ts';
import type { Actor, OperationDTO, OperationState, PeopleDTO, OperationResult } from '../../shared/src/contracts.ts';
import { IntegrationStore } from './integration-db.ts';
import { integrationScheduleState } from './integration-schedules.ts';
import { activeChildren, configuredMacs, devicesOf, validateManagedPolicy } from './integration-children.ts';
import type { ChildRow } from './integration-children.ts';

export const OBSERVATION_FRESH_SECONDS = 30;
export interface IntegrationOperation {
    id: string; actor_id: string; person_id: string; action: 'pause' | 'resume' | 'enroll' | 'unenroll' | 'pause_all' | 'resume_all' | 'move'; revision: number;
    state: OperationState; payload_json: string; base_json: string; request_json: string; idempotency_key: string;
    created_at: number; updated_at: number; error: string | null; confirmed_at: number | null;
}
/** What a bulk operation means for the household right now; only a healthy confirmation counts as in force. */
function bulkEffect(action: IntegrationOperation['action'], state: OperationState, healthy: boolean): Pick<OperationDTO, 'effect'> | Record<string, never> {
    if (action === 'pause_all') return {effect: state === 'confirmed' && healthy ? 'blocking' : 'not_blocking'};
    if (action === 'resume_all') return {effect: state === 'confirmed' && healthy ? 'unblocked' : state === 'failed' ? 'unchanged' : 'may_still_be_blocked'};
    return {};
}
export class IntegrationPolicy {
    readonly store: IntegrationStore;
    readonly now: () => number;
    constructor(store: IntegrationStore, now = () => Math.floor(Date.now() / 1000)) { this.store = store; this.now = now; }
    reconcile(): void { /* HTTP polling reads persisted witnesses only. */ }
    fresh(): boolean {
        const o = this.store.observation(), time = this.now();
        return !this.store.integrationState().observation_error && o.value !== null && o.observedAt !== null && o.observedAt <= time + 1 && time - o.observedAt <= OBSERVATION_FRESH_SECONDS && o.value.routerTime <= time + 1 && time - o.value.routerTime <= OBSERVATION_FRESH_SECONDS;
    }
    /** Only an active database child inside the actor's scope; anything else is indistinguishable from a missing one. */
    authorized(actor: Actor, person: string): ChildRow {
        const child = actor.personIds.includes(person) ? this.store.get<ChildRow>('SELECT * FROM people WHERE id=? AND active=1', person) : undefined;
        if (!child) throw new AppError(404, 'person_not_found');
        return child;
    }
    private row(id: string): IntegrationOperation | undefined { return this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id); }
    envelope(id: string): RPCEnvelope {
        const row = this.store.get<{envelope_json: string}>('SELECT envelope_json FROM operation_rpc WHERE operation_id=?', id);
        if (!row) throw new AppError(404, 'operation_not_found');
        return normalizeEnvelope(JSON.parse(row.envelope_json));
    }
    /**
     * Every child an operation touches. operation_people is the authority; operations.person_id is only a representative and is
     * always unioned in, so an operation written before M2b (no rows) is still covered and a row set can never be empty.
     */
    affectedPeople(op: Pick<IntegrationOperation, 'id' | 'person_id'>): string[] {
        const rows = this.store.all<{person_id: string}>('SELECT person_id FROM operation_people WHERE operation_id=? ORDER BY person_id', op.id).map(r => r.person_id);
        return [...new Set([op.person_id, ...rows])].sort();
    }
    /** Visibility is "any row": a viewer sees an operation through any child they manage. */
    private visibleTo(actor: Actor, op: IntegrationOperation): boolean { return this.affectedPeople(op).some(person => actor.personIds.includes(person)); }
    private dto(op: IntegrationOperation, viewer?: Actor): OperationDTO {
        const r = this.store.get<{phase: string; delivery: string}>('SELECT phase,delivery FROM operation_rpc WHERE operation_id=?', op.id)!;
        const o = this.store.observation().value, e = this.envelope(op.id), fresh = this.fresh(), healthy = fresh && o !== null && exactHealthy(o, e);
        const superseded = fresh && o !== null && (o.acceptedPolicy.revision !== e.policy.revision || o.policyDigest !== policyDigest(e.policy) || o.currentOperationId !== op.id);
        const uncertainClaim = r.phase === 'claimed' && (this.store.get<{lease_until: number}>('SELECT lease_until FROM operation_rpc WHERE operation_id=?', op.id)!.lease_until <= this.now());
        const state: OperationState = uncertainClaim ? 'unknown' : op.state === 'confirmed' && !healthy ? superseded ? 'conflict' : 'unknown' : op.state;
        // A bulk operation's representative child may be outside the viewer's scope: name one they can see instead.
        const personId = viewer ? this.affectedPeople(op).find(person => viewer.personIds.includes(person)) ?? op.person_id : op.person_id;
        return {...this.store.config.provenance, id: op.id, personId, action: op.action, revision: op.revision, ...bulkEffect(op.action, state, healthy),
            // A historical confirmation is retained in confirmedAt, never rendered as current enforcement.
            state, createdAt: op.created_at, updatedAt: op.updated_at,
            error: uncertainClaim ? 'dispatch_lease_expired_remote_outcome_unknown' : op.state === 'confirmed' && !healthy ? superseded ? 'router_receipt_historical' : 'current_router_confirmation_unavailable' : op.error, confirmedAt: op.confirmed_at,
            currentHealthy: healthy, accepted: r.delivery === 'accepted', dispatch: r.phase === 'queued' ? this.automaticEnabled() ? 'awaiting_automatic_dispatch' : 'awaiting_operator_dispatch' : r.phase === 'claimed' ? 'consumed' : r.phase === 'uncertain' ? 'uncertain' : 'resolved'};
    }
    operation(actor: Actor, id: string): OperationDTO {
        const op = this.row(id);
        if (!op || !this.visibleTo(actor, op)) throw new AppError(404, 'operation_not_found');
        return this.dto(op, actor);
    }
    private state() { return this.store.get<{desired_json: string; highwater: number; last_confirmation_at: number | null}>('SELECT * FROM service_state WHERE singleton=1')!; }
    private token(): string | null {
        const o = this.store.observation().value;
        return this.fresh() && o ? `"s${this.state().highwater}-r${o.acceptedPolicy.revision}-${o.policyDigest}"` : null;
    }
    result(op: IntegrationOperation, viewer?: Actor): {status: number; result: OperationResult} {
        const dto = this.dto(op, viewer);
        return {status: dto.currentHealthy && op.state === 'confirmed' ? 200 : op.state === 'conflict' ? 409 : op.state === 'failed' ? 502 : 202,
            result: {...this.store.config.provenance, operation: dto, operationUrl: `/operations/${op.id}`}};
    }
    mutate(actor: Actor, person: string, action: 'pause' | 'resume', input: unknown, precondition: string | undefined, key: string | undefined): {status: number; result: OperationResult} {
        this.authorized(actor, person);
        const body = object(input, action === 'pause' ? ['until'] : []), until = action === 'pause' ? integer(body.until) : null;
        if (!key || !/^[A-Za-z0-9_-]{16,128}$/.test(key)) throw new AppError(400, 'idempotency_key_required');
        if (!precondition || !/^"s(?:0|[1-9][0-9]{0,9})-r(?:0|[1-9][0-9]{0,9})-[0-9a-f]{64}"$/.test(precondition)) throw new AppError(428, 'revision_precondition_required');
        const request = JSON.stringify({person, action, until, precondition, permissionVersion: actor.permissionVersion});
        const op = this.store.transaction(() => {
            this.store.assertIdentity();
            const prior = this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key);
            if (prior) { if (prior.request_json !== request) throw new AppError(409, 'idempotency_payload_conflict'); return prior; }
            if (until !== null && until !== 0 && until <= this.now()) throw new AppError(400, 'pause_expiry_must_be_future');
            return this.queue(actor, person, action, request, key, precondition, base => {
                if (!base.people.some(p => p.id === person)) throw new AppError(409, 'person_has_no_enrolled_device');
                return normalizePolicy({...base, revision: base.revision + 1,
                    pauses: [...base.pauses.filter(p => p.person !== person), ...(action === 'pause' ? [{person, until: until!}] : [])]}, this.store.config.protectedMacs);
            });
        });
        return this.result(op);
    }
    /**
     * The one CAS path for every router change, inside the caller's transaction: a fresh healthy observation, the caller's
     * revision token, no other change in flight. `build` derives the next policy from the router's accepted policy; `stage`
     * records local intent (e.g. a device row) under the new operation id before the result is validated.
     */
    queue(actor: Actor, person: string, action: IntegrationOperation['action'], request: string, key: string, precondition: string | null,
        build: (base: RouterPolicy) => RouterPolicy, stage?: (id: string) => void, affected: readonly string[] = [person]): IntegrationOperation {
        if (!this.store.db.isTransaction) throw new Error('queue_requires_transaction');
        if (!this.fresh()) throw new AppError(503, 'approved_router_observation_required');
        const o = this.store.observation().value!;
        if (precondition === null || precondition !== this.token()) throw new AppError(409, 'revision_conflict');
        if (this.store.integrationState().active_operation_id !== null) throw new AppError(409, 'operation_in_progress');
        if (o.generation !== this.store.config.router.generation || o.errors.length || !healthyConfirmation(o.status, o.acceptedPolicy, o.routerTime)) throw new AppError(503, 'router_runtime_unconfirmed');
        validateManagedPolicy(o.acceptedPolicy, this.store.config, this.store, false);
        const policy = build(o.acceptedPolicy), id = randomUUID(), now = this.now();
        stage?.(id);
        validateManagedPolicy(policy, this.store.config, this.store, false);
        const envelope = normalizeEnvelope({rpc_version: 1, generation: o.generation, operation_id: id, expected_revision: o.acceptedPolicy.revision, expected_digest: o.policyDigest, policy});
        this.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error) VALUES(?,?,?,?,?,'pending',?,?,?,?,?,?,?)", id, actor.id, person, action, policy.revision, policyJSON(policy), policyJSON(o.acceptedPolicy), request, key, now, now, this.automaticEnabled() ? 'awaiting_automatic_dispatch' : 'awaiting_operator_dispatch');
        for (const child of new Set(affected)) this.store.run('INSERT INTO operation_people(operation_id,person_id) VALUES(?,?)', id, child);
        this.store.run("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase) VALUES(?,?,?,?,?,'queued')", id, o.generation, o.policyDigest, requestDigest(envelope), JSON.stringify(envelope));
        this.store.run('UPDATE integration_state SET active_operation_id=? WHERE singleton=1', id);
        this.store.run('UPDATE service_state SET desired_json=?,highwater=highwater+1 WHERE singleton=1', policyJSON(policy));
        this.store.run("INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,'pending')", actor.id, id, action, policy.revision, now);
        return this.row(id)!;
    }
    /** The router holds exactly the child's configured MACs (none when it has no devices). */
    private enrolled(o: RPCObservation | null, child: string): boolean {
        if (o === null) return false;
        const configured = configuredMacs(this.store, child), routed = o.acceptedPolicy.people.find(p => p.id === child)?.macs ?? [];
        return configured.length === routed.length && configured.every(m => routed.includes(m));
    }
    people(actor: Actor): PeopleDTO {
        const state = this.state(), info = this.store.integrationState(), cached = this.store.observation(), o = cached.value, config = this.store.config;
        const routerHealthy = this.fresh() && o !== null && o.errors.length === 0 && healthyConfirmation(o.status, o.acceptedPolicy, o.routerTime);
        const children = activeChildren(this.store).filter(child => actor.personIds.includes(child.id));
        const errors = [...(info.observation_error ? [info.observation_error] : []), ...(!this.fresh() ? ['approved_router_observation_required'] : []), ...(o?.errors ?? []), ...(o?.status.errors ?? [])];
        let allEnrolled = true;
        const people = children.map(child => {
            const enrolled = this.enrolled(o, child.id), healthy = enrolled && routerHealthy, configured = configuredMacs(this.store, child.id);
            if (!enrolled) allEnrolled = false;
            const latest = this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE person_id=? OR id IN (SELECT operation_id FROM operation_people WHERE person_id=?) ORDER BY created_at DESC,rowid DESC LIMIT 1', child.id, child.id);
            const dto = latest ? this.dto(latest, actor) : null;
            if (latest && ['pending', 'unknown'].includes(latest.state)) errors.push(latest.error ?? 'awaiting_operator_dispatch');
            return {id: child.id, name: child.name, kind: child.kind, devices: devicesOf(this.store, child.id).map(d => ({id: d.id, label: d.label, ...(d.state === 'active' ? {} : {change: d.state === 'enrolling' ? 'adding' as const : d.state === 'moving' ? 'moving' as const : 'removing' as const}),
                evidence: deviceEvidence({source: 'router-policy', now: this.now(), sourceObservedAt: o?.routerTime ?? null, serviceReceivedAt: cached.observedAt, personId: child.id, mac: d.identifier, configuredMacs: configured,
                    policy: o?.acceptedPolicy ?? null, status: o?.status ?? null, readError: Boolean(info.observation_error || o?.errors.length), generationMatches: o?.generation === config.router.generation})})),
                manualPause: o?.acceptedPolicy.pauses.find(a => a.person === child.id) ?? null, effectiveManualPause: o?.status.effectivePauses.find(a => a.person === child.id) ?? null,
                ...integrationScheduleState(enrolled ? o!.acceptedPolicy : config.enrollment, config, o?.routerTime ?? null, healthy, this.now(), Math.min(cached.observedAt ?? 0, o?.routerTime ?? 0) + OBSERVATION_FRESH_SECONDS + 1, child.id),
                observationHealth: info.observation_error ? 'unreachable' as const : healthy ? 'healthy' as const : 'unconfirmed' as const, status: dto?.state ?? (healthy ? 'confirmed' as const : 'unknown' as const), latestOperation: dto,
                operationalAlerts: operationalAlerts({source: 'router-policy', now: this.now(), sourceObservedAt: o?.routerTime ?? null, serviceReceivedAt: cached.observedAt,
                    generationMatches: o?.generation === config.router.generation, readError: Boolean(info.observation_error || o?.errors.length), healthy,
                    drift: o?.status.drift === true, pauseUntil: o?.acceptedPolicy.pauses.find(pause => pause.person === child.id)?.until ?? null,
                    expiredEffectivePause: Boolean(o?.status.effectivePauses.some(pause => pause.person === child.id && pause.until > 0 && pause.until <= (o?.routerTime ?? 0))),
                    operation: dto, operationHealthy: dto?.currentHealthy === true})};
        });
        if (!allEnrolled) errors.push('pilot_device_not_enrolled');
        const healthy = routerHealthy && allEnrolled;
        return {...config.provenance, packetAcceptance: 'unmeasured', people,
            serviceDesiredRevision: normalizePolicy(JSON.parse(state.desired_json)).revision, routerDesiredRevision: o?.status.desiredRevision ?? null,
            routerConfirmedRevision: healthy ? o!.status.confirmedRevision : null, revisionToken: healthy && !info.active_operation_id ? this.token() : null,
            observedAt: cached.observedAt, statusAgeSeconds: cached.observedAt === null ? null : Math.max(0, this.now() - cached.observedAt), lastSuccessfulConfirmationAt: state.last_confirmation_at, errors: [...new Set(errors)]};
    }
    /** Admin-only, scoped: device identifiers never reach parents. */
    devices(actor: Actor) {
        if (actor.role !== 'admin') throw new AppError(403, 'admin_required');
        return {...this.store.config.provenance, devices: activeChildren(this.store).filter(child => actor.personIds.includes(child.id))
            .flatMap(child => devicesOf(this.store, child.id).map(d => ({id: d.id, label: d.label, mac: d.identifier, personId: child.id, state: d.state})))};
    }
    private automaticEnabled(): boolean {
        return !!this.store.config.dispatch?.enabled && this.store.get<{enabled: number}>('SELECT enabled FROM automatic_dispatch WHERE singleton=1')?.enabled === 1;
    }
}
