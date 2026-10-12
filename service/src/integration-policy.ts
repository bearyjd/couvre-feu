import { deviceEvidence } from './device-evidence.ts';
import { operationalAlerts } from './operational-alerts.ts';
import { randomUUID } from 'node:crypto';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { integer, normalizePolicy, policyJSON, healthyConfirmation } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { exactHealthy, normalizeEnvelope, policyDigest, requestDigest } from '../../shared/src/router-rpc.ts';
import type { RPCEnvelope } from '../../shared/src/router-rpc.ts';
import type { Actor, OperationDTO, OperationState, PeopleDTO, OperationResult } from '../../shared/src/contracts.ts';
import { IntegrationStore } from './integration-db.ts';
import { validatePilotPolicy } from './integration-config.ts';
import { integrationScheduleState } from './integration-schedules.ts';

export const OBSERVATION_FRESH_SECONDS = 30;
export interface IntegrationOperation {
    id: string; actor_id: string; person_id: string; action: 'pause' | 'resume'; revision: number;
    state: OperationState; payload_json: string; base_json: string; request_json: string; idempotency_key: string;
    created_at: number; updated_at: number; error: string | null; confirmed_at: number | null;
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
    private authorized(actor: Actor, person: string): void {
        if (person !== this.store.config.person.id || !actor.personIds.includes(person)) throw new AppError(404, 'person_not_found');
    }
    private row(id: string): IntegrationOperation | undefined { return this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id); }
    envelope(id: string): RPCEnvelope {
        const row = this.store.get<{envelope_json: string}>('SELECT envelope_json FROM operation_rpc WHERE operation_id=?', id);
        if (!row) throw new AppError(404, 'operation_not_found');
        return normalizeEnvelope(JSON.parse(row.envelope_json));
    }
    private dto(op: IntegrationOperation): OperationDTO {
        const r = this.store.get<{phase: string; delivery: string}>('SELECT phase,delivery FROM operation_rpc WHERE operation_id=?', op.id)!;
        const o = this.store.observation().value, e = this.envelope(op.id), fresh = this.fresh(), healthy = fresh && o !== null && exactHealthy(o, e);
        const superseded = fresh && o !== null && (o.acceptedPolicy.revision !== e.policy.revision || o.policyDigest !== policyDigest(e.policy) || o.currentOperationId !== op.id);
        const uncertainClaim = r.phase === 'claimed' && (this.store.get<{lease_until: number}>('SELECT lease_until FROM operation_rpc WHERE operation_id=?', op.id)!.lease_until <= this.now());
        return {...this.store.config.provenance, id: op.id, personId: op.person_id, action: op.action, revision: op.revision,
            // A historical confirmation is retained in confirmedAt, never rendered as current enforcement.
            state: uncertainClaim ? 'unknown' : op.state === 'confirmed' && !healthy ? superseded ? 'conflict' : 'unknown' : op.state, createdAt: op.created_at, updatedAt: op.updated_at,
            error: uncertainClaim ? 'dispatch_lease_expired_remote_outcome_unknown' : op.state === 'confirmed' && !healthy ? superseded ? 'router_receipt_historical' : 'current_router_confirmation_unavailable' : op.error, confirmedAt: op.confirmed_at,
            currentHealthy: healthy, accepted: r.delivery === 'accepted', dispatch: r.phase === 'queued' ? this.automaticEnabled() ? 'awaiting_automatic_dispatch' : 'awaiting_operator_dispatch' : r.phase === 'claimed' ? 'consumed' : r.phase === 'uncertain' ? 'uncertain' : 'resolved'};
    }
    operation(actor: Actor, id: string): OperationDTO {
        const op = this.row(id);
        if (!op || !actor.personIds.includes(op.person_id)) throw new AppError(404, 'operation_not_found');
        return this.dto(op);
    }
    private state() { return this.store.get<{desired_json: string; highwater: number; last_confirmation_at: number | null}>('SELECT * FROM service_state WHERE singleton=1')!; }
    private token(): string | null {
        const o = this.store.observation().value;
        return this.fresh() && o ? `"s${this.state().highwater}-r${o.acceptedPolicy.revision}-${o.policyDigest}"` : null;
    }
    private result(op: IntegrationOperation): {status: number; result: OperationResult} {
        const dto = this.dto(op);
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
            const prior = this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key);
            if (prior) { if (prior.request_json !== request) throw new AppError(409, 'idempotency_payload_conflict'); return prior; }
            if (until !== null && until !== 0 && until <= this.now()) throw new AppError(400, 'pause_expiry_must_be_future');
            if (!this.fresh()) throw new AppError(503, 'approved_router_observation_required');
            const o = this.store.observation().value!;
            if (precondition !== this.token()) throw new AppError(409, 'revision_conflict');
            if (this.store.integrationState().active_operation_id !== null) throw new AppError(409, 'operation_in_progress');
            if (o.generation !== this.store.config.router.generation || o.errors.length || !healthyConfirmation(o.status, o.acceptedPolicy, o.routerTime)) throw new AppError(503, 'router_runtime_unconfirmed');
            validatePilotPolicy(o.acceptedPolicy, this.store.config, false);
            const policy = normalizePolicy({...o.acceptedPolicy, revision: o.acceptedPolicy.revision + 1,
                pauses: [...o.acceptedPolicy.pauses.filter(p => p.person !== person), ...(action === 'pause' ? [{person, until: until!}] : [])]}, this.store.config.protectedMacs);
            validatePilotPolicy(policy, this.store.config, false);
            const id = randomUUID(), now = this.now();
            const envelope = normalizeEnvelope({rpc_version: 1, generation: o.generation, operation_id: id, expected_revision: o.acceptedPolicy.revision, expected_digest: o.policyDigest, policy});
            this.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error) VALUES(?,?,?,?,?,'pending',?,?,?,?,?,?,?)", id, actor.id, person, action, policy.revision, policyJSON(policy), policyJSON(o.acceptedPolicy), request, key, now, now, this.automaticEnabled() ? 'awaiting_automatic_dispatch' : 'awaiting_operator_dispatch');
            this.store.run("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase) VALUES(?,?,?,?,?,'queued')", id, o.generation, o.policyDigest, requestDigest(envelope), JSON.stringify(envelope));
            this.store.run('UPDATE integration_state SET active_operation_id=? WHERE singleton=1', id);
            this.store.run('UPDATE service_state SET desired_json=?,highwater=highwater+1 WHERE singleton=1', policyJSON(policy));
            this.store.run("INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,'pending')", actor.id, id, action, policy.revision, now);
            return this.row(id)!;
        });
        return this.result(op);
    }
    people(actor: Actor): PeopleDTO {
        const state = this.state(), info = this.store.integrationState(), cached = this.store.observation(), o = cached.value;
        const enrolled = o !== null && o.acceptedPolicy.people.length === 1 && o.acceptedPolicy.people[0].id === this.store.config.person.id && o.acceptedPolicy.people[0].macs.length === 1 && o.acceptedPolicy.people[0].macs[0] === this.store.config.person.device.mac;
        const healthy = enrolled && this.fresh() && o !== null && o.errors.length === 0 && healthyConfirmation(o.status, o.acceptedPolicy, o.routerTime);
        const p = this.store.config.person, latest = this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE person_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1', p.id);
        const dto = latest ? this.dto(latest) : null;
        const errors = [...(info.observation_error ? [info.observation_error] : []), ...(!this.fresh() ? ['approved_router_observation_required'] : []), ...(o?.errors ?? []), ...(o?.status.errors ?? [])];
        if (!enrolled) errors.push('pilot_device_not_enrolled');
        if (latest && ['pending', 'unknown'].includes(latest.state)) errors.push(latest.error ?? 'awaiting_operator_dispatch');
        return {...this.store.config.provenance, packetAcceptance: 'unmeasured', people: actor.personIds.includes(p.id) ? [{id: p.id, name: p.name, devices: [{id: p.device.id, label: p.device.label, evidence: deviceEvidence({source: 'router-policy', now: this.now(),
            sourceObservedAt: o?.routerTime ?? null, serviceReceivedAt: cached.observedAt, personId: p.id, mac: p.device.mac, configuredMacs: [p.device.mac],
            policy: o?.acceptedPolicy ?? null, status: o?.status ?? null, readError: Boolean(info.observation_error || o?.errors.length),
            generationMatches: o?.generation === this.store.config.router.generation})}],
            manualPause: o?.acceptedPolicy.pauses.find(a => a.person === p.id) ?? null, effectiveManualPause: o?.status.effectivePauses.find(a => a.person === p.id) ?? null,
            ...integrationScheduleState(enrolled ? o!.acceptedPolicy : this.store.config.enrollment, this.store.config, o?.routerTime ?? null, healthy, this.now(), Math.min(cached.observedAt ?? 0, o?.routerTime ?? 0) + OBSERVATION_FRESH_SECONDS + 1),
            observationHealth: info.observation_error ? 'unreachable' : healthy ? 'healthy' : 'unconfirmed', status: dto?.state ?? (healthy ? 'confirmed' : 'unknown'), latestOperation: dto,
            operationalAlerts: operationalAlerts({source: 'router-policy', now: this.now(), sourceObservedAt: o?.routerTime ?? null, serviceReceivedAt: cached.observedAt,
                generationMatches: o?.generation === this.store.config.router.generation, readError: Boolean(info.observation_error || o?.errors.length), healthy,
                drift: o?.status.drift === true, pauseUntil: o?.acceptedPolicy.pauses.find(pause => pause.person === p.id)?.until ?? null,
                expiredEffectivePause: Boolean(o?.status.effectivePauses.some(pause => pause.person === p.id && pause.until > 0 && pause.until <= (o?.routerTime ?? 0))),
                operation: dto, operationHealthy: dto?.currentHealthy === true})}] : [],
            serviceDesiredRevision: normalizePolicy(JSON.parse(state.desired_json)).revision, routerDesiredRevision: o?.status.desiredRevision ?? null,
            routerConfirmedRevision: healthy ? o!.status.confirmedRevision : null, revisionToken: healthy && !info.active_operation_id ? this.token() : null,
            observedAt: cached.observedAt, statusAgeSeconds: cached.observedAt === null ? null : Math.max(0, this.now() - cached.observedAt), lastSuccessfulConfirmationAt: state.last_confirmation_at, errors: [...new Set(errors)]};
    }
    devices(actor: Actor) {
        if (actor.role !== 'admin') throw new AppError(403, 'admin_required');
        const p = this.store.config.person;
        return {...this.store.config.provenance, devices: [{...p.device, personId: p.id}]};
    }
    private automaticEnabled(): boolean {
        return !!this.store.config.dispatch?.enabled && this.store.get<{enabled: number}>('SELECT enabled FROM automatic_dispatch WHERE singleton=1')?.enabled === 1;
    }
}
