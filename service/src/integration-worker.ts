import { randomUUID } from 'node:crypto';
import { object } from '../../shared/src/json.ts';
import { AppError } from '../../shared/src/errors.ts';
import { sha256, exactHealthy, exactReceipt, normalizeObservation } from '../../shared/src/router-rpc.ts';
import type { RPCObservation } from '../../shared/src/router-rpc.ts';
import { healthyConfirmation, policyJSON } from '../../shared/src/router-schema.ts';
import { IntegrationStore } from './integration-db.ts';
import { IntegrationPolicy } from './integration-policy.ts';
import { validatePilotPolicy } from './integration-config.ts';
import { RouterTransportError } from './router-transport.ts';
import type { AsyncRouter, DispatchKind, FrozenInvocation } from './router-transport.ts';
import type { IntegrationOperation } from './integration-policy.ts';

export interface PreparedDispatch {
    version: 1; targetDigest: string; manifestDigest: string; generation: string; dispatchEpoch: number;
    preparedAt: number; expiresAt: number; invocation: FrozenInvocation; script: string; scriptSha256: string;
}
function quoted(s: string): string { return "'" + s.replace(/'/g, "'\\''") + "'"; }
function renderScript(plan: Omit<PreparedDispatch, 'script' | 'scriptSha256'>, allowedMac: string): string {
    const i = plan.invocation;
    return `# Couvre-feu finite invocation, version 1\n# Target digest: ${plan.targetDigest}\n# Manifest digest: ${plan.manifestDigest}\n# Installation generation: ${plan.generation}\n# Allowed MAC: ${allowedMac}\n# Dispatch epoch: ${plan.dispatchEpoch}\n# Expires at: ${plan.expiresAt}\n# Kind: ${i.kind}; operation: ${i.operationId ?? 'none'}\n# Request digest: ${i.requestDigest}\n# Exactly one attempt; bounded ${i.deadlineMs}ms, stdout 131072 bytes, stderr 16384 bytes.\n# Abort on changed configuration/base, unsafe identity, timeout, or invalid response.\n# No automatic rollback/retry. Unknown delivery requires separately approved receipt or generation fence.\n# Review artifact: the dispatcher invokes this argv with shell=false and the exact stdin below.\n${[i.executable, ...i.argv].map(quoted).join(' ')}${i.stdin ? " <<'CF_RPC_INPUT'\n" + i.stdin + 'CF_RPC_INPUT\n' : ' < /dev/null\n'}`;
}
export class IntegrationWorker {
    readonly store: IntegrationStore;
    readonly router: AsyncRouter;
    readonly policy: IntegrationPolicy;
    readonly now: () => number;
    constructor(store: IntegrationStore, router: AsyncRouter, now = () => Math.floor(Date.now() / 1000)) {
        this.store = store; this.router = router; this.now = now; this.policy = new IntegrationPolicy(store, now);
    }
    /** Preparing a review artifact performs no network call and grants no authorization. */
    prepare(kind: DispatchKind, operationId?: string): PreparedDispatch {
        if ((kind === 'apply' || kind === 'receipt') && !operationId) throw new AppError(400, 'operation_id_required');
        if (kind === 'receipt' && !this.store.get('SELECT id FROM operations WHERE id=?', operationId!)) throw new AppError(404, 'operation_not_found');
        const invocation = this.router.invocation(kind, kind === 'apply' ? this.policy.envelope(operationId!) : undefined, kind === 'receipt' ? operationId : undefined);
        const c = this.store.config, now = this.now();
        const base: Omit<PreparedDispatch, 'script' | 'scriptSha256'> = {version: 1, targetDigest: c.targetDigest, manifestDigest: c.manifestDigest,
            generation: c.router.generation, dispatchEpoch: this.store.integrationState().dispatch_epoch, preparedAt: now, expiresAt: now + 900, invocation};
        const script = renderScript(base, c.person.device.mac);
        return {...base, script, scriptSha256: sha256(script)};
    }
    private validate(plan: PreparedDispatch): FrozenInvocation {
        object(plan, ['version', 'targetDigest', 'manifestDigest', 'generation', 'dispatchEpoch', 'preparedAt', 'expiresAt', 'invocation', 'script', 'scriptSha256']);
        const c = this.store.config, s = this.store.integrationState();
        if (sha256(plan.script) !== plan.scriptSha256) throw new AppError(409, 'dispatch_script_changed');
        if (plan.version !== 1 || plan.targetDigest !== c.targetDigest || plan.manifestDigest !== c.manifestDigest || plan.generation !== c.router.generation || plan.dispatchEpoch !== s.dispatch_epoch || !Number.isSafeInteger(plan.preparedAt) || !Number.isSafeInteger(plan.expiresAt) || plan.preparedAt > this.now() || plan.expiresAt <= this.now() || plan.expiresAt - plan.preparedAt !== 900) throw new AppError(409, 'dispatch_plan_stale_or_changed');
        const i = plan.invocation;
        object(i, ['executable', 'argv', 'stdin', 'deadlineMs', 'kind', 'operationId', 'requestDigest']);
        const expected = this.router.invocation(i.kind, i.kind === 'apply' ? this.policy.envelope(i.operationId!) : undefined, i.kind === 'receipt' ? i.operationId! : undefined);
        if (JSON.stringify(expected) !== JSON.stringify(i)) throw new AppError(409, 'dispatch_invocation_changed');
        const {script: _script, scriptSha256: _digest, ...base} = plan;
        if (renderScript(base, c.person.device.mac) !== plan.script) throw new AppError(409, 'dispatch_script_changed');
        return i;
    }
    /** This CLI-only method consumes one exact permit durably before any possible spawn. */
    async execute(plan: PreparedDispatch, approvedSha: string): Promise<void> {
        if (typeof approvedSha !== 'string' || !/^[a-f0-9]{64}$/.test(approvedSha) || plan.scriptSha256 !== approvedSha || sha256(plan.script) !== approvedSha) throw new AppError(403, 'exact_operator_approval_required');
        await this.run(plan, null);
    }
    /** Only a live manifest-bound owner session can authorize generated invocations. */
    async executeAutomatic(kind: DispatchKind, owner: {token: string; epoch: number}, operationId?: string): Promise<void> {
        await this.run(this.prepare(kind, operationId), owner);
    }
    private async run(plan: PreparedDispatch, owner: {token: string; epoch: number} | null): Promise<void> {
        const invocation = this.validate(plan);
        const batchId = randomUUID(), token = randomUUID(), epoch = plan.dispatchEpoch, now = this.now();
        const invocationDigest = owner ? sha256(plan.script + '\n' + batchId) : plan.scriptSha256;
        this.store.transaction(() => {
            this.validate(plan);
            const automatic = this.store.get<{enabled: number; epoch: number; owner_token: string}>('SELECT * FROM automatic_dispatch WHERE singleton=1');
            if (owner ? !this.store.config.dispatch?.enabled || !automatic?.enabled || automatic.epoch !== owner.epoch || owner.epoch !== epoch || automatic.owner_token !== owner.token : automatic?.enabled) throw new AppError(409, 'automatic_dispatch_authority_required');
            if (this.store.get('SELECT id FROM dispatch_batches WHERE script_sha256=?', invocationDigest)) throw new AppError(409, 'dispatch_permit_already_consumed');
            // An expired local lease authorizes a read-only inspection, never an apply retry.
            if (this.store.get("SELECT batch_id FROM dispatch_steps WHERE state='consumed' AND lease_until>? LIMIT 1", now)) throw new AppError(409, 'dispatch_in_progress');
            this.store.run("UPDATE dispatch_steps SET state='uncertain' WHERE state='consumed' AND lease_until<=?", now);
            if (invocation.kind === 'apply') {
                const id = invocation.operationId!, op = this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id);
                const rpc = this.store.get<{phase: string; attempt_count: number}>('SELECT * FROM operation_rpc WHERE operation_id=?', id);
                if (!op || !rpc || rpc.phase !== 'queued' || rpc.attempt_count !== 0 || op.state !== 'pending' || this.store.integrationState().active_operation_id !== id) throw new AppError(409, 'operation_dispatch_not_eligible');
                if (owner) {
                    const actor = this.store.get<{active: number; person_ids: string; permission_version: number; role: string}>('SELECT * FROM accounts WHERE id=?', op.actor_id);
                    const request = JSON.parse(op.request_json) as {permissionVersion?: string};
                    if (!actor?.active || !['admin', 'parent'].includes(actor.role) || !JSON.parse(actor.person_ids).includes(op.person_id) || String(actor.permission_version) !== request.permissionVersion) {
                        this.updateOperation(id, 'failed', 'actor_permission_changed_before_dispatch');
                        this.store.run("UPDATE operation_rpc SET phase='resolved' WHERE operation_id=?", id);
                        this.store.run('UPDATE integration_state SET active_operation_id=NULL WHERE singleton=1');
                        return;
                    }
                }
                if (!this.policy.fresh()) throw new AppError(503, 'approved_router_observation_required');
                const o = this.store.observation().value!, e = this.policy.envelope(id);
                if (o.generation !== e.generation || o.acceptedPolicy.revision !== e.expected_revision || o.policyDigest !== e.expected_digest || o.errors.length || !healthyConfirmation(o.status, o.acceptedPolicy, o.routerTime)) throw new AppError(409, 'router_base_or_runtime_changed');
                this.store.run("UPDATE operation_rpc SET phase='claimed',claim_token=?,claim_epoch=?,lease_until=?,attempt_count=1,delivery='possible' WHERE operation_id=?", token, epoch, now + 17, id);
                this.store.run("UPDATE operations SET error='awaiting_exact_router_receipt',updated_at=? WHERE id=?", now, id);
            }
            this.store.run("INSERT INTO dispatch_batches(id,script_sha256,target_digest,generation,dispatch_epoch,approved_at,expires_at,state) VALUES(?,?,?,?,?,?,?,'running')", batchId, invocationDigest, plan.targetDigest, plan.generation, epoch, now, plan.expiresAt);
            this.store.run("INSERT INTO dispatch_steps(batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until) VALUES(?,1,?,?,?,?,?,?,'consumed',?,?)", batchId, invocation.operationId, invocation.kind, invocation.requestDigest, JSON.stringify(invocation.argv), invocation.stdin, invocation.deadlineMs, token, now + 17);
            this.store.run('UPDATE integration_state SET dispatch_stopped=0 WHERE singleton=1');
            if (owner && invocation.kind !== 'apply') {
                this.store.run('INSERT INTO automatic_read_polls(batch_id) VALUES(?)', batchId);
                this.store.run(`INSERT INTO automatic_read_summary(kind,dispatch_count,dispatched_at,outcome) VALUES(?,1,?,'claimed_once')
                    ON CONFLICT(kind) DO UPDATE SET dispatch_count=dispatch_count+1,dispatched_at=excluded.dispatched_at,outcome=excluded.outcome`, invocation.kind, now);
            } else if (owner) this.store.run("INSERT INTO audit(actor_id,operation_id,action,timestamp,outcome) VALUES('operator',?,?,?,'claimed_once')", invocation.operationId, 'automatic_apply', now);
        });
        if (!this.store.get('SELECT id FROM dispatch_batches WHERE id=?', batchId)) return;
        // A crash here is deliberately possible delivery. Restart must not replay the operation.
        try {
            if (this.store.db.isTransaction) throw new Error('network_inside_transaction');
            const o = normalizeObservation(await this.router.invoke(invocation));
            if (o.generation !== this.store.config.router.generation) throw new RouterTransportError('router_generation_changed');
            validatePilotPolicy(o.acceptedPolicy, this.store.config);
            if (o.routerTime > this.now() + 1 || this.now() - o.routerTime > 30) throw new RouterTransportError('router_clock_or_observation_stale');
            this.finish(batchId, token, epoch, invocation, o, null);
        } catch (error) {
            const failure = error instanceof RouterTransportError ? error : new RouterTransportError('router_observation_invalid');
            this.finish(batchId, token, epoch, invocation, null, failure);
        }
    }
    private finish(batchId: string, token: string, epoch: number, invocation: FrozenInvocation, o: RPCObservation | null, error: RouterTransportError | null): void {
        this.store.transaction(() => {
            try {
                const s = this.store.integrationState(), step = this.store.get<{claim_token: string; state: string; lease_until: number}>('SELECT claim_token,state,lease_until FROM dispatch_steps WHERE batch_id=? AND ordinal=1', batchId);
                if (!step || step.claim_token !== token || step.state !== 'consumed' || s.dispatch_epoch !== epoch || s.generation !== this.store.config.router.generation || s.dispatch_stopped || step.lease_until < this.now()) return;
                this.store.run("UPDATE dispatch_steps SET state=? WHERE batch_id=? AND ordinal=1 AND claim_token=?", error ? 'uncertain' : 'resolved', batchId, token);
                this.store.run("UPDATE dispatch_batches SET state='spent' WHERE id=?", batchId);
                this.store.run('UPDATE integration_state SET dispatch_stopped=1,observation_error=? WHERE singleton=1', error?.code ?? null);
                if (this.store.get('SELECT batch_id FROM automatic_read_polls WHERE batch_id=?', batchId)) this.store.run('UPDATE automatic_read_summary SET completed_at=?,outcome=? WHERE kind=?', this.now(), error?.code ?? 'observed', invocation.kind);
                const active = s.active_operation_id;
                if (error) {
                    if (invocation.kind === 'apply' && active === invocation.operationId) {
                        const neverDelivered = error.delivery === 'not_delivered';
                        this.store.run("UPDATE operation_rpc SET phase=?,delivery=? WHERE operation_id=? AND claim_token=? AND claim_epoch=?", neverDelivered ? 'resolved' : 'uncertain', error.delivery, active, token, epoch);
                        this.updateOperation(active!, neverDelivered ? 'failed' : 'unknown', error.code);
                        if (neverDelivered) this.store.run('UPDATE integration_state SET active_operation_id=NULL WHERE singleton=1');
                    }
                    return;
                }
                this.store.run('UPDATE service_state SET observation_json=?,observed_at=? WHERE singleton=1', JSON.stringify(o), this.now());
                this.store.run('UPDATE integration_state SET observation_sequence=observation_sequence+1 WHERE singleton=1');
                if (o!.errors.length === 0 && healthyConfirmation(o!.status, o!.acceptedPolicy, o!.routerTime)) this.store.run('UPDATE service_state SET last_confirmation_at=MAX(COALESCE(last_confirmation_at,0),?) WHERE singleton=1', o!.routerTime);
                if (!active) return;
                const e = this.policy.envelope(active), accepted = exactReceipt(o!, e), healthy = accepted && exactHealthy(o!, e);
                if (accepted) {
                    this.store.run("UPDATE operation_rpc SET delivery='accepted',receipt_json=?,phase=? WHERE operation_id=?", JSON.stringify(o!.receipt), healthy || !o!.receipt!.current ? 'resolved' : 'uncertain', active);
                    this.updateOperation(active, healthy ? 'confirmed' : o!.receipt!.current ? 'unknown' : 'conflict', healthy ? null : o!.receipt!.current ? 'accepted_router_runtime_unconfirmed' : 'router_receipt_historical', healthy ? o!.routerTime : null);
                    if (healthy || !o!.receipt!.current) this.store.run('UPDATE integration_state SET active_operation_id=NULL WHERE singleton=1');
                    return;
                }
                const rpc = this.store.get<{attempt_count: number}>('SELECT attempt_count FROM operation_rpc WHERE operation_id=?', active)!;
                if (rpc.attempt_count === 0 && (o!.acceptedPolicy.revision !== e.expected_revision || o!.policyDigest !== e.expected_digest)) {
                    // Positive local no-dispatch witness allows resolving a stale queued intent.
                    this.updateOperation(active, 'conflict', 'router_base_changed_before_dispatch');
                    this.store.run("UPDATE operation_rpc SET phase='resolved' WHERE operation_id=?", active);
                    this.store.run('UPDATE integration_state SET active_operation_id=NULL WHERE singleton=1');
                } else if (rpc.attempt_count > 0) {
                    // Even receipt absence under lock cannot drain a delayed earlier SSH command.
                    this.updateOperation(active, 'unknown', 'receipt_missing_remote_outcome_unknown');
                    this.store.run("UPDATE operation_rpc SET phase='uncertain' WHERE operation_id=?", active);
                }
            } finally {
                this.store.pruneAutomaticReads();
            }
        });
    }
    private updateOperation(id: string, state: 'confirmed' | 'unknown' | 'failed' | 'conflict', error: string | null, confirmedAt: number | null = null): void {
        const op = this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id)!;
        if (op.state === state && op.error === error && (confirmedAt === null || op.confirmed_at === confirmedAt)) return;
        this.store.run('UPDATE operations SET state=?,error=?,confirmed_at=COALESCE(?,confirmed_at),updated_at=? WHERE id=?', state, error, confirmedAt, this.now(), id);
        this.store.run('INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,?)', op.actor_id, id, op.action, op.revision, this.now(), state);
    }
}
