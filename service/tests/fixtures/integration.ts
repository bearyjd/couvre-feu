import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IntegrationConfig } from '../../src/integration-config.ts';
import { IntegrationStore } from '../../src/integration-db.ts';
import { IntegrationPolicy } from '../../src/integration-policy.ts';
import { IntegrationWorker } from '../../src/integration-worker.ts';
import { SSHRouter } from '../../src/ssh-router.ts';
import { RouterTransportError } from '../../src/router-transport.ts';
import { normalizeRouterActivity } from '../../../shared/src/router-activity.ts';
import type { RouterActivity } from '../../../shared/src/router-activity.ts';
import type { AsyncRouter, FrozenInvocation, DispatchKind } from '../../src/router-transport.ts';
import { normalizeEnvelope, policyDigest, requestDigest } from '../../../shared/src/router-rpc.ts';
import type { RPCObservation, RPCEnvelope, RPCReceipt } from '../../../shared/src/router-rpc.ts';
import { normalizePolicy, effectivePauses } from '../../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../../shared/src/router-schema.ts';
import type { Actor } from '../../../shared/src/contracts.ts';

export function testConfig(dir: string): IntegrationConfig {
    return {version: 1, mode: 'integration', port: 4273, dataDir: dir,
        router: {host: '192.168.1.1', user: 'root', port: 22, knownHosts: join(dir, 'known_hosts'), hostFingerprint: 'SHA256:' + 'A'.repeat(43), agentSocket: join(dir, 'agent.sock'), publicIdentity: join(dir, 'service.pub'), publicKeyFingerprint: 'SHA256:' + 'B'.repeat(43), generation: 'a'.repeat(64)},
        person: {id: 'pilot', name: 'Explicit test person', device: {id: 'phone', label: 'Explicit test device', mac: '02:10:20:30:40:50'}},
        protectedMacs: ['02:10:20:30:40:51'], accounts: [{id: 'operator', displayName: 'Test operator', role: 'admin', personIds: ['pilot']}, {id: 'parent', displayName: 'Test parent', role: 'parent', personIds: ['pilot']}],
        enrollment: normalizePolicy({version: 1, revision: 0, people: [{id: 'pilot', macs: ['02:10:20:30:40:50']}], pauses: [], schedules: []}),
        origin: 'http://localhost:4273', host: 'localhost:4273', manifestDigest: 'b'.repeat(64), targetDigest: 'c'.repeat(64), provenance: {source: 'real-router-integration', integrationScope: 'd'.repeat(64), routerCompatibilityVerified: false}};
}
export const actor: Actor = {id: 'operator', displayName: 'Test operator', role: 'admin', personIds: ['pilot'], permissionVersion: '1'};
export function observation(config: IntegrationConfig, policy: RouterPolicy, time: number, receipt: RPCReceipt | null = null): RPCObservation {
    const kids = policy.people.flatMap(p => p.macs).sort(), effective = effectivePauses(policy, time);
    return {rpc_version: 1, generation: config.router.generation, acceptedPolicy: policy, policyDigest: policyDigest(policy), currentOperationId: receipt?.current ? receipt.operationId : null,
        routerTime: time, receipt, errors: [], status: {ok: true, desiredRevision: policy.revision, confirmedRevision: policy.revision, desiredPauses: policy.pauses, effectivePauses: effective,
            observed: {kids, paused: effective.flatMap(p => policy.people.find(person => person.id === p.person)!.macs).sort()}, drift: false, errors: [], capabilities: {ipv6: true, conntrack: true, nativeKernelConfirmed: true, addressCoverageComplete: true, routerCompatibilityVerified: false}}};
}
/** Explicit fake transport for integration tests; never imported by an integration entry point. */
export class TestRouter implements AsyncRouter {
    readonly ssh: SSHRouter;
    readonly config: IntegrationConfig;
    readonly store: IntegrationStore;
    readonly now: () => number;
    policy: RouterPolicy;
    receipts = new Map<string, RPCReceipt>();
    calls: FrozenInvocation[] = [];
    failure: RouterTransportError | null = null;
    afterApplyFailure: RouterTransportError | null = null;
    transform: ((o: RPCObservation) => RPCObservation) | null = null;
    defer: Promise<void> | null = null;
    activity: unknown = null;
    /** Like rpc.sh: an rpc-sync refused under the lock before any write (e.g. a managed device without an address). */
    reject: string | null = null;
    /** Like cf_error_record: a refused transition leaves runtime/error, so status stays not-ok until a later confirmation. */
    runtimeError: string | null = null;
    /** Runs right after an accepted apply, e.g. to simulate a later out-of-band router change. */
    afterApply: (() => void) | null = null;
    constructor(store: IntegrationStore, now: () => number) { this.store = store; this.config = store.config; this.ssh = new SSHRouter(this.config); this.now = now; this.policy = store.config.enrollment; }
    invocation(kind: DispatchKind, envelope?: RPCEnvelope, operationId?: string): FrozenInvocation { return this.ssh.invocation(kind, envelope, operationId); }
    async invokeActivity(i: FrozenInvocation): Promise<RouterActivity> {
        if (this.store.db.isTransaction) throw new Error('test_network_transaction');
        this.calls.push(i);
        if (this.defer) await this.defer;
        if (this.failure) throw this.failure;
        return normalizeRouterActivity(this.activity);
    }
    async invoke(i: FrozenInvocation): Promise<RPCObservation> {
        if (this.store.db.isTransaction) throw new Error('test_network_transaction');
        this.calls.push(i);
        if (this.defer) await this.defer;
        if (this.failure) throw this.failure;
        if (i.kind === 'apply' && this.reject) {
            const code = this.reject;
            if (code === 'incomplete_transition_address_coverage') this.runtimeError = code;
            const current = [...this.receipts.values()].find(r => r.acceptedDigest === policyDigest(this.policy));
            const refused = observation(this.config, this.policy, this.now(), null);
            refused.currentOperationId = current?.operationId ?? null; refused.errors = [code];
            refused.status = {...refused.status, ok: false, errors: [code]};
            return refused;
        }
        if (i.kind === 'apply') {
            const e = normalizeEnvelope(JSON.parse(i.stdin));
            if (e.expected_revision !== this.policy.revision || e.expected_digest !== policyDigest(this.policy)) throw new RouterTransportError('test_rpc_conflict');
            this.policy = e.policy; this.runtimeError = null;
            this.receipts.set(e.operation_id, {operationId: e.operation_id, requestDigest: requestDigest(e), baseRevision: e.expected_revision, baseDigest: e.expected_digest, acceptedRevision: e.policy.revision, acceptedDigest: policyDigest(e.policy), outcome: 'accepted', current: true});
            this.afterApply?.();
            if (this.afterApplyFailure) throw this.afterApplyFailure;
        }
        const current = [...this.receipts.values()].find(r => r.acceptedDigest === policyDigest(this.policy));
        const requested = i.operationId ? this.receipts.get(i.operationId) : current;
        const receipt = requested ? {...requested, current: requested.acceptedDigest === policyDigest(this.policy)} : null;
        const result = observation(this.config, this.policy, this.now(), receipt);
        result.currentOperationId = current?.operationId ?? null;
        if (this.runtimeError) result.status = {...result.status, ok: false, errors: ['previous_apply_failed']};
        return this.transform ? this.transform(result) : result;
    }
}
export function integrationFixture() {
    const dir = mkdtempSync(join(tmpdir(), 'cf-integration-test-')), config = testConfig(dir), store = new IntegrationStore(config);
    let clock = 1791691200;
    const now = () => clock, policy = new IntegrationPolicy(store, now), router = new TestRouter(store, now), worker = new IntegrationWorker(store, router, now);
    return {dir, config, store, now, policy, router, worker, advance: (seconds: number) => {clock += seconds;}, cleanup: () => {store.close(); rmSync(dir, {recursive: true, force: true});},
        observe: async () => { const plan = worker.prepare('observe'); await worker.execute(plan, plan.scriptSha256); },
        pause: (until = 0, key = 'test_key_123456789') => policy.mutate(actor, 'pilot', 'pause', {until}, policy.people(actor).revisionToken!, key)};
}
