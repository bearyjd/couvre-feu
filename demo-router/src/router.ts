/** Fictional file-backed router simulator. Contains no network, SSH, or target configuration. */
import { Store } from '../../service/src/db.ts';
import { INITIAL_POLICY, PROTECTED_MACS } from '../../service/src/fixtures.ts';
import { effectivePauses, normalizePolicy, policyJSON, MAX_INTEGER } from '../../shared/src/router-schema.ts';
import type { RouterPolicy, RouterStatus } from '../../shared/src/router-schema.ts';
import { AppError } from '../../shared/src/errors.ts';
const MIGRATION = `CREATE TABLE fake_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), policy TEXT NOT NULL, confirmed_revision INTEGER, highwater INTEGER NOT NULL, ready_at REAL NOT NULL, fault TEXT NOT NULL, next_fault TEXT NOT NULL, operation_id TEXT) STRICT;`;
export const SCENARIOS = ['healthy', 'pending', 'drift', 'errors', 'coverage', 'stale', 'unreachable', 'failed', 'timeout'] as const;
export type Scenario = typeof SCENARIOS[number];
interface Row {
    policy: string;
    confirmed_revision: number | null;
    highwater: number;
    ready_at: number;
    fault: Scenario;
    next_fault: Scenario;
    operation_id: string | null;
}
export interface RouterObservation {
    policy: RouterPolicy;
    status: RouterStatus;
    appliedOperationId: string | null;
    routerTime: number;
}
export class FakeRouter {
    readonly store: Store;
    readonly now: () => number;
    readonly delay: number;
    constructor(path: string, options: {
        now?: () => number;
        delay?: number;
    } = {}) {
        this.store = new Store(path, MIGRATION);
        this.now = options.now ?? (() => Date.now() / 1000);
        this.delay = options.delay ?? 0.35;
        // Creating the transport is not an engine heartbeat or confirmation.
        this.store.run('INSERT OR IGNORE INTO fake_state(singleton,policy,confirmed_revision,highwater,ready_at,fault,next_fault) VALUES(1,?,NULL,0,0,\'healthy\',\'healthy\')', policyJSON(INITIAL_POLICY));
    }
    private row(): Row {
        return this.store.get<Row>('SELECT * FROM fake_state WHERE singleton=1')!;
    }
    /** The independent fake-router worker owns this tick, not the service reconciler. */
    tick(): void {
        this.store.transaction(() => {
            const row = this.row(), policy = normalizePolicy(JSON.parse(row.policy)), now = this.now();
            if (now < 1577836800 || now > MAX_INTEGER) {
                throw new Error('invalid_router_clock');
            }
            const revision = row.ready_at <= now && !['pending', 'unreachable', 'failed', 'stale'].includes(row.fault) ? policy.revision : row.confirmed_revision;
            this.store.run('UPDATE fake_state SET highwater=?,confirmed_revision=? WHERE singleton=1', Math.max(row.highwater, Math.floor(now)), revision);
        });
    }
    observe(): RouterObservation {
        const row = this.row();
        if (row.fault === 'unreachable' || row.next_fault === 'unreachable') {
            throw new AppError(503, 'router_unreachable');
        }
        const policy = normalizePolicy(JSON.parse(row.policy)), effective = effectivePauses(policy, row.highwater), pending = row.confirmed_revision !== policy.revision;
        const errors = row.fault === 'errors' ? ['synthetic_apply_error'] : row.fault === 'coverage' ? ['incomplete_address_coverage'] : [];
        return {
            policy, appliedOperationId: row.operation_id, routerTime: row.highwater, status: {
                ok: !pending && row.fault === 'healthy', desiredRevision: policy.revision,
                confirmedRevision: row.fault === 'stale' ? Math.max(0, policy.revision - 1) : row.confirmed_revision,
                desiredPauses: policy.pauses, effectivePauses: effective,
                observed: {
                    kids: policy.people.flatMap(p => p.macs).sort(), paused: effective.flatMap(p => policy.people.find(person => person.id === p.person)!.macs).sort()
                },
                drift: row.fault === 'drift', errors,
                capabilities: {
                    ipv6: true, conntrack: true, nativeKernelConfirmed: true, addressCoverageComplete: row.fault !== 'coverage', routerCompatibilityVerified: false
                },
            }
        };
    }
    apply(policy: RouterPolicy, operationId: string, base: {
        revision: number;
        policyJSON: string;
    }): RouterObservation {
        const next = normalizePolicy(policy, PROTECTED_MACS);
        let timeout = false, failed = false;
        this.store.transaction(() => {
            const row = this.row(), current = normalizePolicy(JSON.parse(row.policy));
            if (row.next_fault === 'unreachable' || row.fault === 'unreachable') {
                throw new AppError(503, 'router_unreachable');
            }
            if (next.revision < current.revision || (next.revision === current.revision && policyJSON(next) !== policyJSON(current))) {
                throw new AppError(409, 'router_revision_conflict');
            }
            if (next.revision === current.revision) {
                if (row.operation_id !== operationId) {
                    throw new AppError(409, 'router_operation_conflict');
                }
                return;
            }
            if (current.revision !== base.revision || policyJSON(current) !== base.policyJSON) {
                throw new AppError(409, 'router_base_conflict');
            }
            if (row.next_fault === 'failed') {
                this.store.run("UPDATE fake_state SET next_fault='healthy' WHERE singleton=1");
                failed = true;
                return;
            }
            timeout = row.next_fault === 'timeout';
            const fault = timeout ? 'healthy' : row.next_fault;
            this.store.run('UPDATE fake_state SET policy=?,ready_at=?,fault=?,next_fault=\'healthy\',operation_id=? WHERE singleton=1', policyJSON(next), this.now() + this.delay, fault, operationId);
        });
        if (failed) {
            throw new AppError(502, 'synthetic_apply_failed');
        }
        if (timeout) {
            throw new AppError(504, 'router_timeout_after_possible_apply');
        }
        return this.observe();
    }
    scenario(scenario: Scenario) {
        this.store.run('UPDATE fake_state SET next_fault=?,fault=CASE WHEN ?=\'healthy\' THEN \'healthy\' ELSE fault END WHERE singleton=1', scenario, scenario);
    }
    localAdvance(): number {
        return this.store.transaction(() => {
            const row = this.row(), policy = normalizePolicy(JSON.parse(row.policy));
            if (policy.revision >= MAX_INTEGER) {
                throw new Error('revision_exhausted');
            }
            policy.revision++;
            this.store.run('UPDATE fake_state SET policy=?,confirmed_revision=?,operation_id=NULL WHERE singleton=1', policyJSON(policy), policy.revision);
            return policy.revision;
        });
    }
    close() {
        this.store.close();
    }
}
