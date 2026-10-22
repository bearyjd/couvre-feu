import { randomBytes } from 'node:crypto';
import { AppError } from '../../shared/src/errors.ts';
import { scopeDigest } from '../../shared/src/router-rpc.ts';
import type { RPCObservation } from '../../shared/src/router-rpc.ts';
import { routerScopeOf } from './integration-config.ts';
import type { IntegrationStore } from './integration-db.ts';
import type { ParentAlerts } from './parent-alerts.ts';

/** A scope request expires after a week (the integration-004 CHECK enforces the same bound). */
export const SCOPE_REQUEST_TTL = 7 * 86400;
export const PENDING_PER_CHILD = 4;
export const SCOPE_CHANGE_RETENTION = 200;
/** Resolved requests older than this go, unless a recorded scope change still points at them. */
export const RESOLVED_REQUEST_RETENTION = 90 * 86400;

interface RequestRow { id: string; person_id: string; mac: string; state: string; requested_by: string }
interface ObservedRow { generation: string; scope_sha: string; scope_json: string }

/**
 * Service-side record of the router's scope. The scope itself is changed only by a router administrator (`cfctl scope-add`);
 * this class records who asked for what, notices when the observed scope grows or shrinks, and tells the admins of every change (critical when no
 * request explains it). A compromised app host that never asks still cannot hide a change, and a reply without scope
 * (old router, busy, failed) is "unknown": it neither shrinks nor replaces the remembered scope.
 */
export class ScopeTracker {
    readonly store: IntegrationStore;
    readonly alerts: Pick<ParentAlerts, 'raise'>;
    readonly now: () => number;
    constructor(store: IntegrationStore, alerts: Pick<ParentAlerts, 'raise'>, now = () => Math.floor(Date.now() / 1000)) {
        this.store = store; this.alerts = alerts; this.now = now;
    }
    private atomic<T>(work: () => T): T { return this.store.db.isTransaction ? work() : this.store.transaction(work); }
    /** The last scope this installation's router reported cleanly (generation-checked), or empty when none is remembered. */
    observedScope(): string[] {
        const row = this.current();
        return row ? JSON.parse(row.scope_json) as string[] : [];
    }
    private current(): ObservedRow | undefined {
        const row = this.store.get<ObservedRow>('SELECT generation,scope_sha,scope_json FROM router_scope_observed WHERE singleton=1');
        return row && row.generation === this.store.config.router.generation ? row : undefined;
    }

    /** Records that `actor` asked for `mac` to join the router scope for `person`. One pending row per MAC, at most four per child. */
    request(actor: {id: string}, person: string, mac: string): {id: string; created: boolean} {
        return this.atomic(() => {
            const now = this.now();
            this.expire(now);
            const generation = this.store.config.router.generation;
            // Rows left by an earlier generation say nothing about this router: they neither dedupe nor count toward the cap.
            const pending = this.store.get<RequestRow>("SELECT id,person_id,mac,state FROM scope_requests WHERE mac=? AND state='pending' AND generation=?", mac, generation);
            // Never says whose request it is: the other child may be outside this admin's scope.
            if (pending) { if (pending.person_id !== person) throw new AppError(409, 'scope_request_conflict'); return {id: pending.id, created: false}; }
            if (this.store.get<{n: number}>("SELECT count(*) n FROM scope_requests WHERE person_id=? AND state='pending' AND generation=?", person, generation)!.n >= PENDING_PER_CHILD) {
                throw new AppError(409, 'scope_request_limit', `At most ${PENDING_PER_CHILD} devices per child can wait for router approval.`);
            }
            const id = `scope_${randomBytes(6).toString('hex')}`;
            this.store.run('INSERT INTO scope_requests(id,person_id,mac,requested_by,state,scope_sha_before,generation,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)',
                id, person, mac, actor.id, 'pending', this.current()?.scope_sha ?? null, generation, now, now + SCOPE_REQUEST_TTL);
            return {id, created: true};
        });
    }

    /** Feed every successful router observation through here, inside the transaction that stores it. */
    observe(o: RPCObservation): void {
        // Absent, busy or failed replies leave scope unknown; they must never look like shrinkage.
        if (!o.scope || !o.scopeSha || o.errors.length > 0) return;
        const scope = o.scope, sha = o.scopeSha;
        this.atomic(() => {
            const now = this.now(), config = this.store.config, row = this.current();
            this.expire(now);
            // With no remembered scope the baseline is the manifest floor, so growth that happened while the service was away still shows.
            const floor = [...routerScopeOf(config)].sort(), before = row ? JSON.parse(row.scope_json) as string[] : floor, beforeSha = row?.scope_sha ?? scopeDigest(floor);
            if (beforeSha !== sha) this.record(before, beforeSha, scope, sha, now);
            this.store.run(`INSERT INTO router_scope_observed(singleton,generation,scope_sha,scope_json,observed_at) VALUES(1,?,?,?,?)
                ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,scope_sha=excluded.scope_sha,scope_json=excluded.scope_json,observed_at=excluded.observed_at`,
                config.router.generation, sha, JSON.stringify(scope), now);
            // The device is enrollable from now on: close every pending request whose MAC the router has taken in.
            for (const pending of this.pendingFor(scope)) {
                this.store.run("UPDATE scope_requests SET state='observed',scope_sha_after=?,resolved_at=? WHERE id=? AND state='pending'", sha, now, pending.id);
            }
            this.store.run('DELETE FROM scope_changes WHERE id<=(SELECT max(id) FROM scope_changes)-?', SCOPE_CHANGE_RETENTION);
        });
    }
    private pendingFor(macs: string[]): RequestRow[] {
        const generation = this.store.config.router.generation;
        return this.store.all<RequestRow>("SELECT id,person_id,mac,state,requested_by FROM scope_requests WHERE state='pending' AND generation=? ORDER BY created_at,id", generation).filter(r => macs.includes(r.mac));
    }
    private record(before: string[], beforeSha: string, after: string[], afterSha: string, now: number): void {
        const added = after.filter(m => !before.includes(m)), removed = before.filter(m => !after.includes(m));
        const requests = this.pendingFor(added);
        // Matched only when the whole change is explained: pure growth, every new MAC asked for.
        const matched = removed.length === 0 && added.length > 0 && added.every(m => requests.some(r => r.mac === m));
        const id = Number(this.store.run('INSERT INTO scope_changes(observed_at,sha_before,sha_after,added_json,removed_json,matched_request_id) VALUES(?,?,?,?,?,?)',
            now, beforeSha, afterSha, JSON.stringify(added), JSON.stringify(removed), matched ? requests.find(r => r.mac === added[0])!.id : null).lastInsertRowid);
        // The audit table is never pruned: it keeps the full account of what changed, who asked and which requests it resolved (scope_changes links only the first).
        const outcome = {result: matched ? 'matched' : 'unmatched', before: beforeSha, after: afterSha, added, removed, requests: requests.map(r => ({id: r.id, mac: r.mac, requestedBy: r.requested_by}))};
        this.store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', 'operator', 'router_scope_change', now, JSON.stringify(outcome));
        // Every change is told to the admins: information when explained, critical when unexplained growth, warning for removal. Counts only: the MACs live in scope_changes and audit.
        this.alerts.raise({kind: 'router_scope_change', personId: null, severity: matched ? 'info' : added.length > 0 ? 'critical' : 'warning', details: {added: added.length, removed: removed.length, matched, changeId: id}});
    }
    private expire(now: number): void {
        this.store.run("UPDATE scope_requests SET state='expired',resolved_at=? WHERE state='pending' AND expires_at<=?", now, now);
        this.store.run("DELETE FROM scope_requests WHERE state<>'pending' AND resolved_at<? AND id NOT IN (SELECT matched_request_id FROM scope_changes WHERE matched_request_id IS NOT NULL)", now - RESOLVED_REQUEST_RETENTION);
    }
}
