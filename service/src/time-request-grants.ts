import type { Store } from './db.ts';
import { AppError } from '../../shared/src/errors.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import type { GrantPort } from './time-requests.ts';
import { auditFor } from './parent-audit.ts';

/** What the grant steps need from TimeRequestService. */
export interface GrantContext {
    store: Store; grants: GrantPort; now: () => number; inFlight: ReadonlySet<string>;
    audit(actor: string, action: string, outcome: string, operationId?: string | null, revision?: number | null): void;
}
interface GrantRow {id: string; person_id: string; attempts: number; allowance_until: number | null; grant_operation_id: string | null; decided_by: string | null}
const RELEASE = "state='pending',apply_via='resume',granted_minutes=NULL,allowance_until=NULL,grant_operation_id=NULL,decided_by=NULL,decided_at=NULL";

/**
 * Approve by writing a router-side allowance. Intent is recorded first ('approving', apply_via='allowance'); the request becomes
 * 'approved' only once the router reports the allowance in force (followGrants). No service-side restore is ever owed: the router
 * re-applies the pause and schedule at the deadline by itself.
 */
export function applyGrant(ctx: GrantContext, actor: Actor, row: GrantRow, minutes: number, precondition: string | null): void {
    if (!precondition) throw new AppError(503, 'router_status_unavailable');
    const key = `tr-${row.id}-a${row.attempts + 1}`;
    ctx.store.transaction(() => {
        const changed = ctx.store.run("UPDATE time_requests SET state='approving',apply_via='allowance',granted_minutes=?,repause_state='none',attempts=attempts+1,decided_by=?,decided_at=? WHERE id=? AND state='pending'",
            minutes, actor.id, ctx.now(), row.id).changes;
        if (!changed) throw new AppError(409, 'request_not_pending');
        ctx.audit(actor.id, 'time_request_approving', 'approving');
    });
    try {
        const receipt = ctx.grants.grant(actor, row.person_id, minutes, precondition, key);
        ctx.store.transaction(() => {
            ctx.store.run("UPDATE time_requests SET grant_operation_id=?,allowance_until=? WHERE id=? AND state='approving'", receipt.operationId, receipt.until, row.id);
            ctx.audit(actor.id, 'time_request_allow', 'applying', receipt.operationId, receipt.revision);
        });
    } catch (error) {
        // The CAS path writes nothing when it refuses: with no witness operation the claim is released so the parent can retry.
        if (witness(ctx, row.person_id, key)) return;
        ctx.store.transaction(() => {
            ctx.store.run(`UPDATE time_requests SET ${RELEASE} WHERE id=? AND state='approving'`, row.id);
            ctx.audit(actor.id, 'time_request_approving', `released:${error instanceof AppError ? error.code : 'grant_failed'}`);
        });
        throw error;
    }
}
function witness(ctx: GrantContext, person: string, key: string): {id: string; payload_json: string} | undefined {
    return ctx.store.get<{id: string; payload_json: string}>('SELECT id,payload_json FROM operations WHERE person_id=? AND idempotency_key=?', person, key);
}
function settle(ctx: GrantContext, row: GrantRow, set: string, from: 'approving' | 'approved', outcome: string, action: string) {
    const changed = ctx.store.transaction(() => {
        const changes = ctx.store.run(`UPDATE time_requests SET ${set} WHERE id=? AND state=?`, row.id, from).changes;
        if (changes) ctx.audit('system', action, outcome, row.grant_operation_id);
        return Boolean(changes);
    });
    // Parent-facing log, written once the transition is committed: an approval the router did not take is failed; a grant a later pause removed has ended.
    if (!changed) return;
    const audit = auditFor(ctx.store), at = ctx.now(), people = [row.person_id], operationId = row.grant_operation_id;
    if (outcome === 'apply_failed') audit.record({actor: row.decided_by ?? 'system', action: 'grant_approve', people, operationId, result: 'failed', at});
    else if (outcome === 'ended') audit.record({actor: 'system', action: 'grant_end', people, operationId, result: 'applied', at});
}
/** Re-links an operation queued just before a crash, or releases an approval that never reached the CAS path. */
function recover(ctx: GrantContext, row: GrantRow): GrantRow | null {
    const op = witness(ctx, row.person_id, `tr-${row.id}-a${row.attempts}`);
    if (!op) {
        settle(ctx, row, RELEASE, 'approving', 'released:no_operation', 'time_request_approving');
        return null;
    }
    const until = (JSON.parse(op.payload_json) as {allowances?: {person: string; until: number}[]}).allowances?.find(a => a.person === row.person_id)?.until ?? null;
    ctx.store.run("UPDATE time_requests SET grant_operation_id=?,allowance_until=? WHERE id=? AND state='approving'", op.id, until, row.id);
    return {...row, grant_operation_id: op.id, allowance_until: until};
}
/** Follows grants: approving -> approved / apply_failed, and marks an approved grant that a later pause ended. */
export function followGrants(ctx: GrantContext): void {
    const now = ctx.now();
    for (const found of ctx.store.all<GrantRow>("SELECT * FROM time_requests WHERE state='approving' AND apply_via='allowance'")) {
        if (ctx.inFlight.has(found.id)) continue;
        const row = found.grant_operation_id ? found : recover(ctx, found);
        if (!row?.grant_operation_id || row.allowance_until === null) continue;
        const outcome = ctx.grants.outcome(row.grant_operation_id, row.person_id, row.allowance_until);
        if (outcome === 'confirmed') settle(ctx, row, "state='approved'", 'approving', 'approved', 'time_request_approve');
        else if (outcome === 'failed') settle(ctx, row, "state='apply_failed',decision_code='grant_not_applied'", 'approving', 'apply_failed', 'time_request_apply_failed');
        else if (outcome === 'ended' || row.allowance_until <= now) settle(ctx, row, "state='apply_failed',decision_code='grant_not_in_force'", 'approving', 'apply_failed', 'time_request_apply_failed');
    }
    for (const row of ctx.store.all<GrantRow>("SELECT * FROM time_requests WHERE state='approved' AND apply_via='allowance' AND decision_code IS NULL AND grant_operation_id IS NOT NULL AND allowance_until>?", now)) {
        if (ctx.grants.outcome(row.grant_operation_id!, row.person_id, row.allowance_until!) === 'ended') settle(ctx, row, "decision_code='grant_ended'", 'approved', 'ended', 'time_request_grant_end');
    }
}
