import { AppError } from '../../shared/src/errors.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import type { Store } from './db.ts';
import type { IntegrationManifest } from './integration-config.ts';

/** Audit rows older than this are deleted. */
export const AUDIT_RETENTION_SECONDS = 90 * 86400;
export const AUDIT_PAGE_DEFAULT = 50;
/** A page never exceeds this, whatever the caller asks for. */
export const AUDIT_PAGE_MAX = 100;
const PRUNE_BATCH = 500;
const PRUNE_BATCHES = 4;
const SCOPE_MAX = 64;

export const AUDIT_ACTIONS = ['pause', 'resume', 'pause_all', 'resume_all', 'device_assign', 'device_move', 'device_remove', 'grant_approve', 'grant_decline', 'grant_end'] as const;
export type AuditAction = typeof AUDIT_ACTIONS[number];
/** applied: accepted and queued (the router's own outcome stays on the operation). refused: rejected before anything was queued. failed: could not be carried out. */
export type AuditResult = 'applied' | 'failed' | 'refused';
export interface AuditEntry { actor: string; action: AuditAction; people: readonly string[]; operationId?: string | null; result: AuditResult; at?: number }
export interface AuditEntryDTO { id: number; at: number; actorId: string; actorName: string | null; action: AuditAction; personId: string | null; operationId: string | null; result: AuditResult }
export interface AuditPage { entries: AuditEntryDTO[]; nextBefore: number | null }
interface Row { id: number; at: number; actor_id: string; actor_name: string | null; action: AuditAction; person_id: string | null; operation_id: string | null; result: AuditResult }

/** What a call site tells `audited` about one parent action. `people` is read when the entry is written, so it may fill in as the work proceeds. */
export interface AuditContext<T> {
    actor: string; action: AuditAction; now: () => number; people: () => readonly string[];
    done: (result: T) => {operationId: string | null; people?: readonly string[]; result?: AuditResult};
}

/**
 * Who did what, per child. Stores ids and enums only (see migration 010) and is written only when the manifest's auditLog.enabled is true.
 * A failed write is logged by tag and swallowed: an audit problem must never turn a router operation that succeeded into an error.
 */
export class ParentAudit {
    readonly store: Store;
    readonly now: () => number;
    constructor(store: Store, now = () => Math.floor(Date.now() / 1000)) { this.store = store; this.now = now; }
    /** Read on every call so the flag is exactly the manifest's; the demo store has no config and is always off. */
    get enabled(): boolean { return (this.store as {config?: Pick<IntegrationManifest, 'auditLog'>}).config?.auditLog?.enabled === true; }

    record(entry: AuditEntry): void {
        if (!this.enabled) return;
        try {
            const at = entry.at ?? this.now(), people = entry.people.length ? [...new Set(entry.people)] : [null];
            const write = () => { for (const person of people) this.store.run('INSERT OR IGNORE INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,?,?,?,?)', at, entry.actor, entry.action, person, entry.operationId ?? null, entry.result); };
            if (this.store.db.isTransaction) write(); else this.store.transaction(write);
        } catch { process.stderr.write('parent_audit_write_failed\n'); }
    }

    /** Assigned children always; entries with no child only for admins (the same rule as parent alerts). */
    private visibility(actor: Actor): {sql: string; args: string[]} {
        const people = actor.personIds.slice(0, SCOPE_MAX);
        const parts = [...(people.length ? [`a.person_id IN (${people.map(() => '?').join(',')})`] : []), ...(actor.role === 'admin' ? ['a.person_id IS NULL'] : [])];
        return parts.length ? {sql: `(${parts.join(' OR ')})`, args: people} : {sql: '0', args: []};
    }

    list(actor: Actor, opts: {before?: number; limit?: number} = {}): AuditPage {
        const limit = Math.min(Math.max(1, Math.floor(opts.limit ?? AUDIT_PAGE_DEFAULT)), AUDIT_PAGE_MAX), {sql, args} = this.visibility(actor);
        const rows = this.store.all<Row>(`SELECT a.id,a.at,a.actor_id,acc.display_name actor_name,a.action,a.person_id,a.operation_id,a.result FROM parent_audit a
            LEFT JOIN accounts acc ON acc.id=a.actor_id WHERE ${sql} AND a.id < ? ORDER BY a.id DESC LIMIT ${limit + 1}`, ...args, opts.before ?? Number.MAX_SAFE_INTEGER);
        const page = rows.slice(0, limit);
        return {entries: page.map(r => ({id: r.id, at: r.at, actorId: r.actor_id, actorName: r.actor_name, action: r.action, personId: r.person_id, operationId: r.operation_id, result: r.result})),
            nextBefore: rows.length > limit ? page[page.length - 1].id : null};
    }

    /** Bounded: at most PRUNE_BATCHES x PRUNE_BATCH rows per call. Runs whatever the flag says, so old rows age out after it is turned off. */
    prune(now = this.now()): number {
        let total = 0;
        for (let batch = 0; batch < PRUNE_BATCHES; batch++) {
            const removed = Number(this.store.run('DELETE FROM parent_audit WHERE id IN (SELECT id FROM parent_audit WHERE at < ? ORDER BY id LIMIT ?)', now - AUDIT_RETENTION_SECONDS, PRUNE_BATCH).changes);
            total += removed;
            if (removed < PRUNE_BATCH) break;
        }
        return total;
    }
}

const audits = new WeakMap<Store, ParentAudit>();
/** The one audit log of a store. */
export function auditFor(store: Store): ParentAudit {
    let audit = audits.get(store);
    if (!audit) { audit = new ParentAudit(store); audits.set(store, audit); }
    return audit;
}

/**
 * Refusals (4xx) and failures (5xx or an unexpected error) are recorded; authentication/authorization/rate-limit outcomes and 404s are not,
 * so an out-of-scope probe leaves no trace and nothing is attributed to a child the actor may not see.
 */
function failureResult(error: unknown): AuditResult | null {
    if (!(error instanceof AppError)) return 'failed';
    if (error.status >= 500) return 'failed';
    return [401, 403, 404, 429].includes(error.status) ? null : 'refused';
}

/** Runs `work` (sync or async) and records the outcome after it is known, outside any transaction `work` used. The result or error passes through untouched. */
export function audited<T>(store: Store, ctx: AuditContext<T>, work: () => Promise<T>): Promise<T>;
export function audited<T>(store: Store, ctx: AuditContext<T>, work: () => T): T;
export function audited<T>(store: Store, ctx: AuditContext<T>, work: () => T | Promise<T>): T | Promise<T> {
    const audit = auditFor(store);
    // Building the entry reads the database too: any problem there is as harmless to the operation as a failed insert.
    const safely = (build: () => AuditEntry | null) => { try { const entry = build(); if (entry) audit.record(entry); } catch { process.stderr.write('parent_audit_write_failed\n'); } };
    const fail = (error: unknown) => safely(() => { const result = failureResult(error); return result && {actor: ctx.actor, action: ctx.action, people: ctx.people(), result, at: ctx.now()}; });
    const ok = (value: T) => safely(() => { const d = ctx.done(value); return {actor: ctx.actor, action: ctx.action, people: d.people ?? ctx.people(), operationId: d.operationId, result: d.result ?? 'applied', at: ctx.now()}; });
    let value: T | Promise<T>;
    try { value = work(); } catch (error) { fail(error); throw error; }
    if (value instanceof Promise) return value.then(v => { ok(v); return v; }, error => { fail(error); throw error; });
    ok(value);
    return value;
}
