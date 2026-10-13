import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { digest } from './auth.ts';
import type { Store } from './db.ts';
import { AppError } from '../../shared/src/errors.ts';
import type { Actor, OperationResult, PeopleDTO } from '../../shared/src/contracts.ts';

export const REQUEST_MINUTES = [15, 30, 60] as const;
export const REQUEST_TTL_SECONDS = 900;
export const REQUEST_COOLDOWN_SECONDS = 300;
export const REASON_MAX_LENGTH = 140;
/** Failed restore attempts back off 30 s, 60 s ... up to 5 minutes so a persistent rejection cannot flood the operations table. */
export const REPAUSE_BACKOFF_BASE_SECONDS = 30, REPAUSE_BACKOFF_MAX_SECONDS = 300;
const RECENT_SECONDS = 86400, BAD_TOKEN_LIMIT = 30, STATUS_LIMIT = 30;
const PERSON = /^[a-z][a-z0-9_]{0,31}$/, TOKEN = /^[A-Za-z0-9_-]{43}$/;

export type RequestState = 'pending' | 'approving' | 'approved' | 'declined' | 'expired' | 'unsupported' | 'apply_failed' | 'cancelled';
/** The only policy surface used: the existing revision-CAS read and mutate path. No router access of its own. */
export interface PolicyPort {
    people(actor: Actor): PeopleDTO | Promise<PeopleDTO>;
    mutate(actor: Actor, person: string, action: 'pause' | 'resume', input: unknown, precondition: string | undefined, key: string | undefined):
        {status: number; result: OperationResult} | Promise<{status: number; result: OperationResult}>;
}
/**
 * Plug-in point for a future policy-level schedule override/allowance. When absent, approving a request
 * while a schedule blocks access is reported as unsupported. When present it must either install the override
 * (resolve) or refuse (throw AppError); the request is then approved for `until`.
 */
export type ScheduleOverride = (input: {requestId: string; personId: string; minutes: number; until: number; actor: Actor}) => void | Promise<void>;

interface LinkRow {id: string; person_id: string; token_hash: string; created_by: string; created_at: number; revoked_at: number | null; revoked_by: string | null}
interface RequestRow {
    id: string; link_id: string; person_id: string; minutes: number; reason: string; state: RequestState; created_at: number; expires_at: number;
    decided_by: string | null; decided_at: number | null; granted_minutes: number | null; allowance_until: number | null; decision_code: string | null;
    attempts: number; resume_operation_id: string | null; resume_revision: number | null; original_pause_until: number | null;
    repause_state: 'none' | 'waiting' | 'applying' | 'not_needed' | 'done' | 'superseded'; repause_operation_id: string | null; repause_error: string | null;
    repause_failures: number; next_attempt_at: number | null;
}
interface AccountRow {id: string; display_name: string; role: 'admin' | 'parent'; person_ids: string; permission_version: number}

export interface ParentRequestDTO {
    id: string; personId: string; minutes: number; reason: string; state: RequestState; createdAt: number; expiresAt: number;
    decidedBy: string | null; decidedAt: number | null; grantedMinutes: number | null; allowanceUntil: number | null; code: string | null; repause: string;
    /** The allowance ended but the pause is not restored yet. Retried without limit; the parent is alerted. */
    repauseOverdue: boolean; repauseError: string | null;
}
export interface ChildStatusDTO {
    state: RequestState | 'none'; minutes: number | null; grantedMinutes: number | null; allowanceUntil: number | null; createdAt: number | null;
    expiresAt: number | null; code: string | null; canRequest: boolean; retryAfter: number;
}
const CODES: Partial<Record<RequestState, string>> = {unsupported: 'schedule_override_unsupported', apply_failed: 'approval_not_applied'};

/** Control characters and bidirectional overrides are rejected; the text is only ever rendered with textContent. */
export function normalizeReason(value: unknown): string {
    if (value === undefined) return '';
    if (typeof value !== 'string') throw new AppError(400, 'invalid_reason');
    const text = value.trim();
    if ([...text].length > REASON_MAX_LENGTH || /[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/.test(text)) throw new AppError(400, 'invalid_reason');
    return text;
}
function minutesOf(value: unknown): 15 | 30 | 60 {
    if (!REQUEST_MINUTES.includes(value as 15)) throw new AppError(400, 'invalid_minutes');
    return value as 15 | 30 | 60;
}

export class TimeRequestService {
    readonly store: Store;
    readonly policy: PolicyPort;
    readonly now: () => number;
    readonly scheduleOverride?: ScheduleOverride;
    private readonly inFlight = new Set<string>();
    private badTokens: number[] = [];
    private statusPolls = new Map<string, number[]>();
    constructor(store: Store, policy: PolicyPort, now = () => Math.floor(Date.now() / 1000), scheduleOverride?: ScheduleOverride) {
        this.store = store; this.policy = policy; this.now = now; this.scheduleOverride = scheduleOverride;
    }
    private audit(actor: string, action: string, outcome: string, operationId: string | null = null, revision: number | null = null) {
        this.store.run('INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,?)', actor, operationId, action, revision, this.now(), outcome);
    }
    private assigned(actor: Actor, person: string) {
        if (!PERSON.test(person) || !actor.personIds.includes(person)) throw new AppError(404, 'person_not_found');
    }
    private owned(actor: Actor, id: string): RequestRow {
        const row = typeof id === 'string' ? this.store.get<RequestRow>('SELECT * FROM time_requests WHERE id=?', id) : undefined;
        if (!row || !actor.personIds.includes(row.person_id)) throw new AppError(404, 'request_not_found');
        return row;
    }
    private actorFor(id: string): Actor | null {
        const row = this.store.get<AccountRow>('SELECT * FROM accounts WHERE id=? AND active=1', id);
        return row ? {id: row.id, displayName: row.display_name, role: row.role, personIds: JSON.parse(row.person_ids), permissionVersion: String(row.permission_version)} : null;
    }
    private parentDTO(row: RequestRow): ParentRequestDTO {
        return {id: row.id, personId: row.person_id, minutes: row.minutes, reason: row.reason, state: row.state, createdAt: row.created_at, expiresAt: row.expires_at,
            decidedBy: row.decided_by, decidedAt: row.decided_at, grantedMinutes: row.granted_minutes, allowanceUntil: row.allowance_until,
            code: row.decision_code ?? CODES[row.state] ?? null, repause: row.repause_state,
            repauseOverdue: ['waiting', 'applying'].includes(row.repause_state) && row.allowance_until !== null && row.allowance_until <= this.now(), repauseError: row.repause_error};
    }
    /** Unanswered requests lapse on their own; a request mid-decision is never expired underneath its approver. */
    expire(): void {
        const now = this.now();
        for (const row of this.store.all<RequestRow>("SELECT * FROM time_requests WHERE state='pending' AND expires_at<=?", now)) {
            if (this.inFlight.has(row.id)) continue;
            this.store.transaction(() => {
                if (this.store.run("UPDATE time_requests SET state='expired',decided_at=? WHERE id=? AND state='pending'", now, row.id).changes) this.audit('system', 'time_request_expire', 'expired');
            });
        }
    }

    // ---- Parent-managed request links -------------------------------------------------------------------------
    async issueLink(actor: Actor, person: string): Promise<{token: string; path: string; createdAt: number}> {
        this.assigned(actor, person);
        if (!(await this.policy.people(actor)).people.some(p => p.id === person)) throw new AppError(404, 'person_not_found');
        const token = randomBytes(32).toString('base64url'), now = this.now();
        this.store.transaction(() => {
            this.revoke(actor, person);
            this.store.run('INSERT INTO request_links(id,person_id,token_hash,created_by,created_at) VALUES(?,?,?,?,?)', randomUUID(), person, digest(token), actor.id, now);
            this.audit(actor.id, 'request_link_issue', person);
        });
        return {token, path: `/request.html#${token}`, createdAt: now};
    }
    revokeLink(actor: Actor, person: string): {revoked: boolean} {
        this.assigned(actor, person);
        return {revoked: this.store.transaction(() => this.revoke(actor, person))};
    }
    private revoke(actor: Actor, person: string): boolean {
        const now = this.now(), link = this.store.get<LinkRow>('SELECT * FROM request_links WHERE person_id=? AND revoked_at IS NULL', person);
        if (!link) return false;
        this.store.run('UPDATE request_links SET revoked_at=?,revoked_by=? WHERE id=?', now, actor.id, link.id);
        // Only unanswered requests are cancelled. An approving/approved request has recorded intent and must complete.
        this.store.run("UPDATE time_requests SET state='cancelled',decided_at=? WHERE link_id=? AND state='pending'", now, link.id);
        this.audit(actor.id, 'request_link_revoke', person);
        return true;
    }
    /** Never returns the token or its hash: a lost link is replaced, not recovered. */
    overview(actor: Actor): {links: {personId: string; active: boolean; createdAt: number | null}[]; requests: ParentRequestDTO[]} {
        this.expire();
        const people = actor.personIds.filter(p => PERSON.test(p));
        const links = people.map(personId => {
            const link = this.store.get<LinkRow>('SELECT * FROM request_links WHERE person_id=? AND revoked_at IS NULL', personId);
            return {personId, active: Boolean(link), createdAt: link?.created_at ?? null};
        });
        const cutoff = this.now() - RECENT_SECONDS;
        const requests = this.store.all<RequestRow>("SELECT * FROM time_requests WHERE created_at>=? OR repause_state IN ('waiting','applying') ORDER BY created_at DESC LIMIT 200", cutoff)
            .filter(row => people.includes(row.person_id)).slice(0, 50).map(row => this.parentDTO(row));
        return {links, requests};
    }

    /** Feeds the parent-alerts `time_request_pending` rule. Only unanswered requests; no reason text or child details. */
    pendingForAlerts(): {person: string; requestId: string; createdAt: number}[] {
        this.expire();
        return this.store.all<RequestRow>("SELECT * FROM time_requests WHERE state='pending'").map(row => ({person: row.person_id, requestId: row.id, createdAt: row.created_at}));
    }

    // ---- Parent decisions -------------------------------------------------------------------------------------
    decline(actor: Actor, id: string): ParentRequestDTO {
        this.expire();
        const row = this.owned(actor, id);
        if (row.state !== 'pending' || this.inFlight.has(id)) throw new AppError(409, 'request_not_pending');
        this.store.transaction(() => {
            if (!this.store.run("UPDATE time_requests SET state='declined',decided_by=?,decided_at=? WHERE id=? AND state='pending'", actor.id, this.now(), id).changes) throw new AppError(409, 'request_not_pending');
            this.audit(actor.id, 'time_request_decline', 'declined');
        });
        return this.parentDTO(this.owned(actor, id));
    }
    async approve(actor: Actor, id: string, minutes: unknown): Promise<ParentRequestDTO> {
        this.expire();
        const row = this.owned(actor, id), granted = minutesOf(minutes);
        if (row.state !== 'pending' || this.inFlight.has(id)) throw new AppError(409, 'request_not_pending');
        this.inFlight.add(id);
        try {
            await this.decide(actor, row, granted);
        } finally {
            this.inFlight.delete(id);
        }
        return this.parentDTO(this.owned(actor, id));
    }
    private finish(actor: Actor, row: RequestRow, fields: Partial<RequestRow> & {state: RequestState}, action: string) {
        const columns = Object.keys(fields) as (keyof RequestRow)[];
        this.store.transaction(() => {
            const changed = this.store.run(`UPDATE time_requests SET ${columns.map(c => `${c}=?`).join(',')},decided_by=?,decided_at=? WHERE id=? AND state='pending'`,
                ...columns.map(c => fields[c] as string | number | null), actor.id, this.now(), row.id).changes;
            if (!changed) throw new AppError(409, 'request_not_pending');
            this.audit(actor.id, action, fields.state, fields.resume_operation_id ?? null, fields.resume_revision ?? null);
        });
    }
    private async decide(actor: Actor, row: RequestRow, minutes: number): Promise<void> {
        const people = await this.policy.people(actor), person = people.people.find(p => p.id === row.person_id);
        if (!person) throw new AppError(404, 'person_not_found');
        const until = this.now() + minutes * 60;
        if (person.scheduleBlocked === null) throw new AppError(503, 'schedule_state_unknown');
        if (person.scheduleBlocked) {
            if (!this.scheduleOverride) {
                this.finish(actor, row, {state: 'unsupported', decision_code: 'schedule_override_unsupported', granted_minutes: null}, 'time_request_unsupported');
                return;
            }
            await this.scheduleOverride({requestId: row.id, personId: row.person_id, minutes, until, actor});
        }
        const pause = person.effectiveManualPause;
        if (!pause) {
            this.finish(actor, row, {state: 'approved', granted_minutes: minutes, allowance_until: until, repause_state: 'none'}, 'time_request_approve');
            return;
        }
        if (!people.revisionToken) throw new AppError(503, 'router_status_unavailable');
        // Intent first: once the pause may be lifted, the restore obligation is already durable.
        const timed = pause.until !== 0, key = `tr-${row.id}-r${row.attempts + 1}`;
        this.store.transaction(() => {
            const changed = this.store.run("UPDATE time_requests SET state='approving',granted_minutes=?,allowance_until=?,original_pause_until=?,repause_state=?,attempts=attempts+1,decided_by=?,decided_at=? WHERE id=? AND state='pending'",
                minutes, until, pause.until, timed && pause.until <= until ? 'not_needed' : 'waiting', actor.id, this.now(), row.id).changes;
            if (!changed) throw new AppError(409, 'request_not_pending');
            this.audit(actor.id, 'time_request_approving', 'approving');
        });
        let resume: {id: string; revision: number} | null = null;
        try {
            resume = (await this.policy.mutate(actor, row.person_id, 'resume', {}, people.revisionToken, key)).result.operation;
        } catch (error) {
            // The operation row is the witness that the write path committed, whatever error surfaced afterwards.
            resume = this.store.get<{id: string; revision: number}>('SELECT id,revision FROM operations WHERE person_id=? AND idempotency_key=?', row.person_id, key) ?? null;
            if (error instanceof AppError && !resume) {
                // mutate refused before writing anything: release the claim so the parent can retry.
                this.store.transaction(() => {
                    this.store.run("UPDATE time_requests SET state='pending',granted_minutes=NULL,allowance_until=NULL,original_pause_until=NULL,repause_state='none',decided_by=NULL,decided_at=NULL WHERE id=? AND state='approving'", row.id);
                    this.audit(actor.id, 'time_request_approving', `released:${error.code}`);
                });
                throw error;
            }
            // Committed or unknown outcome: the resume may have been applied. Stay approved so the pause is restored.
        }
        this.store.transaction(() => {
            this.store.run("UPDATE time_requests SET state='approved',resume_operation_id=?,resume_revision=? WHERE id=? AND state='approving'", resume?.id ?? null, resume?.revision ?? null, row.id);
            this.audit(actor.id, 'time_request_approve', 'approved', resume?.id ?? null, resume?.revision ?? null);
        });
    }

    /**
     * Drives time-based follow-ups: completes approvals interrupted before they were finalized, marks approvals whose
     * resume never took effect, and restores the pause that the approval lifted once the allowance ends. Safe to call
     * repeatedly and after a restart: every obligation is read from durable state.
     */
    async advance(): Promise<void> {
        this.expire();
        const now = this.now();
        for (const row of this.store.all<RequestRow>("SELECT * FROM time_requests WHERE state='approving'")) {
            // Intent was recorded but the process stopped before finalizing: the resume may have been applied, so it counts as approved.
            if (this.inFlight.has(row.id)) continue;
            this.store.transaction(() => {
                this.store.run("UPDATE time_requests SET state='approved' WHERE id=? AND state='approving'", row.id);
                this.audit('system', 'time_request_approve', 'recovered');
            });
        }
        for (const row of this.store.all<RequestRow>("SELECT * FROM time_requests WHERE state='approved' AND resume_operation_id IS NOT NULL AND allowance_until>?", now)) {
            const op = this.store.get<{state: string}>('SELECT state FROM operations WHERE id=?', row.resume_operation_id!);
            if (op && ['failed', 'conflict'].includes(op.state)) {
                // repause_state is kept: a restore check still runs at the end of the allowance.
                this.store.run("UPDATE time_requests SET state='apply_failed' WHERE id=? AND state='approved'", row.id);
                this.audit('system', 'time_request_apply_failed', op.state, row.resume_operation_id, row.resume_revision);
            }
        }
        for (const row of this.store.all<RequestRow>("SELECT * FROM time_requests WHERE repause_state='applying'")) {
            // A 202 is not a restore. Done only once the pause operation is confirmed; failed or conflicted ones are retried.
            const op = this.store.get<{state: string}>('SELECT state FROM operations WHERE id=?', row.repause_operation_id ?? '');
            if (op?.state === 'confirmed') this.setRepause(row, 'done', null, row.repause_operation_id);
            else if (!op || ['failed', 'conflict'].includes(op.state)) {
                this.setRepause(row, 'waiting', `repause_${op?.state ?? 'missing'}`);
                this.backoff(row);
            }
        }
        for (const row of this.store.all<RequestRow>("SELECT * FROM time_requests WHERE state IN ('approved','apply_failed') AND repause_state='waiting' AND allowance_until<=? AND (next_attempt_at IS NULL OR next_attempt_at<=?)", now, now)) {
            if (this.inFlight.has(row.id)) continue;
            this.inFlight.add(row.id);
            try {
                await this.repause(row);
            } finally {
                this.inFlight.delete(row.id);
            }
        }
    }
    private setRepause(row: RequestRow, state: RequestRow['repause_state'], error: string | null, operation: string | null = null) {
        this.store.transaction(() => {
            this.store.run('UPDATE time_requests SET repause_state=?,repause_error=?,repause_operation_id=? WHERE id=?', state, error, operation, row.id);
            if (state !== 'waiting') this.audit('system', 'time_request_repause', state, operation);
        });
    }
    /** Any active account assigned to the child. The restore is a service obligation, not the approver's session. */
    private repauseActor(person: string): Actor | null {
        const rows = this.store.all<AccountRow>("SELECT * FROM accounts WHERE active=1 ORDER BY role='parent' DESC,id");
        const row = rows.find(account => (JSON.parse(account.person_ids) as string[]).includes(person));
        return row ? this.actorFor(row.id) : null;
    }
    /**
     * THE restore step. It is the only code that re-applies the pause after an allowance, so it can later be replaced
     * by writing a router-side allowance that expires on its own. Retried without limit (every advance()) until the
     * pause is restored or provably unnecessary; while it is overdue the parent UI shows an alert.
     */
    private async repause(row: RequestRow): Promise<void> {
        // A later confirmed or pending policy change for this child outranks the stale allowance. Our own operations are excluded by key.
        const own = this.store.get<{revision: number}>("SELECT revision FROM operations WHERE person_id=? AND idempotency_key LIKE ? ORDER BY revision LIMIT 1", row.person_id, `tr-${row.id}-r%`);
        const later = own && this.store.get("SELECT id FROM operations WHERE person_id=? AND revision>? AND state IN ('pending','confirmed') AND idempotency_key NOT LIKE ? LIMIT 1", row.person_id, own.revision, `tr-${row.id}-%`);
        if (later) return this.setRepause(row, 'superseded', null);
        // The original timed pause would already have ended by itself: nothing to restore.
        if (row.original_pause_until !== 0 && row.original_pause_until! <= this.now()) return this.setRepause(row, 'not_needed', null);
        const actor = this.repauseActor(row.person_id);
        let error = 'no_assigned_parent';
        if (actor) {
            try {
                const people = await this.policy.people(actor), person = people.people.find(p => p.id === row.person_id);
                if (person?.manualPause) return this.setRepause(row, 'superseded', null);
                if (!person || !people.revisionToken) throw new AppError(503, 'router_status_unavailable');
                this.store.run('UPDATE time_requests SET attempts=attempts+1 WHERE id=?', row.id);
                const outcome = await this.policy.mutate(actor, row.person_id, 'pause', {until: row.original_pause_until!}, people.revisionToken, `tr-${row.id}-p${row.attempts + 1}`);
                if (outcome.status === 409 || outcome.status === 502) throw new AppError(409, 'policy_change_not_applied');
                return this.setRepause(row, outcome.status === 200 && outcome.result.operation.state === 'confirmed' ? 'done' : 'applying', null, outcome.result.operation.id);
            } catch (caught) {
                error = caught instanceof AppError ? caught.code : 'repause_failed';
            }
        }
        this.store.run('UPDATE time_requests SET repause_error=? WHERE id=?', error, row.id);
        this.backoff(row);
    }
    private backoff(row: RequestRow) {
        const delay = Math.min(REPAUSE_BACKOFF_MAX_SECONDS, REPAUSE_BACKOFF_BASE_SECONDS * 2 ** Math.min(row.repause_failures, 10));
        this.store.run('UPDATE time_requests SET repause_failures=repause_failures+1,next_attempt_at=? WHERE id=?', this.now() + delay, row.id);
    }

    // ---- Child capability endpoints (no accounts, no cookies) -------------------------------------------------
    private link(token: unknown): LinkRow {
        const now = this.now();
        let found: LinkRow | null = null;
        if (typeof token === 'string' && TOKEN.test(token)) {
            const candidate = Buffer.from(digest(token), 'hex');
            // Compare against every live hash without early exit.
            for (const link of this.store.all<LinkRow>('SELECT * FROM request_links WHERE revoked_at IS NULL')) {
                if (timingSafeEqual(Buffer.from(link.token_hash, 'hex'), candidate)) found = link;
            }
        }
        if (found) return found;
        this.badTokens = this.badTokens.filter(t => t > now - 60);
        this.badTokens.push(now);
        throw this.badTokens.length > BAD_TOKEN_LIMIT ? new AppError(429, 'rate_limited') : new AppError(404, 'link_invalid');
    }
    private pollLimit(link: LinkRow) {
        const now = this.now(), recent = (this.statusPolls.get(link.id) ?? []).filter(t => t > now - 60);
        if (recent.length >= STATUS_LIMIT) throw new AppError(429, 'rate_limited');
        this.statusPolls.set(link.id, [...recent, now]);
    }
    private childStatus(link: LinkRow): ChildStatusDTO {
        const now = this.now(), row = this.store.get<RequestRow>('SELECT * FROM time_requests WHERE link_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1', link.id);
        const retryAfter = row ? Math.max(0, row.created_at + REQUEST_COOLDOWN_SECONDS - now) : 0;
        const state = row?.state === 'approving' ? 'pending' : row?.state ?? 'none';
        return {state, minutes: row?.minutes ?? null, grantedMinutes: row?.granted_minutes ?? null, allowanceUntil: row?.allowance_until ?? null,
            createdAt: row?.created_at ?? null, expiresAt: row?.expires_at ?? null, code: row ? CODES[row.state] ?? null : null,
            canRequest: state !== 'pending' && retryAfter === 0, retryAfter: state === 'pending' ? 0 : retryAfter};
    }
    status(token: unknown): ChildStatusDTO {
        const link = this.link(token);
        this.pollLimit(link);
        this.expire();
        return this.childStatus(link);
    }
    submit(token: unknown, minutes: unknown, reason: unknown): ChildStatusDTO {
        const link = this.link(token), granted = minutesOf(minutes), text = normalizeReason(reason);
        this.pollLimit(link);
        this.expire();
        const now = this.now();
        this.store.transaction(() => {
            const current = this.childStatus(link);
            if (current.state === 'pending') throw new AppError(409, 'request_pending');
            if (!current.canRequest) throw new AppError(429, 'request_cooldown', `Wait ${current.retryAfter} seconds before asking again.`);
            this.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at) VALUES(?,?,?,?,?,'pending',?,?)", randomUUID(), link.id, link.person_id, granted, text, now, now + REQUEST_TTL_SECONDS);
            this.audit(`child:${link.person_id}`, 'time_request_create', 'pending');
        });
        return this.childStatus(link);
    }
}
