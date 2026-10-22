import { AppError } from '../../shared/src/errors.ts';
import type { Actor, PeopleDTO } from '../../shared/src/contracts.ts';
import { FICTIONAL_PEOPLE } from './fixtures.ts';
import type { Store } from './db.ts';
import { enforcementUnhealthy, syncProblems, possibleBypass, repeatedBlockedAttempts, timeRequestPending, evaluatedPeople } from './alert-rules.ts';
import type { ActivityDelta, AlertCandidate, AlertKind, AlertSeverity, PendingTimeRequest } from './alert-rules.ts';

export const RETENTION_SECONDS = 90 * 86400;
/** An activity alert with no fresh evidence either way resolves after this much silence. */
export const ACTIVITY_QUIET_SECONDS = 1800;
/** A clean evaluation resolves an activity alert only this long after it was last seen, so one quiet batch cannot hide it. */
export const ACTIVITY_CLEAR_SECONDS = 120;
const RANK: Record<AlertSeverity, number> = {info: 0, warning: 1, critical: 2};
export const PAGE_SIZE = 25;
const STATE_KINDS: AlertKind[] = ['enforcement_unhealthy', 'sync_failed', 'apply_pending_too_long'];
const ACTIVITY_KINDS: AlertKind[] = ['possible_bypass', 'repeated_blocked_attempts'];

export interface ParentAlertDTO {
    id: number; personId: string | null; kind: AlertKind; severity: AlertSeverity; createdAt: number; firstSeen: number; lastSeen: number;
    count: number; state: 'open' | 'acknowledged' | 'resolved'; acknowledgedAt: number | null; resolvedAt: number | null;
    details: Record<string, number | string | boolean>;
}
export interface ParentAlertPage { alerts: ParentAlertDTO[]; nextBefore: number | null; openCount: number }
/** Everything a reconciliation pass sees. An omitted input means "not evaluated": its alerts are left alone. */
export interface AlertInput { now: number; people?: PeopleDTO | null; activity?: ActivityDelta[]; timeRequests?: PendingTimeRequest[] }
/** Providers for the live service; activity and time requests are supplied by other components. */
export interface AlertSources { people(): PeopleDTO; activity?(): ActivityDelta[]; timeRequests?(): PendingTimeRequest[] }
interface Row {
    id: number; person_id: string | null; kind: AlertKind; severity: AlertSeverity; created_at: number; first_seen: number; last_seen: number;
    count: number; state: ParentAlertDTO['state']; acknowledged_at: number | null; resolved_at: number | null; details: string;
}
const key = (kind: string, person: string | null) => `${kind}\u0000${person ?? ''}`;
const dto = (row: Row): ParentAlertDTO => ({id: row.id, personId: row.person_id, kind: row.kind, severity: row.severity, createdAt: row.created_at,
    firstSeen: row.first_seen, lastSeen: row.last_seen, count: row.count, state: row.state, acknowledgedAt: row.acknowledged_at,
    resolvedAt: row.resolved_at, details: JSON.parse(row.details)});

/** Service-internal read of all people; never exposed to a request. */
export const systemActor: Actor = {id: 'system', displayName: 'System', role: 'admin', personIds: FICTIONAL_PEOPLE.map(person => person.id), permissionVersion: '0'};

export class ParentAlerts {
    readonly store: Store;
    readonly sources: AlertSources | null;
    readonly now: () => number;
    constructor(store: Store, sources: AlertSources | null = null, now = () => Math.floor(Date.now() / 1000)) {
        this.store = store; this.sources = sources; this.now = now;
    }

    /** Pull from the live sources and reconcile. A failing source is skipped, never treated as "all clear". */
    sync(): void {
        if (!this.sources) return;
        const attempt = <T>(read?: () => T): T | undefined => { try { return read?.(); } catch { return undefined; } };
        this.reconcile({now: this.now(), people: attempt(() => this.sources!.people()), activity: attempt(this.sources.activity?.bind(this.sources)),
            timeRequests: attempt(this.sources.timeRequests?.bind(this.sources))});
    }

    reconcile(input: AlertInput): void {
        const {now} = input;
        const candidates: AlertCandidate[] = [
            ...(input.people ? [...enforcementUnhealthy(input.people, now), ...syncProblems(input.people, now)] : []),
            ...(input.activity ? [...possibleBypass(input.activity, now), ...repeatedBlockedAttempts(input.activity, now)] : []),
            ...(input.timeRequests ? timeRequestPending(input.timeRequests, now) : [])];
        const active = new Set(candidates.map(candidate => key(candidate.kind, candidate.personId)));
        const decided = input.activity ? evaluatedPeople(input.activity, now) : new Set<string>();
        this.store.transaction(() => {
            for (const candidate of candidates) this.write(candidate, now, false);
            for (const row of this.store.all<Row>("SELECT * FROM parent_alerts WHERE state IN ('open','acknowledged')")) {
                if (active.has(key(row.kind, row.person_id)) || row.kind === 'router_scope_change' || row.kind === 'new_device') continue; // events (scope changes, new devices): only an admin acknowledges them
                const clear = STATE_KINDS.includes(row.kind) ? Boolean(input.people)
                    : ACTIVITY_KINDS.includes(row.kind) ? Boolean(input.activity) && (decided.has(row.person_id ?? '') && now - row.last_seen >= ACTIVITY_CLEAR_SECONDS || now - row.last_seen >= ACTIVITY_QUIET_SECONDS)
                    : Boolean(input.timeRequests);
                if (clear) this.store.run("UPDATE parent_alerts SET state='resolved',resolved_at=? WHERE id=?", now, row.id);
            }
            this.store.run("DELETE FROM parent_alerts WHERE state='resolved' AND resolved_at < ?", now - RETENTION_SECONDS);
        });
    }

    /**
     * Record one new event. Unlike reconcile, which tracks a standing condition, this re-opens an acknowledged alert and counts
     * the occurrence: a second unexplained router change must not hide behind an earlier acknowledgement. Joins a caller's transaction.
     */
    raise(candidate: AlertCandidate): void {
        const now = this.now(), write = () => this.write(candidate, now, true);
        if (this.store.db.isTransaction) write(); else this.store.transaction(write);
    }

    /**
     * One row per unresolved (kind, person). An event re-opens an acknowledged alert, counts the occurrence and never lowers severity;
     * a standing condition only re-opens on escalation, keeps its count (a held condition is not a new occurrence) and follows the candidate's severity.
     */
    private write(candidate: AlertCandidate, now: number, event: boolean): void {
        const details = JSON.stringify(candidate.details);
        if (details.length > 1024) throw new Error('alert_details_too_large');
        const open = this.store.get<Row>("SELECT * FROM parent_alerts WHERE kind=? AND COALESCE(person_id,'')=? AND state IN ('open','acknowledged')", candidate.kind, candidate.personId ?? '');
        if (!open) {
            this.store.run("INSERT INTO parent_alerts(person_id,kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES(?,?,?,?,?,?,1,'open',?)",
                candidate.personId, candidate.kind, candidate.severity, now, now, now, details);
            return;
        }
        const escalated = RANK[candidate.severity] > RANK[open.severity];
        const severity = event && !escalated && RANK[candidate.severity] < RANK[open.severity] ? open.severity : candidate.severity;
        this.store.run(`UPDATE parent_alerts SET last_seen=MAX(last_seen,?),count=count+?,severity=?,details=?${event || escalated ? ",state='open',acknowledged_at=NULL,acknowledged_by=NULL" : ''} WHERE id=?`,
            now, event ? 1 : 0, severity, details, open.id);
    }

    /** Assigned people always; system (null person) alerts only for admins. */
    private visibility(actor: Actor): {sql: string; args: string[]} {
        const people = actor.personIds.slice(0, 64), marks = people.map(() => '?').join(',');
        const parts = [...(people.length ? [`person_id IN (${marks})`] : []), ...(actor.role === 'admin' ? ['person_id IS NULL'] : [])];
        return {sql: parts.length ? `(${parts.join(' OR ')})` : '0', args: people};
    }

    list(actor: Actor, before: number = Number.MAX_SAFE_INTEGER): ParentAlertPage {
        const {sql, args} = this.visibility(actor);
        const rows = this.store.all<Row>(`SELECT * FROM parent_alerts WHERE ${sql} AND id < ? ORDER BY id DESC LIMIT ${PAGE_SIZE + 1}`, ...args, before);
        const openCount = this.store.get<{n: number}>(`SELECT count(*) n FROM parent_alerts WHERE ${sql} AND state='open'`, ...args)!.n;
        const more = rows.length > PAGE_SIZE, page = rows.slice(0, PAGE_SIZE);
        return {alerts: page.map(dto), nextBefore: more ? page[page.length - 1].id : null, openCount};
    }

    acknowledge(actor: Actor, id: number): ParentAlertDTO {
        const {sql, args} = this.visibility(actor);
        return this.store.transaction(() => {
            const row = this.store.get<Row>(`SELECT * FROM parent_alerts WHERE id=? AND ${sql}`, id, ...args);
            if (!row) throw new AppError(404, 'alert_not_found');
            if (row.state === 'resolved') throw new AppError(409, 'alert_resolved');
            if (row.state === 'open') this.store.run("UPDATE parent_alerts SET state='acknowledged',acknowledged_at=?,acknowledged_by=? WHERE id=?", this.now(), actor.id, id);
            return dto(this.store.get<Row>('SELECT * FROM parent_alerts WHERE id=?', id)!);
        });
    }
}
