import type { Schedule } from '../../shared/src/router-schema.ts';
import type { IntegrationStore } from './integration-db.ts';
import type { IntegrationOperation } from './integration-policy.ts';
import { canonicalSchedules, scheduleWindows } from './integration-schedule-store.ts';
import type { ScheduleDecision } from './integration-schedule-settle.ts';

/** Roadmap item 2, S2a (flag schedules.editable, off; unverified on this router): the writes of one settlement decision. */

/** The local evidence of an apply attempt, read from BOTH claim records so losing either one keeps it. */
export interface AttemptEvidence { attemptCount: number; applyLeaseUntil: number | null }
/**
 * attemptCount is 1 when operation_rpc counts an attempt OR an apply step exists. applyLeaseUntil is the later of the apply step's lease and
 * the claim's own lease on operation_rpc (both are claim time + 17 s); null when neither record shows a claim.
 */
export function attemptEvidence(store: IntegrationStore, id: string): AttemptEvidence {
    const step = store.get<{lease_until: number}>("SELECT lease_until FROM dispatch_steps WHERE operation_id=? AND kind='apply' ORDER BY rowid DESC LIMIT 1", id);
    const rpc = store.get<{attempt_count: number; lease_until: number | null}>('SELECT attempt_count,lease_until FROM operation_rpc WHERE operation_id=?', id);
    const claimed = rpc && rpc.attempt_count > 0 ? rpc.lease_until : null;
    const leases = [step?.lease_until ?? null, claimed].filter((n): n is number => typeof n === 'number');
    return {attemptCount: step || (rpc?.attempt_count ?? 0) > 0 ? 1 : 0, applyLeaseUntil: leases.length ? Math.max(...leases) : null};
}
/** Replaces only this child's committed rows, and only when they differ, so a repeated promotion writes nothing. */
function promote(store: IntegrationStore, person: string, windows: readonly Schedule[]): void {
    if (canonicalSchedules(scheduleWindows(store).filter(s => s.person === person)) === canonicalSchedules(windows)) return;
    store.run('DELETE FROM schedule_windows WHERE person_id=?', person);
    for (const w of windows) store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', person, w.id, w.weekdays.join(','), w.start, w.stop);
}
/**
 * Inside the caller's transaction. Rows (and one audit row) change only when the decision changes them. A terminal decision clears the
 * slot, resolves the rpc row and resolves this operation's open dispatch steps, so a later rebind is not blocked.
 */
export function applyScheduleDecision(store: IntegrationStore, op: IntegrationOperation, d: ScheduleDecision | null, now: number): void {
    if (!store.db.isTransaction) throw new Error('schedule_settlement_requires_transaction');
    if (!d) return;
    const rpc = store.get<{phase: string; delivery: string | null; receipt_json: string | null}>('SELECT phase,delivery,receipt_json FROM operation_rpc WHERE operation_id=?', op.id);
    const phase = d.terminal ? 'resolved' : 'uncertain', delivery = d.delivery ?? rpc?.delivery ?? null, receipt = d.receipt ? JSON.stringify(d.receipt) : rpc?.receipt_json ?? null;
    if (rpc && (rpc.phase !== phase || rpc.delivery !== delivery || rpc.receipt_json !== receipt)) store.run('UPDATE operation_rpc SET phase=?,delivery=?,receipt_json=? WHERE operation_id=?', phase, delivery, receipt, op.id);
    if (d.promote) promote(store, op.person_id, d.promote);
    const current = store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', op.id)!;
    if (current.state !== d.state || current.error !== d.error || (d.confirmedAt !== null && current.confirmed_at !== d.confirmedAt)) {
        store.run('UPDATE operations SET state=?,error=?,confirmed_at=COALESCE(?,confirmed_at),updated_at=? WHERE id=?', d.state, d.error, d.confirmedAt, now, op.id);
        store.run('INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,?)', op.actor_id, op.id, op.action, op.revision, now, d.state);
    }
    if (!d.terminal) return;
    store.run('UPDATE integration_state SET active_operation_id=NULL WHERE singleton=1 AND active_operation_id=?', op.id);
    store.run("UPDATE dispatch_steps SET state='resolved' WHERE operation_id=? AND state IN ('consumed','uncertain')", op.id);
}
