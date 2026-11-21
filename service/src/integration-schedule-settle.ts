import { DAYS } from '../../shared/src/router-schema.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import { policyDigest } from '../../shared/src/router-rpc.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { IntegrationOperation } from './integration-policy.ts';
import type { Store } from './db.ts';
import { canonicalSchedules, scheduleWindows } from './integration-schedule-store.ts';

/**
 * Settlement of a schedule operation (roadmap item 2, S2a; flag schedules.editable, off; unverified on this router).
 * Reads only the operation row, its operation_rpc row (envelope and stored receipt) and schedule_windows. It never reads the accepted
 * policy contents or the devices table, never calls normalizePolicy, and never throws for a bad envelope: every check below can only
 * withhold the health claim (confirmed_at) or promote nothing, it never blocks the settlement itself. Codes only, no windows in output.
 */
export interface ScheduleEvidence { state: 'confirmed' | 'unknown' | 'failed' | 'conflict'; error: string | null; confirmedAt: number | null; now: number }
export const SCHEDULE_EXPANSION_LIMIT = 256;
interface Rpc { generation: string; request_digest: string; envelope_json: string; receipt_json: string | null }
interface Envelope { generation: string; operation_id: string; expected_revision: number; expected_digest: string; policy: RouterPolicy }
interface Receipt { operationId: string; requestDigest: string; baseRevision: number; baseDigest: string; acceptedRevision: number; acceptedDigest: string }

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string';
function parse(json: string | null): unknown { try { return json === null ? null : JSON.parse(json); } catch { return null; } }
function windowsOf(policy: unknown): Schedule[] | null {
    if (!isObject(policy) || !Array.isArray(policy.schedules)) return null;
    const out: Schedule[] = [];
    for (const s of policy.schedules) {
        if (!isObject(s) || !text(s.person) || !text(s.id) || !text(s.start) || !text(s.stop) || !Array.isArray(s.weekdays) || !s.weekdays.every(d => DAYS.includes(d as typeof DAYS[number]))) return null;
        out.push({person: s.person, id: s.id, weekdays: s.weekdays as Schedule['weekdays'], start: s.start, stop: s.stop});
    }
    return out;
}
function envelopeOf(json: string): Envelope | null {
    const e = parse(json);
    if (!isObject(e) || !text(e.generation) || !text(e.operation_id) || !Number.isInteger(e.expected_revision) || !text(e.expected_digest) || !isObject(e.policy) || !Number.isInteger(e.policy.revision)) return null;
    return {generation: e.generation, operation_id: e.operation_id, expected_revision: e.expected_revision as number, expected_digest: e.expected_digest, policy: e.policy as unknown as RouterPolicy};
}
function receiptOf(json: string | null): Receipt | null {
    const r = parse(json);
    return isObject(r) && text(r.operationId) && text(r.requestDigest) && Number.isInteger(r.baseRevision) && text(r.baseDigest) && Number.isInteger(r.acceptedRevision) && text(r.acceptedDigest) ? r as unknown as Receipt : null;
}
function digestOf(policy: RouterPolicy): string | null { try { return policyDigest(policy); } catch { return null; } }
/** The stored receipt compared field by field against this operation's own envelope: a reply for another operation or generation never matches. */
function exact(op: IntegrationOperation, rpc: Rpc, e: Envelope | null, r: Receipt | null): boolean {
    if (!e || !r || e.operation_id !== op.id || rpc.generation !== e.generation || r.operationId !== e.operation_id) return false;
    const accepted = digestOf(e.policy);
    return accepted !== null && r.requestDigest === rpc.request_digest && r.baseRevision === e.expected_revision && r.baseDigest === e.expected_digest && r.acceptedRevision === e.policy.revision && r.acceptedDigest === accepted;
}
/** Windows times a person's device count, a cross-midnight window counted twice (the router's expansion limit); null when the payload is unreadable. */
export function expandedWindows(policy: RouterPolicy): number | null {
    const windows = windowsOf(policy);
    if (!windows || !Array.isArray(policy.people)) return null;
    let total = 0;
    for (const s of windows) {
        const person = policy.people.find(p => isObject(p) && p.id === s.person);
        if (!person || !Array.isArray(person.macs)) return null;
        total += person.macs.length * (s.start > s.stop && s.stop !== '00:00' ? 2 : 1);
    }
    return total;
}
/** Replaces the child's committed windows with the payload's; one savepoint, so a failure leaves the committed set untouched. Returns a code on failure. */
function promote(store: Store, person: string, windows: readonly Schedule[]): string | null {
    store.db.exec('SAVEPOINT schedule_promote');
    try {
        store.run('DELETE FROM schedule_windows WHERE person_id=?', person);
        for (const w of windows.filter(s => s.person === person)) store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', person, w.id, w.weekdays.join(','), w.start, w.stop);
        store.db.exec('RELEASE schedule_promote');
        return null;
    } catch {
        store.db.exec('ROLLBACK TO schedule_promote'); store.db.exec('RELEASE schedule_promote');
        return 'schedule_promotion_failed';
    }
}
/** Settles one schedule operation row and, on an exact receipt, promotes the payload windows into schedule_windows. Runs inside the caller's transaction. */
export function settleSchedule(store: Store, op: IntegrationOperation, evidence: ScheduleEvidence): void {
    if (!store.db.isTransaction) throw new Error('settle_requires_transaction');
    const rpc: Rpc | undefined = store.get<Rpc>('SELECT generation,request_digest,envelope_json,receipt_json FROM operation_rpc WHERE operation_id=?', op.id);
    const envelope = rpc ? envelopeOf(rpc.envelope_json) : null;
    let code: string | null = null;
    const verified = rpc !== undefined && exact(op, rpc, envelope, receiptOf(rpc.receipt_json));
    if (evidence.state === 'confirmed' && !verified) code = 'schedule_receipt_unverified';
    if (rpc && verified && evidence.state !== 'failed') {
        const windows = windowsOf(envelope!.policy)!;
        code = promote(store, op.person_id, windows);
        if (!code) {
            const expanded = expandedWindows(envelope!.policy);
            // Pure canonical comparison of the whole committed set with the payload set: it never normalizes and never blocks the settlement.
            if (expanded === null || expanded > SCHEDULE_EXPANSION_LIMIT) code = 'schedule_expansion_limit';
            else if (canonicalSchedules(scheduleWindows(store)) !== canonicalSchedules(windows)) code = 'schedule_set_unverified';
        }
    }
    // An accepted receipt whose promotion failed is NOT settled: the router holds windows the committed set lacks. The operation stays
    // unknown (the worker keeps it active), so the next exact receipt read retries the promotion and no health claim is made meanwhile.
    const stuck = code === 'schedule_promotion_failed';
    const state = stuck ? 'unknown' : evidence.state;
    const withheld = code !== null && evidence.state === 'confirmed';
    store.run('UPDATE operations SET state=?,error=?,confirmed_at=COALESCE(?,confirmed_at),updated_at=? WHERE id=?', state, stuck ? code : evidence.error ?? code, withheld ? null : evidence.confirmedAt, evidence.now, op.id);
    store.run('INSERT INTO audit(actor_id,operation_id,action,revision,timestamp,outcome) VALUES(?,?,?,?,?,?)', op.actor_id, op.id, op.action, op.revision, evidence.now, state);
}
/** Staged state: the active schedule operation's payload windows, or null when none is in flight. Reads the operation row only. */
export function stagedScheduleWindows(store: Store): Schedule[] | null {
    const row = store.get<{action: string; payload_json: string}>("SELECT o.action,o.payload_json FROM operations o JOIN integration_state s ON s.active_operation_id=o.id WHERE s.singleton=1 AND o.action LIKE 'schedule\\_%' ESCAPE '\\'");
    return row ? windowsOf(parse(row.payload_json)) : null;
}
