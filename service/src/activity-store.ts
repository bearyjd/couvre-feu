import { AppError } from '../../shared/src/errors.ts';
import { provenance } from '../../shared/src/contracts.ts';
import type { Actor, ActivityDTO, Provenance } from '../../shared/src/contracts.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { normalizeRouterActivity } from '../../shared/src/router-activity.ts';
import { ACTIVE_MINUTE_THRESHOLD_BYTES, buildDays } from './activity-report.ts';
import type { SampleRow } from './activity-report.ts';
import type { Store } from './db.ts';

export const DEFAULT_RETENTION_DAYS = 30;
export const MAX_RETENTION_DAYS = 365;
/** Longer spacing between two samples cannot be attributed to minutes and is stored as a gap. */
export const MAX_SAMPLE_INTERVAL_SECONDS = 90;
export const ACTIVITY_DISCLAIMER = 'Estimated network activity — not app use, websites or screen time';
const MIN_CLOCK = 1577836800;

export function retentionDays(env: NodeJS.ProcessEnv = process.env): number {
    const input = env.CF_ACTIVITY_RETENTION_DAYS;
    if (input === undefined) return DEFAULT_RETENTION_DAYS;
    if (!/^[1-9][0-9]{0,2}$/.test(input) || +input > MAX_RETENTION_DAYS) throw new Error('invalid_activity_retention_days');
    return +input;
}
export interface IngestResult { stored: number; dropped: number; skipped: string | null }
interface Previous { sampled_at: number; router_epoch: number; counter_epoch: number; tx_bytes: number; rx_bytes: number; blocked_packets: number }

/** Stores and evaluates router-counter samples. Callers must pass a trusted sample time; the router has no wall clock contract. */
export class ActivityStore {
    readonly store: Store;
    readonly retentionDays: number;
    readonly now: () => number;
    readonly source: Provenance;
    constructor(store: Store, options: {retentionDays?: number; now?: () => number; provenance?: Provenance} = {}) {
        const days = options.retentionDays ?? DEFAULT_RETENTION_DAYS;
        if (!Number.isInteger(days) || days < 1 || days > MAX_RETENTION_DAYS) throw new Error('invalid_activity_retention_days');
        this.store = store; this.retentionDays = days; this.now = options.now ?? (() => Math.floor(Date.now() / 1000)); this.source = options.provenance ?? provenance;
    }
    /** Current enrollment: the service's desired policy, not any person or MAC named by a router payload. */
    private policy(): RouterPolicy {
        return normalizePolicy(JSON.parse(this.store.get<{desired_json: string}>('SELECT desired_json FROM service_state WHERE singleton=1')!.desired_json));
    }
    private inTransaction<T>(work: () => T): T { return this.store.db.isTransaction ? work() : this.store.transaction(work); }
    /**
     * Validates, filters to enrolled children and stores one poll. Devices whose (person, MAC) pair is not in the current
     * policy are dropped before any write. A poll that reports router errors is not stored: absence stays unknown.
     */
    ingest(value: unknown, at: number): IngestResult {
        const activity = normalizeRouterActivity(value);
        if (!Number.isSafeInteger(at) || at < MIN_CLOCK) throw new AppError(400, 'invalid_sample_time');
        if (activity.errors.length > 0) return {stored: 0, dropped: activity.devices.length, skipped: 'router_reported_errors'};
        return this.inTransaction(() => {
            this.purgeUnenrolled();
            const enrolled = new Map(this.policy().people.flatMap(person => person.macs.map(mac => [mac, person.id] as const)));
            let stored = 0, dropped = 0;
            for (const d of activity.devices) {
                if (enrolled.get(d.mac) !== d.person) { dropped++; continue; }
                const prev = this.store.get<Previous>('SELECT sampled_at,router_epoch,counter_epoch,tx_bytes,rx_bytes,blocked_packets FROM activity_samples WHERE person_id=? AND mac=? ORDER BY sampled_at DESC LIMIT 1', d.person, d.mac);
                if (prev && at <= prev.sampled_at) { dropped++; continue; }
                let state: 'baseline' | 'valid' | 'reset' | 'gap' = 'baseline', interval: number | null = null, bytes: number | null = null, blocked: number | null = null;
                const total = d.tx_bytes + d.rx_bytes;
                if (prev) {
                    if (prev.router_epoch !== activity.router_epoch || prev.counter_epoch !== activity.counter_epoch || d.tx_bytes < prev.tx_bytes || d.rx_bytes < prev.rx_bytes || d.blocked_packets < prev.blocked_packets) state = 'reset';
                    else if (at - prev.sampled_at > MAX_SAMPLE_INTERVAL_SECONDS) state = 'gap';
                    else { state = 'valid'; interval = at - prev.sampled_at; bytes = total - prev.tx_bytes - prev.rx_bytes; blocked = d.blocked_packets - prev.blocked_packets; }
                }
                this.store.run('INSERT INTO activity_samples(person_id,mac,sampled_at,router_epoch,counter_epoch,offload,tx_bytes,rx_bytes,blocked_packets,delta_state,interval_seconds,delta_bytes,delta_blocked) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    d.person, d.mac, at, activity.router_epoch, activity.counter_epoch, activity.offload, d.tx_bytes, d.rx_bytes, d.blocked_packets, state, interval, bytes, blocked);
                stored++;
            }
            return {stored, dropped, skipped: null};
        });
    }
    /** Deletes samples of any (person, MAC) pair that is not assigned to a child in the current policy. */
    purgeUnenrolled(): number {
        return this.inTransaction(() => {
            const enrolled = new Set(this.policy().people.flatMap(person => person.macs.map(mac => `${person.id}\n${mac}`)));
            let removed = 0;
            for (const row of this.store.all<{person_id: string; mac: string}>('SELECT DISTINCT person_id,mac FROM activity_samples')) {
                if (!enrolled.has(`${row.person_id}\n${row.mac}`)) removed += Number(this.store.run('DELETE FROM activity_samples WHERE person_id=? AND mac=?', row.person_id, row.mac).changes);
            }
            return removed;
        });
    }
    /** Retention job: also purges unenrolled devices, then deletes every sample older than the configured window. Returns the number deleted. */
    prune(at: number = this.now()): number {
        this.purgeUnenrolled();
        return Number(this.store.run('DELETE FROM activity_samples WHERE sampled_at<?', at - this.retentionDays * 86400).changes);
    }
    /** Server-side authorization: only an assigned actor and only a person enrolled as a child in the current policy. */
    report(actor: Actor, personId: string): ActivityDTO {
        this.purgeUnenrolled();
        const person = this.policy().people.find(p => p.id === personId);
        if (!person || !actor.personIds.includes(personId)) throw new AppError(404, 'person_not_found');
        const at = this.now(), today = Math.floor(at / 86400) * 86400, from = today - 7 * 86400;
        const rows = person.macs.length === 0 ? [] : this.store.all<SampleRow>(`SELECT sampled_at AS t, mac, interval_seconds AS interval, delta_bytes AS bytes, delta_blocked AS blocked,
                CASE offload WHEN 'on' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END AS offload_rank
            FROM activity_samples WHERE person_id=? AND delta_state='valid' AND sampled_at>? AND sampled_at<=?`, personId, Math.max(from, at - this.retentionDays * 86400), today + 86400);
        return {...this.source, personId, generatedAt: at, scope: 'estimated-network-activity', disclaimer: ACTIVITY_DISCLAIMER,
            thresholdBytesPerMinute: ACTIVE_MINUTE_THRESHOLD_BYTES, retentionDays: this.retentionDays, days: buildDays(rows, person.macs, at, this.retentionDays)};
    }
}
