import { AppError } from '../../shared/src/errors.ts';
import { isPrivateAddress } from '../../shared/src/router-inventory.ts';
import type { InventorySource, RouterInventory } from '../../shared/src/router-inventory.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { IntegrationStore } from './integration-db.ts';
import type { ParentAlerts } from './parent-alerts.ts';

export const INVENTORY_POLL_SECONDS = 60;
/** One accepted refresh request per this many seconds, across all admins. */
export const REFRESH_MIN_SECONDS = 10;
export const ALERT_MIN_INTERVAL_SECONDS = 3600;
/** Alerts are one shared system row for all admins, so the hourly and daily limits are global (and so hold per admin). */
export const ALERT_DAY_CAP = 12;
export const INVENTORY_ROW_CAP = 1024;
export const DEFAULT_INVENTORY_RETENTION_DAYS = 30;
export const MAX_INVENTORY_RETENTION_DAYS = 90;
const DAY = 86400;
const CANONICAL_MAC = /^[0-9a-f][02468ace](?::[0-9a-f]{2}){5}$/;

export function inventoryRetentionDays(env: NodeJS.ProcessEnv = process.env): number {
    const input = env.CF_INVENTORY_RETENTION_DAYS;
    if (input === undefined) return DEFAULT_INVENTORY_RETENTION_DAYS;
    if (!/^[1-9][0-9]?$/.test(input) || +input > MAX_INVENTORY_RETENTION_DAYS) throw new Error('invalid_inventory_retention_days');
    return +input;
}
/**
 * What is stored in inventory_state.last_error for a failed poll. Reply problems already read `inventory_unavailable:<code>`; ssh's own
 * exit 255 (host-key mismatch, auth) keeps a distinct label so it is never presented as an unavailable inventory.
 */
export function inventoryFailureLabel(code: string): string {
    if (code.startsWith('inventory_unavailable:')) return code;
    if (code === 'ssh_exit_255') return 'inventory_transport_error:ssh_exit_255';
    return `inventory_unavailable:${code.replace(/[^a-z0-9_]/g, '_').slice(0, 64)}`;
}
export interface InventoryDeviceDTO {
    mac: string; ipv4: string[]; hostname: string | null; reportedByDevice: true; source: InventorySource;
    firstSeen: number; lastSeen: number; acknowledgedAt: number | null; flags: {new: boolean; private: boolean; unassigned: boolean};
}
export interface InventoryDTO {
    status: {baselineAt: number | null; lastOkAt: number | null; lastAttemptAt: number | null; lastError: string | null; refreshRequestedAt: number | null; pollSeconds: number; retentionDays: number};
    devices: InventoryDeviceDTO[];
}
interface StateRow {
    generation: string | null; baseline_at: number | null; last_ok_at: number | null; last_attempt_at: number | null; last_error: string | null;
    refresh_requested_at: number | null; refresh_pending: number; alert_day_start: number | null; alert_day_count: number; last_alert_at: number | null;
}
interface DeviceRow {
    mac: string; ipv4_json: string; hostname: string | null; source: InventorySource; first_seen: number; last_seen: number; acknowledged_at: number | null;
}
const presence = (source: InventorySource) => source !== 'lease';

/**
 * The router's br-lan device listing as the service remembers it. Everything here is a HINT for the admin: a hostname is text the device
 * chose, a locally-administered MAC is not proof of rotation, and nothing is merged across MAC changes. Only a COMPLETE poll (no errors, not
 * truncated) can set the baseline or raise an alert, and an incomplete one never stores a device it has not seen before.
 */
export class InventoryStore {
    readonly store: IntegrationStore;
    readonly alerts: Pick<ParentAlerts, 'raise'>;
    readonly now: () => number;
    readonly retentionDays: number;
    constructor(store: IntegrationStore, alerts: Pick<ParentAlerts, 'raise'>, now = () => Math.floor(Date.now() / 1000), retentionDays = DEFAULT_INVENTORY_RETENTION_DAYS) {
        if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > MAX_INVENTORY_RETENTION_DAYS) throw new Error('invalid_inventory_retention_days');
        this.store = store; this.alerts = alerts; this.now = now; this.retentionDays = retentionDays;
    }
    private get generation(): string { return this.store.config.router.generation; }
    /** All-or-nothing, whether or not the caller already holds a transaction (the worker settles its step in the same one). */
    private atomic<T>(work: () => T): T {
        if (!this.store.db.isTransaction) return this.store.transaction(work);
        this.store.db.exec('SAVEPOINT inventory_work');
        try { const result = work(); this.store.db.exec('RELEASE inventory_work'); return result; }
        catch (error) { this.store.db.exec('ROLLBACK TO inventory_work'); this.store.db.exec('RELEASE inventory_work'); throw error; }
    }
    /** The singleton for the configured generation; a rebind (new generation) starts from nothing: no baseline, no counters. */
    private state(): StateRow {
        let row = this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1');
        if (!row) this.store.run('INSERT INTO inventory_state(singleton,generation) VALUES(1,?)', this.generation);
        else if (row.generation !== this.generation) this.store.run('UPDATE inventory_state SET generation=?,baseline_at=NULL,last_ok_at=NULL,last_attempt_at=NULL,last_error=NULL,refresh_requested_at=NULL,refresh_pending=0,alert_day_start=NULL,alert_day_count=0,last_alert_at=NULL WHERE singleton=1', this.generation);
        else return row;
        row = this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1')!;
        return row;
    }
    private requireAdmin(actor: Actor): void { if (actor.role !== 'admin') throw new AppError(403, 'admin_required'); }

    /** A poll is due every 60 s, or at once when an admin asked for a refresh. Reads only; opens nothing. */
    due(at = this.now()): boolean {
        const s = this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1');
        if (!s || s.generation !== this.generation || s.last_attempt_at === null) return true;
        return s.refresh_pending === 1 || at - s.last_attempt_at >= INVENTORY_POLL_SECONDS || at < s.last_attempt_at;
    }
    /** Recorded before the invocation, so a failing router is re-polled on the cadence, not on every dispatch cycle. */
    recordAttempt(at = this.now()): void {
        this.atomic(() => { this.state(); this.store.run('UPDATE inventory_state SET last_attempt_at=?,refresh_pending=0 WHERE singleton=1', at); });
    }
    /** The ONLY place a failed poll is recorded. It never touches integration_state.observation_error. */
    recordFailure(label: string): void {
        this.atomic(() => { this.state(); this.store.run('UPDATE inventory_state SET last_error=? WHERE singleton=1', label.slice(0, 96)); });
    }
    /** Admin refresh: sets the request marker only; the dispatch loop does the polling. */
    requestRefresh(actor: Actor, at = this.now()): void {
        this.requireAdmin(actor);
        const automatic = this.store.get<{enabled: number}>('SELECT enabled FROM automatic_dispatch WHERE singleton=1');
        if (!this.store.config.dispatch?.enabled || !automatic?.enabled) throw new AppError(409, 'inventory_dispatch_disabled');
        this.atomic(() => {
            const s = this.state();
            if (s.refresh_requested_at !== null && at >= s.refresh_requested_at && at - s.refresh_requested_at < REFRESH_MIN_SECONDS) throw new AppError(429, 'inventory_refresh_rate_limited');
            this.store.run('UPDATE inventory_state SET refresh_requested_at=?,refresh_pending=1 WHERE singleton=1', at);
        });
    }

    /** Applies one validated reply. Incomplete replies only refresh devices already known. */
    ingest(reply: RouterInventory, at = this.now()): {complete: boolean; alerted: number} {
        if (reply.generation !== this.generation) throw new AppError(409, 'inventory_generation_mismatch');
        return this.atomic(() => {
            const state = this.state();
            this.pruneAt(at);
            const g = this.generation;
            if (reply.errors.length > 0 || reply.truncated) {
                for (const d of reply.devices) this.refresh(g, d, at);
                this.store.run('UPDATE inventory_state SET last_error=? WHERE singleton=1', `inventory_incomplete:${reply.errors[0] ?? 'truncated'}`);
                return {complete: false, alerted: 0};
            }
            const known = new Set(this.store.all<{mac: string}>('SELECT mac FROM inventory_devices WHERE generation=?', g).map(r => r.mac));
            const stale = state.last_ok_at !== null && at - state.last_ok_at > this.retentionDays * DAY;
            const rebaseline = state.baseline_at === null || known.size === 0 || stale;
            const fresh = reply.devices.filter(d => !known.has(d.mac));
            this.makeRoom(g, known.size + fresh.length, new Set(reply.devices.map(d => d.mac)));
            for (const d of reply.devices) {
                if (known.has(d.mac)) this.refresh(g, d, at);
                else this.store.run('INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)', g, d.mac, JSON.stringify(d.ipv4), d.hostname, d.source, at, at);
            }
            this.store.run('UPDATE inventory_state SET baseline_at=?,last_ok_at=?,last_error=NULL WHERE singleton=1', rebaseline ? at : state.baseline_at, at);
            return {complete: true, alerted: rebaseline ? 0 : this.alertNew(g, at)};
        });
    }
    private refresh(g: string, d: RouterInventory['devices'][number], at: number): void {
        this.store.run(`UPDATE inventory_devices SET ipv4_json=?,hostname=?,source=?${presence(d.source) ? ',last_seen=?' : ''} WHERE generation=? AND mac=?`,
            JSON.stringify(d.ipv4), d.hostname, d.source, ...(presence(d.source) ? [at] : []), g, d.mac);
    }
    /** Keeps the per-generation row cap by dropping the longest-unseen rows that this reply does not list. */
    private makeRoom(g: string, wanted: number, listed: Set<string>): void {
        let excess = wanted - INVENTORY_ROW_CAP;
        if (excess <= 0) return;
        for (const row of this.store.all<{mac: string}>('SELECT mac FROM inventory_devices WHERE generation=? ORDER BY last_seen ASC, first_seen ASC, mac ASC', g)) {
            if (excess <= 0) break;
            if (listed.has(row.mac)) continue;
            this.store.run('DELETE FROM inventory_devices WHERE generation=? AND mac=?', g, row.mac); excess--;
        }
    }
    /**
     * One alert per poll at most, at most one per hour and 12 per day. A device whose alert was held back keeps alerted_at NULL, so a later
     * complete poll covers it. The alert carries a count only: never a MAC, an address or a hostname.
     */
    private alertNew(g: string, at: number): number {
        const s = this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1')!;
        const fresh = this.store.all<{mac: string}>('SELECT mac FROM inventory_devices WHERE generation=? AND acknowledged_at IS NULL AND alerted_at IS NULL AND first_seen > ?', g, s.baseline_at!);
        if (fresh.length === 0) return 0;
        const newDay = s.alert_day_start === null || at - s.alert_day_start >= DAY || at < s.alert_day_start;
        const used = newDay ? 0 : s.alert_day_count;
        if (used >= ALERT_DAY_CAP || (s.last_alert_at !== null && at >= s.last_alert_at && at - s.last_alert_at < ALERT_MIN_INTERVAL_SECONDS)) return 0;
        this.alerts.raise({kind: 'new_device', personId: null, severity: 'warning', details: {count: fresh.length}});
        this.store.run('UPDATE inventory_devices SET alerted_at=? WHERE generation=? AND acknowledged_at IS NULL AND alerted_at IS NULL AND first_seen > ?', at, g, s.baseline_at!);
        this.store.run('UPDATE inventory_state SET alert_day_start=?,alert_day_count=?,last_alert_at=? WHERE singleton=1', newDay ? at : s.alert_day_start, used + 1, at);
        return fresh.length;
    }
    prune(): void { this.atomic(() => this.pruneAt(this.now())); }
    private pruneAt(at: number): void { this.store.run('DELETE FROM inventory_devices WHERE last_seen < ?', at - this.retentionDays * DAY); }

    /** MACs that the current policy or the children admin already assigns to someone. */
    private assigned(): Set<string> {
        const macs = new Set(this.store.all<{identifier: string}>("SELECT identifier FROM devices WHERE identifier_kind='mac'").map(r => r.identifier));
        const desired = this.store.get<{desired_json: string}>('SELECT desired_json FROM service_state WHERE singleton=1');
        if (desired) for (const person of normalizePolicy(JSON.parse(desired.desired_json)).people) for (const mac of person.macs) macs.add(mac);
        return macs;
    }
    list(actor: Actor): InventoryDTO {
        this.requireAdmin(actor);
        const s = this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1'), current = s?.generation === this.generation ? s : undefined;
        const assigned = this.assigned(), baseline = current?.baseline_at ?? null, hidden = new Set(this.store.config.protectedMacs);
        const rows = this.store.all<DeviceRow>('SELECT mac,ipv4_json,hostname,source,first_seen,last_seen,acknowledged_at FROM inventory_devices WHERE generation=? ORDER BY last_seen DESC, mac ASC LIMIT ?', this.generation, INVENTORY_ROW_CAP);
        return {
            status: {baselineAt: baseline, lastOkAt: current?.last_ok_at ?? null, lastAttemptAt: current?.last_attempt_at ?? null, lastError: current?.last_error ?? null,
                refreshRequestedAt: current?.refresh_requested_at ?? null, pollSeconds: INVENTORY_POLL_SECONDS, retentionDays: this.retentionDays},
            devices: rows.filter(r => !hidden.has(r.mac)).map(r => this.dto(r, baseline, assigned))
        };
    }
    private dto(r: DeviceRow, baseline: number | null, assigned: Set<string>): InventoryDeviceDTO {
        return {mac: r.mac, ipv4: JSON.parse(r.ipv4_json) as string[], hostname: r.hostname, reportedByDevice: true, source: r.source, firstSeen: r.first_seen, lastSeen: r.last_seen, acknowledgedAt: r.acknowledged_at,
            flags: {new: baseline !== null && r.acknowledged_at === null && r.first_seen > baseline, private: isPrivateAddress(r.mac), unassigned: !assigned.has(r.mac)}};
    }
    /** Acknowledging records who looked; it never changes identity, assignment or policy. Repeating it keeps the first acknowledgement. */
    acknowledge(actor: Actor, mac: unknown): InventoryDeviceDTO {
        this.requireAdmin(actor);
        if (typeof mac !== 'string' || !CANONICAL_MAC.test(mac)) throw new AppError(400, 'invalid_mac');
        return this.atomic(() => {
            const g = this.generation, row = this.store.get<DeviceRow>('SELECT mac,ipv4_json,hostname,source,first_seen,last_seen,acknowledged_at FROM inventory_devices WHERE generation=? AND mac=?', g, mac);
            if (!row || this.store.config.protectedMacs.includes(mac)) throw new AppError(404, 'inventory_device_not_found');
            if (row.acknowledged_at === null) {
                this.store.run('UPDATE inventory_devices SET acknowledged_at=?,acknowledged_by=? WHERE generation=? AND mac=?', this.now(), actor.id, g, mac);
                this.store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', actor.id, 'inventory_acknowledge', this.now(), mac);
            }
            return this.dto(this.store.get<DeviceRow>('SELECT mac,ipv4_json,hostname,source,first_seen,last_seen,acknowledged_at FROM inventory_devices WHERE generation=? AND mac=?', g, mac)!,
                this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1')?.baseline_at ?? null, this.assigned());
        });
    }
}
