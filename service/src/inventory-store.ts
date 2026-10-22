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
/** No complete poll for this long raises `inventory_stalled`, then at most once per STALL_ALERT_INTERVAL_SECONDS. */
export const STALL_SECONDS = 1800;
export const STALL_ALERT_INTERVAL_SECONDS = 6 * 3600;
/** The one router error that does not make a poll incomplete: devices are still listed, only routerTime (0) is untrusted. */
export const BENIGN_ROUTER_ERROR = 'invalid_clock';
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
    firstSeen: number; lastSeen: number; acknowledgedAt: number | null; personId: string | null; personName: string | null; flags: {new: boolean; private: boolean; unassigned: boolean};
}
export interface InventoryDTO {
    status: {baselineAt: number | null; lastOkAt: number | null; lastAttemptAt: number | null; lastError: string | null; refreshRequestedAt: number | null; pollSeconds: number; retentionDays: number};
    devices: InventoryDeviceDTO[];
}
interface StateRow {
    generation: string | null; baseline_at: number | null; last_ok_at: number | null; last_attempt_at: number | null; last_error: string | null;
    refresh_requested_at: number | null; refresh_pending: number; alert_day_start: number | null; alert_day_count: number; last_alert_at: number | null;
    incomplete_since: number | null; last_stall_alert_at: number | null;
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
        this.atomic(() => this.purgeProtected());
    }
    /** A protected management MAC is never listed, so a stored row for one (an older manifest, a hand edit) is removed. */
    private purgeProtected(): void {
        const macs = this.store.config.protectedMacs;
        if (macs.length > 0) this.store.run(`DELETE FROM inventory_devices WHERE mac IN (${macs.map(() => '?').join(',')})`, ...macs);
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
        else if (row.generation !== this.generation) this.store.run('UPDATE inventory_state SET generation=?,baseline_at=NULL,last_ok_at=NULL,last_attempt_at=NULL,last_error=NULL,refresh_requested_at=NULL,refresh_pending=0,alert_day_start=NULL,alert_day_count=0,last_alert_at=NULL,incomplete_since=NULL,last_stall_alert_at=NULL WHERE singleton=1', this.generation);
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
    recordFailure(label: string, at = this.now()): void {
        this.atomic(() => { this.state(); this.store.run('UPDATE inventory_state SET last_error=? WHERE singleton=1', label.slice(0, 96)); this.noteIncomplete(at); });
    }
    /** Starts (or continues) the clock of "no complete poll" at the last complete one, and alerts once it has run for 30 minutes. */
    private noteIncomplete(at: number): void {
        const s = this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1')!;
        const since = s.incomplete_since ?? s.last_ok_at ?? at;
        if (s.incomplete_since === null) this.store.run('UPDATE inventory_state SET incomplete_since=? WHERE singleton=1', since);
        if (at - since >= STALL_SECONDS) this.raiseStalled('no_complete_poll', Math.floor((at - since) / 60), at);
    }
    /** System alert, counts and a cause only. One per 6 hours across every cause (the alert row is shared). */
    private raiseStalled(cause: 'no_complete_poll' | 'row_cap', count: number, at: number): void {
        const s = this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1')!;
        if (s.last_stall_alert_at !== null && at >= s.last_stall_alert_at && at - s.last_stall_alert_at < STALL_ALERT_INTERVAL_SECONDS) return;
        this.alerts.raise({kind: 'inventory_stalled', personId: null, severity: 'warning', details: {cause, count}});
        this.store.run('UPDATE inventory_state SET last_stall_alert_at=? WHERE singleton=1', at);
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
            this.purgeProtected();
            this.pruneAt(at);
            const g = this.generation;
            // invalid_clock alone is not structural, but a refusal body (errors and no devices) lists nothing and is never a baseline.
            const other = reply.errors.find(e => e !== BENIGN_ROUTER_ERROR);
            if (other !== undefined || reply.truncated || (reply.errors.length > 0 && reply.devices.length === 0)) {
                for (const d of reply.devices) this.refresh(g, d, at);
                this.store.run('UPDATE inventory_state SET last_error=? WHERE singleton=1', `inventory_incomplete:${other ?? reply.errors[0] ?? 'truncated'}`);
                this.noteIncomplete(at);
                return {complete: false, alerted: 0};
            }
            const known = new Set(this.store.all<{mac: string}>('SELECT mac FROM inventory_devices WHERE generation=?', g).map(r => r.mac));
            const stale = state.last_ok_at !== null && at - state.last_ok_at > this.retentionDays * DAY;
            const rebaseline = state.baseline_at === null || known.size === 0 || stale;
            const fresh = reply.devices.filter(d => !known.has(d.mac));
            const room = this.makeRoom(g, known.size, fresh.length, new Set(reply.devices.map(d => d.mac)), rebaseline ? at : state.baseline_at!);
            const stored = new Set(fresh.slice(0, room).map(d => d.mac));
            for (const d of reply.devices) {
                if (known.has(d.mac)) this.refresh(g, d, at);
                else if (stored.has(d.mac)) this.store.run('INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)', g, d.mac, JSON.stringify(d.ipv4), d.hostname, d.source, at, at);
            }
            const dropped = fresh.length - stored.size;
            this.store.run('UPDATE inventory_state SET baseline_at=?,last_ok_at=?,last_error=?,incomplete_since=NULL WHERE singleton=1', rebaseline ? at : state.baseline_at, at,
                dropped > 0 ? 'inventory_row_cap' : reply.errors.length > 0 ? `inventory_warning:${BENIGN_ROUTER_ERROR}` : null);
            if (dropped > 0) this.raiseStalled('row_cap', dropped, at);
            // A re-baseline over an existing baseline accepts every device it lists without review: say so, with a count.
            if (rebaseline && state.baseline_at !== null && stored.size > 0) this.alerts.raise({kind: 'new_device', personId: null, severity: 'warning', details: {count: stored.size, rebaselined: true}});
            return {complete: true, alerted: rebaseline ? 0 : this.alertNew(g, at)};
        });
    }
    private refresh(g: string, d: RouterInventory['devices'][number], at: number): void {
        this.store.run(`UPDATE inventory_devices SET ipv4_json=?,hostname=?,source=?${presence(d.source) ? ',last_seen=?' : ''} WHERE generation=? AND mac=?`,
            JSON.stringify(d.ipv4), d.hostname, d.source, ...(presence(d.source) ? [at] : []), g, d.mac);
    }
    /**
     * Keeps the per-generation row cap. Only the longest-unseen rows that this reply does not list, that nobody acknowledged and that are not a
     * New device still waiting for its alert may go. Returns how many new rows fit: at the cap with nothing evictable it is 0 (never a flood
     * pushing out the evidence).
     */
    private makeRoom(g: string, known: number, wanted: number, listed: Set<string>, baseline: number): number {
        let excess = known + wanted - INVENTORY_ROW_CAP, held = known;
        if (excess > 0) {
            for (const row of this.store.all<{mac: string; acknowledged_at: number | null; alerted_at: number | null; first_seen: number}>('SELECT mac,acknowledged_at,alerted_at,first_seen FROM inventory_devices WHERE generation=? ORDER BY last_seen ASC, first_seen ASC, mac ASC', g)) {
                if (excess <= 0) break;
                if (listed.has(row.mac) || row.acknowledged_at !== null || (row.alerted_at === null && row.first_seen > baseline)) continue;
                this.store.run('DELETE FROM inventory_devices WHERE generation=? AND mac=?', g, row.mac); excess--; held--;
            }
        }
        return Math.max(0, Math.min(wanted, INVENTORY_ROW_CAP - held));
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
        if (s.last_alert_at !== null && at >= s.last_alert_at && at - s.last_alert_at < ALERT_MIN_INTERVAL_SECONDS) return 0;
        const open = this.store.get<{id: number}>("SELECT id FROM parent_alerts WHERE kind='new_device' AND person_id IS NULL AND state IN ('open','acknowledged') ORDER BY id DESC LIMIT 1");
        if (used >= ALERT_DAY_CAP) {
            // Past the daily cap the existing alert only counts the occurrence: it is never re-opened, so a flood cannot nag the admin.
            if (!open) return 0;
            this.store.run('UPDATE parent_alerts SET count=count+1,last_seen=MAX(last_seen,?) WHERE id=?', at, open.id);
        } else {
            this.alerts.raise({kind: 'new_device', personId: null, severity: 'warning', details: {count: fresh.length}});
            this.store.run('UPDATE inventory_state SET alert_day_start=?,alert_day_count=? WHERE singleton=1', newDay ? at : s.alert_day_start, used + 1);
        }
        this.store.run('UPDATE inventory_devices SET alerted_at=? WHERE generation=? AND acknowledged_at IS NULL AND alerted_at IS NULL AND first_seen > ?', at, g, s.baseline_at!);
        this.store.run('UPDATE inventory_state SET last_alert_at=? WHERE singleton=1', at);
        return fresh.length;
    }
    prune(): void { this.atomic(() => this.pruneAt(this.now())); }
    private pruneAt(at: number): void { this.store.run('DELETE FROM inventory_devices WHERE last_seen < ?', at - this.retentionDays * DAY); }

    /** The child that owns each MAC through the children admin (devices) or, failing that, the desired policy. A corrupt policy only costs the fallback. */
    private owners(): Map<string, string> {
        const owners = new Map<string, string>();
        for (const r of this.store.all<{identifier: string; person_id: string}>("SELECT identifier,person_id FROM devices WHERE identifier_kind='mac'")) owners.set(r.identifier, r.person_id);
        try {
            const desired = this.store.get<{desired_json: string}>('SELECT desired_json FROM service_state WHERE singleton=1');
            if (desired) for (const person of normalizePolicy(JSON.parse(desired.desired_json)).people) for (const mac of person.macs) if (!owners.has(mac)) owners.set(mac, person.id);
        } catch { /* devices alone decide */ }
        return owners;
    }
    list(actor: Actor): InventoryDTO {
        this.requireAdmin(actor);
        const s = this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1'), current = s?.generation === this.generation ? s : undefined;
        const lookup = this.lookup(), baseline = current?.baseline_at ?? null, hidden = new Set(this.store.config.protectedMacs);
        const rows = this.store.all<DeviceRow>('SELECT mac,ipv4_json,hostname,source,first_seen,last_seen,acknowledged_at FROM inventory_devices WHERE generation=? ORDER BY last_seen DESC, mac ASC LIMIT ?', this.generation, INVENTORY_ROW_CAP);
        return {
            status: {baselineAt: baseline, lastOkAt: current?.last_ok_at ?? null, lastAttemptAt: current?.last_attempt_at ?? null, lastError: current?.last_error ?? null,
                refreshRequestedAt: current?.refresh_requested_at ?? null, pollSeconds: INVENTORY_POLL_SECONDS, retentionDays: this.retentionDays},
            devices: rows.filter(r => !hidden.has(r.mac)).map(r => this.dto(r, baseline, lookup, actor))
        };
    }
    private lookup(): {owners: Map<string, string>; names: Map<string, string>} {
        return {owners: this.owners(), names: new Map(this.store.all<{id: string; name: string}>('SELECT id,name FROM people WHERE active=1').map(p => [p.id, p.name]))};
    }
    /** The owner is named only to a viewer who manages that child; for anyone else it is null (the device still counts as assigned). */
    private dto(r: DeviceRow, baseline: number | null, lookup: {owners: Map<string, string>; names: Map<string, string>}, viewer: Actor): InventoryDeviceDTO {
        const owner = lookup.owners.get(r.mac), visible = owner !== undefined && viewer.personIds.includes(owner) && lookup.names.has(owner);
        return {mac: r.mac, ipv4: JSON.parse(r.ipv4_json) as string[], hostname: r.hostname, reportedByDevice: true, source: r.source, firstSeen: r.first_seen, lastSeen: r.last_seen, acknowledgedAt: r.acknowledged_at,
            personId: visible ? owner : null, personName: visible ? lookup.names.get(owner)! : null,
            flags: {new: baseline !== null && r.acknowledged_at === null && r.first_seen > baseline, private: isPrivateAddress(r.mac), unassigned: owner === undefined}};
    }
    /** Acknowledging records who looked; it never changes identity, assignment or policy. Repeating it keeps the first acknowledgement. */
    acknowledge(actor: Actor, mac: unknown): InventoryDeviceDTO {
        this.requireAdmin(actor);
        if (typeof mac !== 'string' || !CANONICAL_MAC.test(mac)) throw new AppError(400, 'invalid_mac');
        return this.atomic(() => {
            const g = this.generation, row = this.store.get<DeviceRow & {id: number}>('SELECT rowid id,mac,ipv4_json,hostname,source,first_seen,last_seen,acknowledged_at FROM inventory_devices WHERE generation=? AND mac=?', g, mac);
            if (!row || this.store.config.protectedMacs.includes(mac)) throw new AppError(404, 'inventory_device_not_found');
            if (row.acknowledged_at === null) {
                this.store.run('UPDATE inventory_devices SET acknowledged_at=?,acknowledged_by=? WHERE generation=? AND mac=?', this.now(), actor.id, g, mac);
                // The row id, never the MAC: the audit trail must not become a second device list.
                this.store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', actor.id, 'inventory_acknowledge', this.now(), `inventory_row:${row.id}`);
            }
            return this.dto(this.store.get<DeviceRow>('SELECT mac,ipv4_json,hostname,source,first_seen,last_seen,acknowledged_at FROM inventory_devices WHERE generation=? AND mac=?', g, mac)!,
                this.store.get<StateRow>('SELECT * FROM inventory_state WHERE singleton=1')?.baseline_at ?? null, this.lookup(), actor);
        });
    }
}
