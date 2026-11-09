import type { Actor } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { presenceOf } from '../../shared/src/inventory-hints.ts';
import type { InventoryPresence } from '../../shared/src/inventory-hints.ts';
import { isPrivateAddress } from '../../shared/src/router-inventory.ts';
import type { InventorySource } from '../../shared/src/router-inventory.ts';
import { lookupVendor } from '../../shared/src/oui.ts';
import { digest as sha256 } from './auth.ts';
import type { Auth, AuthSession } from './auth.ts';
import { activeChildren, devicesOf } from './integration-children.ts';
import type { InventoryStore } from './inventory-store.ts';
import type { Routed } from './time-requests-http.ts';

/** A device not seen for this long is flagged; the page says "quiet", never "gone". */
export const QUIET_SECONDS = 7 * 86400;
export const ACTION = 'install_list_approve';
const DIGEST = /^[0-9a-f]{64}$/;

export type ReadinessPresence = InventoryPresence | 'unknown';
export interface ReadinessDevice { label: string; mac: string; vendor: string | null; stable: boolean; inScope: boolean; enrolled: boolean; presence: ReadinessPresence }
export interface ReadinessWarning { code: 'private_address_unconfirmed' | 'device_quiet' | 'device_unseen' | 'child_no_device'; child: string | null; device: string | null }
export interface ReadinessDTO { children: {id: string; name: string; devices: ReadinessDevice[]}[]; adults: ReadinessDevice[]; adultsAvailable: boolean; warnings: ReadinessWarning[]; digest: string; reviewedAt: number | null }
export interface ReadinessExport { version: 1; digest: string; generatedAt: number; reviewed: boolean; children: ReadinessDTO['children']; adults: ReadinessDevice[]; adultsAvailable: boolean; warnings: ReadinessWarning[] }

/** JSON with every object's keys sorted, so equal data always serialises to the same bytes. */
export function canonical(value: unknown): string {
    if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
    if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(',')}}`;
    return JSON.stringify(value);
}
const byText = <T>(key: (item: T) => string) => (a: T, b: T) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0);
const identity = (d: {mac: string; label: string; stable: boolean; inScope: boolean; enrolled: boolean}) => ({mac: d.mac, label: d.label, stable: d.stable, inScope: d.inScope, enrolled: d.enrolled});
/**
 * What the install consumes, and nothing that moves between polls: presence, vendor and warnings are left out, so the digest an operator
 * quotes only changes when the list itself does. Independent of key order and of row order.
 */
export function readinessDigest(list: {children: {id: string; name: string; devices: ReturnType<typeof identity>[]}[]; adults: ReturnType<typeof identity>[]}): string {
    const children = list.children.map(c => ({id: c.id, name: c.name, devices: c.devices.map(identity).sort(byText(d => d.mac))})).sort(byText(c => c.id));
    return sha256(canonical({v: 1, children, adults: list.adults.map(identity).sort(byText(d => d.mac))}));
}

/**
 * The adapter for what UI plan D adds (migration 015, not on main yet). TODO(D): read inventory_decisions here: `stable_confirmed_at` for
 * stableConfirmed, and role='adult' rows for adultDevices. Until then no private address counts as confirmed and no adult is listed.
 */
export const decisions = {
    /** False while adultDevices is a stub: the review is then partial and the page must say so and not offer approval. */
    adultsAvailable: false,
    stableConfirmed: (_mac: string): boolean => false,
    adultDevices: (): {label: string; mac: string}[] => [],
};

interface SeenRow { mac: string; source: InventorySource; last_seen: number }

/**
 * Review of the list the permanent router install will protect and allow. Admin-only; reads and records only, it never touches the router.
 * Off (the manifest default) is a set of routes that does not exist. Approval is a step-up bound to the exact digest; audit rows carry the
 * digest and an action type, never a MAC.
 */
export class InstallReadiness {
    readonly auth: Auth;
    readonly inventory: InventoryStore;
    constructor(auth: Auth, inventory: InventoryStore) { this.auth = auth; this.inventory = inventory; }
    private admin(actor: Actor): void { if (actor.role !== 'admin') throw new AppError(403, 'admin_required'); }
    private device(d: {label: string; mac: string}, enrolled: boolean, seen: Map<string, SeenRow>, now: number): ReadinessDevice {
        const row = seen.get(d.mac), vendor = lookupVendor(d.mac);
        return {label: d.label, mac: d.mac, vendor: vendor ?? null, stable: !isPrivateAddress(d.mac) || decisions.stableConfirmed(d.mac), inScope: this.inventory.scope.inRouterScope(d.mac, this.inventory.policy), enrolled,
            presence: row ? presenceOf({source: row.source, lastSeen: row.last_seen, now}) : 'unknown'};
    }
    private warnings(groups: {child: string | null; devices: ReadinessDevice[]}[], seen: Map<string, SeenRow>, now: number): ReadinessWarning[] {
        const out: ReadinessWarning[] = [];
        for (const {child, devices} of groups) {
            if (child !== null && devices.length === 0) out.push({code: 'child_no_device', child, device: null});
            for (const d of devices) {
                if (!d.stable) out.push({code: 'private_address_unconfirmed', child, device: d.label});
                const row = seen.get(d.mac);
                if (!row) out.push({code: 'device_unseen', child, device: d.label});
                else if (now - row.last_seen > QUIET_SECONDS) out.push({code: 'device_quiet', child, device: d.label});
            }
        }
        return out.sort(byText(w => `${w.code}\n${w.child ?? ''}\n${w.device ?? ''}`));
    }
    private build(): ReadinessDTO {
        const {store} = this.inventory, now = this.inventory.now();
        const seen = new Map(store.all<SeenRow>('SELECT mac,source,last_seen FROM inventory_devices WHERE generation=?', store.config.router.generation).map(r => [r.mac, r]));
        const children = activeChildren(store).filter(c => c.kind === 'child').map(c => ({id: c.id, name: c.name,
            devices: devicesOf(store, c.id).filter(d => d.state !== 'removing').map(d => this.device({label: d.label, mac: d.identifier}, true, seen, now)).sort(byText(d => d.mac))}))
            .sort(byText(c => c.id));
        const adults = decisions.adultDevices().map(d => this.device(d, false, seen, now)).sort(byText(d => d.mac));
        const sum = readinessDigest({children, adults});
        const reviewed = store.get<{at: number | null}>("SELECT MAX(timestamp) at FROM audit WHERE action='install_list_reviewed' AND outcome=?", `digest:${sum}`);
        return {children, adults, adultsAvailable: decisions.adultsAvailable, warnings: this.warnings([...children.map(c => ({child: c.name, devices: c.devices})), {child: null, devices: adults}], seen, now), digest: sum, reviewedAt: reviewed?.at ?? null};
    }
    private current(input: unknown): ReadinessDTO {
        if (typeof input !== 'string' || !DIGEST.test(input)) throw new AppError(400, 'invalid_digest');
        const list = this.build();
        if (list.digest !== input) throw new AppError(409, 'install_list_stale');
        return list;
    }
    private record(actor: string, action: 'install_list_reviewed' | 'install_list_exported', sum: string): void {
        this.inventory.store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', actor, action, this.auth.now(), `digest:${sum}`);
    }
    get(session: AuthSession, path: string): Routed | null {
        if (path !== '/admin/install-readiness') return null;
        this.admin(session.dto.actor);
        return {status: 200, body: this.build()};
    }
    async post(session: AuthSession, path: string, payload: unknown): Promise<Routed | null> {
        if (path === '/step-up/options') {
            if ((payload as {action?: unknown} | null)?.action !== ACTION) return null;
            this.admin(session.dto.actor);
            const body = object(payload, ['action', 'digest']);
            return {status: 200, body: await this.auth.stepUpChallenge(session, binding(this.current(body.digest).digest))};
        }
        if (path === '/admin/install-readiness/approve') return this.approve(session, payload);
        if (path === '/admin/install-readiness/export') return this.export(session, payload);
        return null;
    }
    private async approve(session: AuthSession, payload: unknown): Promise<Routed> {
        this.admin(session.dto.actor);
        const body = object(payload, ['digest'], ['stepUp']), sum = this.current(body.digest).digest;
        const proof = await this.auth.stepUpVerify(session, body.stepUp, binding(sum));
        this.auth.store.transaction(() => {
            const actor = this.auth.commitStepUp(session, proof);
            this.admin(actor);
            // The list may have changed during the passkey step: approve only the exact digest the passkey confirmed.
            this.current(sum);
            this.record(actor.id, 'install_list_reviewed', sum);
        });
        return {status: 200, body: {approved: true, digest: sum}};
    }
    /** The one place the list leaves with its MACs. Only the current digest can be exported, and each export is audited. */
    private export(session: AuthSession, payload: unknown): Routed {
        this.admin(session.dto.actor);
        const list = this.current(object(payload, ['digest']).digest);
        this.auth.store.transaction(() => { this.record(session.dto.actor.id, 'install_list_exported', list.digest); });
        const file: ReadinessExport = {version: 1, digest: list.digest, generatedAt: this.auth.now(), reviewed: list.reviewedAt !== null, children: list.children, adults: list.adults, adultsAvailable: list.adultsAvailable, warnings: list.warnings};
        return {status: 200, body: {export: file}};
    }
}
const binding = (sum: string): string => sha256(JSON.stringify([ACTION, sum]));
