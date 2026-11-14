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
export interface ReadinessWarning { code: 'private_address_unconfirmed' | 'adult_private_address' | 'device_quiet' | 'device_unseen' | 'child_no_device'; child: string | null; device: string | null }
/** Where an adult comes from: the router's protected baseline (config.protectedMacs) or a parent's role=adult decision (UI plan D). Part of the digest identity. */
export type AdultSource = 'baseline' | 'role';
export interface ReadinessAdultDevice extends ReadinessDevice { source: AdultSource }
export type ReadinessAdult = Omit<ReadinessAdultDevice, 'mac'>;
export const ADULTS_SOURCE = 'protected-baseline';
export const PROTECTED_LABEL = 'Protected device';
/** The full list, addresses included: only the export (and the digest) use it as is; GET answers with `view` (adult addresses stripped). */
export interface ReadinessDTO { children: {id: string; name: string; devices: ReadinessDevice[]}[]; adults: ReadinessAdultDevice[]; adultsAvailable: boolean; adultsSource: typeof ADULTS_SOURCE; warnings: ReadinessWarning[]; digest: string; reviewedAt: number | null }
export interface ReadinessView extends Omit<ReadinessDTO, 'adults'> { adults: ReadinessAdult[] }
export interface ReadinessExport { version: 1; digestVersion: typeof DIGEST_VERSION; digest: string; generatedAt: number; reviewed: boolean; children: ReadinessDTO['children']; adults: ReadinessAdultDevice[]; adultsAvailable: boolean; adultsSource: typeof ADULTS_SOURCE; warnings: ReadinessWarning[] }

/** JSON with every object's keys sorted, so equal data always serialises to the same bytes. */
export function canonical(value: unknown): string {
    if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
    if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(',')}}`;
    return JSON.stringify(value);
}
const byText = <T>(key: (item: T) => string) => (a: T, b: T) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0);
const identity = (d: {mac: string; label: string; stable: boolean; inScope: boolean; enrolled: boolean}) => ({mac: d.mac, label: d.label, stable: d.stable, inScope: d.inScope, enrolled: d.enrolled});
const adultIdentity = (d: Parameters<typeof identity>[0] & {source: AdultSource}) => ({...identity(d), source: d.source});
/**
 * What the install consumes, and nothing that moves between polls: presence, vendor and warnings are left out, so the digest an operator
 * quotes only changes when the list itself does. Independent of key order and of row order.
 */
export function readinessDigest(list: {children: {id: string; name: string; devices: ReturnType<typeof identity>[]}[]; adults: ReturnType<typeof adultIdentity>[]}): string {
    const children = list.children.map(c => ({id: c.id, name: c.name, devices: c.devices.map(identity).sort(byText(d => d.mac))})).sort(byText(c => c.id));
    return sha256(canonical({v: DIGEST_VERSION, children, adults: list.adults.map(adultIdentity).sort(byText(d => d.mac))}));
}

/** The `v` in the digest input; bumped whenever what the digest covers changes. The export's own `version` is the file format. */
export const DIGEST_VERSION = 2;
export const ADULT_LABEL = 'Adult device';
interface DecisionFact { mac: string; role: string; label: string | null; stable_confirmed: number }

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
    /** UI plan D's decisions for the current generation (none while inventoryUi.triage is off, when the decision routes do not exist). */
    private decided(): Map<string, DecisionFact> {
        const {store} = this.inventory;
        if (!this.inventory.triage) return new Map();
        return new Map(store.all<DecisionFact>('SELECT mac,role,label,stable_confirmed FROM inventory_decisions WHERE generation=?', store.config.router.generation).map(d => [d.mac, d]));
    }
    private device(d: {label: string; mac: string}, enrolled: boolean, seen: Map<string, SeenRow>, facts: Map<string, DecisionFact>, now: number): ReadinessDevice {
        const row = seen.get(d.mac), vendor = lookupVendor(d.mac);
        return {label: d.label, mac: d.mac, vendor: vendor ?? null, stable: !isPrivateAddress(d.mac) || facts.get(d.mac)?.stable_confirmed === 1, inScope: this.inventory.scope.inRouterScope(d.mac, this.inventory.policy), enrolled,
            presence: row ? presenceOf({source: row.source, lastSeen: row.last_seen, now}) : 'unknown'};
    }
    private warnings(groups: {child: string | null; devices: ReadinessDevice[]}[], adults: ReadinessDevice[], seen: Map<string, SeenRow>, now: number): ReadinessWarning[] {
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
        // A private address on the protect list is as unreliable as one on the allow list: the adult is not silent. The code carries no MAC.
        for (const a of adults) if (!a.stable) out.push({code: 'adult_private_address', child: null, device: a.label});
        return out.sort(byText(w => `${w.code}\n${w.child ?? ''}\n${w.device ?? ''}`));
    }
    private build(): ReadinessDTO {
        const {store} = this.inventory, now = this.inventory.now();
        const seen = new Map(store.all<SeenRow>('SELECT mac,source,last_seen FROM inventory_devices WHERE generation=?', store.config.router.generation).map(r => [r.mac, r]));
        const facts = this.decided();
        const children = activeChildren(store).filter(c => c.kind === 'child').map(c => ({id: c.id, name: c.name,
            devices: devicesOf(store, c.id).filter(d => d.state !== 'removing').map(d => this.device({label: d.label, mac: d.identifier}, true, seen, facts, now)).sort(byText(d => d.mac))}))
            .sort(byText(c => c.id));
        // The adults are the protected baseline the router install preserves (config.protectedMacs), plus the devices a parent decided are adults.
        // Baseline wins a duplicate; the decision rows are keyed by mac, so a role adult appears once.
        const baseline = new Set(store.config.protectedMacs), extras = new Map<string, {label: string; mac: string}>();
        for (const d of facts.values()) if (d.role === 'adult' && !baseline.has(d.mac)) extras.set(d.mac, {label: d.label ?? ADULT_LABEL, mac: d.mac});
        const adults: ReadinessAdultDevice[] = [...[...baseline].map(mac => ({label: PROTECTED_LABEL, mac, source: 'baseline' as const})), ...[...extras.values()].map(d => ({...d, source: 'role' as const}))]
            .map(d => ({...this.device(d, false, seen, facts, now), source: d.source})).sort(byText(d => d.mac));
        // A device is protected or allowed, never both: refuse a list that would do both.
        const adultMacs = new Set(adults.map(a => a.mac));
        if (children.some(c => c.devices.some(d => adultMacs.has(d.mac)))) throw new AppError(409, 'install_list_overlap');
        const sum = readinessDigest({children, adults});
        const reviewed = store.get<{at: number | null}>("SELECT MAX(timestamp) at FROM audit WHERE action='install_list_reviewed' AND outcome=?", `digest:${sum}`);
        return {children, adults, adultsAvailable: baseline.size > 0, adultsSource: ADULTS_SOURCE, warnings: this.warnings(children.map(c => ({child: c.name, devices: c.devices})), adults, seen, now), digest: sum, reviewedAt: reviewed?.at ?? null};
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
        const list = this.build();
        return {status: 200, body: {...list, adults: list.adults.map(({mac: _mac, ...rest}): ReadinessAdult => rest)} satisfies ReadinessView};
    }
    async post(session: AuthSession, path: string, payload: unknown): Promise<Routed | null> {
        if (path === '/step-up/options') {
            if ((payload as {action?: unknown} | null)?.action !== ACTION) return null;
            this.admin(session.dto.actor);
            const body = object(payload, ['action', 'digest']), list = this.current(body.digest);
            // No challenge for a list that cannot be approved.
            if (!list.adultsAvailable) throw new AppError(409, 'install_list_incomplete');
            return {status: 200, body: await this.auth.stepUpChallenge(session, binding(list.digest))};
        }
        if (path === '/admin/install-readiness/approve') return this.approve(session, payload);
        if (path === '/admin/install-readiness/export') return this.export(session, payload);
        return null;
    }
    private async approve(session: AuthSession, payload: unknown): Promise<Routed> {
        this.admin(session.dto.actor);
        const body = object(payload, ['digest'], ['stepUp']), current = this.current(body.digest), sum = current.digest;
        // A review without the protect list is partial: it cannot be approved.
        if (!current.adultsAvailable) throw new AppError(409, 'install_list_incomplete');
        const proof = await this.auth.stepUpVerify(session, body.stepUp, binding(sum));
        this.auth.store.transaction(() => {
            const actor = this.auth.commitStepUp(session, proof);
            this.admin(actor);
            // The list may have changed during the passkey step: approve only the exact digest the passkey confirmed.
            if (!this.current(sum).adultsAvailable) throw new AppError(409, 'install_list_incomplete');
            this.record(actor.id, 'install_list_reviewed', sum);
        });
        return {status: 200, body: {approved: true, digest: sum}};
    }
    /** The one place the list leaves with its MACs. Only the current digest can be exported, and each export is audited. */
    private export(session: AuthSession, payload: unknown): Routed {
        this.admin(session.dto.actor);
        const list = this.current(object(payload, ['digest']).digest);
        this.auth.store.transaction(() => { this.record(session.dto.actor.id, 'install_list_exported', list.digest); });
        const file: ReadinessExport = {version: 1, digestVersion: DIGEST_VERSION, digest: list.digest, generatedAt: this.auth.now(), reviewed: list.reviewedAt !== null, children: list.children, adults: list.adults, adultsAvailable: list.adultsAvailable, adultsSource: ADULTS_SOURCE, warnings: list.warnings};
        return {status: 200, body: {export: file}};
    }
}
const binding = (sum: string): string => sha256(JSON.stringify([ACTION, sum]));
