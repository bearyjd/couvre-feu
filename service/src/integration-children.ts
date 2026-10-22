import { AppError } from '../../shared/src/errors.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { IntegrationManifest } from './integration-config.ts';
import type { Store } from './db.ts';

/** The router's own policy limits (router/lib/json.awk, shared/src/router-schema.ts); not product limits of this service. */
export const CHILD_LIMIT = 64;
export const DEVICES_PER_CHILD = 32;
export const DEVICE_LIMIT = 256;
/** A router revision token ("s<state>-r<revision>-<digest>") as the If-Match / precondition value of every router change. */
export const TOKEN = /^"s(?:0|[1-9][0-9]{0,9})-r(?:0|[1-9][0-9]{0,9})-[0-9a-f]{64}"$/;
/** Client idempotency keys. The `tr-` prefix belongs to the time-request service (its re-pause keys), so a client key can never mimic one. */
export const CLIENT_KEY = /^(?!tr-)[A-Za-z0-9_-]{16,128}$/;
/** Router replies to an rpc-sync that it refused under its lock before writing anything (router/lib/rpc.sh). */
export const PRE_WRITE_REJECTIONS: ReadonlySet<string> = new Set(['incomplete_address_coverage', 'incomplete_transition_address_coverage', 'rpc_scope_overlap', 'protected_mac_overlap']);
/** The router needs a DHCP lease or neighbour entry for these MACs; it does not say which one was missing. */
export const ADDRESS_COVERAGE_REJECTIONS: ReadonlySet<string> = new Set(['incomplete_address_coverage', 'incomplete_transition_address_coverage']);

export interface ChildRow { id: string; name: string; kind: 'child' | 'device_group'; active: number; created_at: number }
export interface DeviceRow {
    id: string; person_id: string; label: string; identifier_kind: 'mac'; identifier: string;
    state: 'enrolling' | 'active' | 'removing' | 'moving'; operation_id: string | null; created_at: number; move_to: string | null;
}

/**
 * Migration 008 data step: an empty table set is seeded once from the manifest's single child and device (deterministic,
 * manifest-named). Manifest admins could only ever name that one child, so they become scope_all; parents keep their list.
 */
export function seedChildren(store: Store, config: Pick<IntegrationManifest, 'person'>, now: number): void {
    if (!store.db.isTransaction) throw new Error('seed_requires_transaction');
    if (store.get('SELECT id FROM people LIMIT 1')) return;
    const p = config.person;
    store.run('INSERT INTO people(id,name,active,created_at) VALUES(?,?,1,?)', p.id, p.name, now);
    store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',?)", p.device.id, p.id, p.device.label, p.device.mac, now);
    store.run("UPDATE accounts SET scope_all=1 WHERE role='admin'");
}
export const activeChildren = (store: Store): ChildRow[] => store.all<ChildRow>('SELECT * FROM people WHERE active=1 ORDER BY created_at,id');
export const devicesOf = (store: Store, person: string): DeviceRow[] => store.all<DeviceRow>('SELECT * FROM devices WHERE person_id=? ORDER BY created_at,id', person);
/** MACs the router should hold for this child right now (pending additions excluded, pending removals included). */
export const configuredMacs = (store: Store, person: string): string[] => devicesOf(store, person).filter(d => d.state !== 'enrolling').map(d => d.identifier).sort();

/**
 * Router policy accepted by this service: only database children and their known devices (any state, so both sides of a
 * queued change are admitted), never a protected MAC, and exactly the manifest-owned schedules of the children present.
 */
export function validateManagedPolicy(policy: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment' | 'scheduleClock'>, store: Store, allowEmpty = true): void {
    normalizePolicy(policy, config.protectedMacs);
    if (allowEmpty && policy.people.length === 0 && policy.pauses.length === 0 && policy.schedules.length === 0) return;
    // A moving device is admitted under both its source and its target child, so a policy on either side of the change validates.
    const known = new Set(store.all<{person_id: string; identifier: string; move_to: string | null}>("SELECT person_id,identifier,move_to FROM devices WHERE identifier_kind='mac'")
        .flatMap(d => [`${d.person_id}\n${d.identifier}`, ...(d.move_to ? [`${d.move_to}\n${d.identifier}`] : [])]));
    if (policy.people.some(person => person.macs.length === 0 || person.macs.some(m => !known.has(`${person.id}\n${m}`)))) throw new AppError(502, 'router_policy_foreign');
    if (JSON.stringify(policy.schedules) !== JSON.stringify(ownerSchedules(policy, config))) throw new AppError(409, 'owner_schedule_configuration_changed');
    if (policy.schedules.length > 0 && !config.scheduleClock) throw new AppError(409, 'owner_schedule_clock_required');
}
/** Schedules stay owner-configured in the manifest; they apply to whichever of their children are on the router. */
function ownerSchedules(policy: Pick<RouterPolicy, 'people'>, config: Pick<IntegrationManifest, 'enrollment'>) {
    const present = new Set(policy.people.map(p => p.id));
    return normalizePolicy(config.enrollment).schedules.filter(s => present.has(s.person));
}
/** Next policy with one MAC added to a child. Built from the router's accepted policy, never from the database. */
export function withDevice(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment'>, person: string, mac: string): RouterPolicy {
    const present = base.people.some(p => p.id === person);
    const people = present ? base.people.map(p => p.id === person ? {...p, macs: [...p.macs, mac]} : p) : [...base.people, {id: person, macs: [mac]}];
    if (people.length > CHILD_LIMIT) throw new AppError(409, 'child_limit_reached');
    return normalizePolicy({...base, revision: base.revision + 1, people, schedules: ownerSchedules({people}, config)}, config.protectedMacs);
}
/** Next policy with one MAC removed; a child left without devices leaves the router with its pause, allowance and schedules. */
export function withoutDevice(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment'>, person: string, mac: string): RouterPolicy {
    const people = base.people.map(p => p.id === person ? {...p, macs: p.macs.filter(m => m !== mac)} : p).filter(p => p.macs.length > 0);
    const gone = !people.some(p => p.id === person);
    return normalizePolicy({...base, revision: base.revision + 1, people, pauses: gone ? base.pauses.filter(p => p.person !== person) : base.pauses,
        ...(base.allowances ? {allowances: gone ? base.allowances.filter(a => a.person !== person) : base.allowances} : {}),
        schedules: ownerSchedules({people}, config)}, config.protectedMacs);
}
/** withoutDevice(A) then withDevice(B), as ONE revision: the router sees a single step, so there is never a state with the device nowhere. */
export function movePolicy(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment'>, from: string, to: string, mac: string): RouterPolicy {
    if (from === to) throw new AppError(409, 'device_move_same_child');
    if (!base.people.some(p => p.id === from && p.macs.includes(mac))) throw new AppError(409, 'device_not_on_router');
    const next = withDevice(withoutDevice(base, config, from, mac), config, to, mac);
    return normalizePolicy({...next, revision: base.revision + 1}, config.protectedMacs);
}
