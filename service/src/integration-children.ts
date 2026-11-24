import { AppError } from '../../shared/src/errors.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy, Schedule } from '../../shared/src/router-schema.ts';
import type { IntegrationManifest } from './integration-config.ts';
import type { Store } from './db.ts';
import { canonicalSchedules, scheduleWindows, schedulesInDatabase } from './integration-schedule-store.ts';
import { reconcileStaticDoh, protectedAddressesOf } from './doh-list.ts';

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
/** An enrol the router has not answered yet. An `enrolling` row whose operation has ended (a conflict with no stored observation) is no longer in flight: it is configured, and only its removal can leave that state. */
export const enrolInFlight = (store: Store, d: DeviceRow): boolean => d.state === 'enrolling' && Boolean(store.get("SELECT 1 FROM operations WHERE id=? AND state IN ('pending','unknown')", d.operation_id));
/**
 * The child's configured addresses. An `enrolling` row counts only once the router is KNOWN to hold it (`heldByRouter`: the addresses a FRESH observation
 * shows for this child, none otherwise): an unsettled row the router does not hold must not make the whole household look unenrolled and hide the revision token.
 */
export const configuredMacs = (store: Store, person: string, heldByRouter: readonly string[] = []): string[] =>
    devicesOf(store, person).filter(d => d.state !== 'enrolling' || (!enrolInFlight(store, d) && heldByRouter.includes(d.identifier))).map(d => d.identifier).sort();

/**
 * Router policy accepted by this service: only database children and their known devices (any state, so both sides of a
 * queued change are admitted), never a protected MAC, and exactly the owned schedules (ownedSchedules) of the children present.
 */
/** S2a (flag schedules.editable on): one child's planned windows, checked in place of its committed rows (queue()'s second validation only). */
export interface ScheduleOverlay { person: string; windows: readonly Schedule[] }
export function validateManagedPolicy(policy: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment' | 'scheduleClock' | 'schedules'>, store: Store, allowEmpty = true, overlay?: ScheduleOverlay): void {
    normalizePolicy(policy, config.protectedMacs);
    if (allowEmpty && policy.people.length === 0 && policy.pauses.length === 0 && policy.schedules.length === 0) return;
    // A moving device is admitted under both its source and its target child, so a policy on either side of the change validates.
    const known = new Set(store.all<{person_id: string; identifier: string; move_to: string | null}>("SELECT person_id,identifier,move_to FROM devices WHERE identifier_kind='mac'")
        .flatMap(d => [`${d.person_id}\n${d.identifier}`, ...(d.move_to ? [`${d.move_to}\n${d.identifier}`] : [])]));
    if (policy.people.some(person => person.macs.length === 0 || person.macs.some(m => !known.has(`${person.id}\n${m}`)))) throw new AppError(502, 'router_policy_foreign');
    const present = new Set(policy.people.map(p => p.id)), committed = ownedSchedules(config, store, present);
    const owned = overlay && schedulesInDatabase(config) ? [...committed.filter(s => s.person !== overlay.person), ...(present.has(overlay.person) ? overlay.windows : [])] : committed;
    // Flag off: main's literal comparison. Flag on: a pure canonical comparison with the committed rows (never normalizes, so never a limit error).
    if (schedulesInDatabase(config) ? canonicalSchedules(policy.schedules) !== canonicalSchedules(owned) : JSON.stringify(policy.schedules) !== JSON.stringify(owned)) throw new AppError(409, 'owner_schedule_configuration_changed');
    if (policy.schedules.length > 0 && !config.scheduleClock) throw new AppError(409, 'owner_schedule_clock_required');
}
/**
 * The schedules this service owns for the children present on the router. Flag off: the manifest enrollment schedules, as on main.
 * Flag schedules.editable on (unverified on this router): the committed schedule_windows rows; in S1 they change only through the one-time seed.
 */
export function ownedSchedules(config: Pick<IntegrationManifest, 'enrollment' | 'schedules'>, store: Store, present: ReadonlySet<string>): Schedule[] {
    if (!schedulesInDatabase(config)) return normalizePolicy(config.enrollment).schedules.filter(s => present.has(s.person));
    return scheduleWindows(store).filter(s => present.has(s.person));
}
/** Next policy with one MAC added to a child. Built from the router's accepted policy; only its schedules come from ownedSchedules. */
export function withDevice(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment' | 'schedules'>, person: string, mac: string, store: Store): RouterPolicy {
    const present = base.people.some(p => p.id === person);
    const people = present ? base.people.map(p => p.id === person ? {...p, macs: [...p.macs, mac]} : p) : [...base.people, {id: person, macs: [mac]}];
    if (people.length > CHILD_LIMIT) throw new AppError(409, 'child_limit_reached');
    return normalizePolicy({...base, revision: base.revision + 1, people, schedules: ownedSchedules(config, store, new Set(people.map(p => p.id)))}, config.protectedMacs);
}
/** All additions share one revision and one router operation; callers stage every device before validation. */
export function withDevices(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment' | 'schedules'>, additions: readonly {person: string; mac: string}[], store: Store): RouterPolicy {
    const people = base.people.map(p => ({...p, macs: [...p.macs]}));
    for (const addition of additions) {
        const person = people.find(p => p.id === addition.person);
        if (person) person.macs.push(addition.mac);
        else people.push({id: addition.person, macs: [addition.mac]});
    }
    if (people.length > CHILD_LIMIT) throw new AppError(409, 'child_limit_reached');
    return normalizePolicy({...base, revision: base.revision + 1, people, schedules: ownedSchedules(config, store, new Set(people.map(p => p.id)))}, config.protectedMacs);
}
/** Next policy with one MAC removed; a child left without devices leaves the router with its pause, allowance and schedules. */
export function withoutDevice(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment' | 'schedules'>, person: string, mac: string, store: Store): RouterPolicy {
    const people = base.people.map(p => p.id === person ? {...p, macs: p.macs.filter(m => m !== mac)} : p).filter(p => p.macs.length > 0);
    const gone = !people.some(p => p.id === person);
    return normalizePolicy({...base, revision: base.revision + 1, people, pauses: gone ? base.pauses.filter(p => p.person !== person) : base.pauses,
        ...(base.allowances ? {allowances: gone ? base.allowances.filter(a => a.person !== person) : base.allowances} : {}),
        schedules: ownedSchedules(config, store, new Set(people.map(p => p.id)))}, config.protectedMacs);
}
/** withoutDevice(A) then withDevice(B), as ONE revision: the router sees a single step, so there is never a state with the device nowhere. */
export function movePolicy(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs' | 'enrollment' | 'schedules'>, from: string, to: string, mac: string, store: Store): RouterPolicy {
    if (from === to) throw new AppError(409, 'device_move_same_child');
    if (!base.people.some(p => p.id === from && p.macs.includes(mac))) throw new AppError(409, 'device_not_on_router');
    const next = withDevice(withoutDevice(base, config, from, mac, store), config, to, mac, store);
    return normalizePolicy({...next, revision: base.revision + 1}, config.protectedMacs);
}
/**
 * S2a (flag schedules.editable on; unverified on this router): the next policy with ONE child's windows replaced. Everything else (people,
 * pauses, allowances, DoH and every other child's windows) is copied from the router base as it is; normalizePolicy enforces the router limits.
 */
export function withScheduleWindows(base: RouterPolicy, config: Pick<IntegrationManifest, 'protectedMacs'>, person: string, windows: readonly Schedule[]): RouterPolicy {
    return normalizePolicy({...base, revision: base.revision + 1, schedules: [...base.schedules.filter(s => s.person !== person), ...windows]}, config.protectedMacs);
}
/** Callers go through this object so a test can count builder calls (flag off must read 0). */
export const childrenSeam = {withScheduleWindows};
/**
 * Flag dnsHardening.dohList: true adds the static public DoH list (and strips retired entries); an explicit false removes the list and
 * retired entries from the policy being submitted. An absent key returns the policy untouched. Pure: the refusal tag is returned, and
 * only queue() writes it, so a rebuild (schedule admission) logs nothing.
 */
export function staticDoh(policy: RouterPolicy, config: Pick<IntegrationManifest, 'dnsHardening' | 'protectedMacs' | 'router' | 'listen' | 'trustedProxies'>): {policy: RouterPolicy; tag: string | null} {
    if (config.dnsHardening === undefined) return {policy, tag: null};
    const merged = reconcileStaticDoh(policy.doh, config.dnsHardening.dohList, protectedAddressesOf(config));
    return {policy: normalizePolicy({...policy, doh: merged.doh}, config.protectedMacs), tag: merged.refused > 0 ? merged.tag : null};
}
