import { randomBytes } from 'node:crypto';
import type { Actor, EntryKind } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { mac as canonicalMac } from '../../shared/src/router-schema.ts';
import { digest } from './auth.ts';
import type { Auth, AuthSession } from './auth.ts';
import { routerScopeOf } from './integration-config.ts';
import type { IntegrationPolicy, IntegrationOperation } from './integration-policy.ts';
import { ADDRESS_COVERAGE_REJECTIONS, CHILD_LIMIT, DEVICES_PER_CHILD, DEVICE_LIMIT, activeChildren, devicesOf, withDevice, withoutDevice } from './integration-children.ts';
import type { ChildRow, DeviceRow } from './integration-children.ts';
import type { Routed } from './time-requests-http.ts';

/** Child/device-group and device changes. Admin-only; every one needs a fresh step-up bound to the exact change. */
export type ChildAction = 'child_create' | 'child_remove' | 'device_add' | 'device_remove';
export const CHILD_ACTIONS: readonly ChildAction[] = ['child_create', 'child_remove', 'device_add', 'device_remove'];
const ID = /^[a-z][a-z0-9_]{0,31}$/;
const TOKEN = /^"s(?:0|[1-9][0-9]{0,9})-r(?:0|[1-9][0-9]{0,9})-[0-9a-f]{64}"$/;
const KINDS: readonly EntryKind[] = ['child', 'device_group'];
export interface ChildAdminDTO {
    id: string; name: string; kind: EntryKind;
    devices: {id: string; label: string; mac: string; state: DeviceRow['state']; onRouter: boolean | null}[];
}
export interface RejectionDTO { operationId: string; code: string; at: number; devices: {child: string; device: string}[]; otherDevices: number }

function label(value: unknown, code: string): string {
    if (typeof value !== 'string') throw new AppError(400, code);
    const trimmed = value.trim();
    if (trimmed.length < 1 || trimmed.length > 64 || /[\x00-\x1f\x7f]/.test(trimmed)) throw new AppError(400, code);
    return trimmed;
}
/** Accepts upper case and dash separators; the result is the router's canonical unicast form (multicast/zero refused). */
function macInput(value: unknown): string {
    if (typeof value !== 'string' || value.length > 17) throw new AppError(400, 'invalid_mac');
    return canonicalMac(value.trim().toLowerCase().replaceAll('-', ':'));
}
function precondition(value: unknown): string | null {
    if (value === null) return null;
    if (typeof value !== 'string' || !TOKEN.test(value)) throw new AppError(428, 'revision_precondition_required');
    return value;
}
function normalize(kind: ChildAction, target: unknown, params: unknown): {target: string; params: Record<string, unknown>} {
    if (typeof target !== 'string') throw new AppError(400, 'invalid_target');
    if (kind === 'child_create') {
        if (target !== '') throw new AppError(400, 'invalid_target');
        const body = object(params, ['name'], ['kind']), entry = body.kind ?? 'child';
        if (!KINDS.includes(entry as EntryKind)) throw new AppError(400, 'invalid_kind');
        return {target, params: {name: label(body.name, 'invalid_child_name'), kind: entry}};
    }
    if (!ID.test(target)) throw new AppError(404, kind === 'device_remove' ? 'device_not_found' : 'person_not_found');
    if (kind === 'child_remove') { object(params, []); return {target, params: {}}; }
    if (kind === 'device_remove') return {target, params: {precondition: precondition(object(params, ['precondition']).precondition)}};
    const body = object(params, ['label', 'mac', 'precondition']);
    return {target, params: {label: label(body.label, 'invalid_label'), mac: macInput(body.mac), precondition: precondition(body.precondition)}};
}
const bindingOf = (kind: ChildAction, target: string, params: Record<string, unknown>) => digest(JSON.stringify(['child_admin', kind, target, params]));
const id = (prefix: string) => `${prefix}_${randomBytes(5).toString('hex')}`;

export class ChildAdmin {
    readonly auth: Auth;
    readonly policy: IntegrationPolicy;
    constructor(auth: Auth, policy: IntegrationPolicy) { this.auth = auth; this.policy = policy; }
    private get store() { return this.policy.store; }
    private allowed(actor: Actor): void { if (actor.role !== 'admin') throw new AppError(403, 'admin_required'); }
    static isAction(value: unknown): value is ChildAction { return CHILD_ACTIONS.includes(value as ChildAction); }
    /** In-scope entries with their device identifiers (admins type them in), router membership and the last refusal. */
    list(actor: Actor): {children: ChildAdminDTO[]; canCreate: boolean; limits: {children: number; devicesPerChild: number; devices: number}; lastRejection: RejectionDTO | null} {
        this.allowed(actor);
        const o = this.policy.fresh() ? this.store.observation().value : null;
        const children = activeChildren(this.store).filter(child => actor.personIds.includes(child.id)).map(child => ({id: child.id, name: child.name, kind: child.kind,
            devices: devicesOf(this.store, child.id).map(d => ({id: d.id, label: d.label, mac: d.identifier, state: d.state,
                onRouter: o ? o.acceptedPolicy.people.some(p => p.id === child.id && p.macs.includes(d.identifier)) : null}))}));
        return {children, canCreate: this.scopeAll(actor.id), limits: {children: CHILD_LIMIT, devicesPerChild: DEVICES_PER_CHILD, devices: DEVICE_LIMIT}, lastRejection: this.rejection(actor)};
    }
    async stepUpOptions(session: AuthSession, input: unknown) {
        const body = object(input, ['action', 'target', 'params']);
        if (!ChildAdmin.isAction(body.action)) throw new AppError(400, 'invalid_action');
        this.allowed(session.dto.actor);
        const change = normalize(body.action, body.target, body.params);
        return this.auth.stepUpChallenge(session, bindingOf(body.action, change.target, change.params));
    }
    /** Verifies the step-up, then re-checks role, scope and installation identity and applies the change with its audit row in one transaction. */
    async perform(session: AuthSession, kind: ChildAction, target: string, input: unknown): Promise<Routed> {
        this.allowed(session.dto.actor);
        if (!input || typeof input !== 'object' || Array.isArray(input)) throw new AppError(400, 'invalid_object');
        const {stepUp, ...rest} = input as Record<string, unknown>;
        const change = normalize(kind, target, rest);
        const proof = await this.auth.stepUpVerify(session, stepUp, bindingOf(kind, change.target, change.params));
        const done = this.store.transaction(() => {
            const actor = this.auth.commitStepUp(session, proof);
            this.allowed(actor);
            this.store.assertIdentity();
            const result = this.apply(actor, kind, change.target, change.params);
            this.store.run('INSERT INTO audit(actor_id,operation_id,action,timestamp,outcome) VALUES(?,?,?,?,?)', actor.id, result.op?.id ?? null, `admin_${kind}`, this.policy.now(), result.audit);
            return result;
        });
        if (!done.op) return {status: 200, body: done.body};
        const queued = this.policy.result(done.op);
        return {status: queued.status, body: queued.result};
    }
    private scopeAll(account: string): boolean { return this.store.get<{scope_all: number}>('SELECT scope_all FROM accounts WHERE id=?', account)?.scope_all === 1; }
    private obligations(person: string): boolean {
        return Boolean(this.store.get("SELECT id FROM time_requests WHERE person_id=? AND (state IN ('pending','approving') OR repause_state IN ('waiting','applying')) LIMIT 1", person));
    }
    private apply(actor: Actor, kind: ChildAction, target: string, params: Record<string, unknown>): {body?: unknown; op?: IntegrationOperation; audit: string} {
        const now = this.policy.now(), config = this.store.config;
        if (kind === 'child_create') {
            if (!this.scopeAll(actor.id)) throw new AppError(403, 'scope_all_required', 'Only an admin who manages every child can add one.');
            if (activeChildren(this.store).length >= CHILD_LIMIT) throw new AppError(409, 'child_limit_reached', `The router holds at most ${CHILD_LIMIT} children and device groups.`);
            let child = id(params.kind === 'device_group' ? 'group' : 'child');
            while (this.store.get('SELECT id FROM people WHERE id=?', child)) child = id('child');
            this.store.run('INSERT INTO people(id,name,kind,active,created_at) VALUES(?,?,?,1,?)', child, params.name as string, params.kind as string, now);
            // scope_all accounts (and the creator) see the new entry at once; explicit scopes stay as they are.
            for (const row of this.store.all<{id: string; person_ids: string}>('SELECT id,person_ids FROM accounts WHERE scope_all=1 OR id=?', actor.id)) {
                const people = JSON.parse(row.person_ids) as string[];
                if (!people.includes(child)) this.store.run('UPDATE accounts SET person_ids=? WHERE id=?', JSON.stringify([...people, child]), row.id);
            }
            return {body: {child: {id: child, name: params.name, kind: params.kind, devices: []}}, audit: child};
        }
        if (kind === 'child_remove') {
            this.policy.authorized(actor, target);
            if (devicesOf(this.store, target).length) throw new AppError(409, 'child_has_devices', 'Remove every device first.');
            if (this.obligations(target)) throw new AppError(409, 'child_has_pending_requests', 'A time request for this child is still open.');
            this.store.run('UPDATE people SET active=0 WHERE id=?', target);
            this.store.run('UPDATE request_links SET revoked_at=?,revoked_by=? WHERE person_id=? AND revoked_at IS NULL', now, actor.id, target);
            return {body: {removed: target}, audit: target};
        }
        const request = (extra: Record<string, unknown>) => JSON.stringify({kind, target, ...extra, permissionVersion: actor.permissionVersion});
        if (kind === 'device_add') {
            this.policy.authorized(actor, target);
            const mac = params.mac as string;
            if (config.protectedMacs.includes(mac)) throw new AppError(409, 'device_mac_protected', 'This device is protected and can never be paused.');
            // Never says whose device it is: the owner may be outside this admin's scope.
            if (this.store.get("SELECT id FROM devices WHERE identifier_kind='mac' AND identifier=?", mac)) throw new AppError(409, 'device_already_enrolled', 'This device is already managed.');
            if (!routerScopeOf(config).includes(mac)) throw new AppError(409, 'device_outside_router_scope', 'The router installation does not allow this device. The router owner must reinstall it with this address in --rpc-allow and list it in the manifest routerScope.');
            if (devicesOf(this.store, target).length >= DEVICES_PER_CHILD) throw new AppError(409, 'child_device_limit_reached', `The router holds at most ${DEVICES_PER_CHILD} devices per entry.`);
            if (this.store.get<{n: number}>('SELECT count(*) n FROM devices')!.n >= DEVICE_LIMIT) throw new AppError(409, 'device_limit_reached', `The router holds at most ${DEVICE_LIMIT} devices.`);
            if (params.precondition === null) throw new AppError(428, 'revision_precondition_required');
            const device = id('d');
            const op = this.policy.queue(actor, target, 'enroll', request({label: params.label, mac}), id('enroll'), params.precondition as string,
                base => withDevice(base, config, target, mac),
                operation => this.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,operation_id,created_at) VALUES(?,?,?,'mac',?,'enrolling',?,?)", device, target, params.label as string, mac, operation, now));
            return {op, audit: device};
        }
        const row = this.store.get<DeviceRow>('SELECT * FROM devices WHERE id=?', target);
        if (!row || !actor.personIds.includes(row.person_id) || !this.store.get('SELECT id FROM people WHERE id=? AND active=1', row.person_id)) throw new AppError(404, 'device_not_found');
        if (row.state !== 'active') throw new AppError(409, 'device_change_in_progress');
        if (!this.policy.fresh()) throw new AppError(503, 'approved_router_observation_required');
        const o = this.store.observation().value!;
        if (!o.acceptedPolicy.people.some(p => p.id === row.person_id && p.macs.includes(row.identifier))) {
            // The router never held it (a refused or superseded enrollment): nothing to sync.
            this.store.run('DELETE FROM devices WHERE id=?', row.id);
            return {body: {removed: row.id, routerChange: false}, audit: `${row.id}:local`};
        }
        if (devicesOf(this.store, row.person_id).length === 1 && this.obligations(row.person_id)) throw new AppError(409, 'child_has_pending_requests', 'A time request for this child is still open.');
        if (params.precondition === null) throw new AppError(428, 'revision_precondition_required');
        const op = this.policy.queue(actor, row.person_id, 'unenroll', request({device: row.id}), id('unenroll'), params.precondition as string,
            base => withoutDevice(base, config, row.person_id, row.identifier),
            operation => this.store.run("UPDATE devices SET state='removing',operation_id=? WHERE id=?", operation, row.id));
        return {op, audit: row.id};
    }
    /**
     * The router refuses any sync while a managed device has no lease/neighbour entry, without naming it. Show the devices
     * the refused change needed (both policies), never device identifiers, and only labels inside this admin's scope.
     */
    private rejection(actor: Actor): RejectionDTO | null {
        const op = this.store.get<IntegrationOperation>('SELECT * FROM operations ORDER BY created_at DESC,rowid DESC LIMIT 1');
        if (!op || op.state !== 'failed' || !op.error || !ADDRESS_COVERAGE_REJECTIONS.has(op.error)) return null;
        const macs = [...new Set([op.base_json, op.payload_json].flatMap(json => (JSON.parse(json) as {people: {id: string; macs: string[]}[]}).people.flatMap(p => p.macs.map(m => `${p.id}\n${m}`))))].sort();
        const request = JSON.parse(op.request_json) as {mac?: string; label?: string; target?: string};
        const names = new Map(this.store.all<ChildRow>('SELECT * FROM people').map(c => [c.id, c.name]));
        const devices: RejectionDTO['devices'] = [];
        let otherDevices = 0;
        for (const entry of macs) {
            const [person, mac] = entry.split('\n');
            if (!actor.personIds.includes(person)) { otherDevices++; continue; }
            const row = this.store.get<DeviceRow>("SELECT * FROM devices WHERE identifier_kind='mac' AND identifier=?", mac);
            const device = row?.label ?? (request.mac === mac ? request.label : undefined);
            if (device) devices.push({child: names.get(person) ?? person, device}); else otherDevices++;
        }
        return {operationId: op.id, code: op.error, at: op.updated_at, devices, otherDevices};
    }
}

/** Session-checked read. Null when the path is not a child-admin route (or this is not an integration service). */
export function childrenGet(admin: ChildAdmin | null, session: AuthSession, path: string): Routed | null {
    return admin && path === '/admin/children' ? {status: 200, body: admin.list(session.dto.actor)} : null;
}
const CHILD = /^\/admin\/children\/([a-z][a-z0-9_]{0,31})\/(remove|devices)$/;
const DEVICE = /^\/admin\/devices\/([a-z][a-z0-9_]{0,31})\/remove$/;
/** Session- and CSRF-checked changes. `/step-up/options` is claimed only for this module's actions. */
export async function childrenPost(admin: ChildAdmin | null, session: AuthSession, path: string, payload: unknown): Promise<Routed | null> {
    if (!admin) return null;
    if (path === '/step-up/options') return ChildAdmin.isAction((payload as {action?: unknown} | null)?.action) ? {status: 200, body: await admin.stepUpOptions(session, payload)} : null;
    if (path === '/admin/children') return admin.perform(session, 'child_create', '', payload);
    const child = CHILD.exec(path);
    if (child) return admin.perform(session, child[2] === 'remove' ? 'child_remove' : 'device_add', child[1], payload);
    const device = DEVICE.exec(path);
    return device ? admin.perform(session, 'device_remove', device[1], payload) : null;
}
