import { randomBytes, randomUUID } from 'node:crypto';
import type { Actor, ChildBatchItem, ChildBatchItemResult, ChildBatchResult } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { healthyConfirmation } from '../../shared/src/router-schema.ts';
import { digest } from './auth.ts';
import type { Auth, AuthSession } from './auth.ts';
import type { Store } from './db.ts';
import { label, macInput } from './admin-children.ts';
import { CHILD_LIMIT, CLIENT_KEY, DEVICES_PER_CHILD, DEVICE_LIMIT, TOKEN, activeChildren, withDevices } from './integration-children.ts';
import type { IntegrationPolicy, IntegrationOperation } from './integration-policy.ts';
import { ScopeTracker } from './integration-scope.ts';
import { ParentAlerts } from './parent-alerts.ts';
import { auditFor } from './parent-audit.ts';
import type { Routed } from './time-requests-http.ts';

export const MAX_BATCH_ITEMS = 40;
export const BATCH_RETENTION_SECONDS = 90 * 86400;
/** Bounded maintenance; the setup marker survives expiry of replay responses. */
export function pruneBatches(store: Store, now = Math.floor(Date.now() / 1000)): number {
    return Number(store.run('DELETE FROM admin_batches WHERE id IN (SELECT id FROM admin_batches WHERE created_at<? ORDER BY created_at LIMIT 500)', now - BATCH_RETENTION_SECONDS).changes);
}
const ID = /^[a-z][a-z0-9_]{0,31}$/;
const REFERENCE = /^@(0|[1-9][0-9]?)$/;
const newId = (prefix: string) => `${prefix}_${randomBytes(6).toString('hex')}`;
const batchLabel = (input: unknown, code: string) => {
    if (typeof input !== 'string' || /[\p{Bidi_Control}\p{Default_Ignorable_Code_Point}]/u.test(input)) throw new AppError(400, code);
    return label(input.normalize('NFC'), code);
};
interface CanonicalBatch { clientKey: string; precondition: string | null; items: ChildBatchItem[]; binding: string }
interface StoredBatch { id: string; digest: string; result_json: string }
interface Addition { id: string; person: string; mac: string; label: string; index: number }
interface Touched { action: ChildBatchItem['action']; devices: number }

/** Canonical key order is shared by the review echo and the challenge commitment. */
function normalize(input: Record<string, unknown>, key: unknown): CanonicalBatch {
    if (typeof key !== 'string' || !CLIENT_KEY.test(key)) throw new AppError(400, 'idempotency_key_required');
    if (!Array.isArray(input.items) || input.items.length < 1) throw new AppError(400, 'invalid_batch_items');
    if (input.items.length > MAX_BATCH_ITEMS) throw new AppError(400, 'max_batch_items');
    if (input.precondition !== null && (typeof input.precondition !== 'string' || !TOKEN.test(input.precondition))) throw new AppError(428, 'revision_precondition_required');
    const items: ChildBatchItem[] = input.items.map(raw => {
        const item = object(raw, ['action', 'target', 'params', 'key']);
        if (item.action !== 'child_create' && item.action !== 'child_rename' && item.action !== 'device_add') throw new AppError(400, 'invalid_action');
        if (typeof item.key !== 'string' || !CLIENT_KEY.test(item.key)) throw new AppError(400, 'invalid_item_key');
        if (typeof item.target !== 'string') throw new AppError(400, 'invalid_target');
        if (item.action === 'child_create') {
            if (item.target !== '') throw new AppError(400, 'invalid_target');
            const params = object(item.params, ['name'], ['kind']), kind = params.kind ?? 'child';
            if (kind !== 'child' && kind !== 'device_group') throw new AppError(400, 'invalid_kind');
            return {action: item.action, target: '', params: {name: batchLabel(params.name, 'invalid_child_name'), kind}, key: item.key};
        }
        if (!ID.test(item.target) && !REFERENCE.test(item.target)) throw new AppError(400, 'invalid_batch_reference');
        if (item.action === 'child_rename') {
            const params = object(item.params, ['name']);
            return {action: item.action, target: item.target, params: {name: batchLabel(params.name, 'invalid_child_name')}, key: item.key};
        }
        if (item.action !== 'device_add') throw new AppError(400, 'invalid_action');
        const params = object(item.params, ['label', 'mac']);
        return {action: item.action, target: item.target, params: {label: batchLabel(params.label, 'invalid_label'), mac: macInput(params.mac)}, key: item.key};
    });
    const precondition = input.precondition as string | null;
    return {clientKey: key, precondition, items, binding: digest(JSON.stringify(['child_admin_batch', 1, key, precondition, items]))};
}

/** One short-lived proof commits one ordered setup list; every local mutation shares its savepoint. */
export class ChildBatchAdmin {
    readonly auth: Auth;
    readonly policy: IntegrationPolicy;
    readonly scope: ScopeTracker;
    private readonly attempts = new Map<string, {at: number}[]>();
    constructor(auth: Auth, policy: IntegrationPolicy) {
        this.auth = auth; this.policy = policy;
        this.scope = new ScopeTracker(policy.store, new ParentAlerts(policy.store, null, policy.now), policy.now);
    }
    private get store() { return this.policy.store; }
    private allowed(actor: Actor): void { if (actor.role !== 'admin') throw new AppError(403, 'admin_required'); }
    /** After setup, only admins with a fresh healthy observation proving no confirmed non-seed device can restart it. */
    private gate(actor: Actor): void {
        this.allowed(actor);
        if (!this.store.get<{setup_completed: number}>('SELECT setup_completed FROM admin_batch_setup WHERE singleton=1')?.setup_completed) return;
        const o = this.store.observation().value, seed = this.store.config.person;
        if (!this.policy.fresh() || !o || o.errors.length || o.generation !== this.store.config.router.generation || !healthyConfirmation(o.status, o.acceptedPolicy, o.routerTime)) throw new AppError(409, 'batch_setup_completed');
        // The accepted router policy is the authority: removing/moving rows still block restart until confirmed absent.
        const confirmed = o.acceptedPolicy.people.some(person => person.macs.some(mac => !(person.id === seed.id && mac === seed.device.mac)));
        if (confirmed) throw new AppError(409, 'batch_setup_completed');
    }
    /** Coverage is per complete inventory poll, unlike inventory last_seen (which tracks neighbour presence). */
    private ready(mac: string): boolean {
        if (!this.policy.fresh() || !this.scope.inRouterScope(mac, this.policy)) return false;
        const now = this.policy.now(), generation = this.store.config.router.generation;
        return Boolean(this.store.get(`SELECT 1 FROM inventory_coverage c JOIN inventory_devices d ON d.generation=c.generation AND d.mac=c.mac
            JOIN inventory_state s ON s.singleton=1 AND s.generation=c.generation
            WHERE c.generation=? AND c.mac=? AND c.observed_at BETWEEN ? AND ? AND s.last_ok_at BETWEEN ? AND ? AND json_array_length(d.ipv4_json)>0`,
            generation, mac, now - 30, now + 1, now - 30, now + 1));
    }
    async stepUpOptions(session: AuthSession, input: unknown) {
        const body = object(input, ['action', 'clientKey', 'precondition', 'items']);
        if (body.action !== 'child_batch') throw new AppError(400, 'invalid_action');
        const batch = normalize(body, body.clientKey), actor = session.dto.actor;
        this.allowed(actor);
        pruneBatches(this.store, this.policy.now());
        const prior = this.store.get<StoredBatch>('SELECT id,digest,result_json FROM admin_batches WHERE actor_id=? AND client_key=?', actor.id, batch.clientKey);
        // A confirmed first run must still let its owner prove a lost-response retry. It cannot mutate again.
        if (prior) {
            if (prior.digest !== batch.binding) throw new AppError(409, 'idempotency_payload_conflict');
        } else {
            this.gate(actor);
            this.validateItems(actor, batch);
        }
        const now = this.policy.now(), recent = (this.attempts.get(actor.id) ?? []).filter(entry => entry.at > now - 60);
        if (recent.length >= 3) throw new AppError(429, 'batch_rate_limited');
        // Reserve before the asynchronous authenticator-options call so concurrent requests cannot bypass the limit.
        const reservation = {at: now};
        this.attempts.set(actor.id, [...recent, reservation]);
        try {
            const challenge = await this.auth.stepUpChallenge(session, batch.binding, true);
            return {...challenge, bindingVersion: 1 as const, binding: batch.binding, items: batch.items};
        } catch (error) {
            this.attempts.set(actor.id, (this.attempts.get(actor.id) ?? []).filter(entry => entry !== reservation));
            throw error;
        }
    }
    /** Shape checks with no writes. Resolve actual references and repeat all authorization/readiness checks at execution. */
    private validateItems(actor: Actor, batch: CanonicalBatch): void {
        const keys = new Set<string>(), macs = new Set<string>();
        batch.items.forEach((item, index) => {
            if (keys.has(item.key)) throw new AppError(400, 'duplicate_item_key');
            keys.add(item.key);
            if (item.action === 'child_create') {
                if (!this.store.get<{scope_all: number}>('SELECT scope_all FROM accounts WHERE id=?', actor.id)?.scope_all) throw new AppError(403, 'scope_all_required');
            } else if (item.target.startsWith('@')) {
                const referenced = Number(item.target.slice(1));
                if (referenced >= index || batch.items[referenced]?.action !== 'child_create') throw new AppError(400, 'invalid_batch_reference');
            } else this.policy.authorized(actor, item.target);
            if (item.action !== 'device_add') return;
            if (macs.has(item.params.mac)) throw new AppError(409, 'device_already_enrolled');
            macs.add(item.params.mac);
            if (this.store.config.protectedMacs.includes(item.params.mac)) throw new AppError(409, 'device_mac_protected');
            if (!this.ready(item.params.mac)) throw new AppError(409, 'device_not_ready');
            if (batch.precondition === null) throw new AppError(428, 'revision_precondition_required');
        });
    }
    async perform(session: AuthSession, input: unknown, key?: string): Promise<Routed> {
        this.allowed(session.dto.actor);
        const body = object(input, ['precondition', 'items', 'stepUp']), batch = normalize(body, key);
        const proof = await this.auth.stepUpVerify(session, body.stepUp, batch.binding);
        return this.store.transaction(() => {
            const actor = this.auth.commitStepUp(session, proof);
            this.allowed(actor);
            const prior = this.store.get<StoredBatch>('SELECT id,digest,result_json FROM admin_batches WHERE actor_id=? AND client_key=?', actor.id, batch.clientKey);
            if (prior) {
                if (prior.digest !== batch.binding) return {status: 409, body: {error: {code: 'idempotency_payload_conflict'}}};
                return JSON.parse(prior.result_json) as Routed;
            }
            const id = newId('batch');
            let routed: Routed, operation: string | null = null, failedIndex: number | null = null;
            this.store.db.exec('SAVEPOINT child_batch_work');
            try {
                this.store.assertIdentity();
                this.gate(actor);
                const result = this.apply(actor, batch, index => { failedIndex = index; });
                operation = result.operation?.id ?? null;
                routed = {status: 200, body: {batchId: id, ...result}};
                this.store.db.exec('RELEASE child_batch_work');
            } catch (error) {
                this.store.db.exec('ROLLBACK TO child_batch_work');
                this.store.db.exec('RELEASE child_batch_work');
                if (!(error instanceof AppError)) throw error;
                routed = {status: error.status, body: {error: {code: error.code, ...(failedIndex === null ? {} : {failedIndex, key: batch.items[failedIndex].key})}}};
                this.store.run('INSERT INTO audit(actor_id,operation_id,action,timestamp,outcome) VALUES(?,NULL,?,?,?)', actor.id, `admin_${batch.items[0].action}`, this.policy.now(), `refused:${error.code}:${batch.items.length}`);
                if (batch.items.some(item => item.action === 'device_add')) auditFor(this.store).record({actor: actor.id, action: 'device_assign', people: [], result: 'refused', at: this.policy.now()});
                if (error.status >= 500 || ['revision_conflict', 'operation_in_progress', 'batch_setup_completed'].includes(error.code)) return routed;
            }
            this.store.run('INSERT INTO admin_batches(id,actor_id,client_key,digest,result_json,operation_id,created_at) VALUES(?,?,?,?,?,?,?)',
                id, actor.id, batch.clientKey, batch.binding, JSON.stringify(routed), operation, this.policy.now());
            return routed;
        });
    }
    private apply(actor: Actor, batch: CanonicalBatch, at: (index: number | null) => void): Omit<ChildBatchResult, 'batchId'> {
        const now = this.policy.now(), created = new Map<number, string>(), touched = new Map<string, Touched>();
        const keys = new Set<string>(), renamed = new Set<string>();
        const seen = new Set(this.store.all<{identifier: string}>("SELECT identifier FROM devices WHERE identifier_kind='mac'").map(d => d.identifier));
        const counts = new Map(this.store.all<{person_id: string; n: number}>('SELECT person_id,count(*) n FROM devices GROUP BY person_id').map(d => [d.person_id, d.n]));
        let childCount = activeChildren(this.store).length, deviceCount = this.store.get<{n: number}>('SELECT count(*) n FROM devices')!.n;
        const results: ChildBatchItemResult[] = [], additions: Addition[] = [];
        for (const [index, item] of batch.items.entries()) {
            at(index);
            if (keys.has(item.key)) throw new AppError(400, 'duplicate_item_key');
            keys.add(item.key);
            let person: string;
            if (item.action === 'child_create') {
                if (!this.store.get<{scope_all: number}>('SELECT scope_all FROM accounts WHERE id=?', actor.id)?.scope_all) throw new AppError(403, 'scope_all_required');
                if (++childCount > CHILD_LIMIT) throw new AppError(409, 'child_limit_reached');
                person = newId(item.params.kind === 'device_group' ? 'group' : 'child');
                this.store.run('INSERT INTO people(id,name,kind,active,created_at) VALUES(?,?,?,1,?)', person, item.params.name, item.params.kind, now);
                for (const row of this.store.all<{id: string; person_ids: string}>('SELECT id,person_ids FROM accounts WHERE scope_all=1 OR id=?', actor.id)) {
                    const ids = JSON.parse(row.person_ids) as string[];
                    if (!ids.includes(person)) this.store.run('UPDATE accounts SET person_ids=? WHERE id=?', JSON.stringify([...ids, person]), row.id);
                }
                created.set(index, person);
                touched.set(person, {action: 'child_create', devices: 0});
                results.push({key: item.key, index, status: 'saved', childId: person});
                continue;
            }
            if (item.target.startsWith('@')) {
                const referenced = Number(item.target.slice(1));
                if (referenced >= index || !created.has(referenced)) throw new AppError(400, 'invalid_batch_reference');
                person = created.get(referenced)!;
            } else { person = item.target; this.policy.authorized(actor, person); }
            if (!touched.has(person)) touched.set(person, {action: item.action, devices: 0});
            if (item.action === 'child_rename') {
                if (renamed.has(person)) throw new AppError(400, 'duplicate_child_setup');
                renamed.add(person);
                this.store.run('UPDATE people SET name=? WHERE id=? AND active=1', item.params.name, person);
                results.push({key: item.key, index, status: 'saved', childId: person});
                continue;
            }
            if (this.store.config.protectedMacs.includes(item.params.mac)) throw new AppError(409, 'device_mac_protected');
            if (seen.has(item.params.mac)) throw new AppError(409, 'device_already_enrolled');
            if ((counts.get(person) ?? 0) >= DEVICES_PER_CHILD) throw new AppError(409, 'child_device_limit_reached');
            if (deviceCount >= DEVICE_LIMIT) throw new AppError(409, 'device_limit_reached');
            if (batch.precondition === null) throw new AppError(428, 'revision_precondition_required');
            if (!this.ready(item.params.mac)) throw new AppError(409, 'device_not_ready');
            seen.add(item.params.mac); counts.set(person, (counts.get(person) ?? 0) + 1); deviceCount++;
            const device = newId('d');
            additions.push({id: device, person, mac: item.params.mac, label: item.params.label, index});
            touched.get(person)!.devices++;
            results.push({key: item.key, index, status: 'queued', childId: person, deviceId: device});
        }
        let op: IntegrationOperation | undefined;
        if (additions.length) {
            at(additions[0].index);
            const scoped = {...actor, personIds: [...new Set([...actor.personIds, ...created.values()])]};
            op = this.policy.queue(scoped, additions[0].person, 'enroll', JSON.stringify({kind: 'child_batch', devices: additions.map(d => ({person: d.person, mac: d.mac, label: d.label})), permissionVersion: actor.permissionVersion}), randomUUID(), batch.precondition,
                base => withDevices(base, this.store.config, additions), operation => {
                    for (const d of additions) this.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,operation_id,created_at) VALUES(?,?,?,'mac',?,'enrolling',?,?)", d.id, d.person, d.label, d.mac, operation, now);
                    at(null);
                    this.assertTotals(childCount, deviceCount, counts, seen);
                }, [...touched.keys()]);
        }
        at(null);
        this.assertTotals(childCount, deviceCount, counts, seen);
        for (const [person, change] of touched) {
            this.store.run('INSERT INTO audit(actor_id,operation_id,action,timestamp,outcome) VALUES(?,?,?,?,?)', actor.id, op?.id ?? null, `admin_${change.action}`, now, `child:${person}:devices:${change.devices}`);
            if (change.devices > 0 && auditFor(this.store).enabled) this.store.run("INSERT OR IGNORE INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,'device_assign',?,?,'applied')", now, actor.id, person, op?.id ?? null);
        }
        if (touched.size) this.store.run('INSERT INTO admin_batch_setup(singleton,setup_completed) VALUES(1,1) ON CONFLICT(singleton) DO UPDATE SET setup_completed=1');
        return {results, ...(op ? {operation: this.policy.result(op, {...actor, personIds: [...new Set([...actor.personIds, ...created.values()])]}).result.operation} : {})};
    }
    /** Reassert the accumulated limits against staged database rows immediately before committing. */
    private assertTotals(children: number, devices: number, counts: Map<string, number>, seen: ReadonlySet<string>): void {
        if (children > CHILD_LIMIT || activeChildren(this.store).length !== children) throw new AppError(409, 'child_limit_reached');
        if (devices > DEVICE_LIMIT || this.store.get<{n: number}>('SELECT count(*) n FROM devices')!.n !== devices) throw new AppError(409, 'device_limit_reached');
        for (const [person, count] of counts) if (count > DEVICES_PER_CHILD || this.store.get<{n: number}>('SELECT count(*) n FROM devices WHERE person_id=?', person)!.n !== count) throw new AppError(409, 'child_device_limit_reached');
        const macs = this.store.all<{identifier: string}>("SELECT identifier FROM devices WHERE identifier_kind='mac'").map(d => d.identifier);
        if (macs.length !== seen.size || new Set(macs).size !== macs.length || macs.some(mac => !seen.has(mac))) throw new AppError(409, 'device_already_enrolled');
    }
}
