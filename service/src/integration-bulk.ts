import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { integer, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { digest } from './auth.ts';
import type { Auth, AuthSession } from './auth.ts';
import { activeChildren, withDevice, withoutDevice } from './integration-children.ts';
import type { IntegrationManifest } from './integration-config.ts';
import type { IntegrationOperation, IntegrationPolicy } from './integration-policy.ts';
import type { Routed } from './time-requests-http.ts';

/** Block everything / lift everything for the children the actor manages: ONE rpc-sync, ONE receipt (design M5). */
export type BulkAction = 'pause_all' | 'resume_all';
export const BULK_ACTIONS: readonly BulkAction[] = ['pause_all', 'resume_all'];
type PolicyConfig = Pick<IntegrationManifest, 'protectedMacs' | 'enrollment'>;
const TOKEN = /^"s(?:0|[1-9][0-9]{0,9})-r(?:0|[1-9][0-9]{0,9})-[0-9a-f]{64}"$/;
const KEY = /^[A-Za-z0-9_-]{16,128}$/;

/**
 * The next policy for a bulk change, built from the router's accepted policy for EXACTLY the bound child ids. It never looks at
 * who else is on the router and never adds a child: an id the router does not hold refuses the whole change. Blocking also clears
 * those children's time allowances (an allowance overrides a pause, core.sh cf_enforced_policy), so "block all" really blocks.
 */
export function bulkPolicy(base: RouterPolicy, config: PolicyConfig, action: BulkAction, ids: readonly string[], until: number | null): RouterPolicy {
    if (ids.length === 0) throw new AppError(409, 'no_enrolled_children');
    if (ids.some(id => !base.people.some(p => p.id === id))) throw new AppError(409, 'bulk_children_changed');
    const bound = new Set(ids), rest = base.pauses.filter(p => !bound.has(p.person));
    const pauses = action === 'pause_all' ? [...rest, ...ids.map(person => ({person, until: until!}))] : rest;
    const allowances = action === 'pause_all' && base.allowances ? {allowances: base.allowances.filter(a => !bound.has(a.person))} : {};
    return normalizePolicy({...base, revision: base.revision + 1, pauses, ...allowances}, config.protectedMacs);
}
/** withoutDevice(A) then withDevice(B), as ONE revision: the router sees a single step, so there is never a state with the device nowhere. */
export function movePolicy(base: RouterPolicy, config: PolicyConfig, from: string, to: string, mac: string): RouterPolicy {
    if (from === to) throw new AppError(409, 'device_move_same_child');
    if (!base.people.some(p => p.id === from && p.macs.includes(mac))) throw new AppError(409, 'device_not_on_router');
    const next = withDevice(withoutDevice(base, config, from, mac), config, to, mac);
    return normalizePolicy({...next, revision: base.revision + 1}, config.protectedMacs);
}

export class BulkOps {
    readonly auth: Auth;
    readonly policy: IntegrationPolicy;
    constructor(auth: Auth, policy: IntegrationPolicy) { this.auth = auth; this.policy = policy; }
    static isAction(value: unknown): value is BulkAction { return BULK_ACTIONS.includes(value as BulkAction); }
    private get store() { return this.policy.store; }
    /**
     * The children this actor manages that the router holds right now, sorted. This list is what the step-up is bound to and what
     * the policy is built from; it is computed from the actor, never from the router, so a larger router can never enlarge it.
     */
    affected(actor: Actor): string[] {
        const o = this.store.observation().value;
        if (!this.policy.fresh() || !o) throw new AppError(503, 'approved_router_observation_required');
        const onRouter = new Set(o.acceptedPolicy.people.map(p => p.id));
        const ids = activeChildren(this.store).map(c => c.id).filter(id => actor.personIds.includes(id) && onRouter.has(id)).sort();
        if (ids.length === 0) throw new AppError(409, 'no_enrolled_children');
        return ids;
    }
    private fields(action: BulkAction, params: unknown): {until: number | null; precondition: string} {
        const body = object(params, action === 'pause_all' ? ['until', 'precondition'] : ['precondition']);
        const until = action === 'pause_all' ? integer(body.until) : null;
        if (typeof body.precondition !== 'string' || !TOKEN.test(body.precondition)) throw new AppError(428, 'revision_precondition_required');
        if (until !== null && until !== 0 && until <= this.policy.now()) throw new AppError(400, 'pause_expiry_must_be_future');
        return {until, precondition: body.precondition};
    }
    private binding(action: BulkAction, ids: readonly string[], until: number | null, precondition: string): string {
        return digest(JSON.stringify(['bulk', action, ids, until, precondition]));
    }
    async stepUpOptions(session: AuthSession, input: unknown) {
        const body = object(input, ['action', 'params']);
        if (!BulkOps.isAction(body.action)) throw new AppError(400, 'invalid_action');
        const {until, precondition} = this.fields(body.action, body.params);
        return this.auth.stepUpChallenge(session, this.binding(body.action, this.affected(session.dto.actor), until, precondition));
    }
    /** Verifies the step-up for the exact child list, then re-derives that list inside the write transaction and refuses any difference. */
    async perform(session: AuthSession, action: BulkAction, key: string | undefined, input: unknown): Promise<Routed> {
        if (!key || !KEY.test(key)) throw new AppError(400, 'idempotency_key_required');
        if (!input || typeof input !== 'object' || Array.isArray(input)) throw new AppError(400, 'invalid_object');
        const {stepUp, ...rest} = input as Record<string, unknown>;
        const {until, precondition} = this.fields(action, rest);
        const ids = this.affected(session.dto.actor);
        const proof = await this.auth.stepUpVerify(session, stepUp, this.binding(action, ids, until, precondition));
        const op = this.store.transaction(() => {
            const actor = this.auth.commitStepUp(session, proof);
            this.store.assertIdentity();
            // Authorization is re-derived per child right now; the bound list must still be exactly it.
            if (JSON.stringify(this.affected(actor)) !== JSON.stringify(ids)) throw new AppError(409, 'bulk_children_changed');
            const request = JSON.stringify({action, ids, until, precondition, permissionVersion: actor.permissionVersion});
            const prior = this.store.get<IntegrationOperation>('SELECT * FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key);
            if (prior) { if (prior.request_json !== request) throw new AppError(409, 'idempotency_payload_conflict'); return prior; }
            return this.policy.queue(actor, ids[0], action, request, key, precondition, base => bulkPolicy(base, this.store.config, action, ids, until), undefined, ids);
        });
        const result = this.policy.result(op, session.dto.actor);
        return {status: result.status, body: result.result};
    }
}

/** `/bulk/pause-all` and `/bulk/resume-all` (session and CSRF are checked by the caller) plus the bulk step-up options. */
export async function bulkPost(bulk: BulkOps | null, session: AuthSession, path: string, payload: unknown, key: string | undefined): Promise<Routed | null> {
    if (!bulk) return null;
    if (path === '/step-up/options') return BulkOps.isAction((payload as {action?: unknown} | null)?.action) ? {status: 200, body: await bulk.stepUpOptions(session, payload)} : null;
    if (path === '/bulk/pause-all') return bulk.perform(session, 'pause_all', key, payload);
    if (path === '/bulk/resume-all') return bulk.perform(session, 'resume_all', key, payload);
    return null;
}
