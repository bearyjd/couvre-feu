import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { integer, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { digest } from './auth.ts';
import type { Auth, AuthSession } from './auth.ts';
import { CLIENT_KEY, TOKEN, activeChildren } from './integration-children.ts';
import type { IntegrationManifest } from './integration-config.ts';
import type { IntegrationOperation, IntegrationPolicy } from './integration-policy.ts';
import type { Routed } from './time-requests-http.ts';
import { audited } from './parent-audit.ts';

/** Block everything / lift everything for the children the actor manages: ONE rpc-sync, ONE receipt (design M5). */
export type BulkAction = 'pause_all' | 'resume_all';
export const BULK_ACTIONS: readonly BulkAction[] = ['pause_all', 'resume_all'];
type PolicyConfig = Pick<IntegrationManifest, 'protectedMacs' | 'enrollment'>;

/**
 * The next policy for a bulk change, built from the router's accepted policy for EXACTLY the bound child ids. It never looks at
 * who else is on the router and never adds a child: an id the router does not hold refuses the whole change. Blocking also clears
 * those children's time allowances (an allowance overrides a pause, core.sh cf_enforced_policy), so "block all" really blocks.
 */
export function bulkPolicy(base: RouterPolicy, config: PolicyConfig, action: BulkAction, ids: readonly string[], until: number | null): RouterPolicy {
    if (ids.length === 0) throw new AppError(409, 'no_enrolled_children');
    if (ids.some(id => !base.people.some(p => p.id === id))) throw new AppError(409, 'bulk_children_changed');
    const bound = new Set(ids), rest = base.pauses.filter(p => !bound.has(p.person));
    const next = (pauses: RouterPolicy['pauses'], extra: Partial<RouterPolicy> = {}) => normalizePolicy({...base, revision: base.revision + 1, pauses, ...extra}, config.protectedMacs);
    if (action === 'resume_all') return next(rest);
    if (until === null) throw new AppError(400, 'pause_expiry_required');
    // "Block all" never SHORTENS a pause a child already has: indefinite (0) wins, otherwise the later expiry.
    const strongest = (existing: number | undefined) => existing === undefined ? until : existing === 0 || until === 0 ? 0 : Math.max(existing, until);
    const pauses = [...rest, ...ids.map(person => ({person, until: strongest(base.pauses.find(p => p.person === person)?.until)}))];
    return next(pauses, base.allowances ? {allowances: base.allowances.filter(a => !bound.has(a.person))} : {});
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
    private fields(action: BulkAction, params: unknown): {action: 'pause_all'; until: number; precondition: string} | {action: 'resume_all'; until: null; precondition: string} {
        const body = object(params, action === 'pause_all' ? ['until', 'precondition'] : ['precondition']);
        const until = action === 'pause_all' ? integer(body.until) : null;
        if (typeof body.precondition !== 'string' || !TOKEN.test(body.precondition)) throw new AppError(428, 'revision_precondition_required');
        if (until !== null && until !== 0 && until <= this.policy.now()) throw new AppError(400, 'pause_expiry_must_be_future');
        return until === null ? {action: 'resume_all', until, precondition: body.precondition} : {action: 'pause_all', until, precondition: body.precondition};
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
        let known: readonly string[] = [];
        return audited(this.store, {actor: session.dto.actor.id, action, now: this.policy.now, people: () => known,
            done: r => ({operationId: (r.body as {operation: {id: string}}).operation.id})}, () => this.performBound(session, action, key, input, ids => { known = ids; }));
    }
    private async performBound(session: AuthSession, action: BulkAction, key: string | undefined, input: unknown, bound: (ids: string[]) => void): Promise<Routed> {
        if (!key || !CLIENT_KEY.test(key)) throw new AppError(400, 'idempotency_key_required');
        if (!input || typeof input !== 'object' || Array.isArray(input)) throw new AppError(400, 'invalid_object');
        const {stepUp, ...rest} = input as Record<string, unknown>;
        const {until, precondition} = this.fields(action, rest);
        const ids = this.affected(session.dto.actor);
        bound(ids);
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
