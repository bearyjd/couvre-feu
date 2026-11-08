import type { Actor } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { digest } from './auth.ts';
import type { Auth, AuthSession } from './auth.ts';
import type { ContentFilterMode } from './content-filter-config.ts';
import type { ContentFilterReconciler } from './content-filter-reconcile.ts';
import { desiredSha256, isLoosening, parseDesired } from './content-filter-state.ts';
import type { ContentFilterDesired, ContentFilterStore, FilterRecord, FilterState } from './content-filter-state.ts';
import { auditFor } from './parent-audit.ts';
import type { Routed } from './time-requests-http.ts';

export const FILTER_PATH = /^\/people\/([a-z][a-z0-9_]{0,31})\/filter$/;
const PERSON = /^[a-z][a-z0-9_]{0,31}$/;
/** Stated on every answer: nothing here is enforced or measured on the router. */
export const FILTER_NOTE = 'unverified on this router';
export const PUTS_PER_MINUTE = 20;
export interface FilterDTO { revision: number; state: FilterState; stateAt: number; desired: ContentFilterDesired; note: typeof FILTER_NOTE }
export interface ContentFilterRoutesOptions {
    auth: Auth; filters: ContentFilterStore; reconciler: ContentFilterReconciler; mode: ContentFilterMode; ownerAccountId?: string;
    /** Throws AppError(404) unless the actor may manage this active child (the repo's person scoping). */
    authorize: (actor: Actor, person: string) => void;
}
/** The step-up commits to this child and this exact canonical filter. */
export const filterBinding = (person: string, sha256: string): string => digest(JSON.stringify(['content_filter_set', person, sha256]));
const unknownPerson = () => new AppError(404, 'person_not_found');
const toDTO = (record: FilterRecord): FilterDTO => ({revision: record.revision, state: record.state, stateAt: record.stateAt, desired: record.desired, note: FILTER_NOTE});

/**
 * GET/PUT /people/:id/filter and the step-up challenge for loosening. Off (or an actor the mode excludes) is a route that does not
 * exist; an unknown, out-of-scope or unmapped child is one identical 404. The audit row carries an action type only.
 */
export class ContentFilterRoutes {
    private readonly options: ContentFilterRoutesOptions;
    private readonly puts = new Map<string, number[]>();
    constructor(options: ContentFilterRoutesOptions) { this.options = options; }
    private visible(actor: Actor): boolean {
        const {mode, ownerAccountId} = this.options;
        return mode === 'parents' || (mode === 'owner' && ownerAccountId !== undefined && actor.id === ownerAccountId);
    }
    /** Mode first (no per-child information), then scope, then the profile map: all child failures look the same. */
    private scope(actor: Actor, person: string): void {
        if (!this.visible(actor)) throw new AppError(404, 'route_not_found');
        try { this.options.authorize(actor, person); } catch { throw unknownPerson(); }
        if (!this.options.reconciler.configured(person)) throw unknownPerson();
    }
    private limit(actorId: string): void {
        const now = this.options.auth.now(), recent = (this.puts.get(actorId) ?? []).filter(at => at > now - 60);
        if (recent.length >= PUTS_PER_MINUTE) throw new AppError(429, 'content_filter_rate_limited');
        this.puts.set(actorId, [...recent, now]);
    }
    get(session: AuthSession, path: string): Routed | null {
        const person = FILTER_PATH.exec(path)?.[1];
        if (person === undefined) return null;
        if (!this.visible(session.dto.actor)) return null;
        this.scope(session.dto.actor, person);
        const record = this.options.filters.get(person);
        if (!record) throw new AppError(404, 'filter_not_set');
        return {status: 200, body: toDTO(record)};
    }
    /** A challenge bound to {child, canonical filter}. Other step-up actions pass through (null). */
    async post(session: AuthSession, path: string, payload: unknown): Promise<Routed | null> {
        if (path !== '/step-up/options' || (payload as {action?: unknown} | null)?.action !== 'content_filter_set' || !this.visible(session.dto.actor)) return null;
        const body = object(payload, ['action', 'person', 'desired']);
        if (typeof body.person !== 'string' || !PERSON.test(body.person)) throw unknownPerson();
        this.scope(session.dto.actor, body.person);
        const sha = desiredSha256(parseDesired(body.desired));
        return {status: 200, body: await this.options.auth.stepUpChallenge(session, filterBinding(body.person, sha))};
    }
    async put(session: AuthSession, path: string, payload: unknown): Promise<Routed | null> {
        const person = FILTER_PATH.exec(path)?.[1], actor = session.dto.actor;
        if (person === undefined) return null;
        this.scope(actor, person);
        this.limit(actor.id);
        const body = object(payload, ['desired'], ['stepUp']), desired = parseDesired(body.desired), sha = desiredSha256(desired);
        const proof = isLoosening(this.options.filters.get(person)?.desired ?? null, desired)
            ? await this.options.auth.stepUpVerify(session, body.stepUp, filterBinding(person, sha)) : undefined;
        const loosened = this.commit(session, person, desired, proof);
        auditFor(this.options.auth.store).record({actor: actor.id, action: loosened ? 'content_filter_loosened' : 'content_filter_set', people: [person], result: 'applied', at: this.options.auth.now()});
        await this.options.reconciler.reconcile(person);
        return {status: 200, body: toDTO(this.options.filters.get(person)!)};
    }
    /** One transaction: loosening is judged again against the stored state, so a change that raced the proof check cannot slip through unproven. */
    private commit(session: AuthSession, person: string, desired: ContentFilterDesired, proof: Parameters<Auth['commitStepUp']>[1] | undefined): boolean {
        return this.options.auth.store.transaction(() => {
            const loosened = isLoosening(this.options.filters.get(person)?.desired ?? null, desired);
            if (loosened && proof === undefined) throw new AppError(403, 'step_up_required');
            if (proof !== undefined) this.options.auth.commitStepUp(session, proof);
            this.options.filters.put(person, desired, session.dto.actor.id);
            return loosened;
        });
    }
}
