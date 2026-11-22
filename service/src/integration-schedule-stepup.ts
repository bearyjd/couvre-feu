import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { parseScheduleChange } from '../../shared/src/schedule-edit.ts';
import type { ScheduleAction } from '../../shared/src/schedule-edit.ts';
import type { Schedule } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { digest } from './auth.ts';
import type { Auth, AuthSession } from './auth.ts';
import { CLIENT_KEY, TOKEN } from './integration-children.ts';
import type { IntegrationPolicy } from './integration-policy.ts';
import { fold } from './integration-schedule-mutate.ts';
import { scheduleWindows } from './integration-schedule-store.ts';
import { isLoosening, windowSetDigest } from './schedule-loosening.ts';
import type { Routed } from './time-requests-http.ts';

/**
 * Passkey step-up before a loosening or deleting schedule edit is queued (roadmap item 2, S2b; flag schedules.editable, off; unverified on
 * this router). Tightening needs none. Settlement, admission and the fence are not touched: this runs before queue() and writes nothing
 * until the in-transaction gate in scheduleMutate has re-judged the change and spent the passkey use. Fixed codes only.
 */
export const SCHEDULE_STEP_UP_ACTION = 'schedule_change';
const SCHEDULE_ACTIONS: readonly string[] = ['schedule_create', 'schedule_update', 'schedule_delete'];
const PERSON = /^[a-z][a-z0-9_]{0,31}$/;

/** What a step-up is bound to: the child, the exact resulting window set, and the revision token the change is made against. */
export const scheduleBinding = (person: string, windows: readonly Schedule[], precondition: string): string =>
    digest(JSON.stringify(['schedule', person, windowSetDigest(windows), precondition]));

interface Judged { windows: Schedule[]; loosening: boolean }

export class ScheduleStepUp {
    readonly auth: Auth;
    readonly policy: IntegrationPolicy;
    constructor(auth: Auth, policy: IntegrationPolicy) { this.auth = auth; this.policy = policy; }

    /** The committed set and the folded set for one change, or null when it cannot be folded (the normal path then refuses it, in its own order). */
    private judge(person: string, action: ScheduleAction, input: unknown, scheduleId: string | undefined): Judged | null {
        try {
            const committed = scheduleWindows(this.policy.store).filter(w => w.person === person);
            const windows = fold(committed, person, parseScheduleChange(action, input, scheduleId));
            return {windows, loosening: isLoosening(committed, windows)};
        } catch { return null; }
    }
    private flagged() {
        const mutate = this.policy.scheduleMutate;
        if (!mutate) throw new AppError(403, 'schedule_editing_unavailable', 'Schedules are owner-configured in this installation.');
        return mutate;
    }
    /** A challenge bound to {child, window-set digest, precondition}. Only for a loosening or deleting change. */
    async options(session: AuthSession, input: unknown): Promise<unknown> {
        this.flagged();
        const body = object(input, ['action', 'person', 'scheduleAction', 'precondition', 'change'], ['scheduleId']);
        if (typeof body.person !== 'string' || !PERSON.test(body.person)) throw new AppError(404, 'person_not_found');
        if (typeof body.scheduleAction !== 'string' || !SCHEDULE_ACTIONS.includes(body.scheduleAction)) throw new AppError(400, 'invalid_action');
        if (typeof body.precondition !== 'string' || !TOKEN.test(body.precondition)) throw new AppError(428, 'revision_precondition_required');
        if (body.scheduleId !== undefined && typeof body.scheduleId !== 'string') throw new AppError(400, 'invalid_action');
        this.policy.authorized(session.dto.actor, body.person);
        const action = body.scheduleAction as ScheduleAction, id = body.scheduleId as string | undefined;
        const committed = scheduleWindows(this.policy.store).filter(w => w.person === body.person);
        // An unfoldable change throws its own refusal (duplicate id, unknown id, bad body); no challenge is minted for it.
        const windows = fold(committed, body.person, parseScheduleChange(action, body.change, id));
        if (!isLoosening(committed, windows)) throw new AppError(409, 'step_up_not_required');
        return this.auth.stepUpChallenge(session, scheduleBinding(body.person, windows, body.precondition));
    }
    /**
     * The route's entry. A stepUp field is stripped from the body. A replay whose operation already exists needs no second step-up (and spends
     * none); a loosening without a valid one is refused before anything is written.
     */
    async mutate(session: AuthSession, person: string, action: ScheduleAction, input: unknown, scheduleId: string | undefined, precondition: string | undefined, key: string | undefined) {
        const mutate = this.flagged(), actor: Actor = session.dto.actor;
        const {rest, stepUp} = split(input);
        const judged = this.judge(person, action, rest, scheduleId);
        const replay = key !== undefined && CLIENT_KEY.test(key) && this.policy.store.get('SELECT 1 FROM operations WHERE actor_id=? AND idempotency_key=?', actor.id, key) !== undefined;
        let verified: {digest: string; commit: () => void} | null = null;
        if (judged?.loosening && !replay) {
            this.policy.authorized(actor, person);
            if (!precondition || !TOKEN.test(precondition)) throw new AppError(428, 'revision_precondition_required');
            const proof = await this.auth.stepUpVerify(session, stepUp, scheduleBinding(person, judged.windows, precondition));
            verified = {digest: windowSetDigest(judged.windows), commit: () => { this.auth.commitStepUp(session, proof); }};
        }
        return mutate(actor, person, action, rest, scheduleId, precondition, key, {verified});
    }
}
function split(input: unknown): {rest: unknown; stepUp: unknown} {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return {rest: input, stepUp: undefined};
    const {stepUp, ...rest} = input as Record<string, unknown>;
    return {rest, stepUp};
}

/** POST /step-up/options for action schedule_change. Null for any other action and with the flag off, so those keep their existing answers. */
export async function scheduleStepUpPost(stepUp: ScheduleStepUp | null, session: AuthSession, path: string, payload: unknown): Promise<Routed | null> {
    if (!stepUp || path !== '/step-up/options' || (payload as {action?: unknown} | null)?.action !== SCHEDULE_STEP_UP_ACTION || !stepUp.policy.scheduleMutate) return null;
    return {status: 200, body: await stepUp.options(session, payload)};
}
