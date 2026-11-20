import type { Actor } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import type { TimeRequestService } from './time-requests.ts';

export interface Routed {status: number; body: unknown}
const LINK = /^\/people\/([a-z][a-z0-9_]{0,31})\/request-link(\/revoke)?$/;
const DECISION = /^\/time-requests\/([0-9a-f-]{36})\/(approve|decline)$/;

/** Unauthenticated capability routes. The token travels in the POST body only, never in a URL, header or cookie. */
export function childRoute(service: TimeRequestService, path: string, payload: unknown, client?: string): Routed {
    // `client` (the TCP source address) only selects a bad-token rate-limit bucket; it is never stored or logged.
    if (path === '/child/status') return {status: 200, body: service.status(object(payload, ['token']).token, client)};
    if (path === '/child/request') {
        const body = object(payload, ['token', 'minutes'], ['reason']);
        return {status: 200, body: service.submit(body.token, body.minutes, body.reason, client)};
    }
    throw new AppError(404, 'route_not_found');
}

/** Session- and CSRF-checked parent mutations; the caller has already authenticated `actor`. */
export async function parentPost(service: TimeRequestService, actor: Actor, path: string, payload: unknown): Promise<Routed | null> {
    const link = LINK.exec(path);
    if (link) {
        object(payload, []);
        return {status: 200, body: link[2] ? service.revokeLink(actor, link[1]) : await service.issueLink(actor, link[1])};
    }
    const decision = DECISION.exec(path);
    if (!decision) return null;
    if (decision[2] === 'decline') {
        object(payload, []);
        return {status: 200, body: {request: service.decline(actor, decision[1])}};
    }
    return {status: 200, body: {request: await service.approve(actor, decision[1], object(payload, ['minutes']).minutes)}};
}

export async function parentGet(service: TimeRequestService, actor: Actor, path: string): Promise<Routed | null> {
    if (path !== '/time-requests') return null;
    // Read-only: follow-ups (including any re-pause) run on the server timer, never as a side effect of a GET.
    return {status: 200, body: service.overview(actor)};
}
