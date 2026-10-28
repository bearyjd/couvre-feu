import { ChildAdmin, childrenGet, childrenPost } from './admin-children.ts';
import { BulkOps, bulkPost } from './integration-bulk.ts';
import { IntegrationPolicy } from './integration-policy.ts';
import { IntegrationGrants } from './integration-allowance.ts';
import { createServer } from 'node:http';
import { createServer as createSecureServer } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Auth } from './auth.ts';
import type { PolicyService } from './policy.ts';
import type { DemoConfig } from './config.ts';
import type { ActivityStore } from './activity-store.ts';
import { provenance } from '../../shared/src/contracts.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { timeRequestMode } from './integration-config.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object, parseJSON } from '../../shared/src/json.ts';
import type { ParentAlerts } from './parent-alerts.ts';
import { TimeRequestService } from './time-requests.ts';
import { childRoute, parentGet, parentPost } from './time-requests-http.ts';
import { AccountAdmin } from './admin-accounts.ts';
import { accountGet, accountPost } from './admin-accounts-http.ts';
import { inventoryGet, inventoryPost } from './inventory-http.ts';
import type { InventoryStore } from './inventory-store.ts';
import { auditFor } from './parent-audit.ts';
const STATIC: Record<string, [
    string,
    string
]> = {
    '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
    '/auth-client.js': ['auth-client.js', 'text/javascript; charset=utf-8'], '/status-cache.js': ['status-cache.js', 'text/javascript; charset=utf-8'],
    '/operational-alerts.js': ['operational-alerts.js', 'text/javascript; charset=utf-8'],
    '/schedule-editor.js': ['schedule-editor.js', 'text/javascript; charset=utf-8'], '/schedule-editor.css': ['schedule-editor.css', 'text/css; charset=utf-8'],
    '/parent-alerts.js': ['parent-alerts.js', 'text/javascript; charset=utf-8'], '/activity.js': ['activity.js', 'text/javascript; charset=utf-8'],
    '/time-requests.js': ['time-requests.js', 'text/javascript; charset=utf-8'], '/reward-time.js': ['reward-time.js', 'text/javascript; charset=utf-8'], '/accounts.js': ['accounts.js', 'text/javascript; charset=utf-8'], '/children.js': ['children.js', 'text/javascript; charset=utf-8'], '/request.html': ['request.html', 'text/html; charset=utf-8'], '/request.js': ['request.js', 'text/javascript; charset=utf-8'],
    '/styles.css': ['styles.css', 'text/css; charset=utf-8'], '/sw.js': ['sw.js', 'text/javascript; charset=utf-8'],
    '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json'], '/icon.svg': ['icon.svg', 'image/svg+xml'],
};
function cookies(request: IncomingMessage): Record<string, string> {
    const result: Record<string, string> = Object.create(null);
    for (const item of (request.headers.cookie ?? '').split(';')) {
        const equal = item.indexOf('=');
        if (equal < 0) {
            continue;
        }
        const name = item.slice(0, equal).trim(), value = item.slice(equal + 1).trim();
        if (Object.hasOwn(result, name)) {
            throw new AppError(400, 'duplicate_cookie');
        }
        result[name] = value;
    }
    return result;
}
async function body(request: IncomingMessage): Promise<unknown> {
    if (Number(request.headers['content-length'] ?? 0) > 65536) {
        request.resume();
        throw new AppError(413, 'body_too_large');
    }
    if (request.headers['content-type'] !== 'application/json') {
        throw new AppError(415, 'json_required');
    }
    if (request.headers['content-encoding']) {
        throw new AppError(415, 'content_encoding_rejected');
    }
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of request) {
        length += chunk.length;
        if (length > 65536) {
            throw new AppError(413, 'body_too_large');
        }
        chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks).toString('utf8');
    if (raw.includes('\uFFFD')) {
        throw new AppError(400, 'invalid_utf8');
    }
    return parseJSON(raw);
}
function send(response: ServerResponse, status: number, value: unknown) {
    response.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8'
    });
    response.end(JSON.stringify(value));
}
type PolicyAPI = Pick<PolicyService, 'people' | 'devices' | 'mutate' | 'operation' | 'reconcile'> & Partial<Pick<PolicyService, 'scheduleMutate'>>;
type AlertsAPI = Pick<ParentAlerts, 'list' | 'acknowledge'> & Partial<Pick<ParentAlerts, 'reconcile'>>;
/** Node reports IPv4 peers on dual-stack sockets as ::ffff:a.b.c.d; compare the plain IPv4 literal. */
export function remoteIPv4(address: string | undefined): string | undefined {
    return address?.startsWith('::ffff:') ? address.slice(7) : address;
}
/** The Idempotency-Key header, dropped when it uses the `tr-` prefix reserved for the time-request service (the route then reports the key as missing). */
const clientKey = (value: string | string[] | undefined): string | undefined => typeof value === 'string' && !value.startsWith('tr-') ? value : undefined;
const alertId = (text: string) => { const id = Number(text); if (!/^[1-9][0-9]{0,15}$/.test(text) || !Number.isSafeInteger(id)) throw new AppError(404, 'alert_not_found'); return id; };
export function appServer(auth: Auth, policy: PolicyAPI, config: DemoConfig, alerts?: AlertsAPI, activity?: ActivityStore, timeRequests?: TimeRequestService, inventory?: InventoryStore) {
    // Demo: always on. Real-router integration: per the private manifest's timeRequests mode (default off); child routes and the timer run in any mode but off.
    const gated = timeRequests === undefined && auth.provenance.source === 'real-router-integration';
    const mode = timeRequestMode((config as {timeRequests?: unknown}).timeRequests), ownerAccountId = (config as {ownerAccountId?: string}).ownerAccountId;
    const timeRequestsEnabled = !gated || mode !== 'off';
    // Who may see and decide requests (parent routes) and read their alert: everyone unless the manifest narrows it to the owner account.
    const mayDecide = (actor: Actor) => !gated || mode === 'parents' || (mode === 'owner' && actor.id === ownerAccountId);
    const hiddenAlerts = (actor: Actor): readonly string[] => mayDecide(actor) ? [] : ['time_request_pending'];
    const clock = (policy as {now?: () => number}).now ?? auth.now;
    // Real router: approvals are router-side allowances (grants), confirmed only from router observations.
    const grants = policy instanceof IntegrationPolicy ? new IntegrationGrants(policy) : undefined;
    // Reward time: off (the manifest default), time requests off, or a parent the owner-mode gate excludes is a route that does not exist.
    const rewardOn = (actor: Actor) => Boolean(grants && timeRequestsEnabled && mayDecide(actor) && grants.policy.store.config.rewardTime?.enabled === true);
    const requests = !timeRequestsEnabled ? null : timeRequests ?? new TimeRequestService(auth.store, policy, clock, undefined, grants);
    // Switched off after approvals were made: no routes, but owed restores of lifted pauses still drain (fail-closed).
    const drain = requests ? null : new TimeRequestService(auth.store, policy, clock, undefined, grants);
    // The demo feeds its alerts from main.ts; on the real path only the time-request rule is reconciled here, nothing else.
    const reconcileAlerts = alerts?.reconcile?.bind(alerts);
    const pendingAlerts = requests && grants && reconcileAlerts ? () => reconcileAlerts({now: clock(), timeRequests: requests.pendingForAlerts()}) : null;
    const provenance = auth.provenance;
    const accounts = new AccountAdmin(auth, gated && mode === 'owner' ? ownerAccountId : undefined);
    // Children/device groups and their devices are database-managed only against a real router integration.
    const children = policy instanceof IntegrationPolicy ? new ChildAdmin(auth, policy) : null;
    const bulk = policy instanceof IntegrationPolicy ? new BulkOps(auth, policy) : null;
    // Audit log of parent actions: real-router integration only, and only when the manifest turns it on (read per request).
    const audit = policy instanceof IntegrationPolicy ? auditFor(policy.store) : null;
    const automatic = (config as DemoConfig & {dispatch?: {enabled: boolean}}).dispatch?.enabled === true;
    const secure = config.origin.startsWith('https:') ? '; Secure' : '';
    // Plain-HTTP LAN proxy mode: X-Forwarded-* and Forwarded are never read; only the TCP source address is trusted.
    const trusted = config.trustedProxies;
    const untrusted = (address: string | undefined) => trusted !== undefined && !trusted.includes(remoteIPv4(address) ?? '');
    const handler = async (request: IncomingMessage, response: ServerResponse) => {
        if (untrusted(request.socket.remoteAddress)) {
            request.socket.destroy();
            return;
        }
        response.setHeader('Cache-Control', 'no-store');
        // Browsers honour HSTS only over HTTPS, i.e. the TLS listener or the TLS-terminating proxy in front of this one.
        if (secure) response.setHeader('Strict-Transport-Security', 'max-age=31536000');
        response.setHeader('X-Content-Type-Options', 'nosniff');
        response.setHeader('Referrer-Policy', 'no-referrer');
        response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
        try {
            if (request.headers.host !== config.host) {
                throw new AppError(403, 'host_rejected');
            }
            if (request.headers.origin && request.headers.origin !== config.origin) {
                throw new AppError(403, 'origin_rejected');
            }
            if (request.headers['sec-fetch-site'] === 'cross-site') {
                throw new AppError(403, 'cross_site_rejected');
            }
            if (request.headers['x-cf-actor'] || request.headers['x-user-id'] || request.headers['x-role'] || request.headers['x-test-identity'] || request.headers['x-forwarded-user']) {
                throw new AppError(400, 'identity_headers_rejected');
            }
            const path = request.url ?? '';
            if (path.includes('?') || path.includes('%') || path.includes('#')) {
                throw new AppError(400, 'invalid_path');
            }
            if (!requests && ['/request.html', '/request.js'].includes(path)) {
                throw new AppError(404, 'route_not_found');
            }
            if (request.method === 'GET' && STATIC[path]) {
                const [name, type] = STATIC[path];
                let data = readFileSync(fileURLToPath(new URL(`../../web/public/${name}`, import.meta.url)));
                if (name === 'index.html' && provenance.source === 'real-router-integration') {
                    data = Buffer.from(integrationHTML(data.toString('utf8'), provenance.integrationScope!, automatic));
                }
                if (name === 'sw.js' && provenance.source === 'real-router-integration') data = Buffer.from(data.toString('utf8').replace("'cf-shell-v4'", `'cf-shell-integration-${provenance.integrationScope}-v3'`));
                if (name === 'manifest.webmanifest' && provenance.source === 'real-router-integration') data = Buffer.from(data.toString('utf8').replace('Couvre-feu synthetic demo', 'Couvre-feu private integration').replace('Local fictional parent-control prototype. Fake router only.', automatic ? 'Private router integration with owner-enabled dispatch.' : 'Private one-device router pilot. Operator-approved dispatch only.'));
                response.setHeader('Content-Type', type);
                response.end(data);
                return;
            }
            const jar = cookies(request), sessionToken = jar.cf_session;
            if (request.method === 'POST') {
                if (request.headers.origin !== config.origin) {
                    throw new AppError(403, 'origin_rejected');
                }
                const payload = await body(request);
                if (path.startsWith('/child/')) {
                    if (!requests) {
                        throw new AppError(404, 'route_not_found');
                    }
                    // Capability token in the body is the only credential: no cookies, no ambient authority, so no CSRF surface.
                    const routed = childRoute(requests, path, payload, remoteIPv4(request.socket.remoteAddress));
                    send(response, routed.status, routed.body);
                    return;
                }
                if (path.startsWith('/auth/') && path !== '/auth/logout') {
                    const browserToken = /^[A-Za-z0-9_-]{43}$/.test(jar.cf_browser ?? '') ? jar.cf_browser : randomBytes(32).toString('base64url');
                    response.setHeader('Set-Cookie', `cf_browser=${browserToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600${secure}`);
                    if (path === '/auth/register/options') {
                        send(response, 200, await auth.registrationOptions(payload, browserToken));
                        return;
                    }
                    if (path === '/auth/login/options') {
                        send(response, 200, await auth.loginOptions(payload, browserToken));
                        return;
                    }
                    if (path === '/auth/register/verify' || path === '/auth/login/verify') {
                        const result = path === '/auth/register/verify' ? await auth.enroll(payload, browserToken, sessionToken) : await auth.loginVerify(payload, browserToken, sessionToken);
                        if ('pending' in result) {
                            // An add-device passkey cannot sign in until an admin approves it: no session cookie.
                            send(response, 202, {...provenance, pending: true, pairingCode: result.pending.pairingCode});
                            return;
                        }
                        response.setHeader('Set-Cookie', [`cf_session=${result.token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600${secure}`, `cf_browser=${browserToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600${secure}`]);
                        send(response, 200, result.dto);
                        return;
                    }
                }
                if (path === '/auth/logout') {
                    object(payload, []);
                    response.setHeader('Set-Cookie', `cf_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
                    auth.logoutRequest(sessionToken, jar.cf_browser, request.headers['x-csrf-token']);
                    send(response, 200, {
                        ...provenance, loggedOut: true
                    });
                    return;
                }
                const session = auth.session(sessionToken, jar.cf_browser);
                auth.csrf(session, request.headers['x-csrf-token']);
                const child = await childrenPost(children, session, path, payload);
                if (child) {
                    send(response, child.status, {...provenance, ...child.body as object});
                    return;
                }
                const bulkRoute = await bulkPost(bulk, session, path, payload, clientKey(request.headers['idempotency-key']));
                if (bulkRoute) {
                    send(response, bulkRoute.status, {...provenance, ...bulkRoute.body as object});
                    return;
                }
                const inventoryWrite = inventoryPost(inventory ?? null, session, path, payload);
                if (inventoryWrite) {
                    send(response, inventoryWrite.status, {...provenance, ...inventoryWrite.body as object});
                    return;
                }
                const account = await accountPost(accounts, session, path, payload);
                if (account) {
                    send(response, account.status, {...provenance, ...account.body as object});
                    return;
                }
                const reward = /^\/people\/([a-z][a-z0-9_]{0,31})\/reward$/.exec(path);
                if (reward && grants && rewardOn(session.dto.actor)) {
                    const result = grants.reward(session.dto.actor, reward[1], object(payload, ['minutes']).minutes, request.headers['if-match'], clientKey(request.headers['idempotency-key']));
                    response.setHeader('Location', result.result.operationUrl);
                    send(response, result.status, result.result);
                    return;
                }
                // Focus window: the same gates as Reward Time, plus its own flag.
                const focus = /^\/people\/([a-z][a-z0-9_]{0,31})\/focus$/.exec(path);
                if (focus && grants && timeRequestsEnabled && mayDecide(session.dto.actor) && grants.policy.store.config.focus?.enabled === true) {
                    const result = grants.policy.focus(session.dto.actor, focus[1], object(payload, ['minutes']).minutes, request.headers['if-match'], clientKey(request.headers['idempotency-key']));
                    response.setHeader('Location', result.result.operationUrl);
                    send(response, result.status, result.result);
                    return;
                }
                const match = /^\/people\/([a-z][a-z0-9_]{0,31})\/(pause|resume)$/.exec(path);
                if (match) {
                    const result = await policy.mutate(session.dto.actor, match[1], match[2] as 'pause' | 'resume', payload, request.headers['if-match'], clientKey(request.headers['idempotency-key']));
                    response.setHeader('Location', result.result.operationUrl);
                    send(response, result.status, result.result);
                    return;
                }
                const schedule = /^\/people\/([a-z][a-z0-9_]{0,31})\/schedules(?:\/([a-z][a-z0-9_]{0,31})(\/delete)?)?$/.exec(path);
                if (schedule) {
                    if (!policy.scheduleMutate) {
                        throw new AppError(403, 'schedule_editing_unavailable', 'Schedules are owner-configured in this installation.');
                    }
                    const action = !schedule[2] ? 'schedule_create' : schedule[3] ? 'schedule_delete' : 'schedule_update';
                    const result = await policy.scheduleMutate(session.dto.actor, schedule[1], action, payload, schedule[2], request.headers['if-match'], clientKey(request.headers['idempotency-key']));
                    response.setHeader('Location', result.result.operationUrl);
                    send(response, result.status, result.result);
                    return;
                }
                const acknowledge = /^\/alerts\/([0-9]+)\/acknowledge$/.exec(path);
                if (acknowledge && alerts) {
                    object(payload, []);
                    send(response, 200, {...provenance, alert: alerts.acknowledge(session.dto.actor, alertId(acknowledge[1]), hiddenAlerts(session.dto.actor))});
                    return;
                }
                const parent = requests && mayDecide(session.dto.actor) && await parentPost(requests, session.dto.actor, path, payload);
                if (parent) {
                    send(response, parent.status, parent.body);
                    return;
                }
                throw new AppError(404, 'route_not_found');
            }
            if (request.method !== 'GET') {
                throw new AppError(405, 'method_not_allowed');
            }
            const session = auth.session(sessionToken, jar.cf_browser);
            if (path === '/auth/session') {
                send(response, 200, session.dto);
                return;
            }
            if (path === '/people') {
                // rewardTime: one viewer-level boolean, present only when the reward route would answer for this viewer (never per child).
                send(response, 200, {...await policy.people(session.dto.actor), ...(rewardOn(session.dto.actor) ? {rewardTime: true} : {})});
                return;
            }
            const childRead = childrenGet(children, session, path);
            if (childRead) {
                send(response, childRead.status, {...provenance, ...childRead.body as object});
                return;
            }
            const inventoryRead = inventoryGet(inventory ?? null, session, path);
            if (inventoryRead) {
                send(response, inventoryRead.status, {...provenance, ...inventoryRead.body as object});
                return;
            }
            const accountRead = accountGet(accounts, session, path);
            if (accountRead) {
                send(response, accountRead.status, {...provenance, ...accountRead.body as object});
                return;
            }
            const activityMatch = /^\/people\/([a-z][a-z0-9_]{0,31})\/activity$/.exec(path);
            if (activityMatch && activity) {
                send(response, 200, activity.report(session.dto.actor, activityMatch[1]));
                return;
            }
            if (path === '/devices') {
                send(response, 200, await policy.devices(session.dto.actor));
                return;
            }
            const page = /^\/alerts(?:\/before\/([0-9]+))?$/.exec(path);
            if (page && alerts) {
                send(response, 200, {...provenance, ...alerts.list(session.dto.actor, page[1] === undefined ? undefined : alertId(page[1]), hiddenAlerts(session.dto.actor))});
                return;
            }
            // Off (the default) is indistinguishable from a route that does not exist. No query strings: the page size and cursor are path segments, like /alerts/before/:id.
            const auditPage = /^\/audit(?:\/limit\/([0-9]{1,4}))?(?:\/before\/([0-9]{1,15}))?$/.exec(path);
            if (auditPage && audit?.enabled) {
                const limit = auditPage[1] === undefined ? undefined : Number(auditPage[1]);
                if (limit === 0) throw new AppError(400, 'invalid_limit');
                send(response, 200, {...provenance, ...audit.list(session.dto.actor, {limit, before: auditPage[2] === undefined ? undefined : Number(auditPage[2])})});
                return;
            }
            const parent = requests && mayDecide(session.dto.actor) && await parentGet(requests, session.dto.actor, path);
            if (parent) {
                send(response, parent.status, parent.body);
                return;
            }
            const operation = /^\/operations\/([0-9a-f-]{36})$/.exec(path);
            if (operation) {
                await policy.reconcile();
                send(response, 200, await policy.operation(session.dto.actor, operation[1]));
                return;
            }
            throw new AppError(404, 'route_not_found');
        }
        catch (error) {
            const app = error instanceof AppError ? error : new AppError(503, 'service_unavailable');
            if (!response.headersSent) {
                send(response, app.status, {
                    ...provenance, error: {
                        code: app.code, message: app.message
                    }
                });
            }
            else {
                response.end();
            }
        }
    };
    const server = config.tlsMaterial ? createSecureServer({...config.tlsMaterial, minVersion: 'TLSv1.2'}, handler) : createServer(handler);
    // Drop any other source before a single request byte is parsed; nothing about the connection is logged.
    if (trusted !== undefined) server.prependListener('connection', socket => { if (untrusted(socket.remoteAddress)) socket.destroy(); });
    // Allowance follow-ups (restoring a lifted pause) must not depend on a parent having the app open.
    let timer: NodeJS.Timeout | undefined;
    server.on('listening', () => {
        if (requests) {
            timer = setInterval(() => requests.advance().catch(() => void process.stderr.write('time_request_advance_failed\n')).then(() => {
                try { pendingAlerts?.(); } catch { process.stderr.write('time_request_alert_failed\n'); }
            }), 5000);
            timer.unref();
        } else if (drain?.hasObligations()) {
            timer = setInterval(() => drain.drain().then(({remaining, overdue}) => {
                if (overdue) process.stderr.write('time_request_restore_overdue\n');
                if (!remaining) { clearInterval(timer); timer = undefined; }
            }).catch(() => void process.stderr.write('time_request_advance_failed\n')), 5000);
            timer.unref();
        }
    });
    server.on('close', () => clearInterval(timer));
    server.requestTimeout = 10000;
    server.headersTimeout = 5000;
    server.maxHeadersCount = 40;
    return server;
}
function integrationHTML(html: string, scope: string, automatic: boolean): string {
    if (!/^[a-f0-9]{64}$/.test(scope)) throw new Error('invalid_integration_scope');
    return html.replace('<html lang="en">', `<html lang="en" data-source="real-router-integration" data-integration-scope="${scope}" data-automatic-dispatch="${automatic}">`)
        .replace('Fictional, local Couvre-feu parent-control prototype.', 'Private one-device Couvre-feu router integration.')
        .replace('Couvre-feu · synthetic demo', 'Couvre-feu · private router integration')
        .replace('<strong>Synthetic demo</strong><span>Fictional people · fake router · target compatibility unverified</span>', `<strong>Private router integration</strong><span>One test device · ${automatic ? 'owner-enabled automatic dispatch' : 'operator approval required'} · packet behavior unverified</span>`)
        .replace('Local prototype / 002', 'Private one-device pilot')
        .replace('This demo changes a fake router. It does not control a household connection.', automatic ? 'Authenticated requests dispatch automatically while the owner authorization is active. Unknown outcomes remain blocked for review.' : 'Requests wait for an operator-approved router invocation. Router observations and packet measurements are separate.')
        .replace('Sign in to the fictional account bound to your passkey.', 'Sign in to the private account bound to your passkey.')
        .replace('Use the token from the local demo bootstrap. It already identifies your fictional account.', 'Use the token from the private integration bootstrap. It fixes your account and permissions.')
        .replace('Create a demo passkey', 'Create a passkey')
        .replace('Source: synthetic fake router. Confirmation describes this fixture only. Real packet cutoff, router compatibility and phone deployment remain unverified.', 'Source: real router integration. Accepted policy, current runtime health and packet acceptance are distinct. Packet cutoff and target compatibility remain unverified.')
        .replace('Local, fictional prototype', 'Private one-device pilot');
}
