import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Auth } from './auth.ts';
import type { PolicyService } from './policy.ts';
import type { DemoConfig } from './config.ts';
import { provenance } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object, parseJSON } from '../../shared/src/json.ts';
const STATIC: Record<string, [
    string,
    string
]> = {
    '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
    '/auth-client.js': ['auth-client.js', 'text/javascript; charset=utf-8'], '/status-cache.js': ['status-cache.js', 'text/javascript; charset=utf-8'],
    '/operational-alerts.js': ['operational-alerts.js', 'text/javascript; charset=utf-8'],
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
type PolicyAPI = Pick<PolicyService, 'people' | 'devices' | 'mutate' | 'operation' | 'reconcile'>;
export function appServer(auth: Auth, policy: PolicyAPI, config: DemoConfig) {
    const provenance = auth.provenance;
    const automatic = (config as DemoConfig & {dispatch?: {enabled: boolean}}).dispatch?.enabled === true;
    const secure = config.origin.startsWith('https:') ? '; Secure' : '';
    const server = createServer(async (request, response) => {
        response.setHeader('Cache-Control', 'no-store');
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
            if (request.method === 'GET' && STATIC[path]) {
                const [name, type] = STATIC[path];
                let data = readFileSync(fileURLToPath(new URL(`../../web/public/${name}`, import.meta.url)));
                if (name === 'index.html' && provenance.source === 'real-router-integration') {
                    data = Buffer.from(integrationHTML(data.toString('utf8'), provenance.integrationScope!, automatic));
                }
                if (name === 'sw.js' && provenance.source === 'real-router-integration') data = Buffer.from(data.toString('utf8').replace("'cf-shell-v2'", `'cf-shell-integration-${provenance.integrationScope}-v2'`));
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
                        const result = path === '/auth/register/verify' ? await auth.registrationVerify(payload, browserToken, sessionToken) : await auth.loginVerify(payload, browserToken, sessionToken);
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
                const match = /^\/people\/([a-z][a-z0-9_]{0,31})\/(pause|resume)$/.exec(path);
                if (match) {
                    const result = await policy.mutate(session.dto.actor, match[1], match[2] as 'pause' | 'resume', payload, request.headers['if-match'], typeof request.headers['idempotency-key'] === 'string' ? request.headers['idempotency-key'] : undefined);
                    response.setHeader('Location', result.result.operationUrl);
                    send(response, result.status, result.result);
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
                send(response, 200, await policy.people(session.dto.actor));
                return;
            }
            if (path === '/devices') {
                send(response, 200, await policy.devices(session.dto.actor));
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
    });
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
