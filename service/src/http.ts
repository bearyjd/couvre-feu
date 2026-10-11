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
export function appServer(auth: Auth, policy: PolicyService, config: DemoConfig) {
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
                const data = readFileSync(fileURLToPath(new URL(`../../web/public/${name}`, import.meta.url)));
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
                    response.setHeader('Set-Cookie', `cf_browser=${browserToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`);
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
                        response.setHeader('Set-Cookie', [`cf_session=${result.token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`, `cf_browser=${browserToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`]);
                        send(response, 200, result.dto);
                        return;
                    }
                }
                if (path === '/auth/logout') {
                    object(payload, []);
                    response.setHeader('Set-Cookie', 'cf_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
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
                    const result = policy.mutate(session.dto.actor, match[1], match[2] as 'pause' | 'resume', payload, request.headers['if-match'], typeof request.headers['idempotency-key'] === 'string' ? request.headers['idempotency-key'] : undefined);
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
                send(response, 200, policy.people(session.dto.actor));
                return;
            }
            if (path === '/devices') {
                send(response, 200, policy.devices(session.dto.actor));
                return;
            }
            const operation = /^\/operations\/([0-9a-f-]{36})$/.exec(path);
            if (operation) {
                policy.reconcile();
                send(response, 200, policy.operation(session.dto.actor, operation[1]));
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
