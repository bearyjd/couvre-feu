/**
 * In-process fake NextDNS API implementing the client's Transport interface. No sockets, no network.
 * Shapes follow https://nextdns.github.io/api where it documents them; everything else is UNVERIFIED and marked.
 * UNVERIFIED: GET /profiles (list), the 204 answer to writes, and bare-JSON write bodies are the fake's assumptions.
 */
import type { HttpRequest, HttpResponse, Transport } from '../../src/nextdns-client.ts';

export interface FakeEntry { id: string; active: boolean }
export interface FakeProfile {
    id: string; name: string;
    parentalControl: { services: FakeEntry[]; categories: FakeEntry[]; safeSearch: boolean; youtubeRestrictedMode: boolean; blockBypass: boolean };
    denylist: FakeEntry[]; allowlist: FakeEntry[]; settings: unknown;
    /** Raw `data` arrays for GET /analytics/status and /analytics/reasons. Shapes follow the API doc; UNVERIFIED beyond that. */
    analytics?: { status: unknown[]; reasons: unknown[] };
}
/** One scripted answer consumed by the next request, whatever it is. */
export type FakeStep = HttpResponse | { throw: 'timeout' | 'network' };
export interface FakeOptions { apiKey: string; pageSize?: number; cursorLoop?: boolean; profiles?: FakeProfile[] }
export interface RecordedRequest { method: string; path: string; body: string | undefined; keyOk: boolean }
export interface FakeNextDns { transport: Transport; requests: RecordedRequest[]; profiles: Map<string, FakeProfile>; enqueue(step: FakeStep): void }

export const json = (status: number, value: unknown, headers: Record<string, string> = {}): HttpResponse => ({ status, headers, body: JSON.stringify(value) });
export const SETTINGS = {
    logs: { enabled: false, drop: { ip: false, domain: false }, retention: 7776000, location: 'eu' },
    blockPage: { enabled: false }, performance: { ecs: true, cacheBoost: true, cnameFlattening: true }, web3: false,
};
export const profile = (id: string, over: Partial<FakeProfile> = {}): FakeProfile => ({
    id, name: `Child ${id}`,
    parentalControl: { services: [{ id: 'tiktok', active: true }], categories: [{ id: 'porn', active: true }], safeSearch: true, youtubeRestrictedMode: true, blockBypass: false },
    denylist: [{ id: 'bad.example', active: true }], allowlist: [{ id: 'good.example', active: true }], settings: structuredClone(SETTINGS), ...over,
});
const badRequest = (pointer: string) => json(400, { errors: [{ code: 'invalid', detail: 'Server free text that must never surface', source: { pointer } }] });
const LISTS: Record<string, (p: FakeProfile) => FakeEntry[]> = {
    denylist: p => p.denylist, allowlist: p => p.allowlist, 'parentalControl/services': p => p.parentalControl.services, 'parentalControl/categories': p => p.parentalControl.categories,
};
const ANALYTICS_PARAMS = ['from', 'to', 'limit', 'cursor'];
const FLAGS = ['safeSearch', 'youtubeRestrictedMode', 'blockBypass'];

export function createFakeNextDns(options: FakeOptions): FakeNextDns {
    const profiles = new Map((options.profiles ?? [profile('abc123')]).map(p => [p.id, p]));
    const requests: RecordedRequest[] = [], queue: FakeStep[] = [], pageSize = options.pageSize ?? 100;
    const page = (all: unknown[], cursor: string | null): HttpResponse => {
        const start = cursor === null ? 0 : Number(cursor.slice(1)), end = start + pageSize;
        const next = options.cursorLoop && start > 0 ? `c${start}` : end < all.length ? `c${end}` : null;
        return json(200, { data: all.slice(start, end), meta: { pagination: { cursor: next } } });
    };
    const patchFlags = (p: FakeProfile, body: unknown): HttpResponse => {
        const o = body as Record<string, unknown>;
        if (typeof o !== 'object' || o === null || Object.keys(o).some(k => !FLAGS.includes(k) || typeof o[k] !== 'boolean')) return badRequest('/parentalControl');
        Object.assign(p.parentalControl, o);
        return { status: 204, headers: {}, body: '' };
    };
    const route = (req: HttpRequest): HttpResponse => {
        const url = new URL(req.path, 'https://api.nextdns.io'), cursor = url.searchParams.get('cursor');
        const parts = url.pathname.split('/').filter(Boolean), body = req.body === undefined ? undefined : JSON.parse(req.body);
        if (parts[0] !== 'profiles') return json(404, { errors: [{ code: 'notFound' }] });
        if (parts.length === 1) return page([...profiles.values()].map(p => ({ id: p.id, name: p.name })), cursor);
        const p = profiles.get(parts[1]!);
        if (!p) return json(404, { errors: [{ code: 'notFound', detail: 'unknown profile' }] });
        const sub = parts.slice(2).join('/');
        if (sub === 'settings' && req.method === 'GET') return json(200, { data: p.settings });
        if (sub === 'parentalControl' && req.method === 'GET') return json(200, { data: p.parentalControl });
        if (sub === 'parentalControl' && req.method === 'PATCH') return patchFlags(p, body);
        if ((sub === 'analytics/status' || sub === 'analytics/reasons') && req.method === 'GET') {
            const q = url.searchParams, int = (k: string) => /^\d{1,12}$/.test(q.get(k) ?? '');
            if (!p.analytics || [...q.keys()].some(k => !ANALYTICS_PARAMS.includes(k)) || !int('from') || !int('to')) return badRequest('/from');
            return page(sub === 'analytics/status' ? p.analytics.status : p.analytics.reasons, cursor);
        }
        const list = LISTS[sub];
        if (list && req.method === 'GET') return page(list(p), cursor);
        if (list && req.method === 'PUT') {
            if (!Array.isArray(body)) return badRequest('/');
            list(p).splice(0, Infinity, ...(body as FakeEntry[]));
            return { status: 204, headers: {}, body: '' };
        }
        return json(404, { errors: [{ code: 'notFound' }] });
    };
    const transport: Transport = async req => {
        const keyOk = req.headers['x-api-key'] === options.apiKey;
        requests.push({ method: req.method, path: req.path, body: req.body, keyOk });
        const step = queue.shift();
        if (step && 'throw' in step) throw new Error(step.throw === 'timeout' ? 'ETIMEDOUT' : 'ECONNRESET');
        if (step) return step;
        if (!keyOk) return json(401, { errors: [{ code: 'authRequired' }] });
        return route(req);
    };
    return { transport, requests, profiles, enqueue: step => { queue.push(step); } };
}
