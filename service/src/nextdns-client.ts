/**
 * Thin, strict client for the NextDNS configuration API (PRP-006 4.1). It touches no router.
 * Read https://nextdns.github.io/api on 2026-11-08. CONFIRMED there: base https://api.nextdns.io, header X-Api-Key, {"data":...,"meta":...}
 * envelopes, {"errors":[{code,detail,source:{parameter|pointer}}]} on 400 (also on 200 for user errors), meta.pagination.cursor (null at the end)
 * passed back as ?cursor=, parentalControl {services, categories, safeSearch, youtubeRestrictedMode, blockBypass}, denylist/allowlist as
 * [{id, active}], settings {logs, blockPage, performance, web3}, array endpoints take PUT, object endpoints take PATCH.
 * UNVERIFIED (the docs are silent; each is labelled again where used): a list-profiles endpoint (GET /profiles) and its item shape, 429 and
 * Retry-After behaviour, idempotency of any write, the status and body of write answers, bare-JSON write bodies, id alphabets and lengths
 * (including hex-encoded service ids), page size limits, and the units and values of settings.logs.retention/location.
 * Errors carry a closed code and never any server text, response body, URL or key. The key arrives through a getter on every request.
 */
export const NEXTDNS_ERROR_CODES = Object.freeze(['transport', 'timeout', 'rate_limited', 'unauthorized', 'not_found', 'invalid_request', 'bad_response', 'server'] as const);
export type NextDnsErrorCode = typeof NEXTDNS_ERROR_CODES[number];
export class NextDnsError extends Error {
    readonly code: NextDnsErrorCode;
    constructor(code: NextDnsErrorCode) { super(code); this.name = 'NextDnsError'; this.code = code; }
}
const fail = (code: NextDnsErrorCode = 'bad_response'): never => { throw new NextDnsError(code); };

export interface HttpRequest { readonly method: 'GET' | 'PUT' | 'PATCH'; readonly path: string; readonly headers: Readonly<Record<string, string>>; readonly body?: string }
export interface HttpResponse { readonly status: number; readonly headers: Readonly<Record<string, string>>; readonly body: string }
export type Transport = (request: HttpRequest) => Promise<HttpResponse>;

export const NEXTDNS_BASE_URL = 'https://api.nextdns.io';
export const MAX_RESPONSE_BYTES = 1_048_576;
export const MAX_ITEMS = 5000;
const MAX_PAGE_ITEMS = 1000;
// UNVERIFIED alphabets: the docs show only "abc123". Wide enough for hex or base36, narrow enough that no separator, dot or escape can pass.
const PROFILE_ID = /^[A-Za-z0-9]{4,32}$/;
const SERVICE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const DOMAIN = /^(?:\*\.)?[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$/;
const CURSOR = /^[A-Za-z0-9_.=-]{1,128}$/;
const API_KEY = /^[\x21-\x7e]{8,256}$/;
const PROFILE_NAME = /^[^\u0000-\u001f\u007f]{0,100}$/u;

export interface ListEntry { readonly id: string; readonly active: boolean }
export interface ProfileSummary { readonly id: string; readonly name: string }
export interface ParentalControl {
    readonly services: readonly ListEntry[]; readonly categories: readonly ListEntry[];
    readonly safeSearch: boolean; readonly youtubeRestrictedMode: boolean; readonly blockBypass?: boolean;
}
export type ParentalFlags = { readonly safeSearch?: boolean; readonly youtubeRestrictedMode?: boolean; readonly blockBypass?: boolean };
export interface ProfileSettings {
    readonly logs: { readonly enabled: boolean; readonly drop: { readonly ip: boolean; readonly domain: boolean }; readonly retention: number; readonly location: string };
    readonly blockPage: { readonly enabled: boolean };
    readonly performance: { readonly ecs: boolean; readonly cacheBoost: boolean; readonly cnameFlattening: boolean };
    readonly web3: boolean;
}
const LISTS = { services: 'parentalControl/services', categories: 'parentalControl/categories', denylist: 'denylist', allowlist: 'allowlist' } as const;
export type ListName = keyof typeof LISTS;
const ENTRY_ID: Record<ListName, RegExp> = { services: SERVICE_ID, categories: SERVICE_ID, denylist: DOMAIN, allowlist: DOMAIN };

export interface NextDnsClientOptions {
    /** Called for every request; the key is never stored by the client. */
    readonly apiKey: () => string;
    readonly transport?: Transport;
    readonly sleep?: (ms: number) => Promise<void>;
    readonly now?: () => number;
    readonly random?: () => number;
    readonly maxAttempts?: number; readonly maxPages?: number;
    readonly baseDelayMs?: number; readonly maxDelayMs?: number; readonly maxRetryAfterMs?: number;
}
export interface NextDnsClient {
    listProfiles(): Promise<readonly ProfileSummary[]>;
    getParentalControl(profile: string): Promise<ParentalControl>;
    setParentalControl(profile: string, flags: ParentalFlags): Promise<void>;
    getList(profile: string, list: ListName): Promise<readonly ListEntry[]>;
    setList(profile: string, list: ListName, entries: readonly ListEntry[]): Promise<void>;
    getSettings(profile: string): Promise<ProfileSettings>;
}

// ---- strict validators (unknown keys, wrong types, oversize values all throw bad_response) ----
type Obj = Record<string, unknown>;
function obj(v: unknown, required: readonly string[], optional: readonly string[] = []): Obj {
    if (typeof v !== 'object' || v === null || Array.isArray(v)) return fail();
    const keys = Object.keys(v);
    if (keys.some(k => !required.includes(k) && !optional.includes(k)) || required.some(k => !keys.includes(k))) return fail();
    return v as Obj;
}
const bool = (v: unknown): boolean => typeof v === 'boolean' ? v : fail();
const str = (v: unknown, re: RegExp): string => typeof v === 'string' && re.test(v) ? v : fail();
function arr<T>(v: unknown, max: number, item: (x: unknown) => T): readonly T[] {
    if (!Array.isArray(v) || v.length > max) return fail();
    return Object.freeze(v.map(item));
}
const entryOf = (re: RegExp) => (v: unknown): ListEntry => { const o = obj(v, ['id', 'active']); return Object.freeze({ id: str(o.id, re), active: bool(o.active) }); };
function parseSettings(v: unknown): ProfileSettings {
    const o = obj(v, ['logs', 'blockPage', 'performance', 'web3']);
    const logs = obj(o.logs, ['enabled', 'drop', 'retention', 'location']), drop = obj(logs.drop, ['ip', 'domain']);
    const perf = obj(o.performance, ['ecs', 'cacheBoost', 'cnameFlattening']);
    // UNVERIFIED: retention is documented as 7776000 without units; location as "eu" without the other values.
    const retention = typeof logs.retention === 'number' && Number.isSafeInteger(logs.retention) && logs.retention >= 0 ? logs.retention : fail();
    return Object.freeze({
        logs: Object.freeze({ enabled: bool(logs.enabled), drop: Object.freeze({ ip: bool(drop.ip), domain: bool(drop.domain) }), retention, location: str(logs.location, /^[a-z]{2,8}$/) }),
        blockPage: Object.freeze({ enabled: bool(obj(o.blockPage, ['enabled']).enabled) }),
        performance: Object.freeze({ ecs: bool(perf.ecs), cacheBoost: bool(perf.cacheBoost), cnameFlattening: bool(perf.cnameFlattening) }),
        web3: bool(o.web3),
    });
}
function parseParental(v: unknown): ParentalControl {
    const o = obj(v, ['services', 'categories', 'safeSearch', 'youtubeRestrictedMode'], ['blockBypass']);
    const base = { services: arr(o.services, MAX_PAGE_ITEMS, entryOf(SERVICE_ID)), categories: arr(o.categories, MAX_PAGE_ITEMS, entryOf(SERVICE_ID)), safeSearch: bool(o.safeSearch), youtubeRestrictedMode: bool(o.youtubeRestrictedMode) };
    return Object.freeze(o.blockBypass === undefined ? base : { ...base, blockBypass: bool(o.blockBypass) });
}
const parseProfile = (v: unknown): ProfileSummary => { const o = obj(v, ['id', 'name']); return Object.freeze({ id: str(o.id, PROFILE_ID), name: str(o.name, PROFILE_NAME) }); };

function parseJson(text: string): unknown {
    try { return JSON.parse(text); } catch { return fail(); }
}
/** Error bodies: {errors:[{code, detail?, source?}]}. Validated for shape, then discarded; no text escapes. */
function checkErrors(v: unknown): void {
    arr(obj(v, ['errors']).errors, 100, e => {
        const o = obj(e, ['code'], ['detail', 'source']);
        str(o.code, /^[A-Za-z0-9_]{1,64}$/);
        if (o.detail !== undefined && (typeof o.detail !== 'string' || o.detail.length > 2000)) fail();
        if (o.source !== undefined) { const s = obj(o.source, [], ['parameter', 'pointer']); for (const k of Object.keys(s)) str(s[k], /^.{0,256}$/s); }
    });
}
interface Parsed { readonly data: unknown; readonly cursor: string | null }
function parseEnvelope(text: string): Parsed {
    const v = parseJson(text);
    if (typeof v === 'object' && v !== null && 'errors' in v) { checkErrors(v); return fail('invalid_request'); }
    const o = obj(v, ['data'], ['meta']);
    if (o.meta === undefined) return { data: o.data, cursor: null };
    const pagination = obj(obj(o.meta, [], ['pagination']).pagination ?? { cursor: null }, ['cursor']);
    return { data: o.data, cursor: pagination.cursor === null ? null : str(pagination.cursor, CURSOR) };
}
/** UNVERIFIED: the docs give no status or body for PUT/PATCH. Accepted: 200/204 with an empty body, {} or {"data":null}. */
function checkWrite(res: HttpResponse): void {
    if (res.body === '') return;
    const v = parseJson(res.body);
    if (typeof v === 'object' && v !== null && 'errors' in v) { checkErrors(v); fail('invalid_request'); }
    const o = obj(v, [], ['data']);
    if (o.data !== undefined && o.data !== null) fail();
}

// ---- default transport ----
export interface FetchTransportOptions { readonly baseUrl?: string; readonly fetch?: typeof fetch; readonly timeoutMs?: number; readonly maxBytes?: number }
async function readCapped(res: Response, max: number): Promise<string> {
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > max) { await res.body?.cancel().catch(() => undefined); return fail(); }
    const chunks: Uint8Array[] = []; let total = 0;
    const reader = res.body?.getReader();
    while (reader) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > max) { await reader.cancel().catch(() => undefined); return fail(); }
        chunks.push(value);
    }
    try { return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); } catch { return fail(); }
}
/** Default transport: global fetch, one host, redirects never followed, hard timeout, capped body. Errors carry codes only. */
export function createFetchTransport(options: FetchTransportOptions = {}): Transport {
    const base = new URL(options.baseUrl ?? NEXTDNS_BASE_URL), f = options.fetch ?? fetch;
    const timeoutMs = options.timeoutMs ?? 10_000, maxBytes = options.maxBytes ?? MAX_RESPONSE_BYTES;
    return async req => {
        const url = new URL(req.path, base);
        if (url.origin !== base.origin || !req.path.startsWith('/') || req.path.includes('\\')) return fail('transport');
        const signal = AbortSignal.timeout(timeoutMs);
        try {
            const res = await f(url, { method: req.method, headers: { ...req.headers }, body: req.body, redirect: 'manual', signal });
            const headers: Record<string, string> = {};
            res.headers.forEach((value, name) => { headers[name.toLowerCase()] = value; });
            if (res.status >= 300 && res.status < 400) { await res.body?.cancel().catch(() => undefined); return { status: res.status, headers: {}, body: '' }; }
            return { status: res.status, headers, body: await readCapped(res, maxBytes) };
        } catch (error) {
            if (error instanceof NextDnsError) throw error;
            return fail(signal.aborted ? 'timeout' : 'transport');
        }
    };
}

// ---- client ----
const header = (res: HttpResponse, name: string): string | undefined => Object.entries(res.headers).find(([k]) => k.toLowerCase() === name)?.[1];
function retryAfterMs(res: HttpResponse, now: number): number | null {
    const v = header(res, 'retry-after')?.trim();
    if (v === undefined) return null;
    if (/^\d{1,9}$/.test(v)) return Number(v) * 1000;
    const at = Date.parse(v);
    return Number.isNaN(at) ? null : Math.max(0, at - now);
}
function statusError(status: number, body: string): NextDnsError | null {
    if (status === 200 || status === 204) return null;
    if (status === 400) { try { checkErrors(parseJson(body)); return new NextDnsError('invalid_request'); } catch (e) { return e instanceof NextDnsError ? e : new NextDnsError('bad_response'); } }
    if (status === 401 || status === 403) return new NextDnsError('unauthorized');
    if (status === 404) return new NextDnsError('not_found');
    if (status === 429) return new NextDnsError('rate_limited');
    return new NextDnsError(status >= 500 && status < 600 ? 'server' : 'bad_response');
}

export function createNextDnsClient(options: NextDnsClientOptions): NextDnsClient {
    const transport = options.transport ?? createFetchTransport();
    const sleep = options.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
    const now = options.now ?? Date.now, random = options.random ?? Math.random;
    const maxAttempts = Math.max(1, options.maxAttempts ?? 4), maxPages = Math.max(1, options.maxPages ?? 20);
    const baseDelay = options.baseDelayMs ?? 500, maxDelay = options.maxDelayMs ?? 10_000, maxRetryAfter = options.maxRetryAfterMs ?? 30_000;

    const backoff = (attempt: number, res?: HttpResponse): number => {
        const cap = Math.min(maxDelay, baseDelay * 2 ** (attempt - 1)), jittered = cap / 2 + random() * cap / 2;
        const after = res ? retryAfterMs(res, now()) : null;
        return after === null ? jittered : Math.max(jittered, Math.min(after, maxRetryAfter));
    };
    /** One attempt. Returns the response, or the failure to decide on. */
    async function attemptOnce(req: HttpRequest): Promise<HttpResponse | NextDnsError> {
        try {
            const res = await transport(req);
            if (typeof res.body !== 'string' || res.body.length > MAX_RESPONSE_BYTES) return new NextDnsError('bad_response');
            return res;
        } catch (e) { return e instanceof NextDnsError ? e : new NextDnsError('transport'); }
    }
    // 429 means "not processed", so every method may retry it. Anything else is retried for GET only (writes are not documented as idempotent).
    async function exchange(req: HttpRequest): Promise<HttpResponse> {
        for (let attempt = 1; ; attempt++) {
            const out = await attemptOnce(req);
            const res = out instanceof NextDnsError ? undefined : out;
            const err = out instanceof NextDnsError ? out : statusError(out.status, out.body);
            if (err === null && res) return res;
            const retryable = err!.code === 'rate_limited' || (req.method === 'GET' && ['transport', 'timeout', 'server'].includes(err!.code));
            if (!retryable || attempt >= maxAttempts) throw err!;
            await sleep(backoff(attempt, res));
        }
    }
    async function call(method: HttpRequest['method'], path: string, payload?: unknown): Promise<HttpResponse> {
        const key = options.apiKey();
        if (typeof key !== 'string' || !API_KEY.test(key)) return fail('unauthorized');
        const headers = { 'x-api-key': key, accept: 'application/json', ...(payload === undefined ? {} : { 'content-type': 'application/json' }) };
        return exchange({ method, path, headers, ...(payload === undefined ? {} : { body: JSON.stringify(payload) }) });
    }
    const profilePath = (profile: string, sub = ''): string => `/profiles/${str(profile, PROFILE_ID)}${sub}`;
    const checked = <T>(run: () => T): T => { try { return run(); } catch { throw new NextDnsError('invalid_request'); } };
    const read = async <T>(path: string, parse: (data: unknown) => T): Promise<T> => parse(parseEnvelope((await call('GET', path)).body).data);

    async function readAll<T>(path: string, item: (x: unknown) => T): Promise<readonly T[]> {
        const out: T[] = [], seen = new Set<string>();
        let cursor: string | null = null;
        for (let page = 0; page < maxPages; page++) {
            const res = await call('GET', cursor === null ? path : `${path}?cursor=${encodeURIComponent(cursor)}`);
            const env = parseEnvelope(res.body);
            out.push(...arr(env.data, MAX_PAGE_ITEMS, item));
            if (out.length > MAX_ITEMS) return fail();
            if (env.cursor === null) return Object.freeze(out);
            if (seen.has(env.cursor)) return fail(); // cursor loop
            seen.add(env.cursor); cursor = env.cursor;
        }
        return fail(); // page cap
    }

    return Object.freeze({
        listProfiles: () => readAll('/profiles', parseProfile), // UNVERIFIED endpoint
        getParentalControl: (profile: string) => read(checked(() => profilePath(profile, '/parentalControl')), parseParental),
        getSettings: (profile: string) => read(checked(() => profilePath(profile, '/settings')), parseSettings),
        getList: (profile: string, list: ListName) => readAll(checked(() => profilePath(profile, `/${LISTS[list]}`)), entryOf(ENTRY_ID[list])),
        async setParentalControl(profile: string, flags: ParentalFlags): Promise<void> {
            const path = checked(() => profilePath(profile, '/parentalControl'));
            const body = checked(() => { const o = obj(flags, [], ['safeSearch', 'youtubeRestrictedMode', 'blockBypass']); for (const k of Object.keys(o)) bool(o[k]); return { ...o }; });
            checkWrite(await call('PATCH', path, body));
        },
        async setList(profile: string, list: ListName, entries: readonly ListEntry[]): Promise<void> {
            const path = checked(() => profilePath(profile, `/${LISTS[list]}`));
            const body = checked(() => arr(entries, MAX_ITEMS, entryOf(ENTRY_ID[list])).map(e => ({ id: e.id, active: e.active })));
            checkWrite(await call('PUT', path, body));
        },
    });
}
