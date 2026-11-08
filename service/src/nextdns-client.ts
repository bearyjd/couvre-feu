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

export interface HttpRequest { readonly method: 'GET' | 'PUT' | 'PATCH'; readonly path: string; readonly headers: Readonly<Record<string, string>>; readonly body?: string; readonly signal?: AbortSignal }
export interface HttpResponse { readonly status: number; readonly headers: Readonly<Record<string, string>>; readonly body: string }
export type Transport = (request: HttpRequest) => Promise<HttpResponse>;

export const NEXTDNS_BASE_URL = 'https://api.nextdns.io';
export const MAX_RESPONSE_BYTES = 1_048_576;
export const MAX_ITEMS = 5000;
export const DEFAULT_FETCH_TIMEOUT_MS = 10_000;
/** Overall budget of one client call, retries and pagination included. */
export const DEFAULT_DEADLINE_MS = 60_000;
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

export type Sleep = (ms: number, signal?: AbortSignal) => Promise<void>;
export interface NextDnsClientOptions {
    /** Called for every request; the key is never stored by the client. */
    readonly apiKey: () => string;
    readonly transport?: Transport;
    /** Must reject when the signal aborts. The default sleep is abortable and unref'd. */
    readonly sleep?: Sleep;
    readonly now?: () => number;
    readonly random?: () => number;
    readonly maxAttempts?: number; readonly maxPages?: number;
    readonly baseDelayMs?: number; readonly maxDelayMs?: number; readonly maxRetryAfterMs?: number;
    /** Overall per-call deadline covering retries and pagination (default 60 s). Expiry is `timeout`. */
    readonly deadlineMs?: number;
    /** Aborts every call of this client. Caller aborts surface as `transport`, deadline expiry as `timeout`. */
    readonly signal?: AbortSignal;
}
export interface CallOptions { readonly signal?: AbortSignal }
export interface NextDnsClient {
    listProfiles(call?: CallOptions): Promise<readonly ProfileSummary[]>;
    getParentalControl(profile: string, call?: CallOptions): Promise<ParentalControl>;
    setParentalControl(profile: string, flags: ParentalFlags, call?: CallOptions): Promise<void>;
    getList(profile: string, list: ListName, call?: CallOptions): Promise<readonly ListEntry[]>;
    setList(profile: string, list: ListName, entries: readonly ListEntry[], call?: CallOptions): Promise<void>;
    getSettings(profile: string, call?: CallOptions): Promise<ProfileSettings>;
}

/** Thrown by assertSafeNextDnsEnvironment. The message is a fixed reason code; no environment value is ever echoed. */
export class NextDnsEnvironmentError extends Error {
    readonly reason: 'tls_verification_disabled' | 'env_proxy_enabled' | 'https_proxy_set';
    constructor(reason: NextDnsEnvironmentError['reason']) { super(reason); this.name = 'NextDnsEnvironmentError'; this.reason = reason; }
}
const OFF_VALUES = new Set(['', '0', 'false']);
/**
 * Startup guard, to be called once by the service before it builds a client (wired in a later PR). The API key travels in a request
 * header, so refuse an environment that would expose it: TLS verification disabled, or Node's env-proxy support switched on (an
 * HTTPS_PROXY / https_proxy would then see or terminate the connection). Pure: it only reads `env`.
 */
export function assertSafeNextDnsEnvironment(env: Readonly<Record<string, string | undefined>> = process.env): void {
    if (env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new NextDnsEnvironmentError('tls_verification_disabled');
    const proxyOn = env.NODE_USE_ENV_PROXY !== undefined && !OFF_VALUES.has(env.NODE_USE_ENV_PROXY.trim().toLowerCase());
    if (!proxyOn) return;
    const proxySet = [env.HTTPS_PROXY, env.https_proxy].some(v => v !== undefined && v !== '');
    throw new NextDnsEnvironmentError(proxySet ? 'https_proxy_set' : 'env_proxy_enabled');
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
    const retention = typeof logs.retention === 'number' && Number.isSafeInteger(logs.retention) && logs.retention >= 0
        ? logs.retention : fail();
    return Object.freeze({
        logs: Object.freeze({
            enabled: bool(logs.enabled), drop: Object.freeze({ ip: bool(drop.ip), domain: bool(drop.domain) }),
            retention, location: str(logs.location, /^[a-z]{2,8}$/),
        }),
        blockPage: Object.freeze({ enabled: bool(obj(o.blockPage, ['enabled']).enabled) }),
        performance: Object.freeze({ ecs: bool(perf.ecs), cacheBoost: bool(perf.cacheBoost), cnameFlattening: bool(perf.cnameFlattening) }),
        web3: bool(o.web3),
    });
}
function parseParental(v: unknown): ParentalControl {
    const o = obj(v, ['services', 'categories', 'safeSearch', 'youtubeRestrictedMode'], ['blockBypass']);
    const base = {
        services: arr(o.services, MAX_PAGE_ITEMS, entryOf(SERVICE_ID)), categories: arr(o.categories, MAX_PAGE_ITEMS, entryOf(SERVICE_ID)),
        safeSearch: bool(o.safeSearch), youtubeRestrictedMode: bool(o.youtubeRestrictedMode),
    };
    return Object.freeze(o.blockBypass === undefined ? base : { ...base, blockBypass: bool(o.blockBypass) });
}
const parseProfile = (v: unknown): ProfileSummary => {
    const o = obj(v, ['id', 'name']);
    return Object.freeze({ id: str(o.id, PROFILE_ID), name: str(o.name, PROFILE_NAME) });
};

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
/** TimeoutError reasons (fetch timeout, call deadline) are `timeout`; any other abort is the caller's and surfaces as `transport`. */
const abortCode = (signal: AbortSignal | undefined): NextDnsErrorCode =>
    (signal?.reason as { name?: string } | undefined)?.name === 'TimeoutError' ? 'timeout' : 'transport';

async function readCapped(res: Response, max: number, signal: AbortSignal): Promise<string> {
    // A missing header reads as null; Number(null) is 0, which passes. The streaming cap below still applies.
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > max) { await res.body?.cancel().catch(() => undefined); return fail(); }
    const aborted = new Promise<never>((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
    aborted.catch(() => undefined); // handled here so an abort after a clean read is not an unhandled rejection
    const chunks: Uint8Array[] = []; let total = 0;
    const reader = res.body?.getReader();
    while (reader) {
        const { done, value } = await Promise.race([reader.read(), aborted]);
        if (done) break;
        total += value.byteLength;
        if (total > max) { await reader.cancel().catch(() => undefined); return fail(); }
        chunks.push(value);
    }
    try { return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); } catch { return fail(); }
}
/** Default transport: global fetch, one host, redirects never followed, hard timeout (also over the body), capped body. Codes only. */
export function createFetchTransport(options: FetchTransportOptions = {}): Transport {
    const base = new URL(options.baseUrl ?? NEXTDNS_BASE_URL), f = options.fetch ?? fetch;
    const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS, maxBytes = options.maxBytes ?? MAX_RESPONSE_BYTES;
    return async req => {
        const url = new URL(req.path, base);
        if (url.origin !== base.origin || !req.path.startsWith('/') || req.path.includes('\\')) return fail('transport');
        const timer = AbortSignal.timeout(timeoutMs), signal = req.signal ? AbortSignal.any([timer, req.signal]) : timer;
        try {
            const res = await f(url, { method: req.method, headers: { ...req.headers }, body: req.body, redirect: 'manual', signal });
            const headers: Record<string, string> = {};
            res.headers.forEach((value, name) => { headers[name.toLowerCase()] = value; });
            if (res.status >= 300 && res.status < 400) { await res.body?.cancel().catch(() => undefined); return { status: res.status, headers: {}, body: '' }; }
            return { status: res.status, headers, body: await readCapped(res, maxBytes, signal) };
        } catch (error) {
            if (error instanceof NextDnsError) throw error;
            return fail(signal.aborted ? abortCode(signal) : 'transport');
        }
    };
}

/** Default sleep: abortable, and unref'd so a pending retry never keeps the process alive. */
export const abortableSleep: Sleep = (ms, signal) => new Promise<void>((resolve, reject) => {
    if (signal?.aborted) return reject(new NextDnsError(abortCode(signal)));
    const onAbort = () => { clearTimeout(timer); reject(new NextDnsError(abortCode(signal))); };
    const timer = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve(); }, ms);
    timer.unref();
    signal?.addEventListener('abort', onAbort, { once: true });
});

// ---- request pipeline ----
interface Config {
    readonly apiKey: () => string; readonly transport: Transport; readonly sleep: Sleep; readonly now: () => number; readonly random: () => number;
    readonly maxAttempts: number; readonly maxPages: number; readonly baseDelay: number; readonly maxDelay: number; readonly maxRetryAfter: number;
    readonly deadlineMs: number; readonly signal: AbortSignal | undefined;
}
interface Ctx { readonly cfg: Config; readonly deadline: number; readonly signal: AbortSignal }
type Attempt = { readonly ok: true; readonly res: HttpResponse } | { readonly ok: false; readonly err: NextDnsError; readonly res?: HttpResponse };

function resolveConfig(o: NextDnsClientOptions): Config {
    return {
        apiKey: o.apiKey, transport: o.transport ?? createFetchTransport(), sleep: o.sleep ?? abortableSleep, now: o.now ?? Date.now, random: o.random ?? Math.random,
        maxAttempts: Math.max(1, o.maxAttempts ?? 4), maxPages: Math.max(1, o.maxPages ?? 20), baseDelay: o.baseDelayMs ?? 500, maxDelay: o.maxDelayMs ?? 10_000,
        maxRetryAfter: o.maxRetryAfterMs ?? 30_000, deadlineMs: o.deadlineMs ?? DEFAULT_DEADLINE_MS, signal: o.signal,
    };
}
function newCtx(cfg: Config, call: CallOptions): Ctx {
    const signals = [AbortSignal.timeout(cfg.deadlineMs), ...[cfg.signal, call.signal].filter((s): s is AbortSignal => s !== undefined)];
    return { cfg, deadline: cfg.now() + cfg.deadlineMs, signal: AbortSignal.any(signals) };
}
/** Throws `timeout` once the call's budget is spent, or `transport` if the caller aborted. */
function checkLive(ctx: Ctx): void {
    if (ctx.cfg.now() > ctx.deadline) fail('timeout');
    if (ctx.signal.aborted) fail(abortCode(ctx.signal));
}
const header = (res: HttpResponse, name: string): string | undefined => Object.entries(res.headers).find(([k]) => k.toLowerCase() === name)?.[1];
function retryAfterMs(res: HttpResponse, now: number): number | null {
    const v = header(res, 'retry-after')?.trim();
    if (v === undefined) return null;
    if (/^\d{1,9}$/.test(v)) return Number(v) * 1000;
    const at = Date.parse(v);
    return Number.isNaN(at) ? null : Math.max(0, at - now);
}
/** Retry-After (seconds or HTTP date) is honoured up to maxRetryAfter; otherwise exponential backoff with jitter in [cap/2, cap]. */
function delayMs(cfg: Config, attempt: number, res?: HttpResponse): number {
    const after = res ? retryAfterMs(res, cfg.now()) : null;
    if (after !== null) return Math.min(after, cfg.maxRetryAfter);
    const cap = Math.min(cfg.maxDelay, cfg.baseDelay * 2 ** (attempt - 1));
    return cap / 2 + cfg.random() * cap / 2;
}
function badRequestError(body: string): NextDnsError {
    try { checkErrors(parseJson(body)); return new NextDnsError('invalid_request'); } catch (e) { return e instanceof NextDnsError ? e : new NextDnsError('bad_response'); }
}
function statusError(status: number, body: string): NextDnsError | null {
    if (status === 200 || status === 204) return null;
    if (status === 400) return badRequestError(body);
    if (status === 401 || status === 403) return new NextDnsError('unauthorized');
    if (status === 404) return new NextDnsError('not_found');
    if (status === 429) return new NextDnsError('rate_limited');
    return new NextDnsError(status >= 500 && status < 600 ? 'server' : 'bad_response');
}
async function attemptOnce(ctx: Ctx, req: HttpRequest): Promise<Attempt> {
    try {
        const res = await ctx.cfg.transport({ ...req, signal: ctx.signal });
        // Bytes, not UTF-16 units: a transport without its own cap must not smuggle in twice the limit.
        if (typeof res.body !== 'string' || Buffer.byteLength(res.body) > MAX_RESPONSE_BYTES) return { ok: false, err: new NextDnsError('bad_response') };
        const err = statusError(res.status, res.body);
        return err === null ? { ok: true, res } : { ok: false, err, res };
    } catch (e) { return { ok: false, err: e instanceof NextDnsError ? e : new NextDnsError('transport') }; }
}
async function pause(ctx: Ctx, ms: number): Promise<void> {
    if (ctx.cfg.now() + ms > ctx.deadline) fail('timeout');
    try { await ctx.cfg.sleep(ms, ctx.signal); } catch (e) { throw e instanceof NextDnsError ? e : new NextDnsError(abortCode(ctx.signal)); }
}
// 429 means "not processed", so every method may retry it. Anything else is retried for GET only (writes are not documented as idempotent).
const retryable = (method: HttpRequest['method'], err: NextDnsError): boolean =>
    err.code === 'rate_limited' || (method === 'GET' && (err.code === 'transport' || err.code === 'timeout' || err.code === 'server'));

async function exchange(ctx: Ctx, req: HttpRequest): Promise<HttpResponse> {
    for (let n = 1; ; n++) {
        checkLive(ctx);
        const attempt = await attemptOnce(ctx, req);
        if (attempt.ok) return attempt.res;
        if (!retryable(req.method, attempt.err) || n >= ctx.cfg.maxAttempts) throw attempt.err;
        await pause(ctx, delayMs(ctx.cfg, n, attempt.res));
    }
}
async function request(ctx: Ctx, method: HttpRequest['method'], path: string, payload?: unknown): Promise<HttpResponse> {
    const key = ctx.cfg.apiKey();
    if (typeof key !== 'string' || !API_KEY.test(key)) return fail('unauthorized');
    const headers = { 'x-api-key': key, accept: 'application/json', ...(payload === undefined ? {} : { 'content-type': 'application/json' }) };
    return exchange(ctx, { method, path, headers, ...(payload === undefined ? {} : { body: JSON.stringify(payload) }) });
}
async function readAll<T>(ctx: Ctx, path: string, item: (x: unknown) => T): Promise<readonly T[]> {
    const out: T[] = [], seen = new Set<string>();
    let cursor: string | null = null;
    for (let page = 0; page < ctx.cfg.maxPages; page++) {
        const res = await request(ctx, 'GET', cursor === null ? path : `${path}?cursor=${encodeURIComponent(cursor)}`);
        const env = parseEnvelope(res.body);
        out.push(...arr(env.data, MAX_PAGE_ITEMS, item));
        if (out.length > MAX_ITEMS) return fail();
        if (env.cursor === null) return Object.freeze(out);
        if (seen.has(env.cursor)) return fail(); // cursor loop
        seen.add(env.cursor); cursor = env.cursor;
    }
    return fail(); // page cap
}
const profilePath = (profile: string, sub = ''): string => `/profiles/${str(profile, PROFILE_ID)}${sub}`;
/**
 * Caller input is validated before any request. Every failure here, whatever the validator threw, is the caller's bad input, so it
 * is reported as invalid_request (the validators' own bad_response means "the server sent junk"). Nothing is swallowed: the code is the report.
 */
const checked = <T>(run: () => T): T => { try { return run(); } catch { throw new NextDnsError('invalid_request'); } };
const FLAG_KEYS = ['safeSearch', 'youtubeRestrictedMode', 'blockBypass'] as const;
/** Each value is read exactly once (getters included) and the body is built from those validated reads only. */
function flagsBody(flags: ParentalFlags): Record<string, boolean> {
    obj(flags, [], FLAG_KEYS);
    return Object.fromEntries(Object.entries(flags).map(([k, v]) => [k, bool(v)]));
}

export function createNextDnsClient(options: NextDnsClientOptions): NextDnsClient {
    const cfg = resolveConfig(options);
    const read = async <T>(call: CallOptions, path: string, parse: (data: unknown) => T): Promise<T> =>
        parse(parseEnvelope((await request(newCtx(cfg, call), 'GET', path)).body).data);
    return Object.freeze({
        listProfiles: (call: CallOptions = {}) => readAll(newCtx(cfg, call), '/profiles', parseProfile), // UNVERIFIED endpoint
        getParentalControl: (profile: string, call: CallOptions = {}) => read(call, checked(() => profilePath(profile, '/parentalControl')), parseParental),
        getSettings: (profile: string, call: CallOptions = {}) => read(call, checked(() => profilePath(profile, '/settings')), parseSettings),
        getList: (profile: string, list: ListName, call: CallOptions = {}) =>
            readAll(newCtx(cfg, call), checked(() => profilePath(profile, `/${LISTS[list]}`)), entryOf(ENTRY_ID[list])),
        async setParentalControl(profile: string, flags: ParentalFlags, call: CallOptions = {}): Promise<void> {
            const path = checked(() => profilePath(profile, '/parentalControl')), body = checked(() => flagsBody(flags));
            checkWrite(await request(newCtx(cfg, call), 'PATCH', path, body));
        },
        async setList(profile: string, list: ListName, entries: readonly ListEntry[], call: CallOptions = {}): Promise<void> {
            const path = checked(() => profilePath(profile, `/${LISTS[list]}`));
            const body = checked(() => arr(entries, MAX_ITEMS, entryOf(ENTRY_ID[list])).map(e => ({ id: e.id, active: e.active })));
            checkWrite(await request(newCtx(cfg, call), 'PUT', path, body));
        },
    });
}
