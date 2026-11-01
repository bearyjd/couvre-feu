/**
 * Content-free push to admins through a self-hosted ntfy topic. Off unless the manifest's push.enabled is true.
 * The text of a notification is built here from constants and integers only: callers pass a kind (and digest counts), never text,
 * so a child name, device name, reason or audit detail has no way into the title, body or link. The topic and token come from the
 * environment and are never logged. A failed send is reported to the caller as a result and never throws.
 */
export interface PushEnv { COUVRE_NTFY_URL?: string; COUVRE_NTFY_TOPIC?: string; COUVRE_NTFY_TOKEN?: string }
export interface NtfySettings { baseUrl: string; topic: string; token: string | null }
export type DigestCounts = {requests: number; grants: number; pauses: number};
export type PushMessage = {kind: 'alert'} | {kind: 'digest'; counts: DigestCounts};
export interface PushResult { ok: boolean; attempts: number; reason: string }
export interface PushOptions { fetch?: typeof fetch; sleep?: (ms: number) => Promise<void>; log?: (line: string) => unknown; timeoutMs?: number; maxAttempts?: number; backoffMs?: number }

export const PUSH_TIMEOUT_MS = 5000;
export const PUSH_MAX_ATTEMPTS = 3;
export const PUSH_BACKOFF_MS = 1000;
/** Loopback, RFC 1918 and Tailscale CGNAT (100.64.0.0/10) IPv4 literals, plus localhost and ::1. */
function privateHost(host: string): boolean {
    if (host === 'localhost' || host === '[::1]') return true;
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (!m) return false;
    const [a, b] = [+m[1], +m[2]];
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}
/** Wraps a log sink so reporting can never throw or leave a rejected promise behind (a sink may be async). */
export function safeLog(sink: (line: string) => unknown): (line: string) => void {
    return line => {
        try { const result = sink(line); if (result !== null && typeof result === 'object' && typeof (result as PromiseLike<unknown>).then === 'function') Promise.resolve(result).catch(() => undefined); } catch { /* nowhere left to report */ }
    };
}
const bad = (code: string): never => { throw new Error(code); };

/** Startup validation when push is enabled. Throws a code only; the values are never echoed. */
export function ntfySettings(env: PushEnv = process.env): NtfySettings {
    let url: URL;
    try { url = new URL(env.COUVRE_NTFY_URL ?? ''); } catch { return bad('invalid_ntfy_url'); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') bad('invalid_ntfy_url');
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(env.COUVRE_NTFY_TOPIC ?? '')) bad('invalid_ntfy_topic');
    const token = env.COUVRE_NTFY_TOKEN;
    if (token !== undefined && token !== '' && !/^[A-Za-z0-9_-]{8,256}$/.test(token)) bad('invalid_ntfy_token');
    // A bearer token must not cross an untrusted network in clear text.
    if (token && url.protocol === 'http:' && !privateHost(url.hostname)) bad('ntfy_token_requires_https');
    return {baseUrl: url.origin, topic: env.COUVRE_NTFY_TOPIC as string, token: token ? token : null};
}

const count = (n: number) => Number.isSafeInteger(n) && n >= 0 ? n : 0;
/** The only text that can leave the house. Digest numbers are coerced to non-negative integers. */
export function pushText(message: PushMessage): {title: string; body: string} {
    if (message.kind === 'alert') return {title: 'Couvre-feu', body: 'New alert. Open the app to see it.'};
    const c = message.counts;
    return {title: 'Couvre-feu weekly summary', body: `Last 7 days: ${count(c.requests)} requests, ${count(c.grants)} grants, ${count(c.pauses)} pauses.`};
}

export class NtfyPush {
    readonly settings: NtfySettings;
    private readonly click: string;
    private readonly o: Required<PushOptions>;
    /** `origin` is the service's own configured origin; it is the link target, never derived from data. */
    constructor(settings: NtfySettings, origin: string, options: PushOptions = {}) {
        this.settings = settings; this.click = origin + '/';
        this.o = {fetch: options.fetch ?? fetch, sleep: options.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms))), log: safeLog(options.log ?? (line => process.stderr.write(line))),
            timeoutMs: options.timeoutMs ?? PUSH_TIMEOUT_MS, maxAttempts: options.maxAttempts ?? PUSH_MAX_ATTEMPTS, backoffMs: options.backoffMs ?? PUSH_BACKOFF_MS};
    }
    /** Bounded: at most maxAttempts tries, each cut off at timeoutMs. 5xx, 429 and network errors retry; any other refusal does not. */
    async send(message: PushMessage, abort?: AbortSignal): Promise<PushResult> {
        const {title, body} = pushText(message), s = this.settings;
        const headers: Record<string, string> = {Title: title, Click: this.click, 'Content-Type': 'text/plain; charset=utf-8', ...(s.token ? {Authorization: `Bearer ${s.token}`} : {})};
        let reason = 'not_sent', attempts = 0;
        while (attempts < this.o.maxAttempts) {
            if (attempts > 0) await this.o.sleep(this.o.backoffMs * 2 ** (attempts - 1));
            if (abort?.aborted) { reason = 'aborted'; break; }
            attempts++;
            try {
                const timeout = AbortSignal.timeout(this.o.timeoutMs);
                const response = await this.o.fetch(`${s.baseUrl}/${s.topic}`, {method: 'POST', headers, body, redirect: 'error', signal: abort ? AbortSignal.any([timeout, abort]) : timeout});
                await response.body?.cancel().catch(() => undefined);
                if (response.ok) return {ok: true, attempts, reason: 'sent'};
                reason = `http_${response.status}`;
                if (response.status < 500 && response.status !== 429) break;
            } catch (error) {
                // Shutdown aborts a send: a clean result, never retried.
                if (abort?.aborted) { reason = 'aborted'; break; }
                reason = (error as Error | null)?.name === 'TimeoutError' ? 'timeout' : 'network_error';
            }
        }
        // Tag and status only: the URL, topic, token and any response text stay out of the log.
        this.o.log(`push_failed ${reason} attempts=${attempts}\n`);
        return {ok: false, attempts, reason};
    }
}
