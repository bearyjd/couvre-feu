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
const bad = (code: string): never => { throw new Error(code); };

/** Startup validation when push is enabled. Throws a code only; the values are never echoed. */
export function ntfySettings(env: PushEnv = process.env): NtfySettings {
    let url: URL;
    try { url = new URL(env.COUVRE_NTFY_URL ?? ''); } catch { return bad('invalid_ntfy_url'); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') bad('invalid_ntfy_url');
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(env.COUVRE_NTFY_TOPIC ?? '')) bad('invalid_ntfy_topic');
    const token = env.COUVRE_NTFY_TOKEN;
    if (token !== undefined && token !== '' && !/^[A-Za-z0-9_-]{8,256}$/.test(token)) bad('invalid_ntfy_token');
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
        this.o = {fetch: options.fetch ?? fetch, sleep: options.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms))), log: options.log ?? (line => process.stderr.write(line)),
            timeoutMs: options.timeoutMs ?? PUSH_TIMEOUT_MS, maxAttempts: options.maxAttempts ?? PUSH_MAX_ATTEMPTS, backoffMs: options.backoffMs ?? PUSH_BACKOFF_MS};
    }
    /** Bounded: at most maxAttempts tries, each cut off at timeoutMs. 5xx, 429 and network errors retry; any other refusal does not. */
    async send(message: PushMessage): Promise<PushResult> {
        const {title, body} = pushText(message), s = this.settings;
        const headers: Record<string, string> = {Title: title, Click: this.click, 'Content-Type': 'text/plain; charset=utf-8', ...(s.token ? {Authorization: `Bearer ${s.token}`} : {})};
        let reason = 'not_sent', attempts = 0;
        while (attempts < this.o.maxAttempts) {
            if (attempts > 0) await this.o.sleep(this.o.backoffMs * 2 ** (attempts - 1));
            attempts++;
            try {
                const response = await this.o.fetch(`${s.baseUrl}/${s.topic}`, {method: 'POST', headers, body, redirect: 'error', signal: AbortSignal.timeout(this.o.timeoutMs)});
                await response.body?.cancel().catch(() => undefined);
                if (response.ok) return {ok: true, attempts, reason: 'sent'};
                reason = `http_${response.status}`;
                if (response.status < 500 && response.status !== 429) break;
            } catch (error) {
                reason = (error as Error).name === 'TimeoutError' ? 'timeout' : 'network_error';
            }
        }
        // Tag and status only: the URL, topic, token and any response text stay out of the log.
        this.o.log(`push_failed ${reason} attempts=${attempts}\n`);
        return {ok: false, attempts, reason};
    }
}
