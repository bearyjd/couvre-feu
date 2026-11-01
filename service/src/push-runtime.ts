import type { IntegrationConfig } from './integration-config.ts';
import type { IntegrationStore } from './integration-db.ts';
import { digestTick, latestDigestSlot } from './digest.ts';
import type { DigestStateStore } from './digest.ts';
import { NtfyPush, ntfySettings } from './push-sender.ts';
import type { DigestCounts, PushEnv, PushOptions } from './push-sender.ts';

export const NOTIFY_POLL_MS = 60000;
/** Shutdown waits for a pass in flight at most this long (the service unit allows 30 s to stop). */
export const STOP_WAIT_MS = 2000;
type Db = Pick<IntegrationStore, 'run' | 'get'>;

/** Created only when push is on, so a flag-off service does no extra database work. */
function stateStore(db: Db, key: string): DigestStateStore & {exists(): boolean} {
    db.run('CREATE TABLE IF NOT EXISTS notify_state (key TEXT PRIMARY KEY, value INTEGER NOT NULL) STRICT');
    const read = () => db.get<{value: number}>('SELECT value FROM notify_state WHERE key=?', key)?.value;
    return {exists: () => read() !== undefined, read: () => read() ?? 0, write: value => { db.run('INSERT INTO notify_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', key, value); }};
}

/** Numbers only: requests made, grants approved and pause operations in the window. No ids, names or text are selected. */
export function weeklyCounts(db: Pick<IntegrationStore, 'get'>, from: number, to: number): DigestCounts {
    const n = (sql: string) => db.get<{n: number}>(sql, from, to)!.n;
    return {
        requests: n('SELECT count(*) n FROM time_requests WHERE created_at > ? AND created_at <= ?'),
        grants: n("SELECT count(*) n FROM time_requests WHERE state='approved' AND decided_at > ? AND decided_at <= ?"),
        pauses: n("SELECT count(*) n FROM operations WHERE action IN ('pause','pause_all') AND state IN ('pending','confirmed','unknown') AND created_at > ? AND created_at <= ?")};
}

export interface Notifications { tick(): Promise<void>; stop(): Promise<void> }
export interface NotificationDeps { env?: PushEnv; options?: PushOptions; now?: () => number; slot?: (epoch: number) => number }
/** Setup errors with these fixed codes (from ntfySettings) may be named in the log; anything else is logged by tag only. */
const SETTING_CODE = /^(invalid_ntfy_(url|topic|token)|ntfy_token_requires_https)$/;

/**
 * Starts the push watcher and (if digest.enabled) the weekly digest. Returns null, creating no timer, table or connection, unless push.enabled.
 * Any initialisation failure (bad ntfy settings, unreadable state) is logged as a fixed tag and leaves notifications disabled: it never blocks policy startup.
 * Afterwards nothing here can throw into request handling: every pass is caught. Recipients are whoever holds the private ntfy topic; keep it to admins.
 */
export function startNotifications(config: IntegrationConfig, store: Db, deps: NotificationDeps = {}): Notifications | null {
    if (config.push?.enabled !== true) return null;
    const sink = deps.options?.log ?? ((line: string) => process.stderr.write(line));
    // Reporting a problem must never be a second problem.
    const log = (line: string) => { try { sink(line); } catch { /* nowhere left to report */ } };
    try { return begin(config, store, deps, log); } catch (error) {
        const code = error instanceof Error ? error.message : '';
        log(SETTING_CODE.test(code) ? `notifications_disabled ${code}\n` : 'notifications_init_failed\n');
        return null;
    }
}

function begin(config: IntegrationConfig, store: Db, deps: NotificationDeps, log: (line: string) => unknown): Notifications {
    const push = new NtfyPush(ntfySettings(deps.env ?? process.env), config.origin, {...deps.options, log});
    const now = deps.now ?? (() => Math.floor(Date.now() / 1000)), slotOf = deps.slot ?? latestDigestSlot, digestOn = config.digest?.enabled === true;
    const alerts = stateStore(store, 'alert_push_id'), digest = digestOn ? stateStore(store, 'digest_slot') : null;
    // First enable starts from now: no backlog of old alerts and no catch-up digest for the week before. (Turning push or digest off and on again later keeps the old marks, so it sends one backlog push and one catch-up digest.)
    if (!alerts.exists()) alerts.write(store.get<{m: number}>('SELECT COALESCE(MAX(id),0) m FROM parent_alerts')!.m);
    if (digest && !digest.exists()) digest.write(slotOf(now()));
    const alertPass = async () => {
        const last = alerts.read(), top = store.get<{m: number | null}>("SELECT MAX(id) m FROM parent_alerts WHERE id > ? AND state='open'", last)!.m;
        if (top === null) return;
        if ((await push.send({kind: 'alert'}, shutdown.signal)).ok) alerts.write(top);
    };
    const deferralLogged = {slot: 0};
    let flight: Promise<void> | null = null;
    const shutdown = new AbortController();
    const pass = async () => {
        try { await alertPass(); } catch { log('push_alert_pass_failed\n'); }
        try { if (digest && !shutdown.signal.aborted) await digestTick({now, slot: slotOf, counts: (from, to) => weeklyCounts(store, from, to), send: m => push.send(m, shutdown.signal), state: digest, log, deferralLogged}); } catch { log('digest_pass_failed\n'); }
    };
    const tick = (): Promise<void> => {
        if (flight) return flight;
        // Never rejects: the interval discards this promise, and an unhandled rejection can end the process.
        const current = pass().catch(() => undefined).finally(() => { if (flight === current) flight = null; });
        flight = current;
        return current;
    };
    const timer = setInterval(() => { void tick(); }, NOTIFY_POLL_MS);
    timer.unref();
    // Aborts sends in flight and waits for the pass at most STOP_WAIT_MS, so shutdown cannot outlast the service unit's stop timeout.
    return {tick, stop: async () => {
        clearInterval(timer); shutdown.abort();
        let wait: ReturnType<typeof setTimeout> | undefined;
        const bound = new Promise<void>(resolve => { wait = setTimeout(resolve, STOP_WAIT_MS); wait.unref(); });
        try { await Promise.race([flight ?? Promise.resolve(), bound]); } finally { clearTimeout(wait); }
    }};
}
