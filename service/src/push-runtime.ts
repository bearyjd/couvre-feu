import type { IntegrationConfig } from './integration-config.ts';
import type { IntegrationStore } from './integration-db.ts';
import { digestTick, latestDigestSlot } from './digest.ts';
import type { DigestStateStore } from './digest.ts';
import { NtfyPush, ntfySettings } from './push-sender.ts';
import type { DigestCounts, PushEnv, PushOptions } from './push-sender.ts';

export const NOTIFY_POLL_MS = 60000;
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

export interface Notifications { tick(): Promise<void>; stop(): void }
export interface NotificationDeps { env?: PushEnv; options?: PushOptions; now?: () => number }

/**
 * Starts the push watcher and (if digest.enabled) the weekly digest. Returns null, creating no timer, table or connection, unless push.enabled.
 * Settings are validated here, so a bad topic or URL stops startup. Afterwards nothing here can throw into request handling: every pass is caught.
 * Recipients are whoever the owner subscribes to the private ntfy topic; keep that topic to admins.
 */
export function startNotifications(config: IntegrationConfig, store: Db, deps: NotificationDeps = {}): Notifications | null {
    if (config.push?.enabled !== true) return null;
    const push = new NtfyPush(ntfySettings(deps.env ?? process.env), config.origin, deps.options);
    const now = deps.now ?? (() => Math.floor(Date.now() / 1000)), log = deps.options?.log ?? (line => process.stderr.write(line));
    const alerts = stateStore(store, 'alert_push_id'), digest = stateStore(store, 'digest_slot');
    // Enabling starts from now: no backlog of old alerts and no catch-up digest for the week before the flag was turned on.
    if (!alerts.exists()) alerts.write(store.get<{m: number}>('SELECT COALESCE(MAX(id),0) m FROM parent_alerts')!.m);
    if (config.digest?.enabled === true && !digest.exists()) digest.write(latestDigestSlot(now()));
    const alertPass = async () => {
        const last = alerts.read(), top = store.get<{m: number | null}>("SELECT MAX(id) m FROM parent_alerts WHERE id > ? AND state='open'", last)!.m;
        if (top === null) return;
        if ((await push.send({kind: 'alert'})).ok) alerts.write(top);
    };
    let running = false;
    const tick = async () => {
        if (running) return;
        running = true;
        try { await alertPass(); } catch { log('push_alert_pass_failed\n'); }
        try { if (config.digest?.enabled === true) await digestTick({now, counts: (from, to) => weeklyCounts(store, from, to), send: m => push.send(m), state: digest, log}); } catch { log('digest_pass_failed\n'); }
        running = false;
    };
    const timer = setInterval(() => { void tick(); }, NOTIFY_POLL_MS);
    timer.unref();
    return {tick, stop: () => clearInterval(timer)};
}
