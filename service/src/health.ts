import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Store } from './db.ts';
import { INVENTORY_POLL_SECONDS } from './inventory-store.ts';

/** Everything /health may say. Add a field here only if it is safe for an unauthenticated caller to read. */
export interface HealthBody {
    ok: true;
    version: string;
    uptimeSeconds: number;
    schemaVersion: number;
    /** Coarse on purpose: true within 3 poll intervals of the last good poll, false if older, null if never polled or the feature is off. */
    inventoryFresh: boolean | null;
}
export const HEALTH_RATE_PER_MINUTE = 1200;
export const INVENTORY_FRESH_SECONDS = 3 * INVENTORY_POLL_SECONDS;
const BUILD = /^[A-Za-z0-9._+-]{1,64}$/;

/** Release identity baked at deploy time: a VERSION file next to package.json, else the package.json version plus "dev". Never shells out. */
export function buildVersion(root = new URL('../../', import.meta.url)): string {
    const read = (name: string) => { try { return readFileSync(fileURLToPath(new URL(name, root)), 'utf8').trim(); } catch { return ''; } };
    const baked = read('VERSION');
    if (BUILD.test(baked)) return baked;
    let pkg = '';
    try { pkg = String((JSON.parse(read('package.json')) as {version?: unknown}).version ?? ''); } catch { /* unknown */ }
    return `${BUILD.test(pkg) ? pkg : '0'}-dev`;
}

export class Health {
    private hits: number[] = [];
    readonly version: string;
    private readonly store: Store;
    private readonly inventoryLastOk: () => number | null;
    private readonly now: () => number;
    constructor(store: Store, inventoryLastOk: () => number | null, now: () => number, version = buildVersion()) {
        this.store = store; this.inventoryLastOk = inventoryLastOk; this.now = now; this.version = version;
    }
    schemaVersion(): number {
        const row = this.store.db.prepare('PRAGMA user_version').get() as {user_version?: unknown} | undefined;
        if (typeof row?.user_version !== 'number') throw new Error('schema_unreadable');
        return row.user_version;
    }
    /** Modest global limit (the caller behind a proxy is not distinguishable); never reveals why it answered. */
    limited(): boolean {
        const at = this.now();
        this.hits = this.hits.filter(t => t > at - 60);
        if (this.hits.length >= HEALTH_RATE_PER_MINUTE) return true;
        this.hits.push(at);
        return false;
    }
    /** Exact age of the last good inventory poll. Authenticated admin callers only; /health itself never says it. */
    inventoryAge(): number | null {
        const ok = this.inventoryLastOk();
        return ok === null ? null : Math.max(0, this.now() - ok);
    }
    /** A trivial DB read only; never touches the router. A failure is a bare null, with no detail. */
    answer(): HealthBody | null {
        try {
            this.store.get('SELECT 1');
            const age = this.inventoryAge();
            return {ok: true, version: this.version, uptimeSeconds: Math.floor(process.uptime()), schemaVersion: this.schemaVersion(),
                inventoryFresh: age === null ? null : age <= INVENTORY_FRESH_SECONDS};
        } catch { return null; }
    }
}
