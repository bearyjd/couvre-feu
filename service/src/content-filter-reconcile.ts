import { NextDnsError } from './nextdns-client.ts';
import type { ListEntry, NextDnsClient } from './nextdns-client.ts';
import { readContentFilterKey } from './content-filter-config.ts';
import { canonicalize, desiredSha256 } from './content-filter-state.ts';
import type { ContentFilterDesired, ContentFilterStore, FilterOutcome, FilterRecord } from './content-filter-state.ts';

/** The inline wait of one reconcile (PUT answers within this); the client's own retries and pagination all run inside it. */
export const RECONCILE_BUDGET_MS = 8000;
const RETRYABLE = new Set(['rate_limited', 'transport', 'timeout', 'server']);

/**
 * The key getter handed to the NextDNS client: the key file is read on every request (never cached) and any key-file problem is
 * reported as the client's closed `unauthorized` code, so no path, content or key-reader detail travels further.
 */
export function contentFilterApiKey(path: string, read: (path: string) => string = readContentFilterKey): () => string {
    return () => {
        try { return read(path); } catch { throw new NextDnsError('unauthorized'); }
    };
}

const entries = (ids: readonly string[]): ListEntry[] => ids.map(id => ({id, active: true}));
const activeIds = (list: readonly ListEntry[]): string[] => list.filter(entry => entry.active).map(entry => entry.id);
type Call = {readonly signal: AbortSignal};

async function write(client: NextDnsClient, profile: string, desired: ContentFilterDesired, call: Call): Promise<void> {
    await client.setParentalControl(profile, {safeSearch: desired.safeSearch, youtubeRestrictedMode: desired.youtubeRestrictedMode, blockBypass: desired.blockBypass}, call);
    await client.setList(profile, 'services', entries(desired.services), call);
    await client.setList(profile, 'categories', entries(desired.categories), call);
    await client.setList(profile, 'denylist', entries(desired.denylist), call);
    await client.setList(profile, 'allowlist', entries(desired.allowlist), call);
}
/** What NextDNS holds now, in the desired shape. Only active entries count: an inactive entry filters nothing. */
async function readBack(client: NextDnsClient, profile: string, call: Call): Promise<ContentFilterDesired> {
    const parental = await client.getParentalControl(profile, call);
    const [denylist, allowlist] = [await client.getList(profile, 'denylist', call), await client.getList(profile, 'allowlist', call)];
    return canonicalize({
        categories: activeIds(parental.categories), services: activeIds(parental.services), safeSearch: parental.safeSearch,
        youtubeRestrictedMode: parental.youtubeRestrictedMode, blockBypass: parental.blockBypass === true, denylist: activeIds(denylist), allowlist: activeIds(allowlist),
    });
}

export interface ReconcilerOptions {
    readonly client: NextDnsClient; readonly profiles: Readonly<Record<string, string>>; readonly store: ContentFilterStore; readonly budgetMs?: number;
}
/**
 * Write the desired filter to NextDNS, read it back, diff. The stop rule of PRP-006: 'applied' only when the read-back equals the
 * desired filter. A retryable write failure leaves 'pending'; any other failure, and any read-back failure, is 'not_confirmed'; a
 * read-back that differs is 'drift'. Never throws, never logs, and keeps nothing from NextDNS beyond the comparison.
 */
export class ContentFilterReconciler {
    private readonly options: ReconcilerOptions;
    private readonly tails = new Map<string, Promise<unknown>>();
    constructor(options: ReconcilerOptions) { this.options = options; }
    /** Whether this child has a NextDNS profile in the manifest. */
    configured(person: string): boolean { return Object.hasOwn(this.options.profiles, person); }
    /** Runs one at a time per child; each run reads the newest revision when it starts. */
    reconcile(person: string): Promise<FilterRecord | undefined> {
        const run = (this.tails.get(person) ?? Promise.resolve()).then(() => this.run(person));
        this.tails.set(person, run);
        const clear = () => { if (this.tails.get(person) === run) this.tails.delete(person); };
        run.then(clear, clear);
        return run;
    }
    /** Never rejects: a store failure leaves the record as it was (still pending) and the caller carries on. */
    private async run(person: string): Promise<FilterRecord | undefined> {
        try {
            const {store, profiles} = this.options, record = store.get(person);
            if (!record || !this.configured(person)) return record;
            const outcome = await this.attempt(profiles[person]!, record).catch((): FilterOutcome => ({state: 'not_confirmed'}));
            try { store.recordOutcome(person, record.revision, outcome); } catch { store.recordOutcome(person, record.revision, {state: 'not_confirmed'}); }
            return store.get(person);
        } catch { return undefined; }
    }
    private async attempt(profile: string, record: FilterRecord): Promise<FilterOutcome> {
        const call = {signal: AbortSignal.timeout(this.options.budgetMs ?? RECONCILE_BUDGET_MS)}, {client} = this.options;
        try { await write(client, profile, record.desired, call); } catch (error) {
            return {state: error instanceof NextDnsError && RETRYABLE.has(error.code) ? 'pending' : 'not_confirmed'};
        }
        let observed: ContentFilterDesired;
        try { observed = await readBack(client, profile, call); } catch { return {state: 'not_confirmed'}; }
        const sha = desiredSha256(observed);
        return sha === record.desiredSha256 ? {state: 'applied', readBackSha256: sha} : {state: 'drift'};
    }
}
