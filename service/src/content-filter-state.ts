import { createHash } from 'node:crypto';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import type { Store } from './db.ts';
import { DOMAIN, SERVICE_ID } from './nextdns-client.ts';

/**
 * The desired filter of one child (PRP-006 A3). Strict and bounded; the canonical form is sorted and de-duplicated, so equal
 * filters hash equally. denylist/allowlist hold parent-chosen domains: they live in the database because applying them needs them,
 * and they never go to audit rows, logs, alerts or error text. Nothing here talks to NextDNS or the router.
 */
export interface ContentFilterDesired {
    readonly categories: readonly string[]; readonly services: readonly string[];
    readonly safeSearch: boolean; readonly youtubeRestrictedMode: boolean; readonly blockBypass: boolean;
    readonly denylist: readonly string[]; readonly allowlist: readonly string[];
}
export type FilterState = 'applied' | 'pending' | 'not_confirmed' | 'drift';
export const FILTER_STATES: readonly FilterState[] = Object.freeze(['applied', 'pending', 'not_confirmed', 'drift']);
export const FILTER_LIMITS = Object.freeze({categories: 64, services: 256, denylist: 500, allowlist: 500});
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const bad = (): never => { throw new AppError(400, 'invalid_filter'); };

/** Strict hostname: lowercase ASCII letters, digits and hyphens, 2+ labels, no IP literal, no wildcard, at most 253 characters. */
export function hostname(value: unknown): string {
    if (typeof value !== 'string' || value.length > 253) return bad();
    const host = value.toLowerCase(), labels = host.split('.');
    if (labels.length < 2 || !labels.every(label => HOST_LABEL.test(label)) || /^[0-9]+$/.test(labels[labels.length - 1]!) || !DOMAIN.test(host)) return bad();
    return host;
}
const serviceId = (value: unknown): string => typeof value === 'string' && SERVICE_ID.test(value) ? value : bad();
const flag = (value: unknown): boolean => typeof value === 'boolean' ? value : bad();
function list(value: unknown, max: number, item: (entry: unknown) => string): string[] {
    if (!Array.isArray(value) || value.length > max) return bad();
    return [...new Set(value.map(item))].sort();
}
/** Sorted, de-duplicated copy: the one shape that is hashed, stored and compared. */
export function canonicalize(desired: ContentFilterDesired): ContentFilterDesired {
    const sorted = (items: readonly string[]) => [...new Set(items)].sort();
    return Object.freeze({
        allowlist: sorted(desired.allowlist), blockBypass: desired.blockBypass, categories: sorted(desired.categories), denylist: sorted(desired.denylist),
        safeSearch: desired.safeSearch, services: sorted(desired.services), youtubeRestrictedMode: desired.youtubeRestrictedMode,
    });
}
/** Throws AppError(400, 'invalid_filter') and nothing else: the message never echoes any part of the input. */
export function parseDesired(value: unknown): ContentFilterDesired {
    let input: Record<string, unknown>;
    try { input = object(value, ['categories', 'services', 'safeSearch', 'youtubeRestrictedMode', 'blockBypass', 'denylist', 'allowlist']); } catch { return bad(); }
    return canonicalize({
        categories: list(input.categories, FILTER_LIMITS.categories, serviceId), services: list(input.services, FILTER_LIMITS.services, serviceId),
        safeSearch: flag(input.safeSearch), youtubeRestrictedMode: flag(input.youtubeRestrictedMode), blockBypass: flag(input.blockBypass),
        denylist: list(input.denylist, FILTER_LIMITS.denylist, hostname), allowlist: list(input.allowlist, FILTER_LIMITS.allowlist, hostname),
    });
}
export const canonicalJSON = (desired: ContentFilterDesired): string => JSON.stringify(canonicalize(desired));
export const desiredSha256 = (desired: ContentFilterDesired): string => createHash('sha256').update(canonicalJSON(desired)).digest('hex');

/**
 * Does `next` weaken `previous`? Removing a category, service or denylist entry, adding an allowlist entry, or turning safeSearch,
 * youtubeRestrictedMode or blockBypass off. With no previous desired state there is no baseline to prove the change is not a
 * weakening of what NextDNS holds, so it counts as loosening (fail closed).
 */
export function isLoosening(previous: ContentFilterDesired | null, next: ContentFilterDesired): boolean {
    if (previous === null) return true;
    const dropped = (before: readonly string[], after: readonly string[]) => before.some(entry => !after.includes(entry));
    return dropped(previous.categories, next.categories) || dropped(previous.services, next.services) || dropped(previous.denylist, next.denylist)
        || dropped(next.allowlist, previous.allowlist)
        || (previous.safeSearch && !next.safeSearch) || (previous.youtubeRestrictedMode && !next.youtubeRestrictedMode) || (previous.blockBypass && !next.blockBypass);
}

export interface FilterRecord {
    readonly revision: number; readonly state: FilterState; readonly stateAt: number; readonly desired: ContentFilterDesired; readonly desiredSha256: string;
}
/** 'applied' carries the hash of what NextDNS returned on read-back; the store refuses it unless it equals the desired hash. */
export type FilterOutcome = {readonly state: 'applied'; readonly readBackSha256: string} | {readonly state: 'pending' | 'not_confirmed' | 'drift'};
interface Row { person_id: string; revision: number; desired_json: string; desired_sha256: string; state: FilterState; state_at: number }

export class ContentFilterStore {
    readonly store: Store;
    readonly now: () => number;
    constructor(store: Store, now: () => number = () => Math.floor(Date.now() / 1000)) { this.store = store; this.now = now; }
    get(person: string): FilterRecord | undefined {
        const row = this.store.get<Row>('SELECT person_id,revision,desired_json,desired_sha256,state,state_at FROM content_filter_desired WHERE person_id=?', person);
        return row && {revision: row.revision, state: row.state, stateAt: row.state_at, desired: parseDesired(JSON.parse(row.desired_json)), desiredSha256: row.desired_sha256};
    }
    /** Stores a new revision as 'pending'. Joins the caller's transaction when there is one. */
    put(person: string, desired: ContentFilterDesired, actor: string): FilterRecord {
        const write = (): void => {
            const canonical = canonicalize(desired), at = this.now(), revision = (this.store.get<{revision: number}>('SELECT revision FROM content_filter_desired WHERE person_id=?', person)?.revision ?? 0) + 1;
            this.store.run(`INSERT INTO content_filter_desired(person_id,revision,desired_json,desired_sha256,state,applied_sha256,state_at,updated_at,updated_by) VALUES(?,?,?,?,'pending',NULL,?,?,?)
                ON CONFLICT(person_id) DO UPDATE SET revision=excluded.revision,desired_json=excluded.desired_json,desired_sha256=excluded.desired_sha256,state='pending',state_at=excluded.state_at,updated_at=excluded.updated_at,updated_by=excluded.updated_by`,
            person, revision, canonicalJSON(canonical), desiredSha256(canonical), at, at, actor);
        };
        if (this.store.db.isTransaction) write(); else this.store.transaction(write);
        return this.get(person)!;
    }
    /** Records the outcome of reconciling `revision`; false when a newer revision replaced it meanwhile. 'applied' is refused unless the read-back hash equals the desired hash. */
    recordOutcome(person: string, revision: number, outcome: FilterOutcome): boolean {
        const row = this.store.get<Row>('SELECT * FROM content_filter_desired WHERE person_id=? AND revision=?', person, revision);
        if (!row) return false;
        if (outcome.state === 'applied') {
            if (outcome.readBackSha256 !== row.desired_sha256) throw new Error('applied_requires_matching_read_back');
            this.store.run('UPDATE content_filter_desired SET state=?,applied_sha256=?,state_at=? WHERE person_id=? AND revision=?', 'applied', outcome.readBackSha256, this.now(), person, revision);
        } else this.store.run('UPDATE content_filter_desired SET state=?,state_at=? WHERE person_id=? AND revision=?', outcome.state, this.now(), person, revision);
        return true;
    }
}
