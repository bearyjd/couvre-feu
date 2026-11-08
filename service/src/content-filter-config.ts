/**
 * Manifest key for NextDNS content filtering (PRP-006). Absent means off. Pure validation: no file or network access here, so the
 * private manifest can be checked without touching the API key. The key file's existence, owner and mode are NOT checked here: the later
 * wiring PR (PRP-006 A2) must enforce a private 0600 file with requirePrivatePath before reading it.
 * Person ids are deliberately not checked against the manifest's single seeded person: children live in the database, so a profile map
 * may name children the manifest does not seed. An unmapped child falls back to defaultProfile.
 * Errors are codes only; no value from the manifest is echoed.
 */
import { isAbsolute, resolve } from 'node:path';
import { object } from '../../shared/src/json.ts';
import { id } from '../../shared/src/router-schema.ts';

export type ContentFilterMode = 'off' | 'owner' | 'parents';
export interface ContentFilterManifest {
    /** Who may change a child's filter: nobody, only ownerAccountId, or every parent account. Loosening always needs step-up. */
    mode: ContentFilterMode;
    /** Absolute path of the file holding the NextDNS API key (must be private 0600; enforced by the reader, see header). The key itself is never in the manifest. */
    apiKeyFile: string;
    /** The strict profile for devices that are not mapped to a child. */
    defaultProfile: string;
    /** Child person id -> that child's NextDNS profile id. */
    profiles: Record<string, string>;
}

export const PROFILE_ID = /^[a-z0-9]{4,12}$/;
export const MAX_FILTER_PROFILES = 64;
const bad = (code: string): never => { throw new Error(code); };

/** `ownerAccountId` is the manifest's owner account; 'owner' mode is refused without one, as timeRequests does. */
export function parseContentFilter(value: unknown, ownerAccountId: string | undefined): ContentFilterManifest {
    let settings: Record<string, unknown>;
    try { settings = object(value, ['mode', 'apiKeyFile', 'defaultProfile', 'profiles']); } catch { return bad('invalid_content_filter'); }
    const mode = settings.mode;
    if (mode !== 'off' && mode !== 'owner' && mode !== 'parents') bad('invalid_content_filter');
    const apiKeyFile = settings.apiKeyFile;
    if (typeof apiKeyFile !== 'string' || !isAbsolute(apiKeyFile) || resolve(apiKeyFile) !== apiKeyFile || !/^\/[A-Za-z0-9_./-]+$/.test(apiKeyFile) || apiKeyFile.length > 4096) bad('invalid_content_filter_key_file');
    const defaultProfile = settings.defaultProfile;
    if (typeof defaultProfile !== 'string' || !PROFILE_ID.test(defaultProfile)) bad('invalid_content_filter_profile');
    const raw = settings.profiles;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return bad('invalid_content_filter_profiles');
    const entries = Object.entries(raw as Record<string, unknown>);
    if (entries.length > MAX_FILTER_PROFILES) bad('invalid_content_filter_profiles');
    // Null prototype: a person id like 'constructor' must not resolve to an inherited member on lookup.
    const profiles: Record<string, string> = Object.create(null);
    const seen = new Set<string>([defaultProfile as string]);
    for (const [person, profile] of entries) {
        let personId: string;
        try { personId = id(person); } catch { return bad('invalid_content_filter_profiles'); }
        // A profile belongs to exactly one child and is never the shared default: reusing one would silently merge two children's filters.
        if (typeof profile !== 'string' || !PROFILE_ID.test(profile) || seen.has(profile)) bad('invalid_content_filter_profiles');
        seen.add(profile as string);
        profiles[personId] = profile as string;
    }
    if (mode === 'owner' && ownerAccountId === undefined) bad('owner_account_required');
    return {mode: mode as ContentFilterMode, apiKeyFile: apiKeyFile as string, defaultProfile: defaultProfile as string, profiles};
}
