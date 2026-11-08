import { constants, lstatSync, readFileSync } from 'node:fs';
import type { Stats } from 'node:fs';
import { object } from '../../shared/src/json.ts';
import { id } from '../../shared/src/router-schema.ts';

export type ContentFilterMode = 'off' | 'owner' | 'parents';
/**
 * The manifest's contentFilter setting (PRP-006 A2). Absent is off. It names where the API key lives and never contains it.
 * When mode is owner or parents, apiKeyFile, defaultProfile and a non-empty profiles map are all present.
 */
export interface ContentFilterConfig {
    mode: ContentFilterMode; apiKeyFile?: string; defaultProfile?: string; profiles?: Readonly<Record<string, string>>;
}
/**
 * The NextDNS profile id rule. A later PR asserts this equals the NextDNS client's own pattern.
 * The key and profile ids are separate things: this validates profile ids only.
 */
export const PROFILE_ID_PATTERN = /^[A-Za-z0-9]{4,32}$/;
export const CONTENT_FILTER_PROFILE_LIMIT = 64;
const API_KEY_FILE_LIMIT = 255;
const KEY_BYTES_LIMIT = 256;
const bad = (): never => { throw new Error('invalid_content_filter'); };

function profileId(value: unknown): string {
    if (typeof value !== 'string' || !PROFILE_ID_PATTERN.test(value)) bad();
    return value as string;
}
/** Absolute and already normalized: no '.', '..', empty ('//' or trailing slash) segments. */
function keyFilePath(value: unknown): string {
    if (typeof value !== 'string' || value.length > API_KEY_FILE_LIMIT || !/^\/[A-Za-z0-9._/-]+$/.test(value)) bad();
    if ((value as string).split('/').slice(1).some(segment => segment === '' || segment === '.' || segment === '..')) bad();
    return value as string;
}
/**
 * Person ids are checked for shape only: the manifest seeds a single person and children live in the database,
 * so the other ids are not knowable at parse time. The profiles map is bounded.
 */
function profileMap(value: unknown): Record<string, string> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return bad();
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > CONTENT_FILTER_PROFILE_LIMIT) bad();
    try { return Object.fromEntries(entries.map(([person, profile]) => [id(person), profileId(profile)])); } catch { return bad(); }
}
export function parseContentFilter(value: unknown): ContentFilterConfig | undefined {
    if (value === undefined) return undefined;
    let settings: Record<string, unknown>;
    try { settings = object(value, ['mode'], ['apiKeyFile', 'defaultProfile', 'profiles']); } catch { return bad(); }
    if (!['off', 'owner', 'parents'].includes(settings.mode as string)) bad();
    const mode = settings.mode as ContentFilterMode;
    const apiKeyFile = settings.apiKeyFile === undefined ? undefined : keyFilePath(settings.apiKeyFile);
    const defaultProfile = settings.defaultProfile === undefined ? undefined : profileId(settings.defaultProfile);
    const profiles = settings.profiles === undefined ? undefined : profileMap(settings.profiles);
    if (mode !== 'off' && (apiKeyFile === undefined || defaultProfile === undefined || profiles === undefined || Object.keys(profiles).length === 0)) bad();
    return {mode, ...(apiKeyFile !== undefined ? {apiKeyFile} : {}), ...(defaultProfile !== undefined ? {defaultProfile} : {}), ...(profiles !== undefined ? {profiles} : {})};
}

export type ContentFilterKeyErrorCode = 'key_file_missing' | 'key_file_unsafe' | 'key_file_invalid';
/** The message is the code alone: never the path, never any file content. */
export class ContentFilterKeyError extends Error {
    readonly code: ContentFilterKeyErrorCode;
    constructor(code: ContentFilterKeyErrorCode) { super(code); this.name = 'ContentFilterKeyError'; this.code = code; }
}
export interface ContentFilterKeyDeps {
    lstat: (path: string) => Pick<Stats, 'isFile' | 'isSymbolicLink' | 'mode' | 'size' | 'uid'>;
    readFile: (path: string) => Buffer;
}
const realFs: ContentFilterKeyDeps = {
    lstat: path => lstatSync(path),
    // O_NOFOLLOW closes the window between the lstat and the read.
    readFile: path => readFileSync(path, {flag: constants.O_RDONLY | constants.O_NOFOLLOW}),
};
const fail = (code: ContentFilterKeyErrorCode): never => { throw new ContentFilterKeyError(code); };
const missing = (error: unknown): boolean => ['ENOENT', 'ENOTDIR'].includes((error as NodeJS.ErrnoException)?.code ?? '');
/**
 * Reads the NextDNS API key at use time; callers must not cache it on the manifest, log it or put it in an error.
 * The supported setup is a root-only 0600 or 0400 regular file owned by the service user. Returns the key only.
 */
export function readContentFilterKey(path: string, deps: ContentFilterKeyDeps = realFs): string {
    let stat: ReturnType<ContentFilterKeyDeps['lstat']>;
    try { stat = deps.lstat(path); } catch (error) { return fail(missing(error) ? 'key_file_missing' : 'key_file_unsafe'); }
    if (stat.isSymbolicLink() || !stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) fail('key_file_unsafe');
    if (stat.size > KEY_BYTES_LIMIT) fail('key_file_invalid');
    let data: Buffer;
    try { data = deps.readFile(path); } catch (error) { return fail(missing(error) ? 'key_file_missing' : 'key_file_unsafe'); }
    if (data.length > KEY_BYTES_LIMIT) fail('key_file_invalid');
    const text = data.toString('latin1'), key = text.endsWith('\n') ? text.slice(0, -1) : text;
    if (key.length > KEY_BYTES_LIMIT || !/^[\x21-\x7e]+$/.test(key)) fail('key_file_invalid');
    return key;
}
