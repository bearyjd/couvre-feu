import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import type { Stats } from 'node:fs';
import { dirname } from 'node:path';
import { object } from '../../shared/src/json.ts';
import { id } from '../../shared/src/router-schema.ts';
// A cycle (integration-config imports this file) that is safe: only the hoisted function declaration is used, and only at call time.
import { requirePrivatePath } from './integration-config.ts';

export type ContentFilterMode = 'off' | 'owner' | 'parents';
/**
 * The manifest's contentFilter setting (PRP-006 A2). Absent is off. It names where the API key lives and never contains it.
 * When mode is owner or parents, apiKeyFile, defaultProfile and a non-empty profiles map are all present.
 */
export interface ContentFilterConfig {
    mode: ContentFilterMode; apiKeyFile?: string; defaultProfile?: string; profiles?: Readonly<Record<string, string>>;
}
/**
 * The NextDNS profile id rule. content-filter-state.test.ts asserts this equals the NextDNS client's own pattern.
 * The key and profile ids are separate things: this validates profile ids only.
 */
export const PROFILE_ID_PATTERN = /^[A-Za-z0-9]{4,32}$/;
export const CONTENT_FILTER_PROFILE_LIMIT = 64;
const API_KEY_FILE_LIMIT = 255;
const KEY_BYTES_LIMIT = 256;
/** Printable ASCII with no space, control or non-ASCII characters. */
const KEY_CHARSET = /^[\x21-\x7e]+$/;
function bad(): never { throw new Error('invalid_content_filter'); }

function profileId(value: unknown): string {
    if (typeof value !== 'string' || !PROFILE_ID_PATTERN.test(value)) bad();
    return value;
}
/** Absolute and already normalized: no '.', '..', empty ('//' or trailing slash) segments. */
function keyFilePath(value: unknown): string {
    if (typeof value !== 'string' || value.length > API_KEY_FILE_LIMIT || !/^\/[A-Za-z0-9._/-]+$/.test(value)) bad();
    if (value.split('/').slice(1).some(segment => segment === '' || segment === '.' || segment === '..')) bad();
    return value;
}
/**
 * Person ids are checked for shape only: the manifest seeds a single person and children live in the database,
 * so the other ids are not knowable at parse time. The profiles map is bounded.
 */
function profileMap(value: unknown): Record<string, string> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return bad();
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > CONTENT_FILTER_PROFILE_LIMIT) bad();
    // Null prototype and frozen: a lookup of 'constructor' or 'toString' finds nothing unless that person is configured. Use Object.hasOwn.
    try { return Object.freeze(Object.assign(Object.create(null) as Record<string, string>, Object.fromEntries(entries.map(([person, profile]) => [id(person), profileId(profile)])))); } catch { return bad(); }
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
    return Object.freeze({mode, ...(apiKeyFile !== undefined ? {apiKeyFile} : {}), ...(defaultProfile !== undefined ? {defaultProfile} : {}), ...(profiles !== undefined ? {profiles} : {})});
}

export type ContentFilterKeyErrorCode = 'key_file_missing' | 'key_file_unsafe' | 'key_file_invalid';
/** The message is the code alone: never the path, never any file content, and no cause chain. */
export class ContentFilterKeyError extends Error {
    readonly code: ContentFilterKeyErrorCode;
    constructor(code: ContentFilterKeyErrorCode) { super(code); this.name = 'ContentFilterKeyError'; this.code = code; }
}
/** Every decision is made on the opened descriptor, so a path swapped after the open changes nothing. */
export interface ContentFilterKeyDeps {
    open: (path: string, flags: number) => number;
    fstat: (fd: number) => Pick<Stats, 'isFile' | 'mode' | 'size' | 'uid' | 'nlink'>;
    read: (fd: number, buffer: Buffer, offset: number, length: number) => number;
    close: (fd: number) => void;
    requirePrivateDir: (dir: string) => void;
}
/** Read-only, never follow a final symlink, never block on a FIFO. (Node's open already sets O_CLOEXEC.) */
export const KEY_OPEN_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
export const defaultKeyFs: ContentFilterKeyDeps = {
    open: (path, flags) => openSync(path, flags),
    fstat: fd => fstatSync(fd),
    read: (fd, buffer, offset, length) => readSync(fd, buffer, offset, length, null),
    close: fd => closeSync(fd),
    requirePrivateDir: dir => requirePrivatePath(dir, 'directory'),
};
const fail = (code: ContentFilterKeyErrorCode): never => { throw new ContentFilterKeyError(code); };
const missing = (error: unknown): boolean => ['ENOENT', 'ENOTDIR'].includes((error as NodeJS.ErrnoException)?.code ?? '');
const failOnIO = (error: unknown): never => error instanceof ContentFilterKeyError ? fail(error.code) : fail(missing(error) ? 'key_file_missing' : 'key_file_unsafe');
/** Reads at most KEY_BYTES_LIMIT + 1 bytes so an oversize or growing file is detected without being slurped. */
function readBounded(deps: ContentFilterKeyDeps, fd: number): Buffer {
    const buffer = Buffer.alloc(KEY_BYTES_LIMIT + 1);
    let length = 0;
    while (length < buffer.length) {
        const count = deps.read(fd, buffer, length, buffer.length - length);
        if (count <= 0) break;
        length += count;
    }
    if (length > KEY_BYTES_LIMIT) fail('key_file_invalid');
    return buffer.subarray(0, length);
}
/**
 * Reads the NextDNS API key at use time; callers must not cache it on the manifest, log it or put it in an error.
 * Supported setup: a regular file with mode 0600 or 0400, owned by the service user (root when the service runs as root),
 * with a single link, in a private directory (the manifest path rule: owned by that user, no group/other access, safe ancestors).
 * Returns the key only.
 */
export function readContentFilterKey(path: string, deps: ContentFilterKeyDeps = defaultKeyFs): string {
    try { deps.requirePrivateDir(dirname(path)); } catch (error) { return failOnIO(error); }
    let fd: number;
    try { fd = deps.open(path, KEY_OPEN_FLAGS); } catch (error) { return failOnIO(error); }
    try {
        const stat = deps.fstat(fd), uid = process.getuid?.();
        if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || uid === undefined || stat.uid !== uid) fail('key_file_unsafe');
        if (stat.size > KEY_BYTES_LIMIT) fail('key_file_invalid');
        const text = readBounded(deps, fd).toString('latin1'), key = text.endsWith('\n') ? text.slice(0, -1) : text;
        if (!KEY_CHARSET.test(key)) fail('key_file_invalid');
        return key;
    } catch (error) { return failOnIO(error); } finally { try { deps.close(fd); } catch { /* the key was already read or refused */ } }
}
