import { object, parseJSON } from './json.ts';
import { mac } from './router-schema.ts';
import { AppError } from './errors.ts';

/**
 * Output contract of `cfctl rpc-inventory --json`, version 1 (docs/contracts/tier1-rpc.md section 2). Strict: any violation rejects the
 * WHOLE reply. Hostnames are device-reported text; they are validated here and are never identity.
 */
export const MAX_INVENTORY_DEVICES = 256;
export const MAX_INVENTORY_ERRORS = 16;
export const MAX_INVENTORY_IPV4 = 4;
/** A reply must be strictly smaller than this (the transport stdout cap is 131072 bytes). */
export const MAX_INVENTORY_BYTES = 131072;
export const INVENTORY_SOURCES = ['lease', 'neigh', 'both'] as const;
export type InventorySource = typeof INVENTORY_SOURCES[number];
export interface InventoryDevice { mac: string; ipv4: string[]; hostname: string | null; source: InventorySource }
export interface RouterInventory {
    inventory_version: 1; generation: string; routerTime: number; devices: InventoryDevice[]; truncated: boolean; errors: string[];
}
export interface InventoryContext { generation: string; protectedMacs: readonly string[] }
export type InventoryClassification = {ok: true; inventory: RouterInventory} | {ok: false; code: string};
const HOSTNAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const IPV4 = /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/;
/** Violations the poller reports under their own name, so inventory_state.last_error tells the router side exactly what failed. */
const DISTINCT_CODES = ['protected_mac_listed', 'ipv4_not_sorted'];
const invalid = (): never => { throw new AppError(400, 'invalid_router_inventory'); };
function ipv4(value: unknown): string {
    if (typeof value !== 'string' || !IPV4.test(value) || value.split('.').some(part => Number(part) > 255)) invalid();
    return value as string;
}
function device(value: unknown): InventoryDevice {
    const o = object(value, ['mac', 'ipv4', 'hostname', 'source']);
    if (!Array.isArray(o.ipv4) || o.ipv4.length > MAX_INVENTORY_IPV4) invalid();
    const addresses = (o.ipv4 as unknown[]).map(ipv4);
    // Strictly ascending in C-locale string order (what `sort -u` emits) is both "sorted" and "unique".
    if (addresses.some((a, i) => i > 0 && !(addresses[i - 1] < a))) throw new AppError(400, 'ipv4_not_sorted');
    if (o.hostname !== null && (typeof o.hostname !== 'string' || !HOSTNAME.test(o.hostname))) invalid();
    if (typeof o.source !== 'string' || !(INVENTORY_SOURCES as readonly string[]).includes(o.source)) invalid();
    return {mac: mac(o.mac), ipv4: addresses, hostname: o.hostname as string | null, source: o.source as InventorySource};
}
/** Validates a parsed value completely and returns a fresh copy. The version is checked before the strict key check. */
export function normalizeRouterInventory(value: unknown, context: InventoryContext): RouterInventory {
    if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
    if ((value as Record<string, unknown>).inventory_version !== 1) throw new AppError(400, 'unknown_inventory_version');
    try {
        const o = object(value, ['inventory_version', 'generation', 'routerTime', 'devices', 'truncated', 'errors']);
        if (typeof o.generation !== 'string' || !/^[0-9a-f]{64}$/.test(o.generation) || o.generation !== context.generation) invalid();
        if (typeof o.routerTime !== 'number' || !Number.isSafeInteger(o.routerTime) || o.routerTime < 0) invalid();
        if (typeof o.truncated !== 'boolean') invalid();
        if (!Array.isArray(o.devices) || o.devices.length > MAX_INVENTORY_DEVICES || !Array.isArray(o.errors) || o.errors.length > MAX_INVENTORY_ERRORS) invalid();
        const devices = (o.devices as unknown[]).map(device);
        if (devices.some((d, i) => i > 0 && !(devices[i - 1].mac < d.mac))) invalid(); // ascending, therefore unique
        const errors = (o.errors as unknown[]).map(e => typeof e === 'string' && ERROR_CODE.test(e) ? e : invalid());
        if (devices.some(d => context.protectedMacs.includes(d.mac))) throw new AppError(400, 'protected_mac_listed');
        return {inventory_version: 1, generation: o.generation as string, routerTime: o.routerTime as number, devices, truncated: o.truncated as boolean, errors};
    } catch (error) {
        throw error instanceof AppError && DISTINCT_CODES.includes(error.code) ? error : new AppError(400, 'invalid_router_inventory');
    }
}
/**
 * Raw-text gate run before JSON.parse: printable ASCII (plus JSON whitespace), no backslash (so no \\u escapes) and integer-only numbers
 * (no 1.0, 5e0 or -0). Strings contain no backslash, so they are exactly the `"[^"]*"` runs; numbers are what remains outside them.
 */
export function assertPlainInventoryText(text: string): void {
    if (/[^\x20-\x7e\n\r\t]/.test(text) || text.includes('\\')) invalid();
    for (const token of text.replace(/"[^"]*"/g, '""').match(/-?[0-9][0-9.eE+-]*/g) ?? []) if (!/^(?:0|[1-9][0-9]*)$/.test(token)) invalid();
}
/**
 * Untrusted router stdout. Not the router-mode JSON: that mode rejects the contract's camelCase `routerTime` key, so this is the non-router
 * parse mode plus assertPlainInventoryText above. The field patterns (hostnames, addresses, codes, generation) then pin the rest.
 */
export function parseRouterInventory(text: string, context: InventoryContext): RouterInventory {
    if (typeof text !== 'string') invalid();
    try { assertPlainInventoryText(text); } catch { return invalid(); }
    let parsed: unknown;
    try { parsed = parseJSON(text, false, MAX_INVENTORY_BYTES - 1); } catch { return invalid(); }
    return normalizeRouterInventory(parsed, context);
}
/** Never throws. `invalid_command` is the exact reply of a new cfctl-ssh in front of an old cfctl (D7). */
export function classifyInventoryReply(text: string, context: InventoryContext): InventoryClassification {
    if (text.trim() === '') return {ok: false, code: 'empty_reply'};
    try {
        const parsed = parseJSON(text, false, MAX_INVENTORY_BYTES - 1) as Record<string, unknown> | null;
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length === 2 && parsed.ok === false
            && Array.isArray(parsed.errors) && parsed.errors.length === 1 && parsed.errors[0] === 'invalid_command') return {ok: false, code: 'invalid_command'};
    } catch { return {ok: false, code: 'invalid_router_inventory'}; }
    try { return {ok: true, inventory: parseRouterInventory(text, context)}; }
    catch (error) { return {ok: false, code: error instanceof AppError && ['unknown_inventory_version', ...DISTINCT_CODES].includes(error.code) ? error.code : 'invalid_router_inventory'}; }
}
/** "Private address" hint: the locally-administered bit, i.e. the second hex digit of the first octet is one of 2367abef. Never a gate. */
export function isPrivateAddress(mac: string): boolean {
    return /^[0-9a-f][2367abef]:/.test(mac);
}
