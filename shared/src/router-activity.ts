import { object, parseJSON } from './json.ts';
import { id, mac } from './router-schema.ts';
import { AppError } from './errors.ts';

/** Output contract of `cfctl rpc-activity --json`, version 1. Counters are cumulative and reset when counter_epoch changes. */
export const MAX_ACTIVITY_DEVICES = 256;
export const MAX_ACTIVITY_ERRORS = 16;
export const MAX_ACTIVITY_BYTES = 131072;
export const NEIGHBOR_STATES = ['REACHABLE', 'STALE', 'DELAY', 'PROBE', 'FAILED', 'ABSENT'] as const;
export const OFFLOAD_STATES = ['on', 'off', 'unknown'] as const;
export type NeighborState = typeof NEIGHBOR_STATES[number];
export type OffloadState = typeof OFFLOAD_STATES[number];
export interface ActivityDevice {
    person: string; mac: string; ip: string | null; neighbor: NeighborState;
    tx_bytes: number; rx_bytes: number; tx_packets: number; rx_packets: number; blocked_packets: number;
}
export interface RouterActivity {
    version: 1; router_epoch: number; counter_epoch: number; offload: OffloadState; devices: ActivityDevice[]; errors: string[];
}
const invalid = (): never => { throw new AppError(400, 'invalid_router_activity'); };
/** JavaScript cannot represent larger integers exactly, so the practical bound is 2^53 - 1. */
function counter(value: unknown): number {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) invalid();
    return value as number;
}
function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T {
    if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) invalid();
    return value as T;
}
function ipv4(value: unknown): string {
    if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value) || value.split('.').some(part => Number(part) > 255)) invalid();
    return value as string;
}
function device(value: unknown): ActivityDevice {
    const o = object(value, ['person', 'mac', 'ip', 'neighbor', 'tx_bytes', 'rx_bytes', 'tx_packets', 'rx_packets', 'blocked_packets']);
    return {person: id(o.person), mac: mac(o.mac), ip: o.ip === null ? null : ipv4(o.ip), neighbor: oneOf(o.neighbor, NEIGHBOR_STATES),
        tx_bytes: counter(o.tx_bytes), rx_bytes: counter(o.rx_bytes), tx_packets: counter(o.tx_packets), rx_packets: counter(o.rx_packets), blocked_packets: counter(o.blocked_packets)};
}
/** Validates a parsed value completely before returning a fresh copy. Unknown or missing fields, duplicate MACs and oversize arrays are rejected. */
export function normalizeRouterActivity(value: unknown): RouterActivity {
    const o = object(value, ['version', 'router_epoch', 'counter_epoch', 'offload', 'devices', 'errors']);
    if (o.version !== 1 || !Array.isArray(o.devices) || o.devices.length > MAX_ACTIVITY_DEVICES || !Array.isArray(o.errors) || o.errors.length > MAX_ACTIVITY_ERRORS) invalid();
    const devices = (o.devices as unknown[]).map(device);
    if (new Set(devices.map(d => d.mac)).size !== devices.length) invalid();
    const errors = (o.errors as unknown[]).map(e => typeof e === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(e) ? e : invalid());
    return {version: 1, router_epoch: counter(o.router_epoch), counter_epoch: counter(o.counter_epoch), offload: oneOf(o.offload, OFFLOAD_STATES), devices, errors};
}
/** Parses untrusted router stdout using the ASCII-only duplicate-rejecting router JSON mode. */
export function parseRouterActivity(text: string): RouterActivity {
    if (typeof text !== 'string') invalid();
    return normalizeRouterActivity(parseJSON(text, true, MAX_ACTIVITY_BYTES));
}
