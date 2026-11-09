import { isPrivateAddress } from './router-inventory.ts';
import type { InventorySource } from './router-inventory.ts';

/**
 * Admin-only HINTS derived from what the inventory already holds. None of this is identity or proof: a hostname is text the device chose,
 * a vendor names the maker of the radio, and "kind" is a guess from a name. Nothing here is stored, alerted, audited or logged.
 */
export const INVENTORY_KINDS = ['phone', 'tablet', 'computer', 'console', 'tv', 'speaker', 'appliance', 'virtual', 'network', 'unknown'] as const;
export type InventoryKind = typeof INVENTORY_KINDS[number];
export const INVENTORY_PRESENCES = ['online', 'lease_only', 'recent', 'quiet'] as const;
export type InventoryPresence = typeof INVENTORY_PRESENCES[number];

/** Rules run in order on the lower-cased hostname; the first match wins. `(?<![a-z])` / `(?![a-z])` are word edges that still allow digits and `-`. */
const HOSTNAME_RULES: readonly (readonly [InventoryKind, RegExp])[] = [
    ['virtual', /(?<![a-z])(?:qemu|kvm|proxmox|vmware|virtualbox)(?![a-z])|^(?:pve|vm)\d*(?:[-_.]|$)/],
    ['console', /xbox|playstation|(?<![a-z])ps[345](?![a-z])|nintendo|^switch$|steam-?deck/],
    ['speaker', /google-?home|nest-?(?:mini|audio|hub|home)|(?<![a-z])echo(?![a-z])|alexa|sonos|homepod|home-?mini/],
    ['tv', /(?<![a-z])tv(?![a-z])|roku|chromecast|fire-?tv|apple-?tv|appletv|bravia|webos|tizen|smart-?tv|android-?tv/],
    ['tablet', /ipad|(?<![a-z])tab(?![a-z])|tablet|kindle/],
    ['phone', /iphone|(?<![a-z])pixel(?![a-z])|(?<![a-z])galaxy(?![a-z])|android|oneplus|redmi|(?<![a-z])phone(?![a-z])/],
    ['computer', /macbook|imac|mac-?(?:mini|studio)|laptop|desktop|thinkpad|chromebook|workstation|raspberrypi|(?<![a-z])pc(?![a-z])|surface|windows/],
    ['network', /router|gateway|(?<![a-z])ap(?![a-z])|access-?point|extender|repeater|mesh|(?<![a-z])nas(?![a-z])|synology|qnap|unifi|openwrt|pihole|^switch[-_]|^switch\d/],
    ['appliance', /printer|laserjet|officejet|deskjet|fridge|refrigerator|washer|dryer|dishwasher|thermostat|doorbell|camera|(?<![a-z])cam\d*(?![a-z])|(?<![a-z])(?:plug|bulb)|vacuum|roomba|^esp\d*(?:[-_]|$)|tasmota|shelly|sensor|(?<![a-z])hue(?![a-z])/],
];
/** Fallback when the hostname says nothing. Makers of general-purpose phones and PCs (Apple, Samsung, Google, ...) deliberately say nothing. */
const VENDOR_KINDS: ReadonlyMap<string, InventoryKind> = new Map<string, InventoryKind>([
    ['Sonos', 'speaker'], ['Roku', 'tv'], ['Nintendo', 'console'], ['Raspberry Pi', 'computer'],
    ['Proxmox', 'virtual'], ['QEMU/KVM (virtual)', 'virtual'],
    ['Espressif', 'appliance'], ['Tuya', 'appliance'], ['Wyze', 'appliance'], ['Arlo', 'appliance'], ['ecobee', 'appliance'], ['Ring', 'appliance'],
    ['Nest', 'appliance'], ['Signify (Philips Hue)', 'appliance'], ['Brother', 'appliance'], ['Canon', 'appliance'], ['Epson', 'appliance'],
    ['TP-Link', 'network'], ['Netgear', 'network'], ['GL.iNet', 'network'], ['Ubiquiti', 'network'], ['D-Link', 'network'], ['Synology', 'network'],
    ['QNAP', 'network'], ['Belkin', 'network'],
]);

export function kindHint(input: {hostname?: string | null; vendor?: string | null}): InventoryKind {
    const name = typeof input.hostname === 'string' ? input.hostname.slice(0, 64).toLowerCase() : '';
    for (const [kind, rule] of HOSTNAME_RULES) if (rule.test(name)) return kind;
    return (typeof input.vendor === 'string' ? VENDOR_KINDS.get(input.vendor) : undefined) ?? 'unknown';
}

/**
 * Presence from the two fields the service already stores. The router is polled every 60 s and `last_seen` advances only when the row is
 * listed with a live neighbour (source neigh or both), so `now - lastSeen` is the time since a neighbour was last seen.
 *   online      neighbour source and seen within ONLINE_SECONDS (two polls: one missed poll is tolerated)
 *   lease_only  lease source (no live neighbour) and a neighbour was last seen within RECENT_SECONDS
 *   recent      neighbour source, seen within RECENT_SECONDS but not within ONLINE_SECONDS (the row was not in the latest polls)
 *   quiet       anything older. A lease alone never proves the device is still there.
 * A last_seen in the future (clock skew) counts as just now.
 */
/** The service polls the router this often; ONLINE_SECONDS tolerates one missed poll. */
export const INVENTORY_POLL_SECONDS = 60;
export const ONLINE_SECONDS = 2 * INVENTORY_POLL_SECONDS;
export const RECENT_SECONDS = 900;
export function presenceOf(row: {source: InventorySource; lastSeen: number; now: number}): InventoryPresence {
    const age = row.now - row.lastSeen; // negative (clock skew) is "just now"
    if (age > RECENT_SECONDS) return 'quiet';
    if (row.source === 'lease') return 'lease_only';
    return age <= ONLINE_SECONDS ? 'online' : 'recent';
}

/**
 * Names that many devices share (default phone and PC names, model names). They can never link two rows. A name is generic when it is
 * shorter than 4 characters, a bare placeholder, or a default family word followed only by model-ish tokens ("iPhone-13-Pro-Max").
 */
const PLACEHOLDERS = new Set(['localhost', 'localhost.localdomain', 'unknown', 'device', 'host', 'user', 'none', 'null', 'default', 'home', 'my-phone', 'myphone']);
const FAMILY_WORDS = new Set(['android', 'iphone', 'ipad', 'ipod', 'galaxy', 'pixel', 'macbook', 'phone', 'tablet', 'windows', 'desktop', 'laptop', 'samsung', 'xiaomi', 'redmi', 'huawei', 'oneplus']);
const MODEL_TOKEN = /^(?:pro|max|plus|mini|air|ultra|se|xl|fe|lite|\d+[a-z]?|[a-z]\d{1,3}[a-z]?)$/;
export function isGenericHostname(hostname: string): boolean {
    const name = hostname.toLowerCase();
    if (name.length < 4 || PLACEHOLDERS.has(name)) return true;
    const [first, ...rest] = name.split(/[-_. ]+/);
    return FAMILY_WORDS.has(first) && rest.every(token => MODEL_TOKEN.test(token));
}

export interface HintRow {
    id: number; mac: string; hostname: string | null; firstSeen: number; lastSeen: number; source: InventorySource; protectedRow: boolean;
}
/**
 * "This new row replaces that older one": returns newRowId -> oldRowId (inventory row ids, never MACs). Strict on purpose, because a wrong
 * link is worse than none. A row R (randomized MAC, not protected, active now) is linked only when its hostname is non-generic and exactly
 * one earlier, non-protected row with the same hostname (case-insensitive) is quiet, and R is the only active randomized row with that name.
 * With several quiet predecessors the one seen last is chosen, unless two were last seen at the same moment (ambiguous: no suggestion).
 */
export function suggestReplacements(rows: readonly HintRow[], now: number): Map<number, number> {
    const result = new Map<number, number>();
    const byName = new Map<string, HintRow[]>();
    for (const r of rows) {
        if (r.protectedRow || !r.hostname || isGenericHostname(r.hostname)) continue;
        const key = r.hostname.toLowerCase();
        byName.set(key, [...(byName.get(key) ?? []), r]);
    }
    const quiet = (r: HintRow) => presenceOf({source: r.source, lastSeen: r.lastSeen, now}) === 'quiet';
    for (const group of byName.values()) {
        const active = group.filter(r => isPrivateAddress(r.mac) && !quiet(r));
        if (active.length !== 1) continue;
        const [fresh] = active;
        const older = group.filter(r => r.id !== fresh.id && r.mac !== fresh.mac && quiet(r) && r.firstSeen < fresh.firstSeen);
        const latest = Math.max(...older.map(r => r.lastSeen));
        const predecessors = older.filter(r => r.lastSeen === latest);
        if (predecessors.length === 1) result.set(fresh.id, predecessors[0].id);
    }
    return result;
}
