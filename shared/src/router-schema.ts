import { AppError } from './errors.ts';
import { object, parseJSON } from './json.ts';
export const MAX_INTEGER = 2147483647;
export const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] as const;
export type Day = typeof DAYS[number];
export interface RouterPerson {
    id: string;
    macs: string[];
}
export interface Pause {
    person: string;
    until: number;
}
export interface Schedule {
    person: string;
    id: string;
    weekdays: Day[];
    start: string;
    stop: string;
}
export interface RouterPolicy {
    version: 1;
    revision: number;
    people: RouterPerson[];
    pauses: Pause[];
    schedules: Schedule[];
    doh: {
        ipv4: string[];
        ipv6: string[];
    };
}
export interface RouterStatus {
    ok: boolean;
    desiredRevision: number;
    confirmedRevision: number | null;
    desiredPauses: Pause[];
    effectivePauses: Pause[];
    observed: {
        kids: string[];
        paused: string[];
    };
    drift: boolean;
    errors: string[];
    capabilities: {
        ipv6: boolean;
        conntrack: boolean;
        nativeKernelConfirmed: boolean;
        addressCoverageComplete: boolean;
        routerCompatibilityVerified: false;
    };
}
const bad = (message = 'invalid_policy'): never => {
    throw new AppError(400, message);
};
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
export function integer(value: unknown): number {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > MAX_INTEGER) {
        bad('invalid_integer');
    }
    return value as number;
}
export function id(value: unknown): string {
    if (typeof value !== 'string' || !/^[a-z][a-z0-9_]{0,31}$/.test(value)) {
        bad('invalid_id');
    }
    return value as string;
}
function array(value: unknown, max: number): unknown[] {
    if (!Array.isArray(value) || value.length > max) {
        bad('array_limit');
    }
    return value as unknown[];
}
export function mac(value: unknown): string {
    if (typeof value !== 'string' || !/^[0-9a-f][02468ace](?::[0-9a-f]{2}){5}$/.test(value) || value === '00:00:00:00:00:00') {
        bad('invalid_mac');
    }
    return value as string;
}
function clock(value: unknown): string {
    if (typeof value !== 'string' || !/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(value)) {
        bad('invalid_clock');
    }
    return value as string;
}
function ipv4(value: unknown): string {
    if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value) || value.split('.').some(part => +part > 255)) {
        bad('invalid_ipv4');
    }
    return value as string;
}
export function canonicalIPv6(value: unknown): string {
    if (typeof value !== 'string' || !/^[0-9a-f:]{2,39}$/.test(value) || value.includes(':::') || value.split('::').length > 2) {
        bad('invalid_ipv6');
    }
    const source = value as string, parts = source.split('::');
    const left = parts[0] ? parts[0].split(':') : [], right = parts[1] ? parts[1].split(':') : [];
    if ([...left, ...right].some(p => !/^[0-9a-f]{1,4}$/.test(p)) || (parts.length === 1 ? left.length !== 8 : left.length + right.length >= 8)) {
        bad('invalid_ipv6');
    }
    const words = (parts.length === 1 ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]).map(p => parseInt(p, 16).toString(16));
    let best = -1, count = 1;
    for (let i = 0; i < 8; i++) {
        if (words[i] !== '0') {
            continue;
        }
        let end = i;
        while (end < 8 && words[end] === '0') {
            end++;
        }
        if (end - i > count) {
            best = i;
            count = end - i;
        }
        i = end - 1;
    }
    return best < 0 ? words.join(':') : `${words.slice(0, best).join(':')}::${words.slice(best + count).join(':')}`;
}
function unique<T>(items: T[]): T[] {
    if (new Set(items).size !== items.length) {
        bad('duplicate_value');
    }
    return items;
}
/** Normalization matches the router's policy equality, including retained expired pauses. */
export function normalizePolicy(input: unknown, protectedMacs: string[] = []): RouterPolicy {
    const root = object(input, ['version', 'revision', 'people', 'pauses', 'schedules'], ['doh']);
    if (root.version !== 1) {
        bad('invalid_version');
    }
    const revision = integer(root.revision);
    const people = array(root.people, 64).map(item => {
        const p = object(item, ['id', 'macs']);
        return {
            id: id(p.id), macs: unique(array(p.macs, 32).map(mac)).sort()
        };
    }).sort((a, b) => compare(a.id, b.id));
    unique(people.map(p => p.id));
    const allMacs = unique(people.flatMap(p => p.macs));
    if (allMacs.length > 256) {
        bad('mac_limit');
    }
    if (allMacs.some(m => protectedMacs.includes(m))) {
        bad('protected_mac_overlap');
    }
    const names = new Set(people.map(p => p.id));
    const pauses = array(root.pauses, 64).map(item => {
        const p = object(item, ['person', 'until']);
        const person = id(p.person);
        if (!names.has(person)) {
            bad('undefined_person');
        }
        return {
            person, until: integer(p.until)
        };
    }).sort((a, b) => compare(a.person, b.person));
    unique(pauses.map(p => p.person));
    let expanded = 0;
    const schedules = array(root.schedules, 256).map(item => {
        const p = object(item, ['person', 'id', 'weekdays', 'start', 'stop']);
        const person = id(p.person), scheduleId = id(p.id);
        if (!names.has(person)) {
            bad('undefined_person');
        }
        const start = clock(p.start), stop = clock(p.stop);
        if (start === stop) {
            bad('empty_schedule');
        }
        const days = unique(array(p.weekdays, 7).map(day => {
            if (!DAYS.includes(day as Day)) {
                bad('invalid_weekday');
            }
            return day as Day;
        }));
        if (!days.length) {
            bad('empty_weekdays');
        }
        expanded += people.find(personEntry => personEntry.id === person)!.macs.length * (start > stop && stop !== '00:00' ? 2 : 1);
        if (expanded > 256) {
            bad('expanded_schedule_limit');
        }
        return {
            person, id: scheduleId, weekdays: DAYS.filter(d => days.includes(d)), start, stop
        };
    }).sort((a, b) => compare(`${a.person}/${a.id}`, `${b.person}/${b.id}`));
    unique(schedules.map(s => `${s.person}/${s.id}`));
    const doh = root.doh === undefined ? {
        ipv4: [], ipv6: []
    } : object(root.doh, ['ipv4', 'ipv6']);
    const result: RouterPolicy = {
        version: 1, revision, people, pauses, schedules, doh: {
            ipv4: unique(array(doh.ipv4, 256).map(ipv4)).sort(), ipv6: unique(array(doh.ipv6, 256).map(canonicalIPv6)).sort()
        }
    };
    // Even constructed policies must stay within the actual parser's byte/node/string bounds.
    parseJSON(JSON.stringify(result), true);
    return result;
}
export function parsePolicy(input: string, protectedMacs: string[] = []): RouterPolicy {
    return normalizePolicy(parseJSON(input, true), protectedMacs);
}
export function policyJSON(policy: RouterPolicy): string {
    return JSON.stringify(normalizePolicy(policy));
}
export function effectivePauses(policy: RouterPolicy, now: number): Pause[] {
    return policy.pauses.filter(p => p.until === 0 || p.until > now);
}
export function scheduleBlocked(policy: RouterPolicy, person: string, now: number): boolean {
    // Fictional router explicitly uses UTC; deployment timezone/DST compatibility is not claimed.
    const date = new Date(now * 1000), day = (date.getUTCDay() + 6) % 7, previous = (day + 6) % 7;
    const time = `${String(date.getUTCHours()).padStart(2, '0')}:${String(date.getUTCMinutes()).padStart(2, '0')}`;
    return policy.schedules.some(s => s.person === person && (s.start < s.stop
        ? s.weekdays.includes(DAYS[day]) && time >= s.start && time < s.stop
        : (s.weekdays.includes(DAYS[day]) && time >= s.start) || (s.weekdays.includes(DAYS[previous]) && time < s.stop)));
}
export function healthyConfirmation(status: RouterStatus, policy: RouterPolicy, now: number, requireIPv6 = true): boolean {
    const kids = policy.people.flatMap(p => p.macs).sort();
    const paused = effectivePauses(policy, now).flatMap(p => policy.people.find(person => person.id === p.person)!.macs).sort();
    return status.ok === true && status.desiredRevision === policy.revision && status.confirmedRevision === policy.revision && status.drift === false && status.errors.length === 0
        && (!requireIPv6 || status.capabilities.ipv6) && status.capabilities.conntrack && status.capabilities.nativeKernelConfirmed && status.capabilities.addressCoverageComplete
        && JSON.stringify([...status.observed.kids].sort()) === JSON.stringify(kids) && JSON.stringify([...status.observed.paused].sort()) === JSON.stringify(paused)
        && JSON.stringify(status.desiredPauses) === JSON.stringify(policy.pauses) && JSON.stringify(status.effectivePauses) === JSON.stringify(effectivePauses(policy, now));
}
