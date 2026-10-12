import type { OperationDTO, PeopleDTO } from '../../shared/src/contracts.ts';

export type AlertKind = 'enforcement_unhealthy' | 'sync_failed' | 'apply_pending_too_long' | 'possible_bypass' | 'repeated_blocked_attempts' | 'time_request_pending';
export type AlertSeverity = 'info' | 'warning' | 'critical';
export type DetailValue = number | string | boolean;
/** Bounded summary only: counts, windows and operation ids. Never MACs, addresses, domains or router diagnostics. */
export type AlertDetails = Record<string, DetailValue>;
export interface AlertCandidate { kind: AlertKind; personId: string | null; severity: AlertSeverity; details: AlertDetails }

/** Produced by a separate activity-ingestion change. Rules consume this interface only; nothing here collects traffic. */
export interface ActivityDelta {
    person: string; mac: string; windowStart: number; windowEnd: number;
    txBytes: number; rxBytes: number; blockedPackets: number; enforcementActive: boolean;
}
/** Produced by a separate time-request change. */
export interface PendingTimeRequest { person: string; requestId: string; createdAt: number }

/** Observation older than this (seconds) is an alert; the 31s freshness window alone is too noisy. */
export const STALE_ALERT_SECONDS = 300;
/** An intended change still pending/unknown after this long is an alert. */
export const PENDING_ALERT_SECONDS = 120;
/** A failed/conflicting operation is only reported while it is this recent. */
export const FAILED_RECENCY_SECONDS = 86400;
/** tx+rx bytes while enforcement is active, per person per evaluation batch, above which traffic is suspicious. Heuristic: DHCP/ARP/keepalive leakage is well below 1 MiB. */
export const BYPASS_BYTES = 1048576;
/** Blocked packets per person per batch at or above which attempts are reported (info). */
export const BLOCKED_SPIKE_PACKETS = 100;
/** Longest accepted delta window, and how far back a delta may end and still count. */
export const MAX_WINDOW_SECONDS = 3600;
const PERSON = /^[a-z][a-z0-9_]{0,31}$/;
const nat = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

export function validDelta(delta: ActivityDelta, now: number): boolean {
    return PERSON.test(delta?.person) && nat(delta.windowStart) && nat(delta.windowEnd) && delta.windowEnd > delta.windowStart &&
        delta.windowEnd - delta.windowStart <= MAX_WINDOW_SECONDS && delta.windowEnd <= now + 60 && delta.windowEnd > now - MAX_WINDOW_SECONDS &&
        nat(delta.txBytes) && nat(delta.rxBytes) && nat(delta.blockedPackets) && typeof delta.enforcementActive === 'boolean';
}

export function enforcementUnhealthy(people: PeopleDTO, now: number): AlertCandidate[] {
    const result: AlertCandidate[] = [];
    const routerAge = people.observedAt === null ? null : Math.max(0, now - people.observedAt);
    if (people.errors.length > 0 || routerAge === null || routerAge > STALE_ALERT_SECONDS) {
        result.push({kind: 'enforcement_unhealthy', personId: null, severity: 'warning',
            details: {errors: people.errors.length, statusAgeSeconds: routerAge ?? -1}});
    }
    for (const person of people.people) {
        const evidence = person.operationalAlerts;
        if (!evidence) continue;
        const codes = new Set(evidence.conditions.map(condition => condition.code));
        const age = evidence.sourceObservedAt === null ? null : Math.max(0, now - evidence.sourceObservedAt);
        const drift = codes.has('observed-drift');
        const unobserved = (codes.has('observation-unavailable') || codes.has('observation-stale') || person.observationHealth === 'unreachable') &&
            (age === null || age > STALE_ALERT_SECONDS);
        if (!drift && !unobserved) continue;
        result.push({kind: 'enforcement_unhealthy', personId: person.id, severity: drift ? 'critical' : 'warning',
            details: {drift, unobserved, observationAgeSeconds: age ?? -1}});
    }
    return result;
}

function pendingOrFailed(operation: OperationDTO, now: number): AlertCandidate | null {
    const base = {operationId: operation.id, state: operation.state};
    if (['failed', 'conflict'].includes(operation.state) && now - operation.updatedAt <= FAILED_RECENCY_SECONDS) {
        return {kind: 'sync_failed', personId: operation.personId, severity: 'warning', details: {...base, ageSeconds: Math.max(0, now - operation.updatedAt)}};
    }
    if (['pending', 'unknown'].includes(operation.state) && now - operation.createdAt > PENDING_ALERT_SECONDS) {
        return {kind: 'apply_pending_too_long', personId: operation.personId, severity: 'warning', details: {...base, ageSeconds: now - operation.createdAt}};
    }
    return null;
}

/** Latest operation per person only: a newer confirmed operation clears the condition. */
export function syncProblems(people: PeopleDTO, now: number): AlertCandidate[] {
    return people.people.flatMap(person => {
        const candidate = person.latestOperation ? pendingOrFailed(person.latestOperation, now) : null;
        return candidate ? [{...candidate, personId: person.id}] : [];
    });
}

function perPerson(deltas: ActivityDelta[], now: number) {
    const totals = new Map<string, {bytes: number; active: number; blocked: number; start: number; end: number}>();
    for (const delta of deltas) {
        if (!validDelta(delta, now)) continue;
        const entry = totals.get(delta.person) ?? {bytes: 0, active: 0, blocked: 0, start: delta.windowStart, end: delta.windowEnd};
        if (delta.enforcementActive) entry.bytes += delta.txBytes + delta.rxBytes;
        entry.blocked += delta.blockedPackets;
        entry.start = Math.min(entry.start, delta.windowStart); entry.end = Math.max(entry.end, delta.windowEnd);
        totals.set(delta.person, entry);
    }
    return totals;
}
/** People with at least one valid delta: only they are "decided" for auto-resolution. */
export const evaluatedPeople = (deltas: ActivityDelta[], now: number): Set<string> => new Set(perPerson(deltas, now).keys());

export function possibleBypass(deltas: ActivityDelta[], now: number): AlertCandidate[] {
    return [...perPerson(deltas, now)].filter(([, t]) => t.bytes > BYPASS_BYTES).map(([personId, t]) => ({
        kind: 'possible_bypass' as const, personId, severity: 'critical' as const,
        details: {totalBytes: t.bytes, windowStart: t.start, windowEnd: t.end, thresholdBytes: BYPASS_BYTES}}));
}

export function repeatedBlockedAttempts(deltas: ActivityDelta[], now: number): AlertCandidate[] {
    return [...perPerson(deltas, now)].filter(([, t]) => t.blocked >= BLOCKED_SPIKE_PACKETS).map(([personId, t]) => ({
        kind: 'repeated_blocked_attempts' as const, personId, severity: 'info' as const,
        details: {blockedPackets: t.blocked, windowStart: t.start, windowEnd: t.end, thresholdPackets: BLOCKED_SPIKE_PACKETS}}));
}

export function timeRequestPending(requests: PendingTimeRequest[], now: number): AlertCandidate[] {
    const byPerson = new Map<string, {count: number; oldest: number}>();
    for (const request of requests) {
        if (!PERSON.test(request?.person) || !nat(request.createdAt) || typeof request.requestId !== 'string') continue;
        const entry = byPerson.get(request.person);
        byPerson.set(request.person, {count: (entry?.count ?? 0) + 1, oldest: Math.min(entry?.oldest ?? request.createdAt, request.createdAt)});
    }
    return [...byPerson].map(([personId, e]) => ({kind: 'time_request_pending' as const, personId, severity: 'info' as const,
        details: {pendingRequests: e.count, oldestAgeSeconds: Math.max(0, now - e.oldest)}}));
}
