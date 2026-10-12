import type { DeviceEvidenceDTO } from '../../shared/src/contracts.ts';
import type { RouterPolicy, RouterStatus } from '../../shared/src/router-schema.ts';

const epoch = (value: number | null): value is number => Number.isSafeInteger(value) && value! >= 1577836800;
const sameMembers = (a: string[], b: string[]) => a.length === b.length && new Set(a).size === a.length && a.every(value => b.includes(value));

/** Projects existing policy/firewall membership; it performs no reads or transport calls. */
export function deviceEvidence(input: {
    source: DeviceEvidenceDTO['source']; now: number; sourceObservedAt: number | null; serviceReceivedAt: number | null;
    personId: string; mac: string; configuredMacs: string[];
    policy: RouterPolicy | null; status: RouterStatus | null; readError: boolean; generationMatches?: boolean;
}): DeviceEvidenceDTO {
    const { source, sourceObservedAt, serviceReceivedAt, now, policy, status } = input;
    const result: DeviceEvidenceDTO = {source, sourceObservedAt: epoch(sourceObservedAt) ? sourceObservedAt : null,
        serviceReceivedAt: epoch(serviceReceivedAt) ? serviceReceivedAt : null, freshUntil: null, freshness: 'unknown', enrollment: 'unknown'};
    if (!epoch(now) || !epoch(sourceObservedAt) || sourceObservedAt > now ||
        (source === 'router-policy' && !epoch(serviceReceivedAt)) ||
        (serviceReceivedAt !== null && (!epoch(serviceReceivedAt) || serviceReceivedAt > now))) return result;
    const deadline = Math.min(sourceObservedAt, serviceReceivedAt ?? sourceObservedAt) + 31;
    if (!Number.isSafeInteger(deadline)) return result;
    result.freshUntil = deadline;
    if (!policy || !status || input.readError || input.generationMatches === false || !status.ok || status.drift || status.errors.length ||
        status.desiredRevision !== policy.revision || status.confirmedRevision !== policy.revision ||
        !sameMembers(status.observed.kids, policy.people.flatMap(person => person.macs))) return result;
    const person = policy.people.find(person => person.id === input.personId);
    const assignedElsewhere = policy.people.some(person => person.id !== input.personId && person.macs.some(mac => input.configuredMacs.includes(mac)));
    if (assignedElsewhere || !input.configuredMacs.includes(input.mac) ||
        (person && person.macs.length > 0 && !sameMembers(person.macs, input.configuredMacs))) return result;
    result.enrollment = person?.macs.includes(input.mac) ? 'included' : 'not-included';
    result.freshness = now < deadline ? 'fresh' : 'stale';
    return result;
}
