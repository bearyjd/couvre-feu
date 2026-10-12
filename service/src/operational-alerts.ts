import type { OperationalAlertEvidenceDTO, OperationDTO } from '../../shared/src/contracts.ts';

const epoch = (value: number | null): value is number => Number.isSafeInteger(value) && value! >= 1577836800;

/** Call only for assigned people. No I/O, payloads, diagnostics or presence inference. */
export function operationalAlerts(input: {
    source: OperationalAlertEvidenceDTO['source']; now: number; sourceObservedAt: number | null; serviceReceivedAt: number | null;
    generationMatches: boolean; readError: boolean; healthy: boolean; drift: boolean;
    pauseUntil: number | null; expiredEffectivePause: boolean; operation: OperationDTO | null; operationHealthy: boolean;
}): OperationalAlertEvidenceDTO {
    const {source, now, sourceObservedAt, serviceReceivedAt} = input;
    const result: OperationalAlertEvidenceDTO = {source, evaluatedAt: now,
        sourceObservedAt: epoch(sourceObservedAt) ? sourceObservedAt : null,
        serviceReceivedAt: epoch(serviceReceivedAt) ? serviceReceivedAt : null, freshUntil: null, freshness: 'unknown',
        healthy: false, confirmedOperationId: null, expiryVerifiedThrough: null, conditions: []};
    const clocks = epoch(now) && epoch(sourceObservedAt) && sourceObservedAt <= now &&
        (source === 'synthetic-policy' ? serviceReceivedAt === null : epoch(serviceReceivedAt) && serviceReceivedAt <= now);
    if (clocks) result.freshUntil = Math.min(sourceObservedAt!, serviceReceivedAt ?? sourceObservedAt!) + 31;
    if (clocks && input.generationMatches && !input.readError) result.freshness = now < result.freshUntil! ? 'fresh' : 'stale';
    const fresh = result.freshness === 'fresh';
    result.healthy = fresh && input.healthy;
    if (result.healthy) {
        result.confirmedOperationId = input.operationHealthy ? input.operation?.id ?? null : null;
        result.expiryVerifiedThrough = input.expiredEffectivePause ? null : sourceObservedAt;
    }
    if (!clocks || !input.generationMatches || input.readError) result.conditions.push({code: 'observation-unavailable'});
    else if (!fresh) result.conditions.push({code: 'observation-stale'});
    else if (!input.healthy && !input.drift) result.conditions.push({code: 'observation-unavailable'});
    if (fresh && input.drift) result.conditions.push({code: 'observed-drift'});
    if (input.operation && !input.operationHealthy && ['unknown', 'failed', 'conflict'].includes(input.operation.state)) {
        result.conditions.push({code: 'control-verification-unavailable', operationId: input.operation.id});
    }
    if (epoch(input.pauseUntil) && epoch(now) && input.generationMatches && input.pauseUntil <= now &&
        (result.expiryVerifiedThrough === null || result.expiryVerifiedThrough < input.pauseUntil)) {
        result.conditions.push({code: 'pause-expiry-unverified', pauseUntil: input.pauseUntil});
    }
    return result;
}
