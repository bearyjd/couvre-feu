import { object } from './json.ts';
import { hexDigest, parseObservation, policyDigest } from './router-rpc.ts';
import { healthyConfirmation, integer, normalizePolicy } from './router-schema.ts';

export interface EmptyWitnessContext {
    expectedGeneration: string;
    minRouterTime: number;
    maxRouterTime: number;
}
export type EmptyWitnessReason = 'invalid_context' | 'input_limit' | 'input_not_ascii' | 'input_unavailable' | 'input_deadline'
    | 'invalid_rpc' | 'generation_mismatch' | 'policy_not_empty' | 'operation_present' | 'rpc_errors'
    | 'runtime_unhealthy' | 'clock_unavailable' | 'clock_out_of_bounds';
export interface EmptyWitnessResult {
    source: 'supplied-empty-runtime-witness';
    verdict: 'PASS_EMPTY_WITNESS' | 'FAIL' | 'UNAVAILABLE';
    reason: EmptyWitnessReason | null;
    routerCompatibilityVerified: false;
    packetAcceptance: 'unmeasured';
    restoration: 'unverified';
}
function result(verdict: EmptyWitnessResult['verdict'], reason: EmptyWitnessReason | null): EmptyWitnessResult {
    return {source: 'supplied-empty-runtime-witness', verdict, reason, routerCompatibilityVerified: false, packetAcceptance: 'unmeasured', restoration: 'unverified'};
}
export const unavailableEmptyWitness = (reason: EmptyWitnessReason): EmptyWitnessResult => result('UNAVAILABLE', reason);

/** Checks supplied RPC bytes only. Context truth, transport authenticity and rehearsal gates remain external. */
export function emptyRuntimeWitness(raw: string, context: unknown): EmptyWitnessResult {
    let expectedGeneration: string, minimum: number, maximum: number;
    try {
        const c = object(context, ['expectedGeneration', 'minRouterTime', 'maxRouterTime']);
        expectedGeneration = hexDigest(c.expectedGeneration);
        if (expectedGeneration.length !== 64) return unavailableEmptyWitness('invalid_context');
        minimum = integer(c.minRouterTime); maximum = integer(c.maxRouterTime);
        if (minimum === 0 || maximum === 0 || minimum > maximum) return unavailableEmptyWitness('invalid_context');
    } catch { return unavailableEmptyWitness('invalid_context'); }
    if (typeof raw !== 'string') return unavailableEmptyWitness('input_unavailable');
    if (Buffer.byteLength(raw) > 131072) return unavailableEmptyWitness('input_limit');
    if (!/^[\x09\x0a\x0d\x20-\x7e]*$/.test(raw)) return unavailableEmptyWitness('input_not_ascii');
    let o;
    try { o = parseObservation(raw); } catch { return result('FAIL', 'invalid_rpc'); }
    if (o.generation !== expectedGeneration) return result('FAIL', 'generation_mismatch');
    const empty = normalizePolicy({version: 1, revision: 0, people: [], pauses: [], schedules: [], doh: {ipv4: [], ipv6: []}});
    if (JSON.stringify(normalizePolicy(o.acceptedPolicy)) !== JSON.stringify(empty) || o.policyDigest !== policyDigest(empty)) return result('FAIL', 'policy_not_empty');
    if (o.currentOperationId !== null || o.receipt !== null) return result('FAIL', 'operation_present');
    if (o.errors.length) return result('FAIL', 'rpc_errors');
    if (o.routerTime === 0) return unavailableEmptyWitness('clock_unavailable');
    if (o.routerTime < minimum || o.routerTime > maximum) return result('FAIL', 'clock_out_of_bounds');
    if (!healthyConfirmation(o.status, empty, o.routerTime, true)) return result('FAIL', 'runtime_unhealthy');
    return result('PASS_EMPTY_WITNESS', null);
}
