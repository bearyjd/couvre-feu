import type { RPCObservation, RPCEnvelope } from '../../shared/src/router-rpc.ts';
import type { RouterActivity } from '../../shared/src/router-activity.ts';
export type DispatchKind = 'observe' | 'apply' | 'receipt' | 'activity';
export interface FrozenInvocation {
    executable: '/usr/bin/ssh'; argv: string[]; stdin: string; deadlineMs: number;
    kind: DispatchKind; operationId: string | null; requestDigest: string;
}
/** Network I/O consumes a bounded frozen invocation under maintenance or owner authority. */
export interface AsyncRouter {
    invocation(kind: DispatchKind, envelope?: RPCEnvelope, operationId?: string): FrozenInvocation;
    invoke(invocation: FrozenInvocation): Promise<RPCObservation>;
    /** Read-only counters (`cfctl rpc-activity --json`); only an `activity` invocation is accepted. */
    invokeActivity(invocation: FrozenInvocation): Promise<RouterActivity>;
}
export class RouterTransportError extends Error {
    readonly code: string;
    readonly delivery: 'not_delivered' | 'possible';
    constructor(code: string, delivery: 'not_delivered' | 'possible' = 'possible') {
        super(code); this.code = code; this.delivery = delivery;
    }
}
