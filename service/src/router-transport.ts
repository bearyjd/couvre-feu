import type { RPCObservation, RPCEnvelope } from '../../shared/src/router-rpc.ts';
import type { RouterActivity } from '../../shared/src/router-activity.ts';
import type { RouterInventory } from '../../shared/src/router-inventory.ts';
export type DispatchKind = 'observe' | 'apply' | 'receipt' | 'activity' | 'inventory';
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
    /** Read-only listing (`cfctl rpc-inventory --json`). Resolves only a valid v1 reply; every other outcome is a RouterTransportError. */
    invokeInventory(invocation: FrozenInvocation): Promise<RouterInventory>;
}
export class RouterTransportError extends Error {
    readonly code: string;
    readonly delivery: 'not_delivered' | 'possible';
    /** The remote command's exit status when the child exited nonzero without usable output; otherwise null. */
    readonly exitCode: number | null;
    constructor(code: string, delivery: 'not_delivered' | 'possible' = 'possible', exitCode: number | null = null) {
        super(code); this.code = code; this.delivery = delivery; this.exitCode = exitCode;
    }
}
