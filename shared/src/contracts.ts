export const SOURCE = 'synthetic-fake-router' as const;
export type Provenance = {
    source: typeof SOURCE | 'real-router-integration';
    routerCompatibilityVerified: false;
    integrationScope?: string;
};
export const provenance: Provenance = {
    source: SOURCE, routerCompatibilityVerified: false
};
export type Role = 'admin' | 'parent';
export interface Actor {
    id: string;
    displayName: string;
    role: Role;
    personIds: string[];
    permissionVersion: string;
}
export interface SessionDTO extends Provenance {
    actor: Actor;
    csrfToken: string;
    expiresAt: number;
}
export type OperationState = 'pending' | 'confirmed' | 'unknown' | 'failed' | 'conflict';
export interface OperationDTO extends Provenance {
    id: string;
    personId: string;
    action: 'pause' | 'resume';
    revision: number;
    state: OperationState;
    createdAt: number;
    updatedAt: number;
    error: string | null;
    confirmedAt: number | null;
    currentHealthy?: boolean;
    accepted?: boolean;
    dispatch?: 'awaiting_operator_dispatch' | 'awaiting_automatic_dispatch' | 'consumed' | 'uncertain' | 'resolved';
}
export interface PersonDTO {
    id: string;
    name: string;
    devices: {
        id: string;
        label: string;
    }[];
    manualPause: {
        until: number;
    } | null;
    effectiveManualPause: {
        until: number;
    } | null;
    scheduleBlocked: boolean | null;
    scheduleExplanation: string;
    scheduleTimezone?: string;
    scheduleWitness?: 'none' | 'unverified' | 'owner-reviewed-clock';
    /** Exclusive epoch deadline for a configured schedule claim; null means unknown. */
    scheduleValidUntil?: number | null;
    /** Service epoch when this configured schedule claim was evaluated. */
    scheduleCheckedAt?: number | null;
    observationHealth: 'healthy' | 'unconfirmed' | 'unreachable';
    status: OperationState;
    latestOperation: OperationDTO | null;
}
export interface PeopleDTO extends Provenance {
    people: PersonDTO[];
    serviceDesiredRevision: number;
    routerDesiredRevision: number | null;
    revisionToken: string | null;
    routerConfirmedRevision: number | null;
    observedAt: number | null;
    statusAgeSeconds: number | null;
    lastSuccessfulConfirmationAt: number | null;
    errors: string[];
    packetAcceptance?: 'unmeasured';
}
export interface OperationResult extends Provenance {
    operation: OperationDTO;
    operationUrl: string;
}
export interface ErrorDTO extends Provenance {
    error: {
        code: string;
        message: string;
    };
}
