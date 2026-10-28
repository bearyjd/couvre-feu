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
export type OperationAction = 'pause' | 'resume' | 'schedule_create' | 'schedule_update' | 'schedule_delete' | 'enroll' | 'unenroll' | 'pause_all' | 'resume_all' | 'move' | 'allow';
export interface ScheduleWindowDTO {
    id: string;
    weekdays: string[];
    start: string;
    stop: string;
}
export type OperationState = 'pending' | 'confirmed' | 'unknown' | 'failed' | 'conflict';
export interface OperationDTO extends Provenance {
    id: string;
    personId: string;
    action: OperationAction;
    revision: number;
    state: OperationState;
    createdAt: number;
    updatedAt: number;
    error: string | null;
    confirmedAt: number | null;
    /**
     * Bulk blocks only. What the household can rely on right now: a block is `blocking` only when healthy-confirmed; anything
     * unconfirmed is `not_blocking`. A resume that is unconfirmed `may_still_be_blocked`; a refused one is `unchanged`.
     */
    effect?: 'blocking' | 'not_blocking' | 'unblocked' | 'may_still_be_blocked' | 'unchanged';
    currentHealthy?: boolean;
    accepted?: boolean;
    dispatch?: 'awaiting_operator_dispatch' | 'awaiting_automatic_dispatch' | 'consumed' | 'uncertain' | 'resolved';
}
export interface DeviceEvidenceDTO {
    source: 'synthetic-policy' | 'router-policy';
    sourceObservedAt: number | null;
    serviceReceivedAt: number | null;
    /** Exclusive epoch deadline; observations remain fresh at age exactly 30 seconds. */
    freshUntil: number | null;
    freshness: 'fresh' | 'stale' | 'unknown';
    enrollment: 'included' | 'not-included' | 'unknown';
}
export interface AssignedDeviceDTO {
    id: string;
    label: string;
    /** A queued router change for this device (integration only); absent once the router confirmed it. */
    change?: 'adding' | 'removing' | 'moving';
    /** Policy enrollment evidence only, never network presence or activity. */
    evidence?: DeviceEvidenceDTO;
}
export type OperationalAlertCode = 'observation-unavailable' | 'observation-stale' | 'control-verification-unavailable' | 'observed-drift' | 'pause-expiry-unverified';
export interface OperationalAlertSignalDTO {
    code: OperationalAlertCode;
    operationId?: string;
    pauseUntil?: number;
}
/** Existing router policy witnesses only. Evaluation time is not failure onset. */
export interface OperationalAlertEvidenceDTO {
    source: DeviceEvidenceDTO['source'];
    evaluatedAt: number;
    sourceObservedAt: number | null;
    serviceReceivedAt: number | null;
    freshUntil: number | null;
    freshness: 'fresh' | 'stale' | 'unknown';
    healthy: boolean;
    confirmedOperationId: string | null;
    expiryVerifiedThrough: number | null;
    conditions: OperationalAlertSignalDTO[];
}
export type EntryKind = 'child' | 'device_group';
export interface PersonDTO {
    /** Integration only: a child, or a named group of shared devices (e.g. a TV) paused/scheduled the same way. */
    kind?: EntryKind;
    id: string;
    name: string;
    devices: AssignedDeviceDTO[];
    manualPause: {
        until: number;
    } | null;
    effectiveManualPause: {
        until: number;
    } | null;
    /** Integration only: `focus` while the pause in force is a parent-started focus window; null for any other pause or none. */
    pauseLabel?: 'focus' | null;
    scheduleBlocked: boolean | null;
    scheduleExplanation: string;
    /** Integration only: the router-confirmed time allowance in force now (it lifts pause and schedule until `until`); null when none. */
    allowance?: {
        until: number;
    } | null;
    /** Weekly windows from the latest observed policy; present only where this installation allows editing them. */
    schedules?: ScheduleWindowDTO[];
    schedulesEditable?: boolean;
    scheduleTimezone?: string;
    scheduleWitness?: 'none' | 'unverified' | 'owner-reviewed-clock';
    /** Exclusive epoch deadline for a configured schedule claim; null means unknown. */
    scheduleValidUntil?: number | null;
    /** Service epoch when this configured schedule claim was evaluated. */
    scheduleCheckedAt?: number | null;
    observationHealth: 'healthy' | 'unconfirmed' | 'unreachable';
    status: OperationState;
    latestOperation: OperationDTO | null;
    operationalAlerts?: OperationalAlertEvidenceDTO;
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
export interface ActivityGapDTO {
    start: number;
    end: number;
}
/** One UTC day of router-counter evidence. Null means unknown, never zero. */
export interface ActivityDayDTO {
    date: string;
    start: number;
    /** Exclusive end of the evaluated range: the end of the day, or the last completed minute for today. */
    end: number;
    expectedMinutes: number;
    coveredMinutes: number;
    unknownMinutes: number;
    coverage: 'complete' | 'partial' | 'none';
    estimatedOnlineMinutes: number | null;
    totalBytes: number | null;
    blockedAttempts: number | null;
    offload: 'off' | 'on' | 'unknown' | null;
    possiblyUndercounted: boolean;
    gaps: ActivityGapDTO[];
    gapsTruncated: boolean;
}
export interface ActivityDTO extends Provenance {
    personId: string;
    generatedAt: number;
    scope: 'estimated-network-activity';
    disclaimer: string;
    thresholdBytesPerMinute: number;
    retentionDays: number;
    days: ActivityDayDTO[];
}
