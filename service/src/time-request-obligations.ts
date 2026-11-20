import type { Store } from './db.ts';

export interface ObligationOptions {
    /** Only this child's requests; default is every child. */
    person?: string;
    /** Count a request still awaiting a decision as an obligation. */
    includePending?: boolean;
    /** Count a pending restore only when the request is approved or apply_failed (not e.g. declined or expired rows). */
    approvedRepauseOnly?: boolean;
}

/** Restore states that mean a lifted pause is not yet confirmed restored. */
export const REPAUSE_OPEN_SQL = "repause_state IN ('waiting','applying')";

/** True while a time request still owes work: an approval in flight, a pending decision (opt-in), or an unconfirmed restore. */
export function hasObligation(store: Store, options: ObligationOptions = {}): boolean {
    const states = options.includePending ? "state IN ('pending','approving')" : "state='approving'";
    const repause = options.approvedRepauseOnly ? `(state IN ('approved','apply_failed') AND ${REPAUSE_OPEN_SQL})` : REPAUSE_OPEN_SQL;
    const where = `(${states} OR ${repause})`;
    return Boolean(options.person === undefined
        ? store.get(`SELECT 1 FROM time_requests WHERE ${where} LIMIT 1`)
        : store.get(`SELECT 1 FROM time_requests WHERE person_id=? AND ${where} LIMIT 1`, options.person));
}
