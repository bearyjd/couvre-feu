/**
 * Defensive bounds, not product limits. Parent accounts and devices are meant to be unlimited in practice; these only
 * bound per-request work an admin could otherwise grow without end. Every discoverable sign-in snapshots the
 * credential -> account-version map of all active passkeys into its challenge row, so the product of the two bounds
 * caps that row (worst case ~32k entries, ~3 MB). A household reaches neither. Raise them here if one ever does.
 */
export const ACCOUNT_LIMIT = 1000;
/** Active plus approval-pending passkeys per account. */
export const PASSKEYS_PER_ACCOUNT = 32;
