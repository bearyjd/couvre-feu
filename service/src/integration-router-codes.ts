import type { RPCObservation } from '../../shared/src/router-rpc.ts';

/**
 * Router error codes this service may store and serve while schedules.editable is on (roadmap item 2, S2a; unverified on this router).
 * A closed set: a static test checks that every member is a literal failure code in router/ (`cf_fail <code>`, `platform_fail <code>` or a
 * `CF_ERROR=<code>` default). Any other router string is treated as diagnostic text and never stored or served.
 */
/** Codes cfctl rpc-sync can return before its single policy write (router/lib/rpc.sh: :177 backend, :180 allowance, :182 safe/ssh guard/preflight, :184 transition prepare). */
export const PRE_WRITE_ROUTER_CODES: readonly string[] = [
    'missing_dependencies', 'allowance_beyond_horizon', 'invalid_clock', 'protected_mac_overlap', 'rpc_scope_overlap',
    'ssh_client_in_scope', 'ssh_client_overlap', 'ssh_client_unprotected',
    'foreign_chain_collision', 'foreign_schedule_collision', 'foreign_uci_pending_changes', 'incomplete_address_coverage', 'preflight_baseline_requires_installer',
    'transition_state_mismatch', 'uci_inspection_failed', 'unsafe_ownership_record',
    'firewall_transition_incomplete', 'owned_rule_drift', 'incomplete_transition_address_coverage',
];
export const KNOWN_ROUTER_CODES: ReadonlySet<string> = new Set([...PRE_WRITE_ROUTER_CODES, 'policy_conflict', 'operation_conflict', 'generation_conflict', 'previous_apply_failed', 'apply_failed']);
export const ROUTER_ERROR_UNRECOGNIZED = 'router_error_unrecognized';
/** Entry for entry (never dropped), so the error counts, and with them health, are unchanged. */
export function withFixedErrorCodes(o: RPCObservation): RPCObservation {
    const fixed = (codes: readonly string[]) => codes.map(code => KNOWN_ROUTER_CODES.has(code) ? code : ROUTER_ERROR_UNRECOGNIZED);
    return {...o, errors: fixed(o.errors), status: {...o.status, errors: fixed(o.status.errors)}};
}
