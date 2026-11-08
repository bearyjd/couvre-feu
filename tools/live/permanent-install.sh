#!/bin/sh
# Couvre-feu PERMANENT install, appended to the filled first-rehearsal.sh (its
# final call removed) by tools/live/permanent-install.py; it reuses every cfr_*
# helper and replaces cfr_identity/cfr_install_args/cfr_stop/main.
# POSIX sh / BusyBox ash. Phases: PAYLOAD IDENTITY PREREQ SNAPSHOT INSTALL
# VERIFY CONNECTIVITY. There is NO uninstall here: the install is meant to stay.
# After MUTATION_BEGIN any failure stops with STOPPED_AFTER_MUTATION and prints
# the rollback command; this script never runs it. Never touches dnsmasq, the
# WAN zone, offload, firmware, or any login/key configuration.
# Exit codes: 0 pass/validated, 10 refused before any router mutation, 20 stopped after mutation.
# shellcheck disable=SC2034
# @CF_PERMANENT_PARAMETERS_BEGIN@
CFPI_INSTALL_ARGS=
CFPI_ACTIVATE=0
CFPI_PROTECT=
CFPI_RPC_ALLOW=
CFPI_CT107_MAC=
# @CF_PERMANENT_PARAMETERS_END@
PI_UNTRUSTED=

# A permanent install is single-use: any existing Couvre-feu state refuses before the installer runs.
pi_existing() {
    for pi_path in "$CFR_ROOT/etc/couvrefeu" "$CFR_RELEASE_DIR" "$CFR_ROOT/usr/sbin/cfctl"; do
        if [ -e "$pi_path" ] || [ -L "$pi_path" ]; then cfr_refuse PREREQ existing_installation_present; fi
    done
}

# Exactly the planned installer flags (one per line); --activate is added by the INSTALL phase only.
cfr_install_args() {
    set -f
    # Generated tokens contain no glob characters; splitting is deliberate.
    # shellcheck disable=SC2086
    printf '%s\n' $CFPI_INSTALL_ARGS
}

# Same gate as the rehearsal, for the management and adult devices only.
pi_identity() {
    for pi_live in "$CFR_MGMT_MAC" "$CFR_JD_MAC" "$CFPI_CT107_MAC"; do
        for pi_old in $CFR_HISTORICAL_MACS; do
            [ "$pi_live" != "$pi_old" ] || cfr_refuse IDENTITY live_role_matches_protected_historical_mac
        done
    done
    if [ "$CFR_MGMT_MAC" = "$CFR_JD_MAC" ] && [ "$CFR_MGMT_IP" != "$CFR_JD_IP" ]; then cfr_refuse IDENTITY duplicate_live_mac; fi
    if [ "$CFR_MGMT_IP" = "$CFR_JD_IP" ] && [ "$CFR_MGMT_MAC" != "$CFR_JD_MAC" ]; then cfr_refuse IDENTITY duplicate_live_ip; fi
    for pi_need in "$CFR_MGMT_MAC" "$CFR_JD_MAC" "$CFPI_CT107_MAC" $CFR_HISTORICAL_MACS; do
        case " $CFPI_PROTECT " in *" $pi_need "*) ;; *) cfr_refuse IDENTITY protect_list_incomplete;; esac
    done
    for pi_scope in $CFPI_RPC_ALLOW; do
        case " $CFPI_PROTECT " in *" $pi_scope "*) cfr_refuse IDENTITY rpc_allow_mac_protected;; esac
    done
    [ -n "${SSH_CONNECTION:-}" ] || cfr_refuse IDENTITY ssh_connection_missing
    set -f
    # Deliberate token split of the sshd-provided value; globbing disabled.
    # shellcheck disable=SC2086
    set -- $SSH_CONNECTION
    set +f
    [ "$#" = 4 ] || cfr_refuse IDENTITY ssh_connection_invalid
    [ "$1" = "$CFR_MGMT_IP" ] || cfr_refuse IDENTITY ssh_source_not_management
    ip -4 neigh show dev br-lan > "$CFR_STAGE/identity.neigh" 2>/dev/null </dev/null || cfr_refuse IDENTITY neighbor_read_failed
    if [ ! -f "$CFR_LEASES" ] || [ -L "$CFR_LEASES" ]; then cfr_refuse IDENTITY leases_unavailable; fi
    cfr_neighbor "$CFR_MGMT_IP" "$CFR_MGMT_MAC" REACHABLE "$CFR_STAGE/identity.neigh" || cfr_refuse IDENTITY management_neighbor_mismatch
    cfr_neighbor "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_LIVE_STATES" "$CFR_STAGE/identity.neigh" || cfr_refuse IDENTITY jd_adult_neighbor_mismatch
    for cfr_role in "management $CFR_MGMT_IP $CFR_MGMT_MAC" "jd_adult $CFR_JD_IP $CFR_JD_MAC"; do
        # shellcheck disable=SC2086
        set -- $cfr_role
        awk -v ip="$2" -v mac="$3" 'tolower($2)==mac&&$3==ip{n++}END{exit n!=1}' "$CFR_LEASES" || cfr_refuse IDENTITY "$1_lease_mismatch"
    done
    if [ "$CFR_MGMT_IP" = "$CFR_JD_IP" ] && [ "$CFR_MGMT_MAC" = "$CFR_JD_MAC" ]; then
        cfr_info "adult_identity management=jd_adult same_confirmed_device; adult and management probes share one device"
    fi
    cfr_ok IDENTITY
}

# The retained uninstall.sh is advertised only when it is a regular file equal to the shipped digest and
# VERIFY found no mismatch in the other uninstall inputs.
pi_uninstall_trusted() {
    [ -z "$PI_UNTRUSTED" ] || return 1
    pi_target=$CFR_RELEASE_DIR/uninstall.sh
    [ -f "$pi_target" ] && [ ! -L "$pi_target" ] || return 1
    pi_want=$(awk '$3=="router/uninstall.sh"{print $1}' "$CFR_STAGE/manifest") || return 1
    [ -n "$pi_want" ] || return 1
    pi_have=$(sha256sum < "$pi_target") || return 1
    [ "${pi_have%% *}" = "$pi_want" ]
}
# The install stays: report the retained release's uninstall.sh, never run it.
pi_rollback_lines() {
    if pi_uninstall_trusted; then
        cfr_out "ROLLBACK_COMMAND /bin/sh ${CFR_RELEASE_DIR#"$CFR_ROOT"}/uninstall.sh"
        cfr_out 'ROLLBACK_NOTE run it once, separately, after separate approval; do not rerun install.sh; password login is the recovery path'
    elif [ -e "$CFR_RELEASE_DIR/uninstall.sh" ] || [ -L "$CFR_RELEASE_DIR/uninstall.sh" ]; then
        cfr_out "ROLLBACK_UNTRUSTED retained uninstall.sh not verified (${PI_UNTRUSTED:-digest_differs_from_release_manifest}); do not run it; password login is the recovery path"
    else
        cfr_out 'ROLLBACK_UNAVAILABLE retained release uninstall.sh absent; journal /etc/couvrefeu/backup retained; password login is the recovery path'
    fi
}
pi_halt() {
    # No re-entry: a second signal must not interleave a second FAIL/STOPPED report.
    trap '' INT TERM
    # A scope check leaves globbing off; the snapshot's glob counts need it on.
    set +f
    if cfr_snapshot after; then
        if cmp -s "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"; then cfr_info 'post-failure snapshot equals SNAPSHOT'
        else cfr_diff; fi
    else cfr_info 'post-failure snapshot unavailable'; fi
    pi_rollback_lines
    cfr_out "STOPPED_AFTER_MUTATION $1"
    exit 20
}
cfr_stop() {
    trap '' INT TERM
    cfr_fail "$1" "$2"
    pi_halt "$1"
}
# Invoked by the trap after MUTATION_BEGIN.
# shellcheck disable=SC2317,SC2329
pi_signal() {
    trap '' INT TERM
    cfr_fail INSTALL signal_received
    pi_halt SIGNAL
}

# Installed tree, healthy empty status at revision 0, retained release, and the
# generation: taken from the installer's own journal (never from the response
# being checked), then required to equal what the router's RPC status reports.
pi_verify() {
    cfr_verify_installed && pi_rc=0 || pi_rc=$?
    if [ "$pi_rc" != 0 ]; then
        PI_UNTRUSTED="installed_tree_mismatch$cfr_bad"
        cfr_stop VERIFY "installed_tree_mismatch$cfr_bad; journal retained"
    fi
    if [ ! -f "$CFR_RELEASE_DIR/uninstall.sh" ] || [ -L "$CFR_RELEASE_DIR/uninstall.sh" ]; then cfr_stop VERIFY release_uninstall_missing; fi
    # status exits nonzero when unhealthy; the JSON body is the gate.
    cfr_run_sh "$CFR_CFCTL" status --json > "$CFR_STAGE/status.json" || :
    cfr_status=$(awk 'NR==1{print}END{exit NR!=1}' "$CFR_STAGE/status.json") || cfr_stop VERIFY status_output_shape
    cfr_info "status $cfr_status"
    awk '/^\{"ok":true,"desiredRevision":0,"confirmedRevision":0,"desiredPauses":\[\],"effectivePauses":\[\],"desiredAllowances":\[\],"effectiveAllowances":\[\],"observed":\{"kids":\[\],"paused":\[\]\},"drift":false,"capabilities":\{"ipv6":(true|false),"conntrack":(true|false),"nativeKernelConfirmed":(true|false),"addressCoverageComplete":(true|false),"routerCompatibilityVerified":false\},"errors":\[\]\}$/{n++}END{exit !(NR==1&&n==1)}' \
        "$CFR_STAGE/status.json" || cfr_stop VERIFY status_not_healthy_empty
    pi_generation=$(awk -F '\t' '$1=="G"{print $2; n++}END{exit n!=1}' "$CFR_ROOT/etc/couvrefeu/backup/etc_couvrefeu_state.staged") || cfr_stop VERIFY generation_unreadable
    case "$pi_generation" in *[!0-9a-f]*|'') cfr_stop VERIFY generation_malformed;; esac
    [ "${#pi_generation}" = 64 ] || cfr_stop VERIFY generation_malformed
    cfr_run_sh "$CFR_CFCTL" rpc-status --json > "$CFR_STAGE/status.json" || cfr_stop VERIFY rpc_status_failed
    # ONE reply line; generation and the empty revision-0 policy are checked inside that same object.
    pi_rc=0
    awk -v gen="{\"rpc_version\":1,\"generation\":\"$pi_generation\"," \
        -v pol='"acceptedPolicy":{"version":1,"revision":0,"people":[],' \
        'NR==1{line=$0}END{if(NR!=1)exit 2;if(index(line,gen)!=1)exit 3;if(index(line,gen pol)!=1)exit 4}' \
        "$CFR_STAGE/status.json" || pi_rc=$?
    case "$pi_rc" in
        0) ;;
        3) cfr_stop VERIFY generation_mismatch;;
        4) cfr_stop VERIFY activation_not_fresh;;
        *) cfr_stop VERIFY rpc_status_shape;;
    esac
    # The installed lists must equal the planned sets (installer stores them sorted).
    set -f
    # shellcheck disable=SC2086
    pi_planned=$(printf '%s\n' $CFPI_PROTECT | LC_ALL=C sort -u)
    pi_installed=$(LC_ALL=C sort -u "$CFR_ROOT/etc/couvrefeu/protected") || cfr_stop VERIFY protect_scope_mismatch
    [ "$pi_planned" = "$pi_installed" ] || cfr_stop VERIFY protect_scope_mismatch
    # shellcheck disable=SC2086
    pi_planned=$(printf '%s\n' $CFPI_RPC_ALLOW | LC_ALL=C sort -u)
    pi_installed=$(LC_ALL=C sort -u "$CFR_ROOT/etc/couvrefeu/rpc-allowed") || cfr_stop VERIFY rpc_scope_mismatch
    [ "$pi_planned" = "$pi_installed" ] || cfr_stop VERIFY rpc_scope_mismatch
    set +f
    cfr_out "PERMANENT_GENERATION $pi_generation"
    cfr_ok VERIFY
}

pi_main() {
    umask 077
    cfr_payload_prereq
    CFR_START=$(date +%s)
    printf 'BEGIN permanent-install commit=%s release=%s profile=%s activate=%s\n' "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE" "$CFPI_ACTIVATE"
    for pi_value in "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE" "$CFR_MGMT_IP" "$CFR_MGMT_MAC" "$CFR_JD_IP" "$CFR_JD_MAC" \
        "$CFR_HISTORICAL_MACS" "$CFPI_INSTALL_ARGS" "$CFPI_PROTECT" "$CFPI_RPC_ALLOW" "$CFPI_CT107_MAC"; do
        [ -n "$pi_value" ] || cfr_refuse PAYLOAD parameters_missing
    done
    case "$CFPI_ACTIVATE" in 0|1) ;; *) cfr_refuse PAYLOAD parameters_missing;; esac
    cfr_setup_paths || cfr_refuse PAYLOAD unsafe_environment
    [ "$(id -u)" = 0 ] || [ "$CFR_FIXTURE" = 1 ] || cfr_refuse PAYLOAD root_required
    trap cfr_cleanup 0
    # Before mutation a lost session simply refuses.
    trap 'exit 10' HUP INT TERM PIPE
    cfr_extract
    pi_identity
    pi_existing
    cfr_prereq
    cfr_snapshot before || cfr_refuse SNAPSHOT snapshot_failed
    while IFS= read -r cfr_line; do cfr_out "SNAPSHOT $cfr_line"; done < "$CFR_STAGE/snapshot.before"
    cfr_ok SNAPSHOT
    cfr_now=$(date +%s)
    [ "$((cfr_now - CFR_START))" -le "$CFR_PREMUTATION_BUDGET" ] || cfr_refuse SNAPSHOT premutation_budget_exceeded
    if [ "$CFPI_ACTIVATE" != 1 ]; then
        cfr_info 'activate=false: staged validation only; nothing was installed'
        cfr_out PERMANENT_INSTALL_VALIDATED_NO_MUTATION
        exit 0
    fi
    trap '' HUP PIPE
    trap 'pi_signal' INT TERM
    cfr_out MUTATION_BEGIN
    # ONE installer invocation, never retried.
    cfr_install --activate || cfr_stop INSTALL "installer_exit_nonzero; journal retained; install not retried; uninstall not attempted"
    cfr_ok INSTALL
    pi_verify
    cfr_connectivity
    [ "$CFR_FAILED" = 0 ] || pi_halt CONNECTIVITY
    cfr_out PERMANENT_INSTALL_PASS
    exit 0
}

# Parse everything above first; no child can read the remaining script.
pi_main </dev/null
# Unreachable unless pi_main returns; fail closed.
# shellcheck disable=SC2317
exit 20
