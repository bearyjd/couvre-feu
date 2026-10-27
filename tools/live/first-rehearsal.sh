#!/bin/sh
# Couvre-feu FIRST live rehearsal, run as one `/bin/sh -s` SSH session.
# POSIX sh / BusyBox ash. tools/live/first-rehearsal.py fills the generated
# regions below; the operator discloses the exact payload sha256 first.
# Phases: PAYLOAD IDENTITY PREREQ SNAPSHOT INSTALL VERIFY UNINSTALL RESTORE
# CONNECTIVITY. Only this script writes stdout; children write the stage
# child.log. Once mutation begins, SIGPIPE/SIGHUP are ignored and every marker
# is also appended to the stage phase.log, so a dropped session still finishes
# install -> verify -> uninstall -> restore and leaves its result on the router.
# Never touches dnsmasq, the WAN zone, offload or firmware. Exit codes:
# 0 pass, 10 refused before any router mutation, 20 failure after mutation.
# shellcheck disable=SC2034
# @CF_GENERATED_PARAMETERS_BEGIN@
CFR_SOURCE_COMMIT=
CFR_RELEASE_ID=
CFR_PROFILE=
CFR_MGMT_IP=
CFR_MGMT_MAC=
CFR_JD_IP=
CFR_JD_MAC=
CFR_PENN_IP=
CFR_PENN_MAC=
CFR_HISTORICAL_MACS=
# INSTALL watchdog (first-rehearsal.py is the single source; penn-pilot.sh reuses both).
CFP_INSTALL_ALLOWANCE=
CFP_KILL_GRACE=
# @CF_GENERATED_PARAMETERS_END@

CFR_STAGE=
CFR_FAILED=0
CFR_STDOUT_LOST=0
CFR_PREMUTATION_BUDGET=300
# cfp_run supervision state (shared with penn-pilot.sh): the pid of the child being waited for ("starting" until known;
# empty when none), signals taken, whether one arrived while a child was in flight, the teardown latch, and the
# platform-lock verdict after a signalled child.
CFP_RUN_LIVE=
CFP_SIG_COUNT=0
CFP_SIG_PENDING=0
CFP_TEARDOWN=0
CFP_STALE_LOCK=0
# 1 once cfr_main has saved the session's stdout as fd 5 (children never inherit it).
CFR_FD5=0
CFR_LIVE_STATES='REACHABLE STALE DELAY'
CFR_PRESENT_STATES='REACHABLE STALE DELAY PROBE PERMANENT'
# Every path the installer may create or modify (router/install.sh and
# router/lib/install-common.sh FILES, scoped and profile inventory).
CFR_FILES='usr/lib/couvrefeu/core.sh usr/lib/couvrefeu/rpc.sh usr/lib/couvrefeu/state.awk usr/lib/couvrefeu/firewall.sh usr/lib/couvrefeu/json.awk usr/lib/couvrefeu/rules.awk usr/lib/couvrefeu/install-common.sh usr/lib/couvrefeu/platform-bootstrap.sh usr/lib/couvrefeu/vendor-platform.sh usr/lib/couvrefeu/activity.sh usr/sbin/cfctl usr/sbin/cfctl-ssh usr/sbin/cfctl-scope etc/firewall.couvrefeu etc/config/firewall etc/sysupgrade.conf etc/crontabs/root etc/couvrefeu/protected etc/couvrefeu/state etc/couvrefeu/platform-profile etc/couvrefeu/rpc-allowed'
CFR_DIRS='etc usr usr/sbin usr/lib usr/lib/couvrefeu etc/config etc/crontabs etc/couvrefeu etc/couvrefeu/backup etc/couvrefeu/runtime'
CFR_RELEASE_FILES='install.sh uninstall.sh cfctl cfctl-ssh cfctl-scope release.sha256 lib/core.sh lib/rpc.sh lib/firewall.sh lib/install-common.sh lib/state.awk lib/rules.awk lib/json.awk lib/vendor-platform.sh lib/platform-bootstrap.sh lib/activity.sh'

# Durable phase log first, then best-effort stdout (EPIPE never aborts).
cfr_out() {
    if [ -n "$CFR_STAGE" ] && [ -d "$CFR_STAGE" ]; then printf '%s\n' "$1" >> "$CFR_STAGE/phase.log"; fi
    printf '%s\n' "$1" 2>/dev/null || CFR_STDOUT_LOST=1
}
cfr_info() { cfr_out "INFO $*"; }
cfr_ok() { cfr_out "PHASE $1 OK"; }
cfr_refuse() {
    cfr_out "PHASE $1 FAIL $2"
    cfr_out "REFUSED_BEFORE_MUTATION $1"
    exit 10
}
cfr_fail() {
    cfr_out "PHASE $1 FAIL $2"
    CFR_FAILED=1
}
cfr_stop() {
    cfr_fail "$1" "$2"
    # Read-only re-snapshot: report exactly what the failed step left behind.
    if cfr_snapshot after; then
        if cmp -s "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"; then cfr_info 'post-failure snapshot equals SNAPSHOT'
        else cfr_diff; fi
    else cfr_info 'post-failure snapshot unavailable'; fi
    cfr_out "FAIL_AFTER_MUTATION $1"
    exit 20
}

# Invoked from the EXIT trap.
# shellcheck disable=SC2317,SC2329
cfr_cleanup() {
    case "$CFR_STAGE" in /tmp/couvre-feu-first.??????) ;; *) return 0;; esac
    if [ ! -d "$CFR_STAGE" ] || [ -L "$CFR_STAGE" ]; then return 0; fi
    if [ "$CFR_STDOUT_LOST" = 1 ]; then
        # The session is gone: keep phase.log/child.log for read-only inspection.
        printf '%s\n' "STAGE_RETAINED $CFR_STAGE" >> "$CFR_STAGE/phase.log"
        return 0
    fi
    if [ -f "$CFR_STAGE/child.log" ]; then sed 's/^/child: /' "$CFR_STAGE/child.log" >&2 2>/dev/null || :; fi
    if [ -f "$CFR_STAGE/manifest" ]; then
        while read -r cfr_sum cfr_mode cfr_path; do
            case "$cfr_path" in router/*) rm -f "$CFR_STAGE/$cfr_path";; esac
        done < "$CFR_STAGE/manifest"
    fi
    for cfr_name in manifest mtime-probe identity.neigh connectivity.neigh status.json snapshot.before snapshot.after \
        phase.log child.log diff.txt run.signalled \
        text.before.iptables text.before.ip6tables text.before.ipset text.before.ipsetsave text.before.uci text.before.cron \
        text.after.iptables text.after.ip6tables text.after.ipset text.after.ipsetsave text.after.uci text.after.cron; do
        rm -f "$CFR_STAGE/$cfr_name"
    done
    for cfr_dir in $CFR_PAYLOAD_DIRS; do
        [ ! -d "$CFR_STAGE/$cfr_dir" ] || rmdir "$CFR_STAGE/$cfr_dir" 2>/dev/null || :
    done
    rmdir "$CFR_STAGE" 2>/dev/null || printf 'couvre-feu-first: staging cleanup incomplete: %s\n' "$CFR_STAGE" >&2
}

cfr_setup_paths() {
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then
        # Isolated fixtures only: production SSH runs under `env -i`.
        case "${CF_ROOT:-}" in /tmp/couvre-feu-*) ;; *) return 1;; esac
        if [ ! -d "$CF_ROOT" ] || [ -L "$CF_ROOT" ]; then return 1; fi
        [ "$(CDPATH='' cd -- "$CF_ROOT" && pwd -P)" = "$CF_ROOT" ] || return 1
        CFR_FIXTURE=1
        CFR_ROOT=$CF_ROOT
        CFR_RECOVERY=$CF_ROOT/.couvrefeu-recovery
        CFR_INSTALL_LOCK=$CF_ROOT/.couvrefeu-install.lock
        CFR_STAGE_PARENT=$CF_ROOT
        CFR_TXN_DIR=$CF_ROOT
        CFR_STAGE_PREFIX=.couvrefeu-stage.
        case "${CF_TEST_SHELL:-sh}" in sh) CFR_SH='sh';; 'busybox ash') CFR_SH='busybox ash';; *) return 1;; esac
    else
        [ -z "${CF_ROOT:-}${CF_BACKEND_DIR:-}" ] || return 1
        CFR_FIXTURE=0
        CFR_ROOT=
        CFR_RECOVERY=/etc/.couvrefeu-recovery
        CFR_INSTALL_LOCK=/tmp/couvrefeu-install.lock
        CFR_STAGE_PARENT=/tmp
        CFR_TXN_DIR=/etc
        CFR_STAGE_PREFIX=couvrefeu-stage.
        CFR_SH=/bin/sh
    fi
    CFR_PLATFORM_LOCK=/tmp/couvrefeu-platform.lock
    CFR_RELEASE_DIR=$CFR_ROOT/etc/.couvrefeu-release-$CFR_RELEASE_ID
    CFR_LEASES=$CFR_ROOT/tmp/dhcp.leases
    CFR_CFCTL=$CFR_ROOT/usr/sbin/cfctl
    CFR_RUNTIME_LOCK=$CFR_ROOT/etc/couvrefeu/runtime/lock
}

# Normal-PATH stat (coreutils-stat on the target); PREREQ proves its format.
cfr_stat() { stat "$@"; }
cfr_run_sh() {
    # Deliberate split of the fixed shell selection ("busybox ash").
    # Child diagnostics go to the stage log, never to the marker stream.
    # shellcheck disable=SC2086
    $CFR_SH "$@" </dev/null 2>>"$CFR_STAGE/child.log" 5>&-
}

# The one place a cfctl, wrapper or uninstall child is started. $1 stdin file, $2 allowance in seconds, then the
# script and its arguments (run by the fixed shell). At the allowance the child's whole process group gets TERM (exit
# 143): cfctl and the installers trap it and release their runtime and platform locks (router/lib/platform-bootstrap.sh
# platform_lock_acquire, install-common.sh, core.sh); signalling the group also ends a foreground grandchild
# (iptables -w, ipset, uci) that would otherwise defer the child's trap. Only if the child is still alive
# CFP_KILL_GRACE seconds later is the group KILLed (exit 137), which skips those traps and can leave
# /tmp/couvrefeu-platform.lock behind (cfp_stale_lock_check). Busybox timeout signals only its direct child and has no
# -k, so this shell supervises the child with real uptime and one-second polls (up to 2 s total polling slack). The child is started by `exec setsid`: in a non-interactive shell the background
# subshell is not a process-group leader, so setsid execs in place instead of forking (checked with util-linux and
# busybox 1.33 setsid), the child keeps the pid $! reports and the pid cfctl records in the lock ($$), and the pid is
# also the new group id. A setsid that did fork returns 0 in the parent at once while the child runs on detached:
# cfp_run would lose the child group and cfctl would run unbounded, so cfr_setsid_check refuses such a
# setsid before any mutation (setsid_forks). The group signal is `kill -TERM -PID` with no `--` (busybox 1.33 kill
# rejects `--` as an invalid number and fails although it signals, so the fallback to the bare pid would always run
# and deliver a second TERM that cuts the child's EXIT trap); the bare-pid fallback is only for a group that does not
# exist. The subshell resets TERM because the teardown
# ignores it and an ignored signal would otherwise be inherited by the child. A hung child can never stall the session
# until the router-side last-resort timeout. A signal that the stop trap takes while the child is alive does not start
# the teardown on top of it: cfp_on_signal only notes it, this function reaps the child (it ends at its own end or at
# its supervised deadline), runs the stale-lock check, and only then stops. Callers must not run it inside $(...): a surviving
# grandchild could hold the pipe open, so output goes to a file.
# A separate builtin-only clock for child supervision: real uptime, independent of the pilot fixture clock.
# No command substitution or helper process can be killed by a session-group signal while reading it.
cfp_run_clock() {
    IFS=' ' read -r cfp_run_up cfp_run_rest < /proc/uptime || return 1
    case $cfp_run_up in *.*) :;; *) return 1;; esac
    cfp_run_sec=${cfp_run_up%.*} cfp_run_frac=${cfp_run_up#*.}
    case $cfp_run_sec in ''|*[!0-9]*) return 1;; esac
    case $cfp_run_frac in [0-9][0-9]) :;; *) return 1;; esac
    CFP_RUN_NOW_CS=$((cfp_run_sec * 100 + ${cfp_run_frac#0}))
}
cfp_run() {
    cfp_run_in=$1 cfp_run_t=$2; shift 2
    cfp_run_clock || return 1
    cfp_run_term_cs='' cfp_run_kill_cs=''
    cfp_run_clock_failed=0
    cfp_run_mark=$CFR_STAGE/run.signalled
    rm -f "$cfp_run_mark"
    CFP_RUN_LIVE=starting
    # shellcheck disable=SC2086
    ( trap - TERM; exec setsid $CFR_SH "$@" ) <"$cfp_run_in" 2>>"$CFR_STAGE/child.log" 5>&- &
    cfp_run_pid=$!
    CFP_RUN_LIVE=$cfp_run_pid
    # Supervise in this shell: a watcher fork would briefly inherit default TERM before installing its trap.
    # A killed sleep only wakes this loop; real uptime prevents repeated signals shortening or extending deadlines.
    while kill -0 "$cfp_run_pid" 2>/dev/null; do
        if ! cfp_run_clock; then
            cfp_run_clock_failed=1
            # Emergency STOP is now inevitable. Ignore session signals across the fork so sleep gets full grace;
            # losing another stop request here cannot change the outcome. The isolated commit still receives TERM.
            trap '' HUP INT TERM
            cfp_run_grace_left=$CFP_KILL_GRACE
            if [ -e "$cfp_run_mark" ]; then
                # Retain the last successful uptime on clock failure. Never send TERM twice into an EXIT trap
                # or restart its grace: round remaining centiseconds up, clamped at zero if already overdue.
                cfp_run_left_cs=$((cfp_run_kill_cs - CFP_RUN_NOW_CS))
                if [ "$cfp_run_left_cs" -gt 0 ]; then cfp_run_grace_left=$(((cfp_run_left_cs + 99) / 100))
                else cfp_run_grace_left=0; fi
            else
                : > "$cfp_run_mark"
                kill -TERM "-$cfp_run_pid" 2>/dev/null || kill -TERM "$cfp_run_pid" 2>/dev/null
            fi
            sleep "$cfp_run_grace_left"
            kill -KILL "-$cfp_run_pid" 2>/dev/null || kill -KILL "$cfp_run_pid" 2>/dev/null
            if [ "$CFP_TEARDOWN" = 1 ]; then trap '' INT TERM
            else trap cfp_on_signal INT TERM; fi
            break
        fi
        kill -0 "$cfp_run_pid" 2>/dev/null || break
        if [ -z "$cfp_run_term_cs" ]; then cfp_run_term_cs=$((CFP_RUN_NOW_CS + cfp_run_t * 100)); fi
        if [ "$CFP_RUN_NOW_CS" -ge "$cfp_run_term_cs" ] && [ ! -e "$cfp_run_mark" ]; then
            : > "$cfp_run_mark"
            cfp_run_kill_cs=$((CFP_RUN_NOW_CS + CFP_KILL_GRACE * 100))
            kill -TERM "-$cfp_run_pid" 2>/dev/null || kill -TERM "$cfp_run_pid" 2>/dev/null
        fi
        if [ -e "$cfp_run_mark" ] && [ "$CFP_RUN_NOW_CS" -ge "$cfp_run_kill_cs" ]; then
            kill -KILL "-$cfp_run_pid" 2>/dev/null || kill -KILL "$cfp_run_pid" 2>/dev/null
            break
        fi
        sleep 1
    done
    cfp_run_seen=$CFP_SIG_COUNT
    wait "$cfp_run_pid"
    cfp_run_rc=$?
    # ash reaps asynchronous children during the poll while retaining their wait status. A trapped signal can
    # interrupt wait; retry for its real status, preserving the earlier value if that wait already reaped it (127).
    while [ "$CFP_SIG_COUNT" != "$cfp_run_seen" ]; do
        cfp_run_seen=$CFP_SIG_COUNT
        wait "$cfp_run_pid"
        cfp_run_rc2=$?
        [ "$cfp_run_rc2" = 127 ] || cfp_run_rc=$cfp_run_rc2
    done
    if [ -e "$cfp_run_mark" ]; then
        kill -KILL "-$cfp_run_pid" 2>/dev/null
        [ "$cfp_run_rc" = 0 ] || cfp_stale_lock_check "$cfp_run_pid"
    fi
    CFP_RUN_LIVE=
    if [ "$cfp_run_clock_failed" = 1 ]; then
        [ "$CFP_TEARDOWN" = 1 ] || cfp_stop SIGNAL supervision_clock_unreadable
        return 1
    fi
    if [ "$CFP_SIG_PENDING" = 1 ]; then CFP_SIG_PENDING=0; cfp_stop SIGNAL interrupted; fi
    return "$cfp_run_rc"
}
# The INT/TERM trap of the mutating part. With a cfp_run child in flight the stop waits for it (see cfp_run);
# otherwise it is the stop at once.
cfp_on_signal() {
    CFP_SIG_COUNT=$((CFP_SIG_COUNT + 1))
    if [ -n "$CFP_RUN_LIVE" ]; then CFP_SIG_PENDING=1; return 0; fi
    cfp_stop SIGNAL interrupted
}
# After a signalled child ($1 its pid) ended non-zero: the platform lock a killed cfctl held is never auto-cleared
# (only `cfctl recover-platform-lock`), so the per-minute cron `cfctl expire` fails and pauses have no kernel time
# bound. The lock is the child's only if its pid file holds exactly that pid: a lock that cron `cfctl expire` (or
# anything else) holds legitimately is not ours. Record it here (the caller owns this call's stdout, so nothing is
# printed) and say so in cfp_stop / the teardown instead of waiting on it.
cfp_stale_lock_check() {
    if printf '%s\n' "$1" | cmp -s - "$CFR_PLATFORM_LOCK/pid" 2>/dev/null; then CFP_STALE_LOCK=1
    elif [ -d "$CFR_PLATFORM_LOCK" ] && [ ! -e "$CFR_PLATFORM_LOCK/pid" ]; then CFP_STALE_LOCK=3; fi
}

# A stop taken inside cfp_run runs under its caller's stdout redirection: the evidence goes to the session again.
# penn-pilot.sh replaces this with its own teardown-running cfp_stop.
cfp_stop() {
    [ "$CFR_FD5" != 1 ] || exec 1>&5
    cfr_stop "$1" "$2"
}

# `setsid` must exist and exec in place (see cfp_run); proven before any mutation. $1 is the refusing phase.
cfr_setsid_check() {
    command -v setsid >/dev/null 2>&1 || cfr_refuse "$1" "missing_tool setsid"
    # shellcheck disable=SC2086
    ( exec setsid $CFR_SH -c 'exit 7' ) </dev/null >/dev/null 2>&1 5>&- &
    wait "$!"
    [ "$?" = 7 ] || cfr_refuse "$1" setsid_forks
}

# The activating INSTALL runs under cfp_run: TERM to its whole group at CFP_INSTALL_ALLOWANCE, KILL CFP_KILL_GRACE later
# (worst case allowance + grace + 2 s polling = 257 s). install.sh traps TERM and runs its cleanup (journal rollback or
# retention, lock release); KILL skips it. Same arguments as the PREREQ stage validation.
cfr_install_supervised() {
    # Generated MACs/profile contain no whitespace or glob characters.
    set -f
    # shellcheck disable=SC2046
    set -- $(cfr_install_args) "$@"
    set +f
    cfr_info "run install.sh $*"
    cfp_run /dev/null "$CFP_INSTALL_ALLOWANCE" "$CFR_STAGE/router/install.sh" "$@" >>"$CFR_STAGE/child.log"
}

# What a timed-out INSTALL left behind, read-only. Sets CFR_INSTALL_DIRTY=1 when any of the install, platform or
# runtime locks exists or the transaction owner is `active` or unreadable (an absent owner, `complete` and `recovered`
# are clean). Presence only for the other recovery files and the journal marker.
cfr_install_state() {
    CFR_INSTALL_DIRTY=0
    cfr_is_line=
    for cfr_is_item in "install_lock:$CFR_INSTALL_LOCK" "platform_lock:$CFR_PLATFORM_LOCK" "runtime_lock:$CFR_RUNTIME_LOCK"; do
        if [ -e "${cfr_is_item#*:}" ] || [ -L "${cfr_is_item#*:}" ]; then cfr_is_val=present; CFR_INSTALL_DIRTY=1
        else cfr_is_val=absent; fi
        cfr_is_line="$cfr_is_line ${cfr_is_item%%:*}=$cfr_is_val"
    done
    cfr_is_owner=$CFR_TXN_DIR/.couvrefeu-transaction
    cfr_is_state=absent
    if [ -e "$cfr_is_owner" ] || [ -L "$cfr_is_owner" ]; then
        cfr_is_a='' cfr_is_b=''
        # Regular files only: reading a FIFO here would block.
        if [ -f "$cfr_is_owner" ] && [ ! -L "$cfr_is_owner" ]; then { IFS= read -r cfr_is_a; IFS= read -r cfr_is_b; } < "$cfr_is_owner" 2>/dev/null || :; fi
        case "$cfr_is_a/$cfr_is_b" in
            'CFTRANSACTION 1/complete') cfr_is_state=complete;;
            'CFTRANSACTION 1/recovered') cfr_is_state=recovered;;
            'CFTRANSACTION 1/active') cfr_is_state=active; CFR_INSTALL_DIRTY=1;;
            *) cfr_is_state=unreadable; CFR_INSTALL_DIRTY=1;;
        esac
    fi
    for cfr_is_item in prepared:.couvrefeu-prepared fence:.couvrefeu-recovery-required retirement:.couvrefeu-retirement; do
        if [ -e "$CFR_TXN_DIR/${cfr_is_item#*:}" ] || [ -L "$CFR_TXN_DIR/${cfr_is_item#*:}" ]; then cfr_is_val=present; else cfr_is_val=absent; fi
        cfr_is_line="$cfr_is_line ${cfr_is_item%%:*}=$cfr_is_val"
    done
    if [ -e "$CFR_ROOT/etc/couvrefeu/backup/ready" ]; then cfr_is_val=ready; else cfr_is_val=absent; fi
    cfr_info "install_timeout state$cfr_is_line owner=$cfr_is_state journal=$cfr_is_val"
}

# After a non-zero supervised INSTALL ($1 its status). Chosen by the run.signalled mark plus lock/owner state, never by
# the exit code alone. A plain failure keeps its reason. A timeout that KILLed, or left any lock or an active owner,
# STOPs: no in-session recover-install-lock and no uninstall (the operator runs `cfctl recover-install-lock` from a
# complete authenticated release, then the single ordinary uninstall.sh, from a password shell). A TERM-honoured
# timeout with nothing left and an installed uninstall.sh returns 0 so the caller runs the single uninstall.
cfr_install_failed() {
    cfr_if_rc=$1
    if [ ! -e "$CFR_STAGE/run.signalled" ]; then
        cfr_stop INSTALL "installer_exit_nonzero; journal retained; uninstall not attempted"
    fi
    cfr_install_state
    if [ "$cfr_if_rc" = 137 ] || [ "$CFR_INSTALL_DIRTY" = 1 ]; then
        cfr_stop INSTALL "install_timeout_killed; state above; no in-session recovery; uninstall not attempted; operator: cfctl recover-install-lock, then one uninstall.sh, from a password shell"
    fi
    if [ -f "$CFR_RELEASE_DIR/uninstall.sh" ] && [ ! -L "$CFR_RELEASE_DIR/uninstall.sh" ]; then
        cfr_fail INSTALL "install_timeout; TERM honoured, locks released; the single uninstall follows"
        return 0
    fi
    cfr_stop INSTALL "install_timeout; TERM honoured but no installed uninstall.sh; uninstall not attempted"
}

cfr_extract() {
    CFR_STAGE=$(mktemp -d /tmp/couvre-feu-first.XXXXXX) || cfr_refuse PAYLOAD staging_mktemp_failed
    case "$CFR_STAGE" in /tmp/couvre-feu-first.??????) ;; *) CFR_STAGE=; cfr_refuse PAYLOAD staging_path_unexpected;; esac
    cfr_info "staging $CFR_STAGE"
    chmod 700 "$CFR_STAGE" || cfr_refuse PAYLOAD staging_mode
    cfr_payload_extract || cfr_refuse PAYLOAD extraction_failed
    cfr_count=0
    while read -r cfr_sum cfr_mode cfr_path; do
        case "$cfr_path" in router/*) ;; *) cfr_refuse PAYLOAD manifest_path;; esac
        cfr_actual=$(sha256sum < "$CFR_STAGE/$cfr_path") || cfr_refuse PAYLOAD hash_read
        [ "${cfr_actual%% *}" = "$cfr_sum" ] || cfr_refuse PAYLOAD "hash_mismatch $cfr_path"
        chmod "$cfr_mode" "$CFR_STAGE/$cfr_path" || cfr_refuse PAYLOAD "mode $cfr_path"
        cfr_count=$((cfr_count + 1))
    done < "$CFR_STAGE/manifest"
    [ "$cfr_count" = "$CFR_PAYLOAD_COUNT" ] || cfr_refuse PAYLOAD manifest_count
    for cfr_dir in $CFR_PAYLOAD_DIRS; do chmod 700 "$CFR_STAGE/$cfr_dir" || cfr_refuse PAYLOAD directory_mode; done
    cfr_ok PAYLOAD
}

# One br-lan IPv4 row for $1 with MAC $2 and a state from list $3.
cfr_neighbor() {
    awk -v ip="$1" -v mac="$2" -v states=" $3 " '
        $1==ip {
            rows++; rowmac=""; state=""
            for(i=2;i<=NF;i++){
                if($i=="lladdr"&&i<NF){rowmac=tolower($(i+1));i++}
                else if($i~/^(REACHABLE|PERMANENT|STALE|DELAY|PROBE|FAILED|INCOMPLETE|NOARP|NONE)$/)state=$i
            }
            if(rowmac==mac&&state!=""&&index(states," " state " "))good++
        }
        END {exit !(rows==1&&good==1)}
    ' "$4"
}

cfr_identity() {
    for cfr_live in "$CFR_MGMT_MAC" "$CFR_JD_MAC" "$CFR_PENN_MAC"; do
        for cfr_old in $CFR_HISTORICAL_MACS; do
            [ "$cfr_live" != "$cfr_old" ] || cfr_refuse IDENTITY live_role_matches_protected_historical_mac
        done
    done
    if [ "$CFR_MGMT_MAC" = "$CFR_JD_MAC" ] && [ "$CFR_MGMT_IP" != "$CFR_JD_IP" ]; then
        cfr_refuse IDENTITY duplicate_live_mac
    fi
    if [ "$CFR_MGMT_MAC" = "$CFR_PENN_MAC" ] || [ "$CFR_JD_MAC" = "$CFR_PENN_MAC" ]; then
        cfr_refuse IDENTITY duplicate_live_mac
    fi
    if [ "$CFR_MGMT_IP" = "$CFR_JD_IP" ] && [ "$CFR_MGMT_MAC" != "$CFR_JD_MAC" ]; then
        cfr_refuse IDENTITY duplicate_live_ip
    fi
    if [ "$CFR_PENN_IP" = "$CFR_MGMT_IP" ] || [ "$CFR_PENN_IP" = "$CFR_JD_IP" ]; then
        cfr_refuse IDENTITY duplicate_live_ip
    fi
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
    # The installer itself requires REACHABLE/PERMANENT for the SSH client.
    cfr_neighbor "$CFR_MGMT_IP" "$CFR_MGMT_MAC" REACHABLE "$CFR_STAGE/identity.neigh" || cfr_refuse IDENTITY management_neighbor_mismatch
    cfr_neighbor "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_LIVE_STATES" "$CFR_STAGE/identity.neigh" || cfr_refuse IDENTITY jd_adult_neighbor_mismatch
    cfr_neighbor "$CFR_PENN_IP" "$CFR_PENN_MAC" "$CFR_LIVE_STATES" "$CFR_STAGE/identity.neigh" || cfr_refuse IDENTITY penn_child_neighbor_mismatch
    for cfr_role in "management $CFR_MGMT_IP $CFR_MGMT_MAC" "jd_adult $CFR_JD_IP $CFR_JD_MAC" "penn_child $CFR_PENN_IP $CFR_PENN_MAC"; do
        # shellcheck disable=SC2086
        set -- $cfr_role
        awk -v ip="$2" -v mac="$3" 'tolower($2)==mac&&$3==ip{n++}END{exit n!=1}' "$CFR_LEASES" || cfr_refuse IDENTITY "$1_lease_mismatch"
    done
    if [ "$CFR_MGMT_IP" = "$CFR_JD_IP" ] && [ "$CFR_MGMT_MAC" = "$CFR_JD_MAC" ]; then
        cfr_info "adult_identity management=jd_adult same_confirmed_device; adult and management probes share one device"
    fi
    cfr_ok IDENTITY
}

cfr_install_args() {
    printf '%s\n' --platform-profile "$CFR_PROFILE" --protect "$CFR_MGMT_MAC" --protect "$CFR_JD_MAC"
    for cfr_old in $CFR_HISTORICAL_MACS; do printf '%s\n' --protect "$cfr_old"; done
}
cfr_install() {
    # Generated MACs/profile contain no whitespace or glob characters.
    set -f
    # shellcheck disable=SC2046
    set -- $(cfr_install_args) "$@"
    set +f
    cfr_info "run install.sh $*"
    cfr_run_sh "$CFR_STAGE/router/install.sh" "$@" >>"$CFR_STAGE/child.log"
}

cfr_transients_absent() {
    [ ! -e "$CFR_INSTALL_LOCK" ] && [ ! -L "$CFR_INSTALL_LOCK" ] && [ ! -e "$CFR_PLATFORM_LOCK" ] && [ ! -L "$CFR_PLATFORM_LOCK" ] &&
        [ "$(cfr_glob_count "$CFR_STAGE_PARENT" "$CFR_STAGE_PREFIX")" = 0 ]
}
cfr_glob_count() {
    cfr_n=0
    for cfr_entry in "$1/$2"*; do
        [ -e "$cfr_entry" ] || [ -L "$cfr_entry" ] || continue
        cfr_n=$((cfr_n + 1))
    done
    printf '%s\n' "$cfr_n"
}

cfr_prereq() {
    for cfr_tool in sha256sum awk sed sort cmp mktemp iptables-save ip6tables-save ipset uci ip; do
        command -v "$cfr_tool" >/dev/null 2>&1 || cfr_refuse PREREQ "missing_tool $cfr_tool"
    done
    cfr_od=$(command -v od) || cfr_refuse PREREQ od_missing
    cfr_stat_path=$(command -v stat) || cfr_refuse PREREQ stat_missing
    cfr_info "tools stat=$cfr_stat_path od=$cfr_od"
    [ "$(printf A | od -An -tx1 2>/dev/null | tr -d ' \n')" = 41 ] || cfr_refuse PREREQ od_not_callable
    cfr_stat -c %a / >/dev/null 2>&1 </dev/null || cfr_refuse PREREQ stat_not_callable
    # A probe this script creates proves stat reports nine fractional digits.
    : > "$CFR_STAGE/mtime-probe" || cfr_refuse PREREQ probe_create
    cfr_probe_y=$(cfr_stat -c %y "$CFR_STAGE/mtime-probe" </dev/null) || cfr_refuse PREREQ stat_format
    rm -f "$CFR_STAGE/mtime-probe"
    case "$cfr_probe_y" in *.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]\ *) ;; *) cfr_refuse PREREQ stat_mtime_not_nanosecond;; esac
    # The installer refuses originals without nanosecond mtimes; so do we.
    [ -f "$CFR_ROOT/etc/config/firewall" ] || cfr_refuse PREREQ firewall_config_missing
    cfr_precision=$(cfr_file_record "$CFR_ROOT/etc/config/firewall") || cfr_refuse PREREQ stat_format
    case "$cfr_precision" in *:s) cfr_refuse PREREQ stat_mtime_not_nanosecond;; esac
    cfr_info mtime_precision nanoseconds
    # Originals move into the journal and back by rename only (no touch, no
    # copy); the installer proves one filesystem with `stat -c '%d %m'` on
    # directories. Prove that format here, read-only, before any change.
    cfr_mount=$(cfr_stat -c '%d %m' "$CFR_ROOT/etc/config" </dev/null) || cfr_refuse PREREQ stat_mount_format
    case "$cfr_mount" in [0-9]*' '/*) ;; *) cfr_refuse PREREQ stat_mount_format;; esac
    cfr_info "etc_config_filesystem $cfr_mount"
    cfr_transients_absent || cfr_refuse PREREQ installer_transient_present
    cfr_install || cfr_refuse PREREQ installer_stage_validation_failed
    cfr_transients_absent || cfr_refuse PREREQ installer_stage_left_transient
    cfr_ok PREREQ
}

cfr_file_record() {
    if [ -L "$1" ]; then printf 'F %s symlink\n' "$1"; return 0; fi
    if [ ! -e "$1" ]; then printf 'F %s absent\n' "$1"; return 0; fi
    if [ ! -f "$1" ]; then printf 'F %s nonregular\n' "$1"; return 0; fi
    cfr_sum=$(sha256sum < "$1") || return 1
    cfr_meta=$(cfr_stat -c '%a %u %g %s %Y %y' "$1" </dev/null) || return 1
    printf '%s\n' "$cfr_meta" | awk -v p="$1" -v h="${cfr_sum%% *}" '
        NF==8 && $1~/^[0-7]+$/ && $2~/^[0-9]+$/ && $3~/^[0-9]+$/ && $4~/^[0-9]+$/ && $5~/^-?[0-9]+$/ {
            n=split($7,t,"."); frac="s"
            if(n==2&&length(t[2])==9&&t[2]!~/[^0-9]/)frac=t[2]
            printf "F %s %s:%s:%s:%s:%s:%s:%s\n",p,h,$1,$2,$3,$4,$5,frac; ok=1
        }
        END {exit !ok||NR!=1}'
}
# Directory mtimes are not recorded: neither installer nor uninstaller
# restores them; mode, owner and existence are.
cfr_dir_record() {
    if [ -L "$1" ]; then printf 'D %s symlink\n' "$1"; return 0; fi
    if [ ! -e "$1" ]; then printf 'D %s absent\n' "$1"; return 0; fi
    if [ ! -d "$1" ]; then printf 'D %s nondirectory\n' "$1"; return 0; fi
    cfr_meta=$(cfr_stat -c '%a:%u:%g' "$1" </dev/null) || return 1
    printf 'D %s dir:%s\n' "$1" "$cfr_meta"
}
cfr_text() {
    cfr_text_file=$CFR_STAGE/text.$1.$2
    case "$2" in
        iptables) iptables-save 2>/dev/null </dev/null | sed -e '/^#/d' -e 's/\[[0-9][0-9]*:[0-9][0-9]*\]/[0:0]/g' > "$cfr_text_file";;
        ip6tables) ip6tables-save 2>/dev/null </dev/null | sed -e '/^#/d' -e 's/\[[0-9][0-9]*:[0-9][0-9]*\]/[0:0]/g' > "$cfr_text_file";;
        ipset) ipset list -n 2>/dev/null </dev/null | LC_ALL=C sort > "$cfr_text_file";;
        ipsetsave) ipset save 2>/dev/null </dev/null | LC_ALL=C sort > "$cfr_text_file";;
        uci) uci export firewall 2>/dev/null </dev/null > "$cfr_text_file";;
        cron) if [ -f "$CFR_ROOT/etc/crontabs/root" ]; then cat "$CFR_ROOT/etc/crontabs/root" > "$cfr_text_file"; else printf 'absent\n' > "$cfr_text_file"; fi;;
    esac
}
cfr_snapshot() {
    cfr_snap=$CFR_STAGE/snapshot.$1
    : > "$cfr_snap" || return 1
    # Pipelines hide producer failures; empty iptables output also refuses.
    for cfr_kind in iptables ip6tables ipset ipsetsave uci cron; do
        cfr_text "$1" "$cfr_kind" || return 1
        case "$cfr_kind" in iptables|ip6tables|uci) [ -s "$CFR_STAGE/text.$1.$cfr_kind" ] || return 1;; esac
        cfr_sum=$(sha256sum < "$CFR_STAGE/text.$1.$cfr_kind") || return 1
        printf 'H %s %s\n' "$cfr_kind" "${cfr_sum%% *}" >> "$cfr_snap"
    done
    for cfr_rel in $CFR_FILES; do
        cfr_file_record "$CFR_ROOT/$cfr_rel" >> "$cfr_snap" || return 1
        cfr_file_record "$CFR_ROOT/$cfr_rel.couvrefeu-tmp" >> "$cfr_snap" || return 1
    done
    for cfr_rel in $CFR_DIRS; do cfr_dir_record "$CFR_ROOT/$cfr_rel" >> "$cfr_snap" || return 1; done
    cfr_dir_record "$CFR_RELEASE_DIR" >> "$cfr_snap" || return 1
    cfr_dir_record "$CFR_RELEASE_DIR/lib" >> "$cfr_snap" || return 1
    for cfr_rel in $CFR_RELEASE_FILES; do cfr_file_record "$CFR_RELEASE_DIR/$cfr_rel" >> "$cfr_snap" || return 1; done
    cfr_dir_record "$CFR_RECOVERY" >> "$cfr_snap" || return 1
    cfr_file_record "$CFR_RECOVERY.done" >> "$cfr_snap" || return 1
    cfr_file_record "$CFR_RECOVERY.done.next" >> "$cfr_snap" || return 1
    # The platform transaction's owner, prepared, fence and retirement records (not in CFR_FILES/CFR_DIRS): a
    # timed-out INSTALL may only be called restored when all four are absent again.
    for cfr_rel in .couvrefeu-transaction .couvrefeu-prepared .couvrefeu-recovery-required .couvrefeu-retirement; do
        cfr_file_record "$CFR_TXN_DIR/$cfr_rel" >> "$cfr_snap" || return 1
    done
    cfr_dir_record "$CFR_INSTALL_LOCK" >> "$cfr_snap" || return 1
    cfr_dir_record "$CFR_PLATFORM_LOCK" >> "$cfr_snap" || return 1
    printf 'G %s/%s* %s\n' "$CFR_STAGE_PARENT" "$CFR_STAGE_PREFIX" "$(cfr_glob_count "$CFR_STAGE_PARENT" "$CFR_STAGE_PREFIX")" >> "$cfr_snap"
}

# Every file listed in the manifest is checked in the release directory (named by
# the release id) and, for cfctl* and lib/*, in the place the installer puts it
# under usr/sbin or usr/lib/couvrefeu. Each must be a regular, non-symlink file
# whose sha256 equals the shipped digest. Nothing else is claimed: modes, owners,
# extra files and the symlink status of parent directories are not compared.
# Returns 0 when all match, 1 on a mismatch confined to usr/sbin, and 2 when any
# input of the installed uninstall.sh (release directory or usr/lib/couvrefeu)
# differs, is not a regular file, or nothing was checked.
cfr_verify_installed() {
    cfr_bad=
    cfr_bad_inputs=
    cfr_checked=0
    while read -r cfr_sum cfr_mode cfr_path; do
        cfr_rel=${cfr_path#router/}
        cfr_dests="$CFR_RELEASE_DIR/$cfr_rel"
        case "$cfr_rel" in
            cfctl|cfctl-ssh|cfctl-scope) cfr_dests="$cfr_dests $CFR_ROOT/usr/sbin/$cfr_rel";;
            lib/*) cfr_dests="$cfr_dests $CFR_ROOT/usr/lib/couvrefeu/${cfr_rel#lib/}";;
        esac
        for cfr_dest in $cfr_dests; do
            # A FIFO would block sha256sum and a symlink could point at the right bytes.
            if [ -f "$cfr_dest" ] && [ ! -L "$cfr_dest" ]; then
                cfr_actual=$(sha256sum < "$cfr_dest" 2>/dev/null) || cfr_actual=unreadable
            else
                cfr_actual=not_regular
            fi
            cfr_checked=$((cfr_checked + 1))
            [ "${cfr_actual%% *}" = "$cfr_sum" ] && continue
            cfr_bad="$cfr_bad ${cfr_dest#"$CFR_ROOT"/}"
            case "$cfr_dest" in "$CFR_ROOT"/usr/sbin/*) ;; *) cfr_bad_inputs=1;; esac
        done
    done < "$CFR_STAGE/manifest"
    if ! grep -qx "CF_RELEASE_ID=$CFR_RELEASE_ID" "$CFR_ROOT/usr/lib/couvrefeu/platform-bootstrap.sh" 2>/dev/null; then
        cfr_bad="$cfr_bad installed_release_id"
        cfr_bad_inputs=1
    fi
    if [ "$cfr_checked" -lt 1 ]; then cfr_bad="$cfr_bad nothing_checked"; cfr_bad_inputs=1; fi
    if [ -n "$cfr_bad_inputs" ]; then cfr_info "installed_tree_mismatch$cfr_bad"; return 2; fi
    if [ -n "$cfr_bad" ]; then cfr_fail VERIFY "installed_tree_mismatch$cfr_bad"; return 1; fi
    cfr_info "installed_tree ok release=$CFR_RELEASE_ID files=$cfr_checked"
}

cfr_verify() {
    cfr_verify_installed && cfr_vrc=0 || cfr_vrc=$?
    # The installed uninstall.sh runs as root from these files: never run a tampered one.
    # Recovery is then a manual password login, which this tool never disables.
    [ "$cfr_vrc" != 2 ] || cfr_stop VERIFY "installed_uninstall_inputs_mismatch$cfr_bad; uninstall not attempted; journal retained"
    [ "$cfr_vrc" = 0 ] || return 0
    # status exits nonzero when unhealthy; the JSON body is the gate.
    cfr_run_sh "$CFR_CFCTL" status --json > "$CFR_STAGE/status.json" || :
    cfr_status=$(awk 'NR==1{print}END{exit NR!=1}' "$CFR_STAGE/status.json") || { cfr_fail VERIFY status_output_shape; return 0; }
    cfr_info "status $cfr_status"
    # Structural: the whole fixed cfctl status shape, with only boolean
    # capabilities free; any other field value or extra field fails.
    awk '/^\{"ok":true,"desiredRevision":0,"confirmedRevision":0,"desiredPauses":\[\],"effectivePauses":\[\],"desiredAllowances":\[\],"effectiveAllowances":\[\],"observed":\{"kids":\[\],"paused":\[\]\},"drift":false,"capabilities":\{"ipv6":(true|false),"conntrack":(true|false),"nativeKernelConfirmed":(true|false),"addressCoverageComplete":(true|false),"routerCompatibilityVerified":false\},"errors":\[\]\}$/{n++}END{exit !(NR==1&&n==1)}' \
        "$CFR_STAGE/status.json" || { cfr_fail VERIFY status_not_healthy_empty; return 0; }
    cfr_ok VERIFY
}

# Print every DIFF line between snapshot.before and snapshot.after (both
# present). The host tool saves them all to diff.txt and caps the console.
cfr_diff() {
    { awk 'NR==FNR{before[$1 " " $2]=$0;order[++n]=$1 " " $2;next}
        {after[$1 " " $2]=$0; if(!($1 " " $2 in before))order[++n]=$1 " " $2}
        END{for(i=1;i<=n;i++){k=order[i]; if(before[k]!=after[k]){print "DIFF - " (k in before?before[k]:k " missing"); print "DIFF + " (k in after?after[k]:k " missing")}}}' \
        "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"
    for cfr_kind in iptables ip6tables ipset ipsetsave uci cron; do
        cmp -s "$CFR_STAGE/text.before.$cfr_kind" "$CFR_STAGE/text.after.$cfr_kind" && continue
        awk -v kind="$cfr_kind" 'NR==FNR{b[$0]++;next}{a[$0]++;if(a[$0]>b[$0])print "DIFF " kind " + " $0}' \
            "$CFR_STAGE/text.before.$cfr_kind" "$CFR_STAGE/text.after.$cfr_kind"
        awk -v kind="$cfr_kind" 'NR==FNR{a[$0]++;next}{b[$0]++;if(b[$0]>a[$0])print "DIFF " kind " - " $0}' \
            "$CFR_STAGE/text.after.$cfr_kind" "$CFR_STAGE/text.before.$cfr_kind"
    done; } > "$CFR_STAGE/diff.txt"
    while IFS= read -r cfr_line; do cfr_out "$cfr_line"; done < "$CFR_STAGE/diff.txt"
}
cfr_restore() {
    cfr_snapshot after || { cfr_fail RESTORE snapshot_failed; return 0; }
    if cmp -s "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"; then cfr_ok RESTORE; return 0; fi
    cfr_diff
    cfr_fail RESTORE snapshot_mismatch
}

cfr_connectivity() {
    ip -4 neigh show dev br-lan > "$CFR_STAGE/connectivity.neigh" 2>/dev/null </dev/null || { cfr_fail CONNECTIVITY neighbor_read_failed; return 0; }
    cfr_neighbor "$CFR_MGMT_IP" "$CFR_MGMT_MAC" "$CFR_PRESENT_STATES" "$CFR_STAGE/connectivity.neigh" || { cfr_fail CONNECTIVITY management_neighbor_lost; return 0; }
    cfr_neighbor "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_PRESENT_STATES" "$CFR_STAGE/connectivity.neigh" || { cfr_fail CONNECTIVITY jd_adult_neighbor_lost; return 0; }
    cfr_ok CONNECTIVITY
}

cfr_main() {
    umask 077
    exec 5>&1
    CFR_FD5=1
    CFR_START=$(date +%s)
    printf 'BEGIN first-rehearsal commit=%s release=%s profile=%s\n' "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE"
    for cfr_value in "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE" "$CFR_MGMT_IP" "$CFR_MGMT_MAC" "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_PENN_IP" "$CFR_PENN_MAC" "$CFR_HISTORICAL_MACS" \
        "$CFP_INSTALL_ALLOWANCE" "$CFP_KILL_GRACE"; do
        [ -n "$cfr_value" ] || cfr_refuse PAYLOAD parameters_missing
    done
    cfr_setup_paths || cfr_refuse PAYLOAD unsafe_environment
    [ "$(id -u)" = 0 ] || [ "$CFR_FIXTURE" = 1 ] || cfr_refuse PAYLOAD root_required
    trap cfr_cleanup 0
    # Before mutation a lost session simply refuses.
    trap 'exit 10' HUP INT TERM PIPE
    cfr_extract
    cfr_identity
    cfr_prereq
    cfr_setsid_check PREREQ
    cfr_snapshot before || cfr_refuse SNAPSHOT snapshot_failed
    # The baseline digests belong in local evidence, not only on the router.
    while IFS= read -r cfr_line; do cfr_out "SNAPSHOT $cfr_line"; done < "$CFR_STAGE/snapshot.before"
    cfr_ok SNAPSHOT
    # The script bounds itself before mutating; the INSTALL then runs under its own TERM/KILL watchdog and the
    # rest to completion (the outer KILL timeout is a last resort that stays beyond the watchdog's 257 s).
    cfr_now=$(date +%s)
    [ "$((cfr_now - CFR_START))" -le "$CFR_PREMUTATION_BUDGET" ] || cfr_refuse SNAPSHOT premutation_budget_exceeded
    trap '' HUP PIPE
    # INSTALL is supervised: a signal that reaches this shell is recorded and the stop waits for the child (cfp_run).
    trap cfp_on_signal INT TERM
    cfr_out MUTATION_BEGIN
    cfr_install_supervised --activate && cfr_irc=0 || cfr_irc=$?
    trap 'exit 20' INT TERM
    if [ "$cfr_irc" = 0 ]; then
        cfr_ok INSTALL
        cfr_verify
    else
        # Only a TERM-honoured timeout with nothing left continues: no VERIFY, straight to the single uninstall.
        cfr_install_failed "$cfr_irc"
    fi
    # Production uninstall must run from the external recovery release;
    # fixtures opt into the same path with CF_TEST_RELEASE_DIR=1.
    cfr_uninstall=$CFR_RELEASE_DIR/uninstall.sh
    cfr_info "run uninstall.sh once: $cfr_uninstall"
    cfr_run_sh "$cfr_uninstall" >>"$CFR_STAGE/child.log" || cfr_stop UNINSTALL "uninstall_refused_or_failed; journal preserved; resolve explicitly"
    cfr_ok UNINSTALL
    cfr_restore
    cfr_connectivity
    [ "$CFR_FAILED" = 0 ] || { cfr_out 'FAIL_AFTER_MUTATION summary'; exit 20; }
    cfr_out FIRST_REHEARSAL_PASS
    exit 0
}

# @CF_GENERATED_PAYLOAD_BEGIN@
CFR_PAYLOAD_DIRS=
CFR_PAYLOAD_COUNT=0
cfr_payload_extract() { return 1; }
# @CF_GENERATED_PAYLOAD_END@

# Parse everything above first; no child can read the remaining script.
cfr_main </dev/null
# Unreachable unless cfr_main returns; fail closed.
# shellcheck disable=SC2317
exit 20
