#!/bin/sh
# Couvre-feu Penn live pilot (one or two devices), appended by tools/live/penn-pilot.py
# to the filled first-rehearsal.sh (its final cfr_main call removed), so every
# cfr_* helper, the payload, identity, snapshot, restore and connectivity code
# is the live-proven rehearsal code. Later definitions here win in sh.
# Phases: PAYLOAD IDENTITY PREREQ SNAPSHOT BASELINE INSTALL ENROLL [SCOPE] PAUSE
# RESUME EXPIRY DNS UNINSTALL RESTORE CONNECTIVITY (SCOPE only when the private
# config sets scopeNegativeTest). A second Penn device (CFP_PENN2_*) is enrolled
# under the same person; "paused" means every device is in the paused set.
# Schema v2 (CFP_V2=1): the install floor is the Chromebook only and the phone
# (CFP_PHONE_*) is added to Penn's scope and enrolled later. The phase list is
# ENROLL [SCOPE] SCOPE-ADD-1 SCOPE-ADD-2 PAUSE RESUME MOVE BULK EXPIRY DNS
# INVENTORY SCOPE-REMOVE. scope-add/remove need a TTY and a typed confirmation, so
# leg 1 (this script) only prints `CFP_LEG2_READY <leg> <base>` and re-reads
# rpc-status until the scope changed; the local tool starts the commit leg (T4).
# v2 also begins its teardown at CFP_SELF_ABORT_PCT percent of the remote timeout.
# After MUTATION_BEGIN every path
# ends in one teardown: installed uninstall.sh once, exact snapshot compare and
# connectivity. Pauses are always timed (--until); pause rules carry no kernel
# time bound, so cron `cfctl expire` bounds them if the session is lost.
# Never touches dnsmasq, the WAN zone, offload or firmware; DNS probes only
# read. Exit codes: 0 pass, 10 refused before mutation, 20 after mutation.
# shellcheck disable=SC2034,SC2153,SC2154,SC2317,SC2329
# CFR_* variables and cfr_* functions come from first-rehearsal.sh; cfp_cleanup
# and the cfr_install_args override are invoked indirectly (trap, rehearsal).
# @CF_PILOT_PARAMETERS_BEGIN@
CFP_ROUTER_IP=
CFP_PERSON=
CFP_OPERATION_ID=
CFP_POLICY=
CFP_DNS_NAME=
CFP_PAUSE_SECONDS=
CFP_PAUSE_OBSERVE=
CFP_RESUME_OBSERVE=
CFP_EXPIRY_SECONDS=
CFP_EXPIRY_TOLERANCE=
CFP_POLL=
CFP_EXPIRY_POLL=
CFP_STATUS_SETTLE=
CFP_SAFE_BAND=
CFP_DNS_MARGIN_CS=
CFP_RTT_MARGIN_MS=
CFP_PREMUTATION_BUDGET=
CFP_REMOTE_TIMEOUT=
CFP_TEARDOWN_RESERVE=
CFP_READ_TIMEOUT=
CFP_COUNTERS_WORST=
CFP_ITERATION_WORST=
CFP_CFCTL_ALLOWANCE=
CFP_WORST_ENROLL=
CFP_WORST_PAUSE=
CFP_WORST_RESUME=
CFP_WORST_EXPIRY=
CFP_WORST_DNS=
# Emitted only for two devices / scopeNegativeTest; absent means single-device, no SCOPE.
CFP_PENN2_IP=
CFP_PENN2_MAC=
CFP_RPC_ALLOW=
CFP_KIDS_JSON=
CFP_SCOPE_TEST=
CFP_SCOPE_MAC=
CFP_SCOPE_OPERATION_ID=
CFP_SCOPE_ERROR=
CFP_SCOPE_POLICY=
CFP_WORST_SCOPE=
# Emitted only for schema v2 (absent means v1: no scope_target phases, no self-abort).
CFP_V2=
CFP_PHONE_IP=
CFP_PHONE_MAC=
CFP_PILOT_B=
CFP_POLICY_PHONE=
CFP_POLICY_MOVE=
CFP_POLICY_BACK=
CFP_OP_PHONE=
CFP_OP_MOVE=
CFP_OP_MOVE_BACK=
CFP_OP_BULK_PAUSE=
CFP_OP_BULK_RESUME=
CFP_OP_UNENROL=
CFP_REV_BULK_PAUSE=
CFP_REV_BULK_RESUME=
CFP_REV_UNENROL=
CFP_SCOPE_LEG_SECONDS=
CFP_FAILED_BLOCK_ALL=
CFP_SELF_ABORT_PCT=
CFP_WORST_SCOPE_ADD_1=
CFP_WORST_SCOPE_ADD_2=
CFP_WORST_MOVE=
CFP_WORST_BULK=
CFP_WORST_INVENTORY=
CFP_WORST_SCOPE_REMOVE=
# @CF_PILOT_PARAMETERS_END@

CFP_DIR=
CFP_LAT_MAX=0
CFP_NE_SALT=
# The policy revision the pilot's own successful calls set (rpc-sync from 0,
# then +1 per pause or resume; cron `cfctl expire` keeps it).
CFP_REV=0
CFP_MUTATED=0
CFP_PROOF_FAILED=0
CFP_TEARDOWN=0
# Teardown arithmetic, all inside CFP_TEARDOWN_RESERVE (300 s): the leg-2 cancel wait (CFP_LEG2_CANCEL_WAIT) + one
# safe-band wait (at most 71 s) + the uninstall allowance (CFP_UNINSTALL_ALLOWANCE) + the restore snapshot, proof and
# connectivity reads (local, a few seconds): 20 + 71 + 120 = 211 s, leaving 89 s.
CFP_UNINSTALL_ALLOWANCE=120
CFP_LEG2_CANCEL_WAIT=20
# The leg (2a..2d) whose CFP_LEG2_READY marker was printed and whose confirming rpc-status read has not happened.
CFP_LEG2_ACTIVE=
CFP_START_CS=
CFP_STOPPED=
CFP_FRESH_STATES='REACHABLE DELAY'
CFP_FILES='preview.out wrapper.out inventory.json inventory.w.json fw.move0 fw.move1 fw.raw bulk.chain rpc-status.json request.json rpc-sync.json status.json rules.S rules.L rules.one rules.out members members.list members.all guard.S dns.out ping.out identity.neigh settle.neigh settle.tokens settle.map counters.enrolled counters.prepause counters.pause0 counters.pause1 counters.resume0 counters.resume1 counters.expired counters.final activity.json scope-request.json scope-sync.json coverage.clock coverage.neigh4 coverage.neigh6 coverage.leases coverage.addr4 coverage.addr6 fw.before fw.after fw.ipset fw.rules'

cfp_cleanup() {
    # Raw replies (hostnames, LAN addresses) go even when stdout is lost and the stage is retained for inspection:
    # their summaries are in phase.log. Plain rm: the stage is on tmpfs.
    if [ -n "$CFP_DIR" ] && [ -d "$CFP_DIR" ] && [ ! -L "$CFP_DIR" ]; then
        for cfp_name in preview.out wrapper.out inventory.json inventory.w.json settle.neigh settle.tokens settle.map; do rm -f "$CFP_DIR/$cfp_name"; done
    fi
    if [ -n "$CFP_DIR" ] && [ -d "$CFP_DIR" ] && [ ! -L "$CFP_DIR" ] && [ "$CFR_STDOUT_LOST" != 1 ]; then
        # The rpc-sync reply is evidence: copy it to stderr (stderr.log) before
        # removal; stdout must keep the outcome line last.
        if [ -s "$CFP_DIR/rpc-sync.json" ]; then sed 's/^/rpc-sync: /' "$CFP_DIR/rpc-sync.json" >&2 2>/dev/null || :; fi
        if [ -s "$CFP_DIR/scope-sync.json" ]; then sed 's/^/scope-sync: /' "$CFP_DIR/scope-sync.json" >&2 2>/dev/null || :; fi
        for cfp_name in $CFP_FILES; do rm -f "$CFP_DIR/$cfp_name"; done
        rmdir "$CFP_DIR" 2>/dev/null || :
    fi
    cfr_cleanup
}

# PREREQ stage validation and INSTALL both use the exact scoped arguments:
# one --rpc-allow per Penn device, in the sorted order the plan disclosed.
cfr_install_args() {
    printf '%s\n' --platform-profile "$CFR_PROFILE"
    for cfr_allow in $CFP_RPC_ALLOW; do printf '%s\n' --rpc-allow "$cfr_allow"; done
    printf '%s\n' --protect "$CFR_MGMT_MAC" --protect "$CFR_JD_MAC"
    for cfr_old in $CFR_HISTORICAL_MACS; do printf '%s\n' --protect "$cfr_old"; done
}

# Centiseconds since boot (/proc/uptime has two decimals).
cfp_cs() {
    cfp_uptime=/proc/uptime
    # Fixture hook; the production session runs under env -i and CFR_FIXTURE is 0 there.
    if [ "$CFR_FIXTURE" = 1 ] && [ -n "${CFP_UPTIME_FILE:-}" ]; then cfp_uptime=$CFP_UPTIME_FILE; fi
    IFS=' ' read -r cfp_up cfp_rest < "$cfp_uptime" || return 1
    printf '%s\n' "$cfp_up" | awk '{split($1,a,".");printf "%d\n", a[1]*100+substr(a[2] "00",1,2)}'
}
# Wall-clock epoch seconds: only for values the router compares with its own time (a pause --until) and for
# per-call latencies. Elapsed-time budgets and the self-abort use the uptime clock (cfp_elapsed), which a clock
# step cannot move.
cfp_now() { date +%s; }
# Whole seconds since cfp_main started (uptime clock). Empty and non-zero when the clock is unreadable.
cfp_elapsed() {
    cfp_el_cs=$(cfp_cs) || return 1
    [ -n "$cfp_el_cs" ] && [ -n "$CFP_START_CS" ] || return 1
    printf '%s\n' "$(((cfp_el_cs - CFP_START_CS) / 100))"
}
# True while elapsed time plus $1 more seconds still leaves the teardown reserve.
# An unreadable clock is never "ok": callers stop rather than guess.
cfp_elapsed_ok() {
    cfp_eo_el=$(cfp_elapsed) || { cfr_info 'clock_unavailable'; return 1; }
    [ "$((cfp_eo_el + ${1:-0}))" -le "$((CFP_REMOTE_TIMEOUT - CFP_TEARDOWN_RESERVE))" ]
}

# The one place a cfctl, wrapper or uninstall child is started. $1 stdin file, $2 allowance in seconds, then the
# script and its arguments (run by the fixed shell). The child is KILLed at the allowance (exit 137): a hung child can
# never stall the session until the router-side last-resort timeout. A killed cfctl may leave its runtime or platform
# lock behind; the single uninstall then refuses and the run ends FAIL_AFTER_MUTATION, which is the reported outcome.
# Callers must not run it inside $(...): a surviving grandchild could hold the pipe open (busybox timeout kills only
# its direct child), so output goes to a file.
cfp_run() {
    cfp_run_in=$1 cfp_run_t=$2; shift 2
    # shellcheck disable=SC2086
    timeout -s KILL "$cfp_run_t" $CFR_SH "$@" <"$cfp_run_in" 2>>"$CFR_STAGE/child.log"
}

# --- Read-only adult probes -------------------------------------------------
# Prints "<replies> <avg_ms|-> " for three pings (BusyBox or iputils summary).
cfp_ping() {
    timeout -s KILL 8 ping -c 3 -W 1 -q "$1" > "$CFP_DIR/ping.out" 2>/dev/null </dev/null || :
    awk '/packets transmitted/{r=$4}/min\/avg\/max/{split($0,a,"=");split(a[2],b,"/");avg=b[2];gsub(/ /,"",avg)}
        END{if(r!~/^[0-9]+$/)r=0;if(avg=="")avg="-";print r " " avg}' "$CFP_DIR/ping.out"
}
# Router's own resolver on its LAN address; prints "<ok|fail> <centiseconds>".
cfp_dns() {
    cfp_t0=$(cfp_cs) || { printf 'fail 0\n'; return 0; }
    if timeout -s KILL 5 nslookup "$CFP_DNS_NAME" "$CFP_ROUTER_IP" > "$CFP_DIR/dns.out" 2>&1 </dev/null; then cfp_r=ok; else cfp_r=fail; fi
    cfp_t1=$(cfp_cs) || cfp_t1=$cfp_t0
    printf '%s %s\n' "$cfp_r" "$((cfp_t1 - cfp_t0))"
}
cfp_baseline() {
    for cfp_tool in ping nslookup timeout date; do
        command -v "$cfp_tool" >/dev/null 2>&1 || cfr_refuse BASELINE "missing_tool $cfp_tool"
    done
    cfp_cs >/dev/null || cfr_refuse BASELINE uptime_unreadable
    cfp_crond_count baseline
    CFP_BASE_DNS_CS=0
    for cfp_i in 1 2 3; do
        # shellcheck disable=SC2046
        set -- $(cfp_dns)
        [ "$1" = ok ] || cfr_refuse BASELINE router_dns_failed
        [ "$2" -le "$CFP_BASE_DNS_CS" ] || CFP_BASE_DNS_CS=$2
    done
    CFP_DNS_LIMIT_CS=$((CFP_BASE_DNS_CS + CFP_DNS_MARGIN_CS))
    cfr_out "MEASURE baseline_router_dns measured max_cs=$CFP_BASE_DNS_CS limit_cs=$CFP_DNS_LIMIT_CS name=$CFP_DNS_NAME"
    # shellcheck disable=SC2046
    set -- $(cfp_ping "$CFR_MGMT_IP")
    CFP_BASE_MGMT_REPLIES=$1; CFP_BASE_MGMT_AVG=$2
    # shellcheck disable=SC2046
    set -- $(cfp_ping "$CFR_JD_IP")
    CFP_BASE_JD_REPLIES=$1; CFP_BASE_JD_AVG=$2
    for cfp_role in "management $CFP_BASE_MGMT_REPLIES $CFP_BASE_MGMT_AVG" "jd_adult $CFP_BASE_JD_REPLIES $CFP_BASE_JD_AVG"; do
        # shellcheck disable=SC2086
        set -- $cfp_role
        if [ "$2" -gt 0 ]; then cfr_out "MEASURE baseline_${1}_ping measured replies=$2 avg_ms=$3"
        else cfr_out "MEASURE baseline_${1}_ping unmeasured no_icmp_reply_at_baseline"; fi
    done
    cfp_adult_probe baseline || cfr_refuse BASELINE "adult_probe_failed $CFP_ADULT_REASON"
    cfr_ok BASELINE
}
# Adult disruption: lost management session or neighbor, router DNS failure or
# latency above baseline + margin, or ping loss where baseline replied.
cfp_adult_probe() {
    CFP_ADULT_REASON=
    cfp_tag=$1
    if [ "$CFR_MGMT_IP" = "$CFR_JD_IP" ] && [ "$CFR_MGMT_MAC" = "$CFR_JD_MAC" ]; then
        cfr_info "adult $cfp_tag management=jd_adult same_confirmed_device; probes share one device"
    fi
    [ "$CFR_STDOUT_LOST" != 1 ] || { CFP_ADULT_REASON=management_session_lost; return 1; }
    ip -4 neigh show dev br-lan > "$CFR_STAGE/connectivity.neigh" 2>/dev/null </dev/null || { CFP_ADULT_REASON=neighbor_read_failed; return 1; }
    cfr_neighbor "$CFR_MGMT_IP" "$CFR_MGMT_MAC" "$CFR_PRESENT_STATES" "$CFR_STAGE/connectivity.neigh" || { CFP_ADULT_REASON=management_neighbor_lost; return 1; }
    cfr_neighbor "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_PRESENT_STATES" "$CFR_STAGE/connectivity.neigh" || { CFP_ADULT_REASON=jd_adult_neighbor_lost; return 1; }
    # shellcheck disable=SC2046
    set -- $(cfp_dns)
    cfr_info "adult $cfp_tag dns=$1 dns_cs=$2"
    [ "$1" = ok ] || { CFP_ADULT_REASON=router_dns_failed; return 1; }
    [ "$2" -le "${CFP_DNS_LIMIT_CS:-$2}" ] || { CFP_ADULT_REASON="router_dns_slow $2"; return 1; }
    [ "$2" -le "${CFP_MAX_DNS_CS:-0}" ] || CFP_MAX_DNS_CS=$2
    if [ "${CFP_BASE_MGMT_REPLIES:-0}" -gt 0 ]; then
        # shellcheck disable=SC2046
        set -- $(cfp_ping "$CFR_MGMT_IP")
        cfr_info "adult $cfp_tag management_ping replies=$1 avg_ms=$2"
        [ "$1" -gt 0 ] || { CFP_ADULT_REASON=management_ping_lost; return 1; }
        awk -v a="$2" -v b="$CFP_BASE_MGMT_AVG" -v m="$CFP_RTT_MARGIN_MS" 'BEGIN{exit !(a+0 <= b+m)}' || { CFP_ADULT_REASON="management_rtt_high $2"; return 1; }
    fi
    if [ "${CFP_BASE_JD_REPLIES:-0}" -gt 0 ]; then
        # shellcheck disable=SC2046
        set -- $(cfp_ping "$CFR_JD_IP")
        cfr_info "adult $cfp_tag jd_ping replies=$1 avg_ms=$2"
        [ "$1" -gt 0 ] || { CFP_ADULT_REASON=jd_adult_ping_lost; return 1; }
    fi
}
# Crontab directory of one crond pid: arg after -c (or -c/dir), else the BusyBox default;
# empty when the pid has gone.
cfp_crond_dir() {
    tr '\000' '\n' < "${CFP_PROC_DIR:-/proc}/$1/cmdline" 2>/dev/null | awk -v d="${CFP_DEFAULT_CRONTABS:-/var/spool/cron/crontabs}" '
        p { d = $0; p = 0; next }
        $0 == "-c" { p = 1; next }
        substr($0, 1, 2) == "-c" { d = substr($0, 3) }
        END { if (NR) print d }'
}
# GL firmware runs its own crond (-c /tmp/gl_crontabs); only crond on /etc/crontabs is Couvre-feu's.
cfp_crond_count() {
    if command -v pgrep >/dev/null 2>&1; then cfp_pids=$(pgrep crond </dev/null 2>/dev/null)
    else cfp_pids=$(ps w 2>/dev/null | awk '$0~/crond/&&$0!~/awk/{print $1}'); fi
    cfp_etc=0 cfp_other=0 cfp_want=$(readlink -f "${CFP_ETC_CRONTABS:-/etc/crontabs}" 2>/dev/null)
    for cfp_pid in $cfp_pids; do
        cfp_cdir=$(cfp_crond_dir "$cfp_pid")
        [ -n "$cfp_cdir" ] || continue  # pid exited before its cmdline was read
        if [ -n "$cfp_want" ] && [ "$(readlink -f "$cfp_cdir" 2>/dev/null)" = "$cfp_want" ]; then
            cfp_etc=$((cfp_etc + 1))
        else cfp_other=$((cfp_other + 1)); fi
    done
    cfr_info "crond_processes $1 etc=$cfp_etc other=$cfp_other"
    case $1 in
        baseline) CFP_CROND_BASELINE=$cfp_etc CFP_CROND_OTHER_BASELINE=$cfp_other;;
        after_install) CFP_CROND_INSTALL=$cfp_etc CFP_CROND_OTHER_INSTALL=$cfp_other;;
        during_expiry) CFP_CROND_EXPIRY=$cfp_etc CFP_CROND_OTHER_EXPIRY=$cfp_other;;
        after_uninstall) CFP_CROND_UNINSTALL=$cfp_etc CFP_CROND_OTHER_UNINSTALL=$cfp_other;;
    esac
}

# --- Identity additions -------------------------------------------------------
# One Penn device: fresh, unique, single lease; a protected (or the other
# Penn) MAC never shares its IP. $1 role, $2 IP, $3 MAC, $4 IP reason, $5.. other MACs.
cfp_identity_device() {
    cfp_role=$1 cfp_dip=$2 cfp_dmac=$3 cfp_ipreason=$4; shift 4
    cfr_neighbor "$cfp_dip" "$cfp_dmac" "$CFP_FRESH_STATES" "$CFP_DIR/identity.neigh" || cfr_refuse IDENTITY "${cfp_role}_not_fresh"
    awk -v mac="$cfp_dmac" '{for(i=2;i<NF;i++)if($i=="lladdr"&&tolower($(i+1))==mac)n++}END{exit n!=1}' "$CFP_DIR/identity.neigh" ||
        cfr_refuse IDENTITY "${cfp_role}_mac_ambiguous"
    awk -v mac="$cfp_dmac" -v ip="$cfp_dip" 'tolower($2)==mac{m++}$3==ip{i++}END{exit !(m==1&&i==1)}' "$CFR_LEASES" ||
        cfr_refuse IDENTITY "${cfp_role}_lease_ambiguous"
    for cfp_mac in "$@"; do
        [ "$cfp_mac" != "$cfp_dmac" ] || cfr_refuse IDENTITY "${cfp_role}_is_protected"
        awk -v mac="$cfp_mac" -v ip="$cfp_dip" '$1==ip{for(i=2;i<NF;i++)if($i=="lladdr"&&tolower($(i+1))==mac)bad=1}END{exit bad}' "$CFP_DIR/identity.neigh" ||
            cfr_refuse IDENTITY "$cfp_ipreason"
    done
}
# Bounded refresh probe of one child device before its freshness check: two
# ICMP echoes from the router (the BusyBox ping flags cfp_ping already uses)
# make the kernel re-resolve the neighbor, turning an idle Wi-Fi device's STALE
# entry REACHABLE when it answers ARP. A failed probe may itself move STALE to
# DELAY, so it cannot establish freshness: only an already-fresh device may
# ignore probe failure. A network probe only: no router state is written.
cfp_refresh_probe() {
    cfp_rp_fresh=0
    cfr_neighbor "$2" "$3" "$CFP_FRESH_STATES" "$CFP_DIR/identity.neigh" && cfp_rp_fresh=1
    cfr_info "identity refresh_probe $1 ping_count=2 network_probe_only"
    timeout -s KILL 5 ping -c 2 -W 1 -q "$2" >/dev/null 2>&1 </dev/null ||
        [ "$cfp_rp_fresh" = 1 ] || cfr_refuse IDENTITY "${1}_not_fresh"
}
cfp_identity() {
    for cfp_tool in ping timeout; do
        command -v "$cfp_tool" >/dev/null 2>&1 || cfr_refuse IDENTITY "missing_tool $cfp_tool"
    done
    ip -4 neigh show dev br-lan > "$CFP_DIR/identity.neigh" 2>/dev/null </dev/null || cfr_refuse IDENTITY neighbor_read_failed
    cfp_refresh_probe penn_child "$CFR_PENN_IP" "$CFR_PENN_MAC"
    [ -z "$CFP_PENN2_MAC" ] || cfp_refresh_probe penn_child_2 "$CFP_PENN2_IP" "$CFP_PENN2_MAC"
    [ -z "$CFP_V2" ] || cfp_refresh_probe scope_target "$CFP_PHONE_IP" "$CFP_PHONE_MAC"
    ip -4 neigh show dev br-lan > "$CFP_DIR/identity.neigh" 2>/dev/null </dev/null || cfr_refuse IDENTITY neighbor_read_failed
    if [ ! -f "$CFR_LEASES" ] || [ -L "$CFR_LEASES" ]; then cfr_refuse IDENTITY leases_unavailable; fi
    # shellcheck disable=SC2086
    cfp_identity_device penn_child "$CFR_PENN_IP" "$CFR_PENN_MAC" protected_mac_on_penn_ip "$CFR_MGMT_MAC" "$CFR_JD_MAC" $CFR_HISTORICAL_MACS
    if [ -n "$CFP_PENN2_MAC" ]; then
        [ "$CFP_PENN2_IP" != "$CFR_PENN_IP" ] || cfr_refuse IDENTITY penn_child_2_ip_duplicate
        # shellcheck disable=SC2086
        cfp_identity_device penn_child_2 "$CFP_PENN2_IP" "$CFP_PENN2_MAC" protected_mac_on_penn_child_2_ip \
            "$CFR_MGMT_MAC" "$CFR_JD_MAC" "$CFR_PENN_MAC" $CFR_HISTORICAL_MACS
        # The first device's IP must not carry the second device's MAC either.
        awk -v mac="$CFP_PENN2_MAC" -v ip="$CFR_PENN_IP" '$1==ip{for(i=2;i<NF;i++)if($i=="lladdr"&&tolower($(i+1))==mac)bad=1}END{exit bad}' "$CFP_DIR/identity.neigh" ||
            cfr_refuse IDENTITY penn_child_2_mac_on_penn_ip
    fi
    if [ -n "$CFP_V2" ]; then
        # shellcheck disable=SC2086
        cfp_identity_device scope_target "$CFP_PHONE_IP" "$CFP_PHONE_MAC" protected_mac_on_scope_target_ip \
            "$CFR_MGMT_MAC" "$CFR_JD_MAC" "$CFR_PENN_MAC" $CFR_HISTORICAL_MACS
        awk -v mac="$CFP_PHONE_MAC" -v ip="$CFR_PENN_IP" '$1==ip{for(i=2;i<NF;i++)if($i=="lladdr"&&tolower($(i+1))==mac)bad=1}END{exit bad}' "$CFP_DIR/identity.neigh" ||
            cfr_refuse IDENTITY scope_target_mac_on_penn_ip
    fi
    # The synthetic SCOPE MAC must not belong to any live device.
    if [ -n "$CFP_SCOPE_TEST" ]; then
        awk -v mac="$CFP_SCOPE_MAC" '{for(i=1;i<NF;i++)if($i=="lladdr"&&tolower($(i+1))==mac)bad=1}END{exit bad}' "$CFP_DIR/identity.neigh" ||
            cfr_refuse IDENTITY scope_mac_present
        awk -v mac="$CFP_SCOPE_MAC" 'tolower($2)==mac{bad=1}END{exit bad}' "$CFR_LEASES" || cfr_refuse IDENTITY scope_mac_present
    fi
    cfp_policy_only_penn "$CFP_POLICY" || cfr_refuse IDENTITY policy_not_penn_only
    cfr_info "identity penn_child fresh unique; policy admits only penn_child devices=$CFP_RPC_ALLOW"
}
# Every MAC-shaped token in $1 must be in the space-separated set $2, and every
# member of $2 must appear at least once.
cfp_policy_macs() {
    printf '%s\n' "$1" | awk -v set="$2" 'BEGIN{n=split(set,a," ");for(i=1;i<=n;i++)want[a[i]]=1}{s=tolower($0)
        while(match(s,/[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]/)){
            m=substr(s,RSTART,RLENGTH);if(!(m in want))bad=1;else seen[m]=1;s=substr(s,RSTART+RLENGTH)}}
        END{for(m in want)if(!(m in seen))bad=1;exit bad||n<1}'
}
cfp_policy_only_penn() { cfp_policy_macs "$1" "$CFP_RPC_ALLOW"; }
# Two devices: CFP_RPC_ALLOW and CFP_KIDS_JSON must equal the C-sorted pair of
# the two MACs IDENTITY checks (CFR_PENN_MAC, CFP_PENN2_MAC); never trusted alone.
cfp_device_set() {
    for cfp_m in "$CFR_PENN_MAC" "$CFP_PENN2_MAC"; do
        case $cfp_m in
            [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) ;;
            *) return 1;;
        esac
    done
    [ "$CFR_PENN_MAC" != "$CFP_PENN2_MAC" ] || return 1
    cfp_ds=$(printf '%s\n%s\n' "$CFR_PENN_MAC" "$CFP_PENN2_MAC" | LC_ALL=C sort | tr '\n' ' ') || return 1
    cfp_ds=${cfp_ds% }
    [ "$CFP_RPC_ALLOW" = "$cfp_ds" ] || return 1
    [ "$CFP_KIDS_JSON" = "[\"${cfp_ds% *}\",\"${cfp_ds#* }\"]" ]
}

# --- cfctl calls: avoid the cron minute and any in-flight core operation -----
cfp_safe_band() {
    set -f
    # shellcheck disable=SC2086
    set -- $CFP_SAFE_BAND
    set +f
    cfp_i=0
    while [ "$cfp_i" -le 70 ]; do
        cfp_sec=$(date +%S); cfp_sec=${cfp_sec#0}
        if [ "$cfp_sec" -ge "$1" ] && [ "$cfp_sec" -le "$2" ] && [ ! -e "$CFR_ROOT/etc/couvrefeu/runtime/lock" ] && [ ! -e "$CFR_PLATFORM_LOCK" ]; then return 0; fi
        sleep 1; cfp_i=$((cfp_i + 1))
    done
    return 1
}
# Wall seconds of one cfctl call since $1 (epoch); remembers the slowest call seen.
cfp_lat_note() {
    cfp_lat_now=$(cfp_now)
    cfp_lat=$((${cfp_lat_now:-$1} - $1))
    [ "$cfp_lat" -le "$CFP_LAT_MAX" ] || CFP_LAT_MAX=$cfp_lat
}
cfp_cfctl() {
    cfp_safe_band || return 1
    cfp_c_t0=$(cfp_now)
    cfp_run /dev/null "$CFP_CFCTL_ALLOWANCE" "$CFR_CFCTL" "$@"
    cfp_c_rc=$?
    cfp_lat_note "$cfp_c_t0"
    return "$cfp_c_rc"
}
# cfp_c_ran=1 only once cfctl was invoked (0: the safe band never opened).
cfp_cfctl_input() {
    cfp_input=$1; shift
    cfp_c_ran=0
    cfp_safe_band || return 1
    cfp_c_ran=1
    cfp_c_t0=$(cfp_now)
    cfp_run "$cfp_input" "$CFP_CFCTL_ALLOWANCE" "$CFR_CFCTL" "$@"
    cfp_c_rc=$?
    cfp_lat_note "$cfp_c_t0"
    return "$cfp_c_rc"
}
# Timed pause only; fails only if the safe band never opens. The pause outlasts
# its own cfctl call: on a loaded host a call takes tens of seconds, and a pause
# that lapses inside `cfctl pause` leaves effectivePauses empty (set_drift, exit 1).
# So the predeclared length is extended by the slowest cfctl call measured so far,
# capped at the disclosed cfctl allowance (added to the EXPIRY worst case).
# The call itself runs once.
# Optional $2: counters tag snapshotted just before the safe-band wait and the
# pause apply (same slot instance until that apply).
cfp_pause() {
    [ -z "$2" ] || cfp_counters "$2" || cfr_info "counters $2 unavailable"
    cfp_safe_band || return 1
    cfp_extra=$CFP_LAT_MAX
    [ "$cfp_extra" -le "$CFP_CFCTL_ALLOWANCE" ] || cfp_extra=$CFP_CFCTL_ALLOWANCE
    cfp_p_t0=$(cfp_now)
    [ -n "$cfp_p_t0" ] || { cfr_info 'clock_unavailable'; return 1; }
    CFP_UNTIL=$((cfp_p_t0 + $1 + cfp_extra))
    cfr_info "pause ${CFP_PAUSE_WHO:-$CFP_PERSON} until=$CFP_UNTIL seconds=$1 latency_margin_s=$cfp_extra"
    # The printed status line is the gate (exit status alone is not evidence).
    cfp_run /dev/null "$CFP_CFCTL_ALLOWANCE" "$CFR_CFCTL" pause "${CFP_PAUSE_WHO:-$CFP_PERSON}" --until "$CFP_UNTIL" > "$CFP_DIR/status.json" || cfr_info "pause exit $?"
    cfp_lat_note "$cfp_p_t0"
    cfr_info "pause_call latency_s=$cfp_lat remaining_s=$((CFP_UNTIL - ${cfp_lat_now:-$CFP_UNTIL}))"
}
# $1 file, then literal substrings that the single status line must contain.
cfp_status_has() {
    cfp_file=$1; shift
    awk 'END{exit NR!=1}' "$cfp_file" || return 1
    cfr_info "status $(cat "$cfp_file")"
    for cfp_want in '{"ok":true,' '"drift":false,' '"errors":[]}' "$@"; do
        awk -v w="$cfp_want" 'index($0,w){f=1}END{exit !f}' "$cfp_file" || return 1
    done
}
# $1 file, $2 the revision the pilot's own calls set, then the caller's wanted
# substrings: true only for the transient drift a LAN neighbor change after the
# last confirm causes (cf_effective_digest covers every fresh neighbor): one
# line, drift true, errors empty, desired and confirmed revision both $2 (a
# null or stale confirm, which cron could later repair, is never waited out)
# and every wanted kids/pauses substring present. Anything else is a real failure.
cfp_status_transient() {
    cfp_tr_file=$1 cfp_tr_rev=$2; shift 2
    awk 'END{exit NR!=1}' "$cfp_tr_file" || return 1
    for cfp_tr_want in '"drift":true,' '"errors":[]}' "\"desiredRevision\":$cfp_tr_rev," \
        "\"confirmedRevision\":$cfp_tr_rev," "$@"; do
        awk -v w="$cfp_tr_want" 'index($0,w){f=1}END{exit !f}' "$cfp_tr_file" || return 1
    done
}
# Read-only neighbor evidence for one settle attempt ($1 tag), so a run can name
# the neighbor that changed: role MACs by role, other MACs and every IPv6
# address (EUI-64 embeds the MAC) as a 12-hex prefix of sha256(salt+token),
# with one per-run salt that is never logged or written. IPv4 addresses are
# treated the same way: role addresses by role, every other one hashed. Without a
# salt nothing is hashed or logged. The raw neighbor files are removed on return.
cfp_neigh_evidence() {
    if [ -z "$CFP_NE_SALT" ]; then
        CFP_NE_SALT=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | sha256sum | awk '{print $1}')
        # A failed read hashes nothing: the empty-input digest is no salt.
        case $CFP_NE_SALT in *[!0-9a-f]*|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) CFP_NE_SALT=;; esac
        [ "${#CFP_NE_SALT}" = 64 ] || CFP_NE_SALT=
    fi
    [ -n "$CFP_NE_SALT" ] || { cfr_info "status_settle_neigh $1 salt_unavailable"; return 0; }
    if ! timeout -s KILL "$CFP_READ_TIMEOUT" ip neigh show dev br-lan > "$CFP_DIR/settle.neigh" 2>/dev/null </dev/null; then
        cfr_info "status_settle_neigh $1 unreadable"; return 0
    fi
    awk '{if(index($1,":"))print "ip6 " tolower($1);else print "ip4 " $1;for(i=2;i<NF;i++)if($i=="lladdr")print "mac " tolower($(i+1))}' \
        "$CFP_DIR/settle.neigh" | sort -u > "$CFP_DIR/settle.tokens"
    : > "$CFP_DIR/settle.map"
    while read -r cfp_ne_kind cfp_ne_tok; do
        cfp_ne_label=
        if [ "$cfp_ne_kind" = mac ]; then
            case $cfp_ne_tok in
                "$CFR_MGMT_MAC") cfp_ne_label=management;;
                "$CFR_JD_MAC") cfp_ne_label=jd_adult;;
                "$CFR_PENN_MAC") cfp_ne_label=penn_child;;
                "$CFP_PENN2_MAC") cfp_ne_label=penn_child_2;;
                "$CFP_PHONE_MAC") cfp_ne_label=scope_target;;
            esac
            for cfp_ne_old in $CFR_HISTORICAL_MACS; do [ "$cfp_ne_tok" != "$cfp_ne_old" ] || cfp_ne_label=protected; done
        elif [ "$cfp_ne_kind" = ip4 ]; then
            case $cfp_ne_tok in
                "$CFR_MGMT_IP") cfp_ne_label=management;;
                "$CFR_JD_IP") cfp_ne_label=jd_adult;;
                "$CFR_PENN_IP") cfp_ne_label=penn_child;;
                "$CFP_PENN2_IP") cfp_ne_label=penn_child_2;;
                "$CFP_PHONE_IP") cfp_ne_label=scope_target;;
            esac
        fi
        if [ -z "$cfp_ne_label" ]; then
            cfp_ne_sum=$(printf '%s%s' "$CFP_NE_SALT" "$cfp_ne_tok" | sha256sum | awk '{print substr($1,1,12)}')
            cfp_ne_label=$cfp_ne_kind-$cfp_ne_sum
        fi
        printf '%s %s\n' "$cfp_ne_tok" "$cfp_ne_label" >> "$CFP_DIR/settle.map"
    done < "$CFP_DIR/settle.tokens"
    cfr_info "status_settle_neigh $1 $(awk 'NR==FNR{m[$1]=$2;next}
        {a=tolower($1);if(a in m)a=m[a];mac="-";for(i=2;i<NF;i++)if($i=="lladdr")mac=m[tolower($(i+1))]
         printf "%s=%s/%s ",a,mac,$NF}' "$CFP_DIR/settle.map" "$CFP_DIR/settle.neigh")"
    rm -f "$CFP_DIR/settle.neigh" "$CFP_DIR/settle.tokens" "$CFP_DIR/settle.map"
}
# Read-only status gate: $1 phase, $2 its stop reason, $3 expected revision,
# then wanted substrings. A drift-only read (cfp_status_transient) is re-read
# every CFP_POLL seconds, with the budget and adult-probe checks, until it
# passes at the expected revision or CFP_STATUS_SETTLE seconds after the first
# read; cron `cfctl expire`
# re-confirms every minute. Only `cfctl status` runs here: no rpc-sync or other
# mutating call is retried. Each neighbor snapshot follows its status read.
# Worst case after the first read: its neighbor read, the window, plus one
# attempt admitted a second before it closes (1 s date granularity and the
# hashing forks) (cfctl call with a safe-band wait of at most 71 one-second
# steps + neighbor read).
cfp_status_settle() {
    cfp_ss_phase=$1 cfp_ss_reason=$2 cfp_ss_rev=$3; shift 3
    cfp_ss_n=1
    cfp_cfctl status --json > "$CFP_DIR/status.json" || :
    cfp_neigh_evidence "$cfp_ss_phase attempt=1"
    cfp_ss_t0=$(cfp_now)
    [ -n "$cfp_ss_t0" ] || cfp_stop "$cfp_ss_phase" clock_unavailable
    while :; do
        cfp_ss_now=$(cfp_now)
        [ -n "$cfp_ss_now" ] || cfp_stop "$cfp_ss_phase" clock_unavailable
        cfp_ss_log="status_settle $cfp_ss_phase attempts=$cfp_ss_n waited_s=$((cfp_ss_now - cfp_ss_t0))"
        if cfp_status_has "$CFP_DIR/status.json" "\"desiredRevision\":$cfp_ss_rev," \
            "\"confirmedRevision\":$cfp_ss_rev," "$@"; then
            cfr_info "$cfp_ss_log"
            [ "$cfp_ss_n" = 1 ] || cfr_out "MEASURE status_settle measured settled_after_drift phase=$cfp_ss_phase attempts=$cfp_ss_n waited_s=$((cfp_ss_now - cfp_ss_t0))"
            return 0
        fi
        cfp_status_transient "$CFP_DIR/status.json" "$cfp_ss_rev" "$@" || { cfr_info "$cfp_ss_log not_transient"; cfp_stop "$cfp_ss_phase" "$cfp_ss_reason"; }
        [ "$((cfp_ss_now - cfp_ss_t0))" -lt "$((CFP_STATUS_SETTLE - 1))" ] || { cfr_info "$cfp_ss_log gave_up"; cfp_stop "$cfp_ss_phase" "$cfp_ss_reason"; }
        cfp_abort_check "$cfp_ss_phase"
        cfp_elapsed_ok "$((CFP_ITERATION_WORST + CFP_READ_TIMEOUT + 72 + CFP_CFCTL_ALLOWANCE))" ||
            cfp_stop "$cfp_ss_phase" remote_budget_reserved_for_teardown
        cfp_adult_probe "$cfp_ss_phase" || cfp_stop "$cfp_ss_phase" "adult_disruption $CFP_ADULT_REASON"
        sleep "$CFP_POLL"
        cfp_ss_now=$(cfp_now)
        [ -n "$cfp_ss_now" ] || cfp_stop "$cfp_ss_phase" clock_unavailable
        cfp_ss_log="status_settle $cfp_ss_phase attempts=$cfp_ss_n waited_s=$((cfp_ss_now - cfp_ss_t0))"
        [ "$((cfp_ss_now - cfp_ss_t0))" -lt "$((CFP_STATUS_SETTLE - 1))" ] || { cfr_info "$cfp_ss_log gave_up"; cfp_stop "$cfp_ss_phase" "$cfp_ss_reason"; }
        cfp_ss_n=$((cfp_ss_n + 1))
        cfp_cfctl status --json > "$CFP_DIR/status.json" || :
        cfp_neigh_evidence "$cfp_ss_phase attempt=$cfp_ss_n"
    done
}

# --- Kernel reads (lock-free, never -Z) --------------------------------------
cfp_slot() { awk 'NR==2&&($0=="a"||$0=="b"){print;f=1}END{exit !f}' "$CFR_ROOT/etc/couvrefeu/runtime/firewall.owned" 2>/dev/null; }
cfp_paused_members() {
    cfp_s=$(cfp_slot) || return 1
    timeout -s KILL "$CFP_READ_TIMEOUT" ipset save "cf2_${cfp_s}_p" > "$CFP_DIR/members" 2>/dev/null </dev/null || return 1
    awk -v n="cf2_${cfp_s}_p" '$1=="add"&&$2==n{print tolower($3)}' "$CFP_DIR/members"
}
# Prints paused (every Penn device in the set), clear (none), partial (some)
# or unknown (an unreadable set is never read as clear).
cfp_penn_state() { cfp_set_state "$CFP_RPC_ALLOW"; }
# $1 space-separated MACs: paused (all in the paused set), clear (none), partial or unknown.
cfp_set_state() {
    if ! cfp_paused_members > "$CFP_DIR/members.list"; then printf 'unknown\n'; return 0; fi
    awk -v set="$1" 'BEGIN{n=split(set,a," ");for(i=1;i<=n;i++)want[a[i]]=1}
        ($0 in want)&&!seen[$0]++{c++}END{if(c==n)print "paused";else if(c+0==0)print "clear";else print "partial"}' "$CFP_DIR/members.list"
}
# Diagnostic only: paused=, guard_reachable= (cf_fwd jumps to a cf2_[ab]_g in
# either family) and in_u= (Penn in cf2_a_u or cf2_b_u, either slot); each is
# 1, 0 or unknown (a failed read is never 0).
cfp_kernel_state() {
    case $(cfp_penn_state) in paused) cfp_ks_p=1;; clear) cfp_ks_p=0;; *) cfp_ks_p=unknown;; esac
    cfp_ks_g=0
    for cfp_ks_cmd in iptables ip6tables; do
        if ! timeout -s KILL "$CFP_READ_TIMEOUT" "$cfp_ks_cmd" -w 5 -t filter -S > "$CFP_DIR/guard.S" 2>/dev/null </dev/null; then cfp_ks_g=unknown; break; fi
        if awk '$1=="-A"&&$2=="cf_fwd"{for(i=3;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)~/^cf2_[ab]_g$/)f=1}END{exit !f}' "$CFP_DIR/guard.S"; then cfp_ks_g=1; fi
    done
    if ! timeout -s KILL "$CFP_READ_TIMEOUT" ipset save > "$CFP_DIR/members.all" 2>/dev/null </dev/null; then cfp_ks_u=unknown
    elif awk -v set="$CFP_RPC_ALLOW" 'BEGIN{n=split(set,a," ");for(i=1;i<=n;i++)m[a[i]]=1}$1=="add"&&$2~/^cf2_[ab]_u$/&&(tolower($3) in m){f=1}END{exit !f}' "$CFP_DIR/members.all"; then cfp_ks_u=1
    else cfp_ks_u=0; fi
    printf 'paused=%s guard_reachable=%s in_u=%s\n' "$cfp_ks_p" "$cfp_ks_g" "$cfp_ks_u"
}
# Pair `-S` specs with `-nvxL` rows by index; classify only Penn-relevant rules
# (both devices' reverse rules count as one aggregate class).
cfp_chain_counts() {
    if [ "$1" = 4 ]; then cfp_cmd=iptables; else cfp_cmd=ip6tables; fi
    timeout -s KILL "$CFP_READ_TIMEOUT" "$cfp_cmd" -w 5 -t "$2" -S "$3" > "$CFP_DIR/rules.S" 2>/dev/null </dev/null || return 1
    timeout -s KILL "$CFP_READ_TIMEOUT" "$cfp_cmd" -w 5 -t "$2" -nvxL "$3" > "$CFP_DIR/rules.L" 2>/dev/null </dev/null || return 1
    awk -v ip="$CFR_PENN_IP" -v ip2="$CFP_PENN2_IP" -v chain="$3" '
        function cls(s){s=s " "
            if(s~/--match-set cf2_[ab]_p src /&&s~/-j REJECT /)return "paused"
            if(s~/-o br-lan /&&s~/-j REJECT /&&(index(s," -d " ip " ")||index(s," -d " ip "\/32 ")))return "reverse"
            if(ip2!=""&&s~/-o br-lan /&&s~/-j REJECT /&&(index(s," -d " ip2 " ")||index(s," -d " ip2 "\/32 ")))return "reverse"
            if(s~/--dport 853 /)return "dot"
            if(s~/--dport (784|8853) /)return "doq"
            if(s~/--match-set cf2_[ab]_d[46] dst /)return "doh"
            if(s~/--dport 53 /&&s~/-j REJECT /)return "dns6"
            if(s~/--dport 53 /&&s~/-j ACCEPT /)return "dnsin"
            if(s~/-j DNAT /)return "dnat"
            return ""}
        NR==FNR{if($1=="-A"&&$2==chain)spec[++n]=$0;next}
        FNR>2&&NF{r++;c=cls(spec[r]);if(c!=""&&$1~/^[0-9]+$/)print c " " $1}
        END{if(r!=n)exit 1}' "$CFP_DIR/rules.S" "$CFP_DIR/rules.L"
}
# Slot letter plus the inode and nanosecond mtime of firewall.owned, which every
# changing apply rewrites by rename: a/b alternate, so the letter alone cannot
# tell one chain instance (and its counters) from the next.
cfp_slot_id() {
    cfp_sl=$(cfp_slot) || return 1
    cfp_st=$(cfr_stat -c '%i %y' "$CFR_ROOT/etc/couvrefeu/runtime/firewall.owned" </dev/null 2>/dev/null) || return 1
    printf 'slot %s %s\n' "$cfp_sl" "$cfp_st"
}
cfp_counters() {
    cfp_ctag=$1
    rm -f "$CFP_DIR/counters.$cfp_ctag"
    # A skipped snapshot is only "unmeasured"; the teardown reserve comes first.
    cfp_elapsed_ok "$CFP_COUNTERS_WORST" || { cfr_info "counters_skipped $cfp_ctag budget"; return 1; }
    cfp_id=$(cfp_slot_id) || return 1
    cfp_s=$(cfp_slot) || return 1
    # The IPv4 forward chain is required; the others only add classes.
    cfp_chain_counts 4 filter "cf2_${cfp_s}_f" > "$CFP_DIR/rules.out" || return 1
    for cfp_spec in "6 filter f" "4 filter i" "6 filter i" "4 nat d"; do
        # shellcheck disable=SC2086
        set -- $cfp_spec
        if cfp_chain_counts "$1" "$2" "cf2_${cfp_s}_$3" > "$CFP_DIR/rules.one"; then cat "$CFP_DIR/rules.one" >> "$CFP_DIR/rules.out"
        else cfr_info "counters_partial $cfp_ctag $cfp_spec"; fi
    done
    # A slot change during the reads makes the snapshot unusable.
    [ "$(cfp_slot_id)" = "$cfp_id" ] || { cfr_info "counters_slot_changed $cfp_ctag"; return 1; }
    { printf '%s\n' "$cfp_id"
      awk '{t[$1]+=$2}END{split("paused reverse dot doq doh dns6 dnsin dnat",k," ");for(i=1;i<=8;i++)print k[i] " " t[k[i]]+0}' "$CFP_DIR/rules.out"
    } > "$CFP_DIR/counters.$cfp_ctag"
    cfr_info "counters $cfp_ctag $(tr '\n' ' ' < "$CFP_DIR/counters.$cfp_ctag")"
}
# Sum of classes $3.. between snapshots $1 and $2. Prints "-" (unmeasured) when
# either is missing, they come from different slot instances, or any class fell.
cfp_delta() {
    cfp_a=$CFP_DIR/counters.$1; cfp_b=$CFP_DIR/counters.$2; shift 2
    if [ ! -f "$cfp_a" ] || [ ! -f "$cfp_b" ]; then printf '%s\n' -; return 0; fi
    awk -v want=" $* " '$1=="slot"{if(NR==FNR)sa=$0;else sb=$0;next}
        NR==FNR{a[$1]=$2;next}
        index(want," " $1 " "){if(!($1 in a)||$2<a[$1])bad=1;d+=$2-a[$1]}
        END{if(bad||sa==""||sa!=sb)print "-";else print d+0}' "$cfp_a" "$cfp_b"
}
# Sleep $1 seconds in $CFP_POLL steps with adult probes; optional $2 = Penn must stay paused.
# A slot swap by cron `cfctl expire` can make one read transiently unknown;
# three consecutive unknown reads (or any contrary read) stop the pilot.
cfp_state_check() {
    cfp_state=$(cfp_penn_state)
    case $cfp_state in
        unknown) CFP_UNKNOWN=$((CFP_UNKNOWN + 1)); cfr_info "kernel_set_read unknown $CFP_UNKNOWN"
            [ "$CFP_UNKNOWN" -lt 3 ] || cfp_stop "$2" kernel_set_unreadable;;
        partial) cfp_stop "$2" penn_kernel_state_partial;;
        *) CFP_UNKNOWN=0;;
    esac
    [ "$cfp_state" = unknown ] || [ -z "$1" ] || [ "$cfp_state" = "$1" ] || cfp_stop "$2" "penn_kernel_state_not_$1"
}
cfp_observe() {
    cfp_end=$(cfp_now)
    [ -n "$cfp_end" ] || cfp_stop "$3" clock_unavailable
    cfp_end=$((cfp_end + $1))
    CFP_UNKNOWN=0
    while :; do
        cfp_o_now=$(cfp_now)
        [ -n "$cfp_o_now" ] || cfp_stop "$3" clock_unavailable
        [ "$cfp_o_now" -lt "$cfp_end" ] || break
        cfp_abort_check "$3"
        cfp_elapsed_ok "$CFP_ITERATION_WORST" || cfp_stop "$3" remote_budget_reserved_for_teardown
        cfp_adult_probe "$3" || cfp_stop "$3" "adult_disruption $CFP_ADULT_REASON"
        cfp_state_check "$2" "$3"
        sleep "$CFP_POLL"
    done
}

# --- Post-mutation flow -------------------------------------------------------
cfp_stop() {
    cfr_fail "$1" "$2"
    [ -n "$CFP_STOPPED" ] || CFP_STOPPED=$1
    cfr_out "STOP $1 $2"
    cfp_teardown
}
# A stop while a commit leg is outstanding: tell the driver to end it, then wait (bounded by
# CFP_LEG2_CANCEL_WAIT) until the runtime lock is absent and the live scope file's sha256 is the same on two reads
# one second apart, so uninstall cannot race a leg that is still writing. Timing out is reported, never fatal:
# the uninstall is the safety path. The router cannot stop a driver from starting a leg after this marker.
cfp_leg2_quiesce() {
    cfr_out "CFP_LEG2_CANCEL $CFP_LEG2_ACTIVE"
    cfp_q_t0=$(cfp_cs) || cfp_q_t0=0
    cfp_q_prev=
    while :; do
        cfp_q_sha=$(cfp_scope_file_sha)
        if [ ! -e "$CFR_ROOT/etc/couvrefeu/runtime/lock" ] && [ ! -e "$CFR_PLATFORM_LOCK" ] && [ -n "$cfp_q_sha" ] && [ "$cfp_q_sha" = "$cfp_q_prev" ]; then
            cfr_info "leg2_quiesced $CFP_LEG2_ACTIVE"
            return 0
        fi
        cfp_q_prev=$cfp_q_sha
        cfp_q_now=$(cfp_cs) || cfp_q_now=$((cfp_q_t0 + CFP_LEG2_CANCEL_WAIT * 100))
        if [ "$((cfp_q_now - cfp_q_t0))" -ge "$((CFP_LEG2_CANCEL_WAIT * 100))" ]; then
            cfr_info "leg2_quiesce_timeout $CFP_LEG2_ACTIVE"
            return 0
        fi
        sleep 1
    done
}
# Restore verdict: snapshot compare, then the read-only teardown proof, then ONE verdict. PHASE RESTORE OK is printed
# only after the proof passed, so the output never shows both it and a RESTORE FAIL teardown_* line.
cfp_restore() {
    cfp_rs_same=0
    if cfr_snapshot after; then
        if cmp -s "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"; then cfp_rs_same=1
        else cfr_diff; cfr_fail RESTORE snapshot_mismatch; fi
    else cfr_fail RESTORE snapshot_failed; fi
    cfp_teardown_proof
    [ "$cfp_rs_same" = 0 ] || [ "$CFP_PROOF_FAILED" != 0 ] || cfr_ok RESTORE
}
# The single approved teardown; never retried. Always exits.
cfp_teardown() {
    # Ignore signals first: one arriving before CFP_TEARDOWN=1 must not skip uninstall.
    trap '' INT TERM
    [ "$CFP_TEARDOWN" = 0 ] || exit 20
    CFP_TEARDOWN=1
    [ -z "$CFP_LEG2_ACTIVE" ] || cfp_leg2_quiesce
    cfr_uninstall=$CFR_RELEASE_DIR/uninstall.sh
    if [ ! -f "$cfr_uninstall" ]; then
        cfr_fail UNINSTALL installed_uninstall_absent
        cfr_out "PENN_KERNEL_STATE $(cfp_kernel_state)"
        cfr_out 'FAIL_AFTER_MUTATION UNINSTALL'
        exit 20
    fi
    cfp_safe_band || cfr_info 'teardown proceeding outside safe band'
    cfr_info "run uninstall.sh once: $cfr_uninstall"
    cfp_run /dev/null "$CFP_UNINSTALL_ALLOWANCE" "$cfr_uninstall" >>"$CFR_STAGE/child.log"
    cfp_un_rc=$?
    if [ "$cfp_un_rc" != 0 ]; then
        # 137: killed at the allowance (124: a timeout that reports expiry itself).
        case $cfp_un_rc in
            137|124) cfr_fail UNINSTALL 'uninstall_timeout; journal preserved; resolve explicitly';;
            *) cfr_fail UNINSTALL 'uninstall_refused_or_failed; journal preserved; resolve explicitly';;
        esac
        if cfr_snapshot after; then cfr_diff; fi
        # Penn stays blocked while paused; pause rules have no kernel time bound.
        cfr_out "PENN_KERNEL_STATE $(cfp_kernel_state)"
        cfr_out 'FAIL_AFTER_MUTATION UNINSTALL'
        exit 20
    fi
    cfr_ok UNINSTALL
    cfp_crond_count after_uninstall
    cfp_restore
    # CFR_FAILED is already 1 after a STOP; isolate the connectivity result.
    cfp_failed=$CFR_FAILED
    CFR_FAILED=0
    cfr_connectivity
    cfp_connectivity=$CFR_FAILED
    [ "$cfp_failed" = 0 ] || CFR_FAILED=1
    if [ "$CFR_FAILED" = 0 ] && [ -z "$CFP_STOPPED" ]; then cfr_out PENN_PILOT_PASS; exit 0; fi
    if [ -n "$CFP_STOPPED" ] && [ "$CFP_PROOF_FAILED" = 0 ] && cmp -s "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"; then
        cfr_out "STOPPED_AFTER_MUTATION $CFP_STOPPED"
        if [ "$cfp_connectivity" = 0 ]; then cfr_out PENN_PILOT_STOPPED_RESTORED
        else cfr_out PENN_PILOT_STOPPED_RESTORED_CONNECTIVITY_FAILED; fi
        exit 20
    fi
    cfr_out 'FAIL_AFTER_MUTATION summary'
    exit 20
}
# $1 phase, $2 its worst-case seconds: start it only if it can finish before the reserve.
# v2 also refuses to start a phase whose worst case would cross the self-abort mark (stop reason
# remote_self_abort_worst_case), so a phase is not begun that the mark would cut off mid-way.
cfp_budget() {
    cfp_abort_check "$1"
    cfp_elapsed_ok "$2" || cfp_stop "$1" remote_budget_reserved_for_teardown
    [ -n "$CFP_SELF_ABORT_PCT" ] || return 0
    cfp_bu_el=$(cfp_elapsed) || cfp_stop "$1" clock_unavailable
    [ "$(((cfp_bu_el + $2) * 100))" -le "$((CFP_REMOTE_TIMEOUT * CFP_SELF_ABORT_PCT))" ] || cfp_stop "$1" remote_self_abort_worst_case
}
# v2 only (CFP_SELF_ABORT_PCT set): begin the teardown at that percent of the remote timeout, so the router-side
# `timeout -s KILL` (the full timeout) stays a last resort. A run that reaches the mark ends STOPPED (restored).
cfp_abort_check() {
    [ -n "$CFP_SELF_ABORT_PCT" ] || return 0
    cfp_ab_el=$(cfp_elapsed) || cfp_stop "$1" clock_unavailable
    [ "$((cfp_ab_el * 100))" -lt "$((CFP_REMOTE_TIMEOUT * CFP_SELF_ABORT_PCT))" ] || cfp_stop "$1" remote_self_abort
}

# Failure evidence only: no refresh, retry or policy change. Every read reserves
# its full timeout plus output overhead before touching the teardown reserve.
cfp_coverage_read() {
    cfp_cd_kind=$1; shift
    if ! cfp_elapsed_ok "$((CFP_READ_TIMEOUT + 2))"; then
        cfr_info "coverage_diag $cfp_cd_kind skipped teardown_reserve"
        return 1
    fi
    if ! timeout -s KILL "$CFP_READ_TIMEOUT" "$@" > "$CFP_DIR/coverage.$cfp_cd_kind" 2>/dev/null </dev/null; then
        cfr_info "coverage_diag $cfp_cd_kind unavailable read_timeout_or_failed"
        return 1
    fi
}
cfp_coverage_diag() {
    # Six reads plus bounded formatting; failure diagnostics never reduce the
    # disclosed reserve, and add nothing to successful-run timing/minimums.
    if ! cfp_elapsed_ok "$((6 * (CFP_READ_TIMEOUT + 2)))"; then
        cfr_info 'coverage_diag skipped teardown_reserve'
        return 0
    fi
    cfr_info 'coverage_diag non_atomic_failure_snapshot row_limit=16 expected_revision=0 no_retry'
    if cfp_coverage_read clock date -u '+%Y-%m-%dT%H:%M:%SZ epoch=%s'; then
        cfr_info "coverage_diag clock $(cat "$CFP_DIR/coverage.clock")"
    fi
    for cfp_cd_family in 4 6; do
        if cfp_coverage_read "neigh$cfp_cd_family" ip "-$cfp_cd_family" neigh show dev br-lan; then
            awk -v macs=" $CFP_RPC_ALLOW " -v ips=" $CFR_PENN_IP ${CFP_PENN2_IP:-} " '
                {mac="-";state="-";for(i=2;i<=NF;i++){
                    if($i=="lladdr"&&i<NF)mac=tolower($(i+1))
                    if($i~/^(REACHABLE|PERMANENT|STALE|DELAY|PROBE|FAILED|INCOMPLETE|NOARP|NONE|UNCERTAIN)$/)state=$i}
                if(index(macs," " mac " ")||index(ips," " $1 " ")){
                    if(++n<=16)print "INFO coverage_diag neighbor",$1,"mac=" mac,"state=" state
                    else {print "INFO coverage_diag neighbor truncated";exit}}}
            ' "$CFP_DIR/coverage.neigh$cfp_cd_family" | while IFS= read -r cfp_cd_line; do cfr_out "$cfp_cd_line"; done
        fi
    done
    if cfp_coverage_read leases cat "$CFR_LEASES"; then
        awk -v macs=" $CFP_RPC_ALLOW " -v ips=" $CFR_PENN_IP ${CFP_PENN2_IP:-} " '
            index(macs," " tolower($2) " ")||index(ips," " $3 " "){
                if(++n<=16)print "INFO coverage_diag lease expiry=" $1,"mac=" tolower($2),"ip=" $3
                else {print "INFO coverage_diag lease truncated";exit}}
        ' "$CFP_DIR/coverage.leases" | while IFS= read -r cfp_cd_line; do cfr_out "$cfp_cd_line"; done
    fi
    for cfp_cd_family in 4 6; do
        if cfp_coverage_read "addr$cfp_cd_family" ip "-$cfp_cd_family" addr show dev br-lan; then
            awk '{for(i=1;i<NF;i++)if($i=="inet"||$i=="inet6"){
                if(++n<=16)print "INFO coverage_diag lan",$i,$(i+1)
                else {print "INFO coverage_diag lan truncated";exit}}}' "$CFP_DIR/coverage.addr$cfp_cd_family" |
                while IFS= read -r cfp_cd_line; do cfr_out "$cfp_cd_line"; done
        fi
    done
}

cfp_enroll() {
    cfp_cfctl rpc-status --json > "$CFP_DIR/rpc-status.json" || cfp_stop ENROLL rpc_status_failed
    cfp_gen=$(sed -n 's/^{"rpc_version":1,"generation":"\([0-9a-f]\{64\}\)",.*/\1/p' "$CFP_DIR/rpc-status.json")
    cfp_digest=$(sed -n 's/.*,"policyDigest":"\([0-9a-f]\{64\}\)",.*/\1/p' "$CFP_DIR/rpc-status.json")
    if [ "${#cfp_gen}" != 64 ] || [ "${#cfp_digest}" != 64 ]; then cfp_stop ENROLL rpc_status_unparsed; fi
    # Fresh scoped activation only: revision 0 and nobody enrolled.
    grep -q '"acceptedPolicy":{"version":1,"revision":0,"people":\[\],' "$CFP_DIR/rpc-status.json" || cfp_stop ENROLL activation_not_fresh
    printf '{"rpc_version":1,"generation":"%s","operation_id":"%s","expected_revision":0,"expected_digest":"%s","policy":%s}\n' \
        "$cfp_gen" "$CFP_OPERATION_ID" "$cfp_digest" "$CFP_POLICY" > "$CFP_DIR/request.json" || cfp_stop ENROLL request_write_failed
    cfp_policy_only_penn "$(cat "$CFP_DIR/request.json")" || cfp_stop ENROLL request_not_penn_only
    cfr_info "rpc-sync operation=$CFP_OPERATION_ID"
    cfp_cfctl_input "$CFP_DIR/request.json" rpc-sync > "$CFP_DIR/rpc-sync.json" || {
        cfp_rc=$?
        cfr_info "rpc-sync exit=$cfp_rc $(tr '\n' ' ' < "$CFP_DIR/rpc-sync.json")"
        if grep -Fq '"incomplete_transition_address_coverage"' "$CFP_DIR/rpc-sync.json"; then
            cfp_coverage_diag
        fi
        cfp_stop ENROLL rpc_sync_failed
    }
    cfr_info "rpc-sync $(cat "$CFP_DIR/rpc-sync.json")"
    grep -q "\"receipt\":{\"operationId\":\"$CFP_OPERATION_ID\"" "$CFP_DIR/rpc-sync.json" || cfp_stop ENROLL receipt_missing
    CFP_REV=1
    cfp_status_settle ENROLL penn_not_observed "$CFP_REV" "\"observed\":{\"kids\":$CFP_KIDS_JSON,\"paused\":[]}" '"effectivePauses":[]'
    cfr_out 'MEASURE service_key_confinement unmeasured not_exercised'
    [ -z "$CFP_PENN2_MAC" ] || cfp_rpc_activity
    cfp_counters enrolled || cfr_info 'counters enrolled unavailable'
    cfr_ok ENROLL
}
# Read-only, never gating unless it lists a MAC outside Penn's set: one
# rpc-activity call; per-device listing is measured only when exposed.
cfp_rpc_activity() {
    cfp_cfctl rpc-activity --json > "$CFP_DIR/activity.json" || cfr_info "rpc-activity exit $?"
    if ! awk 'END{exit NR!=1}' "$CFP_DIR/activity.json" || ! grep -q '^{"version":1,.*"devices":\[{' "$CFP_DIR/activity.json"; then
        cfr_out 'MEASURE rpc_activity_devices unmeasured rpc_activity_unavailable'
        return 0
    fi
    cfr_info "rpc-activity $(cat "$CFP_DIR/activity.json")"
    cfp_listed=$(awk -v set="$CFP_RPC_ALLOW" -v person="$CFP_PERSON" 'BEGIN{n=split(set,a," ");for(i=1;i<=n;i++)want[a[i]]=1}
        {s=$0;while(match(s,/"person":"[a-z0-9_]*","mac":"[0-9a-f:]*"/)){split(substr(s,RSTART,RLENGTH),f,"\"")
            if(f[4]!=person||!(f[8] in want))bad=1;else if(!seen[f[8]]++)c++;s=substr(s,RSTART+RLENGTH)}}
        END{if(bad)print "bad";else print c+0 "/" n}' "$CFP_DIR/activity.json")
    [ "$cfp_listed" != bad ] || cfp_stop ENROLL rpc_activity_lists_unenrolled_mac
    cfp_errs=
    grep -q ',"errors":\[\]}$' "$CFP_DIR/activity.json" || cfp_errs=' errors_reported'
    cfr_out "MEASURE rpc_activity_devices measured listed=$cfp_listed person=$CFP_PERSON$cfp_errs"
}
# Lock-free firewall fingerprint for SCOPE: firewall.owned slot instance, cf*
# ipset create/add lines and filter-table rules naming cf* (iptables and
# ip6tables). nat and mangle are not compared. $1 output file.
cfp_fw_state() {
    {
        cfp_slot_id || return 1
        timeout -s KILL "$CFP_READ_TIMEOUT" ipset save > "$CFP_DIR/fw.ipset" 2>/dev/null </dev/null || return 1
        awk '($1=="create"||$1=="add")&&$2~/^cf/' "$CFP_DIR/fw.ipset"
        for cfp_fw_cmd in iptables ip6tables; do
            timeout -s KILL "$CFP_READ_TIMEOUT" "$cfp_fw_cmd" -w 5 -t filter -S > "$CFP_DIR/fw.rules" 2>/dev/null </dev/null || return 1
            printf '%s\n' "$cfp_fw_cmd"
            awk 'index($0," cf")' "$CFP_DIR/fw.rules"
        done
    } > "$1"
}
# $1 reply file, $2 exit status, $3 generation, $4 enrolled policy digest.
# Clean only when the router refused with exactly the scope error and still
# reports the enrolled revision, digest, operation and observed devices.
cfp_scope_clean() {
    [ "$2" != 0 ] || return 1
    awk 'END{exit NR!=1}' "$1" || return 1
    cfp_sc_line=$(cat "$1")
    case $cfp_sc_line in "{\"rpc_version\":1,\"generation\":\"$3\","*) ;; *) return 1;; esac
    case $cfp_sc_line in *"$CFP_SCOPE_MAC"*) return 1;; esac
    # Scoped installs append exactly ,"scope":[macs],"scopeSha":"<64 hex>" after errors.
    cfp_sc_line=$(printf '%s\n' "$cfp_sc_line" | sed 's/\(,"errors":\["[a-z_]*"\]\),"scope":\["[0-9a-f:",]*"\],"scopeSha":"[0-9a-f]\{64\}"}$/\1}/')
    case $cfp_sc_line in *",\"errors\":[\"$CFP_SCOPE_ERROR\"]}") ;; *) return 1;; esac
    for cfp_sc_want in '"acceptedPolicy":{"version":1,"revision":1,' \
        "\"policyDigest\":\"$4\",\"currentOperationId\":\"$CFP_OPERATION_ID\"," '"receipt":null,' \
        "\"observed\":{\"kids\":$CFP_KIDS_JSON,\"paused\":[]}"; do
        case $cfp_sc_line in *"$cfp_sc_want"*) ;; *) return 1;; esac
    done
}
# Optional negative test: one rpc-sync naming a synthetic out-of-scope MAC,
# sent once after enrollment. Anything but a clean rejection with an unchanged
# fingerprint stops the pilot (teardown follows); if the safe band never opens
# the call is not made and the stop reason is safe_band_unavailable.
cfp_scope_phase() {
    cfp_digest=$(sed -n 's/.*,"policyDigest":"\([0-9a-f]\{64\}\)",.*/\1/p' "$CFP_DIR/rpc-sync.json")
    [ "${#cfp_digest}" = 64 ] || cfp_stop SCOPE enrolled_digest_unparsed
    printf '{"rpc_version":1,"generation":"%s","operation_id":"%s","expected_revision":1,"expected_digest":"%s","policy":%s}\n' \
        "$cfp_gen" "$CFP_SCOPE_OPERATION_ID" "$cfp_digest" "$CFP_SCOPE_POLICY" > "$CFP_DIR/scope-request.json" || cfp_stop SCOPE request_write_failed
    cfp_policy_macs "$(cat "$CFP_DIR/scope-request.json")" "$CFP_RPC_ALLOW $CFP_SCOPE_MAC" || cfp_stop SCOPE request_unexpected_macs
    cfp_fw_state "$CFP_DIR/fw.before" || cfp_stop SCOPE firewall_read_failed
    cfr_info "scope rpc-sync operation=$CFP_SCOPE_OPERATION_ID expect=$CFP_SCOPE_ERROR"
    cfp_cfctl_input "$CFP_DIR/scope-request.json" rpc-sync > "$CFP_DIR/scope-sync.json"
    cfp_rc=$?
    [ "$cfp_c_ran" = 1 ] || cfp_stop SCOPE safe_band_unavailable
    cfr_info "scope rpc-sync exit=$cfp_rc $(tr '\n' ' ' < "$CFP_DIR/scope-sync.json")"
    cfp_fw_state "$CFP_DIR/fw.after" || cfp_stop SCOPE firewall_read_failed
    cfp_scope_clean "$CFP_DIR/scope-sync.json" "$cfp_rc" "$cfp_gen" "$cfp_digest" || cfp_stop SCOPE scope_not_cleanly_rejected
    cmp -s "$CFP_DIR/fw.before" "$CFP_DIR/fw.after" || cfp_stop SCOPE firewall_changed
    cfr_out "MEASURE scope_negative measured out_of_scope_rpc_sync_rejected error=$CFP_SCOPE_ERROR receipt=null filter_ipset_slot_unchanged"
    cfr_ok SCOPE
}
cfp_pause_phase() {
    cfp_pause "$CFP_PAUSE_SECONDS" prepause || cfp_stop PAUSE pause_failed
    cfp_status_has "$CFP_DIR/status.json" "\"effectivePauses\":[{\"person\":\"$CFP_PERSON\",\"until\":$CFP_UNTIL}]" \
        "\"paused\":$CFP_KIDS_JSON" || cfp_stop PAUSE pause_not_effective
    CFP_REV=$((CFP_REV + 1))
    [ "$(cfp_penn_state)" = paused ] || cfp_stop PAUSE penn_not_in_kernel_set
    cfp_counters pause0 || cfr_info 'counters pause0 unavailable'
    cfr_info pause_observe_begin
    cfp_observe "$CFP_PAUSE_OBSERVE" paused PAUSE
    cfp_counters pause1 || cfr_info 'counters pause1 unavailable'
    CFP_PAUSE_DELTA=$(cfp_delta pause0 pause1 paused reverse)
    case $CFP_PAUSE_DELTA in
        -) cfr_out 'MEASURE packet_blocking unmeasured counters_unavailable_or_slot_changed';;
        0) cfr_out 'MEASURE packet_blocking unmeasured reject_counters_did_not_increase';;
        *) cfr_out "MEASURE packet_blocking measured router_side_block_observed reject_delta=$CFP_PAUSE_DELTA window_s=$CFP_PAUSE_OBSERVE${CFP_PENN2_MAC:+ devices=2 aggregate_set_match_counters per_device_unavailable}";;
    esac
    cfr_ok PAUSE
}
cfp_resume_phase() {
    cfp_cfctl resume "$CFP_PERSON" > "$CFP_DIR/status.json" || :
    cfp_status_has "$CFP_DIR/status.json" '"effectivePauses":[]' '"paused":[]' || cfp_stop RESUME resume_not_clean
    CFP_REV=$((CFP_REV + 1))
    [ "$(cfp_penn_state)" = clear ] || cfp_stop RESUME penn_kernel_state_not_clear
    cfp_counters resume0 || cfr_info 'counters resume0 unavailable'
    cfp_observe "$CFP_RESUME_OBSERVE" clear RESUME
    cfp_counters resume1 || cfr_info 'counters resume1 unavailable'
    cfp_resume_delta=$(cfp_delta resume0 resume1 paused reverse)
    case "$cfp_resume_delta:$CFP_PAUSE_DELTA" in
        -:*|*:-) cfr_out 'MEASURE resume_unblock unmeasured counters_unavailable_or_slot_changed';;
        0:0) cfr_out 'MEASURE resume_unblock unmeasured no_pause_counter_baseline';;
        0:*) cfr_out "MEASURE resume_unblock measured reject_counters_stopped window_s=$CFP_RESUME_OBSERVE";;
        *) cfp_stop RESUME "reject_counters_increased_after_resume $cfp_resume_delta";;
    esac
    cfr_ok RESUME
}
# Service-off expiry: no cfctl call until cron `cfctl expire` empties the set.
cfp_expiry_phase() {
    cfp_pause "$CFP_EXPIRY_SECONDS" || cfp_stop EXPIRY pause_failed
    cfp_status_has "$CFP_DIR/status.json" "\"paused\":$CFP_KIDS_JSON" || cfp_stop EXPIRY pause_not_effective
    CFP_REV=$((CFP_REV + 1))
    cfr_info "expiry_wait_begin until=$CFP_UNTIL tolerance=$CFP_EXPIRY_TOLERANCE"
    cfp_crond_count during_expiry
    cfp_last=0
    CFP_UNKNOWN=0
    while :; do
        cfp_abort_check EXPIRY
        cfp_elapsed_ok "$CFP_ITERATION_WORST" || cfp_stop EXPIRY remote_budget_reserved_for_teardown
        cfp_t=$(cfp_now)
        [ -n "$cfp_t" ] || cfp_stop EXPIRY clock_unavailable
        cfp_state_check '' EXPIRY
        if [ "$cfp_state" = clear ]; then
            [ "$cfp_t" -ge "$CFP_UNTIL" ] || cfp_stop EXPIRY "premature_unpause $((CFP_UNTIL - cfp_t))s_early"
            break
        fi
        [ "$cfp_t" -le "$((CFP_UNTIL + CFP_EXPIRY_TOLERANCE))" ] || cfp_stop EXPIRY not_expired_within_tolerance
        if [ "$((cfp_t - cfp_last))" -ge "$CFP_POLL" ]; then
            cfp_adult_probe EXPIRY || cfp_stop EXPIRY "adult_disruption $CFP_ADULT_REASON"
            cfp_last=$cfp_t
        fi
        sleep "$CFP_EXPIRY_POLL"
    done
    cfr_info "expiry_observed latency_s=$((cfp_t - CFP_UNTIL))"
    cfp_counters expired || cfr_info 'counters expired unavailable'
    cfr_out "MEASURE timed_expiry measured latency_s=$((cfp_t - CFP_UNTIL)) tolerance_s=$CFP_EXPIRY_TOLERANCE poll_s=$CFP_EXPIRY_POLL"
    cfp_status_settle EXPIRY status_not_clean_after_expiry "$CFP_REV" '"effectivePauses":[]' '"paused":[]'
    cfp_dup=
    [ "${CFP_CROND_INSTALL:-0}" -le 1 ] && [ "${CFP_CROND_EXPIRY:-0}" -le 1 ] || cfp_dup=' duplicate_etc_crond'
    cfr_out "MEASURE crond_processes measured baseline=etc$CFP_CROND_BASELINE,other$CFP_CROND_OTHER_BASELINE after_install=etc$CFP_CROND_INSTALL,other$CFP_CROND_OTHER_INSTALL during_expiry=etc$CFP_CROND_EXPIRY,other$CFP_CROND_OTHER_EXPIRY$cfp_dup"
    cfr_ok EXPIRY
}
cfp_dns_phase() {
    cfp_counters final || cfr_info 'counters final unavailable'
    # Every changing apply builds a new slot instance with fresh counters, so
    # hits are summed only over windows whose two snapshots share one instance;
    # apply transitions and the expiry wait are never counted.
    for cfp_class in dot doq doh dns6 dnsin dnat; do
        cfp_d=0; cfp_w=0
        for cfp_win in 'enrolled prepause' 'pause0 pause1' 'resume0 resume1' 'expired final'; do
            # shellcheck disable=SC2086
            cfp_x=$(cfp_delta $cfp_win "$cfp_class")
            [ "$cfp_x" = - ] || { cfp_d=$((cfp_d + cfp_x)); cfp_w=$((cfp_w + 1)); }
        done
        case $cfp_class:$cfp_w:$cfp_d in
            *:0:*) cfr_out "MEASURE dns_rule_$cfp_class unmeasured counters_unavailable_or_slot_changed";;
            doh:*:0) cfr_out "MEASURE dns_rule_doh unmeasured no_hits_and_no_doh_list_configured windows=$cfp_w/4";;
            *:*:0) cfr_out "MEASURE dns_rule_$cfp_class unmeasured no_router_side_hits windows=$cfp_w/4";;
            *) cfr_out "MEASURE dns_rule_$cfp_class measured router_side_hits_while_enrolled=$cfp_d windows=$cfp_w/4 same_slot_windows_only";;
        esac
    done
    cfr_out "MEASURE adult_router_dns measured baseline_max_cs=$CFP_BASE_DNS_CS observed_max_cs=${CFP_MAX_DNS_CS:-0} limit_cs=$CFP_DNS_LIMIT_CS"
    cfr_ok DNS
}

# --- Schema v2 (scope_target) --------------------------------------------------
# Leg 1 only: the scope commit needs a TTY and a typed confirmation, so the local tool (T4) starts each commit leg
# when it sees the marker. Leg 1 never trusts a leg's report: it re-reads rpc-status until the scope changed.
# Privacy: scope-preview prints a lease hostname and protected MACs, rpc-inventory lists every LAN device. Their raw
# output goes to files in the stage dir (removed by cfp_cleanup) and is never echoed; only counts, booleans and
# hashes reach stdout.

# Space-separated MACs, C-sorted pair.
cfp_sorted_pair() { printf '%s\n%s\n' "$1" "$2" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'; }
# "a b" -> ["a","b"]
cfp_mac_json() { printf '%s\n' "$1" | awk '{printf "[";for(i=1;i<=NF;i++)printf "%s\"%s\"",(i>1?",":""),$i;printf "]"}'; }
# $1 person id, $2 space-separated MACs
cfp_person_json() { printf '{"id":"%s","macs":%s}' "$1" "$(cfp_mac_json "$2")"; }
# $1 stage (enroll|phone|move|back), $2 revision, $3 pauses array body. Built from the MACs IDENTITY checked, never
# from a parameter, so a tampered CFP_POLICY_* parameter cannot reach the router.
cfp_stage_json() {
    case $1 in
        enroll) cfp_sj_people=$(cfp_person_json penn "$CFR_PENN_MAC");;
        phone|back) cfp_sj_people=$(cfp_person_json penn "$CFP_BOTH");;
        move) cfp_sj_people="$(cfp_person_json penn "$CFP_PHONE_MAC"),$(cfp_person_json pilot_b "$CFR_PENN_MAC")";;
        *) return 1;;
    esac
    printf '{"version":1,"revision":%s,"people":[%s],"pauses":[%s],"schedules":[],"doh":{"ipv4":[],"ipv6":[]}}' "$2" "$cfp_sj_people" "$3"
}
# PAYLOAD check: the phone is a distinct unprotected device and every stage policy parameter equals the policy this
# script derives from the MACs (at the revision the parameter names).
cfp_v2_check() {
    [ "$CFP_PILOT_B" = pilot_b ] || return 1
    case $CFP_PHONE_MAC in
        [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) ;;
        *) return 1;;
    esac
    [ "$CFP_PHONE_MAC" != "$CFR_PENN_MAC" ] && [ "$CFP_PHONE_IP" != "$CFR_PENN_IP" ] || return 1
    for cfp_v2_m in "$CFR_MGMT_MAC" "$CFR_JD_MAC" $CFR_HISTORICAL_MACS; do
        [ "$cfp_v2_m" != "$CFP_PHONE_MAC" ] || return 1
    done
    CFP_FLOOR=$CFR_PENN_MAC
    CFP_BOTH=$(cfp_sorted_pair "$CFR_PENN_MAC" "$CFP_PHONE_MAC")
    for cfp_v2_s in "enroll:$CFP_POLICY" "phone:$CFP_POLICY_PHONE" "move:$CFP_POLICY_MOVE" "back:$CFP_POLICY_BACK"; do
        cfp_v2_name=${cfp_v2_s%%:*}
        cfp_v2_given=${cfp_v2_s#*:}
        cfp_v2_rev=${cfp_v2_given#'{"version":1,"revision":'}
        cfp_v2_rev=${cfp_v2_rev%%,*}
        case $cfp_v2_rev in ''|*[!0-9]*) return 1;; esac
        [ "$cfp_v2_given" = "$(cfp_stage_json "$cfp_v2_name" "$cfp_v2_rev" '')" ] || return 1
    done
}

# --- rpc-status / rpc-sync helpers ---------------------------------------------
# Parses $CFP_DIR/rpc-status.json (one scoped reply line) into cfp_gen, cfp_digest, cfp_rev_seen, cfp_sc_sha and
# cfp_sc_list (space-separated scope). An empty scope is deliberately a parse failure: a scoped install cannot have
# one (router/lib/core.sh: cf_scope_file needs 1-256 MACs, install.sh refuses an empty --rpc-allow, scope-remove
# refuses a floor MAC with scope_mac_in_floor and cf_scope_load refuses an unscoped install), and the pilot's floor
# (the Chromebook) is always in the scope.
cfp_status_parse() {
    cfp_rs=$CFP_DIR/rpc-status.json
    awk 'END{exit NR!=1}' "$cfp_rs" || return 1
    cfp_gen=$(sed -n 's/^{"rpc_version":1,"generation":"\([0-9a-f]\{64\}\)",.*/\1/p' "$cfp_rs")
    cfp_digest=$(sed -n 's/.*,"policyDigest":"\([0-9a-f]\{64\}\)",.*/\1/p' "$cfp_rs")
    cfp_rev_seen=$(sed -n 's/.*"acceptedPolicy":{"version":1,"revision":\([0-9][0-9]*\),.*/\1/p' "$cfp_rs")
    cfp_sc_sha=$(sed -n 's/.*,"scope":\[[^]]*\],"scopeSha":"\([0-9a-f]\{64\}\)"}$/\1/p' "$cfp_rs")
    cfp_sc_list=$(sed -n 's/.*,"scope":\[\([^]]*\)\],"scopeSha":"[0-9a-f]\{64\}"}$/\1/p' "$cfp_rs" | tr ',' ' ' | tr -d '"')
    [ "${#cfp_gen}" = 64 ] && [ "${#cfp_digest}" = 64 ] && [ "${#cfp_sc_sha}" = 64 ] && [ -n "$cfp_rev_seen" ] && [ -n "$cfp_sc_list" ]
}
# One rpc-status read with its parse; $1 phase.
cfp_status_read() {
    cfp_cfctl rpc-status --json > "$CFP_DIR/rpc-status.json" || cfp_stop "$1" rpc_status_failed
    cfp_status_parse || cfp_stop "$1" rpc_status_unparsed
}
# The router's scopeSha of a space-separated MAC list (sorted, one per line, trailing newline).
# The list comes from the router: split it with globbing off so a `*` stays a word.
# shellcheck disable=SC2086
cfp_scope_sha() { set -f; printf '%s\n' $1 | LC_ALL=C sort | sha256sum | awk '{print $1}'; set +f; }
# $1 space-separated MACs, $2 one more MAC: the sorted, space-separated union (globbing off, as above).
# shellcheck disable=SC2086
cfp_scope_with() { set -f; printf '%s\n' $1 "$2" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'; set +f; }
# $1 phase. One status read (CAS: the revision must be the one the pilot's own calls set).
cfp_sync_prepare() {
    cfp_status_read "$1"
    [ "$cfp_rev_seen" = "$CFP_REV" ] || cfp_stop "$1" "revision_unexpected seen=$cfp_rev_seen want=$CFP_REV"
}
# $1 phase, $2 operation id, $3 policy JSON, $4 space-separated MACs the policy must name (all of them, nothing else).
# One rpc-sync after cfp_sync_prepare, never retried; exactly one receipt, accepted at the next revision.
cfp_sync_send() {
    cfp_sy_phase=$1 cfp_sy_op=$2 cfp_sy_policy=$3 cfp_sy_macs=$4
    case $cfp_sy_policy in
        '{"version":1,"revision":'"$((CFP_REV + 1))"',"people":'*) ;;
        *) cfp_stop "$cfp_sy_phase" policy_revision_mismatch;;
    esac
    printf '{"rpc_version":1,"generation":"%s","operation_id":"%s","expected_revision":%s,"expected_digest":"%s","policy":%s}\n' \
        "$cfp_gen" "$cfp_sy_op" "$CFP_REV" "$cfp_digest" "$cfp_sy_policy" > "$CFP_DIR/request.json" || cfp_stop "$cfp_sy_phase" request_write_failed
    cfp_policy_macs "$(cat "$CFP_DIR/request.json")" "$cfp_sy_macs" || cfp_stop "$cfp_sy_phase" request_unexpected_macs
    cfr_info "rpc-sync operation=$cfp_sy_op"
    cfp_cfctl_input "$CFP_DIR/request.json" rpc-sync > "$CFP_DIR/rpc-sync.json" || {
        cfp_rc=$?
        cfr_info "rpc-sync exit=$cfp_rc $(tr '\n' ' ' < "$CFP_DIR/rpc-sync.json")"
        cfp_stop "$cfp_sy_phase" rpc_sync_failed
    }
    cfp_sy_base=$(sed -n "s/.*\"receipt\":{\"operationId\":\"$cfp_sy_op\",\"requestDigest\":\"[0-9a-f]*\",\"baseRevision\":\([0-9][0-9]*\),.*/\1/p" "$CFP_DIR/rpc-sync.json")
    cfp_sy_acc=$(sed -n "s/.*\"receipt\":{\"operationId\":\"$cfp_sy_op\",.*\"acceptedRevision\":\([0-9][0-9]*\),\"acceptedDigest\".*/\1/p" "$CFP_DIR/rpc-sync.json")
    [ -n "$cfp_sy_base" ] && [ -n "$cfp_sy_acc" ] || cfp_stop "$cfp_sy_phase" receipt_missing
    [ "$cfp_sy_base" = "$CFP_REV" ] && [ "$cfp_sy_acc" = "$((CFP_REV + 1))" ] || cfp_stop "$cfp_sy_phase" "receipt_revision_unexpected base=$cfp_sy_base accepted=$cfp_sy_acc"
    CFP_REV=$cfp_sy_acc
}
cfp_sync() { cfp_sync_prepare "$1"; cfp_sync_send "$@"; }
# The last rpc-sync reply contains the fragment $1.
cfp_reply_has() { grep -Fq "$1" "$CFP_DIR/rpc-sync.json"; }

# --- scope preview, wrapper runs and the leg-2 marker --------------------------
# Wrapper copies are the installed ones; fixtures may point CFP_WRAPPER_DIR at test-mode-capable copies.
cfp_wrapper_dir() {
    cfp_wd=$CFR_ROOT/usr/sbin
    if [ "$CFR_FIXTURE" = 1 ] && [ -n "${CFP_WRAPPER_DIR:-}" ]; then cfp_wd=$CFP_WRAPPER_DIR; fi
    printf '%s\n' "$cfp_wd"
}
# $1 wrapper name, $2 SSH_ORIGINAL_COMMAND, rest: wrapper argv. stdin is /dev/null; child diagnostics go to the stage log.
cfp_wrapper_run() {
    cfp_wr_name=$1 cfp_wr_cmd=$2; shift 2
    # shellcheck disable=SC2086
    env SSH_ORIGINAL_COMMAND="$cfp_wr_cmd" timeout -s KILL "$CFP_CFCTL_ALLOWANCE" $CFR_SH "$(cfp_wrapper_dir)/$cfp_wr_name" "$@" </dev/null 2>>"$CFR_STAGE/child.log"
}
# $1 phase, $2 direct|wrapper. Raw output is in preview.out only until parsed; sets cfp_pv_sha, cfp_pv_count, cfp_pv_absent.
cfp_preview() {
    cfp_safe_band || cfp_stop "$1" safe_band_unavailable
    if [ "$2" = wrapper ]; then cfp_wrapper_run cfctl-scope "cfctl scope-preview $CFP_PHONE_MAC" pilot > "$CFP_DIR/preview.out" || cfp_stop "$1" scope_preview_failed
    else cfp_run /dev/null "$CFP_CFCTL_ALLOWANCE" "$CFR_CFCTL" scope-preview "$CFP_PHONE_MAC" > "$CFP_DIR/preview.out" || cfp_stop "$1" scope_preview_failed; fi
    cfp_pv_line=$(tail -n 1 "$CFP_DIR/preview.out")
    # The raw preview carries a lease hostname: only the parsed summary is kept.
    rm -f "$CFP_DIR/preview.out"
    case $cfp_pv_line in
        "{\"ok\":true,\"action\":\"scope-preview\",\"mac\":\"$CFP_PHONE_MAC\","*",\"errors\":[]}") ;;
        *) cfp_stop "$1" scope_preview_unparsed;;
    esac
    case $cfp_pv_line in *'"inScope":false,'*) ;; *) cfp_stop "$1" scope_target_in_scope_at_start;; esac
    case $cfp_pv_line in *'"evidence":true,'*) ;; *) cfp_stop "$1" scope_target_no_evidence;; esac
    case $cfp_pv_line in
        *'"addRefusal":null,'*) ;;
        *) cfp_pv_why=$(printf '%s\n' "$cfp_pv_line" | sed -n 's/.*"addRefusal":"\([a-z_]*\)".*/\1/p')
           cfp_stop "$1" "scope_add_refused ${cfp_pv_why:-unknown}";;
    esac
    cfp_pv_sha=$(printf '%s\n' "$cfp_pv_line" | sed -n 's/.*,"scopeSha":"\([0-9a-f]\{64\}\)",.*/\1/p')
    cfp_pv_count=$(printf '%s\n' "$cfp_pv_line" | sed -n 's/.*,"scopeCount":\([0-9][0-9]*\),.*/\1/p')
    cfp_pv_absent=$(printf '%s\n' "$cfp_pv_line" | sed -n 's/.*,"protectedAbsent":\([0-9][0-9]*\),.*/\1/p')
    [ "${#cfp_pv_sha}" = 64 ] && [ -n "$cfp_pv_count" ] && [ -n "$cfp_pv_absent" ] || cfp_stop "$1" scope_preview_unparsed
    cfr_out "MEASURE scope_preview_$3 measured in_scope=false evidence=true add_refusal=none scope_entries=$cfp_pv_count protected_absent=$cfp_pv_absent"
}
# The live scope file is read lock-free: the commit leg takes the runtime and platform locks and refuses when they
# are held, so the poll must not hold them. Its sha256 is the router's scopeSha (the file is canonical, LF-terminated).
cfp_scope_file_sha() { sha256sum "$CFR_ROOT/etc/couvrefeu/rpc-allowed" 2>/dev/null | awk '{print $1}'; }
# $1 phase, $2 leg id (2a..2d), $3 base scopeSha the leg commits against, $4 scopeSha that proves the leg's effect,
# $5 add|remove. Prints the marker once, then polls the scope file until it became $4 and confirms with ONE
# authoritative rpc-status read (sha and the phone's membership). The leg's own report is never used. A scope that is
# neither $3 nor $4, a mismatching re-read or CFP_SCOPE_LEG_SECONDS without change stops the pilot.
cfp_leg2() {
    cfp_l_phase=$1 cfp_l_leg=$2 cfp_l_base=$3 cfp_l_want=$4 cfp_l_op=$5
    cfp_safe_band || cfp_stop "$cfp_l_phase" safe_band_unavailable
    # Set before the marker: from here a stop must cancel the leg before uninstall (cleared after the confirming read).
    CFP_LEG2_ACTIVE=$cfp_l_leg
    cfr_out "CFP_LEG2_READY $cfp_l_leg $cfp_l_base"
    cfp_l_t0=$(cfp_now)
    [ -n "$cfp_l_t0" ] || cfp_stop "$cfp_l_phase" clock_unavailable
    while :; do
        cfp_abort_check "$cfp_l_phase"
        cfp_elapsed_ok "$((CFP_CFCTL_ALLOWANCE + 72 + 2))" || cfp_stop "$cfp_l_phase" remote_budget_reserved_for_teardown
        cfp_l_sha=$(cfp_scope_file_sha)
        if [ "$cfp_l_sha" = "$cfp_l_want" ]; then break; fi
        if [ -n "$cfp_l_sha" ] && [ "$cfp_l_sha" != "$cfp_l_base" ]; then cfp_stop "$cfp_l_phase" scope_sha_unexpected; fi
        cfp_l_now=$(cfp_now)
        [ -n "$cfp_l_now" ] || cfp_stop "$cfp_l_phase" clock_unavailable
        [ "$((cfp_l_now - cfp_l_t0))" -lt "$CFP_SCOPE_LEG_SECONDS" ] || cfp_stop "$cfp_l_phase" scope_leg_timeout
        sleep 2
    done
    cfp_status_read "$cfp_l_phase"
    [ "$cfp_sc_sha" = "$cfp_l_want" ] || cfp_stop "$cfp_l_phase" scope_reread_mismatch
    case " $cfp_sc_list " in
        *" $CFP_PHONE_MAC "*) cfp_l_in=add;;
        *) cfp_l_in=remove;;
    esac
    [ "$cfp_l_in" = "$cfp_l_op" ] || cfp_stop "$cfp_l_phase" scope_membership_unexpected
    [ "$(cfp_scope_sha "$cfp_sc_list")" = "$cfp_l_want" ] || cfp_stop "$cfp_l_phase" scope_sha_inconsistent
    cfr_out "MEASURE scope_leg_$cfp_l_leg measured scope_sha_changed membership=$cfp_l_op reread_rpc_status"
    CFP_LEG2_ACTIVE=
}

cfp_scope_add_1_phase() {
    cfp_preview SCOPE-ADD-1 direct add_1
    CFP_BASE0=$cfp_pv_sha
    # No TTY: cfctl must refuse before platform admission, with exactly this reply and no state change.
    cfp_run /dev/null "$CFP_CFCTL_ALLOWANCE" "$CFR_CFCTL" scope-add "$CFP_PHONE_MAC" --base "$CFP_BASE0" > "$CFP_DIR/wrapper.out"
    cfp_nrc=$?
    cfp_na=$(cat "$CFP_DIR/wrapper.out")
    rm -f "$CFP_DIR/wrapper.out"
    { [ "$cfp_nrc" = 1 ] && [ "$cfp_na" = '{"ok":false,"errors":["scope_tty_required"]}' ]; } || cfp_stop SCOPE-ADD-1 scope_tty_refusal_unexpected
    cfp_status_read SCOPE-ADD-1
    [ "$cfp_sc_sha" = "$CFP_BASE0" ] || cfp_stop SCOPE-ADD-1 scope_changed_by_refusal
    [ "$(cfp_scope_sha "$cfp_sc_list")" = "$CFP_BASE0" ] || cfp_stop SCOPE-ADD-1 scope_sha_inconsistent
    CFP_SC_LIST0=$cfp_sc_list
    cfr_out 'MEASURE scope_no_tty_refusal measured scope_tty_required exit=1 state_unchanged'
    CFP_SC_ADDED=$(cfp_scope_with "$CFP_SC_LIST0" "$CFP_PHONE_MAC")
    CFP_SHA_ADDED=$(cfp_scope_sha "$CFP_SC_ADDED")
    cfp_leg2 SCOPE-ADD-1 2a "$CFP_BASE0" "$CFP_SHA_ADDED" add
    cfp_leg2 SCOPE-ADD-1 2b "$CFP_SHA_ADDED" "$CFP_BASE0" remove
    cfr_ok SCOPE-ADD-1
}
# Wrapper argv negatives exit 2 before exec: no cfctl, no state change.
cfp_wrapper_negatives() {
    cfp_wn=0
    for cfp_wn_cmd in 'cfctl scope-add bad' "cfctl scope-add $CFP_PHONE_MAC --base short" \
        "cfctl scope-add $CFP_PHONE_MAC --base $CFP_BASE0 extra" 'cfctl scope-preview'; do
        cfp_wn_out=$(cfp_wrapper_run cfctl-scope "$cfp_wn_cmd" pilot)
        cfp_wn_rc=$?
        { [ "$cfp_wn_rc" = 2 ] && [ -z "$cfp_wn_out" ]; } || cfp_stop SCOPE-ADD-2 wrapper_negative_accepted
        cfp_wn=$((cfp_wn + 1))
    done
    cfr_out "MEASURE scope_wrapper_argv_negatives measured rejected=$cfp_wn exit=2 no_output"
}
cfp_scope_add_2_phase() {
    cfp_preview SCOPE-ADD-2 wrapper add_2
    [ "$cfp_pv_sha" = "$CFP_BASE0" ] || cfp_stop SCOPE-ADD-2 scope_not_restored_after_leg_2b
    cfp_wrapper_negatives
    cfp_status_read SCOPE-ADD-2
    [ "$cfp_sc_sha" = "$CFP_BASE0" ] || cfp_stop SCOPE-ADD-2 scope_changed_by_negatives
    cfp_leg2 SCOPE-ADD-2 2c "$CFP_BASE0" "$CFP_SHA_ADDED" add
    cfp_sync SCOPE-ADD-2 "$CFP_OP_PHONE" "$CFP_POLICY_PHONE" "$CFP_BOTH"
    CFP_RPC_ALLOW=$CFP_BOTH
    CFP_KIDS_JSON=$(cfp_mac_json "$CFP_BOTH")
    CFP_PENN2_IP=$CFP_PHONE_IP
    CFP_PENN2_MAC=$CFP_PHONE_MAC
    cfp_status_settle SCOPE-ADD-2 phone_not_observed "$CFP_REV" "\"observed\":{\"kids\":$CFP_KIDS_JSON,\"paused\":[]}" '"effectivePauses":[]'
    cfr_ok SCOPE-ADD-2
}

# --- MOVE: the Chromebook moves to pilot_b and back; the block follows the device -----------------
# Lock-free firewall shape for the move-back compare: cfp_fw_state without the slot line and with the slot letter
# normalised (every apply may flip a/b).
cfp_fw_shape() {
    cfp_fw_state "$CFP_DIR/fw.raw" || return 1
    sed -e '/^slot /d' -e 's/cf2_[ab]_/cf2_X_/g' "$CFP_DIR/fw.raw" > "$1"
    rm -f "$CFP_DIR/fw.raw"
}
cfp_move_phase() {
    cfp_fw_shape "$CFP_DIR/fw.move0" || cfp_stop MOVE firewall_read_failed
    cfp_sync MOVE "$CFP_OP_MOVE" "$CFP_POLICY_MOVE" "$CFP_BOTH"
    cfp_reply_has "{\"id\":\"pilot_b\",\"macs\":[\"$CFR_PENN_MAC\"]}" || cfp_stop MOVE pilot_b_not_populated
    cfp_reply_has "{\"id\":\"penn\",\"macs\":[\"$CFP_PHONE_MAC\"]}" || cfp_stop MOVE penn_not_phone_only
    cfp_status_settle MOVE move_not_observed "$CFP_REV" "\"observed\":{\"kids\":$CFP_KIDS_JSON,\"paused\":[]}" '"effectivePauses":[]'
    CFP_PAUSE_WHO=$CFP_PILOT_B
    cfp_pause "$CFP_PAUSE_SECONDS" || cfp_stop MOVE pause_failed
    CFP_PAUSE_WHO=
    cfp_status_has "$CFP_DIR/status.json" "\"effectivePauses\":[{\"person\":\"$CFP_PILOT_B\",\"until\":$CFP_UNTIL}]" \
        "\"paused\":[\"$CFR_PENN_MAC\"]" || cfp_stop MOVE pause_not_effective
    CFP_REV=$((CFP_REV + 1))
    cfp_move_kernel_check paused clear
    cfp_adult_probe MOVE || cfp_stop MOVE "adult_disruption $CFP_ADULT_REASON"
    cfp_cfctl resume "$CFP_PILOT_B" > "$CFP_DIR/status.json" || :
    cfp_status_has "$CFP_DIR/status.json" '"effectivePauses":[]' '"paused":[]' || cfp_stop MOVE resume_not_clean
    CFP_REV=$((CFP_REV + 1))
    cfp_move_kernel_check clear clear
    cfp_sync MOVE "$CFP_OP_MOVE_BACK" "$CFP_POLICY_BACK" "$CFP_BOTH"
    cfp_reply_has "{\"id\":\"penn\",\"macs\":$(cfp_mac_json "$CFP_BOTH")}" || cfp_stop MOVE penn_not_restored
    if grep -Fq "$CFP_PILOT_B" "$CFP_DIR/rpc-sync.json"; then cfp_stop MOVE pilot_b_left_populated; fi
    cfp_status_settle MOVE move_back_not_observed "$CFP_REV" "\"observed\":{\"kids\":$CFP_KIDS_JSON,\"paused\":[]}" '"effectivePauses":[]'
    cfp_fw_shape "$CFP_DIR/fw.move1" || cfp_stop MOVE firewall_read_failed
    cmp -s "$CFP_DIR/fw.move0" "$CFP_DIR/fw.move1" || cfp_stop MOVE firewall_not_restored_after_move_back
    cfr_out 'MEASURE move_block_follows_device measured chromebook_paused=1 phone_paused=0 adult_probe_ok moved_back=1 pilot_b_absent=1 filter_ipset_shape_unchanged'
    cfr_ok MOVE
}
# $1 want state of the Chromebook alone, $2 want state of the phone alone (paused|clear), by kernel paused-set member.
cfp_move_kernel_check() {
    cfp_mk_c=$(cfp_set_state "$CFR_PENN_MAC")
    cfp_mk_p=$(cfp_set_state "$CFP_PHONE_MAC")
    [ "$cfp_mk_c" = "$1" ] || cfp_stop MOVE "chromebook_kernel_state_not_$1"
    [ "$cfp_mk_p" = "$2" ] || cfp_stop MOVE "phone_kernel_state_not_$2"
}

# --- BULK: pause_all and resume_all over penn and pilot_b are ONE rpc-sync each -------------------
# Paused-rule count of the forward chain per family (unknown when unreadable). Sets cfp_bc4 and cfp_bc6.
cfp_bulk_chain_state() {
    cfp_bs=$(cfp_slot) || { cfp_bc4=unknown; cfp_bc6=unknown; return 0; }
    if cfp_chain_counts 4 filter "cf2_${cfp_bs}_f" > "$CFP_DIR/bulk.chain" 2>/dev/null; then
        cfp_bc4=$(awk '$1=="paused"{n++}END{print n+0}' "$CFP_DIR/bulk.chain")
    else cfp_bc4=unknown; fi
    if cfp_chain_counts 6 filter "cf2_${cfp_bs}_f" > "$CFP_DIR/bulk.chain" 2>/dev/null; then
        cfp_bc6=$(awk '$1=="paused"{n++}END{print n+0}' "$CFP_DIR/bulk.chain")
    else cfp_bc6=unknown; fi
}
# A failed block-all is reported with the single decided wording (CFP_FAILED_BLOCK_ALL, `unchanged`): provable by
# the firewall fingerprint compare, never a packet claim.
cfp_block_all_failed() {
    cfp_fw_shape "$CFP_DIR/fw.move1" 2>/dev/null && if cmp -s "$CFP_DIR/fw.move0" "$CFP_DIR/fw.move1"; then cfr_info 'bulk firewall_fingerprint same'; else cfr_info 'bulk firewall_fingerprint differs'; fi
    cfp_stop BULK "block_all_$CFP_FAILED_BLOCK_ALL $1"
}
# $1 BULK operation id. The router's receipt for that id is read by id (`rpc-status --json <id>`) and must appear
# exactly once: a replayed or duplicated operation would show none or several.
cfp_bulk_receipt_check() {
    cfp_cfctl rpc-status --json "$1" > "$CFP_DIR/rpc-status.json" || cfp_stop BULK rpc_status_failed
    cfp_br_n=$(grep -o "\"operationId\":\"$1\"" "$CFP_DIR/rpc-status.json" | wc -l | tr -d ' ')
    [ "$cfp_br_n" = 1 ] || cfp_stop BULK "bulk_receipt_count_unexpected id=$1 count=$cfp_br_n"
}
cfp_bulk_phase() {
    cfp_fw_shape "$CFP_DIR/fw.move0" || cfp_stop BULK firewall_read_failed
    cfp_bk_rev0=$CFP_REV
    cfp_sync_prepare BULK
    cfp_bk_now=$(cfp_now)
    [ -n "$cfp_bk_now" ] || cfp_stop BULK clock_unavailable
    cfp_bk_extra=$CFP_LAT_MAX
    [ "$cfp_bk_extra" -le "$CFP_CFCTL_ALLOWANCE" ] || cfp_bk_extra=$CFP_CFCTL_ALLOWANCE
    cfp_bk_until=$((cfp_bk_now + CFP_PAUSE_SECONDS + cfp_bk_extra))
    # Timed pauses only: never an open-ended (until 0) pause.
    [ "$cfp_bk_until" -gt "$cfp_bk_now" ] || cfp_stop BULK pause_not_timed
    cfp_bk_pauses="{\"person\":\"penn\",\"until\":$cfp_bk_until},{\"person\":\"$CFP_PILOT_B\",\"until\":$cfp_bk_until}"
    cfp_sync_send BULK "$CFP_OP_BULK_PAUSE" "$(cfp_stage_json move "$CFP_REV_BULK_PAUSE" "$cfp_bk_pauses")" "$CFP_BOTH"
    cfp_status_settle BULK pause_all_not_observed "$CFP_REV" "\"observed\":{\"kids\":$CFP_KIDS_JSON,\"paused\":$CFP_KIDS_JSON}" \
        "\"person\":\"penn\",\"until\":$cfp_bk_until" "\"person\":\"$CFP_PILOT_B\",\"until\":$cfp_bk_until"
    cfp_bk_rev1=$CFP_REV
    cfp_bulk_receipt_check "$CFP_OP_BULK_PAUSE"
    [ "$(cfp_penn_state)" = paused ] || cfp_block_all_failed set_not_paused
    cfp_bulk_chain_state
    cfp_bk_v4=$cfp_bc4 cfp_bk_v6=$cfp_bc6
    case $cfp_bk_v4 in unknown|0) cfp_block_all_failed ipv4_chain_not_blocking;; esac
    cfp_observe "$CFP_RESUME_OBSERVE" paused BULK
    cfp_sync BULK "$CFP_OP_BULK_RESUME" "$(cfp_stage_json back "$CFP_REV_BULK_RESUME" '')" "$CFP_BOTH"
    cfp_status_settle BULK resume_all_not_observed "$CFP_REV" "\"observed\":{\"kids\":$CFP_KIDS_JSON,\"paused\":[]}" '"effectivePauses":[]'
    [ "$(cfp_penn_state)" = clear ] || cfp_stop BULK penn_kernel_state_not_clear
    cfp_bulk_chain_state
    cfp_bulk_receipt_check "$CFP_OP_BULK_RESUME"
    cfr_out "MEASURE bulk_receipts measured pause_all=1 resume_all=1 revisions=$cfp_bk_rev0,$cfp_bk_rev1,$CFP_REV"
    case $cfp_bk_v6 in
        unknown|0) cfr_out "MEASURE bulk_ipv6 unmeasured partial_or_unconfirmed paused_rules=$cfp_bk_v6 not_retried";;
        *) cfr_out "MEASURE bulk_ipv6 measured paused_rules=$cfp_bk_v6";;
    esac
    cfr_out "MEASURE bulk_ipv4 measured paused_rules=$cfp_bk_v4 set_members=$(printf '%s\n' "$CFP_BOTH" | awk '{print NF}')"
    cfr_ok BULK
}

# --- INVENTORY: counts, shape and hashes only -------------------------------------
# $1 reply file. Sets cfp_iv_* ; returns non-zero with cfp_iv_why. The reply is never printed.
cfp_inventory_check() {
    cfp_iv_why=
    if [ ! -s "$1" ]; then cfp_iv_why=empty_reply; return 1; fi
    if grep -Fq '"errors":["invalid_command"]' "$1"; then cfp_iv_why=invalid_command; return 1; fi
    awk 'END{exit NR!=1}' "$1" || { cfp_iv_why=not_one_line; return 1; }
    grep -q '^{"inventory_version":1,"generation":"[0-9a-f]\{64\}","routerTime":[0-9][0-9]*,"devices":\[' "$1" || { cfp_iv_why=not_inventory_v1; return 1; }
    if ! grep -q ',"errors":\[\]}$' "$1"; then
        cfp_iv_why=$(sed -n 's/.*,"errors":\["\([a-z0-9_]*\)".*/\1/p' "$1")
        cfp_iv_why=reply_errors_${cfp_iv_why:-unknown}; return 1
    fi
    cfp_iv_bytes=$(wc -c < "$1" | tr -d ' ')
    [ "$cfp_iv_bytes" -lt 131072 ] || { cfp_iv_why=reply_too_large; return 1; }
    cfp_iv_count=$(grep -o '{"mac":"' "$1" | wc -l | tr -d ' ')
    if grep -q '"truncated":true,' "$1"; then cfp_iv_trunc=true; else cfp_iv_trunc=false; fi
    for cfp_iv_m in "$CFR_MGMT_MAC" "$CFR_JD_MAC" $CFR_HISTORICAL_MACS; do
        if grep -Fq "\"mac\":\"$cfp_iv_m\"" "$1"; then cfp_iv_why=protected_device_listed; return 1; fi
    done
    for cfp_iv_m in "$CFR_PENN_MAC" "$CFP_PHONE_MAC"; do
        grep -Fq "\"mac\":\"$cfp_iv_m\"" "$1" || { cfp_iv_why=penn_device_missing; return 1; }
    done
    # Top-level key set: the devices array is blanked, the remaining keys are listed in order.
    cfp_iv_shape=$(sed 's/"devices":\[.*\],"truncated"/"devices":[],"truncated"/' "$1" | grep -o '"[a-z_]*":' | tr -d '\n' | sha256sum | awk '{print substr($1,1,12)}')
    cfp_iv_hash=$({ printf '%s' "$cfp_iv_salt"; cat "$1"; } | sha256sum | awk '{print substr($1,1,12)}')
}
cfp_inventory_phase() {
    cfp_iv_salt=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | sha256sum | awk '{print $1}')
    # A failed read hashes nothing: the empty-input digest is no salt.
    case $cfp_iv_salt in *[!0-9a-f]*|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) cfp_iv_salt=;; esac
    [ "${#cfp_iv_salt}" = 64 ] || cfp_stop INVENTORY salt_unavailable
    cfp_iv_ms=
    cfp_iv_counts=
    cfp_iv_first=
    for cfp_iv_n in 1 2 3; do
        cfp_safe_band || cfp_stop INVENTORY safe_band_unavailable
        cfp_iv_t0=$(cfp_cs) || cfp_iv_t0=0
        cfp_run /dev/null "$CFP_CFCTL_ALLOWANCE" "$CFR_CFCTL" rpc-inventory --json > "$CFP_DIR/inventory.json"
        cfp_iv_rc=$?
        cfp_iv_t1=$(cfp_cs) || cfp_iv_t1=$cfp_iv_t0
        cfp_iv_ms="${cfp_iv_ms:+$cfp_iv_ms,}$(((cfp_iv_t1 - cfp_iv_t0) * 10))"
        if [ "$cfp_iv_rc" != 0 ] && ! grep -Fq '"inventory_version":1' "$CFP_DIR/inventory.json"; then
            rm -f "$CFP_DIR/inventory.json"
            cfp_stop INVENTORY "inventory_unsupported exit=$cfp_iv_rc"
        fi
        cfp_inventory_check "$CFP_DIR/inventory.json" || { rm -f "$CFP_DIR/inventory.json"; cfp_stop INVENTORY "inventory_$cfp_iv_why"; }
        # The device count may move between samples (a lease expires, a guest joins); the shape may not.
        cfp_iv_counts="${cfp_iv_counts:+$cfp_iv_counts,}$cfp_iv_count"
        if [ -z "$cfp_iv_first" ]; then cfp_iv_first=$cfp_iv_shape
        elif [ "$cfp_iv_first" != "$cfp_iv_shape" ]; then rm -f "$CFP_DIR/inventory.json"; cfp_stop INVENTORY inventory_shape_changed; fi
        rm -f "$CFP_DIR/inventory.json"
    done
    # The service's real path: the stripped wrapper in --rpc-only mode.
    cfp_safe_band || cfp_stop INVENTORY safe_band_unavailable
    cfp_wrapper_run cfctl-ssh 'cfctl rpc-inventory --json' --rpc-only > "$CFP_DIR/inventory.w.json"
    cfp_iw_rc=$?
    if [ "$cfp_iw_rc" != 0 ]; then rm -f "$CFP_DIR/inventory.w.json"; cfp_stop INVENTORY "wrapper_inventory_failed exit=$cfp_iw_rc"; fi
    cfp_iv_wfirst=$cfp_iv_first
    cfp_inventory_check "$CFP_DIR/inventory.w.json" || { rm -f "$CFP_DIR/inventory.w.json"; cfp_stop INVENTORY "wrapper_inventory_$cfp_iv_why"; }
    rm -f "$CFP_DIR/inventory.w.json"
    [ "$cfp_iv_wfirst" = "$cfp_iv_shape" ] || cfp_stop INVENTORY wrapper_inventory_shape_differs
    cfp_iv_salt=
    cfr_out "MEASURE inventory measured device_counts=$cfp_iv_counts protected_listed=0 penn_devices_listed=2 truncated=$cfp_iv_trunc bytes=$cfp_iv_bytes shape=$cfp_iv_shape reply_salted_sha256=$cfp_iv_hash elapsed_ms=$cfp_iv_ms wrapper_rpc_only=same_shape"
    cfr_ok INVENTORY
}

# --- SCOPE-REMOVE: unenrol first (scope_mac_in_use), then the leg --------------------
cfp_audit_count() {
    if ! command -v logread >/dev/null 2>&1; then cfr_out 'MEASURE scope_audit unmeasured logread_absent'; return 0; fi
    cfp_au=$(timeout -s KILL "$CFP_READ_TIMEOUT" logread -e couvrefeu 2>/dev/null </dev/null | awk '/ scope-(add|remove) phase=(intent|commit) /{n++}END{print n+0}') || cfp_au=0
    if [ "$cfp_au" -gt 0 ]; then cfr_out "MEASURE scope_audit measured lines=$cfp_au"
    else cfr_out 'MEASURE scope_audit unmeasured no_audit_lines_on_device'; fi
}
cfp_scope_remove_phase() {
    cfp_sync SCOPE-REMOVE "$CFP_OP_UNENROL" "$(cfp_stage_json enroll "$CFP_REV_UNENROL" '')" "$CFP_FLOOR"
    CFP_RPC_ALLOW=$CFP_FLOOR
    CFP_KIDS_JSON="[\"$CFP_FLOOR\"]"
    CFP_PENN2_IP=
    CFP_PENN2_MAC=
    cfp_status_settle SCOPE-REMOVE unenrol_not_observed "$CFP_REV" "\"observed\":{\"kids\":$CFP_KIDS_JSON,\"paused\":[]}" '"effectivePauses":[]'
    cfp_status_read SCOPE-REMOVE
    [ "$cfp_sc_sha" = "$CFP_SHA_ADDED" ] || cfp_stop SCOPE-REMOVE scope_changed_before_leg
    cfp_leg2 SCOPE-REMOVE 2d "$CFP_SHA_ADDED" "$CFP_BASE0" remove
    cfp_audit_count
    cfr_ok SCOPE-REMOVE
}

# Read-only proof after UNINSTALL and RESTORE (v1 and v2): no scope candidate left, the cf* ipset and chain
# lines as before, the /etc/crontabs crond count back to baseline, no person in state, no release directory.
# Every file must exist (-f): a missing file is `missing`, never a vacuous count of 0.
cfp_cf_lines() {
    for cfp_cl_f in "$@"; do [ -f "$cfp_cl_f" ] || { printf 'missing\n'; return 1; }; done
    awk '{for(i=1;i<=NF;i++)if($i~/^cf/){n++;break}}END{print n+0}' "$@" 2>/dev/null
}
cfp_teardown_proof() {
    CFP_PROOF_FAILED=0
    cfp_tp_scope=0
    for cfp_tp_f in "$CFR_ROOT"/etc/couvrefeu/runtime/.scope.* "$CFR_ROOT"/etc/couvrefeu/.scope.*; do
        if [ -e "$cfp_tp_f" ] || [ -L "$cfp_tp_f" ]; then cfp_tp_scope=$((cfp_tp_scope + 1)); fi
    done
    cfp_tp_have=1
    cfp_tp_sets=$(cfp_cf_lines "$CFR_STAGE/text.after.ipset" "$CFR_STAGE/text.after.ipsetsave") || cfp_tp_have=0
    cfp_tp_sets0=$(cfp_cf_lines "$CFR_STAGE/text.before.ipset" "$CFR_STAGE/text.before.ipsetsave") || cfp_tp_have=0
    cfp_tp_v4=$(cfp_cf_lines "$CFR_STAGE/text.after.iptables") || cfp_tp_have=0
    cfp_tp_v40=$(cfp_cf_lines "$CFR_STAGE/text.before.iptables") || cfp_tp_have=0
    cfp_tp_v6=$(cfp_cf_lines "$CFR_STAGE/text.after.ip6tables") || cfp_tp_have=0
    cfp_tp_v60=$(cfp_cf_lines "$CFR_STAGE/text.before.ip6tables") || cfp_tp_have=0
    cfp_tp_people=0
    if [ -f "$CFR_ROOT/etc/couvrefeu/state" ] && grep -Eq 'penn|pilot_b' "$CFR_ROOT/etc/couvrefeu/state"; then cfp_tp_people=1; fi
    cfp_tp_rel=absent
    if [ -e "$CFR_RELEASE_DIR" ]; then cfp_tp_rel=present; fi
    [ "$cfp_tp_have" = 1 ] || { cfr_fail RESTORE teardown_evidence_missing; CFP_PROOF_FAILED=1; }
    [ "$cfp_tp_scope" = 0 ] || { cfr_fail RESTORE teardown_scope_candidate_left; CFP_PROOF_FAILED=1; }
    [ "$cfp_tp_sets" = "$cfp_tp_sets0" ] || { cfr_fail RESTORE teardown_cf_ipset_left; CFP_PROOF_FAILED=1; }
    { [ "$cfp_tp_v4" = "$cfp_tp_v40" ] && [ "$cfp_tp_v6" = "$cfp_tp_v60" ]; } || { cfr_fail RESTORE teardown_cf_chain_left; CFP_PROOF_FAILED=1; }
    [ "${CFP_CROND_UNINSTALL:-x}" = "${CFP_CROND_BASELINE:-y}" ] || { cfr_fail RESTORE teardown_crond_count_changed; CFP_PROOF_FAILED=1; }
    [ "$cfp_tp_people" = 0 ] || { cfr_fail RESTORE teardown_person_left_in_state; CFP_PROOF_FAILED=1; }
    [ "$cfp_tp_rel" = absent ] || { cfr_fail RESTORE teardown_release_dir_left; CFP_PROOF_FAILED=1; }
    cfr_out "MEASURE teardown_proof measured scope_candidates=$cfp_tp_scope cf_ipset_lines=$cfp_tp_sets/$cfp_tp_sets0 cf_iptables_lines=$cfp_tp_v4/$cfp_tp_v40 cf_ip6tables_lines=$cfp_tp_v6/$cfp_tp_v60 crond_etc=${CFP_CROND_UNINSTALL:-?}/${CFP_CROND_BASELINE:-?} state_people=$cfp_tp_people release_dir=$cfp_tp_rel"
}

# The post-install phase order (DEC-4 for v2).
cfp_phase_list() {
    if [ -n "$CFP_V2" ]; then
        printf '%s\n' "ENROLL ${CFP_SCOPE_TEST:+SCOPE }SCOPE-ADD-1 SCOPE-ADD-2 PAUSE RESUME MOVE BULK EXPIRY DNS INVENTORY SCOPE-REMOVE"
    else
        printf '%s\n' "ENROLL ${CFP_SCOPE_TEST:+SCOPE }PAUSE RESUME EXPIRY DNS"
    fi
}

cfp_main() {
    umask 077
    CFR_START=$(date +%s)
    CFR_PREMUTATION_BUDGET=$CFP_PREMUTATION_BUDGET
    printf 'BEGIN penn-pilot commit=%s release=%s profile=%s\n' "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE"
    for cfr_value in "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE" "$CFR_MGMT_IP" "$CFR_MGMT_MAC" "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_PENN_IP" "$CFR_PENN_MAC" "$CFR_HISTORICAL_MACS" \
        "$CFP_ROUTER_IP" "$CFP_PERSON" "$CFP_OPERATION_ID" "$CFP_POLICY" "$CFP_DNS_NAME" "$CFP_SAFE_BAND" "$CFP_STATUS_SETTLE" "$CFP_REMOTE_TIMEOUT" \
        "$CFP_TEARDOWN_RESERVE" "$CFP_READ_TIMEOUT" "$CFP_COUNTERS_WORST" "$CFP_ITERATION_WORST" "$CFP_CFCTL_ALLOWANCE" "$CFP_WORST_ENROLL" "$CFP_WORST_PAUSE" \
        "$CFP_WORST_RESUME" "$CFP_WORST_EXPIRY" "$CFP_WORST_DNS"; do
        [ -n "$cfr_value" ] || cfr_refuse PAYLOAD parameters_missing
    done
    if [ -n "$CFP_PENN2_MAC$CFP_PENN2_IP" ]; then
        for cfr_value in "$CFP_PENN2_IP" "$CFP_PENN2_MAC" "$CFP_RPC_ALLOW" "$CFP_KIDS_JSON"; do
            [ -n "$cfr_value" ] || cfr_refuse PAYLOAD parameters_missing
        done
        cfp_device_set || cfr_refuse PAYLOAD device_set_mismatch
    else
        # Single device: the set is Penn's one MAC.
        CFP_RPC_ALLOW=$CFR_PENN_MAC
        CFP_KIDS_JSON="[\"$CFR_PENN_MAC\"]"
    fi
    if [ -n "$CFP_V2" ]; then
        for cfr_value in "$CFP_PHONE_IP" "$CFP_PHONE_MAC" "$CFP_PILOT_B" "$CFP_POLICY_PHONE" "$CFP_POLICY_MOVE" "$CFP_POLICY_BACK" \
            "$CFP_OP_PHONE" "$CFP_OP_MOVE" "$CFP_OP_MOVE_BACK" "$CFP_OP_BULK_PAUSE" "$CFP_OP_BULK_RESUME" "$CFP_OP_UNENROL" \
            "$CFP_REV_BULK_PAUSE" "$CFP_REV_BULK_RESUME" "$CFP_REV_UNENROL" "$CFP_SCOPE_LEG_SECONDS" "$CFP_FAILED_BLOCK_ALL" "$CFP_SELF_ABORT_PCT" "$CFP_WORST_SCOPE_ADD_1" "$CFP_WORST_SCOPE_ADD_2" \
            "$CFP_WORST_MOVE" "$CFP_WORST_BULK" "$CFP_WORST_INVENTORY" "$CFP_WORST_SCOPE_REMOVE"; do
            [ -n "$cfr_value" ] || cfr_refuse PAYLOAD parameters_missing
        done
        [ -z "$CFP_PENN2_MAC$CFP_PENN2_IP" ] || cfr_refuse PAYLOAD penn_child_2_with_scope_target
    fi
    if [ -n "$CFP_SCOPE_TEST" ]; then
        for cfr_value in "$CFP_SCOPE_MAC" "$CFP_SCOPE_OPERATION_ID" "$CFP_SCOPE_ERROR" "$CFP_SCOPE_POLICY" "$CFP_WORST_SCOPE"; do
            [ -n "$cfr_value" ] || cfr_refuse PAYLOAD parameters_missing
        done
    fi
    cfr_setup_paths || cfr_refuse PAYLOAD unsafe_environment
    # After cfr_setup_paths: the uptime file override is honoured only once CFR_FIXTURE is known.
    CFP_START_CS=$(cfp_cs) || cfr_refuse PAYLOAD uptime_unreadable
    [ -z "$CFP_V2" ] || cfp_v2_check || cfr_refuse PAYLOAD policy_stage_mismatch
    [ "$(id -u)" = 0 ] || [ "$CFR_FIXTURE" = 1 ] || cfr_refuse PAYLOAD root_required
    trap cfp_cleanup 0
    trap 'exit 10' HUP INT TERM PIPE
    cfr_extract
    CFP_DIR=$CFR_STAGE/pilot
    mkdir -m 700 "$CFP_DIR" || cfr_refuse PAYLOAD pilot_dir
    cfp_identity
    cfr_identity
    cfr_prereq
    cfr_snapshot before || cfr_refuse SNAPSHOT snapshot_failed
    while IFS= read -r cfr_line; do cfr_out "SNAPSHOT $cfr_line"; done < "$CFR_STAGE/snapshot.before"
    cfr_ok SNAPSHOT
    cfp_baseline
    cfp_pm_el=$(cfp_elapsed) || cfr_refuse BASELINE uptime_unreadable
    [ "$cfp_pm_el" -le "$CFR_PREMUTATION_BUDGET" ] || cfr_refuse BASELINE premutation_budget_exceeded
    trap '' HUP PIPE
    trap 'cfp_stop SIGNAL interrupted' INT TERM
    cfr_out MUTATION_BEGIN
    CFP_MUTATED=1
    cfp_safe_band || cfr_info 'install proceeding outside safe band'
    # Deviation from the rehearsal: an install failure still runs the installed
    # recovery uninstall.sh once when present (single teardown path).
    cfr_install --activate || cfp_stop INSTALL installer_exit_nonzero
    cfr_ok INSTALL
    cfp_crond_count after_install
    for cfp_phase in $(cfp_phase_list); do
        case $cfp_phase in
            ENROLL) cfp_budget ENROLL "$CFP_WORST_ENROLL"; cfp_enroll;;
            SCOPE) cfp_budget SCOPE "$CFP_WORST_SCOPE"; cfp_scope_phase;;
            PAUSE) cfp_budget PAUSE "$CFP_WORST_PAUSE"; cfp_pause_phase;;
            RESUME) cfp_budget RESUME "$CFP_WORST_RESUME"; cfp_resume_phase;;
            EXPIRY) cfp_budget EXPIRY "$CFP_WORST_EXPIRY"; cfp_expiry_phase;;
            DNS) cfp_budget DNS "$CFP_WORST_DNS"; cfp_dns_phase;;
            SCOPE-ADD-1) cfp_budget SCOPE-ADD-1 "$CFP_WORST_SCOPE_ADD_1"; cfp_scope_add_1_phase;;
            SCOPE-ADD-2) cfp_budget SCOPE-ADD-2 "$CFP_WORST_SCOPE_ADD_2"; cfp_scope_add_2_phase;;
            MOVE) cfp_budget MOVE "$CFP_WORST_MOVE"; cfp_move_phase;;
            BULK) cfp_budget BULK "$CFP_WORST_BULK"; cfp_bulk_phase;;
            INVENTORY) cfp_budget INVENTORY "$CFP_WORST_INVENTORY"; cfp_inventory_phase;;
            SCOPE-REMOVE) cfp_budget SCOPE-REMOVE "$CFP_WORST_SCOPE_REMOVE"; cfp_scope_remove_phase;;
        esac
    done
    cfp_teardown
}

# Parse everything above first; no child can read the remaining script.
cfp_main </dev/null
# Unreachable unless cfp_main returns; fail closed.
# shellcheck disable=SC2317
exit 20
