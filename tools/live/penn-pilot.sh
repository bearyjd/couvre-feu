#!/bin/sh
# Couvre-feu one-device (Penn) live pilot, appended by tools/live/penn-pilot.py
# to the filled first-rehearsal.sh (its final cfr_main call removed), so every
# cfr_* helper, the payload, identity, snapshot, restore and connectivity code
# is the live-proven rehearsal code. Later definitions here win in sh.
# Phases: PAYLOAD IDENTITY PREREQ SNAPSHOT BASELINE INSTALL ENROLL PAUSE RESUME
# EXPIRY DNS UNINSTALL RESTORE CONNECTIVITY. After MUTATION_BEGIN every path
# ends in one teardown: installed uninstall.sh once, exact snapshot compare and
# connectivity. Pauses are always timed (--until); pause rules carry no kernel
# time bound, so cron `cfctl expire` bounds them if the session is lost.
# Never touches dnsmasq, the WAN zone, offload or firmware; DNS probes only
# read. Exit codes: 0 pass, 10 refused before mutation, 20 after mutation.
# shellcheck disable=SC2034,SC2153,SC2154,SC2329
# CFR_* variables and cfr_* functions come from first-rehearsal.sh.
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
CFP_SAFE_BAND=
CFP_DNS_MARGIN_CS=
CFP_RTT_MARGIN_MS=
CFP_PREMUTATION_BUDGET=
CFP_REMOTE_TIMEOUT=
CFP_TEARDOWN_RESERVE=
# @CF_PILOT_PARAMETERS_END@

CFP_DIR=
CFP_MUTATED=0
CFP_TEARDOWN=0
CFP_STOPPED=
CFP_FRESH_STATES='REACHABLE DELAY'
CFP_FILES='rpc-status.json request.json rpc-sync.json status.json rules.S rules.L rules.one rules.out members members.list dns.out ping.out identity.neigh counters.enrolled counters.pause0 counters.pause1 counters.resume0 counters.resume1 counters.final'

cfp_cleanup() {
    if [ -n "$CFP_DIR" ] && [ -d "$CFP_DIR" ] && [ ! -L "$CFP_DIR" ] && [ "$CFR_STDOUT_LOST" != 1 ]; then
        for cfp_name in $CFP_FILES; do rm -f "$CFP_DIR/$cfp_name"; done
        rmdir "$CFP_DIR" 2>/dev/null || :
    fi
    cfr_cleanup
}

# PREREQ stage validation and INSTALL both use the exact scoped arguments.
cfr_install_args() {
    printf '%s\n' --platform-profile "$CFR_PROFILE" --rpc-allow "$CFR_PENN_MAC" --protect "$CFR_MGMT_MAC" --protect "$CFR_JD_MAC"
    for cfr_old in $CFR_HISTORICAL_MACS; do printf '%s\n' --protect "$cfr_old"; done
}

# Centiseconds since boot (/proc/uptime has two decimals).
cfp_cs() {
    IFS=' ' read -r cfp_up cfp_rest < /proc/uptime || return 1
    printf '%s\n' "$cfp_up" | awk '{split($1,a,".");printf "%d\n", a[1]*100+substr(a[2] "00",1,2)}'
}
cfp_now() { date +%s; }
cfp_elapsed_ok() { [ "$(($(cfp_now) - CFR_START))" -le "$((CFP_REMOTE_TIMEOUT - CFP_TEARDOWN_RESERVE))" ]; }

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
cfp_crond_count() {
    if command -v pgrep >/dev/null 2>&1; then cfp_n=$(pgrep crond </dev/null 2>/dev/null | wc -l)
    else cfp_n=$(ps w 2>/dev/null | awk '$0~/crond/&&$0!~/awk/{n++}END{print n+0}'); fi
    cfr_info "crond_processes $1 $cfp_n"
    case $1 in
        baseline) CFP_CROND_BASELINE=$cfp_n;; after_install) CFP_CROND_INSTALL=$cfp_n;;
        during_expiry) CFP_CROND_EXPIRY=$cfp_n;; after_uninstall) CFP_CROND_UNINSTALL=$cfp_n;;
    esac
}

# --- Identity additions -------------------------------------------------------
# Penn: fresh, unique, single lease; a protected MAC never shares Penn's IP.
cfp_identity() {
    ip -4 neigh show dev br-lan > "$CFP_DIR/identity.neigh" 2>/dev/null </dev/null || cfr_refuse IDENTITY neighbor_read_failed
    if [ ! -f "$CFR_LEASES" ] || [ -L "$CFR_LEASES" ]; then cfr_refuse IDENTITY leases_unavailable; fi
    cfr_neighbor "$CFR_PENN_IP" "$CFR_PENN_MAC" "$CFP_FRESH_STATES" "$CFP_DIR/identity.neigh" || cfr_refuse IDENTITY penn_child_not_fresh
    awk -v mac="$CFR_PENN_MAC" '{for(i=2;i<NF;i++)if($i=="lladdr"&&tolower($(i+1))==mac)n++}END{exit n!=1}' "$CFP_DIR/identity.neigh" ||
        cfr_refuse IDENTITY penn_child_mac_ambiguous
    awk -v mac="$CFR_PENN_MAC" -v ip="$CFR_PENN_IP" 'tolower($2)==mac{m++}$3==ip{i++}END{exit !(m==1&&i==1)}' "$CFR_LEASES" ||
        cfr_refuse IDENTITY penn_child_lease_ambiguous
    for cfp_mac in "$CFR_MGMT_MAC" "$CFR_JD_MAC" $CFR_HISTORICAL_MACS; do
        [ "$cfp_mac" != "$CFR_PENN_MAC" ] || cfr_refuse IDENTITY penn_child_is_protected
        awk -v mac="$cfp_mac" -v ip="$CFR_PENN_IP" '$1==ip{for(i=2;i<NF;i++)if($i=="lladdr"&&tolower($(i+1))==mac)bad=1}END{exit bad}' "$CFP_DIR/identity.neigh" ||
            cfr_refuse IDENTITY protected_mac_on_penn_ip
    done
    cfp_policy_only_penn "$CFP_POLICY" || cfr_refuse IDENTITY policy_not_penn_only
    cfr_info 'identity penn_child fresh unique; policy admits only penn_child'
}
# Every MAC-shaped token in $1 must be Penn's, at least once.
cfp_policy_only_penn() {
    printf '%s\n' "$1" | awk -v penn="$CFR_PENN_MAC" '{s=tolower($0)
        while(match(s,/[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]/)){
            if(substr(s,RSTART,RLENGTH)!=penn)bad=1;n++;s=substr(s,RSTART+RLENGTH)}}END{exit bad||n<1}'
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
cfp_cfctl() {
    cfp_safe_band || return 1
    cfr_run_sh "$CFR_CFCTL" "$@"
}
cfp_cfctl_input() {
    cfp_input=$1; shift
    cfp_safe_band || return 1
    # shellcheck disable=SC2086
    $CFR_SH "$CFR_CFCTL" "$@" <"$cfp_input" 2>>"$CFR_STAGE/child.log"
}
# Timed pause only; fails only if the safe band never opens.
cfp_pause() {
    cfp_safe_band || return 1
    CFP_UNTIL=$(($(cfp_now) + $1))
    cfr_info "pause $CFP_PERSON until=$CFP_UNTIL seconds=$1"
    # The printed status line is the gate (exit status alone is not evidence).
    cfr_run_sh "$CFR_CFCTL" pause "$CFP_PERSON" --until "$CFP_UNTIL" > "$CFP_DIR/status.json" || cfr_info "pause exit $?"
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
cfp_status() {
    cfp_cfctl status --json > "$CFP_DIR/status.json" || :
    cfp_status_has "$CFP_DIR/status.json" "$@"
}

# --- Kernel reads (lock-free, never -Z) --------------------------------------
cfp_slot() { awk 'NR==2&&($0=="a"||$0=="b"){print;f=1}END{exit !f}' "$CFR_ROOT/etc/couvrefeu/runtime/firewall.owned" 2>/dev/null; }
cfp_paused_members() {
    cfp_s=$(cfp_slot) || return 1
    ipset save "cf2_${cfp_s}_p" > "$CFP_DIR/members" 2>/dev/null </dev/null || return 1
    awk -v n="cf2_${cfp_s}_p" '$1=="add"&&$2==n{print tolower($3)}' "$CFP_DIR/members"
}
# Prints paused, clear or unknown (an unreadable set is never read as clear).
cfp_penn_state() {
    if ! cfp_paused_members > "$CFP_DIR/members.list"; then printf 'unknown\n'
    elif grep -qx "$CFR_PENN_MAC" "$CFP_DIR/members.list"; then printf 'paused\n'
    else printf 'clear\n'; fi
}
# Pair `-S` specs with `-nvxL` rows by index; classify only Penn-relevant rules.
cfp_chain_counts() {
    if [ "$1" = 4 ]; then cfp_cmd=iptables; else cfp_cmd=ip6tables; fi
    "$cfp_cmd" -w 5 -t "$2" -S "$3" > "$CFP_DIR/rules.S" 2>/dev/null </dev/null || return 1
    "$cfp_cmd" -w 5 -t "$2" -nvxL "$3" > "$CFP_DIR/rules.L" 2>/dev/null </dev/null || return 1
    awk -v ip="$CFR_PENN_IP" -v chain="$3" '
        function cls(s){s=s " "
            if(s~/--match-set cf2_[ab]_p src /&&s~/-j REJECT /)return "paused"
            if(s~/-o br-lan /&&s~/-j REJECT /&&(index(s," -d " ip " ")||index(s," -d " ip "\/32 ")))return "reverse"
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
cfp_counters() {
    cfp_ctag=$1
    rm -f "$CFP_DIR/counters.$cfp_ctag"
    cfp_s=$(cfp_slot) || return 1
    # The IPv4 forward chain is required; the others only add classes.
    cfp_chain_counts 4 filter "cf2_${cfp_s}_f" > "$CFP_DIR/rules.out" || return 1
    for cfp_spec in "6 filter f" "4 filter i" "6 filter i" "4 nat d"; do
        # shellcheck disable=SC2086
        set -- $cfp_spec
        if cfp_chain_counts "$1" "$2" "cf2_${cfp_s}_$3" > "$CFP_DIR/rules.one"; then cat "$CFP_DIR/rules.one" >> "$CFP_DIR/rules.out"
        else cfr_info "counters_partial $cfp_ctag $cfp_spec"; fi
    done
    awk '{t[$1]+=$2}END{split("paused reverse dot doq doh dns6 dnsin dnat",k," ");for(i=1;i<=8;i++)print k[i] " " t[k[i]]+0}' "$CFP_DIR/rules.out" > "$CFP_DIR/counters.$cfp_ctag"
    cfr_info "counters $cfp_ctag $(tr '\n' ' ' < "$CFP_DIR/counters.$cfp_ctag")"
}
# Sum of classes $3.. between snapshots $1 and $2; "-" when either is missing.
cfp_delta() {
    cfp_a=$CFP_DIR/counters.$1; cfp_b=$CFP_DIR/counters.$2; shift 2
    if [ ! -f "$cfp_a" ] || [ ! -f "$cfp_b" ]; then printf '%s\n' -; return 0; fi
    awk -v want=" $* " 'NR==FNR{a[$1]=$2;next}index(want," " $1 " "){d+=$2-a[$1]}END{print d+0}' "$cfp_a" "$cfp_b"
}
# Sleep $1 seconds in $CFP_POLL steps with adult probes; optional $2 = Penn must stay paused.
# A slot swap by cron `cfctl expire` can make one read transiently unknown;
# three consecutive unknown reads (or any contrary read) stop the pilot.
cfp_state_check() {
    cfp_state=$(cfp_penn_state)
    case $cfp_state in
        unknown) CFP_UNKNOWN=$((CFP_UNKNOWN + 1)); cfr_info "kernel_set_read unknown $CFP_UNKNOWN"
            [ "$CFP_UNKNOWN" -lt 3 ] || cfp_stop "$2" kernel_set_unreadable;;
        *) CFP_UNKNOWN=0;;
    esac
    [ "$cfp_state" = unknown ] || [ -z "$1" ] || [ "$cfp_state" = "$1" ] || cfp_stop "$2" "penn_kernel_state_not_$1"
}
cfp_observe() {
    cfp_end=$(($(cfp_now) + $1))
    CFP_UNKNOWN=0
    while [ "$(cfp_now)" -lt "$cfp_end" ]; do
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
# The single approved teardown; never retried. Always exits.
cfp_teardown() {
    [ "$CFP_TEARDOWN" = 0 ] || exit 20
    CFP_TEARDOWN=1
    trap '' INT TERM
    cfr_uninstall=$CFR_RELEASE_DIR/uninstall.sh
    if [ ! -f "$cfr_uninstall" ]; then
        cfr_fail UNINSTALL installed_uninstall_absent
        cfr_out 'FAIL_AFTER_MUTATION UNINSTALL'
        exit 20
    fi
    cfp_safe_band || cfr_info 'teardown proceeding outside safe band'
    cfr_info "run uninstall.sh once: $cfr_uninstall"
    if ! cfr_run_sh "$cfr_uninstall" >>"$CFR_STAGE/child.log"; then
        cfr_fail UNINSTALL 'uninstall_refused_or_failed; journal preserved; resolve explicitly'
        if cfr_snapshot after; then cfr_diff; fi
        cfr_out 'FAIL_AFTER_MUTATION UNINSTALL'
        exit 20
    fi
    cfr_ok UNINSTALL
    cfp_crond_count after_uninstall
    cfr_restore
    cfr_connectivity
    if [ "$CFR_FAILED" = 0 ] && [ -z "$CFP_STOPPED" ]; then cfr_out PENN_PILOT_PASS; exit 0; fi
    if [ -n "$CFP_STOPPED" ] && cmp -s "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"; then
        cfr_out "STOPPED_AFTER_MUTATION $CFP_STOPPED"
        cfr_out PENN_PILOT_STOPPED_RESTORED
        exit 20
    fi
    cfr_out 'FAIL_AFTER_MUTATION summary'
    exit 20
}
cfp_budget() { cfp_elapsed_ok || cfp_stop "$1" remote_budget_reserved_for_teardown; }

cfp_enroll() {
    cfp_cfctl rpc-status --json > "$CFP_DIR/rpc-status.json" || cfp_stop ENROLL rpc_status_failed
    cfp_gen=$(sed -n 's/^{"rpc_version":1,"generation":"\([0-9a-f]\{64\}\)",.*/\1/p' "$CFP_DIR/rpc-status.json")
    cfp_digest=$(sed -n 's/.*,"policyDigest":"\([0-9a-f]\{64\}\)",.*/\1/p' "$CFP_DIR/rpc-status.json")
    [ "${#cfp_gen}" = 64 ] && [ "${#cfp_digest}" = 64 ] || cfp_stop ENROLL rpc_status_unparsed
    # Fresh scoped activation only: revision 0 and nobody enrolled.
    grep -q '"acceptedPolicy":{"version":1,"revision":0,"people":\[\],' "$CFP_DIR/rpc-status.json" || cfp_stop ENROLL activation_not_fresh
    printf '{"rpc_version":1,"generation":"%s","operation_id":"%s","expected_revision":0,"expected_digest":"%s","policy":%s}\n' \
        "$cfp_gen" "$CFP_OPERATION_ID" "$cfp_digest" "$CFP_POLICY" > "$CFP_DIR/request.json" || cfp_stop ENROLL request_write_failed
    cfp_policy_only_penn "$(cat "$CFP_DIR/request.json")" || cfp_stop ENROLL request_not_penn_only
    cfr_info "rpc-sync operation=$CFP_OPERATION_ID"
    cfp_cfctl_input "$CFP_DIR/request.json" rpc-sync > "$CFP_DIR/rpc-sync.json" || cfp_stop ENROLL rpc_sync_failed
    cfr_info "rpc-sync $(cat "$CFP_DIR/rpc-sync.json")"
    grep -q "\"receipt\":{\"operationId\":\"$CFP_OPERATION_ID\"" "$CFP_DIR/rpc-sync.json" || cfp_stop ENROLL receipt_missing
    cfp_status "\"observed\":{\"kids\":[\"$CFR_PENN_MAC\"],\"paused\":[]}" '"effectivePauses":[]' || cfp_stop ENROLL penn_not_observed
    cfr_out 'MEASURE service_key_confinement unmeasured not_exercised'
    cfp_counters enrolled || cfr_info 'counters enrolled unavailable'
    cfr_ok ENROLL
}
cfp_pause_phase() {
    cfp_pause "$CFP_PAUSE_SECONDS" || cfp_stop PAUSE pause_failed
    cfp_status_has "$CFP_DIR/status.json" "\"effectivePauses\":[{\"person\":\"$CFP_PERSON\",\"until\":$CFP_UNTIL}]" \
        "\"paused\":[\"$CFR_PENN_MAC\"]" || cfp_stop PAUSE pause_not_effective
    [ "$(cfp_penn_state)" = paused ] || cfp_stop PAUSE penn_not_in_kernel_set
    cfp_counters pause0 || cfr_info 'counters pause0 unavailable'
    cfr_info pause_observe_begin
    cfp_observe "$CFP_PAUSE_OBSERVE" paused PAUSE
    cfp_counters pause1 || cfr_info 'counters pause1 unavailable'
    CFP_PAUSE_DELTA=$(cfp_delta pause0 pause1 paused reverse)
    case $CFP_PAUSE_DELTA in
        -) cfr_out 'MEASURE packet_blocking unmeasured counters_unavailable';;
        0) cfr_out 'MEASURE packet_blocking unmeasured reject_counters_did_not_increase';;
        *) cfr_out "MEASURE packet_blocking measured router_side_block_observed reject_delta=$CFP_PAUSE_DELTA window_s=$CFP_PAUSE_OBSERVE";;
    esac
    cfr_ok PAUSE
}
cfp_resume_phase() {
    cfp_cfctl resume "$CFP_PERSON" > "$CFP_DIR/status.json" || :
    cfp_status_has "$CFP_DIR/status.json" '"effectivePauses":[]' '"paused":[]' || cfp_stop RESUME resume_not_clean
    [ "$(cfp_penn_state)" = clear ] || cfp_stop RESUME penn_kernel_state_not_clear
    cfp_counters resume0 || cfr_info 'counters resume0 unavailable'
    cfp_observe "$CFP_RESUME_OBSERVE" clear RESUME
    cfp_counters resume1 || cfr_info 'counters resume1 unavailable'
    cfp_resume_delta=$(cfp_delta resume0 resume1 paused reverse)
    case "$cfp_resume_delta:$CFP_PAUSE_DELTA" in
        -:*|*:-) cfr_out 'MEASURE resume_unblock unmeasured counters_unavailable';;
        0:0) cfr_out 'MEASURE resume_unblock unmeasured no_pause_counter_baseline';;
        0:*) cfr_out "MEASURE resume_unblock measured reject_counters_stopped window_s=$CFP_RESUME_OBSERVE";;
        *) cfp_stop RESUME "reject_counters_increased_after_resume $cfp_resume_delta";;
    esac
    cfr_ok RESUME
}
# Service-off expiry: no cfctl call until cron `cfctl expire` empties the set.
cfp_expiry_phase() {
    cfp_pause "$CFP_EXPIRY_SECONDS" || cfp_stop EXPIRY pause_failed
    cfp_status_has "$CFP_DIR/status.json" "\"paused\":[\"$CFR_PENN_MAC\"]" || cfp_stop EXPIRY pause_not_effective
    cfr_info "expiry_wait_begin until=$CFP_UNTIL tolerance=$CFP_EXPIRY_TOLERANCE"
    cfp_crond_count during_expiry
    cfp_last=0
    CFP_UNKNOWN=0
    while :; do
        cfp_t=$(cfp_now)
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
    cfr_out "MEASURE timed_expiry measured latency_s=$((cfp_t - CFP_UNTIL)) tolerance_s=$CFP_EXPIRY_TOLERANCE poll_s=$CFP_EXPIRY_POLL"
    cfp_status '"effectivePauses":[]' '"paused":[]' || cfp_stop EXPIRY status_not_clean_after_expiry
    cfr_out "MEASURE crond_processes measured baseline=$CFP_CROND_BASELINE after_install=$CFP_CROND_INSTALL during_expiry=$CFP_CROND_EXPIRY"
    cfr_ok EXPIRY
}
cfp_dns_phase() {
    cfp_counters final || cfr_info 'counters final unavailable'
    for cfp_class in dot doq doh dns6 dnsin dnat; do
        cfp_d=$(cfp_delta enrolled final "$cfp_class")
        case $cfp_class:$cfp_d in
            *:-) cfr_out "MEASURE dns_rule_$cfp_class unmeasured counters_unavailable";;
            doh:0) cfr_out 'MEASURE dns_rule_doh unmeasured no_hits_and_no_doh_list_configured';;
            *:0) cfr_out "MEASURE dns_rule_$cfp_class unmeasured no_router_side_hits";;
            *) cfr_out "MEASURE dns_rule_$cfp_class measured router_side_hits_while_enrolled=$cfp_d";;
        esac
    done
    cfr_out "MEASURE adult_router_dns measured baseline_max_cs=$CFP_BASE_DNS_CS observed_max_cs=${CFP_MAX_DNS_CS:-0} limit_cs=$CFP_DNS_LIMIT_CS"
    cfr_ok DNS
}

cfp_main() {
    umask 077
    CFR_START=$(date +%s)
    CFR_PREMUTATION_BUDGET=$CFP_PREMUTATION_BUDGET
    printf 'BEGIN penn-pilot commit=%s release=%s profile=%s\n' "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE"
    for cfr_value in "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE" "$CFR_MGMT_IP" "$CFR_MGMT_MAC" "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_PENN_IP" "$CFR_PENN_MAC" "$CFR_HISTORICAL_MACS" \
        "$CFP_ROUTER_IP" "$CFP_PERSON" "$CFP_OPERATION_ID" "$CFP_POLICY" "$CFP_DNS_NAME" "$CFP_SAFE_BAND" "$CFP_REMOTE_TIMEOUT"; do
        [ -n "$cfr_value" ] || cfr_refuse PAYLOAD parameters_missing
    done
    cfr_setup_paths || cfr_refuse PAYLOAD unsafe_environment
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
    [ "$(($(date +%s) - CFR_START))" -le "$CFR_PREMUTATION_BUDGET" ] || cfr_refuse BASELINE premutation_budget_exceeded
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
    for cfp_phase in ENROLL PAUSE RESUME EXPIRY DNS; do
        cfp_budget "$cfp_phase"
        case $cfp_phase in
            ENROLL) cfp_enroll;; PAUSE) cfp_pause_phase;; RESUME) cfp_resume_phase;;
            EXPIRY) cfp_expiry_phase;; DNS) cfp_dns_phase;;
        esac
    done
    cfp_teardown
}

# Parse everything above first; no child can read the remaining script.
cfp_main </dev/null
# Unreachable unless cfp_main returns; fail closed.
# shellcheck disable=SC2317
exit 20
