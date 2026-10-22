# shellcheck disable=SC2034,SC2015
# Cross-module globals; A && B || fail intentionally rejects either failure.
# Couvre-feu durable policy and safe command boundary.
CF_DIR=$CF_BASE/etc/couvrefeu
CF_STATE=$CF_DIR/state
CF_PROTECTED=$CF_DIR/protected
CF_RUNTIME=$CF_DIR/runtime
CF_ERROR=
CF_LOCKED=0
CF_NOW_VALUE=
CF_EXPIRY_NOW=
CF_OWNER=$(id -u)

cf_fail() { CF_ERROR=$1; return 1; }
cf_backend_available() {
    cf_backend_name=$1
    if [ "$CF_LOCAL_TEST" = 1 ];then
        cf_executable=$CF_BACKEND_DIR/$cf_backend_name
        [ -f "$cf_executable" ] && [ ! -L "$cf_executable" ] && [ -x "$cf_executable" ]
        return $?
    fi
    case $cf_backend_name in
        iptables|ip6tables|ipset|conntrack)cf_backend_paths="/usr/sbin/$cf_backend_name /sbin/$cf_backend_name";;
        sync)cf_backend_paths='/bin/sync /usr/bin/sync';;
        uci|fw3)cf_backend_paths="/sbin/$cf_backend_name /usr/sbin/$cf_backend_name";;
        ip)cf_backend_paths='/sbin/ip /usr/sbin/ip /bin/ip';;
        *)return 1;;
    esac
    for cf_backend_path in $cf_backend_paths;do
        if [ -x "$cf_backend_path" ];then cf_executable=$cf_backend_path;return 0;fi
    done
    return 1
}
cf_backend() {
    cf_cmd=$1; shift
    cf_backend_available "$cf_cmd" || { cf_fail missing_backend;return 127; }
    case "$cf_cmd" in
        iptables|ip6tables)
            for cf_deadline_arg in "$@"; do case "$cf_deadline_arg" in -A|-I|-R|-D|-N|-X|-F|-P|-Z|--append|--insert|--replace|--delete|--new-chain|--delete-chain|--flush|--policy|--zero) platform_initial_write;; esac; done;;
        ipset) case "${1:-}" in create|add|del|destroy|flush|swap|rename|restore) platform_initial_write;; esac;;
        conntrack) for cf_deadline_arg in "$@"; do case "$cf_deadline_arg" in -D|-F|-I|-U|--delete|--flush|--create|--update) platform_initial_write;; esac; done;;
        fw3) case "${1:-}" in reload|restart|start|stop) platform_initial_write;; esac;;
        uci) for cf_deadline_arg in "$@"; do case "$cf_deadline_arg" in set|add|delete|rename|commit|import|revert) platform_initial_write;; esac; done;;
    esac
    "$cf_executable" "$@"
}
cf_safe_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    cf_meta=$(stat -c '%u:%a' "$1" 2>/dev/null) || return 1
    [ "$cf_meta" = "$CF_OWNER:600" ]
}
cf_private_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = "$CF_OWNER:700" ]
}
cf_mac_valid() {
    printf '%s\n' "$1" | awk '
    length($0)!=17 {exit 1}
    {n=split($0,a,":");if(n!=6)exit 1;for(i=1;i<=6;i++)if(a[i]!~/^[0-9a-f][0-9a-f]$/)exit 1;if(index("02468ace",substr(a[1],2,1))==0 || $0=="00:00:00:00:00:00")exit 1}'
}
# RPC scope file: 1..256 canonical unicast MACs, LF-terminated, unique and
# LC_ALL=C sorted. Prints the space-joined set; never an empty (unscoped) value.
# Reads the root-private file several times (awk, wc, sort/cmp); callers bind it
# first (installer stage dir, or cmp with the signed staged copy at runtime).
cf_scope_file() {
    cf_sf_list=$(awk '
    length($0)!=17 {exit 1}
    {n=split($0,a,":");if(n!=6)exit 1;for(i=1;i<=6;i++)if(a[i]!~/^[0-9a-f][0-9a-f]$/)exit 1;if(index("02468ace",substr(a[1],2,1))==0 || $0=="00:00:00:00:00:00")exit 1;printf "%s%s",(NR>1?" ":""),$0}
    END {if(NR<1||NR>256)exit 1}' "$1") || return 1
    cf_sf_count=$(printf '%s\n' "$cf_sf_list" | awk '{print NF}')
    [ -n "$cf_sf_list" ] && [ "$cf_sf_count" -ge 1 ] && [ "$cf_sf_count" -le 256 ] || return 1
    # Exact size rejects NUL, CR, blank lines and a missing final newline.
    [ "$(wc -c < "$1")" -eq $((cf_sf_count * 18)) ] || return 1
    # Order and uniqueness use the tool that produced the file, not awk comparisons.
    LC_ALL=C sort -u "$1" | cmp -s - "$1" || return 1
    printf '%s\n' "$cf_sf_list"
}
cf_id_valid() { case $1 in ''|*[!a-z0-9_]*|[!a-z]*) return 1;; esac; [ "${#1}" -le 32 ]; }
cf_number_valid() {
    printf '%s\n' "$1" | awk '$0!~/^(0|[1-9][0-9]*)$/ || length($0)>10 || $0+0>2147483647 {exit 1}'
}
cf_clock() {
    if [ "$CF_LOCAL_TEST" = 1 ] && [ -n "${CF_NOW-}" ]; then CF_NOW_VALUE=$CF_NOW; else CF_NOW_VALUE=$(date +%s) || return 1; fi
    cf_number_valid "$CF_NOW_VALUE" || { cf_fail invalid_clock; return 1; }
    # Reject clocks before 2020: silently applying schedules on an unsynced clock is unsafe.
    [ "$CF_NOW_VALUE" -ge 1577836800 ] || { cf_fail invalid_clock; return 1; }
    CF_EXPIRY_NOW=$CF_NOW_VALUE
    if [ -e "$CF_RUNTIME/expiry" ] || [ -L "$CF_RUNTIME/expiry" ];then
        cf_safe_file "$CF_RUNTIME/expiry" || { cf_fail unsafe_expiry_record;return 1; }
        cf_highwater=$(awk 'NR==1{print}NR>1{exit 2}' "$CF_RUNTIME/expiry") || { cf_fail unsafe_expiry_record;return 1; }
        cf_number_valid "$cf_highwater" || { cf_fail unsafe_expiry_record;return 1; }
        [ "$cf_highwater" -le "$CF_EXPIRY_NOW" ] || CF_EXPIRY_NOW=$cf_highwater
    fi
}
# Allowances: router-local temporary unblocking. Honored only with a valid
# (post-2020, highwater-monotonic) clock and only within the admission horizon,
# so an uncertain clock or out-of-bound record blocks (fails closed).
CF_ALLOWANCE_HORIZON=14400
cf_active_allowances() {
    # Conservative recovery must replay the immutable prepared generation, so it
    # evaluates at the prepared epoch like pauses. That replay cannot fail open:
    # the generation carries the person's blocks gated by --datestart <until>,
    # which the kernel already enforces once until has passed.
    printf '%s\n' "$CF_POLICY" | awk -F '\t' -v now="${CF_PREPARED_EPOCH:-$CF_EXPIRY_NOW}" -v horizon="$CF_ALLOWANCE_HORIZON" '
    BEGIN{valid=now~/^[1-9][0-9]*$/&&length(now)<=10&&now+0>=1577836800}
    valid&&$1=="U"&&NF==3&&$3~/^[1-9][0-9]*$/&&length($3)<=10&&$3+0>now+0&&$3+0<=now+horizon{print $2 "\t" $3 "\t" ($3-now)}'
}
# Enforcement view of the policy: an active allowance overrides (never deletes)
# the person's pauses and schedules, so they re-apply when it expires.
cf_enforced_policy() {
    cf_ep_allowed=$(cf_active_allowances | awk -F '\t' '{print $1}')
    printf '%s\n' "$CF_POLICY" | awk -F '\t' -v allowed="$cf_ep_allowed" 'BEGIN{n=split(allowed,a,"\n");for(i=1;i<=n;i++)if(a[i]!="")skip[a[i]]=1}($1=="A"||$1=="S")&&skip[$2]{next}{print}'
}
# Kernel-side expiry: while an allowance is active, the person's pause and
# schedule blocks stay installed, gated by xt_time --datestart (UTC) at
# `until`, so they re-apply at the deadline even if cron or the shell clock
# fails afterwards. `cfctl expire` later rebuilds the ungated form.
cf_allowance_gates() {
    cf_active_allowances | while IFS="$(printf '\t')" read -r cf_ag_person cf_ag_until cf_ag_rest; do
        [ -n "$cf_ag_person" ] || continue
        cf_ag_date=$(date -u -d "@$cf_ag_until" +%Y-%m-%dT%H:%M:%S) || return 1
        case $cf_ag_date in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]) ;; *) return 1;; esac
        printf '%s\t%s\t%s\n' "$cf_ag_person" "$cf_ag_until" "$cf_ag_date"
    done
}
cf_gated_ips() {
    printf '%s\n' "$CF_ADDRESS_DATA" | awk -F '\t' -v m="$1" -v f="$2" 'NF==2&&$2==m&&((index($1,":")>0)==(f==6)){print $1}'
}
cf_gated_plan() {
    cf_gp_family=$1
    cf_gp_gates=$(cf_allowance_gates) || { cf_fail allowance_gate_failed;return 1; }
    printf '%s\n' "$cf_gp_gates" | while IFS="$(printf '\t')" read -r cf_gp_person cf_gp_until cf_gp_date; do
        [ -n "$cf_gp_person" ] || continue
        # Pauses still in force at the gate, plus every schedule, for this person only.
        cf_gp_policy=$(printf '%s\n' "$CF_POLICY" | awk -F '\t' -v p="$cf_gp_person" -v g="$cf_gp_until" '$2!=p{next}$1=="P"||$1=="S"||($1=="A"&&($3==0||$3>g)){print}')
        cf_gp_paused=$(printf '%s\n' "$cf_gp_policy" | awk -F '\t' '$1=="P"&&$3!="-"{m[++n]=$3}$1=="A"{a=1}END{if(a)for(i=1;i<=n;i++)print m[i]}')
        for cf_gp_mac in $cf_gp_paused;do
            printf '%s\tfilter\tcf_fwd\t-i br-lan -m mac --mac-source %s -m time --datestart %s -m comment --comment cf:v1 -j REJECT\n' "$cf_gp_family" "$cf_gp_mac" "$cf_gp_date"
            for cf_gp_ip in $(cf_gated_ips "$cf_gp_mac" "$cf_gp_family");do
                printf '%s\tfilter\tcf_fwd\t-o br-lan -d %s -m time --datestart %s -m comment --comment cf:v1 -j REJECT\n' "$cf_gp_family" "$cf_gp_ip" "$cf_gp_date"
            done
        done
        printf '%s\n' "$cf_gp_policy" | cf_schedule_rows | while IFS="$(printf '\t')" read -r cf_gp_name cf_gp_p cf_gp_mac cf_gp_days cf_gp_start cf_gp_stop;do
            [ -n "$cf_gp_name" ] || continue
            # Schedule windows keep --kerneltz like the ungated mirrors; the gate is a separate UTC time match.
            printf '%s\tfilter\tcf_fwd\t-i br-lan -m mac --mac-source %s -m time --weekdays %s --timestart %s --timestop %s --kerneltz -m time --datestart %s -m comment --comment cf:v1 -j REJECT\n' "$cf_gp_family" "$cf_gp_mac" "$cf_gp_days" "$cf_gp_start" "$cf_gp_stop" "$cf_gp_date"
            for cf_gp_ip in $(cf_gated_ips "$cf_gp_mac" "$cf_gp_family");do
                printf '%s\tfilter\tcf_fwd\t-o br-lan -d %s -m time --weekdays %s --timestart %s --timestop %s --kerneltz -m time --datestart %s -m comment --comment cf:v1 -j REJECT\n' "$cf_gp_family" "$cf_gp_ip" "$cf_gp_days" "$cf_gp_start" "$cf_gp_stop" "$cf_gp_date"
            done
        done
    done
}
cf_allowance_admissible() {
    # Newly staged policy only ($1, default CF_POLICY); retained expired allowances stay inert for replay equality.
    cf_number_valid "${CF_EXPIRY_NOW-}" && [ "$CF_EXPIRY_NOW" -ge 1577836800 ] || { cf_fail invalid_clock;return 1; }
    printf '%s\n' "${1-$CF_POLICY}" | awk -F '\t' -v now="$CF_EXPIRY_NOW" -v horizon="$CF_ALLOWANCE_HORIZON" '$1=="U"&&$3+0>now+0&&$3+0>now+horizon{exit 1}' || { cf_fail allowance_beyond_horizon;return 1; }
}
cf_protected_valid() {
    cf_safe_file "$CF_PROTECTED" && [ -s "$CF_PROTECTED" ] || { cf_fail unsafe_protected_file; return 1; }
    awk 'length($0)!=17 {exit 1} {n=split($0,a,":");if(n!=6)exit 1;for(i=1;i<=6;i++)if(a[i]!~/^[0-9a-f][0-9a-f]$/)exit 1;if(index("02468ace",substr(a[1],2,1))==0 || $0=="00:00:00:00:00:00" || seen[$0]++)exit 1}' "$CF_PROTECTED" || { cf_fail invalid_protected_mac; return 1; }
}
cf_canonical() { sort | awk -F '\t' '$1=="V"{v=$0;next}$1=="R"{r=$0;next}{a[++n]=$0}END{print v;print r;for(i=1;i<=n;i++)print a[i]}'; }
cf_state_json() {
    awk -F '\t' '
    function bad(){exit 2}
    BEGIN{people="";pauses="";sched="";d4="";d6=""}
    $1=="V"{if(NF!=2||v++)bad();version=$2;next}
    $1=="R"{if(NF!=2||r++)bad();revision=$2;next}
    $1=="P"{if(NF!=3||$2!~/^[a-z][a-z0-9_]*$/||$3!~/^[-0-9a-f:]+$/)bad();person[$2]=1;if($3!="-"){mac[$2]=mac[$2] (mac[$2]==""?"":",") "\"" $3 "\""}next}
    $1=="A"{if(NF!=3||$2!~/^[a-z][a-z0-9_]*$/||$3!~/^[0-9]+$/)bad();sep="";if(pauses!="")sep=",";pauses=pauses sep "{\"person\":\"" $2 "\",\"until\":" $3 "}";next}
    $1=="U"{if(NF!=3||$2!~/^[a-z][a-z0-9_]*$/||$3!~/^[1-9][0-9]*$/)bad();sep="";if(allow!="")sep=",";allow=allow sep "{\"person\":\"" $2 "\",\"until\":" $3 "}";next}
    $1=="S"{if(NF!=6||$2!~/^[a-z][a-z0-9_]*$/||$3!~/^[a-z][a-z0-9_]*$/||$4!~/^[A-Za-z,]+$/||$5!~/^[0-9:]+$/||$6!~/^[0-9:]+$/)bad();n=split($4,a,",");days="";for(i=1;i<=n;i++){sep="";if(i!=1)sep=",";days=days sep "\"" a[i] "\""}sep="";if(sched!="")sep=",";sched=sched sep "{\"person\":\"" $2 "\",\"id\":\"" $3 "\",\"weekdays\":[" days "],\"start\":\"" $5 "\",\"stop\":\"" $6 "\"}";next}
    $1=="D4"{if(NF!=2||$2!~/^[0-9.]+$/)bad();sep="";if(d4!="")sep=",";d4=d4 sep "\"" $2 "\"";next}
    $1=="D6"{if(NF!=2||$2!~/^[0-9a-f:]+$/)bad();sep="";if(d6!="")sep=",";d6=d6 sep "\"" $2 "\"";next}
    {bad()}
    END{if(v!=1||r!=1||version!~/^[0-9]+$/||revision!~/^[0-9]+$/)exit 2;for(p in person){sep="";if(people!="")sep=",";people=people sep "{\"id\":\"" p "\",\"macs\":[" mac[p] "]}"}print "{\"version\":" version ",\"revision\":" revision ",\"people\":[" people "],\"pauses\":[" pauses "]" (allow==""?"":",\"allowances\":[" allow "]") ",\"schedules\":[" sched "],\"doh\":{\"ipv4\":[" d4 "],\"ipv6\":[" d6 "]}}"}' "$1"
}
cf_state_load() {
    cf_safe_file "$CF_STATE" || { cf_fail unsafe_state_file; return 1; }
    [ "$(wc -c < "$CF_STATE")" -le 131072 ] || { cf_fail state_too_large; return 1; }
    cf_policy_records=$(awk -f "$CF_LIB/state.awk" "$CF_STATE") || { cf_fail invalid_state;return 1; }
    CF_METADATA=$(awk -v mode=meta -f "$CF_LIB/state.awk" "$CF_STATE") || { cf_fail invalid_state;return 1; }
    [ "${#cf_policy_records}" -lt 65536 ] || { cf_fail state_too_large;return 1; }
    cf_raw=$(printf '%s\n' "$cf_policy_records" | cf_state_json -) || { cf_fail invalid_state; return 1; }
    cf_validated=$(printf '%s\n' "$cf_raw" | awk -f "$CF_LIB/json.awk") || { cf_fail invalid_state;return 1; }
    CF_POLICY=$(printf '%s\n' "$cf_validated" | cf_canonical)
    [ -n "$CF_POLICY" ] && [ "$CF_POLICY" = "$(printf '%s\n' "$cf_policy_records" | cf_canonical)" ] || { cf_fail invalid_state; return 1; }
    CF_REVISION=$(printf '%s\n' "$CF_POLICY" | awk -F '\t' '$1=="R"{print $2}')
    CF_DIGEST=$(printf '%s\n' "$CF_POLICY" | sha256sum | awk '{print $1}')
    CF_GENERATION=$(printf '%s\n' "$CF_METADATA" | awk -F '\t' '$1=="G"{print $2}')
    CF_CURRENT=$(printf '%s\n' "$CF_METADATA" | awk -F '\t' '$1=="C"{print $2}')
    if [ -n "$CF_CURRENT" ] && [ "$CF_CURRENT" != - ];then
        printf '%s\n' "$CF_METADATA" | awk -F '\t' -v id="$CF_CURRENT" -v rev="$CF_REVISION" -v digest="$CF_DIGEST" '$1=="O"&&$2==id{if($6!=rev||$7!=digest)exit 1}' || { cf_fail invalid_receipt_pointer;return 1; }
    fi
    cf_rpc_binding
}

cf_policy_safe() {
    cf_scope_safe || return 1
    printf '%s\n' "$CF_POLICY" | awk -F '\t' 'NR==FNR{protected[$1]=1;next}$1=="P"&&protected[$3]{exit 1}' "$CF_PROTECTED" - || { cf_fail protected_mac_overlap; return 1; }
}
cf_runtime_prepare() {
    if [ ! -e "$CF_RUNTIME" ]; then platform_initial_write; mkdir -m 700 "$CF_RUNTIME" || { cf_fail runtime_create_failed; return 1; }; fi
    cf_private_dir "$CF_RUNTIME" || { cf_fail unsafe_runtime; return 1; }
}
cf_install_gate() {
    CF_INSTALL_AUTH=0
    if [ "$CF_LOCAL_TEST" = 1 ];then
        cf_install_lock=$CF_BASE/.couvrefeu-install.lock
        cf_recovery_base=$CF_BASE
    else
        cf_install_lock=/tmp/couvrefeu-install.lock
        cf_recovery_base=/etc
    fi
    if [ -e "$cf_install_lock" ] || [ -L "$cf_install_lock" ];then
        case $1 in apply-fw|remove-fw) ;;*)cf_fail installation_in_progress;return 1;;esac
        cf_private_dir "$cf_install_lock" && cf_safe_file "$cf_install_lock/pid" && cf_safe_file "$cf_install_lock/token" || { cf_fail unsafe_install_lock;return 1; }
        cf_install_pid=$(awk 'NR==1{print}NR>1{exit 2}' "$cf_install_lock/pid") || return 1
        case $cf_install_pid in ''|*[!0-9]*)cf_fail unsafe_install_lock;return 1;;esac
        [ "$cf_install_pid" -gt 1 ] && kill -0 "$cf_install_pid" 2>/dev/null || { cf_fail stale_install_lock;return 1; }
        cf_install_token=$(awk 'NR==1{print}NR>1{exit 2}' "$cf_install_lock/token") || return 1
        case $cf_install_token in ''|*[!0-9a-f]*)cf_fail unsafe_install_lock;return 1;;esac
        [ "${#cf_install_token}" = 64 ] && [ "${CF_INSTALL_TOKEN-}" = "$cf_install_token" ] || { cf_fail installation_in_progress;return 1; }
        CF_INSTALL_AUTH=1
    fi
    # Durable recovery phases survive a failed uninstall, a released lock, or reboot.
    for cf_recovery_marker in "$CF_DIR/backup/kernel-cleaned" "$CF_DIR/backup/kernel-cleaned.next" "$CF_DIR/backup/restoring" "$CF_DIR/backup/restoring.next" "$CF_DIR/backup/no-kernel-mutations" "$CF_DIR/backup/no-kernel-mutations.next" "$cf_recovery_base/.couvrefeu-recovery" "$cf_recovery_base/.couvrefeu-recovery.done";do
        if [ -e "$cf_recovery_marker" ] || [ -L "$cf_recovery_marker" ];then
            [ "$1" = remove-fw ] && [ "$CF_INSTALL_AUTH" = 1 ] || { cf_fail uninstall_recovery_in_progress;return 1; }
        fi
    done
    if [ -e "$CF_RUNTIME/firewall.cleanup" ] || [ -L "$CF_RUNTIME/firewall.cleanup" ];then
        [ "$1" = remove-fw ] || { cf_fail firewall_cleanup_in_progress;return 1; }
    fi
}

cf_control_dirs() {
    platform_deadline_check
    for cf_dir in "$CF_BASE/etc" "$CF_DIR";do
        [ -d "$cf_dir" ] && [ ! -L "$cf_dir" ] || { cf_fail unsafe_control_directory;return 1; }
        cf_dir_meta=$(stat -c '%u:%a' "$cf_dir") || return 1
        case $cf_dir_meta in "$CF_OWNER:700"|"$CF_OWNER:755"|"$CF_OWNER:750") ;;
            "$CF_OWNER:775")
                [ "$cf_dir" = /etc ] && [ "${CF_PLATFORM_ADMITTED:-0}" = 1 ] && { [ "${CF_PLATFORM_PROFILE:-strict}" = gl-xe3000-4.8.3-logd-011-v1 ] || [ "${CF_PLATFORM_PROFILE:-strict}" = gl-xe3000-4.8.3-os-trust-v1 ]; } || { cf_fail unsafe_control_directory;return 1; };;
            *)cf_fail unsafe_control_directory;return 1;;esac
    done
}
cf_lock() {
    platform_deadline_check
    if [ "${CF_RPC_REQUIRE_RUNTIME:-0}" = 1 ];then
        cf_private_dir "$CF_RUNTIME" || { cf_fail unsafe_runtime;return 1; }
    else cf_runtime_prepare || return 1;fi
    if ! mkdir -m 700 "$CF_RUNTIME/lock" 2>/dev/null; then
        cf_private_dir "$CF_RUNTIME/lock" && cf_safe_file "$CF_RUNTIME/lock/pid" || { cf_fail unsafe_lock; return 1; }
        cf_pid=$(awk 'NR==1{print}NR>1{exit 2}' "$CF_RUNTIME/lock/pid") || { cf_fail unsafe_lock; return 1; }
        case $cf_pid in ''|*[!0-9]*) cf_fail unsafe_lock; return 1;; esac
        [ "$cf_pid" -gt 1 ] || { cf_fail unsafe_lock; return 1; }
        if kill -0 "$cf_pid" 2>/dev/null || [ -e "/proc/$cf_pid" ]; then cf_fail locked; return 1; fi
        # Demonstrably dead PID. Remove only the two known records, never a tree.
        [ ! -e "$CF_RUNTIME/lock/reload" ] || cf_safe_file "$CF_RUNTIME/lock/reload" || { cf_fail unsafe_lock; return 1; }
        rm -f "$CF_RUNTIME/lock/pid" "$CF_RUNTIME/lock/reload" || return 1
        rmdir "$CF_RUNTIME/lock" || { cf_fail unsafe_lock; return 1; }
        mkdir -m 700 "$CF_RUNTIME/lock" || { cf_fail locked; return 1; }
    fi
    printf '%s\n' "$$" > "$CF_RUNTIME/lock/pid" || return 1
    CF_LOCKED=1
    trap 'cf_unlock; platform_lock_release; exit 129' HUP
    trap 'cf_unlock; platform_lock_release; exit 130' INT
    trap 'cf_unlock; platform_lock_release; exit 143' TERM
    trap 'cf_unlock; platform_lock_release' 0
    platform_deadline_check
}
cf_unlock() {
    if [ "$CF_LOCKED" = 1 ]; then
        if [ "$(awk 'NR==1{print}' "$CF_RUNTIME/lock/pid" 2>/dev/null)" = "$$" ]; then
            rm -f "$CF_RUNTIME/lock/pid" "$CF_RUNTIME/lock/reload"
            rmdir "$CF_RUNTIME/lock" 2>/dev/null || :
        fi
        CF_LOCKED=0
    fi
}
cf_reentrant_include() {
    [ -n "${CF_RELOAD_TOKEN-}" ] || return 1
    cf_private_dir "$CF_RUNTIME/lock" && cf_safe_file "$CF_RUNTIME/lock/pid" && cf_safe_file "$CF_RUNTIME/lock/reload" || return 1
    [ "$(awk 'NR==1{print}' "$CF_RUNTIME/lock/reload")" = "$CF_RELOAD_TOKEN" ] || return 1
    cf_pid=$(awk 'NR==1{print}' "$CF_RUNTIME/lock/pid")
    case $cf_pid in ''|*[!0-9]*) return 1;; esac
    kill -0 "$cf_pid" 2>/dev/null || return 1
    printf '%s\n' '{"ok":false,"deferred":true,"errors":["outer_reload_in_progress"]}'
}
cf_addresses() {
    # Only usable, unique bindings authorize address-based rules/eviction.
    # IPv6 cached NUD bindings need not prove recent reachability; IPv4 keeps
    # its existing current-lease or REACHABLE/PERMANENT requirement.
    cf_network || return 1
    cf_neigh4=$(cf_backend ip -4 neigh show dev br-lan) || return 1
    cf_neigh6=$(cf_backend ip -6 neigh show dev br-lan) || return 1
    # The fixed collectors already select br-lan: ip legitimately omits dev.
    cf_neigh=$(printf '%s\n%s\n' "$cf_neigh4" "$cf_neigh6" | awk '
    NF{
        dev="";mac="";state="";nd=nm=ns=0
        for(i=2;i<=NF;i++){
            if($i=="dev"){if(++nd>1||i==NF||$(i+1)!="br-lan")exit 2;dev=$(++i)}
            else if($i=="lladdr"){if(++nm>1||i==NF)exit 2;mac=tolower($(++i))}
            else if($i~/^(REACHABLE|PERMANENT|STALE|DELAY|PROBE|FAILED|INCOMPLETE|NOARP|NONE)$/){if(++ns>1)exit 2;state=$i}
            else if($i!~/^(router|proxy|extern_learn|extern_valid|managed|use)$/)exit 2
        }
        if(state=="FAILED"||state=="INCOMPLETE"||state=="NONE"||state=="NOARP")next
        if(nm!=1||ns!=1)exit 2
        print "N\t" $1 "\t" mac "\t" state
    }') || { cf_fail unsafe_neighbor_output;return 1; }
    cf_leases=
    if [ -e "$CF_BASE/tmp/dhcp.leases" ];then
        [ -f "$CF_BASE/tmp/dhcp.leases" ] && [ ! -L "$CF_BASE/tmp/dhcp.leases" ] || return 1
        cf_leases=$(awk 'NF>=3{print "L\t" $3 "\t" tolower($2) "\t" $1}' "$CF_BASE/tmp/dhcp.leases") || return 1
    fi
    cf_address_kids=$(cf_kids)
    cf_address_protected=$(awk '{print}' "$CF_PROTECTED")
    cf_address_result=$(printf '%s\n%s\n' "$cf_neigh" "$cf_leases" | awk -F '\t' -v now="$CF_NOW_VALUE" -v kids="$cf_address_kids" -v protected="$cf_address_protected" -v lan="$CF_LAN_IP" -v lan6="$CF_ROUTER6" '
    function ip4(s,a,n,i){n=split(s,a,".");if(n!=4)return 0;for(i=1;i<=4;i++)if(a[i]!~/^(0|[1-9][0-9]*)$/||length(a[i])>3||a[i]+0>255)return 0;return 1}
    function ip6(s,a,n,i,t,k){if(s!~/^[0-9a-f:]+$/||length(s)>39||index(s,":::")||!index(s,":"))return 0;k=index(s,"::");if(k&&index(substr(s,k+2),"::"))return 0;if((substr(s,1,1)==":"&&substr(s,1,2)!="::")||(substr(s,length(s),1)==":"&&substr(s,length(s)-1,2)!="::"))return 0;n=split(s,a,":");for(i=1;i<=n;i++)if(a[i]!=""){if(length(a[i])>4)return 0;t++}return k?t<8:t==8}
    function canon6(s,a,b,n,i,k,t,m,beg,out,j){k=index(s,"::");if(k){t=substr(s,1,k-1);n=split(t,a,":");if(t=="")n=0;t=substr(s,k+2);m=split(t,b,":");if(t=="")m=0;for(i=1;i<=m;i++)a[8-m+i]=b[i];for(i=n+1;i<=8-m;i++)a[i]="0"}else split(s,a,":");for(i=1;i<=8;i++){sub(/^0+/,"",a[i]);if(a[i]=="")a[i]="0"}m=0;for(i=1;i<=8;i++)if(a[i]=="0"){j=i;while(j<=8&&a[j]=="0")j++;if(j-i>m){m=j-i;beg=i}i=j-1}if(m<2)beg=0;out="";for(i=1;i<=8;i++){if(i==beg){out=out "::";i+=m-1;continue}if(out!=""&&substr(out,length(out),1)!=":")out=out ":";out=out a[i]}return out}
    function mac(s,a,n,i){if(length(s)!=17)return 0;n=split(s,a,":");if(n!=6)return 0;for(i=1;i<=6;i++)if(a[i]!~/^[0-9a-f][0-9a-f]$/)return 0;return index("02468ace",substr(a[1],2,1))&&s!="00:00:00:00:00:00"}
    BEGIN{n=split(kids,a,"\n");for(i=1;i<=n;i++)kid[a[i]]=1;n=split(protected,a,"\n");for(i=1;i<=n;i++)adult[a[i]]=1;n=split(lan6,a,"\n");router[lan]=1;for(i=1;i<=n;i++)if(ip6(a[i]))router[canon6(a[i])]=1}
    $1=="N"&&(NF!=4||!mac($3)){exit 2}
    NF==4&&mac($3){
        ip=tolower($2);if(ip6(ip))ip=canon6(ip);else if(!ip4(ip)){if($1=="N")exit 2;next}
        if($1=="L"){
            if($4!~/^(0|[1-9][0-9]*)$/||length($4)>10||$4+0>2147483647||($4!=0&&$4<=now))next
            usable[ip SUBSEP $3]=1
        }else if($1=="N"){
            if($4!~/^(REACHABLE|PERMANENT|STALE|DELAY|PROBE)$/)next
            if(index(ip,":")||$4~/^(REACHABLE|PERMANENT)$/)usable[ip SUBSEP $3]=1
        }else next
        if(!owner[ip SUBSEP $3]++){count[ip]++;chosen[ip]=$3}
        if(adult[$3])protectedip[ip]=$3
        if(kid[$3])relevant[ip]=1
    }
    END{
        for(ip in count){
            if(protectedip[ip])print "PROTECTED\t" ip "\t" protectedip[ip]
            if(count[ip]==1&&!router[ip]&&usable[ip SUBSEP chosen[ip]])print ip "\t" chosen[ip]
            if(relevant[ip]&&(count[ip]!=1||router[ip]||protectedip[ip]||!usable[ip SUBSEP chosen[ip]])){
                for(key in owner){split(key,b,SUBSEP);if(b[1]==ip&&kid[b[2]])print "UNCERTAIN\t" ip "\t" b[2]}
            }
        }
    }') || { cf_fail unsafe_address_attribution;return 1; }
    printf '%s\n' "$cf_address_result" | sort -u
}
cf_address_refresh() {
    CF_ADDRESS_OK=false
    CF_ADDRESS_DATA=$(cf_addresses) || return 1
    cf_address_required=$(printf '%s\n' "$CF_POLICY" | awk -F '\t' -v now="$CF_EXPIRY_NOW" '$1=="P"&&$3!="-"{m[$2]=m[$2] " " $3}$1=="S"||$1=="A"&&($3==0||$3>now){p[$2]=1}END{for(id in p){n=split(m[id],a," ");for(i=1;i<=n;i++)if(a[i]!="")print a[i]}}' | sort -u)
    if printf '%s\n' "$CF_ADDRESS_DATA" | awk -F '\t' -v required="$cf_address_required" 'BEGIN{n=split(required,a,"\n");for(i=1;i<=n;i++)if(a[i]!="")need[a[i]]=1}NF==2{have[$2]=1}$1=="UNCERTAIN"&&($3 in need){bad=1}END{for(m in need)if(!have[m])bad=1;exit bad}';then CF_ADDRESS_OK=true;fi
}
cf_ssh_guard() {
    [ -n "${SSH_CONNECTION-}${SSH_CLIENT-}" ] || return 0
    cf_ip=$(printf '%s\n' "${SSH_CONNECTION:-${SSH_CLIENT-}}" | awk 'NF==4||NF==3{print $1}')
    [ -n "$cf_ip" ] || { cf_fail unknown_ssh_client; return 1; }
    cf_pairs=$(cf_addresses) || { cf_fail unknown_ssh_client; return 1; }
    cf_macs=$(printf '%s\n' "$cf_pairs" | awk -F '\t' -v ip="$cf_ip" '$1==ip{print $2}' | sort -u)
    [ "$(printf '%s\n' "$cf_macs" | awk 'NF{n++}END{print n+0}')" = 1 ] || { cf_fail ambiguous_ssh_client; return 1; }
    cf_mac_valid "$cf_macs" || { cf_fail unknown_ssh_client; return 1; }
    printf '%s\n' "$CF_POLICY" | awk -F '\t' -v mac="$cf_macs" '$1=="P"&&$3==mac{exit 1}' || { cf_fail ssh_client_overlap; return 1; }
    # The guard only reads: a refused request must never grow `protected`.
    awk -v mac="$cf_macs" -v scope="${CF_SCOPE-}" 'BEGIN{n=split(scope,s," ");for(i=1;i<=n;i++)if(s[i]==mac)exit 1}' || { cf_fail ssh_client_in_scope; return 1; }
    awk -v mac="$cf_macs" '$0==mac{yes=1}END{exit !yes}' "$CF_PROTECTED" || { cf_fail ssh_client_unprotected; return 1; }
}
cf_write_policy() {
    platform_deadline_check
    cf_temp=$CF_RUNTIME/.candidate.$$
    [ ! -e "$cf_temp" ] && [ ! -L "$cf_temp" ] || { cf_fail unsafe_temporary; return 1; }
    cf_runtime_device=$(stat -c %d "$CF_RUNTIME") || { cf_fail cross_filesystem_state;return 1; }
    cf_state_device=$(stat -c %d "$CF_DIR") || { cf_fail cross_filesystem_state;return 1; }
    [ "$cf_runtime_device" = "$cf_state_device" ] || { cf_fail cross_filesystem_state;return 1; }
    cf_rpc_checkpoint before_write
    platform_initial_write
    printf '%s\n' "$CF_POLICY" > "$cf_temp" || { cf_fail state_write_failed;return 1; }
    cf_rpc_checkpoint during_write
    if [ -n "$CF_METADATA" ];then
        printf '%s\n' "$CF_METADATA" >> "$cf_temp" || { cf_fail state_write_failed;return 1; }
    fi
    chmod 600 "$cf_temp" || { cf_fail state_write_failed;return 1; }
    cf_rpc_checkpoint after_write
    cf_backend sync || { cf_fail state_write_failed;return 1; }
    cf_rpc_checkpoint before_rename
    mv -f "$cf_temp" "$CF_STATE" || { cf_fail state_write_failed;return 1; }
    cf_rpc_checkpoint after_rename
    cf_backend sync || { cf_fail state_write_failed;return 1; }
    CF_DIGEST=$(printf '%s\n' "$CF_POLICY" | sha256sum | awk '{print $1}')
}
cf_person_exists() { printf '%s\n' "$CF_POLICY" | awk -F '\t' -v p="$1" '$1=="P"&&$2==p{yes=1}END{exit !yes}'; }
cf_pause_edit() {
    cf_person=$1; cf_until=$2
    cf_id_valid "$cf_person" && cf_person_exists "$cf_person" || { cf_fail unknown_person; return 1; }
    cf_number_valid "$cf_until" || { cf_fail invalid_until; return 1; }
    [ "$cf_until" = 0 ] || [ "$cf_until" -gt "$CF_EXPIRY_NOW" ] || { cf_fail expired_until; return 1; }
    [ "$CF_REVISION" -lt 2147483647 ] || { cf_fail revision_exhausted; return 1; }
    CF_REVISION=$((CF_REVISION + 1))
    # An explicit local pause is an emergency block: it also clears the person's allowance.
    CF_POLICY=$(printf '%s\n' "$CF_POLICY" | awk -F '\t' -v p="$cf_person" -v u="$cf_until" -v r="$CF_REVISION" 'BEGIN{OFS="\t"}$1=="R"{$2=r}($1=="A"||$1=="U")&&$2==p{next}{print}END{print "A",p,u}' | cf_canonical)
}
cf_resume_edit() {
    cf_person=$1
    cf_id_valid "$cf_person" && cf_person_exists "$cf_person" || { cf_fail unknown_person; return 1; }
    [ "$CF_REVISION" -lt 2147483647 ] || { cf_fail revision_exhausted; return 1; }
    CF_REVISION=$((CF_REVISION + 1))
    CF_POLICY=$(printf '%s\n' "$CF_POLICY" | awk -F '\t' -v p="$cf_person" -v r="$CF_REVISION" 'BEGIN{OFS="\t"}$1=="R"{$2=r}$1=="A"&&$2==p{next}{print}' | cf_canonical)
}
cf_timeout_available() {
    if [ "$CF_LOCAL_TEST" = 1 ] && [ -n "${CF_TEST_TIMEOUT-}" ];then
        case $CF_TEST_TIMEOUT in
            'busybox timeout')CF_TIMEOUT=$(command -v busybox) || { cf_fail missing_input_deadline_dependency;return 1; };;
            /tmp/*/busybox\ timeout)CF_TIMEOUT=${CF_TEST_TIMEOUT% timeout};[ -f "$CF_TIMEOUT" ] && [ ! -L "$CF_TIMEOUT" ] && [ -x "$CF_TIMEOUT" ] || { cf_fail missing_input_deadline_dependency;return 1; };;
            *)cf_fail missing_input_deadline_dependency;return 1;;
        esac
        CF_TIMEOUT_BUSYBOX=1
        return 0
    fi
    CF_TIMEOUT_BUSYBOX=0
    for cf_timeout_path in /usr/bin/timeout /bin/timeout;do
        if [ -x "$cf_timeout_path" ];then CF_TIMEOUT=$cf_timeout_path;return 0;fi
    done
    cf_fail missing_input_deadline_dependency
    return 1
}
cf_input_deadline() {
    if [ "$CF_TIMEOUT_BUSYBOX" = 1 ];then "$CF_TIMEOUT" timeout "$@";else "$CF_TIMEOUT" "$@";fi
}

cf_input_cleanup() {
    if [ -n "${CF_INPUT_DIR-}" ];then
        rm -f "$CF_INPUT_DIR/input"
        rmdir "$CF_INPUT_DIR" 2>/dev/null || :
        CF_INPUT_DIR=
    fi
}
cf_sync_stage() {
    platform_deadline_check
    cf_timeout_available || return 1
    cf_input_parent=$CF_BASE/tmp
    [ -d "$cf_input_parent" ] && [ ! -L "$cf_input_parent" ] && [ "$(CDPATH='' cd -- "$cf_input_parent" && pwd -P)" = "$cf_input_parent" ] || { cf_fail unsafe_input_directory;return 1; }
    CF_INPUT_DIR=$cf_input_parent/couvrefeu-input.$$
    mkdir -m 700 "$CF_INPUT_DIR" || { CF_INPUT_DIR=;cf_fail unsafe_input_directory;return 1; }
    trap 'cf_input_cleanup; cf_unlock' 0
    trap 'cf_input_cleanup; cf_unlock;exit 129' HUP
    trap 'cf_input_cleanup; cf_unlock;exit 130' INT
    trap 'cf_input_cleanup; cf_unlock;exit 143' TERM
    # Deadline and byte bound apply before acquiring the policy mutation lock.
    cf_input_deadline 10 dd bs=1 count=65537 of="$CF_INPUT_DIR/input" 2>/dev/null || { cf_input_cleanup;cf_fail input_deadline_or_read_failure;return 1; }
    platform_deadline_check
    cf_input_size=$(wc -c < "$CF_INPUT_DIR/input")
    if [ "$cf_input_size" -gt 65536 ];then cf_input_cleanup;cf_fail policy_too_large;return 1;fi
    cf_ascii_size=$(tr -cd '\11\12\15\40-\176' < "$CF_INPUT_DIR/input" | wc -c)
    [ "$cf_ascii_size" = "$cf_input_size" ] || { cf_input_cleanup;cf_fail invalid_policy_bytes;return 1; }
    cf_parsed=$(awk -v rpc="${1:-0}" -f "$CF_LIB/json.awk" "$CF_INPUT_DIR/input")
    cf_rc=$?
    cf_input_cleanup
    [ "$cf_rc" = 0 ] || { cf_fail invalid_policy;return 1; }
    if [ "${1:-0}" = 1 ];then
        CF_REQUEST_GENERATION=$(printf '%s\n' "$cf_parsed" | awk -F '\t' '$1=="Q"{print $2}')
        CF_REQUEST_ID=$(printf '%s\n' "$cf_parsed" | awk -F '\t' '$1=="Q"{print $3}')
        CF_BASE_REVISION=$(printf '%s\n' "$cf_parsed" | awk -F '\t' '$1=="Q"{print $4}')
        CF_BASE_DIGEST=$(printf '%s\n' "$cf_parsed" | awk -F '\t' '$1=="Q"{print $5}')
        cf_parsed=$(printf '%s\n' "$cf_parsed" | awk -F '\t' '$1!="Q"')
    fi
    CF_STAGED_POLICY=$(printf '%s\n' "$cf_parsed" | cf_canonical)
    CF_NEXT_DIGEST=$(printf '%s\n' "$CF_STAGED_POLICY" | sha256sum | awk '{print $1} ')
}
cf_sync_read() {
    cf_new=$CF_STAGED_POLICY
    cf_new_rev=$(printf '%s\n' "$cf_new" | awk -F '\t' '$1=="R"{print $2}')
    [ "$cf_new_rev" -ge "$CF_REVISION" ] || { cf_fail stale_revision;return 1; }
    if [ "$cf_new_rev" = "$CF_REVISION" ] && [ "$cf_new" != "$CF_POLICY" ];then cf_fail conflicting_revision;return 1;fi
    cf_allowance_admissible "$cf_new" || return 1
    CF_POLICY=$cf_new;CF_REVISION=$cf_new_rev
}
cf_check() {
    cf_missing=
    cf_timeout_available || cf_missing=timeout
    for cf_dep in awk sort stat date sha256sum dd chmod mkdir mv rm rmdir wc cmp cp tr id dirname env sync cat; do
        command -v "$cf_dep" >/dev/null 2>&1 || cf_missing="$cf_missing $cf_dep"
    done
    for cf_dep in iptables ip6tables ipset uci conntrack ip fw3 sync; do
        cf_backend_available "$cf_dep" || cf_missing="$cf_missing $cf_dep"
    done
    if [ -n "$cf_missing" ]; then printf '%s\n' '{"ok":false,"errors":["missing_dependencies"]}'; return 1; fi
    # This checks the shipped parser, not an unverified desktop substitute.
    cf_probe=$(printf '%s\n' '{"version":1,"revision":0,"people":[],"pauses":[],"schedules":[]}' | awk -f "$CF_LIB/json.awk") || return 1
    [ "$cf_probe" = "$(printf 'V\t1\nR\t0')" ] || return 1
    printf '%s\n' '{"ok":true,"capabilities":{"parser":"strict-posix-awk","routerCompatibilityVerified":false},"errors":[]}'
}
cf_error_record() {
    [ "$CF_LOCKED" = 1 ] || return 0
    cf_temp=$CF_RUNTIME/.error.$$
    [ ! -e "$cf_temp" ] && [ ! -L "$cf_temp" ] || return 1
    platform_initial_write
    printf '%s\n' "${CF_ERROR:-apply_failed}" > "$cf_temp" && chmod 600 "$cf_temp" && mv -f "$cf_temp" "$CF_RUNTIME/error"
}
cf_status() {
    if [ -d "$CF_RUNTIME/lock" ] && [ "$CF_LOCKED" != 1 ];then
        cf_state_load || :
        CF_ERROR=${CF_ERROR:-operation_in_progress}
        cf_busy_result
        return 1
    fi
    cf_status_error=$CF_ERROR
    # Status is the last step of every command and must stay read-only, even
    # after a refused command left CF_TRANSITION/CF_SLOT loaded.
    CF_STATUS_READ_ONLY=1
    cf_ok=true; cf_drift=false; cf_confirmed=null
    CF_REVISION=0; CF_POLICY=; CF_DIGEST=
    cf_control_dirs || cf_ok=false
    cf_state_load || cf_ok=false
    cf_clock || { cf_ok=false;CF_EXPIRY_NOW=;unset CF_PREPARED_EPOCH; }
    cf_protected_valid || cf_ok=false
    [ "$cf_ok" = false ] || cf_policy_safe || cf_ok=false
    cf_kids_json='[]';cf_paused_json='[]'
    if [ "$cf_ok" = true ]; then
        cf_slot_load
        cf_address_refresh || cf_ok=false
        CF_EXPECTED=$(cf_plan) || cf_ok=false
        cf_observed_kids=$(cf_set_members "cf2_${CF_SLOT}_k") || { cf_ok=false;cf_fail observed_set_read_failed; }
        cf_observed_paused=$(cf_set_members "cf2_${CF_SLOT}_p") || { cf_ok=false;cf_fail observed_set_read_failed; }
        cf_kids_json=$(printf '%s\n' "$cf_observed_kids" | cf_json_strings)
        cf_paused_json=$(printf '%s\n' "$cf_observed_paused" | cf_json_strings)
        cf_verify || { cf_ok=false;cf_drift=true;[ -n "$CF_ERROR" ] || cf_fail observed_verification_failed; }
    else cf_drift=true; fi
    if cf_safe_file "$CF_RUNTIME/confirmed"; then
        cf_confirmed=$(awk 'NR==1&&$1~/^[0-9]+$/{print $1}' "$CF_RUNTIME/confirmed")
        [ -n "$cf_confirmed" ] || cf_confirmed=null
        cf_old_digest=$(awk 'NR==1{print $2}' "$CF_RUNTIME/confirmed")
        cf_old_effective=$(awk 'NR==1{print $3}' "$CF_RUNTIME/confirmed")
        [ "$cf_old_digest" = "$CF_DIGEST" ] && [ "$cf_old_effective" = "$(cf_effective_digest)" ] || { cf_ok=false;cf_drift=true; }
    else cf_ok=false; cf_drift=true; fi
    if [ -e "$CF_RUNTIME/firewall.intent" ] || [ -L "$CF_RUNTIME/firewall.intent" ];then cf_ok=false;cf_drift=true;[ -n "$CF_ERROR" ] || CF_ERROR=apply_incomplete;fi
    if [ -e "$CF_RUNTIME/error" ]; then
        cf_safe_file "$CF_RUNTIME/error" || CF_ERROR=unsafe_error_record
        cf_ok=false
        [ -n "$CF_ERROR" ] || CF_ERROR=previous_apply_failed
    fi
    if [ -d "$CF_RUNTIME/lock" ] && [ "$CF_LOCKED" != 1 ]; then cf_ok=false;cf_drift=true;[ -n "$CF_ERROR" ] || CF_ERROR=operation_in_progress; fi
    [ -z "$cf_status_error" ] || { CF_ERROR=$cf_status_error;cf_ok=false; }
    cf_desired=$(printf '%s\n' "$CF_POLICY" | awk -F '\t' 'BEGIN{printf "["}$1=="A"{printf "%s{\"person\":\"%s\",\"until\":%s}",sep,$2,$3;sep=","}END{print "]"}')
    cf_effective=$(printf '%s\n' "$CF_POLICY" | awk -F '\t' -v now="$CF_EXPIRY_NOW" 'BEGIN{printf "["}$1=="A"&&($3==0||$3>now){printf "%s{\"person\":\"%s\",\"until\":%s}",sep,$2,$3;sep=","}END{print "]"}')
    cf_desired_allow=$(printf '%s\n' "$CF_POLICY" | awk -F '\t' 'BEGIN{printf "["}$1=="U"{printf "%s{\"person\":\"%s\",\"until\":%s}",sep,$2,$3;sep=","}END{print "]"}')
    cf_effective_allow=$(cf_active_allowances | awk -F '\t' 'BEGIN{printf "["}{printf "%s{\"person\":\"%s\",\"until\":%s,\"remaining\":%s}",sep,$1,$2,$3;sep=","}END{print "]"}')
    cf_errors='[]'
    if [ -n "$CF_ERROR" ]; then cf_errors=$(printf '%s\n' "$CF_ERROR" | cf_json_strings); fi
    printf '{"ok":%s,"desiredRevision":%s,"confirmedRevision":%s,"desiredPauses":%s,"effectivePauses":%s,"desiredAllowances":%s,"effectiveAllowances":%s,"observed":{"kids":%s,"paused":%s},"drift":%s,"capabilities":{"ipv6":%s,"conntrack":%s,"nativeKernelConfirmed":%s,"addressCoverageComplete":%s,"routerCompatibilityVerified":false},"errors":%s}\n' "$cf_ok" "$CF_REVISION" "$cf_confirmed" "$cf_desired" "$cf_effective" "$cf_desired_allow" "$cf_effective_allow" "$cf_kids_json" "$cf_paused_json" "$cf_drift" "${CF_IPV6_OK:-false}" "${CF_CONNTRACK_OK:-false}" "${CF_NATIVE_OK:-false}" "${CF_ADDRESS_OK:-false}" "$cf_errors"
    [ "$cf_ok" = true ]
}
cf_json_strings() { awk 'BEGIN{printf "["}NF{gsub(/\\/,"\\\\");gsub(/"/,"\\\"");gsub(/[[:cntrl:]]/,"?");printf "%s\"%s\"",sep,$0;sep=","}END{print "]"}'; }
cf_busy_result() {
    printf '{"ok":false,"desiredRevision":%s,"confirmedRevision":null,"desiredPauses":[],"effectivePauses":[],"desiredAllowances":[],"effectiveAllowances":[],"observed":{"kids":[],"paused":[]},"drift":true,"capabilities":{"ipv6":false,"conntrack":false,"nativeKernelConfirmed":false,"addressCoverageComplete":false,"routerCompatibilityVerified":false},"errors":["%s"]}\n' "${CF_REVISION:-0}" "${CF_ERROR:-locked}"
}
cf_main() {
    platform_deadline_check
    cf_action=${1-}
    case $cf_action in
        rpc-sync|rpc-status) cf_rpc_main "$@";return $?;;
        activity|rpc-activity) [ "$#" = 2 ] && [ "$2" = --json ] || { printf '%s\n' '{"ok":false,"errors":["invalid_command"]}'; return 2; }
            if [ "$cf_action" = activity ];then cf_activity;else cf_rpc_activity;fi;return $?;;
        check) [ "$#" = 1 ] || { printf '%s\n' '{"ok":false,"errors":["invalid_command"]}'; return 2; };cf_check;return $?;;
        status) [ "$#" = 2 ] && [ "$2" = --json ] || { printf '%s\n' '{"ok":false,"errors":["invalid_command"]}'; return 2; };cf_status;return 0;;
        pause) if [ "$#" = 2 ]; then cf_until=0;elif [ "$#" = 4 ] && [ "$3" = --until ];then cf_until=$4;else cf_action=invalid;fi;;
        resume) [ "$#" = 2 ] || cf_action=invalid;;
        expire|apply-fw|sync|remove-fw) [ "$#" = 1 ] || cf_action=invalid;;
        *)cf_action=invalid;;
    esac
    if [ "$cf_action" = invalid ]; then printf '%s\n' '{"ok":false,"errors":["invalid_command"]}';return 2;fi
    if ! cf_install_gate "$cf_action";then cf_busy_result;return 1;fi
    if [ "$cf_action" = apply-fw ] && cf_reentrant_include; then return 0;fi
    if ! cf_control_dirs || ! cf_protected_valid || ! cf_state_load || ! cf_clock; then cf_status;return 1;fi
    # remove-fw skips cf_policy_safe so uninstall still works in an inconsistent policy state.
    if [ "$cf_action" != remove-fw ] && ! cf_policy_safe;then cf_status;return 1;fi
    if [ "$cf_action" = sync ] && ! cf_sync_stage 0;then cf_status;return 1;fi
    if ! cf_lock;then cf_busy_result;return 1;fi
    if ! cf_install_gate "$cf_action";then cf_busy_result;return 1;fi
    # A different operation may have committed between the first read and mkdir.
    if ! cf_control_dirs || ! cf_protected_valid || ! cf_state_load || ! cf_clock;then cf_status;return 1;fi
    # remove-fw skips cf_policy_safe (see above).
    if [ "$cf_action" != remove-fw ] && ! cf_policy_safe;then cf_status;return 1;fi
    CF_OLD_POLICY=$CF_POLICY
    CF_OLD_DIGEST=$CF_DIGEST
    case $cf_action in
        sync) cf_sync_read || { cf_status;return 1; };;
        pause) cf_pause_edit "$2" "$cf_until" || { cf_status;return 1; };;
        resume) cf_resume_edit "$2" || { cf_status;return 1; };;
    esac
    if ! cf_backend_available sync;then cf_fail missing_dependencies;cf_status;return 1;fi
    # remove-fw skips policy, scope and guard checks so uninstall works in inconsistent states.
    # Only policy-changing actions face the SSH-client guard: apply-fw and expire
    # re-enforce the existing policy and must work from any admin device.
    case $cf_action in
        sync|pause|resume) cf_policy_safe && cf_ssh_guard || { cf_status;return 1; };;
        apply-fw|expire) cf_policy_safe || { cf_status;return 1; };;
    esac
    if [ "$cf_action" = remove-fw ];then
        cf_remove_fw || { cf_error_record;cf_status;return 1; }
        if [ "$CF_PLATFORM_PROFILE" = "$CF_OS_TRUST_PROFILE" ]; then
            cf_initial_write=false
            [ "$CF_PLATFORM_INITIAL_WRITE" != 1 ] || cf_initial_write=true
            printf '{"ok":true,"removed":true,"zeroOwnedMutations":%s,"initialProtectedWrite":%s,"errors":[]}\n' "${CF_ZERO_OWNED:-false}" "$cf_initial_write"
        else
            printf '{"ok":true,"removed":true,"zeroOwnedMutations":%s,"errors":[]}\n' "${CF_ZERO_OWNED:-false}"
        fi
        return 0
    fi
    # Validate capabilities and foreign-object ownership BEFORE accepting a new revision.
    if ! cf_preflight_baseline_prepare;then cf_status;return 1;fi
    if ! cf_preflight; then cf_status;return 1;fi
    if ! cf_preflight_baseline_clear;then cf_status;return 1;fi
    if ! cf_transition_prepare;then cf_error_record;cf_status;return 1;fi
    case $cf_action in sync|pause|resume)
        if [ -n "$CF_METADATA" ];then
            CF_CURRENT=-
            CF_METADATA=$(printf '%s\n' "$CF_METADATA" | awk -F '\t' 'BEGIN{OFS="\t"}$1=="C"{$2="-"}{print}')
        fi
        cf_write_policy || { cf_error_record;cf_status;return 1; };;esac
    if ! cf_apply;then cf_error_record;cf_status;return 1;fi
    cf_status
}
