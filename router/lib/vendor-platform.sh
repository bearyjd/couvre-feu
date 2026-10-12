#!/bin/sh
# PRIVATE candidate012: source only after exact bootstrap/helper verification.
# Reuses bounded readers/selectors008/010; no vendor scripts are executed.
vp_hash_value() {
    # Ordinary paths never follow a link; the explicit proc-image caller below
    # hashes its admitted magic link separately, after exact target validation.
    regular "$1"
    value=$(timeout -s KILL 6 sha256sum "$1") || fail hash_read
    value=${value%% *}
    case "$value" in ''|*[!0-9a-f]*) fail hash_format;; esac
    [ "${#value}" = 64 ] || fail hash_length
    printf '%s\n' "$value"
}
vp_canonical() {
    parent=${1%/*}; [ -n "$parent" ] || parent=/
    [ "$(CDPATH='' cd -- "$parent" && pwd -P)" = "$parent" ] || fail metadata_parent_canonical
}
vp_metadata() {
    [ ! -L "$1" ] || fail metadata_symlink
    vp_canonical "$1"
    tuple=$(stat_private -c '%u:%g:%a' "$1") || fail metadata_read
    case "$tuple" in 0:0:*) ;; *) fail metadata_owner;; esac
    mode=${tuple##*:}
    case "$mode" in ''|*[!0-7]*) fail metadata_mode;; esac
    [ "${#mode}" -le 4 ] && [ "${#mode}" -ge 3 ] || fail metadata_mode
    [ "$((0$mode & 07002))" = 0 ] || fail metadata_special_or_world_write
    [ "$((0$mode & 020))" != 0 ] || return 0
    [ "${vp_profile:-strict}" = gl-xe3000-4.8.3-logd-011-v1 ] || fail unsupported_vendor_profile
    # This private primitive is used inside a fresh transaction. Callers must
    # use vp_transaction_check, never retain its success as later permission.
    case "$1:$tuple" in
        /lib/config:0:0:775|/etc:0:0:775|/etc/opkg:0:0:775|/usr/libexec:0:0:775|/sbin:0:0:775|/etc/init.d:0:0:775)
            [ -d "$1" ] || fail exception_type;;
        /lib/functions.sh:0:0:664)
            [ "$(vp_hash_value "$1")" = b2b07ca83222f8677f8117e4ed8bff162ef9e6ad0aadaa42d6248c5865831406 ] || fail helper_pin;;
        /lib/config/uci.sh:0:0:664)
            [ "$(vp_hash_value "$1")" = 0a84923c0de12443b97969b1124cb195bedcd150e5128e5e3c9c9f8458594588 ] || fail helper_pin;;
        /etc/opkg/keys/06a6bf2ad909388f:0:0:775)
            [ "$(vp_hash_value "$1")" = 4e57e74980a8f5b2c8978f7c19d0689530453e50d24689c25ab8ddf80f790d1a ] || fail key_pin;;
        /etc/passwd:0:0:664|/etc/group:0:0:664)
            # Reused008 account-source READ admission, not a mutation target.
            regular "$1";;
        *) fail unobserved_group_writable_path;;
    esac
}
vp_pins() {
    for p in / /lib /lib/config /etc /etc/opkg /etc/opkg/keys /usr /usr/bin /usr/lib /usr/libexec /usr/lib/opkg /usr/lib/opkg/info /bin /sbin /usr/sbin /etc/init.d; do
        [ -d "$p" ] && [ ! -L "$p" ] || fail system_parent_type
        vp_metadata "$p"
    done
    [ "$(stat_private -c '%u:%g:%a' /tmp)" = 0:0:1777 ] && [ ! -L /tmp ] || fail tmp_metadata
    for p in /lib/libc.so /lib/libgcc_s.so.1 /lib/functions.sh /lib/config/uci.sh /etc/opkg/keys/06a6bf2ad909388f /usr/lib/opkg/status /bin/opkg; do
        regular "$p"; vp_metadata "$p"
    done
    [ -L /lib/ld-musl-aarch64.so.1 ] && [ "$(readlink /lib/ld-musl-aarch64.so.1)" = libc.so ] || fail loader_link
    hash_is /lib/libc.so c7ad6aff9300a5810e33ed8099057ef4515c0e711e9570309161d4014a5768ce
    hash_is /lib/libgcc_s.so.1 6baf0c0086b0bd2915019e942a2fa7b2b4dfb4e0935db43a71fc54add13d1a69
    hash_is /lib/functions.sh b2b07ca83222f8677f8117e4ed8bff162ef9e6ad0aadaa42d6248c5865831406
    hash_is /lib/config/uci.sh 0a84923c0de12443b97969b1124cb195bedcd150e5128e5e3c9c9f8458594588
    hash_is /etc/opkg/keys/06a6bf2ad909388f 4e57e74980a8f5b2c8978f7c19d0689530453e50d24689c25ab8ddf80f790d1a
    for p in /sbin/logd /sbin/procd /etc/init.d/log; do
        regular "$p"; vp_canonical "$p"
        [ "$(stat_private -c '%u:%g:%a' "$p")" = 0:0:755 ] || fail profile_file_metadata
        case "$p" in
            /sbin/logd) size=12713; pin=776968b15aa4ab7056e7be12dd10aa1b4540ac194ee9dd9a81d595dba76b04b4;;
            /sbin/procd) size=97569; pin=cbd00d8102c236d3f2ee2c56c159a9133f574477ef89efc80d2be5f4daf0a3d1;;
            /etc/init.d/log) size=2339; pin=54cdc170cb9ada1d208063f79916d7da2c364e098c05734ac72b50e0026c3b9e;;
        esac
        [ "$(stat_private -c %s "$p")" = "$size" ] || fail profile_file_size
        hash_is "$p" "$pin"
    done
    # Compare freshly observed inodes/sizes across this transaction, not boots.
    stat_private -c '%n:%d:%i:%s' /sbin/logd /sbin/procd /etc/init.d/log
}
vp_read_body() {
    # NUL is mapped to reserved SOH before BusyBox awk sees it; both controls
    # are rejected. Explicit dd and transform status footers preserve failures.
    {
        if timeout -s KILL 6 dd if="$1" bs=1 count="$2" 2>/dev/null; then rc=0; else rc=$?; fi
        printf '\nCF008_DD_END=%s\n' "$rc"
    } | tr '\000' '\001'
    transform_rc=$?
    printf 'CF008_READ_END=%s\n' "$transform_rc"
}
vp_credentials() {
    # shellcheck disable=SC2016
    vp_read_body "$1" 32769 | awk -v expected_pid="$2" -v expected_tid="$3" '
    function number(s) {return s~/^[0-9]+$/ && length(s)<=10 && s+0<=4294967295}
    /^CF008_DD_END=/ {if($0!="CF008_DD_END=0" || dd_footer++) bad=1;next}
    /^CF008_READ_END=/ {if($0!="CF008_READ_END=0" || footer++ || dd_footer!=1) bad=1;next}
    {
        if(footer||dd_footer) bad=1
        bytes+=length($0)+1
        if(bytes>32769 || ++lines>512 || $0~/[\001-\010\013-\037\177]/) bad=1
        if($1=="Uid:") {
            if(u++ || NF!=5) bad=1
            for(i=2;i<=NF;i++) {if(!number($i)) bad=1;if($i+0!=0) nonroot=1;if(i>2) uids=uids ",";uids=uids $i}
        } else if($1=="Gid:") {
            if(g++ || NF!=5) bad=1
            for(i=2;i<=NF;i++) {if(!number($i)) bad=1;if($i+0==0) group0=1;if(i>2) gids=gids ",";gids=gids $i}
        } else if($1=="Groups:") {
            if(s++ || NF>65) bad=1
            for(i=2;i<=NF;i++) {if(!number($i)) bad=1;if($i+0==0) group0=1;if(i>2) groups=groups ",";groups=groups $i}
        } else if($1=="Tgid:") {if(tg++ || NF!=2 || !number($2) || $2!=expected_pid) bad=1}
        else if($1=="Pid:") {if(ti++ || NF!=2 || !number($2) || $2!=expected_tid) bad=1}
        else if($1=="PPid:") {if(pp++ || NF!=2 || !number($2)) bad=1;parent=$2}
        else if(tolower($1)~/^(uid|gid|groups|tgid|pid|ppid):?$/) bad=1
    }
    END {if(bad||footer!=1||u!=1||g!=1||s!=1||tg!=1||ti!=1||pp!=1) exit 2
        printf "%d %s %s %s %s\n",group0&&nonroot,uids,gids,(groups==""?"none":groups),parent}'
}
vp_comm() {
    # shellcheck disable=SC2016
    vp_read_body "$1" 65 | awk '
    /^CF008_DD_END=/ {if($0!="CF008_DD_END=0" || dd_footer++) bad=1;next}
    /^CF008_READ_END=/ {if($0!="CF008_READ_END=0" || footer++ || dd_footer!=1) bad=1;next}
    {if(footer||dd_footer)bad=1;bytes+=length($0)+1
     if(bytes>65 || $0~/[\001-\010\013-\037\177]/) bad=1
     if($0!="") {if(records++ || length($0)>15)bad=1;value=$0}}
    END {if(bad||footer!=1||records!=1)exit 2;print value}'
}
vp_starttime() {
    # shellcheck disable=SC2016
    vp_read_body "$1" 4097 | awk -v expected="$2" '
    /^CF008_DD_END=/ {if($0!="CF008_DD_END=0" || dd_footer++) bad=1;next}
    /^CF008_READ_END=/ {if($0!="CF008_READ_END=0" || footer++ || dd_footer!=1) bad=1;next}
    {if(footer||dd_footer)bad=1;bytes+=length($0)+1
     if(bytes>4097 || $0~/[\001-\010\013-\037\177]/)bad=1
     if($0!="") {
         if(records++ || $1!=expected || $0!~/^[0-9]+ \(.*\) /)bad=1
         sub(/^[0-9]+ \(.*\) /,"")
         if(NF<20 || $1!~/^[A-Za-z]$/ || $20!~/^[0-9]+$/ || length($20)>20)bad=1
         value=$20
     }}
    END {if(bad||footer!=1||records!=1)exit 2;print value}'
}
vp_exe() {
    [ -L "$1" ] || return 2
    exe=$(timeout -s KILL 4 readlink "$1" && printf ".") || return 2
    # Keep any newline in the target; strip only our marker and readlink delimiter.
    exe=${exe%.}; exe=${exe%?}
    case "$exe" in /*) ;; *) return 2;; esac
    case "$exe" in *[!A-Za-z0-9_./+:-]*) return 2;; esac
    [ "${#exe}" -le 512 ] || return 2
    printf '%s\n' "$exe"
}

vp_account_select() {
    # shellcheck disable=SC2016
    { vp_read_body /etc/passwd 262145; vp_read_body /etc/group 262145; } |
    awk -F: -v ps="$passwd_size" -v gs="$group_size" '
    function nameok(s) { return s ~ /^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/ }
    function number(s) { return s ~ /^[0-9]+$/ && length(s)<=10 && s+0<=4294967295 }
    BEGIN {phase=1}
    /^CF008_DD_END=/ {if($0!="CF008_DD_END=0" || dd_footer++ || phase>2) bad=1;next}
    /^CF008_READ_END=/ {
        if ($0!="CF008_READ_END=0" || phase>2 || dd_footer!=1) bad=1
        if (bytes!=(phase==1?ps:gs)+1 || bytes>262145) bad=1
        phase++;bytes=0;dd_footer=0;next
    }
    {
        if (phase>2 || dd_footer) {bad=1;next}
        bytes+=length($0)+1
        if (bytes>262145 || length($0)>4096 || $0~/[\001-\010\013-\037\177]/) {bad=1;next}
        if ($0=="") next
        if (++records[phase]>4096) {bad=1;next}
        if (phase==1) {
            if (NF!=7 || !nameok($1) || !number($3) || !number($4) || ($1 in uid)) {bad=1;next}
            uid[$1]=$3+0
            if($3+0==514) {uid514++;if($1!="logd" || $4+0!=514) bad=1}
            if($1=="logd") {logd++;if($3+0!=514 || $4+0!=514) bad=1}
            if ($3+0==0) roots++
            if ($4+0==0) {primary++;if ($3+0!=0) violations++}
        } else {
            if (NF!=4 || !nameok($1) || !number($3) || group_seen[$1]++) {bad=1;next}
            if($3+0==514) {gid514++;if($1!="logd") bad=1}
            if($1=="logd" && $3+0!=514) bad=1
            n=($4=="" ? 0 : split($4,members,","))
            for(i=1;i<=n;i++) if(!nameok(members[i])) bad=1
            if ($3+0==0) {
                groups0++
                for(i=1;i<=n;i++) {supplementary++;if(!(members[i] in uid) || uid[members[i]]!=0) violations++}
            }
        }
    }
    END {
        if (phase!=3 || records[1]<1 || records[2]<1 || roots<1 || groups0<1) bad=1
        if (bad || violations || logd!=1 || uid514!=1 || gid514!=1) exit 2
        printf "%d %d %d %d %d %d %d\n",records[1],records[2],roots,groups0,primary,supplementary,violations
    }'
}

vp_providers() {
    [ -L /var ] && [ "$(readlink /var)" = tmp ] || fail var_link
vp_provider_scan() {
    [ -L /var ] && [ "$(readlink /var)" = tmp ] || fail var_link
    provider_sockets=0
    for base in /tmp/run /run; do
        if [ -e "$base" ] || [ -L "$base" ]; then
            [ -d "$base" ] && [ ! -L "$base" ] || fail provider_ancestor_type
            vp_metadata "$base"
            if [ -e "$base/nscd" ] || [ -L "$base/nscd" ]; then
                [ -d "$base/nscd" ] && [ ! -L "$base/nscd" ] || fail provider_directory_type
                vp_metadata "$base/nscd"
                if [ -e "$base/nscd/socket" ] || [ -L "$base/nscd/socket" ]; then provider_sockets=$((provider_sockets+1)); fi
            fi
        fi
    done
}


vp_provider_scan
 :
[ "$provider_sockets" = 0 ] || fail credential_provider_socket
nss_exists=0
if [ -e /etc/nsswitch.conf ] || [ -L /etc/nsswitch.conf ]; then
    nss_exists=1; regular /etc/nsswitch.conf; vp_metadata /etc/nsswitch.conf
    nss_size=$(stat_private -c %s /etc/nsswitch.conf)
    [ "$nss_size" -le 65536 ] || fail provider_config_size
    nss_hash=$(vp_hash_value /etc/nsswitch.conf)
    nss_meta=$(stat_private -c '%u:%g:%a:%d:%i:%s' /etc/nsswitch.conf) || fail provider_metadata_read
    # shellcheck disable=SC2016
    provider_result=$(vp_read_body /etc/nsswitch.conf 65537 | awk -v expected="$nss_size" '
    /^CF008_DD_END=/ {if($0!="CF008_DD_END=0" || dd_footer++) bad=1;next}
    /^CF008_READ_END=/ {if ($0!="CF008_READ_END=0" || footer++ || dd_footer!=1) bad=1;next}
    {
        if(footer || dd_footer) bad=1
        bytes+=length($0)+1
        if(bytes>65537 || length($0)>4096 || ++lines>1024 || $0~/[\001-\010\013-\037\177]/) bad=1
        sub(/#.*/,"")
        if(tolower($1)=="passwd:" || tolower($1)=="group:") {
            if(($1!="passwd:" && $1!="group:") || seen[$1]++ || NF!=2 || $2!="files") provider_bad=1
            records++
        } else if($0~/^[ \t]*(passwd|group)([ \t:]|$)/) provider_bad=1
    }
    END {if(bad||footer!=1||bytes!=expected+1) exit 2;printf "%d %d\n",records,provider_bad}') || fail malformed_provider_config
    [ "$(vp_hash_value /etc/nsswitch.conf)" = "$nss_hash" ] || fail provider_config_drift
    # Numeric output from the fixed selector, with no data-controlled glob bytes.
    # shellcheck disable=SC2086
    set -- $provider_result
    [ "$#" = 2 ] || fail provider_aggregate_shape
     :
    [ "$2" = 0 ] || fail configured_credential_provider
else
    :
fi

}

vp_presence() {
    for q in "$proc_pid" "$proc_pid/task" "$task_dir"; do
        [ ! -L "$q" ] || return 2
        if [ ! -e "$q" ]; then return 1; fi
        [ -d "$q" ] || return 2
    done
}
vp_gone() {
    if vp_presence; then return 1; else rc=$?; fi
    [ "$rc" = 1 ] || fail task_type
}
vp_image() {
    # This is the sole proc magic-link exception, after exact literal target.
    [ "$(vp_exe "$1")" = "$2" ] || fail process_image_target
    inode=$(stat_private -L -c '%d:%i:%s' "$1") || fail process_image_stat
    [ "$inode" = "$(stat_private -c '%d:%i:%s' "$2")" ] || fail process_image_inode
    image=$(timeout -s KILL 6 sha256sum "$1") || fail process_image_hash
    image=${image%% *}
    [ "$image" = "$(vp_hash_value "$2")" ] || fail process_image_hash
    [ "$(vp_exe "$1")" = "$2" ] && [ "$(stat_private -L -c '%d:%i:%s' "$1")" = "$inode" ] || fail process_image_changed
    printf '%s:%s\n' "$inode" "$image"
}
vp_supervisor() (
    # Separate scope avoids overwriting the selected thread's bracket locals.
    for p in /proc /proc/1 /proc/1/task /proc/1/task/1; do
        [ -d "$p" ] && [ ! -L "$p" ] || fail supervisor_type
    done
    for p in /proc/1/task/1/stat /proc/1/task/1/status /proc/1/task/1/comm; do regular "$p"; done
    first=$(vp_starttime /proc/1/task/1/stat 1) || fail supervisor_start
    tuple=$(vp_credentials /proc/1/task/1/status 1 1) || fail supervisor_credentials
    [ "$tuple" = '0 0,0,0,0 0,0,0,0 none 0' ] || fail supervisor_credentials
    [ "$(vp_comm /proc/1/task/1/comm)" = procd ] || fail supervisor_comm
    witness=$(vp_image /proc/1/task/1/exe /sbin/procd) || fail supervisor_image
    [ "$(vp_starttime /proc/1/task/1/stat 1)" = "$first" ] && [ "$(vp_credentials /proc/1/task/1/status 1 1)" = "$tuple" ] && [ "$(vp_comm /proc/1/task/1/comm)" = procd ] || fail supervisor_changed
    [ "$(vp_image /proc/1/task/1/exe /sbin/procd)" = "$witness" ] || fail supervisor_image_changed
    [ "$(vp_starttime /proc/1/task/1/stat 1)" = "$first" ] && [ "$(vp_credentials /proc/1/task/1/status 1 1)" = "$tuple" ] && [ "$(vp_comm /proc/1/task/1/comm)" = procd ] || fail supervisor_changed
    printf '%s:%s\n' "$first" "$witness"
)
vp_budget() {
    regular /proc/uptime
    IFS=' ' read -r uptime rest < /proc/uptime || fail clock_read
    now=${uptime%%.*}
    case "$now" in ''|*[!0-9]*) fail clock_format;; esac
    [ "$now" -ge "$vp_start" ] && [ "$((now-vp_start))" -le 120 ] || fail census_time_bound
}
vp_classify() {
    # Only parser-owned space/comma/numeric output is split; no account bytes.
    # shellcheck disable=SC2086
    set -- $creds
    [ "$#" = 5 ] || fail credential_shape
    case "$comm" in nscd|unscd) fail credential_provider_process;; esac
    if [ "$2" = 0,0,0,0 ]; then classification=root
    elif [ "$1" = 0 ]; then classification=ordinary
    elif [ "$creds" = '1 514,514,514,514 0,0,0,0 none 1' ] && [ "$comm" = logd ]; then
        classification=logd
    else fail unknown_nonroot_gid0
    fi
}
vp_compare_maps() {
    # Finite maps contain only validated identities, credentials and comm.
    printf '%s\n@PASS2\n%s\n' "$previous_map" "$records" | awk -F'|' '
    $0=="@PASS2" {if(second++)bad=1;next}
    $0=="" {next}
    {if(NF!=3 || $1!~/^[0-9]+:[0-9]+:[0-9]+$/ || $2!~/^(root|ordinary|logd)$/)bad=1
     if(second) {if($1 in after)bad=1;after[$1]=$2;af[$1]=$3}
     else {if($1 in before)bad=1;before[$1]=$2;bf[$1]=$3}}
    END {if(second!=1)bad=1
     for(k in before) {
       if(k in after) {if(before[k]!=after[k] || bf[k]!=af[k])bad=1}
       else {removed++;if(before[k]!="root")bad=1}}
     for(k in after) if(!(k in before)) {added++;if(after[k]!="root")bad=1}
     if(bad)exit 2;printf "%d %d\n",added,removed}'
}
vp_census() {
    [ -d /proc ] && [ ! -L /proc ] || fail proc_type
    vp_metadata /proc
    regular /proc/uptime
    IFS=' ' read -r uptime rest < /proc/uptime || fail clock_read
    vp_start=${uptime%%.*}
    case "$vp_start" in ''|*[!0-9]*) fail clock_format;; esac
    previous_map=; previous_logd=; previous_supervisor=
    for pass in 1 2; do
        tasks=0; departures=0; selected=0; logd_pid=; logd_start=; records=; supervisor=
        pids=0
        for proc_pid in /proc/[0-9]*; do
            vp_budget
            pid=${proc_pid##*/}
            case "$pid" in ''|*[!0-9]*) fail incomplete_pid_enumeration;; esac
            pids=$((pids+1)); [ "$pids" -le 4096 ] || fail pid_count_bound
            # A PID discovered by enumeration is never silently dropped because
            # its task collection is absent, malformed, inaccessible or empty.
            [ -d "$proc_pid" ] && [ ! -L "$proc_pid" ] || fail unclassified_pid_absent_or_type
            [ -d "$proc_pid/task" ] && [ ! -L "$proc_pid/task" ] && [ -r "$proc_pid/task" ] && [ -x "$proc_pid/task" ] || fail task_collection_incomplete
            group_tasks=0; group_roots=0; group_logd=0
            for task_dir in "$proc_pid"/task/[0-9]*; do
                vp_budget
                tid=${task_dir##*/}
                case "$pid:$tid" in *[!0-9:]*) fail incomplete_proc_enumeration;; esac
                tasks=$((tasks+1)); [ "$tasks" -le 4096 ] || fail task_count_bound
                vp_presence || fail unclassified_task_absent_or_type
                for p in "$task_dir/stat" "$task_dir/status" "$task_dir/comm"; do regular "$p"; done
                first=$(vp_starttime "$task_dir/stat" "$tid") || fail task_starttime
                creds=$(vp_credentials "$task_dir/status" "$pid" "$tid") || fail task_credentials
                comm=$(vp_comm "$task_dir/comm") || fail task_comm
                vp_classify
                group_tasks=$((group_tasks+1))
                case "$classification" in root) group_roots=$((group_roots+1));; logd) group_logd=$((group_logd+1));; esac
                witness=
                if [ "$classification" = logd ]; then
                    if [ -n "$logd_pid" ]; then [ "$logd_pid" = "$pid" ] || fail duplicate_logd; else logd_pid=$pid; fi
                    selected=$((selected+1))
                    witness=$(vp_image "$task_dir/exe" /sbin/logd) || fail logd_image
                    current_supervisor=$(vp_supervisor) || fail logd_supervisor
                    if [ -n "$supervisor" ]; then [ "$current_supervisor" = "$supervisor" ] || fail supervisor_changed; else supervisor=$current_supervisor; fi
                    if [ "$pid" = "$tid" ]; then logd_start=$first; fi
                fi
                # Only a completely classified root may depart. An unreadable or
                # reused still-present task, ordinary departure or logd departure refuses.
                departed=0
                if vp_presence; then
                    if after_start=$(vp_starttime "$task_dir/stat" "$tid") && after_creds=$(vp_credentials "$task_dir/status" "$pid" "$tid") && after_comm=$(vp_comm "$task_dir/comm"); then
                        [ "$first" = "$after_start" ] && [ "$creds" = "$after_creds" ] && [ "$comm" = "$after_comm" ] || fail task_identity_or_credentials_changed
                    else
                        if [ "$classification" != root ] || ! vp_gone; then fail incomplete_task_bracket; fi
                        departed=1
                    fi
                else
                    if [ "$classification" != root ] || ! vp_gone; then fail unapproved_task_departure; fi
                    departed=1
                fi
                if [ "$classification" = logd ]; then
                    [ "$(vp_image "$task_dir/exe" /sbin/logd)" = "$witness" ] || fail logd_image_changed
                    [ "$(vp_supervisor)" = "$supervisor" ] || fail supervisor_changed
                    [ "$(vp_starttime "$task_dir/stat" "$tid")" = "$first" ] && [ "$(vp_credentials "$task_dir/status" "$pid" "$tid")" = "$creds" ] && [ "$(vp_comm "$task_dir/comm")" = logd ] || fail logd_changed
                fi
                departures=$((departures+departed))
                # Starttime distinguishes root PID reuse between passes. Raw task
                # credential records remain in memory and are never printed.
                records="$records
$pid:$tid:$first|$classification|$creds:$witness"
            done
            [ "$group_tasks" -gt 0 ] || fail empty_task_collection
            # Closure is checked after every sibling regardless of TID order.
            # General root/ordinary eligibility never exempts a selected sibling.
            [ "$group_logd" = 0 ] || [ "$group_logd" = "$group_tasks" ] || fail selected_tgid_thread_mismatch
            if [ -e "$proc_pid" ] || [ -L "$proc_pid" ]; then
                [ -d "$proc_pid" ] && [ ! -L "$proc_pid" ] && [ -d "$proc_pid/task" ] && [ ! -L "$proc_pid/task" ] && [ -r "$proc_pid/task" ] && [ -x "$proc_pid/task" ] || fail task_collection_changed
            else
                [ "$group_roots" = "$group_tasks" ] || fail unapproved_process_departure
            fi
        done
        [ "$tasks" -gt 0 ] || fail empty_task_census
        [ -z "$logd_pid" ] || [ -n "$logd_start" ] || fail logd_leader_not_observed
        logd_identity=$logd_pid:$logd_start
        printf 'VENDOR_CENSUS pass=%s enumerated=%s classified=%s classified_root_departures=%s logd_tgids=%s logd_threads=%s unclassified=0\n' "$pass" "$tasks" "$tasks" "$departures" "$((selected>0))" "$selected"
        if [ "$pass" = 2 ]; then
            [ "$previous_logd" = "$logd_identity" ] && [ "$previous_supervisor" = "$supervisor" ] || fail selected_identity_changed
            changes=$(vp_compare_maps) || fail unsupported_task_churn
            printf 'VENDOR_ROOT_CHURN additions_removals=%s unclassified=0\n' "$changes"
        fi
        previous_map=$records; previous_logd=$logd_identity; previous_supervisor=$supervisor
    done
    vp_budget
}
vp_transaction_check() (
    case "${vp_profile:-strict}" in
        strict)
            for p in / /lib /lib/config /etc /etc/opkg /etc/opkg/keys /usr /usr/bin /usr/lib /usr/libexec /usr/lib/opkg /usr/lib/opkg/info /bin /sbin /usr/sbin; do
                [ -d "$p" ] && [ ! -L "$p" ] || fail system_parent_type
                vp_metadata "$p"
            done
            for p in /lib/libc.so /lib/libgcc_s.so.1 /lib/functions.sh /lib/config/uci.sh /etc/opkg/keys/06a6bf2ad909388f /usr/lib/opkg/status /bin/opkg; do regular "$p"; vp_metadata "$p"; done
            return 0;;
        gl-xe3000-4.8.3-logd-011-v1) ;;
        *) fail unsupported_vendor_profile;;
    esac
    # All provisional vendor/account read admissions become successful only
    # after this complete fresh check. Nothing is persisted as permission.
    pin_before=$(vp_pins) || fail profile_pins
    for p in /etc/passwd /etc/group; do regular "$p"; vp_metadata "$p"; done
    passwd_size=$(stat_private -c %s /etc/passwd); group_size=$(stat_private -c %s /etc/group)
    [ "$passwd_size" -gt 0 ] && [ "$passwd_size" -le 262144 ] && [ "$group_size" -gt 0 ] && [ "$group_size" -le 262144 ] || fail account_size
    passwd_hash=$(vp_hash_value /etc/passwd); group_hash=$(vp_hash_value /etc/group)
    passwd_meta=$(stat_private -c '%u:%g:%a:%d:%i:%s' /etc/passwd) || fail account_metadata_read
    group_meta=$(stat_private -c '%u:%g:%a:%d:%i:%s' /etc/group) || fail account_metadata_read
    vp_account_select >/dev/null || fail malformed_ambiguous_or_unsupported_accounts
    vp_providers
    vp_census
    for p in /etc/passwd /etc/group; do regular "$p"; vp_metadata "$p"; done
    [ "$(stat_private -c '%u:%g:%a:%d:%i:%s' /etc/passwd)" = "$passwd_meta" ] && [ "$(stat_private -c '%u:%g:%a:%d:%i:%s' /etc/group)" = "$group_meta" ] || fail account_metadata_drift
    [ "$(stat_private -c %s /etc/passwd)" = "$passwd_size" ] && [ "$(stat_private -c %s /etc/group)" = "$group_size" ] || fail account_size_drift
    [ "$(vp_hash_value /etc/passwd)" = "$passwd_hash" ] && [ "$(vp_hash_value /etc/group)" = "$group_hash" ] || fail account_drift_during_census
    if [ "$nss_exists" = 1 ]; then
        regular /etc/nsswitch.conf; vp_metadata /etc/nsswitch.conf
        [ "$(stat_private -c '%u:%g:%a:%d:%i:%s' /etc/nsswitch.conf)" = "$nss_meta" ] || fail provider_metadata_drift
        [ "$(vp_hash_value /etc/nsswitch.conf)" = "$nss_hash" ] || fail provider_config_drift
    else [ ! -e /etc/nsswitch.conf ] && [ ! -L /etc/nsswitch.conf ] || fail provider_config_appeared
    fi
    vp_provider_scan
    [ "$provider_sockets" = 0 ] || fail provider_socket_appeared
    [ "$(vp_pins)" = "$pin_before" ] || fail profile_drift
    printf '%s\n' 'VENDOR_PROFILE_ATTESTED: Two complete bounded observations support the selected vendor administration profile; root lifetime churn allowed; non-atomic snapshot.'
)
