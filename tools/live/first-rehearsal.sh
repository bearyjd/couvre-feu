#!/bin/sh
# Couvre-feu FIRST live rehearsal, run as one `/bin/sh -s` SSH session.
# POSIX sh / BusyBox ash. tools/live/first-rehearsal.py fills the generated
# regions below; the operator discloses the exact payload sha256 first.
# Phases: PAYLOAD IDENTITY PREREQ SNAPSHOT INSTALL VERIFY UNINSTALL RESTORE
# CONNECTIVITY. Only this script writes stdout; every child writes stderr.
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
# @CF_GENERATED_PARAMETERS_END@

CFR_STAGE=
CFR_FAILED=0
CFR_LIVE_STATES='REACHABLE STALE DELAY'
CFR_PRESENT_STATES='REACHABLE STALE DELAY PROBE PERMANENT'
# Every path the installer may create or modify (router/install.sh and
# router/lib/install-common.sh FILES, scoped and profile inventory).
CFR_FILES='usr/lib/couvrefeu/core.sh usr/lib/couvrefeu/rpc.sh usr/lib/couvrefeu/state.awk usr/lib/couvrefeu/firewall.sh usr/lib/couvrefeu/json.awk usr/lib/couvrefeu/rules.awk usr/lib/couvrefeu/install-common.sh usr/lib/couvrefeu/platform-bootstrap.sh usr/lib/couvrefeu/vendor-platform.sh usr/sbin/cfctl usr/sbin/cfctl-ssh etc/firewall.couvrefeu etc/config/firewall etc/sysupgrade.conf etc/crontabs/root etc/couvrefeu/protected etc/couvrefeu/state etc/couvrefeu/platform-profile etc/couvrefeu/rpc-allowed'
CFR_DIRS='etc usr usr/sbin usr/lib usr/lib/couvrefeu etc/config etc/crontabs etc/couvrefeu etc/couvrefeu/backup etc/couvrefeu/runtime'
CFR_RELEASE_FILES='install.sh uninstall.sh cfctl cfctl-ssh release.sha256 lib/core.sh lib/rpc.sh lib/firewall.sh lib/install-common.sh lib/state.awk lib/rules.awk lib/json.awk lib/vendor-platform.sh lib/platform-bootstrap.sh'

cfr_info() { printf 'INFO %s\n' "$*"; }
cfr_ok() { printf 'PHASE %s OK\n' "$1"; }
cfr_refuse() {
    printf 'PHASE %s FAIL %s\n' "$1" "$2"
    printf 'REFUSED_BEFORE_MUTATION %s\n' "$1"
    exit 10
}
cfr_fail() {
    printf 'PHASE %s FAIL %s\n' "$1" "$2"
    CFR_FAILED=1
}
cfr_stop() {
    cfr_fail "$1" "$2"
    printf 'FAIL_AFTER_MUTATION %s\n' "$1"
    exit 20
}

# Invoked from the EXIT trap.
# shellcheck disable=SC2329
cfr_cleanup() {
    case "$CFR_STAGE" in /tmp/couvre-feu-first.??????) ;; *) return 0;; esac
    [ -d "$CFR_STAGE" ] && [ ! -L "$CFR_STAGE" ] || return 0
    if [ -f "$CFR_STAGE/manifest" ]; then
        while read -r cfr_sum cfr_mode cfr_path; do
            case "$cfr_path" in router/*) rm -f "$CFR_STAGE/$cfr_path";; esac
        done < "$CFR_STAGE/manifest"
    fi
    for cfr_name in manifest identity.neigh connectivity.neigh status.json snapshot.before snapshot.after \
        text.before.iptables text.before.ip6tables text.before.ipset text.before.uci text.before.cron \
        text.after.iptables text.after.ip6tables text.after.ipset text.after.uci text.after.cron; do
        rm -f "$CFR_STAGE/$cfr_name"
    done
    for cfr_dir in $CFR_PAYLOAD_DIRS; do
        [ ! -d "$CFR_STAGE/$cfr_dir" ] || rmdir "$CFR_STAGE/$cfr_dir" 2>/dev/null || :
    done
    rmdir "$CFR_STAGE" 2>/dev/null || printf 'INFO staging_cleanup_incomplete %s\n' "$CFR_STAGE"
}

cfr_setup_paths() {
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then
        # Isolated fixtures only: production SSH runs under `env -i`.
        case "${CF_ROOT:-}" in /tmp/couvre-feu-*) ;; *) return 1;; esac
        [ -d "$CF_ROOT" ] && [ ! -L "$CF_ROOT" ] || return 1
        [ "$(CDPATH='' cd -- "$CF_ROOT" && pwd -P)" = "$CF_ROOT" ] || return 1
        CFR_FIXTURE=1
        CFR_ROOT=$CF_ROOT
        CFR_RECOVERY=$CF_ROOT/.couvrefeu-recovery
        CFR_INSTALL_LOCK=$CF_ROOT/.couvrefeu-install.lock
        CFR_STAGE_PARENT=$CF_ROOT
        CFR_STAGE_PREFIX=.couvrefeu-stage.
        case "${CF_TEST_SHELL:-sh}" in sh) CFR_SH='sh';; 'busybox ash') CFR_SH='busybox ash';; *) return 1;; esac
    else
        [ -z "${CF_ROOT:-}${CF_BACKEND_DIR:-}" ] || return 1
        CFR_FIXTURE=0
        CFR_ROOT=
        CFR_RECOVERY=/etc/.couvrefeu-recovery
        CFR_INSTALL_LOCK=/tmp/couvrefeu-install.lock
        CFR_STAGE_PARENT=/tmp
        CFR_STAGE_PREFIX=couvrefeu-stage.
        CFR_SH=/bin/sh
    fi
    CFR_PLATFORM_LOCK=/tmp/couvrefeu-platform.lock
    CFR_RELEASE_DIR=$CFR_ROOT/etc/.couvrefeu-release-$CFR_RELEASE_ID
    CFR_LEASES=$CFR_ROOT/tmp/dhcp.leases
    CFR_CFCTL=$CFR_ROOT/usr/sbin/cfctl
}

# The installer's own numeric metadata reader for vendor profiles.
cfr_stat() {
    if [ "$CFR_FIXTURE" = 0 ] && { [ "$CFR_PROFILE" = gl-xe3000-4.8.3-os-trust-v1 ] || [ "$CFR_PROFILE" = gl-xe3000-4.8.3-logd-011-v1 ]; }; then
        env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LD_LIBRARY_PATH=/lib /usr/libexec/stat-coreutils "$@"
    else
        stat "$@"
    fi
}
cfr_run_sh() {
    # Deliberate split of the fixed shell selection ("busybox ash").
    # shellcheck disable=SC2086
    $CFR_SH "$@" </dev/null
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
    [ "$CFR_MGMT_MAC" != "$CFR_JD_MAC" ] && [ "$CFR_MGMT_MAC" != "$CFR_PENN_MAC" ] && [ "$CFR_JD_MAC" != "$CFR_PENN_MAC" ] || cfr_refuse IDENTITY duplicate_live_mac
    [ -n "${SSH_CONNECTION:-}" ] || cfr_refuse IDENTITY ssh_connection_missing
    set -f
    # Deliberate token split of the sshd-provided value; globbing disabled.
    # shellcheck disable=SC2086
    set -- $SSH_CONNECTION
    set +f
    [ "$#" = 4 ] || cfr_refuse IDENTITY ssh_connection_invalid
    [ "$1" = "$CFR_MGMT_IP" ] || cfr_refuse IDENTITY ssh_source_not_management
    ip -4 neigh show dev br-lan > "$CFR_STAGE/identity.neigh" 2>/dev/null </dev/null || cfr_refuse IDENTITY neighbor_read_failed
    [ -f "$CFR_LEASES" ] && [ ! -L "$CFR_LEASES" ] || cfr_refuse IDENTITY leases_unavailable
    # The installer itself requires REACHABLE/PERMANENT for the SSH client.
    cfr_neighbor "$CFR_MGMT_IP" "$CFR_MGMT_MAC" REACHABLE "$CFR_STAGE/identity.neigh" || cfr_refuse IDENTITY management_neighbor_mismatch
    cfr_neighbor "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_LIVE_STATES" "$CFR_STAGE/identity.neigh" || cfr_refuse IDENTITY jd_adult_neighbor_mismatch
    cfr_neighbor "$CFR_PENN_IP" "$CFR_PENN_MAC" "$CFR_LIVE_STATES" "$CFR_STAGE/identity.neigh" || cfr_refuse IDENTITY penn_child_neighbor_mismatch
    for cfr_role in "management $CFR_MGMT_IP $CFR_MGMT_MAC" "jd_adult $CFR_JD_IP $CFR_JD_MAC" "penn_child $CFR_PENN_IP $CFR_PENN_MAC"; do
        # shellcheck disable=SC2086
        set -- $cfr_role
        awk -v ip="$2" -v mac="$3" 'tolower($2)==mac&&$3==ip{n++}END{exit n!=1}' "$CFR_LEASES" || cfr_refuse IDENTITY "$1_lease_mismatch"
    done
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
    cfr_run_sh "$CFR_STAGE/router/install.sh" "$@" >&2
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
    command -v od >/dev/null 2>&1 || cfr_refuse PREREQ od_missing
    [ "$(printf A | od -An -tx1 2>/dev/null | tr -d ' \n')" = 41 ] || cfr_refuse PREREQ od_not_callable
    cfr_stat -c %a / >/dev/null 2>&1 </dev/null || cfr_refuse PREREQ stat_not_callable
    # The installer refuses originals without nanosecond mtimes; so do we.
    [ -f "$CFR_ROOT/etc/config/firewall" ] || cfr_refuse PREREQ firewall_config_missing
    cfr_precision=$(cfr_file_record "$CFR_ROOT/etc/config/firewall") || cfr_refuse PREREQ stat_format
    case "$cfr_precision" in *:s) cfr_refuse PREREQ stat_mtime_not_nanosecond;; esac
    cfr_info mtime_precision nanoseconds
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
        uci) uci export firewall 2>/dev/null </dev/null > "$cfr_text_file";;
        cron) if [ -f "$CFR_ROOT/etc/crontabs/root" ]; then cat "$CFR_ROOT/etc/crontabs/root" > "$cfr_text_file"; else printf 'absent\n' > "$cfr_text_file"; fi;;
    esac
}
cfr_snapshot() {
    cfr_snap=$CFR_STAGE/snapshot.$1
    : > "$cfr_snap" || return 1
    # Pipelines hide producer failures; empty iptables output also refuses.
    for cfr_kind in iptables ip6tables ipset uci cron; do
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
    cfr_dir_record "$CFR_INSTALL_LOCK" >> "$cfr_snap" || return 1
    cfr_dir_record "$CFR_PLATFORM_LOCK" >> "$cfr_snap" || return 1
    printf 'G %s/%s* %s\n' "$CFR_STAGE_PARENT" "$CFR_STAGE_PREFIX" "$(cfr_glob_count "$CFR_STAGE_PARENT" "$CFR_STAGE_PREFIX")" >> "$cfr_snap"
}

cfr_verify() {
    # status exits nonzero when unhealthy; the JSON body is the gate.
    cfr_run_sh "$CFR_CFCTL" status --json > "$CFR_STAGE/status.json" || :
    cfr_status=$(awk 'NR==1{print}END{exit NR!=1}' "$CFR_STAGE/status.json") || { cfr_fail VERIFY status_output_shape; return 0; }
    printf 'INFO status %s\n' "$cfr_status"
    for cfr_need in '"ok":true' '"drift":false' '"errors":[]' '"desiredRevision":0' '"desiredPauses":[]' '"effectivePauses":[]' '"observed":{"kids":[],"paused":[]}'; do
        case "$cfr_status" in *"$cfr_need"*) ;; *) cfr_fail VERIFY "status_missing $cfr_need"; return 0;; esac
    done
    cfr_ok VERIFY
}

cfr_restore() {
    cfr_snapshot after || { cfr_fail RESTORE snapshot_failed; return 0; }
    if cmp -s "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"; then cfr_ok RESTORE; return 0; fi
    awk 'NR==FNR{before[$1 " " $2]=$0;order[++n]=$1 " " $2;next}
        {after[$1 " " $2]=$0; if(!($1 " " $2 in before))order[++n]=$1 " " $2}
        END{for(i=1;i<=n;i++){k=order[i]; if(before[k]!=after[k]){print "DIFF - " (k in before?before[k]:k " missing"); print "DIFF + " (k in after?after[k]:k " missing")}}}' \
        "$CFR_STAGE/snapshot.before" "$CFR_STAGE/snapshot.after"
    for cfr_kind in iptables ip6tables ipset uci cron; do
        cmp -s "$CFR_STAGE/text.before.$cfr_kind" "$CFR_STAGE/text.after.$cfr_kind" && continue
        awk -v kind="$cfr_kind" 'NR==FNR{b[$0]++;next}{a[$0]++;if(a[$0]>b[$0]&&shown<40){print "DIFF " kind " + " $0;shown++}}' \
            "$CFR_STAGE/text.before.$cfr_kind" "$CFR_STAGE/text.after.$cfr_kind"
        awk -v kind="$cfr_kind" 'NR==FNR{a[$0]++;next}{b[$0]++;if(b[$0]>a[$0]&&shown<40){print "DIFF " kind " - " $0;shown++}}' \
            "$CFR_STAGE/text.after.$cfr_kind" "$CFR_STAGE/text.before.$cfr_kind"
    done
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
    printf 'BEGIN first-rehearsal commit=%s release=%s profile=%s\n' "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE"
    for cfr_value in "$CFR_SOURCE_COMMIT" "$CFR_RELEASE_ID" "$CFR_PROFILE" "$CFR_MGMT_IP" "$CFR_MGMT_MAC" "$CFR_JD_IP" "$CFR_JD_MAC" "$CFR_PENN_IP" "$CFR_PENN_MAC" "$CFR_HISTORICAL_MACS"; do
        [ -n "$cfr_value" ] || cfr_refuse PAYLOAD parameters_missing
    done
    cfr_setup_paths || cfr_refuse PAYLOAD unsafe_environment
    [ "$(id -u)" = 0 ] || [ "$CFR_FIXTURE" = 1 ] || cfr_refuse PAYLOAD root_required
    trap cfr_cleanup 0
    trap 'exit 20' HUP INT TERM PIPE
    cfr_extract
    cfr_identity
    cfr_prereq
    cfr_snapshot before || cfr_refuse SNAPSHOT snapshot_failed
    cfr_ok SNAPSHOT
    printf '%s\n' MUTATION_BEGIN
    cfr_install --activate || cfr_stop INSTALL "installer_exit_nonzero; journal retained; uninstall not attempted"
    cfr_ok INSTALL
    cfr_verify
    if [ "$CFR_FIXTURE" = 1 ]; then cfr_uninstall=$CFR_STAGE/router/uninstall.sh
    else cfr_uninstall=$CFR_RELEASE_DIR/uninstall.sh; fi
    cfr_info "run uninstall.sh once: $cfr_uninstall"
    cfr_run_sh "$cfr_uninstall" >&2 || cfr_stop UNINSTALL "uninstall_refused_or_failed; journal preserved; resolve explicitly"
    cfr_ok UNINSTALL
    cfr_restore
    cfr_connectivity
    [ "$CFR_FAILED" = 0 ] || { printf 'FAIL_AFTER_MUTATION %s\n' summary; exit 20; }
    printf '%s\n' FIRST_REHEARSAL_PASS
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
