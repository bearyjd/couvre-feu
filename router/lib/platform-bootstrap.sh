# shellcheck shell=sh
# shellcheck disable=SC2034,SC1090,SC1091,SC2329
# A transaction-local admission boundary. Never source from an unverified entry.
# Release entry hashes are authenticated by the reviewed external release, not
# recursively by the entry itself. The manifest preserves that outer closure.
CF_PLATFORM_PROFILE=strict
CF_PLATFORM_ADMITTED=0
CF_PLATFORM_LOCKED=0
CF_PLATFORM_NESTED=0
CF_PLATFORM_OWNER=0:0
CF_PLATFORM_LIB=
CF_RELEASE_ID=a802214ea5a7e6335b8f78056b10734d1226e4735564555617df243ba19a2ab6
CF_VENDOR_PROFILE=gl-xe3000-4.8.3-logd-011-v1
CF_OS_TRUST_PROFILE=gl-xe3000-4.8.3-os-trust-v1
CF_PLATFORM_INITIAL_WRITE=0
CF_RELEASE_MODULES='core.sh:c2aa5b03ddb3b57569291d72358dab358cf8978f8ed149ba464509f9d87c9f34 rpc.sh:d9a4897277865d1dff29f36167b830ac24c34c6d2b27f51ff39b6b64acbac74e firewall.sh:8dfe686a481a824a08395c3a60c362d5400b74f78c846c57d0204cd332fa78ad install-common.sh:273e17fde3342f342fe27d0709b16a02e7279b28104137236c0ea1f52bc24ee2 state.awk:3326364e1827d767c9b7b291e66668fef456a705ea79bd25f2e9fe82b15b7755 rules.awk:523595998750193b4cc2bc8b1d407a45fae95738d8a47a356afd16025a268954 json.awk:ae3a0773339230ebff7349e9bafc6ff02d42aa7cf162b6377ff33638186d03fc vendor-platform.sh:e093670bf47f6a9da749a73aef17a564c7e910e9b9acf5376bb331b56593b43b activity.sh:22d78f6a78174dcfc7ca040cd1dc3cda5d516f5dbdbdbc15cad655773cbb6566'

platform_fail() {
    printf 'couvre-feu: platform %s\n' "$*" >&2
    case "$0" in */cfctl) printf '%s\n' '{"ok":false,"errors":["platform_admission_refused"]}';; esac
    exit 2
}
platform_vendor_selected() {
    case "$CF_PLATFORM_PROFILE" in "$CF_VENDOR_PROFILE"|"$CF_OS_TRUST_PROFILE") return 0;; *) return 1;; esac
}
platform_clock_tick() {
    # /proc/uptime has two decimal places; centiseconds avoid rounded budgets.
    IFS=' ' read -r platform_uptime platform_unused < /proc/uptime || platform_fail admission_clock_read
    platform_seconds=${platform_uptime%.*}; platform_fraction=${platform_uptime#*.}
    case "$platform_seconds:$platform_fraction" in *[!0-9:]*|:*) platform_fail admission_clock_format;; esac
    [ "${#platform_seconds}" -le 10 ] && [ "${#platform_fraction}" = 2 ] || platform_fail admission_clock_format
    case "$platform_seconds" in 0|[1-9]*) ;; *) platform_fail admission_clock_format;; esac
    platform_fraction=${platform_fraction#0}; platform_fraction=${platform_fraction:-0}
    printf '%s\n' "$((platform_seconds * 100 + platform_fraction))"
}
platform_deadline_check() {
    [ "$CF_PLATFORM_PROFILE" = "$CF_OS_TRUST_PROFILE" ] || return 0
    [ "${CF_PLATFORM_INITIAL_WRITE:-0}" != 1 ] || return 0
    case "${CF_PLATFORM_ENTRY_TICK:-}" in ''|*[!0-9]*) platform_fail admission_clock_anchor;; esac
    platform_now=$(platform_clock_tick) || platform_fail admission_clock_read
    [ "$platform_now" -ge "$CF_PLATFORM_ENTRY_TICK" ] && [ "$((platform_now-CF_PLATFORM_ENTRY_TICK))" -lt 1300 ] || platform_fail admission_deadline
}
platform_initial_write() {
    # Logical cutoff only: no hard syscall, scheduler-gap or drain guarantee.
    # After the first protected write, existing journal/recovery semantics own
    # interruption; never introduce an arbitrary mid-restoration deadline.
    platform_deadline_check
    CF_PLATFORM_INITIAL_WRITE=1
}
platform_cleanup_receipt() {
    # Source closure and selected profile bind this internal child result.
    [ "$CF_PLATFORM_PROFILE" = "$CF_OS_TRUST_PROFILE" ] || platform_fail cleanup_receipt_profile
    platform_cleanup_zero=0
    case "$1" in
        '{"ok":true,"removed":true,"zeroOwnedMutations":true,"initialProtectedWrite":false,"errors":[]}')
            [ "$CF_PLATFORM_INITIAL_WRITE" = 0 ] || platform_fail cleanup_receipt_contradiction
            platform_cleanup_zero=1;;
        '{"ok":true,"removed":true,"zeroOwnedMutations":true,"initialProtectedWrite":true,"errors":[]}')
            CF_PLATFORM_INITIAL_WRITE=1;platform_cleanup_zero=1;;
        '{"ok":true,"removed":true,"zeroOwnedMutations":false,"initialProtectedWrite":true,"errors":[]}')
            CF_PLATFORM_INITIAL_WRITE=1;;
        *) platform_fail cleanup_receipt_shape;;
    esac
}
platform_entry_root_validate() {
    case "${CF_TEST_MODE:-0}" in
        0)
            [ -z "${CF_ROOT:-}" ] || platform_fail fixture_root_without_test_mode
            [ "$(id -u):$(id -g)" = 0:0 ] || platform_fail production_requires_root_group
            CF_PLATFORM_OWNER=0:0;;
        1)
            case "${CF_ROOT:-}" in /tmp/couvre-feu-*) ;; *) platform_fail isolated_fixture_root_required;; esac
            [ -d "$CF_ROOT" ] && [ ! -L "$CF_ROOT" ] && [ "$(CDPATH='' cd -- "$CF_ROOT" && pwd -P)" = "$CF_ROOT" ] || platform_fail fixture_root_canonical
            CF_PLATFORM_OWNER=$(id -u):$(id -g);;
        *) platform_fail unknown_test_mode;;
    esac
}
platform_regular() { [ -f "$1" ] && [ ! -L "$1" ] || platform_fail regular_file; }
platform_canonical() {
    [ "$(CDPATH='' cd -- "${1%/*}" && pwd -P)" = "${1%/*}" ] || platform_fail canonical_path
}
platform_hash() {
    platform_regular "$1"
    platform_hash_result=$(timeout -s KILL 6 sha256sum "$1") || platform_fail hash_read
    [ "${platform_hash_result%% *}" = "$2" ] || platform_fail hash_mismatch
    platform_deadline_check
}
platform_stat() { command stat "$@"; }
platform_private() {
    [ ! -L "$1" ] || platform_fail private_symlink
    platform_canonical "$1"
    [ "$(platform_stat -c '%u:%g:%a' "$1")" = "$CF_PLATFORM_OWNER:$2" ] || platform_fail private_metadata
    platform_deadline_check
}
platform_read_profile() {
    platform_regular "$1"
    # A marker preserves every trailing LF in the bounded read. Do not run wc
    # over provisional files: newline/NUL tails may otherwise be unbounded.
    platform_read_value=$(timeout -s KILL 4 dd if="$1" bs=1 count=65 2>/dev/null && printf '.') || platform_fail profile_read
    if [ "$platform_read_value" = "$(printf 'strict\n.')" ]; then platform_read_value=strict
    elif [ "$platform_read_value" = "$(printf 'gl-xe3000-4.8.3-logd-011-v1\n.')" ]; then platform_read_value=gl-xe3000-4.8.3-logd-011-v1
    elif [ "$platform_read_value" = "$(printf 'gl-xe3000-4.8.3-os-trust-v1\n.')" ]; then platform_read_value=gl-xe3000-4.8.3-os-trust-v1
    else platform_fail unknown_profile; fi
    # Exact bytes also reject NULs dropped by shell command substitution.
    printf '%s\n' "$platform_read_value" | timeout -s KILL 4 cmp -s - "$1" || platform_fail profile_bytes
    printf '%s\n' "$platform_read_value"
}
platform_done_legacy() {
    platform_regular "$1"
    printf '2\n' | timeout -s KILL 4 cmp -s - "$1"
}
platform_done_profile() {
    platform_regular "$1"
    platform_done_value=$(timeout -s KILL 4 dd if="$1" bs=1 count=161 2>/dev/null && printf '.') || platform_fail completion_read
    if [ "$platform_done_value" = "$(printf '2\n.')" ]; then
        platform_done_legacy "$1" || platform_fail completion_bytes
        printf 'strict\n'
        return 0
    fi
    for platform_completion_profile in strict gl-xe3000-4.8.3-logd-011-v1 gl-xe3000-4.8.3-os-trust-v1; do
        if [ "$platform_done_value" = "$(printf '3\n%s\n%s\n.' "$platform_completion_profile" "$CF_RELEASE_ID")" ]; then
            printf '3\n%s\n%s\n' "$platform_completion_profile" "$CF_RELEASE_ID" | timeout -s KILL 4 cmp -s - "$1" || platform_fail completion_bytes
            printf '%s\n' "$platform_completion_profile"
            return 0
        fi
    done
    platform_fail completion_binding
}
platform_choose() {
    # Reads here are provisional only. Metadata, journal signatures and agreement
    # are checked after admission, before any private policy or mutation.
    platform_selection=$1
    platform_root=$2
    platform_stage_profile=
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then platform_recovery=$platform_root/.couvrefeu-recovery
    else platform_recovery=$platform_root/etc/.couvrefeu-recovery; fi
    platform_done=$platform_recovery.done
    platform_installed=$platform_root/etc/couvrefeu/platform-profile
    for platform_journal in "$platform_root/etc/couvrefeu/backup" "$platform_recovery"; do
        if [ -e "$platform_journal/etc_couvrefeu_platform-profile.staged" ] || [ -L "$platform_journal/etc_couvrefeu_platform-profile.staged" ]; then
            [ -z "$platform_stage_profile" ] || platform_fail ambiguous_journals
            platform_stage_profile=$(platform_read_profile "$platform_journal/etc_couvrefeu_platform-profile.staged") || exit 2
        fi
    done
    if [ -e "$platform_done" ] || [ -L "$platform_done" ]; then
        platform_completion=$(platform_done_profile "$platform_done") || exit 2
        [ -z "$platform_stage_profile" ] || [ "$platform_stage_profile" = "$platform_completion" ] || platform_fail conflicting_completion
        platform_stage_profile=$platform_completion
    fi
    if [ -e "$platform_installed" ] || [ -L "$platform_installed" ]; then
        platform_disk_profile=$(platform_read_profile "$platform_installed") || exit 2
        [ -z "$platform_stage_profile" ] || [ "$platform_disk_profile" = "$platform_stage_profile" ] || platform_fail conflicting_profile
    else platform_disk_profile=; fi
    if [ "$platform_selection" = runtime ]; then
        CF_PLATFORM_PROFILE=${platform_stage_profile:-${platform_disk_profile:-strict}}
    else
        case "$platform_selection" in strict|gl-xe3000-4.8.3-logd-011-v1|gl-xe3000-4.8.3-os-trust-v1) ;; *) platform_fail unknown_profile;; esac
        CF_PLATFORM_PROFILE=$platform_selection
        [ -z "$platform_stage_profile" ] || [ "$platform_stage_profile" = "$CF_PLATFORM_PROFILE" ] || platform_fail changed_profile
        [ -z "$platform_disk_profile" ] || [ "$platform_disk_profile" = "$CF_PLATFORM_PROFILE" ] || platform_fail changed_profile
    fi
    platform_deadline_check
}
platform_bootstrap_vendor() {
    for platform_parent in / /lib /usr /usr/libexec /bin; do
        [ -d "$platform_parent" ] && [ ! -L "$platform_parent" ] || platform_fail bootstrap_parent
        platform_canonical "$platform_parent/."
    done
    [ -L /lib/ld-musl-aarch64.so.1 ] && [ "$(readlink /lib/ld-musl-aarch64.so.1)" = libc.so ] || platform_fail loader_link
    platform_hash /lib/libc.so c7ad6aff9300a5810e33ed8099057ef4515c0e711e9570309161d4014a5768ce
    platform_hash /lib/libgcc_s.so.1 6baf0c0086b0bd2915019e942a2fa7b2b4dfb4e0935db43a71fc54add13d1a69
    platform_hash /usr/libexec/stat-coreutils 774eaa80136871de03ea7c94ef713aac209cea00eddb8e7d07c7036e511499a0
    [ -L /bin/stat ] && [ "$(readlink /bin/stat)" = /usr/libexec/stat-coreutils ] || platform_fail stat_alternative
    platform_stat() {
        if [ "$CF_PLATFORM_PROFILE" = "$CF_OS_TRUST_PROFILE" ]; then
            platform_stat_result=$(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LD_LIBRARY_PATH=/lib timeout -s KILL 4 /usr/libexec/stat-coreutils "$@") || platform_fail stat_read
            platform_deadline_check
            printf '%s\n' "$platform_stat_result"
        else env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LD_LIBRARY_PATH=/lib timeout -s KILL 4 /usr/libexec/stat-coreutils "$@"; fi
    }
    [ "$(platform_stat -c '%u:%g:%a' /usr/libexec/stat-coreutils)" = 0:0:755 ] || platform_fail stat_metadata
    for platform_parent in / /lib /usr /bin; do
        [ "$(platform_stat -c '%u:%g:%a' "$platform_parent")" = 0:0:755 ] || platform_fail bootstrap_metadata
    done
    case $(platform_stat -c '%u:%g:%a' /usr/libexec) in 0:0:755|0:0:775) ;; *) platform_fail bootstrap_metadata;; esac
    # All later numeric metadata reads use this exact payload in a clean env.
    stat() { platform_stat "$@"; }
}
platform_verify_modules() {
    platform_lib=$1
    [ -d "$platform_lib" ] && [ ! -L "$platform_lib" ] || platform_fail source_directory
    platform_canonical "$platform_lib/."
    # Deliberate bounded splitting of compiled literals; no environment input.
    for platform_pair in $CF_RELEASE_MODULES; do
        platform_name=${platform_pair%%:*}; platform_pin=${platform_pair#*:}
        platform_hash "$platform_lib/$platform_name" "$platform_pin"
        [ "$(platform_stat -c '%u:%g:%a' "$platform_lib/$platform_name")" = "$CF_PLATFORM_OWNER:644" ] || platform_fail source_metadata
    done
}
platform_external_closure() {
    platform_release=$1
    platform_private "$platform_release" 700
    platform_private "$platform_release/lib" 700
    platform_verify_modules "$platform_release/lib"
    platform_private "$platform_release/release.sha256" 600
    # Outer reviewed manifest has exactly these direct files, no path escapes.
    awk 'NF!=2||length($1)!=64||$1~/[^0-9a-f]/||$2!~/^(install.sh|uninstall.sh|cfctl|cfctl-ssh|cfctl-scope|lib\/(platform-bootstrap.sh|vendor-platform.sh|install-common.sh|core.sh|rpc.sh|firewall.sh|state.awk|rules.awk|json.awk|activity.sh))$/||seen[$2]++ {bad=1}END{exit bad||NR!=15}' "$platform_release/release.sha256" || platform_fail release_manifest
    while read -r platform_digest platform_file; do
        platform_hash "$platform_release/$platform_file" "$platform_digest"
        case "$platform_file" in lib/*) platform_mode=644;; *) platform_mode=755;; esac
        [ "$(platform_stat -c '%u:%g:%a' "$platform_release/$platform_file")" = "$CF_PLATFORM_OWNER:$platform_mode" ] || platform_fail release_metadata
    done < "$platform_release/release.sha256"
}
platform_lock_release() {
    if [ "$CF_PLATFORM_LOCKED" = 1 ]; then
        platform_cleanup_saved=$CF_PLATFORM_INITIAL_WRITE
        CF_PLATFORM_INITIAL_WRITE=1
        platform_private "$CF_PLATFORM_LOCK" 700
        platform_private "$CF_PLATFORM_LOCK/pid" 600
        printf '%s\n' "$$" | cmp -s - "$CF_PLATFORM_LOCK/pid" || platform_fail lock_owner_changed
        rm -f "$CF_PLATFORM_LOCK/pid" || platform_fail lock_cleanup
        rmdir "$CF_PLATFORM_LOCK" || platform_fail lock_cleanup
        CF_PLATFORM_LOCKED=0
        CF_PLATFORM_INITIAL_WRITE=$platform_cleanup_saved
    fi
}
platform_lock_acquire() {
    [ -d /tmp ] && [ ! -L /tmp ] && [ "$(platform_stat -c '%u:%g:%a' /tmp)" = 0:0:1777 ] || platform_fail tmp_metadata
    CF_PLATFORM_LOCK=/tmp/couvrefeu-platform.lock
    mkdir -m 700 "$CF_PLATFORM_LOCK" 2>/dev/null || platform_fail transaction_contention
    CF_PLATFORM_LOCKED=1
    trap 'platform_lock_release' 0
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    (set -C; printf '%s\n' "$$" > "$CF_PLATFORM_LOCK/pid") || platform_fail lock_record
    platform_private "$CF_PLATFORM_LOCK" 700
    platform_private "$CF_PLATFORM_LOCK/pid" 600
}
platform_lock_recover() {
    # Explicit operation only; a partial/foreign record is never stolen.
    CF_PLATFORM_LOCK=/tmp/couvrefeu-platform.lock
    [ -d /tmp ] && [ ! -L /tmp ] && [ "$(platform_stat -c '%u:%g:%a' /tmp)" = 0:0:1777 ] || platform_fail tmp_metadata
    platform_private "$CF_PLATFORM_LOCK" 700
    platform_private "$CF_PLATFORM_LOCK/pid" 600
    platform_dead_pid=$(awk 'NR==1&&$0~/^[0-9]+$/{p=$0;next}{bad=1}END{if(bad||NR!=1||p<=1)exit 2;print p}' "$CF_PLATFORM_LOCK/pid") || platform_fail lock_owner
    ! kill -0 "$platform_dead_pid" 2>/dev/null && [ ! -e "/proc/$platform_dead_pid" ] || platform_fail live_lock
    for platform_record in "$CF_PLATFORM_LOCK"/* "$CF_PLATFORM_LOCK"/.[!.]* "$CF_PLATFORM_LOCK"/..?*; do
        [ -e "$platform_record" ] || [ -L "$platform_record" ] || continue
        [ "$platform_record" = "$CF_PLATFORM_LOCK/pid" ] || platform_fail ambiguous_lock
    done
    platform_initial_write
    rm -f "$CF_PLATFORM_LOCK/pid"
    rmdir "$CF_PLATFORM_LOCK" || platform_fail lock_cleanup
}
platform_profile_validate() {
    platform_cleanup_binding=0
    if [ -e "$platform_done" ] && ! platform_done_legacy "$platform_done"; then
        platform_private "$platform_done" 600
        [ "$(platform_done_profile "$platform_done")" = "$CF_PLATFORM_PROFILE" ] || platform_fail conflicting_completion
        printf '3\n%s\n%s\n' "$CF_PLATFORM_PROFILE" "$CF_RELEASE_ID" | timeout -s KILL 4 cmp -s - "$platform_done" || platform_fail completion_bytes
        platform_cleanup_binding=1
    fi
    for platform_journal in "$platform_root/etc/couvrefeu/backup" "$platform_recovery"; do
        platform_stage=$platform_journal/etc_couvrefeu_platform-profile.staged
        if [ -e "$platform_stage" ] || [ -L "$platform_stage" ]; then
            platform_private "$platform_journal" 700
            platform_private "$platform_stage" 600
            if [ "$platform_cleanup_binding" = 0 ]; then
                platform_private "$platform_journal/etc_couvrefeu_platform-profile.after" 600
                platform_expected=$(sha256sum "$platform_stage" | awk '{print $1}')":600:$CF_PLATFORM_OWNER"
                printf '%s\n' "$platform_expected" | cmp -s - "$platform_journal/etc_couvrefeu_platform-profile.after" || platform_fail profile_journal
            fi
            [ "$(platform_read_profile "$platform_stage")" = "$CF_PLATFORM_PROFILE" ] || platform_fail changed_profile
        fi
    done
    if [ -e "$platform_installed" ] || [ -L "$platform_installed" ]; then
        platform_private "${platform_installed%/*}" 700
        platform_private "$platform_installed" 600
        [ "$(platform_read_profile "$platform_installed")" = "$CF_PLATFORM_PROFILE" ] || platform_fail changed_profile
        [ -n "$platform_stage_profile" ] || platform_fail profile_without_journal
    fi
    if [ -e "$platform_done" ] || [ -L "$platform_done" ]; then platform_private "$platform_done" 600; fi
}
platform_attest_vendor() {
        # Exact helper API adapters; helper bytes remain unchanged.
        regular() { platform_regular "$@"; }
        hash_is() { platform_hash "$@"; }
        stat_private() { platform_stat "$@"; }
        fail() { platform_fail "$@"; }
        vp_profile=$CF_PLATFORM_PROFILE
        . "$1/vendor-platform.sh"
        vp_transaction_check >/dev/null || platform_fail attestation
        platform_deadline_check
}
platform_admit() {
    platform_choose "$1" "$2"
    if platform_vendor_selected; then platform_bootstrap_vendor; fi
    platform_private "$3/platform-bootstrap.sh" 644
    if [ "${CF_TEST_MODE:-0}" != 1 ]; then platform_private "$3" 700; fi
    platform_verify_modules "$3"
    CF_PLATFORM_LIB=$3
    if platform_vendor_selected; then
        platform_lock_acquire
        platform_attest_vendor "$3" || platform_fail attestation
    fi
    CF_PLATFORM_ADMITTED=1
    platform_profile_validate
    platform_deadline_check
}

platform_recovery_prepare() {
    platform_source_release=$1
    # Optional isolated fixture root; production always uses /etc.
    platform_target_release=${2:-}/etc/.couvrefeu-release-$CF_RELEASE_ID
    if [ -e "$platform_target_release" ] || [ -L "$platform_target_release" ]; then
        platform_external_closure "$platform_target_release"
        cmp -s "$platform_source_release/release.sha256" "$platform_target_release/release.sha256" || platform_fail release_id_collision
        return 0
    fi
    # No overwrite or speculative cleanup after partial acquisition. Such a
    # collision retains its evidence and requires explicit recovery.
    platform_initial_write
    mkdir -m 700 "$platform_target_release" || platform_fail release_collision
    mkdir -m 700 "$platform_target_release/lib" || platform_fail release_directory
    while read -r platform_digest platform_file; do
        cp "$platform_source_release/$platform_file" "$platform_target_release/$platform_file" || platform_fail release_copy
        case "$platform_file" in lib/*) platform_mode=644;; *) platform_mode=755;; esac
        chmod "$platform_mode" "$platform_target_release/$platform_file" || platform_fail release_copy_metadata
    done < "$platform_source_release/release.sha256"
    cp "$platform_source_release/release.sha256" "$platform_target_release/release.sha256"
    chmod 600 "$platform_target_release/release.sha256"
    platform_external_closure "$platform_target_release"
}
platform_valid_done() {
    platform_private "$1" 600
    [ "$(platform_done_profile "$1")" = "$CF_PLATFORM_PROFILE" ] || return 1
    # The parser accepts only exact bounded DONE2 or bound DONE3 bytes.
}
platform_publish_done() {
    # Publishing a bounded cleanup binding is permitted only after all exact
    # restoration proofs and verification of the external immutable closure.
    if [ "${CF_TEST_MODE:-0}" != 1 ]; then platform_external_closure "$HERE"; fi
    [ ! -e "$DONE" ] && [ ! -L "$DONE" ] || platform_fail completion_collision
    if [ -e "$DONE.next" ] || [ -L "$DONE.next" ]; then
        platform_valid_done "$DONE.next" || platform_fail completion_publication_collision
    else
        platform_initial_write
        (set -C; printf '3\n%s\n%s\n' "$CF_PLATFORM_PROFILE" "$CF_RELEASE_ID" > "$DONE.next") || platform_fail completion_write
    fi
    platform_initial_write
    chmod 600 "$DONE.next"
    sync
    mv "$DONE.next" "$DONE" || platform_fail completion_publish
    sync
}
