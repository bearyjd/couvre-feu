#!/bin/sh
# shellcheck disable=SC2034,SC1090,SC1091
# Restore exact original files only after a complete drift preflight.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# BEGIN authenticated bootstrap boundary
if [ "${CF_TEST_MODE:-0}" != 1 ]; then PATH=/usr/sbin:/usr/bin:/sbin:/bin; fi
LC_ALL=C
export PATH LC_ALL
umask 077
if [ -n "${LD_PRELOAD-}${LD_LIBRARY_PATH-}${LD_AUDIT-}" ] || [ "${CF_PLATFORM_ADMITTED+x}${CF_PLATFORM_LOCKED+x}${CF_PLATFORM_NESTED+x}${CF_RELEASE_ID+x}${CF_PLATFORM_PROFILE+x}${CF_PLATFORM_CALLER_PID+x}${CF_PLATFORM_OWNER+x}${CF_PLATFORM_LIB+x}${CF_VENDOR_PROFILE+x}${CF_OS_TRUST_PROFILE+x}${CF_PLATFORM_ENTRY_TICK+x}${CF_PLATFORM_INITIAL_WRITE+x}${CF_RELEASE_MODULES+x}${vp_profile+x}" != "" ]; then
    printf '%s\n' 'couvre-feu: injected platform environment refused' >&2
    exit 2
fi
unset CF_PLATFORM_ADMITTED CF_PLATFORM_LOCKED CF_PLATFORM_NESTED CF_RELEASE_ID CF_PLATFORM_PROFILE CF_VENDOR_PROFILE CF_OS_TRUST_PROFILE CF_PLATFORM_ENTRY_TICK CF_PLATFORM_INITIAL_WRITE CF_RELEASE_MODULES CF_PLATFORM_CALLER_PID CF_PLATFORM_OWNER CF_PLATFORM_LIB vp_profile
# Capture once before bootstrap; invalid clocks refuse only the OS-trust profile.
cf_capture_entry_tick() {
    IFS=' ' read -r cf_entry_uptime cf_entry_unused < /proc/uptime || return 2
    cf_entry_seconds=${cf_entry_uptime%.*}; cf_entry_fraction=${cf_entry_uptime#*.}
    case "$cf_entry_seconds:$cf_entry_fraction" in *[!0-9:]*|:*) return 2;; esac
    [ "${#cf_entry_seconds}" -le 10 ] && [ "${#cf_entry_fraction}" = 2 ] || return 2
    case "$cf_entry_seconds" in 0|[1-9]*) ;; *) return 2;; esac
    cf_entry_fraction=${cf_entry_fraction#0}; cf_entry_fraction=${cf_entry_fraction:-0}
    printf '%s\n' "$((cf_entry_seconds * 100 + cf_entry_fraction))"
}
CF_PLATFORM_ENTRY_TICK=$(cf_capture_entry_tick) || CF_PLATFORM_ENTRY_TICK=
CF_BOOTSTRAP_PIN=3da44fa95080f595a1a2b0c67f3a378fae63add5a072621080c701041caedc20
platform_bootstrap_path=$HERE/lib/platform-bootstrap.sh
[ -f "$platform_bootstrap_path" ] && [ ! -L "$platform_bootstrap_path" ] && [ "$(CDPATH='' cd -- "${platform_bootstrap_path%/*}" && pwd -P)" = "${platform_bootstrap_path%/*}" ] || exit 2
platform_bootstrap_digest=$(timeout -s KILL 6 sha256sum "$platform_bootstrap_path") || exit 2
[ "${platform_bootstrap_digest%% *}" = "$CF_BOOTSTRAP_PIN" ] || exit 2
# shellcheck disable=SC1091
. "$platform_bootstrap_path"
platform_deadline_check
# END authenticated bootstrap boundary
platform_entry_root_validate
platform_admit runtime "${CF_ROOT:-}" "$HERE/lib"
[ "${CF_TEST_MODE:-0}" = 1 ] || platform_external_closure "$HERE"
[ "${CF_TEST_MODE:-0}" = 1 ] || [ "$HERE" = "/etc/.couvrefeu-release-$CF_RELEASE_ID" ] || platform_fail external_recovery_release_required
# shellcheck disable=SC1091
. "$HERE/lib/install-common.sh"
platform_deadline_check
[ "$#" = 0 ] || fail 'usage: uninstall.sh'
safe_paths
# Final cleanup has its own private completion record: removing the journal
# can be interrupted without losing the fact that every restoration succeeded.
finish_cleanup() {
    CLEANUP_COUNT=0
    platform_valid_done "$DONE" || fail 'unsafe/legacy recovery completion record; preserved'
    if [ -e "$BACKUP" ]; then
        journal_preflight cleanup
        platform_initial_write
        for entry in "$BACKUP"/* "$BACKUP"/.[!.]* "$BACKUP"/..?*; do
            [ -e "$entry" ] || continue
            rm -f "$entry"
            CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
            if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CLEANUP_FAIL_AFTER:-0}" = "$CLEANUP_COUNT" ]; then fail 'injected cleanup interruption'; fi
        done
        rmdir "$BACKUP" || fail 'recovery cleanup incomplete; completion record retained'
    fi
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CLEANUP_FAIL_AT:-}" = journal ]; then fail 'injected after journal removal'; fi
    unlock_install
    platform_lock_release
    trap - 0 1 2 15
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CLEANUP_FAIL_AT:-}" = 'done' ]; then fail 'injected before DONE removal'; fi
    # Last filesystem operation: the binding survives journal and lock cleanup.
    platform_initial_write
    rm -f "$DONE"
}
if [ -e "$DONE" ]; then
    finish_cleanup
    printf '%s\n' 'Original files restored; Couvre-feu installation removed.'
    exit 0
fi
if [ ! -e "$BACKUP" ]; then
    printf '%s\n' 'No recorded installation; no changes made.'
    exit 0
fi
preflight
runtime_preflight
platform_deadline_check
# Persist successful kernel removal before touching helpers or executables.
# Retries never invoke an installed program that has already been restored.
if [ ! -f "$BACKUP/kernel-cleaned" ]; then
    if [ -f "$BACKUP/activated" ] && live_tools; then
        platform_deadline_check
        cleanup_result=$(installed_core remove-fw) || fail 'kernel cleanup failed; original files retained'
        # The kernel proof and protected filesystem/write-attempt receipt are
        # separate. A successful readonly empty proof cannot waive expiry.
        if [ "$CF_PLATFORM_PROFILE" = "$CF_OS_TRUST_PROFILE" ]; then
            platform_cleanup_receipt "$cleanup_result"
        elif [ "$cleanup_result" = '{"ok":true,"removed":true,"zeroOwnedMutations":true,"errors":[]}' ]; then
            platform_cleanup_zero=1
        else platform_cleanup_zero=0; fi
        if [ "$platform_cleanup_zero" = 1 ]; then phase no-kernel-mutations; fi
    fi
    runtime_preflight
    phase kernel-cleaned
fi
if [ "$BACKUP" != "$RECOVERY" ]; then
    phase restoring
    if ! { [ ! -e "$RECOVERY" ] && [ ! -L "$RECOVERY" ]; }; then
        fail 'recovery path collision'
    fi
    mv "$BACKUP" "$RECOVERY"
    BACKUP=$RECOVERY
fi
# Recovery is outside managed directories; even an originally absent BASE can
# be removed while all original bytes and directory records remain available.
if [ ! -f "$BACKUP/restored" ]; then
    runtime_preflight
    platform_deadline_check
    if [ -d "$BASE/runtime" ]; then
        for p in "$BASE/runtime"/* "$BASE/runtime"/.[!.]* "$BASE/runtime"/..?*; do
            [ -e "$p" ] || continue
            if [ -d "$p" ]; then
                if [ -d "$p/.delta" ]; then platform_initial_write; rm -f "$p/.delta/firewall"; rmdir "$p/.delta"; fi
                platform_initial_write
                rm -f "$p/firewall"; rmdir "$p"
            else platform_initial_write; rm -f "$p"; fi
        done
        platform_initial_write
        rmdir "$BASE/runtime"
    fi
    COUNT=0
    for rel in $FILES; do
        k=$(key "$rel")
        before=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.before")
        original_mtime=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.mtime")
        if [ "$(signature "$ROOT/$rel")" != "$before" ] || ! exact_mtime "$ROOT/$rel" "$original_mtime"; then
            if [ "$before" = absent ]; then platform_initial_write; rm -f "$ROOT/$rel"
            else
                atomic_copy "$BACKUP/$k.original" "$ROOT/$rel" "$original_mtime"
                # Successful atomic_copy always attempted a protected write.
                CF_PLATFORM_INITIAL_WRITE=1
            fi
        fi
        # Validated abandoned install rename sources are installation owned.
        if [ -e "$ROOT/$rel.couvrefeu-tmp" ]; then platform_initial_write; rm -f "$ROOT/$rel.couvrefeu-tmp"; fi
        COUNT=$((COUNT + 1))
        if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_FAIL_AFTER:-0}" = "$COUNT" ]; then fail 'injected partial restoration'; fi
    done
    if [ -f "$BACKUP/activated" ] && [ ! -f "$BACKUP/no-kernel-mutations" ] && live_tools; then
        reload_firewall || fail 'firewall reload failed; originals restored, backup retained'
    fi
    for rel in etc/couvrefeu etc/crontabs etc/config usr/lib/couvrefeu usr/lib usr/sbin usr etc; do
        k=$(key "$rel")
        mode=$(awk 'NR==1 {print; exit}' "$BACKUP/dir_$k")
        if [ "$mode" = absent ]; then
            if [ -d "$ROOT/$rel" ]; then
                platform_initial_write
                rmdir "$ROOT/$rel" || fail "directory restoration incomplete: $rel; journal retained"
            fi
        else platform_initial_write; chmod "$mode" "$ROOT/$rel"; fi
    done
fi
# Do not retire the journal on a copy tool success alone. Every original
# must still match exact bytes, mode, owner/group, timestamp or absence.
for rel in $FILES; do
    k=$(key "$rel")
    before=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.before")
    original_mtime=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.mtime")
    if ! { [ "$(signature "$ROOT/$rel")" = "$before" ] && exact_mtime "$ROOT/$rel" "$original_mtime"; }; then
        fail "exact restoration incomplete: $rel; journal retained"
    fi
done
[ -f "$BACKUP/restored" ] || phase restored 2
if [ -f "$BACKUP/etc_couvrefeu_platform-profile.after" ]; then
    platform_publish_done
else
    [ "$CF_PLATFORM_PROFILE" = strict ] || fail 'vendor legacy completion refused'
    mv "$BACKUP/restored" "$DONE"
fi
finish_cleanup
printf '%s\n' 'Original files restored; Couvre-feu installation removed.'
