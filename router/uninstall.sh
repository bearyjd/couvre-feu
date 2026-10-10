#!/bin/sh
# Restore exact original files only after a complete drift preflight.
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$HERE/lib/install-common.sh"
[ "$#" = 0 ] || fail 'usage: uninstall.sh'
safe_paths
# Final cleanup has its own private completion record: removing the journal
# can be interrupted without losing the fact that every restoration succeeded.
finish_cleanup() {
    valid_marker "$DONE" || fail 'unsafe recovery completion record'
    if [ -e "$BACKUP" ]; then
        journal_preflight cleanup
        for entry in "$BACKUP"/* "$BACKUP"/.[!.]* "$BACKUP"/..?*; do
            [ -e "$entry" ] || continue
            rm -f "$entry"
        done
        rmdir "$BACKUP" || fail 'recovery cleanup incomplete; completion record retained'
    fi
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
# Persist successful kernel removal before touching helpers or executables.
# Retries never invoke an installed program that has already been restored.
if [ ! -f "$BACKUP/kernel-cleaned" ]; then
    if [ -f "$BACKUP/activated" ] && live_tools; then
        cleanup_result=$(installed_core remove-fw) || fail 'kernel cleanup failed; original files retained'
        # Only the trusted core's exact explicit proof can suppress the reload.
        # Activation failure alone may leave partially mutated kernel objects.
        if [ "$cleanup_result" = '{"ok":true,"removed":true,"zeroOwnedMutations":true,"errors":[]}' ];then
            phase no-kernel-mutations
        fi
    fi
    runtime_preflight
    phase kernel-cleaned
fi
if [ "$BACKUP" != "$RECOVERY" ]; then
    phase restoring
    [ ! -e "$RECOVERY" ] && [ ! -L "$RECOVERY" ] || fail 'recovery path collision'
    mv "$BACKUP" "$RECOVERY"
    BACKUP=$RECOVERY
fi
# Recovery is outside managed directories; even an originally absent BASE can
# be removed while all original bytes and directory records remain available.
if [ ! -f "$BACKUP/restored" ]; then
    runtime_preflight
    if [ -d "$BASE/runtime" ]; then
        for p in "$BASE/runtime"/* "$BASE/runtime"/.[!.]* "$BASE/runtime"/..?*; do
            [ -e "$p" ] || continue
            if [ -d "$p" ]; then
                if [ -d "$p/.delta" ]; then rm -f "$p/.delta/firewall"; rmdir "$p/.delta"; fi
                rm -f "$p/firewall"; rmdir "$p"
            else rm -f "$p"; fi
        done
        rmdir "$BASE/runtime"
    fi
    COUNT=0
    for rel in $FILES; do
        k=$(key "$rel")
        before=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.before")
        if [ "$(signature "$ROOT/$rel")" != "$before" ]; then
            if [ "$before" = absent ]; then rm -f "$ROOT/$rel"
            else atomic_copy "$BACKUP/$k.original" "$ROOT/$rel"; fi
        fi
        # Validated abandoned install rename sources are installation owned.
        if [ -e "$ROOT/$rel.couvrefeu-tmp" ]; then rm -f "$ROOT/$rel.couvrefeu-tmp"; fi
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
                rmdir "$ROOT/$rel" || fail "directory restoration incomplete: $rel; journal retained"
            fi
        else chmod "$mode" "$ROOT/$rel"; fi
    done
    phase restored
fi
mv "$BACKUP/restored" "$DONE"
finish_cleanup
printf '%s\n' 'Original files restored; Couvre-feu installation removed.'
