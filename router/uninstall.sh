#!/bin/sh
# shellcheck disable=SC2034,SC1090,SC1091
# Restore exact original files only after a complete drift preflight.
set -eu
CF_ENTRY_SESSION_PID=
if [ "${1:-}" = --cf-transaction-session ]; then
    [ "$#" -ge 2 ] || exit 2
    CF_ENTRY_SESSION_PID=$2
    shift 2
fi
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# BEGIN authenticated bootstrap boundary
if [ "${CF_TEST_MODE:-0}" != 1 ]; then PATH=/usr/sbin:/usr/bin:/sbin:/bin; fi
LC_ALL=C
export PATH LC_ALL
umask 077
if [ -n "${LD_PRELOAD-}${LD_LIBRARY_PATH-}${LD_AUDIT-}" ] || [ "${CF_TRANSACTION_DEFINITIONS_ONLY+x}${CF_TRANSACTION_LAUNCH_PID+x}${CF_TRANSACTION_PID+x}${CF_TRANSACTION_START+x}${CF_TRANSACTION_BOOT+x}${CF_TRANSACTION_RETIREMENT+x}${CF_TRANSACTION_RECOVER+x}${CF_TRANSACTION_FENCE+x}${CF_TRANSACTION_PREPARED+x}${CF_TRANSACTION_BASE+x}${CF_TRANSACTION_HELD+x}${CF_TRANSACTION_OWNED+x}${CF_TRANSACTION_TOKEN+x}${CF_TRANSACTION_PARENT+x}${CF_TRANSACTION_MUTEX+x}${CF_TRANSACTION_OWNER+x}${CF_TRANSACTION_DIGEST+x}${CF_TRANSACTION_STATE+x}${CF_PLATFORM_ADMITTED+x}${CF_PLATFORM_LOCKED+x}${CF_PLATFORM_NESTED+x}${CF_RELEASE_ID+x}${CF_PLATFORM_PROFILE+x}${CF_PLATFORM_CALLER_PID+x}${CF_PLATFORM_OWNER+x}${CF_PLATFORM_LIB+x}${CF_VENDOR_PROFILE+x}${CF_OS_TRUST_PROFILE+x}${CF_PLATFORM_ENTRY_TICK+x}${CF_PLATFORM_INITIAL_WRITE+x}${CF_RELEASE_MODULES+x}${vp_profile+x}" != "" ]; then
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
CF_BOOTSTRAP_PIN=552a437c3ce190ec201f49a150f3dd17f124278cbdfa7197e7e4fc3883e36616
platform_bootstrap_path=$HERE/lib/platform-bootstrap.sh
[ -f "$platform_bootstrap_path" ] && [ ! -L "$platform_bootstrap_path" ] && [ "$(CDPATH='' cd -- "${platform_bootstrap_path%/*}" && pwd -P)" = "${platform_bootstrap_path%/*}" ] || exit 2
platform_bootstrap_digest=$(timeout -s KILL 6 sha256sum "$platform_bootstrap_path") || exit 2
[ "${platform_bootstrap_digest%% *}" = "$CF_BOOTSTRAP_PIN" ] || exit 2
# shellcheck disable=SC1091
. "$platform_bootstrap_path"
platform_deadline_check
# END authenticated bootstrap boundary
platform_entry_root_validate
platform_transaction_session "$@"
platform_admit runtime "${CF_ROOT:-}" "$HERE/lib"
[ "${CF_TEST_MODE:-0}" = 1 ] || platform_external_closure "$HERE"
# Any complete authenticated external release is usable after a partial install.
# shellcheck disable=SC1091
. "$HERE/lib/install-common.sh"
platform_deadline_check
[ "$#" = 0 ] || fail 'usage: uninstall.sh'
safe_paths
if [ "${CF_TEST_MODE:-0}" != 1 ] && [ "${CF_TRANSACTION_DIGEST:-none}" = none ] && {
    [ -e "$BACKUP" ] || [ -e "$DONE" ] || [ -e "$CF_TRANSACTION_RETIREMENT" ];
}; then
    fail 'legacy callback quiescence is unproven; automatic restoration refused; originals and journals preserved for separately authorized recovery'
fi
RELEASE_DIR=$ROOT/etc/.couvrefeu-release-$CF_RELEASE_ID
RELEASE_RETIRE=0
RETIRE_TARGET=$CF_RELEASE_ID
RETIRE_LEGACY=0
release_target_select() {
    if retirement_present; then retirement_validate
    else
        RETIRE_TARGET=$CF_RELEASE_ID
        RETIRE_LEGACY=0
        if [ -e "$BACKUP/release-absent" ] && [ "${CF_TRANSACTION_DIGEST:-none}" = none ]; then
            release_binding=$BACKUP/usr_lib_couvrefeu_platform-bootstrap.sh.after
            platform_regular "$release_binding"
            platform_private "$release_binding" 600
            if ! { [ "$(stat -c %h "$release_binding")" = 1 ] && valid_signature_record "$release_binding" 0; }; then
                fail 'invalid owned recovery release binding; preserved'
            fi
            release_bootstrap=$(awk -F: '{print $1}' "$release_binding")
            if [ "$release_bootstrap" = "$(retirement_legacy_bootstrap)" ]; then
                [ "$(cat "$release_binding")" = "$(retirement_legacy_bootstrap):644:$(id -u):$(id -g)" ] || fail 'legacy recovery release bootstrap metadata binding mismatch'
                RETIRE_TARGET=$(retirement_legacy_id)
                RETIRE_LEGACY=1
            else
                fail 'unknown legacy owned recovery release; journal preserved'
            fi
        fi
    fi
    RELEASE_DIR=$ROOT/etc/.couvrefeu-release-$RETIRE_TARGET
}
release_legacy_check() (
    set +f
    [ "$RETIRE_TARGET" = "$(retirement_legacy_id)" ] || fail 'unknown legacy release target'
    if ! { [ -d "$RELEASE_DIR" ] && [ ! -L "$RELEASE_DIR" ]; }; then fail 'known legacy recovery release absent or unsafe; journal preserved'; fi
    platform_private "$RELEASE_DIR" 700
    if ! { [ -d "$RELEASE_DIR/lib" ] && [ ! -L "$RELEASE_DIR/lib" ]; }; then fail 'unsafe legacy recovery release lib'; fi
    platform_private "$RELEASE_DIR/lib" 700
    platform_regular "$RELEASE_DIR/release.sha256"
    platform_private "$RELEASE_DIR/release.sha256" 600
    if ! {
        [ "$(stat -c %h "$RELEASE_DIR/release.sha256")" = 1 ] &&
        [ "$(sha256sum "$RELEASE_DIR/release.sha256" | awk '{print $1}')" = "$(retirement_legacy_manifest)" ]
    }; then fail 'legacy recovery release manifest drift; journal preserved'; fi
    release_expected=$(retirement_target_names)
    release_seen=$(awk 'BEGIN{s=""}{printf "%s%s",s,$2;s=" "}END{print ""}' "$RELEASE_DIR/release.sha256")
    [ "$release_seen" = "$release_expected" ] || fail 'legacy recovery release inventory mismatch'
    for release_entry in "$RELEASE_DIR"/* "$RELEASE_DIR"/.[!.]* "$RELEASE_DIR"/..?* "$RELEASE_DIR"/lib/* "$RELEASE_DIR"/lib/.[!.]* "$RELEASE_DIR"/lib/..?*; do
        [ -e "$release_entry" ] || [ -L "$release_entry" ] || continue
        release_name=${release_entry#"$RELEASE_DIR"/}
        case "$release_name" in lib|release.sha256) continue;; esac
        case " $release_expected " in *" $release_name "*) ;; *) fail 'foreign legacy recovery release entry; journal preserved';; esac
    done
    while read -r release_hash release_name; do
        platform_regular "$RELEASE_DIR/$release_name"
        case "$release_name" in lib/*) release_mode=644;; *) release_mode=755;; esac
        platform_private "$RELEASE_DIR/$release_name" "$release_mode"
        if ! {
            [ "$(stat -c %h "$RELEASE_DIR/$release_name")" = 1 ] &&
            [ "$(sha256sum "$RELEASE_DIR/$release_name" | awk '{print $1}')" = "$release_hash" ]
        }; then fail 'legacy recovery release bytes changed; journal preserved'; fi
    done < "$RELEASE_DIR/release.sha256"
    [ "$(sha256sum "$RELEASE_DIR/lib/platform-bootstrap.sh" | awk '{print $1}')" = "$(retirement_legacy_bootstrap)" ] || fail 'legacy recovery bootstrap mismatch'
)
# A recovery release this installation created is retired only with exact
# reviewed contents and no foreign entries; drift refuses and keeps it.
release_retire_check() {
    release_target_select
    if retirement_present; then
        retirement_validate
        RELEASE_RETIRE=$RETIRE_RELEASE_OWNED
        [ "$RELEASE_RETIRE" = 1 ] || return 0
        [ -e "$RELEASE_DIR" ] || [ -L "$RELEASE_DIR" ] || return 0
        if ! { [ -d "$RELEASE_DIR" ] && [ ! -L "$RELEASE_DIR" ]; }; then fail 'unsafe retiring recovery release; preserved'; fi
        platform_private "$RELEASE_DIR" 700
        release_names=$(retirement_target_names)
        if [ -e "$RELEASE_DIR/lib" ] || [ -L "$RELEASE_DIR/lib" ]; then
            if ! { [ -d "$RELEASE_DIR/lib" ] && [ ! -L "$RELEASE_DIR/lib" ]; }; then fail 'unsafe retiring recovery release lib; preserved'; fi
            platform_private "$RELEASE_DIR/lib" 700
        fi
        # All remaining entries must still match the authenticated source.
        # Missing entries are allowed only under the durable retirement receipt.
        for entry in "$RELEASE_DIR"/* "$RELEASE_DIR"/.[!.]* "$RELEASE_DIR"/..?* "$RELEASE_DIR"/lib/* "$RELEASE_DIR"/lib/.[!.]* "$RELEASE_DIR"/lib/..?*; do
            [ -e "$entry" ] || [ -L "$entry" ] || continue
            name=${entry#"$RELEASE_DIR"/}
            [ "$name" != lib ] || continue
            if [ "$name" = release.sha256 ]; then
                release_hash=$(sed -n '10p' "$CF_TRANSACTION_RETIREMENT")
                release_mode=600
            else
                release_hash=$(printf '%s\n' "$RETIRE_TARGET_PAIRS" | awk -v n="$name" '{for(i=1;i<=NF;i++){split($i,p,":");if(p[1]==n)print p[2]}}')
                [ -n "$release_hash" ] || fail "unexpected recovery release entry: $name; preserved"
                case "$name" in lib/*) release_mode=644;; *) release_mode=755;; esac
            fi
            platform_regular "$entry"
            platform_private "$entry" "$release_mode"
            if ! { [ "$(stat -c %h "$entry")" = 1 ] && [ "$(sha256sum "$entry" | awk '{print $1}')" = "$release_hash" ]; }; then fail "retiring recovery release drift: $name; preserved"; fi
        done
        return 0
    fi
    [ -e "$BACKUP/release-absent" ] || return 0
    valid_marker "$BACKUP/release-absent" || fail 'invalid release marker; journal retained'
    if [ "$RETIRE_LEGACY" = 1 ]; then
        release_legacy_check
        release_names=$(retirement_target_names)
        RELEASE_RETIRE=1
        return 0
    fi
    if [ ! -e "$RELEASE_DIR" ] && [ ! -L "$RELEASE_DIR" ]; then return 0; fi
    ( platform_external_closure "$RELEASE_DIR" ) || fail "recovery release drift at $RELEASE_DIR; retained with journal"
    release_names=$(awk '{print $2}' "$RELEASE_DIR/release.sha256")
    for entry in "$RELEASE_DIR"/* "$RELEASE_DIR"/.[!.]* "$RELEASE_DIR"/..?* "$RELEASE_DIR"/lib/* "$RELEASE_DIR"/lib/.[!.]* "$RELEASE_DIR"/lib/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        name=${entry#"$RELEASE_DIR"/}
        case "$name" in release.sha256|lib) continue;; esac
        printf '%s\n' "$release_names" | awk -v n="$name" '$0==n{found=1}END{exit !found}' || fail "unexpected recovery release entry: $name; retained with journal"
    done
    RELEASE_RETIRE=1
}
# Final command only: exec leaves no shell reading this (possibly removed) script.
release_retire() {
    if retirement_present; then
        retirement_validate
        retirement_originals
        retirement_prepared_check
        release_retire_check
        # Shells retain their open script inode across unlink; all helpers are
        # already loaded. No removed release file is subsequently sourced.
        if [ "$RELEASE_RETIRE" = 1 ] && [ -d "$RELEASE_DIR" ]; then
            for release_name in $release_names release.sha256; do rm -f "$RELEASE_DIR/$release_name"; done
            if [ -d "$RELEASE_DIR/lib" ]; then rmdir "$RELEASE_DIR/lib"; fi
            rmdir "$RELEASE_DIR" || fail 'recovery release retirement incomplete; receipt retained'
        fi
        unlock_install
        platform_lock_release
        if [ -e "$CF_TRANSACTION_FENCE" ] || [ -L "$CF_TRANSACTION_FENCE" ]; then
            platform_regular "$CF_TRANSACTION_FENCE"
            platform_private "$CF_TRANSACTION_FENCE" 600
            printf '%s\n' "$RETIRE_TOKEN" | cmp -s - "$CF_TRANSACTION_FENCE" || fail 'retirement fence mismatch; preserved'
        fi
        # The receipt fences admission through every interrupted final unlink,
        # including after owner and DONE have disappeared. fd9 stays held.
        rm -f "$CF_TRANSACTION_OWNER"
        rm -f "$CF_TRANSACTION_FENCE"
        if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CLEANUP_FAIL_AT:-}" = 'done' ]; then fail 'injected before DONE removal'; fi
        rm -f "$DONE"
        sync
        platform_transaction_barrier retirement-final
        rm -f "$CF_TRANSACTION_RETIREMENT"
        trap - 0 1 2 15
        [ "$RELEASE_RETIRE" != 1 ] || printf '%s\n' "Recovery release removed: $RELEASE_DIR"
        exit 0
    fi
    [ "$RELEASE_RETIRE" = 1 ] || exit 0
    # Names are validated release manifest entries without whitespace.
    # shellcheck disable=SC2086
    exec sh -c 'd=$1; shift; for f do rm -f "$d/$f" || exit 1; done; rmdir "$d/lib" "$d" || { printf "couvre-feu: recovery release removal incomplete: %s\n" "$d" >&2; exit 1; }; printf "%s\n" "Recovery release removed: $d"' \
        release-retire "$RELEASE_DIR" $release_names release.sha256
}
# Final cleanup has its own private completion record: removing the journal
# can be interrupted without losing the fact that every restoration succeeded.
finish_cleanup() {
    CLEANUP_COUNT=0
    if retirement_present; then
        retirement_validate
        retirement_originals
        retirement_prepared_check
        release_retire_check
        if [ -e "$DONE" ] || [ -L "$DONE" ]; then
            platform_valid_done "$DONE" || fail 'unsafe recovery completion record; preserved'
        fi
    else
        platform_valid_done "$DONE" || fail 'unsafe/legacy recovery completion record; preserved'
        if [ "${CF_TRANSACTION_DIGEST:-none}" != none ] || [ "$RETIRE_LEGACY" = 1 ]; then retirement_publish; fi
    fi
    if [ -e "$BACKUP" ]; then
        journal_preflight cleanup
        # Remove the journal only while each managed path still holds its
        # exact original (bytes, mode, owner and nanosecond mtime): a legacy
        # journal copy, or the remaining records of one renamed back.
        for rel in $FILES etc/couvrefeu/rpc-allowed usr/sbin/cfctl-scope; do
            k=$(key "$rel")
            if [ -e "$BACKUP/$k.original" ]; then
                if ! { [ -f "$ROOT/$rel" ] && [ ! -L "$ROOT/$rel" ] &&
                    [ "$(signature "$ROOT/$rel")" = "$(signature "$BACKUP/$k.original")" ] && [ "$(mtime "$ROOT/$rel")" = "$(mtime "$BACKUP/$k.original")" ]; }; then
                    fail "original backup is not restored at /$rel; journal preserved"
                fi
            elif [ -f "$BACKUP/$k.before" ] && [ -f "$BACKUP/$k.mtime" ]; then
                cleanup_before=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.before")
                [ "$cleanup_before" = absent ] && continue
                if ! { [ -f "$ROOT/$rel" ] && [ ! -L "$ROOT/$rel" ] &&
                    exact_file "$ROOT/$rel" "$cleanup_before" "$(awk 'NR==1 {print; exit}' "$BACKUP/$k.mtime")"; }; then
                    fail "original backup is not restored at /$rel; journal preserved"
                fi
            fi
        done
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
    prepared_retire
    if retirement_present; then return 0; fi
    rm -f "$CF_TRANSACTION_FENCE" "$CF_TRANSACTION_OWNER"
    unlock_install
    platform_lock_release
    trap - 0 1 2 15
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CLEANUP_FAIL_AT:-}" = 'done' ]; then fail 'injected before DONE removal'; fi
    # Last filesystem operation: the binding survives journal and lock cleanup.
    platform_initial_write
    rm -f "$DONE"
}
if retirement_present; then
    finish_cleanup
    printf '%s\n' 'Original files restored; Couvre-feu installation removed.'
    release_retire
fi
if [ -e "$DONE" ]; then
    if [ -e "$BACKUP" ]; then release_retire_check; fi
    finish_cleanup
    printf '%s\n' 'Original files restored; Couvre-feu installation removed.'
    release_retire
fi
if [ ! -e "$BACKUP" ]; then
    if [ "${CF_TRANSACTION_DIGEST:-none}" != none ]; then prepared_materialize
    else
        rm -f "$CF_TRANSACTION_FENCE" "$CF_TRANSACTION_OWNER"
    printf '%s\n' 'No recorded installation; no changes made.'
    exit 0
    fi
fi
if [ ! -e "$BACKUP/ready" ] && [ "${CF_TRANSACTION_DIGEST:-none}" != none ]; then prepared_materialize; fi
preflight
# Historical release selection is anchored by the complete journal and trusted
# fixed manifest. Refuse unknown/tampered historical trees before restoration.
release_target_select
if [ "$RETIRE_LEGACY" = 1 ]; then release_legacy_check; fi
# Originals return by rename only (never a cross-filesystem mv, which BusyBox
# would turn into a copy): prove one filesystem before the first change.
if [ "$BACKUP" != "$RECOVERY" ]; then
    same_mount "$BACKUP" "$RECOVERY" || fail 'journal and recovery journal are not on one filesystem; no changes made'
fi
for rel in $FILES; do
    k=$(key "$rel")
    if [ -e "$BACKUP/$k.original" ] && ! same_mount "$ROOT/$rel" "$BACKUP"; then
        fail "journal original and /$rel are not on one filesystem; no changes made"
    fi
done
runtime_preflight
platform_deadline_check
recover_private_scratch
# Persist successful kernel removal before touching helpers or executables.
# Retries never invoke an installed program that has already been restored.
if [ ! -f "$BACKUP/kernel-cleaned" ]; then
    if [ -f "$BACKUP/activated" ] && live_tools; then
        platform_deadline_check
        # The refusal status JSON (its error code) is the only diagnosis; keep it.
        cleanup_result=$(installed_core remove-fw) || {
            cleanup_code=$?
            printf '%s\n' "couvre-feu: remove-fw exit $cleanup_code: $cleanup_result" >&2
            fail 'kernel cleanup failed; original files retained'
        }
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
    if [ -f "$BACKUP/activated" ] && live_tools; then cron_restore_barrier; fi
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
        if [ "$before" = absent ]; then
            if [ -e "$ROOT/$rel" ]; then platform_initial_write; rm -f "$ROOT/$rel"; fi
        elif ! { [ -e "$ROOT/$rel" ] && exact_file "$ROOT/$rel" "$before" "$original_mtime"; }; then
            # Proved journal original renamed back over the path.
            restore_original "$BACKUP/$k.original" "$ROOT/$rel" "$before" "$original_mtime"
            # Successful restoration always attempted a protected write.
            CF_PLATFORM_INITIAL_WRITE=1
            if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CRASH_AT:-}" = restored ]; then kill -KILL "$$"; fi
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
# Cron was reconciled while the installation's executable was still fenced.
release_retire_check
[ -f "$BACKUP/restored" ] || phase restored 2
if [ -f "$BACKUP/etc_couvrefeu_platform-profile.after" ]; then
    platform_publish_done
else
    [ "$CF_PLATFORM_PROFILE" = strict ] || fail 'vendor legacy completion refused'
    mv "$BACKUP/restored" "$DONE"
fi
finish_cleanup
printf '%s\n' 'Original files restored; Couvre-feu installation removed.'
release_retire
