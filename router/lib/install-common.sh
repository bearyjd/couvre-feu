# shellcheck shell=sh
# shellcheck disable=SC2034,SC1091
# Shared installation/recovery helpers. POSIX sh / OpenWrt ash.
set -eu
case "$0" in */install-common.sh) printf 'couvre-feu: executable journal helper refused\n' >&2; exit 2;; esac
umask 077

fail() { printf '%s\n' "couvre-feu: $*" >&2; exit 1; }
if [ "${CF_TEST_MODE:-0}" = 1 ]; then
    if ! { [ -n "${CF_ROOT:-}" ] && [ "$CF_ROOT" != / ]; }; then
        fail 'fixture root required'
    fi
    case "$CF_ROOT" in /tmp/couvre-feu-*) ;; *) fail 'fixture root must use /tmp/couvre-feu-*';; esac
    ROOT=${CF_ROOT%/}
    [ "$(CDPATH='' cd -- "$ROOT" && pwd -P)" = "$ROOT" ] || fail 'fixture root must be canonical with no symlink ancestors'
else
    [ -z "${CF_ROOT:-}" ] || fail 'CF_ROOT requires CF_TEST_MODE=1'
    [ "$(id -u)" = 0 ] || fail 'production installation requires root'
    ROOT=
fi
BASE=$ROOT/etc/couvrefeu
BACKUP=$BASE/backup
if [ "${CF_TEST_MODE:-0}" = 1 ]; then RECOVERY=$ROOT/.couvrefeu-recovery
else RECOVERY=/etc/.couvrefeu-recovery; fi
DONE=$RECOVERY.done
recovery_parent=${RECOVERY%/*}
if ! { [ -d "$recovery_parent" ] && [ ! -L "$recovery_parent" ]; }; then
    fail 'unsafe recovery parent'
fi
[ "$(stat -c %u "$recovery_parent")" = "$(id -u)" ] || fail 'unsafe recovery parent owner'
recovery_parent_mode=$(stat -c %a "$recovery_parent")
[ "$((0$recovery_parent_mode & 022))" = 0 ] || {
    [ "${CF_PLATFORM_ADMITTED:-0}" = 1 ] && { [ "${CF_PLATFORM_PROFILE:-strict}" = gl-xe3000-4.8.3-logd-011-v1 ] || [ "${CF_PLATFORM_PROFILE:-strict}" = gl-xe3000-4.8.3-os-trust-v1 ]; } && [ "$recovery_parent" = /etc ] && [ "$(stat -c '%u:%g:%a' "$recovery_parent")" = 0:0:775 ]
} || fail 'unsafe writable recovery parent'
# A recovery journal and its completion record are fixed, private paths.
for recovery_path in "$RECOVERY" "$DONE"; do
    [ ! -L "$recovery_path" ] || fail 'recovery path is a symlink'
done
if [ -e "$RECOVERY" ]; then
    if ! { [ ! -e "$BACKUP" ] && [ ! -L "$BACKUP" ]; }; then
        fail 'ambiguous installation and recovery journals'
    fi
    BACKUP=$RECOVERY
fi
if [ -e "$DONE" ]; then
    if ! { [ ! -e "$BASE/backup" ] && [ ! -L "$BASE/backup" ]; }; then
        fail 'ambiguous completed recovery and installation journal'
    fi
    BACKUP=$RECOVERY
fi
FILES='usr/lib/couvrefeu/core.sh usr/lib/couvrefeu/rpc.sh usr/lib/couvrefeu/state.awk usr/lib/couvrefeu/firewall.sh usr/lib/couvrefeu/json.awk usr/lib/couvrefeu/rules.awk usr/lib/couvrefeu/install-common.sh usr/sbin/cfctl usr/sbin/cfctl-ssh etc/firewall.couvrefeu etc/config/firewall etc/sysupgrade.conf etc/crontabs/root etc/couvrefeu/protected etc/couvrefeu/state'
# The optional scope file is journaled only for explicit scoped activation.
# Recovery derives inventory from its existing journal, never environment input.
SCOPED_INSTALL=0
# Installer options are parsed before bootstrap; recover their explicit value.
# Runtime/recovery inventory still comes exclusively from existing journals.
case "$0" in */install.sh) [ -z "${RPC_ALLOW:-}" ] || SCOPED_INSTALL=1;; esac
if [ -e "$BACKUP/etc_couvrefeu_rpc-allowed.after" ] || [ "$SCOPED_INSTALL" = 1 ];then
    FILES="$FILES etc/couvrefeu/rpc-allowed"
fi
# The per-admin scope wrapper is journaled by fresh installations only; older journals keep
# their own inventory (derived from the journal, never environment input).
if { [ ! -e "$BACKUP" ] && [ ! -e "$DONE" ]; } || [ -e "$BACKUP/usr_sbin_cfctl-scope.after" ];then
    FILES="$FILES usr/sbin/cfctl-scope"
fi
# Legacy inventory comes solely from the validated original journal shape.
PROFILE_INVENTORY=0
if [ ! -e "$BACKUP" ] && [ ! -e "$DONE" ]; then PROFILE_INVENTORY=1
elif [ -e "$BACKUP/etc_couvrefeu_platform-profile.after" ]; then PROFILE_INVENTORY=1
elif [ -e "$DONE" ] && ! platform_done_legacy "$DONE"; then PROFILE_INVENTORY=1; fi
if [ "$PROFILE_INVENTORY" = 1 ]; then
    FILES="$FILES usr/lib/couvrefeu/platform-bootstrap.sh usr/lib/couvrefeu/vendor-platform.sh etc/couvrefeu/platform-profile usr/lib/couvrefeu/activity.sh"
elif [ "${CF_PLATFORM_PROFILE:-strict}" != strict ]; then fail 'legacy journal cannot select vendor profile'; fi
DIRS='etc usr usr/sbin usr/lib usr/lib/couvrefeu etc/config etc/crontabs etc/couvrefeu'

for dep in sha256sum stat cp mv mkdir rmdir chmod awk sed cmp dd od tr sync wc; do
    command -v "$dep" >/dev/null 2>&1 || fail "missing dependency: $dep"
done

if [ "${CF_TEST_MODE:-0}" = 1 ]; then LOCK=$ROOT/.couvrefeu-install.lock
else LOCK=/tmp/couvrefeu-install.lock; fi
INSTALL_LOCK_OWNED=0
if [ "${CF_PLATFORM_NESTED:-0}" = 1 ] && [ -d "$LOCK" ]; then
    platform_private "$LOCK" 700
    platform_private "$LOCK/pid" 600
    platform_private "$LOCK/token" 600
    printf '%s\n' "$$" | cmp -s - "$LOCK/pid" || fail 'nested install lock owner mismatch'
    printf '%s\n' "${INSTALL_TOKEN:-}" | cmp -s - "$LOCK/token" || fail 'nested install lock token mismatch'
else
    mkdir -m 700 "$LOCK" 2>/dev/null || fail 'another install/recovery transaction is running'
    INSTALL_LOCK_OWNED=1
    printf '%s\n' "$$" > "$LOCK/pid"
    INSTALL_TOKEN=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | sha256sum | awk '{print $1}')
    printf '%s\n' "$INSTALL_TOKEN" > "$LOCK/token"
fi
unlock_install() {
    [ "$INSTALL_LOCK_OWNED" = 1 ] || return 0
    printf '%s\n' "$$" | cmp -s - "$LOCK/pid" || fail 'installation lock owner mismatch'
    printf '%s\n' "$INSTALL_TOKEN" | cmp -s - "$LOCK/token" || fail 'installation lock token mismatch'
    rm -f "$LOCK/pid" "$LOCK/token"
    rmdir "$LOCK" 2>/dev/null || :
    INSTALL_LOCK_OWNED=0
}
trap 'unlock_install; platform_lock_release' 0
trap 'exit 1' 1 2 15

# Every core mutation checks the global lock before and after obtaining its
# own runtime lock. Once this lock is held, an existing runtime lock means
# an operation predates us and we must stop. Journal calls come directly
# from that lock-owning core process and are the sole exception here.
# Uninstall already holds the install lock, so no new core mutation can
# start. A cron `cfctl expire` that took the runtime lock first gets a bounded
# wait to finish; OS-trust admission deadlines still refuse first.
case "$0" in */uninstall.sh)
    lock_wait=0
    while { [ -e "$BASE/runtime/lock" ] || [ -L "$BASE/runtime/lock" ]; } && [ "$lock_wait" -lt 20 ]; do
        sleep 1
        lock_wait=$((lock_wait + 1))
        platform_deadline_check
    done;;
esac
if [ -e "$BASE/runtime/lock" ] || [ -L "$BASE/runtime/lock" ]; then
    case "${1:-}" in
        firewall-prepare|firewall-commit)
            if ! { [ -d "$BASE/runtime/lock" ] && [ ! -L "$BASE/runtime/lock" ]; }; then
                fail 'unsafe core lock'
            fi
            if ! { [ -f "$BASE/runtime/lock/pid" ] && [ ! -L "$BASE/runtime/lock/pid" ]; }; then
                fail 'unsafe core owner'
            fi
            owner=$(awk 'NR==1 {print; exit}' "$BASE/runtime/lock/pid")
            if [ "$owner" != "${CF_PLATFORM_CALLER_PID:-${PPID:-}}" ] || ! kill -0 "$owner" 2>/dev/null; then fail 'journal caller does not own the core lock'; fi;;
        *) fail 'core operation is running; no installation/recovery changes made';;
    esac
fi

# Never follow a symlink in any managed path or ancestor.
safe_paths() {
    [ ! -L "$ROOT" ] || fail 'root is a symlink'
    for rel in $DIRS; do
        p=$ROOT/$rel
        [ ! -L "$p" ] || fail "symlink directory: $p"
        [ ! -e "$p" ] || [ -d "$p" ] || fail "not a directory: $p"
    done
    [ ! -L "$BACKUP" ] || fail 'backup is a symlink'
    for rel in $FILES; do
        p=$ROOT/$rel
        [ ! -L "$p" ] || fail "symlink file: $p"
        [ ! -e "$p" ] || [ -f "$p" ] || fail "not a regular file: $p"
    done
}
signature() {
    if [ -e "$1" ]; then
        if ! { [ -f "$1" ] && [ ! -L "$1" ]; }; then
            fail "unsafe file: $1"
        fi
        printf '%s:%s:%s:%s\n' "$(sha256sum "$1" | awk '{print $1}')" "$(stat -c %a "$1")" "$(stat -c %u "$1")" "$(stat -c %g "$1")"
    else
        printf '%s\n' absent
    fi
}
# Numeric epoch plus the full fractional mtime; locale/time zone text is not
# stored. A stat implementation without nanosecond reporting cannot prove
# exact restoration and must refuse before creating an installation journal.
mtime() {
    if [ ! -e "$1" ]; then printf '%s\n' absent; return; fi
    mtime_output=$(stat -c '%Y %y' "$1") || return 1
    printf '%s\n' "$mtime_output" | awk '
        NF==4 && $1 ~ /^-?[0-9]+$/ {
            n=split($3,t,".")
            if(n==2 && length(t[2])==9 && t[2] !~ /[^0-9]/) {
                print $1 ":" t[2]; good=1
            }
        }
        END {exit !good || NR!=1}
    '
}
valid_mtime_record() {
    awk -F: '
        $0=="absent" {good=1; next}
        NF==2 && $1 ~ /^-?[0-9]+$/ && length($2)==9 && $2 !~ /[^0-9]/ {good=1}
        END {exit !good || NR!=1}
    ' "$1"
}
exact_mtime() {
    observed_mtime=$(mtime "$1") || fail "precise mtime unavailable: $1"
    [ "$observed_mtime" = "$2" ]
}
key() { printf '%s' "$1" | sed 's|/|_|g'; }
# Identity is exact content and metadata, never dev:ino, ctime or link count.
# Without index=on, overlayfs reports a copied-up file with an origin xattr as
# the overlay dev plus the lower inode, while a new hard link to it reports
# another identity (GL-XE3000, OpenWrt 21.02).
exact_file() {
    [ "$(signature "$1")" = "$2" ] && exact_mtime "$1" "$3"
}
# Originals move into and out of the journal by rename(2) only; the kernel
# keeps bytes, owner, mode and nanosecond mtime (an overlay copy-up of a
# lower-only file preserves them too). Nothing re-applies a timestamp: the
# target's BusyBox touch truncates nanoseconds. BusyBox mv silently falls back
# to copy and unlink across filesystems, so both ends must first be proved on
# one filesystem *and* one mount: the device and mount point of the nearest
# existing directory (directories report the overlay's own device; files may
# not), and its mount ID from mountinfo, longest mount-point prefix of the
# physical path, last entry winning. A same-device bind mount shares %d and
# may share %m but has its own mount ID (rename across it is EXDEV).
# Unreadable or malformed output refuses.
mount_dir() {
    md_dir=$1
    while [ -n "$md_dir" ] && { [ ! -d "$md_dir" ] || [ -L "$md_dir" ]; }; do md_dir=${md_dir%/*}; done
    (CDPATH='' cd -- "${md_dir:-/}" && pwd -P)
}
mountinfo_path() {
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ -n "${CF_TEST_MOUNTINFO:-}" ]; then
        case "$CF_TEST_MOUNTINFO" in "$ROOT"/*) printf '%s\n' "$CF_TEST_MOUNTINFO";; *) fail 'fixture mountinfo must be below fixture root';; esac
    else printf '%s\n' /proc/self/mountinfo; fi
}
mount_of() {
    mo_dir=$(mount_dir "$1") || return 1
    mo_info=$(mountinfo_path) || return 1
    mo_id=$(awk -v p="$mo_dir" '
        NF < 10 || $1 !~ /^[0-9]+$/ || $5 !~ /^\// {bad=1; exit}
        {
            m=$5; gsub(/\\040/, " ", m); gsub(/\\011/, "\t", m); gsub(/\\012/, "\n", m); gsub(/\\134/, "\\", m)
            if ((m == "/" || p == m || index(p, m "/") == 1) && length(m) >= best) {best=length(m); id=$1}
        }
        END {if (bad || id == "") exit 1; print id}' "$mo_info") || return 1
    stat -c '%d %m' "$mo_dir" | awk -v id="$mo_id" 'NR==1 && NF==2 && $1 ~ /^[0-9]+$/ && $2 ~ /^\// {print id, $0; good=1} END {exit !good || NR!=1}'
}
same_mount() {
    sm_first=$(mount_of "$1") && sm_second=$(mount_of "$2") && [ "$sm_first" = "$sm_second" ]
}
valid_inode_record() {
    awk '$0 ~ /^[0-9]+$/ && length($0) <= 20 {good=1} END {exit !good || NR!=1}' "$1"
}

valid_protection() {
    awk -F: '
        NF != 6 || seen[$0]++ || $0=="00:00:00:00:00:00" || substr($1,2,1) !~ /^[02468ace]$/ {exit 1}
        {for(i=1;i<=6;i++) if($i !~ /^[0-9a-f][0-9a-f]$/) exit 1}
        END {if(NR < 1 || NR > 128) exit 1}
    ' "$1"
}
# Live RPC scope validation is the runtime's (core.sh cf_scope_file / cf_scope_has_floor),
# sourced in a subshell so its globals stay out of the installer: one validator, no mirror.
scope_core() ( CF_BASE=$ROOT CF_LIB=${SOURCE:-$HERE}/lib; . "$CF_LIB/core.sh"; "$@" )
valid_scope() { scope_core cf_scope_file "$1" >/dev/null; }
scope_has_floor() { scope_core cf_scope_has_floor "$1" "$2"; }
metadata() { stat -c '%a:%u:%g' "$1"; }

valid_signature_record() {
    awk -F: -v allow_absent="$2" '
        function valid() {
            return NF==4 && length($1)==64 && $1 !~ /[^0-9a-f]/ &&
                length($2)>=3 && length($2)<=4 && $2 !~ /[^0-7]/ &&
                $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/
        }
        {if(!valid() && !(allow_absent && $0=="absent")) bad=1}
        END {exit bad || NR!=1}
    ' "$1"
}

# Validate the complete journal tree and directory restoration records before
# touching any installed file. A foreign entry, symlink or malformed record
# leaves both the installation and every backup intact.
journal_preflight() {
    owner_ids=$(id -u):$(id -g)
    if ! { [ -d "$BACKUP" ] && [ ! -L "$BACKUP" ] && [ "$(metadata "$BACKUP")" = "700:$owner_ids" ]; }; then
        fail 'unsafe backup directory metadata'
    fi
    if [ "$BACKUP" != "$RECOVERY" ]; then
        [ "$(metadata "$BASE")" = "700:$owner_ids" ] || fail 'unsafe installation directory metadata'
    elif [ "${1:-}" != cleanup ]; then
        if ! { [ -f "$BACKUP/restoring" ] && [ -f "$BACKUP/kernel-cleaned" ]; }; then
            fail 'recovery phase missing'
        fi
        if [ -e "$BASE" ]; then
            original_mode=$(awk 'NR==1 {print; exit}' "$BACKUP/dir_etc_couvrefeu")
            base_metadata=$(metadata "$BASE")
            [ "$base_metadata" = "700:$owner_ids" ] || [ "$base_metadata" = "$original_mode:$owner_ids" ] || fail 'unsafe recovery installation directory metadata'
        else
            [ "$(awk 'NR==1 {print; exit}' "$BACKUP/dir_etc_couvrefeu")" = absent ] || fail 'original installation directory missing'
        fi
    fi
    allowed_entries='release-absent ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next firewall.transaction firewall.transaction.next etc_config_firewall.after.next firewall.pending etc_config_firewall.staged.couvrefeu-tmp'
    record_entries='release-absent ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next firewall.transaction firewall.transaction.next etc_config_firewall.after.next'
    # DONE proves full exact restoration has already succeeded. Its authenticated
    # cleanup-only whitelist survives deletion of an optional (scope, wrapper) .after;
    # restoration inventory and its full preflight remain journal-derived.
    if [ "${1:-}" = cleanup ]; then
        platform_valid_done "$DONE" || fail 'unsafe cleanup completion record'
        for optional_key in etc_couvrefeu_rpc-allowed usr_sbin_cfctl-scope;do
            allowed_entries="$allowed_entries $optional_key.before $optional_key.after $optional_key.original $optional_key.copy $optional_key.staged $optional_key.mtime $optional_key.inode"
            record_entries="$record_entries $optional_key.before $optional_key.after $optional_key.mtime $optional_key.inode"
        done
    fi
    for rel in $FILES; do
        k=$(key "$rel")
        allowed_entries="$allowed_entries $k.before $k.after $k.original $k.copy $k.staged $k.mtime $k.inode"
        record_entries="$record_entries $k.before $k.after $k.mtime $k.inode"
    done
    for rel in $DIRS; do
        k=$(key "$rel")
        allowed_entries="$allowed_entries dir_$k"
        record_entries="$record_entries dir_$k"
    done
    for entry in "$BACKUP"/* "$BACKUP"/.[!.]* "$BACKUP"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        if ! { [ -f "$entry" ] && [ ! -L "$entry" ]; }; then
            fail 'backup entry is not a regular file; preserved'
        fi
        name=${entry##*/}
        case "$name" in *[!a-z0-9_.-]*) fail 'invalid backup filename';; esac
        case " $allowed_entries " in *" $name "*) ;; *) fail "unexpected backup entry: $name; all files preserved";; esac
        case " $record_entries " in *" $name "*)
            [ "$(metadata "$entry")" = "600:$owner_ids" ] || fail "unsafe journal record metadata: $name"
            [ "$(stat -c %s "$entry")" -le 512 ] || fail "oversized journal record: $name"
        ;; esac
    done
    for marker in release-absent ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next; do
        if [ -e "$BACKUP/$marker" ]; then
            marker_version=1
            case "$marker" in restored|restored.next) marker_version=2;; esac
            valid_marker "$BACKUP/$marker" "$marker_version" || fail "invalid transaction marker: $marker"
        fi
    done
    [ "${1:-}" != cleanup ] || return 0
    for rel in $DIRS; do
        k=$(key "$rel")
        [ -f "$BACKUP/dir_$k" ] || fail "missing directory record: $rel"
        awk '($0!="absent" && (length($0)<3 || length($0)>4 || $0 ~ /[^0-7]/)) {bad=1} END {exit bad || NR!=1}' "$BACKUP/dir_$k" || fail "invalid directory record: $rel"
    done
}

# Preflight *all* files before any restore/write. A partially completed
# transaction may contain either originals or our recorded installed files.
preflight() {
    safe_paths
    journal_preflight full
    if ! { [ -f "$BACKUP/ready" ] && [ ! -L "$BACKUP/ready" ]; }; then
        fail 'incomplete backup; manual recovery required'
    fi
    owned_temp "$BACKUP/etc_config_firewall.staged" || fail 'temporary journal path collision'
    for rel in $FILES; do
        k=$(key "$rel")
        if ! { [ -f "$BACKUP/$k.before" ] && [ -f "$BACKUP/$k.after" ]; }; then
            fail "missing manifest: $rel"
        fi
        if ! valid_signature_record "$BACKUP/$k.before" 1 || ! valid_signature_record "$BACKUP/$k.after" 0; then fail "invalid signature record: $rel"; fi
        if ! valid_mtime_record "$BACKUP/$k.mtime"; then fail "missing/invalid original mtime record: $rel"; fi
        before=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.before")
        original_mtime=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.mtime")
        if [ "$before" = absent ]; then
            [ "$original_mtime" = absent ] || fail "invalid absent mtime record: $rel"
        else
            [ "$original_mtime" != absent ] || fail "missing original mtime: $rel"
        fi
        after=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.after")
        current=$(signature "$ROOT/$rel")
        tx_old='' tx_new=''
        if [ "$rel" = etc/config/firewall ] && [ -e "$BACKUP/firewall.transaction" ]; then
            [ ! -L "$BACKUP/firewall.transaction" ] || fail 'unsafe firewall transaction'
            tx_old=$(awk 'NR==1 {print}' "$BACKUP/firewall.transaction")
            tx_new=$(awk 'NR==2 {print}' "$BACKUP/firewall.transaction")
            awk 'END {exit NR!=2}' "$BACKUP/firewall.transaction" || fail 'invalid firewall transaction length'
            if ! { [ -n "$tx_old" ] && [ -n "$tx_new" ] && [ "$(signature "$BACKUP/firewall.pending")" = "$tx_new" ]; }; then
                fail 'corrupt firewall transaction'
            fi
        fi
        saved=$BACKUP/$k.original
        if [ "$rel" = etc/couvrefeu/protected ] && [ "$current" != "$before" ]; then
            if ! { [ -f "$ROOT/$rel" ] && [ "$(metadata "$ROOT/$rel")" = "$(metadata "$BACKUP/$k.staged")" ]; }; then
                fail 'protected metadata drift'
            fi
            valid_protection "$ROOT/$rel" || fail 'invalid protected list'
            awk 'NR==FNR {baseline[++n]=$0; next} FNR<=n && $0!=baseline[FNR] {exit 1} END {if(FNR<n) exit 1}' "$BACKUP/$k.staged" "$ROOT/$rel" || fail 'protected baseline was changed'
        elif [ "$rel" = etc/couvrefeu/rpc-allowed ] && [ "$current" != "$before" ] && [ "$current" != "$after" ]; then
            # The live scope may grow past its immutable floor (.staged), like protected.
            if ! { [ -f "$ROOT/$rel" ] && [ ! -L "$ROOT/$rel" ] && [ "$(metadata "$ROOT/$rel")" = "$(metadata "$BACKUP/$k.staged")" ]; }; then
                fail 'RPC scope metadata drift'
            fi
            valid_scope "$ROOT/$rel" || fail 'invalid RPC scope'
            scope_has_floor "$BACKUP/$k.staged" "$ROOT/$rel" || fail 'RPC scope floor was changed'
        elif [ "$rel" = etc/couvrefeu/state ] && [ "$current" != "$before" ]; then
            if ! { [ -f "$ROOT/$rel" ] && [ "$(metadata "$ROOT/$rel")" = "$(metadata "$BACKUP/$k.staged")" ]; }; then
                fail 'runtime state metadata drift'
            fi
        else
            # Absent is crash state only between the two install renames: the
            # original journaled and the owned temporary file still present
            # (owned_temp below proves it). A later deletion is drift.
            [ "$current" = "$before" ] || [ "$current" = "$after" ] || [ "$current" = "$tx_old" ] || [ "$current" = "$tx_new" ] ||
                { [ "$current" = absent ] && [ -e "$saved" ] && [ -f "$ROOT/$rel.couvrefeu-tmp" ]; } || fail "drift at /$rel; preserved current file and backup; resolve explicitly"
        fi
        # The exact original is journaled (renamed in, or a legacy copy), or
        # still in place: not yet renamed by install, or already restored.
        if [ "$before" != absent ]; then
            if [ -e "$saved" ] || [ -L "$saved" ]; then
                [ "$(signature "$saved")" = "$before" ] || fail "corrupt original backup: $rel"
                exact_mtime "$saved" "$original_mtime" || fail "corrupt original backup mtime: $rel"
            elif ! exact_file "$ROOT/$rel" "$before" "$original_mtime"; then
                fail "original neither journaled nor in place: /$rel; preserved current file and journal; manual recovery copy: $BACKUP/$k.copy"
            fi
        fi
        # Legacy hard-link journals (7676637) also recorded an inode number.
        # It is validated as a record only: overlayfs inode numbers are not
        # stable identity, and exact bytes/metadata/mtime above are the proof.
        if [ -e "$BACKUP/$k.inode" ]; then
            [ "$before" != absent ] && valid_inode_record "$BACKUP/$k.inode" || fail "invalid original inode record: $rel"
        fi
        owned_temp "$ROOT/$rel" || fail "temporary path collision: $ROOT/$rel.couvrefeu-tmp"
        staged_sig=$(signature "$BACKUP/$k.staged")
        [ "$staged_sig" = "$after" ] || [ "$staged_sig" = "$tx_old" ] || [ "$staged_sig" = "$tx_new" ] || fail "corrupt staged backup: $rel"
    done
}

valid_marker() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(metadata "$1")" = "600:$(id -u):$(id -g)" ] &&
        [ "$(stat -c %s "$1")" = 2 ] && [ "$(awk 'NR==1 {print}' "$1")" = "${2:-1}" ]
}
phase() {
    platform_initial_write
    printf '%s\n' "${2:-1}" > "$BACKUP/$1.next"
    mv -f "$BACKUP/$1.next" "$BACKUP/$1"
}
# A leftover rename source is owned only when exact bytes AND metadata match
# an immutable original/staged journal signature. Foreign collisions survive.
owned_temp() (
    target=$1 temp=$1.couvrefeu-tmp
    [ -e "$temp" ] || [ -L "$temp" ] || exit 0
    temp_sig=$(signature "$temp")
    for managed in $FILES; do
        [ "$target" = "$ROOT/$managed" ] || continue
        manifest=$(key "$managed")
        for suffix in before after; do
            expected=$(awk 'NR==1 {print; exit}' "$BACKUP/$manifest.$suffix")
            [ "$temp_sig" != absent ] && [ "$temp_sig" = "$expected" ] && exit 0
        done
        if [ "$managed" = etc/config/firewall ] && [ -f "$BACKUP/firewall.transaction" ]; then
            [ "$temp_sig" = "$(signature "$BACKUP/firewall.pending")" ] && exit 0
        fi
        exit 1
    done
    # The core journal's own staged rename is also transaction owned.
    [ "$target" = "$BACKUP/etc_config_firewall.staged" ] &&
        [ -f "$BACKUP/firewall.transaction" ] &&
        [ "$temp_sig" = "$(signature "$BACKUP/firewall.pending")" ]
)
# Immediately before the install rename, the managed path must still be what
# preflight accepted. Not yet journaled, it must be the exact original (it is
# about to be renamed into the journal). Journaled, the journal original must
# be exact and the path absent (between the two renames), owned content or a
# legacy in-place original. An in-place writer's change is never replaced.
original_intact() {
    oi_before=$(awk 'NR==1 {print; exit}' "$BACKUP/$1.before")
    oi_mtime=$(awk 'NR==1 {print; exit}' "$BACKUP/$1.mtime")
    oi_current=$(signature "$ROOT/$2")
    oi_tx_old='' oi_tx_new=''
    if [ "$2" = etc/config/firewall ] && [ -f "$BACKUP/firewall.transaction" ]; then
        oi_tx_old=$(awk 'NR==1 {print}' "$BACKUP/firewall.transaction")
        oi_tx_new=$(awk 'NR==2 {print}' "$BACKUP/firewall.transaction")
    fi
    oi_exact=0
    if [ "$oi_current" = "$oi_before" ] && exact_mtime "$ROOT/$2" "$oi_mtime"; then oi_exact=1; fi
    if [ -e "$BACKUP/$1.original" ] || [ -L "$BACKUP/$1.original" ]; then
        exact_file "$BACKUP/$1.original" "$oi_before" "$oi_mtime" &&
            { [ "$oi_exact" = 1 ] || [ "$oi_current" = absent ] || [ "$oi_current" = "$(awk 'NR==1 {print; exit}' "$BACKUP/$1.after")" ] ||
                [ "$oi_current" = "$oi_tx_old" ] || [ "$oi_current" = "$oi_tx_new" ]; }
    elif [ "$oi_before" = absent ]; then
        [ "$oi_current" = absent ] || [ "$oi_current" = "$(awk 'NR==1 {print; exit}' "$BACKUP/$1.after")" ] ||
            [ "$oi_current" = "$oi_tx_old" ] || [ "$oi_current" = "$oi_tx_new" ]
    else [ "$oi_exact" = 1 ]; fi ||
        fail "original changed in place before install rename: /$2; installation refused, journal retained; manual recovery copy: $BACKUP/$1.copy"
}
# Publish an owned, verified temporary file. With a journal key whose existing
# original is not yet journaled, first rename the original into the journal
# (same filesystem and mount, proved again here), then immediately rename the
# temporary file over the path. HUP/INT/TERM are ignored across the pair so no
# signal leaves the path absent; if the second rename fails, or the journaled
# original is not exact afterwards, the original is renamed straight back and
# proved. Only SIGKILL or a failed rollback leave the path absent, with the
# journaled original and the owned temporary file as recovery state (install
# resume publishes it, uninstall renames the original back).
publish_temp() {
    if [ -n "${3:-}" ]; then
        original_intact "$3" "${2#"$ROOT"/}"
        pt_saved=$BACKUP/$3.original
        pt_before=$(awk 'NR==1 {print; exit}' "$BACKUP/$3.before")
        pt_mtime=$(awk 'NR==1 {print; exit}' "$BACKUP/$3.mtime")
        if [ ! -e "$pt_saved" ] && [ ! -L "$pt_saved" ] && [ "$pt_before" != absent ]; then
            same_mount "$2" "$BACKUP" || fail "original and journal are not on one filesystem: $2; journal retained"
            platform_initial_write
            trap '' 1 2 15
            if ! mv "$2" "$pt_saved"; then trap 'exit 1' 1 2 15; fail "original rename into journal failed: $2; journal retained"; fi
            mv -f "$1" "$2" || pt_rollback "$pt_saved" "$2" "$3" 'install rename failed'
            if ! exact_file "$pt_saved" "$pt_before" "$pt_mtime"; then
                if [ "$(signature "$2")" = "$(signature "$BACKUP/$3.staged")" ]; then
                    pt_rollback "$pt_saved" "$2" "$3" 'journal original is not exact after rename'
                fi
                trap 'exit 1' 1 2 15
                fail "journal original is not exact after rename: $2; journal retained; manual recovery copy: $BACKUP/$3.copy"
            fi
            trap 'exit 1' 1 2 15
            sync "$pt_saved" "$2" 2>/dev/null
            [ "$(signature "$2")" = "$(signature "$BACKUP/$3.staged")" ] ||
                fail "installed file mismatch after rename: $2; original journaled, journal retained"
            return 0
        fi
    fi
    platform_initial_write
    mv -f "$1" "$2"
}
# Rename journaled original $1 back over path $2 (journal key $3), prove it and
# refuse with reason $4. Never returns.
pt_rollback() {
    if mv -f "$1" "$2"; then
        trap 'exit 1' 1 2 15
        if exact_file "$2" "$pt_before" "$pt_mtime"; then fail "$4: $2; original restored in place, journal retained"; fi
        fail "$4: $2; original renamed back in place but not exact; journal retained; manual recovery copy: $BACKUP/$3.copy"
    fi
    trap 'exit 1' 1 2 15
    fail "$4 and original rollback failed: $2; original journaled at $1; manual recovery copy: $BACKUP/$3.copy"
}
# Rename in the same directory; do not write through existing files. Installed
# content needs exact bytes/mode/owner only; its timestamp is never restored.
# A third argument `durable` flushes the data before the publishing rename.
# A fourth argument names the journal key whose original must be intact.
atomic_copy() (
    src=$1 dst=$2 tmp=$2.couvrefeu-tmp durable=${3:-} original_key=${4:-}
    if [ -e "$tmp" ] || [ -L "$tmp" ]; then
        owned_temp "$dst" || fail "temporary path collision: $tmp"
        # Write barriers follow the blocking proofs.
        if [ "$(signature "$tmp")" = "$(signature "$src")" ]; then
            publish_temp "$tmp" "$dst" "$original_key"
            exit 0
        fi
        platform_initial_write
        rm -f "$tmp"
    fi
    platform_initial_write
    cp -p "$src" "$tmp"
    chmod "$(stat -c %a "$src")" "$tmp"
    [ "$(signature "$tmp")" = "$(signature "$src")" ] || fail "staged copy metadata mismatch: $dst; journal retained"
    # Flush data before the rename publishes it (BusyBox without
    # FEATURE_SYNC_FANCY ignores the operand and syncs everything).
    if [ "$durable" = durable ]; then sync "$tmp" 2>/dev/null; fi
    publish_temp "$tmp" "$dst" "$original_key"
)
# Exact restoration proves the journal original, then renames it over the
# managed path (one atomic replace on one filesystem). Nothing is copied or
# re-timestamped. A path that already holds the exact original (never
# installed, or a legacy copy journal) is left as it is.
restore_original() (
    src=$1 dst=$2 before=$3 original_mtime=$4
    if [ -e "$dst" ] && exact_file "$dst" "$before" "$original_mtime"; then exit 0; fi
    exact_file "$src" "$before" "$original_mtime" || fail "journal original is not exact: $dst; nothing restored, journal retained"
    same_mount "$dst" "$src" || fail "journal original and $dst are not on one filesystem; nothing restored, journal retained"
    platform_initial_write
    mv -f "$src" "$dst" || fail "exact original rename failed: $dst; journal retained"
    sync "$dst" 2>/dev/null
    exact_file "$dst" "$before" "$original_mtime" || fail "exact original rename mismatch: $dst; journal retained"
)

# Only explicitly marked isolated fixtures can emulate live tool calls.
fixture_tools() {
    case "${CF_BACKEND_DIR:-}" in "$ROOT"/*) ;; *) fail 'fixture backend must be below fixture root';; esac
    [ "$(CDPATH='' cd -- "$CF_BACKEND_DIR" && pwd -P)" = "$CF_BACKEND_DIR" ] || fail 'fixture backend must be canonical with no symlink ancestors'
    if ! { [ -f "$CF_BACKEND_DIR/.couvrefeu-test-backend" ] && [ ! -L "$CF_BACKEND_DIR/.couvrefeu-test-backend" ]; }; then
        fail 'fixture backend marker missing'
    fi
}
live_tools() {
    [ "${CF_TEST_MODE:-0}" != 1 ] || [ "${CF_TEST_INSTALL_KERNEL:-0}" = 1 ]
}
installed_core() (
    [ "${CF_PLATFORM_ADMITTED:-0}" = 1 ] || fail 'missing transaction admission'
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then
        fixture_tools
        # Existing inert filesystem fixtures emulate the core call boundary.
        # An actual kernel fixture omits this double and runs verified code.
        if [ -e "$CF_BACKEND_DIR/core" ] || [ -L "$CF_BACKEND_DIR/core" ]; then
            [ -f "$CF_BACKEND_DIR/core" ] && [ ! -L "$CF_BACKEND_DIR/core" ] && [ -x "$CF_BACKEND_DIR/core" ] || fail 'unsafe fixture core backend'
            CF_INSTALL_TOKEN=$INSTALL_TOKEN "$CF_BACKEND_DIR/core" "$@"
            exit $?
        fi
    fi
    [ -n "${CF_PLATFORM_LIB:-}" ] || fail 'missing verified release library'
    platform_verify_modules "$CF_PLATFORM_LIB"
    CF_LOCAL_TEST=${CF_TEST_MODE:-0} CF_BASE=$ROOT CF_LIB=$CF_PLATFORM_LIB
    CF_INSTALL_TOKEN=$INSTALL_TOKEN
    CF_PLATFORM_LOCKED=0
    # Isolate core's runtime traps; the outer transaction owns admission.
    . "$CF_LIB/core.sh"
    . "$CF_LIB/rpc.sh"
    . "$CF_LIB/firewall.sh"
    . "$CF_LIB/activity.sh"
    platform_deadline_check
    cf_main "$@"
)
reload_firewall() {
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then
        fixture_tools
        if ! { [ -x "$CF_BACKEND_DIR/firewall" ] && [ ! -L "$CF_BACKEND_DIR/firewall" ]; }; then
            fail 'fixture firewall tool unavailable'
        fi
        platform_initial_write
        "$CF_BACKEND_DIR/firewall" reload
    else platform_initial_write; /etc/init.d/firewall reload; fi
}
# BusyBox crond rescans its directory only when the whole-second mtime changes,
# so a temporary file and its rename within one second can stay unseen for up
# to an hour. The OpenWrt 21.02 procd init script registers each crontab's md5:
# reload restarts crond only when a crontab changed, starts an absent crond and
# stops crond when /etc/crontabs is empty. Its exit status is not evidence
# (procd start returns 0); cron_running asks procd directly.
# Callers own the protected-write barrier; these subshells confine failures.
cron_script() {
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then fixture_tools; printf '%s\n' "$CF_BACKEND_DIR/cron"
    else printf '%s\n' /etc/init.d/cron; fi
}
cron_service() (
    script=$(cron_script)
    if ! { [ -f "$script" ] && [ -x "$script" ]; }; then fail "cron init script unavailable: $script"; fi
    # Fixed environment; rc.common inherits only the init-script umask.
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then "$script" "$1"
    else umask 022; env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$script" "$1"; fi
)
# A non-procd script falls back to `help` (exit 0) for unknown actions, so the
# only running proof is procd's own instance record.
# One pipeline: fixtures vary only the tool directory and the env -i prefix.
cron_running() (
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then fixture_tools; tools=$CF_BACKEND_DIR/; set --
    else tools=; set -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C; fi
    "$@" "${tools}ubus" call service list '{"name":"cron"}' |
        "$@" "${tools}jsonfilter" -e '@.cron.instances[*].running' | grep -qx true
)
# Read-only, before the first protected write: expiry needs a procd-managed
# crond that also starts at boot.
cron_preflight() {
    cron_preflight_script=$(cron_script) || fail 'cron init script unavailable; no installation made'
    if ! { [ -f "$cron_preflight_script" ] && [ -x "$cron_preflight_script" ] &&
        grep -qx 'USE_PROCD=1' "$cron_preflight_script"; }; then
        fail "cron init script unavailable or not procd-based: $cron_preflight_script; no installation made"
    fi
    cron_service enabled || fail 'cron service is not enabled at boot; minute expiry would stop after reboot; no installation made'
}

# Runtime is newly owned by this installation; preexisting runtime is refused
# by install. Never remove unknown paths, symlinks, active locks, or weak modes.
runtime_preflight() {
    runtime=$BASE/runtime
    [ -e "$runtime" ] || [ -L "$runtime" ] || return 0
    if ! { [ -d "$runtime" ] && [ ! -L "$runtime" ]; }; then
        fail 'unsafe runtime directory'
    fi
    if ! { [ ! -e "$runtime/lock" ] && [ ! -L "$runtime/lock" ]; }; then
        fail 'runtime lock present; installation/recovery stopped'
    fi
    expected_owner=$(stat -c '%u:%g' "$BACKUP/etc_couvrefeu_state.staged")
    [ "$(metadata "$runtime")" = "700:$expected_owner" ] || fail 'runtime directory metadata drift'
    for p in "$runtime"/* "$runtime"/.[!.]* "$runtime"/..?*; do
        [ -e "$p" ] || [ -L "$p" ] || continue
        name=${p##*/}
        case "$name" in
            .uci.*)
                suffix=${name##*.}
                case "$suffix" in ''|*[!0-9]*) fail "unowned runtime directory: $name";; esac
                if ! { [ -d "$p" ] && [ ! -L "$p" ] && [ "$(metadata "$p")" = "700:$expected_owner" ]; }; then
                    fail 'unsafe UCI staging directory'
                fi
                for child in "$p"/* "$p"/.[!.]* "$p"/..?*; do
                    [ -e "$child" ] || [ -L "$child" ] || continue
                    if [ "${child##*/}" = .delta ]; then
                        if ! { [ -d "$child" ] && [ ! -L "$child" ] && [ "$(metadata "$child")" = "700:$expected_owner" ]; }; then
                            fail 'unsafe UCI delta directory'
                        fi
                        for delta in "$child"/* "$child"/.[!.]* "$child"/..?*; do
                            [ -e "$delta" ] || [ -L "$delta" ] || continue
                            if ! { [ "${delta##*/}" = firewall ] && [ -f "$delta" ] && [ ! -L "$delta" ]; }; then
                                fail 'unowned UCI delta contents'
                            fi
                            [ "$(metadata "$delta")" = "600:$expected_owner" ] || fail 'UCI delta metadata drift'
                        done
                    else
                        if ! { [ "${child##*/}" = firewall ] && [ -f "$child" ] && [ ! -L "$child" ]; }; then
                            fail 'unowned UCI staging contents'
                        fi
                        [ "$(metadata "$child")" = "$(metadata "$BACKUP/etc_config_firewall.staged")" ] || fail 'UCI staging metadata drift'
                    fi
                done
                continue;;
            confirmed|error|firewall.snapshot|firewall.owned|firewall.intent|firewall.preflight|firewall.cleanup|expiry|schedule.clock|activity.epoch) ;;
            .candidate.*|.protected.*|.fw.*|.input.*|.error.*|.confirmed.*|.snapshot.*|.expiry.*|.intent.*|.cleanup.*|.scope.*)
                suffix=${name##*.}
                case "$suffix" in ''|*[!0-9]*) fail "unowned runtime file: $name";; esac;;
            *) fail "unowned runtime file: $name";;
        esac
        if ! { [ -f "$p" ] && [ ! -L "$p" ]; }; then
            fail 'runtime lock/directory/symlink present; preserved'
        fi
        [ "$(metadata "$p")" = "600:$expected_owner" ] || fail "runtime file metadata drift: $name"
    done
}

firewall_commit() {
    preflight
    [ -f "$BACKUP/firewall.transaction" ] || fail 'no pending owned firewall transaction'
    new=$(awk 'NR==2 {print}' "$BACKUP/firewall.transaction")
    [ "$(signature "$ROOT/etc/config/firewall")" = "$new" ] || fail 'firewall transaction has not been applied'
    printf '%s\n' "$new" > "$BACKUP/etc_config_firewall.after.next"
    mv "$BACKUP/etc_config_firewall.after.next" "$BACKUP/etc_config_firewall.after"
    atomic_copy "$BACKUP/firewall.pending" "$BACKUP/etc_config_firewall.staged"
    rm -f "$BACKUP/firewall.transaction" "$BACKUP/firewall.pending"
}

# Called by core around *owned, validated* native schedule writes. This helper
# refuses existing drift before recording pending exact bytes for recovery.
case "${1:-}" in
    firewall-prepare)
        [ "$#" = 2 ] || fail 'firewall-prepare requires staged configuration'
        preflight
        if [ -e "$BACKUP/firewall.transaction" ]; then firewall_commit; fi
        candidate=$2
        if ! { [ -f "$candidate" ] && [ ! -L "$candidate" ]; }; then
            fail 'unsafe firewall candidate'
        fi
        [ "$(metadata "$candidate")" = "$(metadata "$ROOT/etc/config/firewall")" ] || fail 'firewall candidate metadata mismatch'
        cp -p "$candidate" "$BACKUP/firewall.pending"
        { signature "$ROOT/etc/config/firewall"; signature "$BACKUP/firewall.pending"; } > "$BACKUP/firewall.transaction.next"
        mv "$BACKUP/firewall.transaction.next" "$BACKUP/firewall.transaction"
        exit 0;;
    firewall-commit)
        [ "$#" = 1 ] || fail 'firewall-commit takes no arguments'
        firewall_commit
        exit 0;;
esac
