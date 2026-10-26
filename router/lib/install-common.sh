# shellcheck shell=sh
# shellcheck disable=SC2034,SC1091
# Shared installation/recovery helpers. POSIX sh / OpenWrt ash.
set -eu
# Imported only from the authenticated bootstrap; stand-alone fixtures may omit it.
: "${CF_TRANSACTION_OWNER:=}"
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
# A pre-ready journal killed before its profile signature is still modern
# only beside its PREPARED baseline (published before BACKUP is created, and
# digest-bound by prepared_recovery_check before any record is used). An
# old-format pre-ready journal has none and keeps its legacy inventory.
elif [ -d "$BACKUP" ] && [ ! -L "$BACKUP" ] && [ ! -e "$BACKUP/ready" ] && [ ! -L "$BACKUP/ready" ] &&
    [ -n "${CF_TRANSACTION_PREPARED:-}" ] && [ -d "$CF_TRANSACTION_PREPARED" ] && [ ! -L "$CF_TRANSACTION_PREPARED" ]; then PROFILE_INVENTORY=1
elif [ -e "$DONE" ] && ! platform_done_legacy "$DONE"; then PROFILE_INVENTORY=1; fi
if [ "$PROFILE_INVENTORY" = 1 ]; then
    FILES="$FILES usr/lib/couvrefeu/platform-bootstrap.sh usr/lib/couvrefeu/vendor-platform.sh etc/couvrefeu/platform-profile usr/lib/couvrefeu/activity.sh"
elif [ "${CF_PLATFORM_PROFILE:-strict}" != strict ]; then fail 'legacy journal cannot select vendor profile'; fi
DIRS='etc usr usr/sbin usr/lib usr/lib/couvrefeu etc/config etc/crontabs etc/couvrefeu'

for dep in sha256sum stat cp mv mkdir rmdir chmod awk sed cmp dd od tr sync wc; do
    command -v "$dep" >/dev/null 2>&1 || fail "missing dependency: $dep"
done

install_admission() {
if [ "${CF_TEST_MODE:-0}" = 1 ]; then LOCK=$ROOT/.couvrefeu-install.lock
else LOCK=/tmp/couvrefeu-install.lock; fi
INSTALL_LOCK_OWNED=0
if [ "${CF_TRANSACTION_RECOVER:-0}" != 1 ] && [ -e "${CF_TRANSACTION_RETIREMENT:-/nonexistent}" ]; then
    retirement_validate
    retirement_originals
    retirement_prepared_check
    if [ ! -e "$CF_TRANSACTION_OWNER" ]; then
        CF_TRANSACTION_PID=$$
        CF_TRANSACTION_BOOT=$(cat /proc/sys/kernel/random/boot_id)
        admission_identity=$(platform_process_identity "$$") || fail 'retirement process identity unavailable'
        CF_TRANSACTION_START=${admission_identity%%:*}
        CF_TRANSACTION_STATE=recovered
        platform_transaction_publish
        CF_TRANSACTION_OWNED=1
    fi
fi
if [ "${CF_TRANSACTION_RECOVER:-0}" = 1 ]; then
    : # Explicit recovery validates old ownership before retiring any fence.
elif [ "${CF_PLATFORM_NESTED:-0}" = 1 ] && [ -d "$LOCK" ]; then
    platform_transaction_mutex_check
    platform_private "$LOCK" 700
    platform_private "$LOCK/pid" 600
    platform_private "$LOCK/token" 600
    printf '%s\n' "$$" | cmp -s - "$LOCK/pid" || fail 'nested install lock owner mismatch'
    printf '%s\n' "${INSTALL_TOKEN:-}" | cmp -s - "$LOCK/token" || fail 'nested install lock token mismatch'
else
    mkdir -m 700 "$LOCK" 2>/dev/null || fail 'another install/recovery transaction is running'
    INSTALL_LOCK_OWNED=1
    printf '%s\n' "$$" > "$LOCK/pid"
    if [ -n "${CF_TRANSACTION_TOKEN:-}" ]; then INSTALL_TOKEN=$CF_TRANSACTION_TOKEN
    else INSTALL_TOKEN=$(platform_random_token) || fail 'installation entropy unavailable'; fi
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
trap 'unlock_install; platform_transaction_finish; platform_lock_release' 0
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
if [ "${CF_TRANSACTION_RECOVER:-0}" != 1 ] && { [ -e "$BASE/runtime/lock" ] || [ -L "$BASE/runtime/lock" ]; }; then
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
}

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

# Immutable PREPARED records are built outside managed directories and bound
# to the durable transaction before their fixed name is published.
prepared_manifest() (
    cd "$1" || exit 1
    for prepared_record in inventory directories profile release-absent $2; do
        sha256sum "$prepared_record" || exit 1
    done
)
prepared_records() {
    PREPARED_RECORDS=
    for rel in $FILES; do k=$(key "$rel"); PREPARED_RECORDS="$PREPARED_RECORDS $k.before $k.mtime"; done
    for rel in $DIRS; do k=$(key "$rel"); PREPARED_RECORDS="$PREPARED_RECORDS dir_$k dir_$k.metadata"; done
}
prepared_validate() {
    prepared_validate_noglob=0
    case $- in *f*) prepared_validate_noglob=1;; esac
    set +f
    prepared_tree=$1
    platform_private "$prepared_tree" 700
    if ! { [ -d "$prepared_tree" ] && [ ! -L "$prepared_tree" ]; }; then fail 'unsafe PREPARED tree'; fi
    platform_private "$prepared_tree/manifest" 600
    [ "$(sha256sum "$prepared_tree/manifest" | awk '{print $1}')" = "$CF_TRANSACTION_DIGEST" ] || fail 'PREPARED digest mismatch; preserved'
    platform_private "$prepared_tree/inventory" 600
    # Inventory controls only this fixed whitelist, with no duplicate/extra path.
    prepared_inventory=$(cat "$prepared_tree/inventory")
    prepared_fixed='usr/lib/couvrefeu/core.sh usr/lib/couvrefeu/rpc.sh usr/lib/couvrefeu/state.awk usr/lib/couvrefeu/firewall.sh usr/lib/couvrefeu/json.awk usr/lib/couvrefeu/rules.awk usr/lib/couvrefeu/install-common.sh usr/sbin/cfctl usr/sbin/cfctl-ssh etc/firewall.couvrefeu etc/config/firewall etc/sysupgrade.conf etc/crontabs/root etc/couvrefeu/protected etc/couvrefeu/state'
    case "$prepared_inventory" in "$prepared_fixed"*) ;; *) fail 'invalid PREPARED inventory';; esac
    prepared_optional=${prepared_inventory#"$prepared_fixed"}
    for prepared_option in ' etc/couvrefeu/rpc-allowed' ' usr/sbin/cfctl-scope' ' usr/lib/couvrefeu/platform-bootstrap.sh usr/lib/couvrefeu/vendor-platform.sh etc/couvrefeu/platform-profile usr/lib/couvrefeu/activity.sh'; do
        case "$prepared_optional" in "$prepared_option"*) prepared_optional=${prepared_optional#"$prepared_option"};; esac
    done
    [ -z "$prepared_optional" ] || fail 'invalid PREPARED inventory'
    FILES=$prepared_inventory
    prepared_records
    for prepared_record in inventory directories profile release-absent manifest $PREPARED_RECORDS; do
        platform_regular "$prepared_tree/$prepared_record"
        platform_private "$prepared_tree/$prepared_record" 600
        [ "$(stat -c '%h:%s' "$prepared_tree/$prepared_record" | awk -F: '$1==1&&$2<=8192{print "ok"}')" = ok ] || fail 'invalid PREPARED record shape'
    done
    for prepared_entry in "$prepared_tree"/* "$prepared_tree"/.[!.]* "$prepared_tree"/..?*; do
        [ -e "$prepared_entry" ] || [ -L "$prepared_entry" ] || continue
        case " inventory directories profile release-absent manifest $PREPARED_RECORDS " in *" ${prepared_entry##*/} "*) ;; *) fail 'unexpected PREPARED entry; preserved';; esac
    done
    printf '%s\n' "$DIRS" | cmp -s - "$prepared_tree/directories" || fail 'PREPARED directories mismatch'
    printf '%s\n' "$CF_PLATFORM_PROFILE" | cmp -s - "$prepared_tree/profile" || fail 'PREPARED profile mismatch'
    prepared_manifest "$prepared_tree" "$PREPARED_RECORDS" | cmp -s - "$prepared_tree/manifest" || fail 'PREPARED contents changed; preserved'
    for rel in $FILES; do
        k=$(key "$rel")
        if ! { valid_signature_record "$prepared_tree/$k.before" 1 && valid_mtime_record "$prepared_tree/$k.mtime"; }; then fail 'invalid PREPARED original record'; fi
    done
    if [ "$prepared_validate_noglob" = 1 ]; then set -f; fi
}
prepared_publish() {
    platform_transaction_mutex_check
    if [ "$CF_TRANSACTION_DIGEST" != none ] && [ -e "$CF_TRANSACTION_PREPARED" ]; then
        prepared_validate "$CF_TRANSACTION_PREPARED"
        prepared_originals
        return 0
    fi
    prepared_candidate=$CF_TRANSACTION_PREPARED.$CF_TRANSACTION_TOKEN
    mkdir -m 700 "$prepared_candidate" || fail 'PREPARED candidate collision'
    printf '%s\n' "$FILES" > "$prepared_candidate/inventory"
    printf '%s\n' "$DIRS" > "$prepared_candidate/directories"
    printf '%s\n' "$CF_PLATFORM_PROFILE" > "$prepared_candidate/profile"
    printf '%s\n' "$RELEASE_ABSENT" > "$prepared_candidate/release-absent"
    prepared_records
    for rel in $FILES; do k=$(key "$rel"); cp "$STAGE/$k.before" "$STAGE/$k.mtime" "$prepared_candidate/"; done
    for rel in $DIRS; do
        k=$(key "$rel"); cp "$STAGE/dir_$k" "$prepared_candidate/"
        if [ -d "$ROOT/$rel" ]; then metadata "$ROOT/$rel" > "$prepared_candidate/dir_$k.metadata"
        else printf '%s\n' absent > "$prepared_candidate/dir_$k.metadata"; fi
    done
    prepared_manifest "$prepared_candidate" "$PREPARED_RECORDS" > "$prepared_candidate/manifest"
    CF_TRANSACTION_DIGEST=$(sha256sum "$prepared_candidate/manifest" | awk '{print $1}')
    prepared_validate "$prepared_candidate"
    sync
    platform_transaction_publish
    platform_transaction_barrier prepared-bound
    if ! { [ ! -e "$CF_TRANSACTION_PREPARED" ] && [ ! -L "$CF_TRANSACTION_PREPARED" ]; }; then fail 'PREPARED publication collision'; fi
    mv "$prepared_candidate" "$CF_TRANSACTION_PREPARED"
    sync
    platform_transaction_barrier prepared
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_INSTALL_CRASH_AT:-}" = prepared ]; then kill -KILL "$$"; fi
}
prepared_originals() {
    prepared_original_tree=${1:-$CF_TRANSACTION_PREPARED}
    for rel in $FILES; do
        k=$(key "$rel")
        prepared_before=$(cat "$prepared_original_tree/$k.before")
        prepared_mtime=$(cat "$prepared_original_tree/$k.mtime")
        if ! { [ "$(signature "$ROOT/$rel")" = "$prepared_before" ] && exact_mtime "$ROOT/$rel" "$prepared_mtime"; }; then fail "PREPARED original drift: /$rel; preserved"; fi
    done
}
prepared_recovery_check() {
    PREPARED_RECOVERY_TREE=
    if [ "$CF_TRANSACTION_DIGEST" = none ]; then
        if [ -e "$BACKUP" ] || [ -L "$BACKUP" ] || [ -e "$CF_TRANSACTION_PREPARED" ] || [ -L "$CF_TRANSACTION_PREPARED" ]; then
            fail 'transaction has no bound baseline for existing managed journal; preserved'
        fi
        return 0
    fi
    if [ -e "$CF_TRANSACTION_PREPARED" ] || [ -L "$CF_TRANSACTION_PREPARED" ]; then
        PREPARED_RECOVERY_TREE=$CF_TRANSACTION_PREPARED
        if [ -e "$CF_TRANSACTION_PREPARED.$CF_TRANSACTION_TOKEN" ] || [ -L "$CF_TRANSACTION_PREPARED.$CF_TRANSACTION_TOKEN" ]; then fail 'ambiguous PREPARED publication; preserved'; fi
    else PREPARED_RECOVERY_TREE=$CF_TRANSACTION_PREPARED.$CF_TRANSACTION_TOKEN; fi
    prepared_validate "$PREPARED_RECOVERY_TREE"
}
prepared_partial_journal_check() (
    set +f
    [ -e "$BACKUP" ] || [ -L "$BACKUP" ] || exit 0
    platform_private "$BACKUP" 700
    if ! { [ -d "$BACKUP" ] && [ ! -L "$BACKUP" ]; }; then fail 'unsafe pre-ready journal; preserved'; fi
    prepared_allowed='ready.next release-absent release-absent.next'
    for pending_marker in ready release-absent; do prepared_allowed="$prepared_allowed $pending_marker.pending.$CF_TRANSACTION_TOKEN"; done
    for rel in $FILES; do k=$(key "$rel"); prepared_allowed="$prepared_allowed $k.before $k.mtime $k.copy $k.after $k.staged"; done
    for rel in $DIRS; do k=$(key "$rel"); prepared_allowed="$prepared_allowed dir_$k"; done
    for prepared_entry in "$BACKUP"/* "$BACKUP"/.[!.]* "$BACKUP"/..?*; do
        [ -e "$prepared_entry" ] || [ -L "$prepared_entry" ] || continue
        case " $prepared_allowed " in *" ${prepared_entry##*/} "*) ;;
            *) fail 'foreign pre-ready journal entry; preserved';; esac
        platform_regular "$prepared_entry"
        [ "$(stat -c '%u:%g:%h' "$prepared_entry")" = "$(id -u):$(id -g):1" ] || fail 'unsafe pre-ready journal record; preserved'
        case "${prepared_entry##*/}" in ready.pending.*|release-absent.pending.*)
            platform_private "$prepared_entry" 600
            prepared_pending_size=$(stat -c %s "$prepared_entry")
            [ "$prepared_pending_size" -le 2 ] || fail 'oversized pre-ready marker candidate; preserved'
            prepared_pending=$(cat "$prepared_entry" && printf '.') || fail 'unreadable pre-ready marker candidate'
            case "$prepared_pending_size:$prepared_pending" in '0:.'|'1:1.') ;;
                *) [ "$prepared_pending_size:$prepared_pending" = "$(printf '2:1\n.')" ] || fail 'invalid pre-ready marker candidate; preserved';; esac;;
        esac
    done
)
prepared_resume_publication() {
    [ "$CF_TRANSACTION_DIGEST" != none ] || return 0
    if [ ! -e "$CF_TRANSACTION_PREPARED" ] && [ ! -L "$CF_TRANSACTION_PREPARED" ]; then
        prepared_candidate=$CF_TRANSACTION_PREPARED.$CF_TRANSACTION_TOKEN
        prepared_validate "$prepared_candidate"
        mv "$prepared_candidate" "$CF_TRANSACTION_PREPARED"
        sync
    fi
    prepared_validate "$CF_TRANSACTION_PREPARED"
}
# Exact record read (cmp, never command substitution): 0 = complete record
# equal to $2 plus LF; 1 = torn write, a newline-free prefix of that value
# (empty included); 2 = anything else. A complete record is never a prefix.
recover_lock_record() {
    recovery_record_size=$(stat -c %s "$1") || return 2
    if printf '%s\n' "$2" | cmp -s - "$1"; then return 0; fi
    if [ "$recovery_record_size" -le "${#2}" ] &&
        printf '%s' "$2" | dd bs=1 count="$recovery_record_size" 2>/dev/null | cmp -s - "$1"; then return 1; fi
    return 2
}
# $2 is the owner's publication order: token-pid (core.sh cf_lock) or
# pid-token (install lock, platform_lock_acquire). Only the LAST record a
# kill interrupted may be torn; every earlier record must be complete.
recover_owned_lock_check() (
    set +f
    recovery_lock=$1
    [ -e "$recovery_lock" ] || [ -L "$recovery_lock" ] || return 0
    platform_private "$recovery_lock" 700
    if ! { [ -d "$recovery_lock" ] && [ ! -L "$recovery_lock" ]; }; then fail 'unsafe recovery lock; preserved'; fi
    for recovery_entry in "$recovery_lock"/* "$recovery_lock"/.[!.]* "$recovery_lock"/..?*; do
        [ -e "$recovery_entry" ] || [ -L "$recovery_entry" ] || continue
        case "${recovery_entry##*/}" in pid|token|reload) ;;
            *) fail 'foreign recovery lock entry; preserved';; esac
        platform_regular "$recovery_entry"
        platform_private "$recovery_entry" 600
        [ "$(stat -c '%h:%s' "$recovery_entry" | awk -F: '$1==1&&$2<=128{print "ok"}')" = ok ] || fail 'unsafe recovery lock record'
    done
    # A complete PID record naming a live process other than the retained
    # (already proven dead) installer is a live holder: never remove it.
    if [ -f "$recovery_lock/pid" ]; then
        recovery_live=$(awk 'NR==1&&$0~/^[1-9][0-9]*$/&&length($0)<=10{p=$0;next}{p="";exit}END{print p}' "$recovery_lock/pid")
        if [ -n "$recovery_live" ] && [ "$recovery_live" != "$CF_TRANSACTION_PID" ] &&
            printf '%s\n' "$recovery_live" | cmp -s - "$recovery_lock/pid" &&
            { kill -0 "$recovery_live" 2>/dev/null || [ -e "/proc/$recovery_live" ]; }; then
            fail 'live recovery lock holder; preserved'
        fi
    fi
    # New ownership precedes directory creation, so an absent or torn PID or
    # token is owned only under this intact durable transaction and mutex.
    recovery_token_state=absent
    if [ -f "$recovery_lock/token" ]; then
        recovery_token_state=complete
        recover_lock_record "$recovery_lock/token" "$CF_TRANSACTION_TOKEN" || case $? in
            1) recovery_token_state=torn;;
            *) fail 'recovery lock token mismatch; preserved';; esac
    fi
    recovery_pid_state=absent
    if [ -f "$recovery_lock/pid" ]; then
        recovery_pid_state=complete
        recover_lock_record "$recovery_lock/pid" "$CF_TRANSACTION_PID" || case $? in
            1) recovery_pid_state=torn;;
            *) fail 'recovery lock owner mismatch; preserved';; esac
    fi
    case "$2:$recovery_token_state:$recovery_pid_state" in
        # token-pid: a PID-only lock is a non-owned writer's; it must be exact.
        token-pid:*:absent|token-pid:complete:*|token-pid:absent:complete) ;;
        pid-token:absent:*|pid-token:*:complete) ;;
        *) fail 'recovery lock records out of publication order; preserved';;
    esac
)
recover_owned_lock() {
    recover_owned_lock_check "$1" "$2"
    [ -e "$1" ] || return 0
    rm -f "$1/pid" "$1/token" "$1/reload"
    rmdir "$1" || fail 'recovery lock cleanup failed'
}
recover_install_preflight() {
    RECOVERY_NEEDS_OWNER=0
    if retirement_present; then
        retirement_validate
        retirement_originals
        retirement_prepared_check
        if [ -e "$BACKUP" ] || [ -L "$BACKUP" ]; then journal_preflight cleanup; fi
        if [ ! -e "$CF_TRANSACTION_OWNER" ]; then
            RECOVERY_NEEDS_OWNER=1
            CF_TRANSACTION_STATE=recovered
            if [ -e "$LOCK" ] || [ -L "$LOCK" ] || [ -e "$BASE/runtime/lock" ] || [ -L "$BASE/runtime/lock" ]; then
                fail 'orphan compatibility lock alongside final retirement receipt; preserved'
            fi
        fi
    else
        [ -e "$CF_TRANSACTION_OWNER" ] || [ -L "$CF_TRANSACTION_OWNER" ] || fail 'legacy or absent transaction ownership; manual recovery required'
        platform_transaction_read
    fi
    if [ "$CF_TRANSACTION_STATE" = active ] && [ "$CF_TRANSACTION_BOOT" = "$(cat /proc/sys/kernel/random/boot_id)" ]; then
        if [ -e "/proc/$CF_TRANSACTION_PID" ]; then
            recovery_process=$(platform_process_identity "$CF_TRANSACTION_PID") || fail 'unknown transaction process identity; preserved'
            [ "${recovery_process%%:*}" != "$CF_TRANSACTION_START" ] || fail 'live transaction owner; preserved'
        else
            if ! { [ -r /proc/self/stat ] && ! kill -0 "$CF_TRANSACTION_PID" 2>/dev/null; }; then fail 'unknown transaction owner visibility; preserved'; fi
        fi
    fi
    recover_owned_lock_check "$LOCK" pid-token
    # Strict fixtures share the host /tmp; vendor fixtures relocate this path
    # (platform_lock_path is set by platform-bootstrap.sh).
    # shellcheck disable=SC2154
    if [ "${CF_TEST_MODE:-0}" != 1 ] || platform_vendor_selected; then
        if [ "$RECOVERY_NEEDS_OWNER" = 1 ] && { [ -e "$platform_lock_path" ] || [ -L "$platform_lock_path" ]; }; then fail 'orphan platform lock alongside retirement receipt; preserved'; fi
        recover_owned_lock_check "$platform_lock_path" pid-token
    fi
    # Runtime publication is mkdir, token, PID (core.sh cf_lock), all under
    # the transaction mutex this recovery now holds: an empty directory or a
    # token/PID prefix of this owner's records is that dead owner's kill window.
    if [ -e "$BASE/runtime/lock" ] || [ -L "$BASE/runtime/lock" ]; then recover_owned_lock_check "$BASE/runtime/lock" token-pid; fi
    if ! retirement_present; then
        prepared_recovery_check
        if [ "$CF_TRANSACTION_DIGEST" != none ]; then
            if [ ! -e "$BACKUP/ready" ] && [ ! -e "$RECOVERY/restoring" ]; then
                prepared_originals "$PREPARED_RECOVERY_TREE"
                prepared_partial_journal_check
            else preflight; fi
        fi
    fi
    safe_paths
    runtime_preflight recover-owned-lock
    recovery_fence_check
    recover_private_scratch check
}
recovery_fence_check() {
    if [ -e "$CF_TRANSACTION_FENCE" ] || [ -L "$CF_TRANSACTION_FENCE" ]; then
        platform_regular "$CF_TRANSACTION_FENCE"
        platform_private "$CF_TRANSACTION_FENCE" 600
        [ "$(stat -c '%h:%s' "$CF_TRANSACTION_FENCE")" = 1:65 ] || fail 'recovery fence shape mismatch; preserved'
        printf '%s\n' "$CF_TRANSACTION_TOKEN" | cmp -s - "$CF_TRANSACTION_FENCE" || fail 'recovery fence mismatch; preserved'
    fi
}
recover_install_lock() {
    platform_transaction_mutex
    # Every predicate is read-only until ALL ownership, namespaces, originals,
    # fences and private scratch pass. A refusal never consumes crash evidence.
    recover_install_preflight
    platform_transaction_barrier recovery-validated
    recovery_fence_check
    if [ ! -e "$CF_TRANSACTION_FENCE" ]; then
        recovery_fence_candidate=$(mktemp "$CF_TRANSACTION_PARENT/.couvrefeu-fence.XXXXXX")
        printf '%s\n' "$CF_TRANSACTION_TOKEN" > "$recovery_fence_candidate"
        sync
        mv "$recovery_fence_candidate" "$CF_TRANSACTION_FENCE"
        sync
    fi
    if ! retirement_present; then prepared_resume_publication; fi
    recover_private_scratch
    recover_owned_lock "$LOCK" pid-token
    if [ "${CF_TEST_MODE:-0}" != 1 ] || platform_vendor_selected; then recover_owned_lock "$platform_lock_path" pid-token; fi
    if [ -e "$BASE/runtime/lock" ] || [ -L "$BASE/runtime/lock" ]; then recover_owned_lock "$BASE/runtime/lock" token-pid; fi
    if [ "$RECOVERY_NEEDS_OWNER" = 1 ]; then
        CF_TRANSACTION_PID=$$
        CF_TRANSACTION_BOOT=$(cat /proc/sys/kernel/random/boot_id)
        recovery_identity=$(platform_process_identity "$$") || fail 'retirement recovery identity unavailable'
        CF_TRANSACTION_START=${recovery_identity%%:*}
    fi
    CF_TRANSACTION_STATE=recovered
    platform_transaction_publish
    printf '%s\n' '{"ok":true,"installLockRecovered":true,"uninstallRequired":true}'
}
recover_private_scratch() (
    set +f
    platform_done_candidate_check
    recovery_release_parent=$ROOT/etc
    recovery_release_container=$recovery_release_parent/.couvrefeu-release-candidate.$CF_TRANSACTION_TOKEN
    recovery_release_name=.couvrefeu-release-$CF_RELEASE_ID
    recovery_release_candidate=$recovery_release_container/$recovery_release_name
    if [ -e "$recovery_release_container" ] || [ -L "$recovery_release_container" ]; then
        platform_release_container_check "$recovery_release_container" "$recovery_release_name"
        if [ -e "$recovery_release_candidate" ] || [ -L "$recovery_release_candidate" ]; then
            platform_release_candidate_check "$recovery_release_candidate" "${CF_PLATFORM_LIB%/lib}"
        fi
    fi
    for rel in $FILES; do
        recovery_pending=$ROOT/$rel.couvrefeu-pending.$CF_TRANSACTION_TOKEN
        [ -e "$recovery_pending" ] || [ -L "$recovery_pending" ] || continue
        platform_regular "$recovery_pending"
        [ "$(stat -c '%u:%g' "$recovery_pending")" = "$(id -u):$(id -g)" ] || fail 'pending copy owner mismatch; preserved'
        recovery_links=$(stat -c %h "$recovery_pending")
        if [ "$recovery_links" != 1 ]; then
            if ! { [ "$recovery_links" = 2 ] && [ "$(stat -c '%d:%i' "$recovery_pending")" = "$(stat -c '%d:%i' "$ROOT/$rel.couvrefeu-tmp")" ]; }; then fail 'pending copy link collision; preserved'; fi
        fi
    done
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then recovery_stage=$ROOT/.couvrefeu-stage.$CF_TRANSACTION_TOKEN
    else recovery_stage=/tmp/couvrefeu-stage.$CF_TRANSACTION_TOKEN; fi
    if [ -e "$recovery_stage" ] || [ -L "$recovery_stage" ]; then
        platform_private "$recovery_stage" 700
        recovery_stage_names='cfctl cfctl-ssh cfctl-scope include protected state rpc-allowed rpc-allowed.live generation firewall sysupgrade cron platform-profile etc_couvrefeu_rpc-allowed.before etc_couvrefeu_rpc-allowed.mtime etc_couvrefeu_rpc-allowed.size'
        for rel in $FILES; do k=$(key "$rel"); recovery_stage_names="$recovery_stage_names $k.before $k.mtime $k.size"; done
        for rel in $DIRS; do k=$(key "$rel"); recovery_stage_names="$recovery_stage_names dir_$k"; done
        for recovery_entry in "$recovery_stage"/* "$recovery_stage"/.[!.]* "$recovery_stage"/..?*; do
            [ -e "$recovery_entry" ] || [ -L "$recovery_entry" ] || continue
            case " $recovery_stage_names " in *" ${recovery_entry##*/} "*) platform_regular "$recovery_entry";;
                *) if [ "${recovery_entry##*/}" = .delta ]; then
                    platform_private "$recovery_entry" 700
                    for recovery_delta in "$recovery_entry"/* "$recovery_entry"/.[!.]* "$recovery_entry"/..?*; do
                        [ -e "$recovery_delta" ] || [ -L "$recovery_delta" ] || continue
                        [ "${recovery_delta##*/}" = firewall ] || fail 'foreign staged UCI delta; preserved'
                        platform_regular "$recovery_delta"
                        platform_private "$recovery_delta" 600
                        [ "$(stat -c %h "$recovery_delta")" = 1 ] || fail 'staged UCI delta hardlink; preserved'
                    done
                    continue
                fi
                fail 'foreign owned stage entry; preserved';; esac
            [ "$(stat -c '%u:%g:%h' "$recovery_entry")" = "$(id -u):$(id -g):1" ] || fail 'owned stage metadata mismatch; preserved'
        done
    fi
    if [ "${1:-}" = check ]; then exit 0; fi
    # All collision checks precede deletion of any bound scratch.
    if [ -d "$recovery_release_container" ]; then
        if [ -d "$recovery_release_candidate" ]; then
            while read -r recovery_release_digest recovery_release_file; do rm -f "$recovery_release_candidate/$recovery_release_file"; done < "${CF_PLATFORM_LIB%/lib}/release.sha256"
            rm -f "$recovery_release_candidate/release.sha256"
            if [ -d "$recovery_release_candidate/lib" ]; then rmdir "$recovery_release_candidate/lib"; fi
            rmdir "$recovery_release_candidate" || fail 'release candidate cleanup incomplete'
        fi
        rmdir "$recovery_release_container" || fail 'release candidate container cleanup incomplete'
    fi
    for rel in $FILES; do rm -f "$ROOT/$rel.couvrefeu-pending.$CF_TRANSACTION_TOKEN"; done
    if [ -d "$recovery_stage" ]; then
        if [ -d "$recovery_stage/.delta" ]; then rm -f "$recovery_stage/.delta/firewall"; rmdir "$recovery_stage/.delta"; fi
        for recovery_name in $recovery_stage_names; do rm -f "$recovery_stage/$recovery_name"; done
        rmdir "$recovery_stage" || fail 'owned stage cleanup failed'
    fi
)
# Callers run this as a plain command under `set -e` (uninstall.sh), so any
# failed mkdir/cp/chmod below stops before `ready` with the journal retained.
prepared_materialize() {
    prepared_materialize_noglob=0
    case $- in *f*) prepared_materialize_noglob=1;; esac
    set +f
    prepared_resume_publication
    prepared_originals
    # A killed candidate publication is owned only under this intact baseline.
    prepared_partial_journal_check
    if [ ! -e "$BACKUP" ]; then mkdir -p "$BACKUP"; chmod 700 "$BACKUP"; fi
    chmod 700 "$BASE"
    for rel in $FILES; do
        k=$(key "$rel")
        cp "$CF_TRANSACTION_PREPARED/$k.before" "$CF_TRANSACTION_PREPARED/$k.mtime" "$BACKUP/"
        # Signature first: a kill never pairs a stale .after with new bytes.
        rm -f "$BACKUP/$k.after" "$BACKUP/$k.staged"
        if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CRASH_AT:-}" = "materialize-$k.cleared" ]; then kill -KILL "$$"; fi
        if [ "$rel" = etc/couvrefeu/platform-profile ]; then
            # Profile selection evidence, exactly as install stages it (never
            # the original's bytes): every later admission reads this record.
            cp "$CF_TRANSACTION_PREPARED/profile" "$BACKUP/$k.staged"; chmod 600 "$BACKUP/$k.staged"
        elif [ -e "$ROOT/$rel" ]; then cp -p "$ROOT/$rel" "$BACKUP/$k.staged"
        else : > "$BACKUP/$k.staged"; chmod 600 "$BACKUP/$k.staged"; fi
        if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CRASH_AT:-}" = "materialize-$k.staged" ]; then kill -KILL "$$"; fi
        signature "$BACKUP/$k.staged" > "$BACKUP/$k.after"
    done
    for rel in $DIRS; do k=$(key "$rel"); cp "$CF_TRANSACTION_PREPARED/dir_$k" "$BACKUP/"; done
    if [ "$(cat "$CF_TRANSACTION_PREPARED/release-absent")" = 1 ]; then phase release-absent; fi
    phase ready
    sync
    if [ "$prepared_materialize_noglob" = 1 ]; then set -f; fi
}
prepared_retire() {
    [ "${CF_TRANSACTION_DIGEST:-none}" != none ] || return 0
    if retirement_present; then
        retirement_validate
        retirement_prepared_check
        if [ -d "$CF_TRANSACTION_PREPARED" ]; then
            for prepared_record in inventory directories profile release-absent manifest $PREPARED_RECORDS; do
                rm -f "$CF_TRANSACTION_PREPARED/$prepared_record"
            done
            rmdir "$CF_TRANSACTION_PREPARED" || fail 'PREPARED retirement incomplete'
        fi
        return 0
    fi
    fail 'PREPARED retirement requires durable receipt; preserved'
}
# The single immutable receipt carries the baseline VALUES as well as hashes:
# the original proof remains available after any PREPARED record is removed.
retirement_present() {
    [ -e "$CF_TRANSACTION_RETIREMENT" ] || [ -L "$CF_TRANSACTION_RETIREMENT" ]
}
retirement_legacy_id() { printf '%s\n' 28b3278555e61239471497b7e806b05c8f5eed82b7cabca7ad8264d22cf6e539; }
retirement_legacy_manifest() { printf '%s\n' 71bd50c7ddde584404e738f349b95a8c0b5a828df34f491c8065f0c54070c463; }
retirement_legacy_bootstrap() { printf '%s\n' c254b9b4364d5f6e252126f4e37d05312cf7cec18b81515a3004b37009ce5820; }
retirement_target_names() {
    printf '%s\n' 'install.sh uninstall.sh cfctl cfctl-ssh cfctl-scope lib/core.sh lib/rpc.sh lib/firewall.sh lib/install-common.sh lib/state.awk lib/rules.awk lib/json.awk lib/vendor-platform.sh lib/activity.sh lib/platform-bootstrap.sh'
}
retirement_records() {
    RETIRE_RECORDS='inventory directories profile release-absent'
    [ "$RETIRE_LEGACY" != 1 ] || RETIRE_RECORDS="$RETIRE_RECORDS legacy-bootstrap.after"
    for retirement_rel in $FILES; do
        retirement_key=$(key "$retirement_rel")
        RETIRE_RECORDS="$RETIRE_RECORDS $retirement_key.before $retirement_key.mtime"
    done
    for retirement_rel in $DIRS; do
        retirement_key=$(key "$retirement_rel")
        if [ "$RETIRE_LEGACY" = 1 ]; then retirement_suffix=post-restore-metadata
        else retirement_suffix=metadata; fi
        RETIRE_RECORDS="$RETIRE_RECORDS dir_$retirement_key dir_$retirement_key.$retirement_suffix"
    done
}
retirement_value() {
    awk -F '\t' -v record="$1" 'NR>13 && $1==record {print $3}' "$CF_TRANSACTION_RETIREMENT"
}
retirement_validate() {
    platform_transaction_mutex_check
    platform_regular "$CF_TRANSACTION_RETIREMENT"
    platform_private "$CF_TRANSACTION_RETIREMENT" 600
    if [ "${CF_TEST_MODE:-0}" != 1 ] && [ "$(sed -n '5p' "$CF_TRANSACTION_RETIREMENT")" = none ]; then
        fail 'legacy callback quiescence is unproven; legacy receipt preserved for separately authorized recovery'
    fi
    [ "$(stat -c '%h:%s' "$CF_TRANSACTION_RETIREMENT" | awk -F: '$1==1&&$2<=32768{print "ok"}')" = ok ] || fail 'unsafe retirement receipt; preserved'
    awk -F '\t' 'NR==1{if($0!="CFRETIREMENT 2")exit 1}
        NR==2||NR==4||NR==10||NR==11||NR==12{if(length($0)!=64||$0~/[^0-9a-f]/)exit 1}
        NR==5{if($0!="none"&&(length($0)!=64||$0~/[^0-9a-f]/))exit 1}
        NR==3{if($0!~/^(strict|gl-xe3000-4.8.3-logd-011-v1|gl-xe3000-4.8.3-os-trust-v1)$/)exit 1}
        NR==6{if(length($0)>42||$0!~/^[0-9]+:[0-9]+$/)exit 1}
        NR==7{if($0!~/^[01]$/)exit 1}
        NR==13{n=split($0,p," ");if(n!=15)exit 1;for(i=1;i<=n;i++){if(split(p[i],a,":")!=2||length(a[2])!=64||a[2]~/[^0-9a-f]/)exit 1}}
        NR>13{if(NF!=3||$1~/[^a-z0-9_.-]/||length($2)!=64||$2~/[^0-9a-f]/||length($3)>8192)exit 1}
        END{if(NR<18)exit 1}' "$CF_TRANSACTION_RETIREMENT" || fail 'invalid retirement receipt; preserved'
    RETIRE_TARGET=$(sed -n '2p' "$CF_TRANSACTION_RETIREMENT")
    if ! {
        [ "$(sed -n '11p' "$CF_TRANSACTION_RETIREMENT")" = "$CF_RELEASE_ID" ] &&
        [ "$(sed -n '3p' "$CF_TRANSACTION_RETIREMENT")" = "$CF_PLATFORM_PROFILE" ]
    }; then fail 'retirement release/profile mismatch; preserved'; fi
    RETIRE_TOKEN=$(sed -n '4p' "$CF_TRANSACTION_RETIREMENT")
    RETIRE_DIGEST=$(sed -n '5p' "$CF_TRANSACTION_RETIREMENT")
    RETIRE_BASELINE_HASH=$(sed -n '12p' "$CF_TRANSACTION_RETIREMENT")
    RETIRE_LEGACY=0
    if [ "$RETIRE_TARGET" = "$(retirement_legacy_id)" ]; then
        RETIRE_LEGACY=1
        if ! { [ "$RETIRE_DIGEST" = none ] && [ "$(sed -n '10p' "$CF_TRANSACTION_RETIREMENT")" = "$(retirement_legacy_manifest)" ]; }; then fail 'legacy retirement trust binding mismatch'; fi
    else
        if ! { [ "$RETIRE_TARGET" = "$CF_RELEASE_ID" ] && [ "$RETIRE_DIGEST" = "$RETIRE_BASELINE_HASH" ]; }; then fail 'retirement target/baseline mismatch'; fi
    fi
    [ "$(sed -n '6p' "$CF_TRANSACTION_RETIREMENT")" = "$(stat -c '%d:%i' "$CF_TRANSACTION_MUTEX")" ] || fail 'retirement mutex mismatch; preserved'
    RETIRE_RELEASE_OWNED=$(sed -n '7p' "$CF_TRANSACTION_RETIREMENT")
    retirement_inventory=$(sed -n '8p' "$CF_TRANSACTION_RETIREMENT")
    retirement_fixed='usr/lib/couvrefeu/core.sh usr/lib/couvrefeu/rpc.sh usr/lib/couvrefeu/state.awk usr/lib/couvrefeu/firewall.sh usr/lib/couvrefeu/json.awk usr/lib/couvrefeu/rules.awk usr/lib/couvrefeu/install-common.sh usr/sbin/cfctl usr/sbin/cfctl-ssh etc/firewall.couvrefeu etc/config/firewall etc/sysupgrade.conf etc/crontabs/root etc/couvrefeu/protected etc/couvrefeu/state'
    case "$retirement_inventory" in "$retirement_fixed"*) ;; *) fail 'invalid retirement inventory';; esac
    retirement_optional=${retirement_inventory#"$retirement_fixed"}
    for retirement_option in ' etc/couvrefeu/rpc-allowed' ' usr/sbin/cfctl-scope' ' usr/lib/couvrefeu/platform-bootstrap.sh usr/lib/couvrefeu/vendor-platform.sh etc/couvrefeu/platform-profile usr/lib/couvrefeu/activity.sh'; do
        case "$retirement_optional" in "$retirement_option"*) retirement_optional=${retirement_optional#"$retirement_option"};; esac
    done
    [ -z "$retirement_optional" ] || fail 'invalid retirement inventory'
    [ "$(sed -n '9p' "$CF_TRANSACTION_RETIREMENT")" = "$DIRS" ] || fail 'retirement directory inventory mismatch'
    FILES=$retirement_inventory
    prepared_records
    retirement_records
    retirement_expected=$(for retirement_record in $RETIRE_RECORDS; do printf '%s\n' "$retirement_record"; done)
    [ "$(awk -F '\t' 'NR>13{print $1}' "$CF_TRANSACTION_RETIREMENT")" = "$retirement_expected" ] || fail 'retirement record inventory mismatch'
    [ "$(awk -F '\t' 'NR>13{print $2 "  " $1}' "$CF_TRANSACTION_RETIREMENT" | sha256sum | awk '{print $1}')" = "$RETIRE_BASELINE_HASH" ] || fail 'retirement baseline digest mismatch'
    retirement_tab=$(printf '\t')
    while IFS="$retirement_tab" read -r retirement_record retirement_hash retirement_data; do
        [ "$(printf '%s\n' "$retirement_data" | sha256sum | awk '{print $1}')" = "$retirement_hash" ] || fail 'retirement baseline value mismatch'
    done <<EOF
$(awk 'NR>13' "$CF_TRANSACTION_RETIREMENT")
EOF
    if ! {
        [ "$(retirement_value inventory)" = "$FILES" ] && [ "$(retirement_value directories)" = "$DIRS" ] &&
        [ "$(retirement_value profile)" = "$CF_PLATFORM_PROFILE" ] &&
        [ "$(retirement_value release-absent)" = "$RETIRE_RELEASE_OWNED" ]
    }; then fail 'retirement binding mismatch'; fi
    retirement_source=${CF_PLATFORM_LIB%/lib}
    if [ "$RETIRE_LEGACY" = 1 ]; then
        [ "$(retirement_value legacy-bootstrap.after)" = "$(retirement_legacy_bootstrap):644:$(id -u):$(id -g)" ] || fail 'legacy retirement bootstrap binding mismatch'
    else
        [ "$(sha256sum "$retirement_source/release.sha256" | awk '{print $1}')" = "$(sed -n '10p' "$CF_TRANSACTION_RETIREMENT")" ] || fail 'retirement source manifest mismatch'
    fi
    RETIRE_TARGET_PAIRS=$(sed -n '13p' "$CF_TRANSACTION_RETIREMENT")
    retirement_names=$(for retirement_pair in $RETIRE_TARGET_PAIRS; do printf '%s ' "${retirement_pair%:*}"; done)
    [ "${retirement_names% }" = "$(retirement_target_names)" ] || fail 'retirement target manifest inventory mismatch'
    retirement_manifest_hash=$(for retirement_pair in $RETIRE_TARGET_PAIRS; do printf '%s  %s\n' "${retirement_pair##*:}" "${retirement_pair%:*}"; done | sha256sum | awk '{print $1}')
    [ "$retirement_manifest_hash" = "$(sed -n '10p' "$CF_TRANSACTION_RETIREMENT")" ] || fail 'retirement target manifest hash mismatch'
    if [ -e "$CF_TRANSACTION_OWNER" ] || [ -L "$CF_TRANSACTION_OWNER" ]; then
        platform_transaction_read
        if ! { [ "$CF_TRANSACTION_TOKEN" = "$RETIRE_TOKEN" ] && [ "$CF_TRANSACTION_DIGEST" = "$RETIRE_DIGEST" ]; }; then fail 'retirement owner mismatch; preserved'; fi
    else
        CF_TRANSACTION_TOKEN=$RETIRE_TOKEN
        CF_TRANSACTION_DIGEST=$RETIRE_DIGEST
    fi
    if [ -e "$CF_TRANSACTION_FENCE" ] || [ -L "$CF_TRANSACTION_FENCE" ]; then
        platform_regular "$CF_TRANSACTION_FENCE"
        platform_private "$CF_TRANSACTION_FENCE" 600
        if ! { [ "$(stat -c %h "$CF_TRANSACTION_FENCE")" = 1 ] &&
            printf '%s\n' "$RETIRE_TOKEN" | cmp -s - "$CF_TRANSACTION_FENCE"; }; then fail 'retirement fence mismatch; preserved'; fi
    fi
}
retirement_originals() {
    safe_paths
    for retirement_rel in $FILES; do
        retirement_key=$(key "$retirement_rel")
        exact_file "$ROOT/$retirement_rel" "$(retirement_value "$retirement_key.before")" "$(retirement_value "$retirement_key.mtime")" || fail "retirement original drift: $retirement_rel; preserved"
    done
    for retirement_rel in $DIRS; do
        retirement_key=$(key "$retirement_rel")
        if [ "$RETIRE_LEGACY" = 1 ]; then retirement_suffix=post-restore-metadata
        else retirement_suffix=metadata; fi
        retirement_metadata=$(retirement_value "dir_$retirement_key.$retirement_suffix")
        if [ "$retirement_metadata" = absent ]; then
            if ! { [ ! -e "$ROOT/$retirement_rel" ] && [ ! -L "$ROOT/$retirement_rel" ]; }; then fail "retirement directory drift: $retirement_rel; preserved"; fi
        else
            if ! {
                [ -d "$ROOT/$retirement_rel" ] && [ ! -L "$ROOT/$retirement_rel" ] &&
                [ "$(metadata "$ROOT/$retirement_rel")" = "$retirement_metadata" ]
            }; then fail "retirement directory drift: $retirement_rel; preserved"; fi
        fi
    done
}
retirement_prepared_check() (
    # cfctl disables pathname expansion for its public argv. Tree validation
    # must still inspect every entry, independently of the caller's shell flags.
    set +f
    if [ "$RETIRE_LEGACY" = 1 ]; then
        if ! { [ ! -e "$CF_TRANSACTION_PREPARED" ] && [ ! -L "$CF_TRANSACTION_PREPARED" ]; }; then fail 'unexpected legacy PREPARED tree; preserved'; fi
        return 0
    fi
    [ -e "$CF_TRANSACTION_PREPARED" ] || [ -L "$CF_TRANSACTION_PREPARED" ] || return 0
    platform_private "$CF_TRANSACTION_PREPARED" 700
    if ! { [ -d "$CF_TRANSACTION_PREPARED" ] && [ ! -L "$CF_TRANSACTION_PREPARED" ]; }; then fail 'unsafe retiring PREPARED tree'; fi
    for retirement_entry in "$CF_TRANSACTION_PREPARED"/* "$CF_TRANSACTION_PREPARED"/.[!.]* "$CF_TRANSACTION_PREPARED"/..?*; do
        [ -e "$retirement_entry" ] || [ -L "$retirement_entry" ] || continue
        retirement_name=${retirement_entry##*/}
        case " inventory directories profile release-absent manifest $PREPARED_RECORDS " in *" $retirement_name "*) ;; *) fail 'foreign retiring PREPARED entry; preserved';; esac
        platform_regular "$retirement_entry"
        platform_private "$retirement_entry" 600
        [ "$(stat -c %h "$retirement_entry")" = 1 ] || fail 'hardlinked retiring PREPARED record; preserved'
        retirement_expected_hash=$(awk -F '\t' -v record="$retirement_name" 'NR>13&&$1==record{print $2}' "$CF_TRANSACTION_RETIREMENT")
        [ "$retirement_name" != manifest ] || retirement_expected_hash=$RETIRE_DIGEST
        [ "$(sha256sum "$retirement_entry" | awk '{print $1}')" = "$retirement_expected_hash" ] || fail 'retiring PREPARED contents changed; preserved'
    done
)
retirement_publish() {
    if retirement_present; then retirement_validate; retirement_originals; retirement_prepared_check; return 0; fi
    RETIRE_LEGACY=${RETIRE_LEGACY:-0}
    if [ "$RETIRE_LEGACY" = 1 ]; then
        # Only a complete, validated legacy journal can supply a post-restoration
        # snapshot. This never adopts pre-journal or missing historical proof.
        journal_preflight full
        valid_marker "$BACKUP/ready" || fail 'legacy retirement requires complete journal'
        if ! { [ "$CF_TRANSACTION_DIGEST" = none ] && [ "$RETIRE_TARGET" = "$(retirement_legacy_id)" ]; }; then fail 'invalid legacy retirement provenance'; fi
    else
        prepared_validate "$CF_TRANSACTION_PREPARED"
        RETIRE_TARGET=$CF_RELEASE_ID
    fi
    if [ "$RETIRE_LEGACY" = 1 ]; then retirement_release_owned=1
    else retirement_release_owned=$(cat "$CF_TRANSACTION_PREPARED/release-absent"); fi
    retirement_records
    retirement_records_candidate=$(mktemp "$CF_TRANSACTION_PARENT/.couvrefeu-retirement-records.XXXXXX") || fail 'retirement records candidate failed'
    for retirement_record in $RETIRE_RECORDS; do
        if [ "$RETIRE_LEGACY" = 1 ]; then
            case "$retirement_record" in
                inventory) retirement_data=$FILES;;
                directories) retirement_data=$DIRS;;
                profile) retirement_data=$CF_PLATFORM_PROFILE;;
                release-absent) retirement_data=1;;
                legacy-bootstrap.after) retirement_data=$(cat "$BACKUP/usr_lib_couvrefeu_platform-bootstrap.sh.after");;
                *.post-restore-metadata)
                    retirement_key=${retirement_record#dir_}; retirement_key=${retirement_key%.post-restore-metadata}
                    retirement_directory=
                    for retirement_rel in $DIRS; do
                        [ "$(key "$retirement_rel")" != "$retirement_key" ] || retirement_directory=$ROOT/$retirement_rel
                    done
                    [ -n "$retirement_directory" ] || fail 'legacy directory snapshot inventory mismatch'
                    if [ -d "$retirement_directory" ]; then retirement_data=$(metadata "$retirement_directory")
                    else retirement_data=absent; fi;;
                *) retirement_data=$(cat "$BACKUP/$retirement_record");;
            esac
        else retirement_data=$(cat "$CF_TRANSACTION_PREPARED/$retirement_record"); fi
        printf '%s\t%s\t%s\n' "$retirement_record" "$(printf '%s\n' "$retirement_data" | sha256sum | awk '{print $1}')" "$retirement_data"
    done > "$retirement_records_candidate"
    RETIRE_BASELINE_HASH=$(awk -F '\t' '{print $2 "  " $1}' "$retirement_records_candidate" | sha256sum | awk '{print $1}')
    if [ "$RETIRE_LEGACY" != 1 ]; then
        [ "$RETIRE_BASELINE_HASH" = "$CF_TRANSACTION_DIGEST" ] || fail 'retirement baseline changed before publication'
        retirement_target_manifest=${CF_PLATFORM_LIB%/lib}/release.sha256
    else retirement_target_manifest=$RELEASE_DIR/release.sha256; fi
    retirement_target_hash=$(sha256sum "$retirement_target_manifest" | awk '{print $1}')
    RETIRE_TARGET_PAIRS=$(awk 'BEGIN{s=""}{printf "%s%s:%s",s,$2,$1;s=" "}END{print ""}' "$retirement_target_manifest")
    retirement_candidate=$(mktemp "$CF_TRANSACTION_PARENT/.couvrefeu-retirement.XXXXXX") || fail 'retirement candidate creation failed'
    {
        printf 'CFRETIREMENT 2\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
            "$RETIRE_TARGET" "$CF_PLATFORM_PROFILE" "$CF_TRANSACTION_TOKEN" "$CF_TRANSACTION_DIGEST" \
            "$(stat -c '%d:%i' "$CF_TRANSACTION_MUTEX")" "$retirement_release_owned" "$FILES" "$DIRS" \
            "$retirement_target_hash" "$CF_RELEASE_ID" "$RETIRE_BASELINE_HASH" "$RETIRE_TARGET_PAIRS"
        cat "$retirement_records_candidate"
    } > "$retirement_candidate"
    chmod 600 "$retirement_candidate"
    sync
    if ! { [ ! -e "$CF_TRANSACTION_RETIREMENT" ] && [ ! -L "$CF_TRANSACTION_RETIREMENT" ]; }; then fail 'retirement receipt collision; preserved'; fi
    mv "$retirement_candidate" "$CF_TRANSACTION_RETIREMENT"
    rm -f "$retirement_records_candidate"
    sync
    retirement_validate
    retirement_originals
    retirement_prepared_check
    platform_transaction_barrier retirement-published
}
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
scope_core() (
    CF_BASE=$ROOT
    case "$0" in */install.sh) CF_LIB=$SOURCE/lib;; *) CF_LIB=$CF_PLATFORM_LIB;; esac
    [ -n "$CF_LIB" ] || fail 'missing verified scope library'
    . "$CF_LIB/core.sh"
    "$@"
)
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
journal_preflight() (
    set +f
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
    allowed_entries='release-absent ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next firewall.transaction firewall.transaction.next etc_config_firewall.after.next firewall.pending etc_config_firewall.staged.couvrefeu-tmp cron-quiescing cron-reconciled'
    record_entries='release-absent ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next firewall.transaction firewall.transaction.next etc_config_firewall.after.next cron-quiescing cron-reconciled'
    for pending_marker in release-absent ready activated complete kernel-cleaned no-kernel-mutations restoring restored cron-quiescing cron-reconciled; do
        marker_pending=$pending_marker.pending.${CF_TRANSACTION_TOKEN:-$INSTALL_TOKEN}
        allowed_entries="$allowed_entries $marker_pending"
        record_entries="$record_entries $marker_pending"
    done
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
    for marker in release-absent ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next cron-reconciled; do
        if [ -e "$BACKUP/$marker" ]; then
            marker_version=1
            case "$marker" in restored|restored.next) marker_version=2;; esac
            valid_marker "$BACKUP/$marker" "$marker_version" || fail "invalid transaction marker: $marker"
        fi
    done
    cron_quiescence_preflight
    [ "${1:-}" != cleanup ] || return 0
    for rel in $DIRS; do
        k=$(key "$rel")
        [ -f "$BACKUP/dir_$k" ] || fail "missing directory record: $rel"
        awk '($0!="absent" && (length($0)<3 || length($0)>4 || $0 ~ /[^0-7]/)) {bad=1} END {exit bad || NR!=1}' "$BACKUP/dir_$k" || fail "invalid directory record: $rel"
    done
)

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
            if ! { [ "$before" != absent ] && valid_inode_record "$BACKUP/$k.inode"; }; then fail "invalid original inode record: $rel"; fi
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
    journal_record "$1" "${2:-1}"
}
journal_record() {
    journal_name=$1 journal_value=$2
    journal_candidate=$BACKUP/$journal_name.pending.${CF_TRANSACTION_TOKEN:-$INSTALL_TOKEN}
    if [ -e "$journal_candidate" ] || [ -L "$journal_candidate" ]; then
        platform_regular "$journal_candidate"
        platform_private "$journal_candidate" 600
        [ "$(stat -c '%h:%s' "$journal_candidate" | awk -F: '$1==1&&$2<=512{print "ok"}')" = ok ] || fail 'transaction marker candidate collision'
        rm -f "$journal_candidate"
    fi
    (set -C; : > "$journal_candidate") || fail 'transaction marker candidate acquisition failed'
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_INSTALL_CRASH_AT:-}" = "marker-empty-$journal_name" ]; then kill -KILL "$$"; fi
    printf '%s\n' "$journal_value" > "$journal_candidate" || fail 'transaction marker candidate write failed'
    sync "$journal_candidate" 2>/dev/null
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_INSTALL_CRASH_AT:-}" = "marker-$journal_name" ]; then kill -KILL "$$"; fi
    mv -f "$journal_candidate" "$BACKUP/$journal_name" || fail 'transaction marker publication failed'
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
                # A successfully published cron table may already be observable.
                # Preserve its original/provenance even for a transient verifier
                # failure; rollback here would erase the only publication proof.
                if [ "$3" = etc_crontabs_root ]; then
                    trap 'exit 1' 1 2 15
                    fail "cron original verification failed after publication: $2; installed table and original retained"
                fi
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
    if [ "${CF_TRANSACTION_OWNED:-0}" = 1 ]; then
        # A partial copy has an exact, token-bound private name. The public
        # rename source appears only after complete bytes/metadata are proved.
        pending=$dst.couvrefeu-pending.$CF_TRANSACTION_TOKEN
        if ! { [ ! -e "$pending" ] && [ ! -L "$pending" ]; }; then fail "pending copy collision: $pending"; fi
        (set -C; : > "$pending") || fail 'pending copy acquisition failed'
        cp -p "$src" "$pending"
        chmod "$(stat -c %a "$src")" "$pending"
        [ "$(signature "$pending")" = "$(signature "$src")" ] || fail "staged copy metadata mismatch: $dst; journal retained"
        sync "$pending" 2>/dev/null
        ln -T -n "$pending" "$tmp" || fail 'temporary no-replace publication failed'
        rm -f "$pending"
    else
        cp -p "$src" "$tmp"
        chmod "$(stat -c %a "$src")" "$tmp"
        [ "$(signature "$tmp")" = "$(signature "$src")" ] || fail "staged copy metadata mismatch: $dst; journal retained"
    fi
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
            if ! { [ -f "$CF_BACKEND_DIR/core" ] && [ ! -L "$CF_BACKEND_DIR/core" ] && [ -x "$CF_BACKEND_DIR/core" ]; }; then fail 'unsafe fixture core backend'; fi
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
    else platform_initial_write; env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /etc/init.d/firewall reload; fi
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
    # Retain exclusion through the direct init/ubus caller, including a late
    # service-set after parent death. The already-running procd receives JSON,
    # not this descriptor; its daemon/jobs enter generation-bound cfctl normally.
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
    service_source_gate
    cron_preflight_script=$(cron_script) || fail 'cron init script unavailable; no installation made'
    if ! { [ -f "$cron_preflight_script" ] && [ -x "$cron_preflight_script" ] &&
        grep -qx 'USE_PROCD=1' "$cron_preflight_script"; }; then
        fail "cron init script unavailable or not procd-based: $cron_preflight_script; no installation made"
    fi
    cron_service enabled || fail 'cron service is not enabled at boot; minute expiry would stop after reboot; no installation made'
}
service_source_gate() { platform_service_sources; }
cron_instance() (
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then fixture_tools; cron_tools=$CF_BACKEND_DIR/; set --
    else cron_tools=; set -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C; fi
    cron_reply=$("$@" "${cron_tools}ubus" call service list '{"name":"cron"}') || fail 'cron service state unavailable; journal retained'
    [ "$(printf '%s' "$cron_reply" | wc -c)" -le 32768 ] || fail 'oversized cron service state'
    cron_live=$(printf '%s\n' "$cron_reply" | "$@" "${cron_tools}jsonfilter" -e '@.cron.instances[*].running') || fail 'cron service state invalid'
    case "$cron_live" in
        ''|false) printf '%s\n' stopped; exit 0;;
        true) ;;
        *) fail 'ambiguous cron service instances; journal retained';;
    esac
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then
        # Shared kernel fixtures expose their loaded-table model explicitly.
        # The older filesystem double stores the same model in crond-table.
        # Neither model is evidence for daemon/process behavior on a router.
        cron_fixture_generation=$(printf '%s\n' "$cron_reply" | "$@" "${cron_tools}jsonfilter" -e '@.cron.instances[*].fixtureGeneration' 2>/dev/null) || cron_fixture_generation=
        case "$cron_fixture_generation" in *[!0-9a-f]*|'') ;;
            *) if [ "${#cron_fixture_generation}" = 64 ]; then printf 'fixture:%s\n' "$cron_fixture_generation"; exit 0; fi;;
        esac
        if ! { [ -f "$ROOT/crond-table" ] && [ ! -L "$ROOT/crond-table" ]; }; then fail 'fixture cron generation missing'; fi
        printf 'fixture:%s\n' "$(sha256sum "$ROOT/crond-table" | awk '{print $1}')"
        exit 0
    fi
    cron_pid=$(printf '%s\n' "$cron_reply" | "$@" "${cron_tools}jsonfilter" -e '@.cron.instances[*].pid') || fail 'cron service PID unavailable'
    case "$cron_pid" in ''|*[!0-9]*) fail 'ambiguous cron service PID';; esac
    if ! { [ "${#cron_pid}" -le 10 ] && [ "$cron_pid" -gt 1 ]; }; then fail 'invalid cron service PID'; fi
    cron_identity=$(platform_process_identity "$cron_pid") || fail 'cron process identity unavailable'
    printf '%s:%s\n' "$cron_pid" "${cron_identity%%:*}"
)
cron_old_gone() {
    case "$cron_old" in stopped) return 0;;
        fixture:*) [ "$(cron_instance)" != "$cron_old" ]; return;;
    esac
    [ "$cron_boot" = "$(cat /proc/sys/kernel/random/boot_id)" ] || return 0
    cron_old_pid=${cron_old%%:*}; cron_old_start=${cron_old#*:}
    if [ -e "/proc/$cron_old_pid" ]; then
        cron_seen=$(platform_process_identity "$cron_old_pid") || fail 'unknown old cron identity; journal retained'
        [ "${cron_seen%%:*}" != "$cron_old_start" ]
    else
        [ -r /proc/self/stat ] && ! kill -0 "$cron_old_pid" 2>/dev/null
    fi
}
# For this source ID, a successful cron publication never rolls its saved
# original back on a later verifier failure. Before any quiescence record,
# these endpoints therefore prove that this installation never exposed a table.
cron_unpublished() {
    [ "${CF_TRANSACTION_DIGEST:-none}" != none ] || return 1
    for cron_path in "$BACKUP/etc_crontabs_root.original" "$ROOT/etc/crontabs/root.couvrefeu-tmp" "$ROOT/etc/crontabs/root.couvrefeu-pending.$CF_TRANSACTION_TOKEN"; do
        [ ! -e "$cron_path" ] && [ ! -L "$cron_path" ] || return 1
    done
    exact_file "$ROOT/etc/crontabs/root" "$(cat "$BACKUP/etc_crontabs_root.before")" "$(cat "$BACKUP/etc_crontabs_root.mtime")"
}
cron_quiescence_capture() {
    cron_old=$(cron_instance)
    cron_boot=$(cat /proc/sys/kernel/random/boot_id)
    cron_mode=replace
    if cron_unpublished; then cron_mode=unpublished; fi
}
cron_quiescence_bytes() {
    if [ "${CF_TRANSACTION_DIGEST:-none}" = none ]; then
        printf 'CFCRON 1\n%s\n%s\n' "$cron_boot" "$cron_old"
    else
        printf 'CFCRON 2\n%s\n%s\n%s\n%s\n' "$cron_boot" "$cron_old" "$cron_mode" "$CF_TRANSACTION_TOKEN"
    fi
}
cron_quiescence_read() {
    platform_regular "$BACKUP/cron-quiescing"
    platform_private "$BACKUP/cron-quiescing" 600
    [ "$(stat -c '%h:%s' "$BACKUP/cron-quiescing" | awk -F: '$1==1&&$2<=512{print "ok"}')" = ok ] || fail 'unsafe cron quiescence record'
    cron_format=$(sed -n '1p' "$BACKUP/cron-quiescing")
    cron_boot=$(sed -n '2p' "$BACKUP/cron-quiescing")
    cron_old=$(sed -n '3p' "$BACKUP/cron-quiescing")
    [ "${#cron_boot}" = 36 ] || fail 'invalid cron boot identity'
    case "$cron_boot" in *[!0-9a-f-]*) fail 'invalid cron boot identity';; esac
    case "$cron_old" in
        stopped) ;;
        fixture:*)
            [ "${CF_TEST_MODE:-0}" = 1 ] || fail 'fixture cron identity in production'
            cron_hash=${cron_old#fixture:}
            [ "${#cron_hash}" = 64 ] || fail 'invalid fixture cron identity'
            case "$cron_hash" in *[!0-9a-f]*) fail 'invalid fixture cron identity';; esac;;
        *) printf '%s\n' "$cron_old" | awk -F: 'NF!=2||length($1)>10||$1!~/^[0-9]+$/||$1<=1||length($2)>20||$2!~/^[0-9]+$/{bad=1}END{exit bad||NR!=1}' || fail 'invalid old cron identity';;
    esac
    cron_mode=replace
    case "$cron_format" in
        'CFCRON 1') printf 'CFCRON 1\n%s\n%s\n' "$cron_boot" "$cron_old" | cmp -s - "$BACKUP/cron-quiescing" || fail 'invalid cron quiescence record';;
        'CFCRON 2')
            [ "${CF_TRANSACTION_DIGEST:-none}" != none ] || fail 'unbound cron quiescence record'
            cron_mode=$(sed -n '4p' "$BACKUP/cron-quiescing")
            case "$cron_mode" in unpublished|replace) ;; *) fail 'invalid cron quiescence mode';; esac
            cron_quiescence_bytes | cmp -s - "$BACKUP/cron-quiescing" || fail 'invalid cron quiescence binding';;
        *) fail 'invalid cron quiescence version';;
    esac
}
cron_quiescence_preflight() (
    cron_pending=$BACKUP/cron-quiescing.pending.${CF_TRANSACTION_TOKEN:-$INSTALL_TOKEN}
    if [ -e "$BACKUP/cron-quiescing" ] || [ -L "$BACKUP/cron-quiescing" ]; then
        cron_quiescence_read
        if ! { [ ! -e "$cron_pending" ] && [ ! -L "$cron_pending" ]; }; then fail 'ambiguous cron quiescence publication'; fi
    elif [ -e "$cron_pending" ] || [ -L "$cron_pending" ]; then
        platform_regular "$cron_pending"
        platform_private "$cron_pending" 600
        [ "$(stat -c %h "$cron_pending")" = 1 ] || fail 'cron quiescence candidate hardlink'
        service_source_gate
        cron_quiescence_capture
        cron_pending_size=$(stat -c %s "$cron_pending")
        # Coarse bound before tr/sed scan the file; the exact bound (the live
        # record's length, cron_pending_limit) needs the parsed lines below.
        [ "$cron_pending_size" -le 512 ] || fail 'oversized cron quiescence candidate'
        # Boot and daemon lines record the killed writer's moment. A later boot
        # or daemon only means that old daemon is gone (as cron_old_gone): check
        # their shape, then bind header, live mode and token byte for byte. This
        # subshell only validates; cron_restore_barrier re-captures LIVE boot and
        # daemon identity before it publishes the record.
        cron_pending_lines=$(tr -dc '\n' < "$cron_pending" | wc -c)
        cron_boot=$(sed -n '2p' "$cron_pending")
        cron_old=$(sed -n '3p' "$cron_pending")
        cron_boot_complete=0 cron_old_complete=0
        [ "$cron_pending_lines" -lt 2 ] || cron_boot_complete=1
        [ "$cron_pending_lines" -lt 3 ] || cron_old_complete=1
        printf '%s\n' "$cron_boot" | awk -v full="$cron_boot_complete" 'NR==1{ok=$0!~/[^0-9a-f-]/&&(full?length($0)==36:length($0)<=36)}NR>1{ok=0}END{exit !ok}' || fail 'invalid cron quiescence candidate boot identity'
        printf '%s\n' "$cron_old" | awk -v full="$cron_old_complete" -v fixture="${CF_TEST_MODE:-0}" '
            function ids(v, partial,  n, a) {
                if (v ~ /^[0-9]+:[0-9]+$/) { n = split(v, a, ":"); return length(a[1]) <= 10 && a[1] + 0 > 1 && length(a[2]) <= 20 }
                if (!partial) return 0
                if (v ~ /^[0-9]*$/) return length(v) <= 10
                if (v ~ /^[0-9]+:$/) return length(v) <= 11
                return 0
            }
            NR==1 {
                v = $0
                if (full) ok = v == "stopped" || (fixture == 1 && v ~ /^fixture:[0-9a-f]+$/ && length(v) == 72) || ids(v, 0)
                else ok = v == "" || index("stopped", v) == 1 || (fixture == 1 && (index("fixture:", v) == 1 || (v ~ /^fixture:[0-9a-f]*$/ && length(v) <= 72))) || ids(v, 1)
            }
            NR>1 {ok=0}
            END {exit !ok}' || fail 'invalid cron quiescence candidate daemon identity'
        cron_pending_limit=$(cron_quiescence_bytes | wc -c)
        [ "$cron_pending_size" -le "$cron_pending_limit" ] || fail 'oversized cron quiescence candidate'
        cron_quiescence_bytes | dd bs=1 count="$cron_pending_size" 2>/dev/null | cmp -s - "$cron_pending" || fail 'invalid cron quiescence candidate prefix'
    fi
)
cron_restore_barrier() {
    [ ! -f "$BACKUP/cron-reconciled" ] || return 0
    service_source_gate
    if [ ! -e "$BACKUP/cron-quiescing" ]; then
        cron_quiescence_preflight
        cron_quiescence_capture
        journal_record cron-quiescing "$(cron_quiescence_bytes)"
    fi
    cron_quiescence_read
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CRASH_AT:-}" = cron-quiescing ]; then kill -KILL "$$"; fi
    # Restore only cron first. The installed executable remains fenced while
    # the daemon may still hold the installation's old in-memory table.
    cron_before=$(cat "$BACKUP/etc_crontabs_root.before")
    cron_mtime=$(cat "$BACKUP/etc_crontabs_root.mtime")
    if [ "$cron_before" = absent ]; then rm -f "$ROOT/etc/crontabs/root"
    elif ! exact_file "$ROOT/etc/crontabs/root" "$cron_before" "$cron_mtime"; then
        restore_original "$BACKUP/etc_crontabs_root.original" "$ROOT/etc/crontabs/root" "$cron_before" "$cron_mtime"
    fi
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CRASH_AT:-}" = cron-table-restored ]; then kill -KILL "$$"; fi
    cron_service reload || fail 'baseline cron reload failed; executable restoration fenced; journal retained'
    cron_wait=0
    # An untouched baseline needs service reconciliation, not replacement of a
    # daemon that this installation never supplied with its table. Persisted
    # replace (including CFCRON1) never downgrades after restoration/retry.
    while [ "$cron_mode" = replace ] && ! cron_old_gone; do
        [ "$cron_wait" -lt 20 ] || fail 'old cron instance has not drained; executable restoration fenced; journal retained'
        sleep 1; cron_wait=$((cron_wait + 1))
    done
    cron_now=$(cron_instance)
    cron_tables=0
    for cron_table in "$ROOT/etc/crontabs"/*; do [ ! -f "$cron_table" ] || cron_tables=$((cron_tables + 1)); done
    if [ "$cron_tables" = 0 ]; then [ "$cron_now" = stopped ] || fail 'cron stop reconciliation incomplete; journal retained'
    else [ "$cron_now" != stopped ] || fail 'baseline cron instance unavailable; journal retained'; fi
    phase cron-reconciled
    platform_transaction_barrier cron-reconciled
}

# Runtime is newly owned by this installation; preexisting runtime is refused
# by install. Never remove unknown paths, symlinks, active locks, or weak modes.
runtime_preflight() (
    set +f
    runtime=$BASE/runtime
    [ -e "$runtime" ] || [ -L "$runtime" ] || return 0
    if ! { [ -d "$runtime" ] && [ ! -L "$runtime" ]; }; then
        fail 'unsafe runtime directory'
    fi
    if ! { [ ! -e "$runtime/lock" ] && [ ! -L "$runtime/lock" ]; }; then
        [ "${1:-}" = recover-owned-lock ] || fail 'runtime lock present; installation/recovery stopped'
        recover_owned_lock_check "$runtime/lock" token-pid
    fi
    expected_owner=$(stat -c '%u:%g' "$BACKUP/etc_couvrefeu_state.staged")
    [ "$(metadata "$runtime")" = "700:$expected_owner" ] || fail 'runtime directory metadata drift'
    for p in "$runtime"/* "$runtime"/.[!.]* "$runtime"/..?*; do
        [ -e "$p" ] || [ -L "$p" ] || continue
        name=${p##*/}
        case "$name" in
            lock)
                [ "${1:-}" = recover-owned-lock ] || fail 'runtime lock present; installation/recovery stopped'
                continue;;
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
)

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
if [ "${CF_TRANSACTION_DEFINITIONS_ONLY:-0}" != 1 ]; then
install_admission "$@"
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
fi
