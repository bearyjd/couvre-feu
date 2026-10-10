# shellcheck shell=sh
# Shared installation/recovery helpers. POSIX sh / OpenWrt ash.
set -eu
umask 077

fail() { printf '%s\n' "couvre-feu: $*" >&2; exit 1; }
if [ "${CF_TEST_MODE:-0}" = 1 ]; then
    [ -n "${CF_ROOT:-}" ] && [ "$CF_ROOT" != / ] || fail 'fixture root required'
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
[ -d "$recovery_parent" ] && [ ! -L "$recovery_parent" ] || fail 'unsafe recovery parent'
[ "$(stat -c %u "$recovery_parent")" = "$(id -u)" ] || fail 'unsafe recovery parent owner'
recovery_parent_mode=$(stat -c %a "$recovery_parent")
[ "$((0$recovery_parent_mode & 022))" = 0 ] || fail 'unsafe writable recovery parent'
# A recovery journal and its completion record are fixed, private paths.
for recovery_path in "$RECOVERY" "$DONE"; do
    [ ! -L "$recovery_path" ] || fail 'recovery path is a symlink'
done
if [ -e "$RECOVERY" ]; then
    [ ! -e "$BACKUP" ] && [ ! -L "$BACKUP" ] || fail 'ambiguous installation and recovery journals'
    BACKUP=$RECOVERY
fi
if [ -e "$DONE" ]; then
    [ ! -e "$BASE/backup" ] && [ ! -L "$BASE/backup" ] || fail 'ambiguous completed recovery and installation journal'
    BACKUP=$RECOVERY
fi
FILES='usr/lib/couvrefeu/core.sh usr/lib/couvrefeu/firewall.sh usr/lib/couvrefeu/json.awk usr/lib/couvrefeu/rules.awk usr/lib/couvrefeu/install-common.sh usr/sbin/cfctl usr/sbin/cfctl-ssh etc/firewall.couvrefeu etc/config/firewall etc/sysupgrade.conf etc/crontabs/root etc/couvrefeu/protected etc/couvrefeu/state'
DIRS='etc usr usr/sbin usr/lib usr/lib/couvrefeu etc/config etc/crontabs etc/couvrefeu'

for dep in sha256sum stat cp mv mkdir rmdir chmod awk sed cmp dd; do
    command -v "$dep" >/dev/null 2>&1 || fail "missing dependency: $dep"
done

if [ "${CF_TEST_MODE:-0}" = 1 ]; then LOCK=$ROOT/.couvrefeu-install.lock
else LOCK=/tmp/couvrefeu-install.lock; fi
mkdir "$LOCK" 2>/dev/null || fail 'another install/recovery transaction is running'
chmod 700 "$LOCK"
printf '%s\n' "$$" > "$LOCK/pid"
INSTALL_TOKEN=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | sha256sum | awk '{print $1}')
printf '%s\n' "$INSTALL_TOKEN" > "$LOCK/token"
unlock_install() {
    rm -f "$LOCK/pid" "$LOCK/token"
    rmdir "$LOCK" 2>/dev/null || :
}
trap unlock_install 0
trap 'exit 1' 1 2 15

# Every core mutation checks the global lock before and after obtaining its
# own runtime lock. Once this lock is held, an existing runtime lock means
# an operation predates us and we must stop. Journal calls come directly
# from that lock-owning core process and are the sole exception here.
if [ -e "$BASE/runtime/lock" ] || [ -L "$BASE/runtime/lock" ]; then
    case "${1:-}" in
        firewall-prepare|firewall-commit)
            [ -d "$BASE/runtime/lock" ] && [ ! -L "$BASE/runtime/lock" ] || fail 'unsafe core lock'
            [ -f "$BASE/runtime/lock/pid" ] && [ ! -L "$BASE/runtime/lock/pid" ] || fail 'unsafe core owner'
            owner=$(awk 'NR==1 {print; exit}' "$BASE/runtime/lock/pid")
            if [ "$owner" != "${PPID:-}" ] || ! kill -0 "$owner" 2>/dev/null; then fail 'journal caller does not own the core lock'; fi;;
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
        [ -f "$1" ] && [ ! -L "$1" ] || fail "unsafe file: $1"
        printf '%s:%s:%s:%s\n' "$(sha256sum "$1" | awk '{print $1}')" "$(stat -c %a "$1")" "$(stat -c %u "$1")" "$(stat -c %g "$1")"
    else
        printf '%s\n' absent
    fi
}
key() { printf '%s' "$1" | sed 's|/|_|g'; }

valid_protection() {
    awk -F: '
        NF != 6 || seen[$0]++ || $0=="00:00:00:00:00:00" || substr($1,2,1) !~ /^[02468ace]$/ {exit 1}
        {for(i=1;i<=6;i++) if($i !~ /^[0-9a-f][0-9a-f]$/) exit 1}
        END {if(NR < 1 || NR > 128) exit 1}
    ' "$1"
}
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
    [ -d "$BACKUP" ] && [ ! -L "$BACKUP" ] && [ "$(metadata "$BACKUP")" = "700:$owner_ids" ] || fail 'unsafe backup directory metadata'
    if [ "$BACKUP" != "$RECOVERY" ]; then
        [ "$(metadata "$BASE")" = "700:$owner_ids" ] || fail 'unsafe installation directory metadata'
    elif [ "${1:-}" != cleanup ]; then
        [ -f "$BACKUP/restoring" ] && [ -f "$BACKUP/kernel-cleaned" ] || fail 'recovery phase missing'
        if [ -e "$BASE" ]; then
            original_mode=$(awk 'NR==1 {print; exit}' "$BACKUP/dir_etc_couvrefeu")
            base_metadata=$(metadata "$BASE")
            [ "$base_metadata" = "700:$owner_ids" ] || [ "$base_metadata" = "$original_mode:$owner_ids" ] || fail 'unsafe recovery installation directory metadata'
        else
            [ "$(awk 'NR==1 {print; exit}' "$BACKUP/dir_etc_couvrefeu")" = absent ] || fail 'original installation directory missing'
        fi
    fi
    allowed_entries='ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next firewall.transaction firewall.transaction.next etc_config_firewall.after.next firewall.pending etc_config_firewall.staged.couvrefeu-tmp'
    record_entries='ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next firewall.transaction firewall.transaction.next etc_config_firewall.after.next'
    for rel in $FILES; do
        k=$(key "$rel")
        allowed_entries="$allowed_entries $k.before $k.after $k.original $k.staged"
        record_entries="$record_entries $k.before $k.after"
    done
    for rel in $DIRS; do
        k=$(key "$rel")
        allowed_entries="$allowed_entries dir_$k"
        record_entries="$record_entries dir_$k"
    done
    for entry in "$BACKUP"/* "$BACKUP"/.[!.]* "$BACKUP"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        [ -f "$entry" ] && [ ! -L "$entry" ] || fail 'backup entry is not a regular file; preserved'
        name=${entry##*/}
        case "$name" in *[!a-z0-9_.-]*) fail 'invalid backup filename';; esac
        case " $allowed_entries " in *" $name "*) ;; *) fail "unexpected backup entry: $name; all files preserved";; esac
        case " $record_entries " in *" $name "*)
            [ "$(metadata "$entry")" = "600:$owner_ids" ] || fail "unsafe journal record metadata: $name"
            [ "$(stat -c %s "$entry")" -le 512 ] || fail "oversized journal record: $name"
        ;; esac
    done
    for marker in ready activated complete kernel-cleaned kernel-cleaned.next no-kernel-mutations no-kernel-mutations.next restoring restoring.next restored restored.next; do
        if [ -e "$BACKUP/$marker" ]; then
            valid_marker "$BACKUP/$marker" || fail "invalid transaction marker: $marker"
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
    journal_preflight
    [ -f "$BACKUP/ready" ] && [ ! -L "$BACKUP/ready" ] || fail 'incomplete backup; manual recovery required'
    owned_temp "$BACKUP/etc_config_firewall.staged" || fail 'temporary journal path collision'
    for rel in $FILES; do
        k=$(key "$rel")
        [ -f "$BACKUP/$k.before" ] && [ -f "$BACKUP/$k.after" ] || fail "missing manifest: $rel"
        if ! valid_signature_record "$BACKUP/$k.before" 1 || ! valid_signature_record "$BACKUP/$k.after" 0; then fail "invalid signature record: $rel"; fi
        before=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.before")
        after=$(awk 'NR==1 {print; exit}' "$BACKUP/$k.after")
        current=$(signature "$ROOT/$rel")
        tx_old='' tx_new=''
        if [ "$rel" = etc/config/firewall ] && [ -e "$BACKUP/firewall.transaction" ]; then
            [ ! -L "$BACKUP/firewall.transaction" ] || fail 'unsafe firewall transaction'
            tx_old=$(awk 'NR==1 {print}' "$BACKUP/firewall.transaction")
            tx_new=$(awk 'NR==2 {print}' "$BACKUP/firewall.transaction")
            awk 'END {exit NR!=2}' "$BACKUP/firewall.transaction" || fail 'invalid firewall transaction length'
            [ -n "$tx_old" ] && [ -n "$tx_new" ] && [ "$(signature "$BACKUP/firewall.pending")" = "$tx_new" ] || fail 'corrupt firewall transaction'
        fi
        if [ "$rel" = etc/couvrefeu/protected ] && [ "$current" != "$before" ]; then
            [ -f "$ROOT/$rel" ] && [ "$(metadata "$ROOT/$rel")" = "$(metadata "$BACKUP/$k.staged")" ] || fail 'protected metadata drift'
            valid_protection "$ROOT/$rel" || fail 'invalid protected list'
            awk 'NR==FNR {baseline[++n]=$0; next} FNR<=n && $0!=baseline[FNR] {exit 1} END {if(FNR<n) exit 1}' "$BACKUP/$k.staged" "$ROOT/$rel" || fail 'protected baseline was changed'
        elif [ "$rel" = etc/couvrefeu/state ] && [ "$current" != "$before" ]; then
            [ -f "$ROOT/$rel" ] && [ "$(metadata "$ROOT/$rel")" = "$(metadata "$BACKUP/$k.staged")" ] || fail 'runtime state metadata drift'
        else
            [ "$current" = "$before" ] || [ "$current" = "$after" ] || [ "$current" = "$tx_old" ] || [ "$current" = "$tx_new" ] || fail "drift at /$rel; preserved current file and backup; resolve explicitly"
        fi
        if [ "$before" != absent ]; then
            [ "$(signature "$BACKUP/$k.original")" = "$before" ] || fail "corrupt original backup: $rel"
        fi
        owned_temp "$ROOT/$rel" || fail "temporary path collision: $ROOT/$rel.couvrefeu-tmp"
        staged_sig=$(signature "$BACKUP/$k.staged")
        [ "$staged_sig" = "$after" ] || [ "$staged_sig" = "$tx_old" ] || [ "$staged_sig" = "$tx_new" ] || fail "corrupt staged backup: $rel"
    done
}

valid_marker() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(metadata "$1")" = "600:$(id -u):$(id -g)" ] &&
        [ "$(stat -c %s "$1")" = 2 ] && [ "$(awk 'NR==1 {print}' "$1")" = 1 ]
}
phase() {
    printf '%s\n' 1 > "$BACKUP/$1.next"
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
# Rename in the same directory; do not write through existing files.
atomic_copy() (
    src=$1 dst=$2 tmp=$2.couvrefeu-tmp
    if [ -e "$tmp" ] || [ -L "$tmp" ]; then
        owned_temp "$dst" || fail "temporary path collision: $tmp"
        if [ "$(signature "$tmp")" = "$(signature "$src")" ]; then
            mv -f "$tmp" "$dst"
            exit 0
        fi
        rm -f "$tmp"
    fi
    cp -p "$src" "$tmp"
    mv -f "$tmp" "$dst"
)

# Only explicitly marked isolated fixtures can emulate live tool calls.
fixture_tools() {
    case "${CF_BACKEND_DIR:-}" in "$ROOT"/*) ;; *) fail 'fixture backend must be below fixture root';; esac
    [ "$(CDPATH='' cd -- "$CF_BACKEND_DIR" && pwd -P)" = "$CF_BACKEND_DIR" ] || fail 'fixture backend must be canonical with no symlink ancestors'
    [ -f "$CF_BACKEND_DIR/.couvrefeu-test-backend" ] && [ ! -L "$CF_BACKEND_DIR/.couvrefeu-test-backend" ] || fail 'fixture backend marker missing'
}
live_tools() {
    [ "${CF_TEST_MODE:-0}" != 1 ] || [ "${CF_TEST_INSTALL_KERNEL:-0}" = 1 ]
}
installed_core() {
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then
        fixture_tools
        if [ "${CF_TEST_SHELL:-}" = 'busybox ash' ];then
            fixture_busybox=$(command -v busybox) || fail 'BusyBox test shell unavailable'
            CF_INSTALL_TOKEN=$INSTALL_TOKEN "$fixture_busybox" ash "$ROOT/usr/sbin/cfctl" "$1"
            return $?
        fi
    fi
    CF_INSTALL_TOKEN=$INSTALL_TOKEN "$ROOT/usr/sbin/cfctl" "$1"
}
reload_firewall() {
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then
        fixture_tools
        [ -x "$CF_BACKEND_DIR/firewall" ] && [ ! -L "$CF_BACKEND_DIR/firewall" ] || fail 'fixture firewall tool unavailable'
        "$CF_BACKEND_DIR/firewall" reload
    else /etc/init.d/firewall reload; fi
}

# Runtime is newly owned by this installation; preexisting runtime is refused
# by install. Never remove unknown paths, symlinks, active locks, or weak modes.
runtime_preflight() {
    runtime=$BASE/runtime
    [ -e "$runtime" ] || [ -L "$runtime" ] || return 0
    [ -d "$runtime" ] && [ ! -L "$runtime" ] || fail 'unsafe runtime directory'
    [ ! -e "$runtime/lock" ] && [ ! -L "$runtime/lock" ] || fail 'runtime lock present; installation/recovery stopped'
    expected_owner=$(stat -c '%u:%g' "$BACKUP/etc_couvrefeu_state.staged")
    [ "$(metadata "$runtime")" = "700:$expected_owner" ] || fail 'runtime directory metadata drift'
    for p in "$runtime"/* "$runtime"/.[!.]* "$runtime"/..?*; do
        [ -e "$p" ] || [ -L "$p" ] || continue
        name=${p##*/}
        case "$name" in
            .uci.*)
                suffix=${name##*.}
                case "$suffix" in ''|*[!0-9]*) fail "unowned runtime directory: $name";; esac
                [ -d "$p" ] && [ ! -L "$p" ] && [ "$(metadata "$p")" = "700:$expected_owner" ] || fail 'unsafe UCI staging directory'
                for child in "$p"/* "$p"/.[!.]* "$p"/..?*; do
                    [ -e "$child" ] || [ -L "$child" ] || continue
                    if [ "${child##*/}" = .delta ]; then
                        [ -d "$child" ] && [ ! -L "$child" ] && [ "$(metadata "$child")" = "700:$expected_owner" ] || fail 'unsafe UCI delta directory'
                        for delta in "$child"/* "$child"/.[!.]* "$child"/..?*; do
                            [ -e "$delta" ] || [ -L "$delta" ] || continue
                            [ "${delta##*/}" = firewall ] && [ -f "$delta" ] && [ ! -L "$delta" ] || fail 'unowned UCI delta contents'
                            [ "$(metadata "$delta")" = "600:$expected_owner" ] || fail 'UCI delta metadata drift'
                        done
                    else
                        [ "${child##*/}" = firewall ] && [ -f "$child" ] && [ ! -L "$child" ] || fail 'unowned UCI staging contents'
                        [ "$(metadata "$child")" = "$(metadata "$BACKUP/etc_config_firewall.staged")" ] || fail 'UCI staging metadata drift'
                    fi
                done
                continue;;
            confirmed|error|firewall.snapshot|firewall.owned|firewall.intent|firewall.cleanup|expiry) ;;
            .candidate.*|.protected.*|.fw.*|.input.*|.error.*|.confirmed.*|.snapshot.*|.expiry.*|.intent.*|.cleanup.*)
                suffix=${name##*.}
                case "$suffix" in ''|*[!0-9]*) fail "unowned runtime file: $name";; esac;;
            *) fail "unowned runtime file: $name";;
        esac
        [ -f "$p" ] && [ ! -L "$p" ] || fail 'runtime lock/directory/symlink present; preserved'
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
        [ -f "$candidate" ] && [ ! -L "$candidate" ] || fail 'unsafe firewall candidate'
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
