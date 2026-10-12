#!/bin/sh
# shellcheck disable=SC2034,SC1090,SC1091
# Default: validate/stage only. Installation requires explicit --activate.
set -eu
set -f
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ACTIVATE=0
PROTECTED=
RPC_ALLOW=
SOURCE=$HERE
PLATFORM_SELECTION=strict
PLATFORM_OPTION=0
fail() { printf 'couvre-feu: %s\n' "$*" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --platform-profile)
            [ "$#" -ge 2 ] && [ "$PLATFORM_OPTION" = 0 ] || fail 'one --platform-profile required'
            case "$2" in strict|gl-xe3000-4.8.3-logd-011-v1) ;; *) fail 'unknown platform profile';; esac
            PLATFORM_SELECTION=$2; PLATFORM_OPTION=1; shift 2;;
        --activate) ACTIVATE=1; shift;;
        --protect)
            [ "$#" -ge 2 ] || fail '--protect requires a canonical MAC'
            PROTECTED="$PROTECTED$2
"
            shift 2;;
        --rpc-allow)
            if [ "$#" -lt 2 ] || [ -n "$RPC_ALLOW" ];then
                fail '--rpc-allow requires one canonical MAC'
            fi
            RPC_ALLOW=$2;shift 2;;
        --source-dir)
            [ "$#" -ge 2 ] || fail '--source-dir requires a directory'
            SOURCE=$2; shift 2;;
        *) fail 'usage: install.sh [--activate] [--protect aa:bb:cc:dd:ee:ff] [--source-dir DIR]';;
    esac
done
# BEGIN authenticated bootstrap boundary
if [ "${CF_TEST_MODE:-0}" != 1 ]; then PATH=/usr/sbin:/usr/bin:/sbin:/bin; fi
LC_ALL=C
export PATH LC_ALL
umask 077
if [ -n "${LD_PRELOAD-}${LD_LIBRARY_PATH-}${LD_AUDIT-}" ] || [ "${CF_PLATFORM_ADMITTED+x}${CF_PLATFORM_LOCKED+x}${CF_PLATFORM_NESTED+x}${CF_RELEASE_ID+x}${CF_PLATFORM_PROFILE+x}${CF_PLATFORM_CALLER_PID+x}${CF_PLATFORM_OWNER+x}${CF_PLATFORM_LIB+x}${CF_VENDOR_PROFILE+x}${CF_RELEASE_MODULES+x}${vp_profile+x}" != "" ]; then
    printf '%s\n' 'couvre-feu: injected platform environment refused' >&2
    exit 2
fi
unset CF_PLATFORM_ADMITTED CF_PLATFORM_LOCKED CF_PLATFORM_NESTED CF_RELEASE_ID CF_PLATFORM_PROFILE CF_VENDOR_PROFILE CF_RELEASE_MODULES CF_PLATFORM_CALLER_PID CF_PLATFORM_OWNER CF_PLATFORM_LIB vp_profile
CF_BOOTSTRAP_PIN=bf93a1d753df799b313693d5c16a7e60740e476388b8ae2008fa0a03eab291fc
platform_bootstrap_path=$HERE/lib/platform-bootstrap.sh
[ -f "$platform_bootstrap_path" ] && [ ! -L "$platform_bootstrap_path" ] && [ "$(CDPATH='' cd -- "${platform_bootstrap_path%/*}" && pwd -P)" = "${platform_bootstrap_path%/*}" ] || exit 2
platform_bootstrap_digest=$(timeout -s KILL 6 sha256sum "$platform_bootstrap_path") || exit 2
[ "${platform_bootstrap_digest%% *}" = "$CF_BOOTSTRAP_PIN" ] || exit 2
# shellcheck disable=SC1091
. "$platform_bootstrap_path"
# END authenticated bootstrap boundary
platform_entry_root_validate
platform_admit "$PLATFORM_SELECTION" "${CF_ROOT:-}" "$HERE/lib"
[ "${CF_TEST_MODE:-0}" = 1 ] || platform_external_closure "$HERE"
if [ "${CF_TEST_MODE:-0}" = 1 ]; then
    case "$SOURCE" in "$CF_ROOT"/*|"$HERE") ;; *) fail 'fixture source outside isolated root';; esac
    [ "$(CDPATH='' cd -- "$SOURCE" && pwd -P)" = "$SOURCE" ] || fail 'fixture source must be canonical'
else
    [ "$SOURCE" = "$HERE" ] || fail 'source must equal the verified release directory'
fi
# shellcheck disable=SC1091
. "$HERE/lib/install-common.sh"
safe_paths
if ! { [ "$BACKUP" != "$RECOVERY" ] && [ ! -e "$DONE" ]; }; then
    fail 'uninstallation recovery is pending; finish uninstall before reinstalling'
fi
if ! { [ ! -f "$BACKUP/restoring" ] && [ ! -f "$BACKUP/restoring.next" ] && [ ! -f "$BACKUP/kernel-cleaned" ] && [ ! -f "$BACKUP/kernel-cleaned.next" ]; }; then
    fail 'uninstallation recovery is pending; finish uninstall before reinstalling'
fi
for file in cfctl cfctl-ssh lib/core.sh lib/rpc.sh lib/state.awk lib/firewall.sh lib/json.awk lib/rules.awk lib/install-common.sh lib/platform-bootstrap.sh lib/vendor-platform.sh; do
    if ! { [ -f "$SOURCE/$file" ] && [ ! -L "$SOURCE/$file" ]; }; then
        fail "missing/unsafe source: $file"
    fi
    case "$file" in *.awk) ;; *) sh -n "$SOURCE/$file" || fail "source shell syntax: $file";; esac
done

backend() {
    name=$1; shift
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then
        case "${CF_BACKEND_DIR:-}" in "$ROOT"/*) ;; *) fail 'fixture backend must be below fixture root';; esac
        [ "$(CDPATH='' cd -- "$CF_BACKEND_DIR" && pwd -P)" = "$CF_BACKEND_DIR" ] || fail 'fixture backend must be canonical with no symlink ancestors'
        if ! { [ -f "$CF_BACKEND_DIR/.couvrefeu-test-backend" ] && [ ! -L "$CF_BACKEND_DIR/.couvrefeu-test-backend" ]; }; then
            fail 'fixture backend marker missing'
        fi
        if ! { [ ! -L "$CF_BACKEND_DIR" ] && [ -x "$CF_BACKEND_DIR/$name" ] && [ ! -L "$CF_BACKEND_DIR/$name" ]; }; then
            fail "fixture backend unavailable: $name"
        fi
        "$CF_BACKEND_DIR/$name" "$@"
    else
        command -v "$name" >/dev/null 2>&1 || fail "missing dependency: $name"
        "$name" "$@"
    fi
}

# A live SSH client must be uniquely mapped on br-lan even if explicit adults
# were supplied. An unresolved client is never permission to proceed.
if [ -n "${SSH_CONNECTION:-}" ]; then
    # Deliberate token splitting; globbing disabled above.
    # shellcheck disable=SC2086
    set -- $SSH_CONNECTION
    [ "$#" = 4 ] || fail 'invalid SSH_CONNECTION'
    CLIENT=$1
    # Fixed dev br-lan collector may omit the selected device in its output.
    CLIENT_MAC=$(backend ip neigh show "$CLIENT" dev br-lan | awk -v ip="$CLIENT" '
        NF {
            if($1!=ip){bad=1;next}
            dev="";rowmac="";state="";nd=nm=ns=0
            for(i=2;i<=NF;i++){
                if($i=="dev"){if(++nd>1||i==NF||$(i+1)!="br-lan"){bad=1;break}dev=$(++i)}
                else if($i=="lladdr"){if(++nm>1||i==NF){bad=1;break}rowmac=tolower($(++i))}
                else if($i~/^(REACHABLE|PERMANENT|STALE|DELAY|PROBE|FAILED|INCOMPLETE|NOARP|NONE)$/){if(++ns>1){bad=1;break}state=$i}
                else if($i!~/^(router|proxy|extern_learn|extern_valid|managed|use)$/){bad=1;break}
            }
            if(nm==1&&ns==1&&state~/^(REACHABLE|PERMANENT)$/){mac=rowmac;count++}
        }
        END {if(!bad&&count==1) print mac; else exit 1}
    ') || fail 'SSH client identity unresolved or ambiguous'
    PROTECTED="$PROTECTED$CLIENT_MAC
"
fi

# Build staging outside managed paths. In fixtures it stays under CF_ROOT.
if [ "${CF_TEST_MODE:-0}" = 1 ]; then STAGE=$(mktemp -d "$ROOT/.couvrefeu-stage.XXXXXX")
else STAGE=$(mktemp -d /tmp/couvrefeu-stage.XXXXXX); fi
cleanup() {
    for file in restore-probe cfctl cfctl-ssh include protected state rpc-allowed generation firewall sysupgrade cron platform-profile; do rm -f "$STAGE/$file"; done
    for rel in $DIRS; do k=$(key "$rel"); rm -f "$STAGE/dir_$k"; done
    if [ -d "$STAGE/.delta" ]; then rmdir "$STAGE/.delta" 2>/dev/null || :; fi
    rmdir "$STAGE" 2>/dev/null || :
    unlock_install
    platform_lock_release
}
trap cleanup 0
if [ -e "$BASE/protected" ]; then
    valid_protection "$BASE/protected" || fail 'existing protected list invalid'
    cp "$BASE/protected" "$STAGE/protected"
else : > "$STAGE/protected"; fi
printf '%s' "$PROTECTED" >> "$STAGE/protected"
awk '!seen[$0]++' "$STAGE/protected" > "$STAGE/state"
mv "$STAGE/state" "$STAGE/protected"
valid_protection "$STAGE/protected" || fail 'at least one unique canonical protected MAC is required'
chmod 600 "$STAGE/protected"
cp "$SOURCE/cfctl" "$STAGE/cfctl"
cp "$SOURCE/cfctl-ssh" "$STAGE/cfctl-ssh"
chmod 755 "$STAGE/cfctl" "$STAGE/cfctl-ssh"
printf '%s\n' '#!/bin/sh' 'exec /usr/sbin/cfctl apply-fw' > "$STAGE/include"
chmod 755 "$STAGE/include"
if [ -e "$BASE/state" ]; then cp -p "$BASE/state" "$STAGE/state"
else printf 'V\t1\nR\t0\n' > "$STAGE/state"; fi
chmod 600 "$STAGE/state"
printf '%s\n' "$CF_PLATFORM_PROFILE" > "$STAGE/platform-profile"
chmod 600 "$STAGE/platform-profile"
if [ -n "$RPC_ALLOW" ];then
    printf '%s\n' "$RPC_ALLOW" > "$STAGE/rpc-allowed"
    valid_protection "$STAGE/rpc-allowed" || fail '--rpc-allow requires a canonical unicast MAC'
    awk -v mac="$RPC_ALLOW" '$0==mac{exit 1}' "$STAGE/protected" || fail 'RPC allowed MAC is protected'
    chmod 600 "$STAGE/rpc-allowed"
    if [ -e "$BACKUP" ];then
        [ -f "$BACKUP/etc_couvrefeu_rpc-allowed.staged" ] || fail 'scoped migration of a legacy installation is not supported'
        cmp -s "$STAGE/rpc-allowed" "$BACKUP/etc_couvrefeu_rpc-allowed.staged" || fail 'reinstallation cannot change RPC scope'
    else
        # Read exactly 32 bytes, check the read, then encode without deriving identity.
        dd if=/dev/urandom bs=1 count=32 of="$STAGE/generation" 2>/dev/null || fail 'generation entropy read failed'
        [ "$(wc -c < "$STAGE/generation")" = 32 ] || fail 'short generation entropy read'
        GENERATION=$(od -An -tx1 "$STAGE/generation" | tr -d ' \n')
        [ "${#GENERATION}" = 64 ] || fail 'invalid generation entropy'
        # Validate the original envelope before creating fresh activation metadata.
        awk -f "$SOURCE/lib/state.awk" "$STAGE/state" >/dev/null || fail 'invalid preinstallation state'
        # Preserve original bytes for rollback; a fresh activation resets metadata.
        awk '$1 !~ /^(X|G|C|O)$/ {print}' "$STAGE/state" > "$STAGE/generation"
        mv "$STAGE/generation" "$STAGE/state"
        printf 'X\t1\nG\t%s\nC\t-\n' "$GENERATION" >> "$STAGE/state"
        chmod 600 "$STAGE/state"
    fi
    # Every scoped admission, including initial activation, precedes managed writes.
    (
        # shellcheck disable=SC2034
        CF_BASE=$ROOT CF_LIB=$SOURCE/lib
        # shellcheck disable=SC1091
        . "$SOURCE/lib/core.sh"
        stage_records=$(awk -f "$SOURCE/lib/state.awk" "$STAGE/state") || exit 1
        stage_json=$(printf '%s\n' "$stage_records" | cf_state_json /dev/stdin) || exit 1
        stage_valid=$(printf '%s\n' "$stage_json" | awk -f "$SOURCE/lib/json.awk") || exit 1
        [ "$(printf '%s\n' "$stage_valid" | cf_canonical)" = "$(printf '%s\n' "$stage_records" | cf_canonical)" ] || exit 1
        printf '%s\n' "$stage_records" | awk -F '\t' -v mac="$RPC_ALLOW" '$1=="P"&&$3!="-"&&$3!=mac{exit 1}' || exit 1
        printf '%s\n' "$stage_records" | awk -F '\t' 'NR==FNR{protected[$1]=1;next}$1=="P"&&protected[$3]{exit 1}' "$STAGE/protected" -
    ) || fail 'initial state violates scoped policy or protected identities'
elif [ -e "$BACKUP/etc_couvrefeu_rpc-allowed.after" ];then
    fail 'recorded scoped installation requires explicit --rpc-allow'
fi
for pair in 'firewall:etc/config/firewall' 'sysupgrade:etc/sysupgrade.conf' 'cron:etc/crontabs/root'; do
    file=${pair%%:*} rel=${pair#*:}
    if [ -e "$ROOT/$rel" ]; then cp -p "$ROOT/$rel" "$STAGE/$file"
    else : > "$STAGE/$file"; chmod 644 "$STAGE/$file"; fi
done
if awk '/couvrefeu|couvre-feu|cfctl/ {found=1} END {exit !found}' "$STAGE/firewall" "$STAGE/sysupgrade" "$STAGE/cron"; then
    [ -f "$BACKUP/ready" ] || fail 'unrecorded existing installation; refusing without originals'
fi
if [ -e "$BASE/runtime" ] && [ ! -f "$BACKUP/ready" ]; then
    fail 'preexisting runtime directory has no installation journal; preserved'
fi
if [ -e "$BACKUP" ]; then
    preflight
    if [ -f "$BACKUP/complete" ]; then expected_protected=$BASE/protected
    else expected_protected=$BACKUP/etc_couvrefeu_protected.staged; fi
    cmp -s "$STAGE/protected" "$expected_protected" || fail 'reinstallation cannot change protected identities; use a separately reviewed policy change'
    # Resume from the immutable staged journal; do not append integration twice.
    if [ "$ACTIVATE" = 0 ]; then printf '%s\n' 'Recorded installation validated; no changes made.'; exit 0; fi
else
    printf '\nconfig include '\''couvrefeu'\''\n\toption type '\''script'\''\n\toption path '\''/etc/firewall.couvrefeu'\''\n\toption reload '\''1'\''\n' >> "$STAGE/firewall"
    printf '\n/etc/couvrefeu\n/usr/sbin/cfctl\n/usr/sbin/cfctl-ssh\n/usr/lib/couvrefeu\n/etc/firewall.couvrefeu\n/etc/crontabs/root\n' >> "$STAGE/sysupgrade"
    printf '\n/etc/.couvrefeu-release-%s\n' "$CF_RELEASE_ID" >> "$STAGE/sysupgrade"
    printf '\n* * * * * /usr/sbin/cfctl expire\n' >> "$STAGE/cron"
    chmod 600 "$STAGE/cron"
    if [ "$ACTIVATE" = 0 ]; then
        printf '%s\n' 'Sources and protected identities staged/validated. No installation or activation performed. Use --activate only with separate live authorization.'
        exit 0
    fi
fi
# Mandatory read-only backend gate occurs before any managed file changes.
(
    CF_LOCAL_TEST=${CF_TEST_MODE:-0} CF_BASE=$ROOT CF_LIB=$SOURCE/lib
    . "$SOURCE/lib/core.sh"
    cf_check
) || fail 'core dependency/capability gate failed'
if [ "${CF_TEST_MODE:-0}" != 1 ]; then platform_recovery_prepare "$HERE"; fi
if [ ! -e "$BACKUP" ]; then
    # Validate the native UCI configuration from the staging directory.
    mkdir "$STAGE/.delta"
    backend uci -c "$STAGE" -t "$STAGE/.delta" show firewall >/dev/null || fail 'staged UCI firewall validation failed'
    # Test the actual originals with the target copy implementation before any
    # managed path changes. BusyBox cp -p may truncate fractional timestamps;
    # integer originals remain supported, fractional originals then refuse.
    for rel in $FILES; do
        original_mtime=$(mtime "$ROOT/$rel") || fail "precise original mtime unavailable: $rel"
        if [ "$original_mtime" != absent ]; then
            cp -p "$ROOT/$rel" "$STAGE/restore-probe"
            if ! { [ "$(signature "$ROOT/$rel")" = "$(signature "$STAGE/restore-probe")" ] && exact_mtime "$STAGE/restore-probe" "$original_mtime"; }; then
                fail "cannot preserve exact original metadata/mtime: $rel; no installation made"
            fi
            rm -f "$STAGE/restore-probe"
        fi
    done
    # Capture directory modes before creating anything in managed paths.
    for rel in $DIRS; do
        k=$(key "$rel")
        if [ -d "$ROOT/$rel" ]; then stat -c %a "$ROOT/$rel" > "$STAGE/dir_$k"
        else printf '%s\n' absent > "$STAGE/dir_$k"; fi
    done
    mkdir -p "$BACKUP"
    chmod 700 "$BASE" "$BACKUP"
    for rel in $DIRS; do k=$(key "$rel"); mv "$STAGE/dir_$k" "$BACKUP/dir_$k"; done
    for rel in $FILES; do
        k=$(key "$rel")
        signature "$ROOT/$rel" > "$BACKUP/$k.before"
        mtime "$ROOT/$rel" > "$BACKUP/$k.mtime" || fail "precise original mtime unavailable: $rel"
        if [ -e "$ROOT/$rel" ]; then cp -p "$ROOT/$rel" "$BACKUP/$k.original"; fi
        case "$rel" in
            usr/lib/couvrefeu/platform-bootstrap.sh) staged=lib/platform-bootstrap.sh;;
            usr/lib/couvrefeu/vendor-platform.sh) staged=lib/vendor-platform.sh;;
            etc/couvrefeu/platform-profile) staged=platform-profile;;
            usr/lib/couvrefeu/core.sh) staged=lib/core.sh;;
            usr/lib/couvrefeu/rpc.sh) staged=lib/rpc.sh;;
            usr/lib/couvrefeu/state.awk) staged=lib/state.awk;;
            etc/couvrefeu/rpc-allowed) staged=rpc-allowed;;
            usr/lib/couvrefeu/firewall.sh) staged=lib/firewall.sh;;
            usr/lib/couvrefeu/json.awk) staged=lib/json.awk;;
            usr/lib/couvrefeu/rules.awk) staged=lib/rules.awk;;
            usr/lib/couvrefeu/install-common.sh) staged=lib/install-common.sh;;
            usr/sbin/cfctl) staged=cfctl;; usr/sbin/cfctl-ssh) staged=cfctl-ssh;;
            etc/firewall.couvrefeu) staged=include;; etc/config/firewall) staged=firewall;;
            etc/sysupgrade.conf) staged=sysupgrade;; etc/crontabs/root) staged=cron;;
            etc/couvrefeu/protected) staged=protected;; etc/couvrefeu/state) staged=state;;
        esac
        case "$staged" in lib/*) cp "$SOURCE/$staged" "$BACKUP/$k.staged"; chmod 644 "$BACKUP/$k.staged";;
            *) cp -p "$STAGE/$staged" "$BACKUP/$k.staged";; esac
        signature "$BACKUP/$k.staged" > "$BACKUP/$k.after"
    done
    printf '%s\n' 1 > "$BACKUP/ready"
fi
preflight
runtime_preflight
COUNT=0
for rel in $FILES; do
    k=$(key "$rel")
    mkdir -p "$(dirname "$ROOT/$rel")"
    # Reinstall/resume never overwrites legitimate mutable runtime contents.
    case "$rel" in etc/couvrefeu/state|etc/couvrefeu/protected)
        if [ -f "$BACKUP/complete" ]; then continue; fi;;
    esac
    atomic_copy "$BACKUP/$k.staged" "$ROOT/$rel"
    COUNT=$((COUNT + 1))
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_INSTALL_FAIL_AFTER:-0}" = "$COUNT" ]; then fail 'injected partial installation'; fi
done
# Scoped RPC requires an activation-owned runtime parent; a delayed request must
# never recreate it after uninstall. The global install lock fences this creation.
if [ -n "$RPC_ALLOW" ] && [ ! -e "$BASE/runtime" ];then
    mkdir -m 700 "$BASE/runtime"
fi
# Record possible kernel mutation *before* invoking the backend, for recovery
# even when apply fails or the process is interrupted.
printf '%s\n' 1 > "$BACKUP/activated"
if live_tools; then
    installed_core apply-fw || fail 'apply failed; journal retained; use uninstall for recovery'
fi
printf '%s\n' 1 > "$BACKUP/complete"
printf '%s\n' 'Installation recorded. Live packet enforcement requires separate acceptance.'
