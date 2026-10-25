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
CF_RELEASE_ID=ff8e0723c18aaf34f8c9d9db3412a4207f507bf4c6d684628051e0dcf2590247
CF_VENDOR_PROFILE=gl-xe3000-4.8.3-logd-011-v1
CF_OS_TRUST_PROFILE=gl-xe3000-4.8.3-os-trust-v1
CF_PLATFORM_INITIAL_WRITE=0
CF_RELEASE_MODULES='core.sh:30766e2691486e0b94661da6dcd242370d37e8d60af0e893bfe9299d2fe78828 rpc.sh:09da345369405c59ee943c2e8340673d6be224ddd64456176c991718e954ae67 firewall.sh:6d26a4d0bbb658224a568c87f3efa29e7fc1316561efd79017f440339267cbd7 install-common.sh:8e03a9d663f61c68cd7be70668101939c61c65a5d673eacfd45ccf79d85660b8 state.awk:3326364e1827d767c9b7b291e66668fef456a705ea79bd25f2e9fe82b15b7755 rules.awk:523595998750193b4cc2bc8b1d407a45fae95738d8a47a356afd16025a268954 json.awk:ae3a0773339230ebff7349e9bafc6ff02d42aa7cf162b6377ff33638186d03fc vendor-platform.sh:e093670bf47f6a9da749a73aef17a564c7e910e9b9acf5376bb331b56593b43b activity.sh:6bf33a31000f5a8c3078a813856b21834b58b06d98055e45fa71a8cd414e2155'

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
    if ! { [ "${#platform_seconds}" -le 10 ] && [ "${#platform_fraction}" = 2 ]; }; then platform_fail admission_clock_format; fi
    case "$platform_seconds" in 0|[1-9]*) ;; *) platform_fail admission_clock_format;; esac
    platform_fraction=${platform_fraction#0}; platform_fraction=${platform_fraction:-0}
    printf '%s\n' "$((platform_seconds * 100 + platform_fraction))"
}
platform_deadline_check() {
    [ "$CF_PLATFORM_PROFILE" = "$CF_OS_TRUST_PROFILE" ] || return 0
    [ "${CF_PLATFORM_INITIAL_WRITE:-0}" != 1 ] || return 0
    case "${CF_PLATFORM_ENTRY_TICK:-}" in ''|*[!0-9]*) platform_fail admission_clock_anchor;; esac
    platform_now=$(platform_clock_tick) || platform_fail admission_clock_read
    if ! { [ "$platform_now" -ge "$CF_PLATFORM_ENTRY_TICK" ] && [ "$((platform_now-CF_PLATFORM_ENTRY_TICK))" -lt 1300 ]; }; then platform_fail admission_deadline; fi
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
            if ! { [ -d "$CF_ROOT" ] && [ ! -L "$CF_ROOT" ] && [ "$(CDPATH='' cd -- "$CF_ROOT" && pwd -P)" = "$CF_ROOT" ]; }; then platform_fail fixture_root_canonical; fi
            CF_PLATFORM_OWNER=$(id -u):$(id -g);;
        *) platform_fail unknown_test_mode;;
    esac
}
platform_regular() { if ! { [ -f "$1" ] && [ ! -L "$1" ]; }; then platform_fail regular_file; fi; }
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
# The permanent inode is never unlinked. Direct workers retain the same open
# file description; closing a descriptor is safe, LOCK_UN would unlock them.
platform_transaction_paths() {
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then CF_TRANSACTION_PARENT=$CF_ROOT
    else CF_TRANSACTION_PARENT=/etc; fi
    CF_TRANSACTION_MUTEX=$CF_TRANSACTION_PARENT/.couvrefeu-mutex
    CF_TRANSACTION_OWNER=$CF_TRANSACTION_PARENT/.couvrefeu-transaction
    CF_TRANSACTION_PREPARED=$CF_TRANSACTION_PARENT/.couvrefeu-prepared
    CF_TRANSACTION_FENCE=$CF_TRANSACTION_PARENT/.couvrefeu-recovery-required
    CF_TRANSACTION_RETIREMENT=$CF_TRANSACTION_PARENT/.couvrefeu-retirement
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then CF_TRANSACTION_BASE=$CF_ROOT/etc/couvrefeu
    else CF_TRANSACTION_BASE=/etc/couvrefeu; fi
    if ! { [ -d "$CF_TRANSACTION_PARENT" ] && [ ! -L "$CF_TRANSACTION_PARENT" ]; }; then platform_fail transaction_parent; fi
    platform_canonical "$CF_TRANSACTION_PARENT/.parent-check"
    platform_parent_metadata=$(platform_stat -c '%u:%g:%a' "$CF_TRANSACTION_PARENT")
    case "$platform_parent_metadata" in "$CF_PLATFORM_OWNER:700"|"$CF_PLATFORM_OWNER:755"|"$CF_PLATFORM_OWNER:750") ;;
        0:0:775) if ! { [ "$CF_TRANSACTION_PARENT" = /etc ] && platform_vendor_selected && [ "${CF_PLATFORM_ADMITTED:-0}" = 1 ]; }; then platform_fail transaction_parent_metadata; fi;;
        *) platform_fail transaction_parent_metadata;;
    esac
}
platform_process_identity() {
    # comm may contain spaces and parentheses: discard through the FINAL ')'.
    platform_identity_pid=$1
    case "$platform_identity_pid" in ''|*[!0-9]*) return 1;; esac
    [ "${#platform_identity_pid}" -le 10 ] || return 1
    platform_identity_line=$(cat "/proc/$platform_identity_pid/stat") || return 1
    case "$platform_identity_line" in "$platform_identity_pid ("*') '*) ;; *) return 1;; esac
    platform_identity_tail=${platform_identity_line##*) }
    printf '%s\n' "$platform_identity_tail" | awk '
        NF>=20 && length($20)<=20 && $20~/^[0-9]+$/ && $3~/^[0-9]+$/ && $4~/^[0-9]+$/ {print $20 ":" $3 ":" $4; good=1}
        END {exit !good || NR!=1}'
}
platform_transaction_session() {
    platform_session=$(platform_process_identity "$$") || platform_fail transaction_process_identity
    if [ -n "${CF_ENTRY_SESSION_PID:-}" ]; then
        [ "$CF_ENTRY_SESSION_PID" = "$$" ] || platform_fail transaction_session_forked
        unset CF_ENTRY_SESSION_PID
        case "$platform_session" in *:"$$":"$$") return 0;; *) platform_fail transaction_session_launch;; esac
    fi
    case "$platform_session" in *:"$$":"$$") return 0;; esac
    # setsid silently forks for a process-group leader. Refuse that case before
    # writes; normal direct script invocation is a nonleader and execs in place.
    case "$platform_session" in *:"$$":*) platform_fail transaction_group_leader;; esac
    platform_transaction_shell=$(readlink "/proc/$$/exe") || platform_fail transaction_shell
    case "$platform_transaction_shell" in */busybox) exec setsid "$platform_transaction_shell" ash "$0" --cf-transaction-session "$$" "$@";;
        *) exec setsid "$platform_transaction_shell" "$0" --cf-transaction-session "$$" "$@";; esac
}
platform_transaction_mutex_check() {
    platform_regular "$CF_TRANSACTION_MUTEX"
    platform_private "$CF_TRANSACTION_MUTEX" 600
    [ "$(platform_stat -c '%h:%s' "$CF_TRANSACTION_MUTEX")" = 1:0 ] || platform_fail transaction_mutex_shape
    [ "$(platform_stat -Lc '%d:%i' "/proc/$$/fd/9")" = "$(platform_stat -c '%d:%i' "$CF_TRANSACTION_MUTEX")" ] || platform_fail transaction_mutex_changed
}
platform_transaction_mutex() {
    platform_transaction_paths
    platform_transaction_orphan_check
    if [ "${CF_TRANSACTION_HELD:-0}" = 1 ]; then
        platform_transaction_mutex_check
        return 0
    fi
    # Noclobber uses exclusive creation. A killed creator leaves a valid empty
    # permanent inode; no owner record is needed to recover this kernel lock.
    if [ ! -e "$CF_TRANSACTION_MUTEX" ] && [ ! -L "$CF_TRANSACTION_MUTEX" ]; then
        platform_initial_write
        (umask 077; set -C; : > "$CF_TRANSACTION_MUTEX") 2>/dev/null || :
    fi
    platform_regular "$CF_TRANSACTION_MUTEX"
    platform_private "$CF_TRANSACTION_MUTEX" 600
    [ "$(platform_stat -c '%h:%s' "$CF_TRANSACTION_MUTEX")" = 1:0 ] || platform_fail transaction_mutex_shape
    exec 9<>"$CF_TRANSACTION_MUTEX"
    platform_transaction_mutex_check
    flock -n 9 || platform_fail transaction_contention
    platform_transaction_mutex_check
    CF_TRANSACTION_HELD=1
}
platform_transaction_orphan_check() {
    if [ -e "$CF_TRANSACTION_OWNER" ] || [ -L "$CF_TRANSACTION_OWNER" ]; then
        # A durable owner cannot legitimately predate its permanent mutex.
        if ! { [ -f "$CF_TRANSACTION_MUTEX" ] && [ ! -L "$CF_TRANSACTION_MUTEX" ]; }; then platform_fail orphan_transaction_owner; fi
        return 0
    fi
    if [ -e "$CF_TRANSACTION_RETIREMENT" ] || [ -L "$CF_TRANSACTION_RETIREMENT" ]; then
        # Final receipt retirement may remove owner/DONE first. Check its bound
        # source and original mutex without creating any new state; the common
        # helper validates the entire baseline before any cleanup is admitted.
        platform_regular "$CF_TRANSACTION_RETIREMENT"
        platform_private "$CF_TRANSACTION_RETIREMENT" 600
        [ "$(platform_stat -c '%h:%s' "$CF_TRANSACTION_RETIREMENT" | awk -F: '$1==1&&$2<=32768{print "ok"}')" = ok ] || platform_fail orphan_retirement_receipt
        [ "$(sed -n '1p' "$CF_TRANSACTION_RETIREMENT")" = 'CFRETIREMENT 2' ] || platform_fail orphan_retirement_receipt
        [ "$(sed -n '3p' "$CF_TRANSACTION_RETIREMENT")" = "$CF_PLATFORM_PROFILE" ] || platform_fail orphan_retirement_profile
        [ "$(sed -n '11p' "$CF_TRANSACTION_RETIREMENT")" = "$CF_RELEASE_ID" ] || platform_fail orphan_retirement_source
        platform_regular "$CF_TRANSACTION_MUTEX"
        platform_private "$CF_TRANSACTION_MUTEX" 600
        [ "$(sed -n '6p' "$CF_TRANSACTION_RETIREMENT")" = "$(platform_stat -c '%d:%i' "$CF_TRANSACTION_MUTEX")" ] || platform_fail orphan_retirement_mutex
    elif [ -e "$CF_TRANSACTION_FENCE" ] || [ -L "$CF_TRANSACTION_FENCE" ]; then
        platform_fail orphan_recovery_fence
    fi
}
platform_transaction_read() {
    platform_regular "$CF_TRANSACTION_OWNER"
    platform_private "$CF_TRANSACTION_OWNER" 600
    [ "$(platform_stat -c '%h:%s' "$CF_TRANSACTION_OWNER" | awk -F: '$1==1&&$2<=1024{print "ok"}')" = ok ] || platform_fail transaction_owner_shape
    awk 'NR==1{if($0!="CFTRANSACTION 1")exit 1}
         NR==2{if($0!~/^(active|complete|recovered)$/)exit 1}
         NR==3{if(length($0)!=36||$0~/[^0-9a-f-]/)exit 1}
         NR==4{if(length($0)>10||$0!~/^[1-9][0-9]*$/||$0=="1")exit 1}
         NR==5{if(length($0)>20||$0!~/^[0-9]+$/)exit 1}
         NR==6||NR==7{if(length($0)!=64||$0~/[^0-9a-f]/)exit 1}
         NR==8{if($0!~/^(strict|gl-xe3000-4.8.3-logd-011-v1|gl-xe3000-4.8.3-os-trust-v1)$/)exit 1}
         NR==9{if($0!="none"&&(length($0)!=64||$0~/[^0-9a-f]/))exit 1}
         NR==10{if(length($0)>42||$0!~/^[0-9]+:[0-9]+$/)exit 1}
         END{if(NR!=10)exit 1}' "$CF_TRANSACTION_OWNER" || platform_fail transaction_owner_shape
    CF_TRANSACTION_STATE=$(sed -n '2p' "$CF_TRANSACTION_OWNER")
    CF_TRANSACTION_BOOT=$(sed -n '3p' "$CF_TRANSACTION_OWNER")
    CF_TRANSACTION_PID=$(sed -n '4p' "$CF_TRANSACTION_OWNER")
    CF_TRANSACTION_START=$(sed -n '5p' "$CF_TRANSACTION_OWNER")
    CF_TRANSACTION_TOKEN=$(sed -n '6p' "$CF_TRANSACTION_OWNER")
    [ "$(sed -n '7p' "$CF_TRANSACTION_OWNER")" = "$CF_RELEASE_ID" ] || platform_fail transaction_release_mismatch
    [ "$(sed -n '8p' "$CF_TRANSACTION_OWNER")" = "$CF_PLATFORM_PROFILE" ] || platform_fail transaction_profile_mismatch
    CF_TRANSACTION_DIGEST=$(sed -n '9p' "$CF_TRANSACTION_OWNER")
    [ "$(sed -n '10p' "$CF_TRANSACTION_OWNER")" = "$(platform_stat -c '%d:%i' "$CF_TRANSACTION_MUTEX")" ] || platform_fail transaction_mutex_replaced
}
platform_transaction_publish() {
    platform_transaction_mutex_check
    platform_initial_write
    platform_publication=$(mktemp "$CF_TRANSACTION_PARENT/.couvrefeu-owner.XXXXXX") || platform_fail transaction_owner_candidate
    printf 'CFTRANSACTION 1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$CF_TRANSACTION_STATE" "$CF_TRANSACTION_BOOT" "$CF_TRANSACTION_PID" "$CF_TRANSACTION_START" \
        "$CF_TRANSACTION_TOKEN" "$CF_RELEASE_ID" "$CF_PLATFORM_PROFILE" "$CF_TRANSACTION_DIGEST" \
        "$(platform_stat -c '%d:%i' "$CF_TRANSACTION_MUTEX")" > "$platform_publication" || platform_fail transaction_owner_write
    sync
    mv "$platform_publication" "$CF_TRANSACTION_OWNER" || platform_fail transaction_owner_publish
    sync
}
platform_transaction_barrier() {
    [ "${CF_TEST_MODE:-0}" = 1 ] || return 0
    [ "${CF_TEST_TRANSACTION_BARRIER:-}" = "$1" ] || return 0
    if ! {
        [ -p "$CF_ROOT/.barrier-$1.entered" ] && [ ! -L "$CF_ROOT/.barrier-$1.entered" ] &&
        [ -p "$CF_ROOT/.barrier-$1.release" ] && [ ! -L "$CF_ROOT/.barrier-$1.release" ]
    }; then platform_fail fixture_barrier_shape; fi
    printf '%s\n' "$$" > "$CF_ROOT/.barrier-$1.entered"
    IFS= read -r platform_barrier_ack < "$CF_ROOT/.barrier-$1.release" || platform_fail fixture_barrier_read
}
platform_random_token() {
    # Read status is checked BEFORE normalization. A failed/short reader must
    # never become SHA256(empty) or another repeatable installation identity.
    platform_entropy=$(od -An -N32 -tx1 -v /dev/urandom) || platform_fail transaction_entropy_read
    [ "${#platform_entropy}" -le 128 ] || platform_fail transaction_entropy_encoding
    platform_token=$(printf '%s' "$platform_entropy" | tr -d ' \n') || platform_fail transaction_entropy_encoding
    case "$platform_token" in ''|*[!0-9a-f]*) platform_fail transaction_entropy_encoding;; esac
    [ "${#platform_token}" = 64 ] || platform_fail transaction_entropy_short_read
    printf '%s\n' "$platform_token"
}
platform_transaction_compat_clear() {
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then platform_existing_install=$CF_ROOT/.couvrefeu-install.lock
    else platform_existing_install=/tmp/couvrefeu-install.lock; fi
    if [ -e "$platform_existing_install" ] || [ -L "$platform_existing_install" ] ||
        [ -e /tmp/couvrefeu-platform.lock ] || [ -L /tmp/couvrefeu-platform.lock ]; then
        platform_fail existing_compatibility_fence_requires_explicit_recovery
    fi
}
platform_transaction_readonly_preflight() {
    # Definitions are authenticated first, and this internal mode performs no
    # admission, journal dispatch, cleanup or publication while they load.
    CF_TRANSACTION_DEFINITIONS_ONLY=1
    . "$CF_PLATFORM_LIB/install-common.sh"
    CF_TRANSACTION_DEFINITIONS_ONLY=0
    safe_paths
    if retirement_present; then
        retirement_validate
        retirement_originals
        retirement_prepared_check
        if [ -e "$BACKUP" ] || [ -L "$BACKUP" ]; then journal_preflight cleanup; fi
    else
        prepared_recovery_check
        if [ -e "$BACKUP/ready" ]; then preflight
        else prepared_originals "$PREPARED_RECOVERY_TREE"; prepared_partial_journal_check; fi
        runtime_preflight
    fi
    recovery_fence_check
    recover_private_scratch check
}
platform_transaction_begin() {
    platform_transaction_mutex
    # A complete marker can publish before its old compatibility guards retire.
    # Never overwrite that old PID/provenance before explicit recovery consumes it.
    platform_transaction_compat_clear
    CF_TRANSACTION_DIGEST=none
    CF_TRANSACTION_TOKEN=
    if [ -e "$CF_TRANSACTION_RETIREMENT" ] || [ -L "$CF_TRANSACTION_RETIREMENT" ]; then
        [ "${1:-}" = uninstall ] || platform_fail retirement_in_progress
        platform_transaction_readonly_preflight
    fi
    if [ "${1:-}" = install ] && { [ -e "$CF_TRANSACTION_FENCE" ] || [ -L "$CF_TRANSACTION_FENCE" ]; }; then platform_fail explicit_install_recovery_required; fi
    if [ -e "$CF_TRANSACTION_OWNER" ] || [ -L "$CF_TRANSACTION_OWNER" ]; then
        platform_transaction_read
        case "$CF_TRANSACTION_STATE:${1:-}" in
            complete:install|complete:uninstall|recovered:uninstall) ;;
            *) platform_fail explicit_install_recovery_required;;
        esac
    else
        # Legacy state has no new-format provenance. Never invent it.
        if [ "${CF_TEST_MODE:-0}" = 1 ]; then platform_old_lock=$CF_ROOT/.couvrefeu-install.lock
        else platform_old_lock=/tmp/couvrefeu-install.lock; fi
        if ! { [ ! -e "$platform_old_lock" ] && [ ! -L "$platform_old_lock" ]; }; then platform_fail legacy_install_lock_manual_recovery; fi
    fi
    if [ "${1:-}" = install ] && { [ -e "$CF_TRANSACTION_BASE/backup" ] || [ -L "$CF_TRANSACTION_BASE/backup" ]; }; then
        [ "$CF_TRANSACTION_DIGEST" != none ] || platform_fail legacy_installation_resume_refused
    fi
    # A retained baseline describes originals, not the requested installation
    # policy. Never reuse it to infer a new RPC/protection inventory.
    if [ "${1:-}" = install ] && [ "$CF_TRANSACTION_DIGEST" != none ] &&
        [ ! -e "$CF_TRANSACTION_BASE/backup" ] && [ ! -L "$CF_TRANSACTION_BASE/backup" ]; then
        platform_fail 'recovery required; run ordinary uninstall before retrying installation'
    fi
    if [ "$CF_TRANSACTION_DIGEST" != none ] && [ ! -e "$CF_TRANSACTION_RETIREMENT" ]; then platform_transaction_readonly_preflight; fi
    CF_TRANSACTION_STATE=active
    CF_TRANSACTION_BOOT=$(cat /proc/sys/kernel/random/boot_id) || platform_fail transaction_boot_identity
    platform_identity=$(platform_process_identity "$$") || platform_fail transaction_process_identity
    CF_TRANSACTION_PID=$$
    CF_TRANSACTION_START=${platform_identity%%:*}
    if [ -z "$CF_TRANSACTION_TOKEN" ]; then CF_TRANSACTION_TOKEN=$(platform_random_token) || platform_fail transaction_entropy_unavailable; fi
    platform_transaction_publish
    CF_TRANSACTION_OWNED=1
    trap 'platform_transaction_finish; platform_lock_release' 0
    platform_transaction_barrier ownership-published
}
platform_transaction_finish() {
    [ "${CF_TRANSACTION_OWNED:-0}" = 1 ] || return 0
    [ -e "$CF_TRANSACTION_OWNER" ] || return 0
    platform_transaction_read
    if [ -e "$CF_TRANSACTION_RETIREMENT" ] || [ -L "$CF_TRANSACTION_RETIREMENT" ]; then
        if [ -e "$CF_TRANSACTION_FENCE" ]; then CF_TRANSACTION_STATE=recovered
        else CF_TRANSACTION_STATE=complete; fi
        platform_transaction_publish
        CF_TRANSACTION_OWNED=0
        return 0
    fi
    if [ "$CF_TRANSACTION_DIGEST" = none ]; then
        rm -f "$CF_TRANSACTION_OWNER"
    elif [ ! -e "${BACKUP:-$CF_TRANSACTION_BASE/backup}" ] && [ ! -e "${DONE:-$CF_TRANSACTION_PARENT/.couvrefeu-recovery.done}" ]; then
        # Bound baselines retire only behind the exact-restoration receipt.
        CF_TRANSACTION_STATE=complete
        platform_transaction_publish
    else
        if [ -e "$CF_TRANSACTION_FENCE" ]; then CF_TRANSACTION_STATE=recovered
        else CF_TRANSACTION_STATE=complete; fi
        platform_transaction_publish
    fi
    CF_TRANSACTION_OWNED=0
}
platform_transaction_complete() {
    [ "${CF_TRANSACTION_OWNED:-0}" = 1 ] || return 0
    CF_TRANSACTION_STATE=complete
    platform_transaction_publish
}
platform_transaction_gate() {
    case "${1:-}" in rpc-status|rpc-activity|rpc-inventory|activity|status)
        platform_transaction_paths;;
        *) platform_transaction_mutex;;
    esac
    if ! { [ ! -e "$CF_TRANSACTION_RETIREMENT" ] && [ ! -L "$CF_TRANSACTION_RETIREMENT" ]; }; then platform_fail retirement_in_progress; fi
    if [ -e "$CF_TRANSACTION_OWNER" ] || [ -L "$CF_TRANSACTION_OWNER" ]; then
        platform_transaction_read
        if [ "$CF_TRANSACTION_STATE" != complete ]; then
            if ! { [ "${CF_INSTALL_TOKEN:-}" = "$CF_TRANSACTION_TOKEN" ] && [ "${CF_TRANSACTION_OWNED:-0}" = 1 ]; }; then platform_fail explicit_install_recovery_required; fi
        fi
        if [ -e "$CF_TRANSACTION_BASE/backup/ready" ] && [ ! -e "$CF_TRANSACTION_BASE/backup/complete" ]; then
            [ "${CF_TRANSACTION_OWNED:-0}" = 1 ] || platform_fail incomplete_installation
        fi
    fi
    if [ -e "$CF_TRANSACTION_FENCE" ] || [ -L "$CF_TRANSACTION_FENCE" ]; then
        if ! { [ "${CF_INSTALL_TOKEN:-}" = "${CF_TRANSACTION_TOKEN:-}" ] && [ "${CF_TRANSACTION_OWNED:-0}" = 1 ]; }; then platform_fail explicit_install_recovery_required; fi
    fi
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
    if [ "${CF_TEST_MODE:-0}" = 1 ]; then platform_retirement=$platform_root/.couvrefeu-retirement
    else platform_retirement=$platform_root/etc/.couvrefeu-retirement; fi
    if [ -e "$platform_retirement" ] || [ -L "$platform_retirement" ]; then
        platform_regular "$platform_retirement"
        platform_private "$platform_retirement" 600
        [ "$(platform_stat -c %s "$platform_retirement")" -le 32768 ] || platform_fail retirement_record_size
        platform_retirement_profile=$(sed -n '3p' "$platform_retirement")
        case "$platform_retirement_profile" in strict|gl-xe3000-4.8.3-logd-011-v1|gl-xe3000-4.8.3-os-trust-v1) ;;
            *) platform_fail retirement_profile;; esac
        [ -z "$platform_stage_profile" ] || [ "$platform_stage_profile" = "$platform_retirement_profile" ] || platform_fail conflicting_retirement
        platform_stage_profile=$platform_retirement_profile
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
        if ! { [ -d "$platform_parent" ] && [ ! -L "$platform_parent" ]; }; then platform_fail bootstrap_parent; fi
        platform_canonical "$platform_parent/."
    done
    if ! { [ -L /lib/ld-musl-aarch64.so.1 ] && [ "$(readlink /lib/ld-musl-aarch64.so.1)" = libc.so ]; }; then platform_fail loader_link; fi
    platform_hash /lib/libc.so c7ad6aff9300a5810e33ed8099057ef4515c0e711e9570309161d4014a5768ce
    platform_hash /lib/libgcc_s.so.1 6baf0c0086b0bd2915019e942a2fa7b2b4dfb4e0935db43a71fc54add13d1a69
    platform_hash /usr/libexec/stat-coreutils 774eaa80136871de03ea7c94ef713aac209cea00eddb8e7d07c7036e511499a0
    if ! { [ -L /bin/stat ] && [ "$(readlink /bin/stat)" = /usr/libexec/stat-coreutils ]; }; then platform_fail stat_alternative; fi
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
    if ! { [ -d "$platform_lib" ] && [ ! -L "$platform_lib" ]; }; then platform_fail source_directory; fi
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
        if [ -f "$CF_PLATFORM_LOCK/token" ]; then rm -f "$CF_PLATFORM_LOCK/token"; fi
        rmdir "$CF_PLATFORM_LOCK" || platform_fail lock_cleanup
        CF_PLATFORM_LOCKED=0
        CF_PLATFORM_INITIAL_WRITE=$platform_cleanup_saved
    fi
}
platform_lock_acquire() {
    if ! { [ -d /tmp ] && [ ! -L /tmp ] && [ "$(platform_stat -c '%u:%g:%a' /tmp)" = 0:0:1777 ]; }; then platform_fail tmp_metadata; fi
    CF_PLATFORM_LOCK=/tmp/couvrefeu-platform.lock
    mkdir -m 700 "$CF_PLATFORM_LOCK" 2>/dev/null || platform_fail transaction_contention
    CF_PLATFORM_LOCKED=1
    trap 'platform_lock_release' 0
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    (set -C; printf '%s\n' "$$" > "$CF_PLATFORM_LOCK/pid") || platform_fail lock_record
    if [ "${CF_TRANSACTION_OWNED:-0}" = 1 ]; then
        (set -C; printf '%s\n' "$CF_TRANSACTION_TOKEN" > "$CF_PLATFORM_LOCK/token") || platform_fail lock_record
    fi
    platform_private "$CF_PLATFORM_LOCK" 700
    platform_private "$CF_PLATFORM_LOCK/pid" 600
}
platform_lock_recover() (
    set +f
    # Explicit operation only; a partial/foreign record is never stolen.
    CF_PLATFORM_LOCK=/tmp/couvrefeu-platform.lock
    if ! { [ -d /tmp ] && [ ! -L /tmp ] && [ "$(platform_stat -c '%u:%g:%a' /tmp)" = 0:0:1777 ]; }; then platform_fail tmp_metadata; fi
    platform_private "$CF_PLATFORM_LOCK" 700
    platform_private "$CF_PLATFORM_LOCK/pid" 600
    platform_dead_pid=$(awk 'NR==1&&$0~/^[0-9]+$/{p=$0;next}{bad=1}END{if(bad||NR!=1||p<=1)exit 2;print p}' "$CF_PLATFORM_LOCK/pid") || platform_fail lock_owner
    if ! { ! kill -0 "$platform_dead_pid" 2>/dev/null && [ ! -e "/proc/$platform_dead_pid" ]; }; then platform_fail live_lock; fi
    for platform_record in "$CF_PLATFORM_LOCK"/* "$CF_PLATFORM_LOCK"/.[!.]* "$CF_PLATFORM_LOCK"/..?*; do
        [ -e "$platform_record" ] || [ -L "$platform_record" ] || continue
        [ "$platform_record" = "$CF_PLATFORM_LOCK/pid" ] || platform_fail ambiguous_lock
    done
    platform_initial_write
    rm -f "$CF_PLATFORM_LOCK/pid"
    rmdir "$CF_PLATFORM_LOCK" || platform_fail lock_cleanup
)
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
platform_service_sources() {
    [ "${CF_TEST_MODE:-0}" != 1 ] || return 0
    for service_parent in /etc /etc/init.d /lib /lib/functions /lib/config /usr /usr/share /usr/share/libubox /sbin; do
        platform_canonical "$service_parent/.parent-check"
        if ! { [ -d "$service_parent" ] && [ ! -L "$service_parent" ]; }; then platform_fail service_source_parent; fi
        service_parent_meta=$(platform_stat -c '%u:%g:%a' "$service_parent")
        case "$service_parent_meta" in 0:0:755) ;;
            0:0:775) case "$service_parent" in /etc|/etc/init.d|/lib/config|/sbin)
                platform_vendor_selected || platform_fail service_source_parent_metadata;;
                *) platform_fail service_source_parent_metadata;; esac;;
            *) platform_fail service_source_parent_metadata;; esac
    done
    # Audited OpenWrt source revision 78e4cffcd882389cb8f0bf818303f85f8d1e9c8e.
    # Unknown vendor modifications refuse; these bytes do not attest hardware
    # behavior or establish that the target binary corresponds to upstream C.
    for service_source in /etc/init.d/cron /etc/rc.common /lib/functions/procd.sh /lib/functions.sh /lib/functions/service.sh /lib/config/uci.sh /usr/share/libubox/jshn.sh /etc/init.d/firewall /sbin/procd; do
        case "$service_source" in
            /etc/init.d/cron) service_mode=755; service_pin=efd3ba0b38246cecc2d38b9604b86ee6bc2bc96eb83bd1b48c54de5d166e9094;;
            /etc/rc.common) service_mode=755; service_pin=ebeeedc132a75942ce876465e4636a75f745e468c573fdf9ad058e57e58a0341;;
            /lib/functions/procd.sh) service_mode=644; service_pin=e29a5482fe6e050ec9a14ce129416cc43819d6cc804d644014f9a86f5b615da7;;
            /etc/init.d/firewall) service_mode=755; service_pin=dbc6e31653ba3d7e57534386cf1a83523318ed9dbb0d793f7947520e33b0e776;;
            /lib/functions.sh) service_mode=644; service_pin=b2b07ca83222f8677f8117e4ed8bff162ef9e6ad0aadaa42d6248c5865831406;;
            /lib/functions/service.sh) service_mode=644; service_pin=afb750abd9c4b4eeb1e8dc5eb9f66c7d47774782494f2c168183390803db3b91;;
            /lib/config/uci.sh) service_mode=644; service_pin=0a84923c0de12443b97969b1124cb195bedcd150e5128e5e3c9c9f8458594588;;
            /usr/share/libubox/jshn.sh) service_mode=644; service_pin=c5056cf87f47d12625a5695cfc1f5b48df4807b9095665dd9c682ca977d1eb59;;
            /sbin/procd) service_mode=755; service_pin=cbd00d8102c236d3f2ee2c56c159a9133f574477ef89efc80d2be5f4daf0a3d1;;
        esac
        service_exception=0
        case "$service_source" in /lib/functions.sh|/lib/config/uci.sh)
            if platform_vendor_selected && [ "$(platform_stat -c '%u:%g:%a' "$service_source")" = 0:0:664 ]; then service_exception=1; fi;;
        esac
        if [ "$service_exception" = 1 ]; then platform_regular "$service_source"; platform_canonical "$service_source"
        else platform_private "$service_source" "$service_mode"; fi
        platform_hash "$service_source" "$service_pin"
    done
}
platform_admit() {
    platform_choose "$1" "$2"
    if platform_vendor_selected; then platform_bootstrap_vendor; fi
    platform_private "$3/platform-bootstrap.sh" 644
    if [ "${CF_TEST_MODE:-0}" != 1 ]; then platform_private "$3" 700; fi
    platform_verify_modules "$3"
    CF_PLATFORM_LIB=$3
    case "$0" in */install.sh|*/uninstall.sh)
        if [ "${CF_TEST_MODE:-0}" != 1 ]; then platform_external_closure "${3%/lib}"; fi;;
    esac
    # Persistent control records are protected writes too. Fresh vendor trust
    # and profile validation must precede their first creation/publication.
    if platform_vendor_selected; then platform_attest_vendor "$3" || platform_fail attestation; fi
    CF_PLATFORM_ADMITTED=1
    platform_profile_validate
    case "$0" in */install.sh|*/uninstall.sh) platform_service_sources;; esac
    case "$0" in
        */install.sh)
            if [ "${ACTIVATE:-0}" = 1 ]; then platform_transaction_begin install; fi;;
        */uninstall.sh) platform_transaction_begin uninstall;;
        *) :;;
    esac
    if platform_vendor_selected; then
        platform_lock_acquire
    fi
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
    # Unpublished copies have an exact owner-token binding. A partial candidate
    # is never executed; only a complete verified tree obtains the public name.
    platform_release_container=${platform_target_release%/*}/.couvrefeu-release-candidate.$CF_TRANSACTION_TOKEN
    platform_release_candidate=$platform_release_container/${platform_target_release##*/}
    platform_initial_write
    if [ -e "$platform_release_container" ] || [ -L "$platform_release_container" ]; then
        platform_release_container_check "$platform_release_container" "${platform_target_release##*/}"
    else mkdir -m 700 "$platform_release_container" || platform_fail release_candidate_container; fi
    if [ -e "$platform_release_candidate" ] || [ -L "$platform_release_candidate" ]; then
        platform_release_candidate_check "$platform_release_candidate" "$platform_source_release"
    else mkdir -m 700 "$platform_release_candidate" || platform_fail release_collision; fi
    if [ ! -e "$platform_release_candidate/lib" ]; then mkdir -m 700 "$platform_release_candidate/lib" || platform_fail release_directory; fi
    while read -r platform_digest platform_file; do
        cp "$platform_source_release/$platform_file" "$platform_release_candidate/$platform_file" || platform_fail release_copy
        case "$platform_file" in lib/*) platform_mode=644;; *) platform_mode=755;; esac
        chmod "$platform_mode" "$platform_release_candidate/$platform_file" || platform_fail release_copy_metadata
    done < "$platform_source_release/release.sha256"
    cp "$platform_source_release/release.sha256" "$platform_release_candidate/release.sha256"
    chmod 600 "$platform_release_candidate/release.sha256"
    platform_external_closure "$platform_release_candidate"
    platform_release_candidate_check "$platform_release_candidate" "$platform_source_release"
    sync
    platform_transaction_mutex_check
    if [ -e "$platform_target_release" ] || [ -L "$platform_target_release" ]; then platform_fail release_publication_collision; fi
    # Verified BusyBox1.33: fixed-basename CHILD -> existing PARENT never nests
    # into an existing leaf; -n can return0 on skip, hence the sourcegone proof.
    # All authorized publishers hold this mutex; this is not renameat2/CAS
    # against an uncoordinated administrator modifying private paths.
    mv -n "$platform_release_candidate" "${platform_target_release%/*}/" || platform_fail release_publish
    if [ -e "$platform_release_candidate" ] || [ -L "$platform_release_candidate" ]; then platform_fail release_publication_collision; fi
    sync
    platform_external_closure "$platform_target_release"
    rmdir "$platform_release_container" || platform_fail release_candidate_container_cleanup
}
platform_release_container_check() (
    set +f
    platform_private "$1" 700
    if ! { [ -d "$1" ] && [ ! -L "$1" ]; }; then platform_fail release_candidate_container; fi
    for platform_container_entry in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        [ -e "$platform_container_entry" ] || [ -L "$platform_container_entry" ] || continue
        [ "${platform_container_entry##*/}" = "$2" ] || platform_fail foreign_release_candidate_container
    done
)
platform_release_candidate_check() (
    set +f
    platform_candidate=$1 platform_candidate_source=$2
    platform_private "$platform_candidate" 700
    if ! { [ -d "$platform_candidate" ] && [ ! -L "$platform_candidate" ]; }; then platform_fail release_candidate_directory; fi
    if [ -e "$platform_candidate/lib" ] || [ -L "$platform_candidate/lib" ]; then
        platform_private "$platform_candidate/lib" 700
        if ! { [ -d "$platform_candidate/lib" ] && [ ! -L "$platform_candidate/lib" ]; }; then platform_fail release_candidate_lib; fi
    fi
    platform_candidate_names=$(awk '{print $2}' "$platform_candidate_source/release.sha256")
    for platform_candidate_entry in "$platform_candidate"/* "$platform_candidate"/.[!.]* "$platform_candidate"/..?* "$platform_candidate"/lib/* "$platform_candidate"/lib/.[!.]* "$platform_candidate"/lib/..?*; do
        [ -e "$platform_candidate_entry" ] || [ -L "$platform_candidate_entry" ] || continue
        platform_candidate_name=${platform_candidate_entry#"$platform_candidate"/}
        [ "$platform_candidate_name" != lib ] || continue
        case "$platform_candidate_name" in release.sha256) platform_candidate_mode=600;;
            *) printf '%s\n' "$platform_candidate_names" | awk -v name="$platform_candidate_name" '$0==name{found=1}END{exit !found}' || platform_fail foreign_release_candidate_entry
                case "$platform_candidate_name" in lib/*) platform_candidate_mode=644;; *) platform_candidate_mode=755;; esac;;
        esac
        platform_regular "$platform_candidate_entry"
        platform_candidate_meta=$(platform_stat -c '%u:%g:%a:%h' "$platform_candidate_entry")
        case "$platform_candidate_meta" in "$CF_PLATFORM_OWNER:600:1"|"$CF_PLATFORM_OWNER:$platform_candidate_mode:1") ;;
            *) platform_fail release_candidate_metadata;; esac
        [ "$(platform_stat -c %s "$platform_candidate_entry")" -le "$(platform_stat -c %s "$platform_candidate_source/$platform_candidate_name")" ] || platform_fail release_candidate_size
    done
)
platform_valid_done() {
    platform_private "$1" 600
    [ "$(platform_done_profile "$1")" = "$CF_PLATFORM_PROFILE" ] || return 1
    # The parser accepts only exact bounded DONE2 or bound DONE3 bytes.
}
platform_done_candidate_check() {
    [ -e "$DONE.next" ] || [ -L "$DONE.next" ] || return 0
    if [ -e "$DONE" ] || [ -L "$DONE" ]; then platform_fail completion_publication_collision; fi
    platform_regular "$DONE.next"
    platform_private "$DONE.next" 600
    [ "$(platform_stat -c %h "$DONE.next")" = 1 ] || platform_fail completion_candidate_hardlink
    if [ "${CF_TRANSACTION_DIGEST:-none}" = none ]; then
        platform_valid_done "$DONE.next" || platform_fail completion_publication_collision
        return 0
    fi
    # Only the bound transaction after its durable exact-restoration marker can
    # own a partial fixed-name completion publication. Check every byte, including
    # NULs/trailing newlines, before any owner handover or scratch removal.
    platform_regular "$BACKUP/restored"
    platform_private "$BACKUP/restored" 600
    printf '2\n' | cmp -s - "$BACKUP/restored" || platform_fail completion_candidate_phase
    platform_done_size=$(platform_stat -c %s "$DONE.next")
    platform_done_limit=$(printf '3\n%s\n%s\n' "$CF_PLATFORM_PROFILE" "$CF_RELEASE_ID" | wc -c)
    [ "$platform_done_size" -le "$platform_done_limit" ] || platform_fail completion_candidate_size
    printf '3\n%s\n%s\n' "$CF_PLATFORM_PROFILE" "$CF_RELEASE_ID" |
        dd bs=1 count="$platform_done_size" 2>/dev/null |
        cmp -s - "$DONE.next" || platform_fail completion_candidate_bytes
}
platform_publish_done() {
    # Publishing a bounded cleanup binding is permitted only after all exact
    # restoration proofs and verification of the external immutable closure.
    if [ "${CF_TEST_MODE:-0}" != 1 ]; then platform_external_closure "$HERE"; fi
    if ! { [ ! -e "$DONE" ] && [ ! -L "$DONE" ]; }; then platform_fail completion_collision; fi
    platform_done_candidate_check
    if [ -e "$DONE.next" ]; then
        platform_initial_write
        rm -f "$DONE.next"
    fi
    platform_initial_write
    (set -C; : > "$DONE.next") || platform_fail completion_write
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CRASH_AT:-}" = completion-empty ]; then kill -KILL "$$"; fi
    if [ "${CF_TEST_MODE:-0}" = 1 ] && [ "${CF_TEST_UNINSTALL_CRASH_AT:-}" = completion-prefix ]; then
        printf '3\n' > "$DONE.next"
        kill -KILL "$$"
    fi
    printf '3\n%s\n%s\n' "$CF_PLATFORM_PROFILE" "$CF_RELEASE_ID" > "$DONE.next" || platform_fail completion_write
    platform_initial_write
    chmod 600 "$DONE.next"
    sync
    mv "$DONE.next" "$DONE" || platform_fail completion_publish
    sync
}

# Explicit fixture adapters exercise the actual target applet implementations;
# production never accepts an environment-selected command.
if [ "${CF_TEST_MODE:-0}" = 1 ]; then
    if [ -n "${CF_TEST_FLOCK:-}" ]; then
        case "$CF_TEST_FLOCK" in /*/busybox\ flock) CF_TEST_FLOCK_BINARY=${CF_TEST_FLOCK% flock};;
            *) platform_fail fixture_flock_adapter;; esac
        if ! { [ -f "$CF_TEST_FLOCK_BINARY" ] && [ ! -L "$CF_TEST_FLOCK_BINARY" ] && [ -x "$CF_TEST_FLOCK_BINARY" ]; }; then platform_fail fixture_flock_binary; fi
        flock() { "$CF_TEST_FLOCK_BINARY" flock "$@"; }
    fi
    if [ -n "${CF_TEST_MV:-}" ]; then
        case "$CF_TEST_MV" in /*/busybox\ mv) CF_TEST_MV_BINARY=${CF_TEST_MV% mv};;
            *) platform_fail fixture_mv_adapter;; esac
        if ! { [ -f "$CF_TEST_MV_BINARY" ] && [ ! -L "$CF_TEST_MV_BINARY" ] && [ -x "$CF_TEST_MV_BINARY" ]; }; then platform_fail fixture_mv_binary; fi
        mv() { "$CF_TEST_MV_BINARY" mv "$@"; }
    fi
fi
