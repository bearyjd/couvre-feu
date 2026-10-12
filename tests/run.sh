#!/bin/sh
# Recovery fixtures run before any core fixture. No host/router network writes.
set -eu
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"
case "${1:-}" in
    '') [ "$#" = 0 ] || { printf 'usage: tests/run.sh [--preflight-only]\n' >&2; exit 2; }; preflight_only=0;;
    --preflight-only) [ "$#" = 1 ] || { printf 'usage: tests/run.sh [--preflight-only]\n' >&2; exit 2; }; preflight_only=1;;
    *) printf 'usage: tests/run.sh [--preflight-only]\n' >&2; exit 2;;
esac
is_shell() {
    case "$1" in *.sh) return 0;; esac
    case "$(head -n 1 "$1")" in '#!'*sh*) return 0;; esac
    return 1
}
printf '%s\n' 'Evidence: isolated fixtures only; packet and live-router gates pending.'
python3 tests/test-install.py
python3 tests/test-platform-integration.py
python3 tests/test-os-trust.py
python3 tests/test-client-probe.py

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck --version
else
    printf '%s\n' 'FAIL: shellcheck is required for the complete fixture gate.' >&2
    exit 1
fi
find router tests -type f | {
    static_failed=0
    while IFS= read -r script; do
        if is_shell "$script"; then
            # ShellCheck 0.9 cannot resolve sourced refusal functions or
            # indirectly invoked vendor callbacks. Keep compatibility exclusions
            # on these exact files; all other diagnostics remain enabled.
            case "$script" in
                router/lib/platform-bootstrap.sh) shellcheck_excludes=SC2015,SC2317;;
                router/lib/vendor-platform.sh|router/lib/install-common.sh|router/install.sh|router/cfctl) shellcheck_excludes=SC2015;;
                *) shellcheck_excludes=;;
            esac
            if ! shellcheck -s sh --exclude="$shellcheck_excludes" "$script"; then static_failed=1; fi
            if command -v busybox >/dev/null 2>&1; then
                if ! busybox ash -n "$script"; then static_failed=1; fi
            else
                if ! sh -n "$script"; then static_failed=1; fi
            fi
        fi
    done
    [ "$static_failed" -eq 0 ]
}
if ! command -v busybox >/dev/null 2>&1; then
    printf '%s\n' 'PENDING: BusyBox ash runtime; host sh syntax alone is not ash proof.'
fi
if [ "$preflight_only" = 1 ]; then
    printf '%s\n' 'PASS: installer recovery, adapter, probe and static preflight; runtime shards follow.'
    exit 0
fi
python3 tests/run-fixtures.py
printf '%s\n' 'PASS: fixture and available static checks. Real fw3/packet/live tests remain pending.'
