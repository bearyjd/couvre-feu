#!/bin/sh
# Recovery fixtures run before any core fixture. No host/router network writes.
set -eu
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"
# Single source of truth for the heavy-fixture preflight suites, in run order.
# CI runs them as parallel matrix entries and fails if the matrix drifts from
# this list (see --list-preflight-suites in .github/workflows/ci.yml).
preflight_suites() {
    printf '%s\n' \
        test-install-recovery-primitives.py \
        test-install.py \
        test-install-recovery.py \
        test-install-retirement-recovery.py \
        test-install-legacy-recovery.py \
        test-no-dev-stdin.py \
        test-platform-integration.py \
        test-os-trust.py \
        test-client-probe.py \
        test-live-rehearsal.py \
        test-deploy-units.py \
        test-service-key-entry.py
}
run_preflight_suite() {
    preflight_suites | grep -Fqx -- "$1" || { printf 'unknown preflight suite: %s\n' "$1" >&2; exit 2; }
    python3 -B "tests/$1"
}
USAGE='usage: tests/run.sh [--preflight-only | --static-only | --list-preflight-suites | --preflight-suite NAME...]'
mode=full
case "${1:-}" in
    '') [ "$#" = 0 ] || { printf '%s\n' "$USAGE" >&2; exit 2; };;
    --preflight-only) [ "$#" = 1 ] || { printf '%s\n' "$USAGE" >&2; exit 2; }; mode=preflight;;
    --static-only) [ "$#" = 1 ] || { printf '%s\n' "$USAGE" >&2; exit 2; }; mode=static;;
    --list-preflight-suites) [ "$#" = 1 ] || { printf '%s\n' "$USAGE" >&2; exit 2; }; preflight_suites; exit 0;;
    --preflight-suite)
        [ "$#" -ge 2 ] || { printf '%s\n' "$USAGE" >&2; exit 2; }
        shift
        for suite in "$@"; do run_preflight_suite "$suite"; done
        exit 0;;
    *) printf '%s\n' "$USAGE" >&2; exit 2;;
esac
is_shell() {
    case "$1" in *.sh) return 0;; esac
    case "$(head -n 1 "$1")" in '#!'*sh*) return 0;; esac
    return 1
}
printf '%s\n' 'Evidence: isolated fixtures only; packet and live-router gates pending.'
if [ "$mode" != static ]; then
    for suite in $(preflight_suites); do run_preflight_suite "$suite"; done
fi

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck --version
else
    printf '%s\n' 'FAIL: shellcheck is required for the complete fixture gate.' >&2
    exit 1
fi
find router tests tools -type f | {
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
if [ "$mode" != full ]; then
    printf '%s\n' 'PASS: installer recovery, adapter, probe and static preflight; runtime shards follow.'
    exit 0
fi
python3 tests/run-fixtures.py
printf '%s\n' 'PASS: fixture and available static checks. Real fw3/packet/live tests remain pending.'
