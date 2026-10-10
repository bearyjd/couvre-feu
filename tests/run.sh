#!/bin/sh
# Recovery fixtures run before any core fixture. No host/router network writes.
set -eu
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"
is_shell() {
    case "$1" in *.sh) return 0;; esac
    case "$(head -n 1 "$1")" in '#!'*sh*) return 0;; esac
    return 1
}
printf '%s\n' 'Evidence: isolated fixtures only; packet and live-router gates pending.'
python3 tests/test-install.py

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
            if ! shellcheck -s sh "$script"; then static_failed=1; fi
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
python3 tests/test-core.py
printf '%s\n' 'PASS: fixture and available static checks. Real fw3/packet/live tests remain pending.'
