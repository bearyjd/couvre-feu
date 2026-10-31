<!-- Generated: 2026-10-29 | Files scanned: ~200 | Token estimate: ~214 -->
# Dependencies
Runtime: `@simplewebauthn/server` 13.3.3 only (service). Node 26.8.1, npm 11.19.0 (engines, exact pins).
Dev: typescript 7.0.2, @playwright/test 1.61.0, @types/node 26.6.5, @levischuck/tiny-cbor 0.2.11. `tsc --noEmit`, no build step (node runs .ts).
Node built-ins used: node:sqlite, https/http, child_process (ssh), crypto.

Router tools (OpenWrt, GL.iNet class): BusyBox 1.33 ash + awk (no bash/python), iptables/ip6tables + ipset (fw3), conntrack, uci, dropbear (forced command), crond, sha256sum, timeout. Tools resolved via fixed backend path lists in core.sh.
Dev/CI-only: python3 (fixture runners, tools/), busybox, shellcheck.

CI (.github/workflows/ci.yml, "isolated-project-checks"):
1. preflight: installer recovery/adapter/probe/static checks, timeout audit, publish fixture plan.
2. matrix: 38 bounded fixture partitions (9 suites x 4, plus a fifth each for test-core.py and test-penn-pilot.py; `PARTITION_COUNTS` in tests/run-fixtures.py), run with python tests/run-fixtures.py; shard receipts.
3. gate: require preflight + all matrix; verify all 38 unique partitions match source discovery.
4. node job: `npm ci`, `npm run typecheck && npm run test:service`, playwright chromium, `npm run test:web`.
Tests: tests/test-*.py (router fixtures; tests/test-timeout-audit.py fails on unjustified tight hard-coded test timeouts, see CONTRIBUTING), service/tests + shared/tests (node --test), web/tests.
