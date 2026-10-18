<!-- Generated: 2026-10-17 | Files scanned: 198 | Token estimate: ~214 -->
# Dependencies
Runtime: `@simplewebauthn/server` 13.3.3 only (service). Node 26.8.1, npm 11.19.0 (engines, exact pins).
Dev: typescript 7.0.2, @playwright/test 1.61.0, @types/node 26.6.5, @levischuck/tiny-cbor 0.2.11. `tsc --noEmit`, no build step (node runs .ts).
Node built-ins used: node:sqlite, https/http, child_process (ssh), crypto.

Router tools (OpenWrt, GL.iNet class): BusyBox 1.33 ash + awk (no bash/python), iptables/ip6tables + ipset (fw3), conntrack, uci, dropbear (forced command), crond, sha256sum, timeout. Tools resolved via fixed backend path lists in core.sh.
Dev/CI-only: python3 (fixture runners, tools/), busybox, shellcheck.

CI (.github/workflows/ci.yml, "isolated-project-checks"):
1. preflight: installer recovery/adapter/probe/static checks, publish fixture plan.
2. matrix: 16 bounded fixture partitions (python tests/run-fixtures.py), shard receipts.
3. gate: require preflight + all matrix; verify 16 unique partitions match source discovery.
4. node job: `npm ci`, `npm run typecheck && npm run test:service`, playwright chromium, `npm run test:web`.
Tests: tests/test-*.py (router fixtures), service/tests + shared/tests (node --test), web/tests.
