<!-- Generated: 2026-11-24 | Files scanned: ~496 (origin/main 727daf6) | Token estimate: ~560 -->
# Dependencies
Runtime: `@simplewebauthn/server` 14.1.0 only (service). Node 26.13.1, npm 11.21.3 (engines, AGENTS.md, CI, Dockerfile: exact pins).
Dev: typescript 7.0.2, @playwright/test 1.65.1, @types/node 26.6.6, @levischuck/tiny-cbor 0.3.6. `tsc --noEmit`, no build step (node runs .ts).
Node built-ins used: node:sqlite, https/http, child_process (ssh), crypto.

External services (all optional or off by default):
- ntfy: content-free admin push (`push.enabled`); `COUVRE_NTFY_URL/TOPIC/TOKEN` env; push-sender.ts.
- NextDNS: `https://api.nextdns.io`, `X-Api-Key` (nextdns-client.ts; `contentFilter` modes); refuses when HTTPS_PROXY/ALL_PROXY/NODE_USE_ENV_PROXY would sit in the path.
- Router over SSH: `/usr/bin/ssh` (ssh-router.ts); CT107 image installs `openssh-client`; a dedicated ssh-agent unit holds the key.
- External heartbeat monitor: deploy/heartbeat.sh pushes to a URL read from a root-only file (a credential).

Router tools (OpenWrt, GL.iNet class): BusyBox 1.33 ash + awk (no bash/python), iptables/ip6tables + ipset (fw3), conntrack, uci, dropbear (forced command), crond, sha256sum, timeout. Tools resolved via fixed backend path lists in core.sh.
Dev/CI-only: python3 (fixture runners, tools/), busybox, shellcheck.

Deploy (CT107, deploy/): docker/{Dockerfile (node:26.13.1-slim pinned by digest, `npm ci --omit=dev`), compose.yaml, healthcheck.mjs}; systemd/{couvrefeu, -agent, -backup(.timer), -heartbeat(.timer), couvrefeu.nft}; backup.mjs; heartbeat.sh. Tests: tests/test-deploy-units.py, test-heartbeat.py.

CI (.github/workflows/ci.yml, "isolated-project-checks"; actions checkout@v7, setup-node@v7, upload-artifact@v7, download-artifact@v8, local `pinned-busybox` 1.33.1):
1. `fixture_preflight`: freeze check, `tests/run.sh --static-only`, timeout audit, acceptance preflight, publish fixture plan.
2. `preflight_suites`: ~16 entries (install, install-recovery, platform-integration x4, os-trust x3, permanent-install, bundled suites); matrix guarded against tests/run.sh.
3. `fixture_shards`: 43 partitions (10 suites x 4, plus a fifth each for test-core.py, test-penn-pilot.py and test-rpc.py; `PARTITION_COUNTS` in tests/run-fixtures.py); receipts per shard.
4. `fixtures`: gate requiring 1-3 and all 43 unique partitions.
5. `local-demo`: `npm ci`, typecheck, `npm run test:service`, Playwright chromium, `npm run test:web`.
Tests: tests/test-*.py (router fixtures; test-timeout-audit.py fails unjustified tight timeouts), service/tests (97) + shared/tests (15) via node --test, web/tests (28 specs).
