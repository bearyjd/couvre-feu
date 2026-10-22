# Contributing

Couvre-feu is a router enforcement layer (POSIX ash under `router/`), a TypeScript policy service (`service/`, `shared/`), a fictional demo router (`demo-router/`) and a parent PWA (`web/`). Read [`AGENTS.md`](../AGENTS.md) first; this file adds the practical commands and the review gates. Fixtures never establish real packet behavior.

## Prerequisites

<!-- AUTO-GENERATED -->
| Tool | Version | Needed for |
|---|---|---|
| Node.js | `26.8.1` (pinned in `package.json` `engines` and CI) | Service, shared, demo router, Playwright. Node runs `.ts` directly |
| npm | `11.19.0` (pinned) | `npm ci` from the lockfile |
| Python 3 | any recent 3.x | Router fixtures under `tests/`, `tools/freeze-router-release.py`, `tools/live/*` |
| BusyBox | with `ash`, `awk`, `timeout` applets | Router fixtures. CI runs them under BusyBox, not the host `sh` |
| ShellCheck | any (CI installs the Ubuntu package) | Static gate in `tests/run.sh` (it fails without it) |
| Chromium | via `npx playwright install chromium` | `npm run test:web` |
<!-- /AUTO-GENERATED -->

Host `sh -n` alone is not ash proof: `tests/run.sh` reports `PENDING` when BusyBox is missing.

## Commands

<!-- AUTO-GENERATED -->
| Command | Purpose |
|---|---|
| `npm ci` | Install locked dependencies |
| `npm run typecheck` | `tsc --noEmit`, strict |
| `npm run test:service` | Node test runner over `shared/tests/*.test.ts` and `service/tests/*.test.ts` |
| `npm run test:web` | Playwright browser scenarios (`web/playwright.config.ts`) |
| `npm run demo:router` | Start the fictional router (own terminal) |
| `npm run demo:start` | Start the loopback demo parent service |
| `npm run demo:bootstrap -- <name>` | Generate a fictional parent's enrollment token |
| `npm run demo:scenario` | Demo router scenario CLI |
| `npm run integration:start -- "<PRIVATE_MANIFEST>"` | Integration-mode service |
| `npm run integration:bootstrap -- "<PRIVATE_MANIFEST>" "<ACCOUNT_ID>"` | Enroll an account in integration mode |
| `npm run integration:dispatch -- prepare\|execute\|stop ...` | Permit-bound router dispatch (see [integration-004](integration-004.md)); never run against a real router without approval of the exact invocation |
| `sh tests/run.sh` | Router static gate plus all router fixture suites (slow) |
| `sh tests/run.sh --preflight-only` | Recovery, adapter, probe, ShellCheck and `ash -n` only |
| `sh tests/acceptance.sh --preflight` | Read-only local prerequisite report |
| `python3 tools/freeze-router-release.py` | Refreeze router release pins |
| `python3 tools/freeze-router-release.py --check` | Read-only check that pins are current |
| `python3 tools/freeze-router-release.py --emit DIR` | Write the shippable router tree (wrappers stripped of CF_TEST_MODE); release.sha256 covers the emitted bytes |
<!-- /AUTO-GENERATED -->

## Running the test suites

**Service and web.** `npm ci && npm run typecheck && npm run test:service`, then `npx playwright install chromium && npm run test:web`. This is the CI `local-demo` job.

**Router fixtures.** The five large suites (`test-transition.py`, `test-rpc.py`, `test-core.py`, `test-fixture-process.py`, `test-penn-pilot.py`) are slow. CI splits each into 4 partitions (20 shards) and proves every case ran. Mirror that locally instead of running `sh tests/run.sh` end to end:

```sh
export CF_TEST_SHELL="busybox ash" CF_TEST_AWK="busybox awk" CF_TEST_TIMEOUT="busybox timeout" CF_TEST_WORKERS=1
python3 tools/freeze-router-release.py --check
sh tests/run.sh --preflight-only
python3 tests/run-fixtures.py --write-plan "$PRIVATE_DIR/plan.json"
python3 tests/run-fixtures.py --shard test-core.py --partition 0 --plan "$PRIVATE_DIR/plan.json" --receipt "$PRIVATE_DIR/test-core.0.json"
python3 tests/run-fixtures.py --verify-receipts "$PRIVATE_DIR/receipts" --plan "$PRIVATE_DIR/plan.json"
```

`--shard` takes one of the five suites and `--partition` 0 to 3. A lane that skips a case is a failure. Smaller suites (`test-install.py`, `test-no-dev-stdin.py`, `test-platform-integration.py`, `test-os-trust.py`, `test-client-probe.py`, `test-live-rehearsal.py`) run directly with `python3 tests/<name>.py`.

**TMPDIR.** Fixtures and the integration service require private roots. A path whose ancestors are symlinks or writable by other users (without the sticky bit, owned by root) is refused with `unsafe_private_ancestor`. Point `TMPDIR` at a directory under your home that only you can write, mode 0700, and keep evidence and manifests there, never in the repository.

## Environment variables

<!-- AUTO-GENERATED -->
Read by code today; there is no `.env.example` and nothing is read from a dotenv file.

| Variable | Read by | Default | Scope |
|---|---|---|---|
| `CF_DEMO_PORT` | demo service config | `4173` | Demo only |
| `CF_DEMO_DATA_DIR` | demo service config | `.demo-data` | Demo only |
| `CF_ACTIVITY_RETENTION_DAYS` | activity store | built-in default; integer 1 to 365, otherwise `invalid_activity_retention_days` | Service |
| `CF_WEB_TEST_PORT` | `web/playwright.config.ts` | `4273` | CI/test only |
| `CF_BROWSER_EXECUTABLE`, `CF_BROWSER_FONTCONFIG` | Playwright config | unset | Local test override |
| `CF_TEST_SHELL`, `CF_TEST_AWK`, `CF_TEST_TIMEOUT`, `CF_TEST_WORKERS` | router fixtures | host `sh`; CI sets `busybox ash`, `busybox awk`, `busybox timeout`, `1` | CI/test only |
| `CF_ACCEPT_LIVE`, `CF_BACKEND_*`, `CF_PLATFORM_*`, `CF_RELEASE_*`, `CF_INSTALL_TOKEN`, `CF_PROBE_*` | router scripts and probes | internal | Set by the installer or tests; do not set by hand |

Integration mode is configured by the private manifest, not by environment variables. Its fields are documented in [integration-004](integration-004.md).
<!-- /AUTO-GENERATED -->

## Router coding rules

Router code runs on BusyBox 1.33 ash and awk (OpenWrt).

- Never use `/dev/stdin`, `/dev/fd/*`, `/dev/std*` or `/proc/self/fd/*`. OpenWrt has none, BusyBox awk opens operands literally, and gawk on CI hid this. `tests/test-no-dev-stdin.py` enforces it.
- No Bash extensions. `tests/run.sh` runs `shellcheck -s sh` and `busybox ash -n` on every shell file.
- Sort with `LC_ALL=C sort`. Stored MAC sets are C-sorted.
- BusyBox sort places `SET` rows before `SETDEF` rows; see the snapshot ordering in `router/lib/firewall.sh` and [router-transition-design](router-transition-design.md).
- Release pins are frozen. After any change under `router/` that is covered by the manifest, run `python3 tools/freeze-router-release.py` and commit the result. CI runs it with `--check` and fails on `not frozen: router/<file>`.
- Never change dnsmasq configuration or the WAN zone. Owned schedule rules use the `cf_sched_*` prefix.

## Pull request checklist

- [ ] Concise imperative subject; the body explains behavior, validation, known gaps and deviations from the PRP.
- [ ] `npm run typecheck`, `npm run test:service` and (for UI) `npm run test:web` pass; UI changes include screenshots.
- [ ] Router changes: BusyBox fixtures pass sharded as in CI, `freeze-router-release.py --check` is clean, and regressions cover failure, concurrency and recovery.
- [ ] Router or enforcement changes have a live rehearsal ([runbook](runbooks/live-first-rehearsal.md)) approved for the exact invocation before they are called accepted.
- [ ] No real MACs, IPs, hostnames, credentials, manifests, databases or captures. Use placeholders: MACs `02:00:00:00:00:xx`, IPs in `192.0.2.0/24`.
- [ ] Independent adversarial review of the exact head commit, and green CI on that exact commit, before merge.
- [ ] Never push to `main`; merge through the PR.
