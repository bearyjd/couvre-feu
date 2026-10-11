# Repository Guidelines

## Project Structure & Module Organization

- `router/`: POSIX ash enforcement commands (`cfctl`, `cfctl-ssh`), helpers, firewall integration, cron, and installation/recovery scripts.
- `shared/`: TypeScript contracts, validation, RPC parsing, and shared tests.
- `service/`: authentication, policy persistence, integration workers, SQLite migrations, and tests.
- `demo-router/`: the fictional router and scenario tools.
- `web/public/`: parent UI, styles, service worker, and static assets; `web/tests/` contains browser scenarios.
- `tests/`: Python router fixtures, acceptance scripts, and client probes. `docs/` contains PRPs, contracts, spike findings, and runbooks.

## Build, Test, and Development Commands

Use Node **26.8.1** and npm **11.19.0**. Node runs TypeScript directly.

- `npm ci`: install locked dependencies.
- `npm run demo:router` and `npm run demo:start`: start the fictional router and loopback parent service in separate terminals.
- `npm run demo:bootstrap -- bryn`: generate a fictional parent's enrollment token.
- `npm run typecheck`: check strict TypeScript without emitting files.
- `npm run test:service`: run Node's service and shared test suites.
- `npx playwright install chromium`, then `npm run test:web`: install Chromium and run browser tests.
- `sh tests/run.sh`: run installer recovery, probe, core, RPC, and shell checks.
- `sh tests/acceptance.sh --preflight`: check local prerequisites; consult the acceptance runbooks for live checks.

## Coding Style & Naming Conventions

Follow nearby formatting; TypeScript and shell source generally use four-space indentation. Use ESM imports with explicit `.ts` extensions and preserve strict typing. Router scripts must work in BusyBox ash without Bash extensions. Use descriptive hyphenated TypeScript filenames and `cf_sched_*` for owned firewall schedule rules. ShellCheck checks shell code; no standalone formatter is configured.

## Testing Guidelines

Name Node tests `*.test.ts`, Playwright scenarios `*.spec.ts`, and Python fixtures `test-*.py`. Add meaningful failure, concurrency, and recovery regressions for enforcement changes. No numeric coverage threshold is configured. Fixtures use isolated temporary backends; passing fixtures never establishes real packet behavior.

## Commit & Pull Request Guidelines

Use concise imperative subjects, following existing `Add`, `Validate`, and `docs:` examples. PRs should explain behavior, validation, known gaps, and deviations from the relevant PRP. Include screenshots for UI changes. Merge only after green exact-commit CI and independent adversarial review.

## Security & Configuration

Obtain approval for each exact live-router invocation, including reads. Test uninstall/restoration before enrollment, use only explicitly authorized devices, and preserve protected management MACs. Never change dnsmasq configuration or the WAN zone. Keep credentials, household identities, manifests, databases, and raw captures private. Preserve recovery journals when drift causes refusal.
