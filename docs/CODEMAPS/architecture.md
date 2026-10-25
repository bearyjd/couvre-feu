<!-- Generated: 2026-10-17 | Files scanned: ~200 | Token estimate: ~299 -->
# Architecture
Monorepo: router (OpenWrt ash/awk) + service (Node 26.8.1 TS, no build) + static PWA.

```
parent browser (PWA, passkey)
  -> reverse proxy / NPM (TLS)            or direct TLS listener (tls.ts)
  -> service/src/http.ts  (trustedProxies allow-list, CSRF, cookies)
  -> Auth / PolicyService | IntegrationPolicy -> SQLite (service/src/db.ts)
  -> IntegrationWorker (single claim, lease) -> SSHRouter (ssh-router.ts)
  -> dropbear forced command router/cfctl-ssh (token grammar)
  -> cfctl rpc-sync | rpc-status | rpc-activity (router/lib/rpc.sh)
  -> fw3 iptables/ipset slots cf2_{a,b}_*  + generation-bound immutable cron callback
```

Entry points
- `npm run demo:start` main.ts: fake router (demo-router/) + synthetic data.
- `npm run integration:start <manifest>` integration-main.ts: real router over SSH; dispatch only if manifest `dispatch.enabled`.
- `integration:bootstrap` issues CLI-only enrollment token; `integration:dispatch` operator dispatch.
- Router: install.sh / uninstall.sh / cfctl, release pinned by router/release.sha256 (tools/freeze-router-release.py). The shipped tree is `--emit`ted: cfctl-ssh and cfctl-scope lose their CF_TEST_MODE block (tools/strip-test-mode.py); release.sha256 covers final emitted bytes; version-2 CF_RELEASE_ID binds all emitted sources, including install/uninstall/bootstrap, with generated assignments normalized to break pin cycles.

Trust boundaries
- Service never gets a shell: cfctl-ssh accepts only `cfctl rpc-*|status|pause|resume|sync|expire|apply-fw` tokens.
- Router is source of truth for enforcement; service holds desired policy (revision CAS) and an observation.
- Time-limited pause/allowance expires via the immutable generation-bound cron callback even if service is down.
- A permanent kernel mutex fences install/runtime/recovery workers; immutable PREPARED and a final retirement receipt bind exact restoration. Admin-only external-source recovery precedes the single uninstaller. Production legacy automatic restore refuses; target eligibility remains UNVERIFIED. [Recovery contract](../runbooks/vendor-platform-admission.md).

Maps: [backend](backend.md) [frontend](frontend.md) [data](data.md) [dependencies](dependencies.md) [router](router.md) [live-tools](live-tools.md)

Layout: router/ service/ shared/src (contracts, router-rpc, router-schema, activity-evidence, schedule-edit) web/public tools/ tests/ docs/ demo-router/src.
