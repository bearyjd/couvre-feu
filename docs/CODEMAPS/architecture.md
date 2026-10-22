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
  -> fw3 iptables/ipset slots cf2_{a,b}_*  + cron "* * * * * cfctl expire"
```

Entry points
- `npm run demo:start` main.ts: fake router (demo-router/) + synthetic data.
- `npm run integration:start <manifest>` integration-main.ts: real router over SSH; dispatch only if manifest `dispatch.enabled`.
- `integration:bootstrap` issues CLI-only enrollment token; `integration:dispatch` operator dispatch.
- Router: install.sh / uninstall.sh / cfctl, release pinned by router/release.sha256 (tools/freeze-router-release.py). The shipped tree is `--emit`ted: cfctl-ssh and cfctl-scope lose their CF_TEST_MODE block (tools/strip-test-mode.py); release.sha256 and CF_RELEASE_ID cover the stripped wrapper bytes.

Trust boundaries
- Service never gets a shell: cfctl-ssh accepts only `cfctl rpc-*|status|pause|resume|sync|expire|apply-fw` tokens.
- Router is source of truth for enforcement; service holds desired policy (revision CAS) and an observation.
- Time-limited pause/allowance expires on router via cron even if service is down.

Maps: [backend](backend.md) [frontend](frontend.md) [data](data.md) [dependencies](dependencies.md) [router](router.md) [live-tools](live-tools.md)

Layout: router/ service/ shared/src (contracts, router-rpc, router-schema, activity-evidence, schedule-edit) web/public tools/ tests/ docs/ demo-router/src.
