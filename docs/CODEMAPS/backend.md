<!-- Generated: 2026-10-17 | Files scanned: ~200 | Token estimate: ~340 -->
# Backend (service/src)
Routing is exact-path in http.ts `appServer(auth, policy, config, alerts?, activity?, timeRequests?)` (http.ts:84); query/%/# in URL -> 400.

| Route | Handler |
|---|---|
| GET static (index, app.js, sw.js, ...) | STATIC table; request.html/js only if time-requests enabled |
| POST /auth/register/{options,verify}, /auth/login/{options,verify}, /auth/logout | auth.ts `Auth` |
| GET /auth/session, /people, /devices, /alerts[/before/N], /operations/:uuid | policy + alerts |
| GET /people/:id/activity | ActivityStore/activity-report |
| POST /people/:id/{pause,resume}, /people/:id/schedules[/:sid[/delete]] | policy -> operation |
| POST /alerts/:n/acknowledge | parent-alerts.ts |
| /child/status, /child/request (unauthenticated; capability token in POST body, Origin-checked) | time-requests-http.ts |
| GET /time-requests; POST /people/:id/request-link[/revoke], /time-requests/:uuid/{approve,decline} | time-requests-http.ts parentGet/parentPost -> TimeRequestService |

Policy path: HTTP -> `PolicyService` (policy.ts, demo) or `IntegrationPolicy` (integration-policy.ts) -> idempotent `operations` row (revision CAS, key per actor) -> worker.

Auth (auth.ts): bootstrap token (CLI `issueBootstrap`, 10 min, one use) -> WebAuthn registration -> session (hash, csrf, permission_version, browser_hash/epoch binding). Login re-checks account permission_version. No separate step-up code; step-up is only planned (runbooks/http-behind-proxy.md).

Dispatch (integration-worker.ts / integration-automatic.ts): op `pending` + rpc phase queued -> claim (token, epoch, lease) -> dispatch_batches/steps (`observe|apply|receipt|activity`, single step, deadline 1-30 s) -> SSHRouter -> receipt -> op `confirmed|unknown|failed|conflict`. Expired claim -> `uncertain`, never auto-retried. `AutomaticDispatch` is one serialized supervisor.

Other modules: alert-rules/parent-alerts/operational-alerts (alerts), activity-store/report/device-evidence, time-requests (15/30/60 min, re-pause), tls.ts (RFC 1918 or Tailscale CGNAT 100.64.0.0/10 only, SIGHUP reload), integration-config.ts (manifest validation, private files), schedule-clock.ts, router-transport.ts (frozen invocations).
Accounts/passkeys/admin-accounts.ts/integration-rebind|revoke: pending #48 (not on main; credentials are currently 1 per account).
