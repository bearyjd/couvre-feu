<!-- Generated: 2026-10-29 | Files scanned: ~200 | Token estimate: ~340 -->
# Backend (service/src)
Routing is exact-path in http.ts `appServer(auth, policy, config, alerts?, activity?, timeRequests?, inventory?)` (http.ts:97); query/%/# in URL -> 400.

| Route | Handler |
|---|---|
| GET static (index, app.js, sw.js, ...) | STATIC table; request.html/js only if time-requests enabled |
| POST /auth/register/{options,verify}, /auth/login/{options,verify}, /auth/logout | auth.ts `Auth` |
| GET /auth/session, /people, /devices, /alerts[/before/N], /operations/:uuid | policy + alerts |
| GET /people/:id/activity | ActivityStore/activity-report |
| POST /people/:id/{pause,resume}, /people/:id/schedules[/:sid[/delete]] | policy -> operation |
| POST /people/:id/reward | Reward Time: +15/+30 min allowance (integration-allowance.ts `IntegrationGrants.reward`); 404 unless `rewardTime.enabled` and the viewer may decide (http.ts:240) |
| POST /people/:id/focus | one-shot focus window = labelled timed pause (`IntegrationPolicy.focus`, integration-policy.ts); 404 unless `focus.enabled` and the viewer may decide (http.ts:248) |
| GET /audit[/limit/:n][/before/:id] | parent-audit.ts `auditFor`; 404 unless `auditLog.enabled`; admins see every row, other parents their assigned children (not owner-mode gated); parent "Activity log" view: web/public/audit.js, shown per viewer via `auditLog` on `GET /people` (http.ts:332) |
| POST /alerts/:n/acknowledge | parent-alerts.ts |
| /child/status, /child/request (unauthenticated; capability token in POST body, Origin-checked) | time-requests-http.ts |
| GET /admin/inventory, POST /admin/inventory/{acknowledge,refresh} | inventory-http.ts |
| GET/POST /admin/accounts[/:id/{tokens,role,active}], /admin/passkeys/:id/{approve,revoke}, GET /account/passkeys, POST /account/passkeys/:id/revoke, POST /step-up/options | admin-accounts-http.ts -> admin-accounts.ts `AccountAdmin` |
| GET /admin/children, POST /admin/children[/:id/{remove,devices}], /admin/devices/:id/{move,remove} | admin-children.ts `ChildAdmin` |
| POST /step-up/options (action child_batch), POST /admin/children/batch | admin-children-batch.ts `ChildBatchAdmin`; childrenPost claims before singles; ordered canonical binding includes clientKey; one transaction, at most one enroll operation |
| GET /time-requests; POST /people/:id/request-link[/revoke], /time-requests/:uuid/{approve,decline} | time-requests-http.ts parentGet/parentPost -> TimeRequestService |

Policy path: HTTP -> `PolicyService` (policy.ts, demo) or `IntegrationPolicy` (integration-policy.ts) -> idempotent `operations` row (revision CAS, key per actor) -> worker.

Auth (auth.ts): bootstrap token (CLI `issueBootstrap`, 10 min, one use) -> WebAuthn registration -> session (hash, csrf, permission_version, browser_hash/epoch binding). Login re-checks account permission_version. Step-up: a fresh passkey confirmation bound to one exact account/passkey/child change (`step_ups` table, migration 007; `/step-up/options`; auth.ts stepUpChallenge/stepUpVerify).

Batch setup: admin-children-batch.ts normalizes at most 40 create/rename/add items, resolves backward @index references, checks readiness/scope/accumulating limits in the write transaction, and queues one composed revision +1 policy. Local-only batches queue nothing. Batch-only challenge = sha256(binding + nonce), session/account bound, 120 s; options rate 3/actor/min. Additive retry/setup state in admin-batches.sql; idempotency lookup after commitStepUp and before first-run gate. Transactional audit once per child, counts only; worker conflict settlement uses each device's person_id. InventoryStore replaces inventory_coverage on complete polls (fresh lease/neighbour address proof); incomplete/failure clears it. Client UI is a separate task; docs/design/first-run preserves the throwaway prototype.

Batch verification: `service/tests/admin-children-batch.test.ts` (transaction/security/recovery), `admin-children-batch-http.test.ts` (HTTP guards and ready-device enrollment), and `fixtures/previous-store.ts` (pre-batch Store reader/writer compatibility). Manual `node service/tests/batch-guard-mutations.ts` disables guards in a disposable source copy and maps each mutation to a failing regression; uses pinned Node 26.13.1 and a private TMPDIR, with `BATCH_REPORT_DIR` for result logs.

Dispatch (integration-worker.ts / integration-automatic.ts): op `pending` + rpc phase queued -> claim (token, epoch, lease) -> dispatch_batches/steps (`observe|apply|receipt|activity`, single step, deadline 1-30 s) -> SSHRouter -> receipt -> op `confirmed|unknown|failed|conflict`. Expired claim -> `uncertain`, never auto-retried. `AutomaticDispatch` is one serialized supervisor.

Other modules: alert-rules/parent-alerts/operational-alerts (alerts), parent-audit (audit log), activity-store/report/device-evidence, inventory-store (unknown-device list; shared admin-inventory DTOs include `inScope` for list/acknowledge), integration-scope (`ScopeTracker.inRouterScope` shares the exact assignment eligibility predicate with inventory: manifest floor or fresh, generation-checked remembered clean scope), time-requests + time-request-grants + integration-allowance (15/30/60 min grants as router allowances; legacy rows re-pause), push-sender.ts + push-runtime.ts + digest.ts (flagged `push.enabled` / `digest.enabled`, off: content-free ntfy push to an admin topic, weekly counts-only digest Sun 18:00 America/New_York with 21:00-07:00 quiet hours; started from integration-main.ts; table `notify_state`), doh-list.ts (seven providers, 32 IPv4 + 28 IPv6, merged into each submitted policy when manifest `dnsHardening.dohList` is true; explicit true/false strips twelve retired Mullvad addresses, absent preserves existing entries; integration-policy.ts; see docs/dns-hardening.md), tls.ts (RFC 1918 or Tailscale CGNAT 100.64.0.0/10 only, SIGHUP reload), integration-config.ts (manifest validation, private files), schedule-clock.ts, router-transport.ts (frozen invocations).
Accounts: many passkeys per account (migration 007), admin-accounts.ts and admin-children.ts with step-up, integration-rebind|revoke CLIs. Owner-account guard (PR #100, admin-accounts.ts:68-72): with `timeRequests.mode` `owner`, other admins get 403 `owner_account_protected` on the owner's account, and the owner cannot deactivate, demote or strip their own last active passkey (409 `owner_self_lockout`).
Per-viewer flag: `GET /people` adds `rewardTime: true` only when the reward route would answer for that viewer (http.ts:295-296). Flags (`timeRequests.mode`, `rewardTime`, `focus`, `auditLog`, `dnsHardening`) are off by default and unverified on this router.
