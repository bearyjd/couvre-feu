# Production policy service seam — future integration

This records the planned real-router and deployment boundary. [PRP-001](prp/PRP-001-enforcement-core.md) retains router enforcement. The local fictional-data prototype is specified in [PRP-003](prp/PRP-003-policy-service.md), with its parent app in [PRP-002](prp/PRP-002-parent-pwa.md); it has no working production-router transport. The proposal below does not authorize SSH, deployment or household enrollment.

Proposed deployment: TypeScript on Atlas, SQLite, Podman, loopback listener and Tailscale private HTTPS. Choose a stable hostname before passkey enrollment, preserve RP ID/origin in recovery, and validate origin/challenge/user verification server-side. Tailscale reachability is not application authentication; forwarded/tailnet identity claims are untrusted unless independently authenticated and bound to the request. Require passkeys and server-enforced roles, with JD admin and Bryn parent. No auth shortcut is authorized. [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve), [WebAuthn](https://www.w3.org/TR/webauthn-2/).

## Router boundary

A future real-router adapter must use a dedicated restricted SSH key with the wrapper grammar in `router/cfctl-ssh`. Serialize mutations, send bounded JSON on stdin, never construct a shell from user text, and require observed confirmation. `remove-fw` is internal recovery and outside the wrapper allowlist. Installer/key deployment and target runtime tests require separate approval.

The local fake transport compares the observed base policy transactionally before applying a higher revision. The current router command protocol does not provide that equivalent atomic base-policy precondition or a fake transport's operation-ID witness. A real adapter needs a reviewed concurrency and confirmation design before live writes; a prior status read alone cannot rule out an intervening router-local change.

Version 1 desired state has required `version`, `revision`, `people`, `pauses`, `schedules` and optional `doh`. People have `id` and disjoint canonical `macs`; pauses have `person` and `until` (0 indefinite, otherwise absolute epoch); schedules have `person`, `id`, `weekdays`, `start`, `stop`; DoH has `ipv4`/`ipv6` address arrays. See the [README example](../README.md). No bonus field or endpoint is supported.

Track service desired revision, router desired/confirmed revision, operation ID, last successful confirmation timestamp, status age and errors. Router status exposes desired/effective pauses, observed kids/paused sets, drift and capability uncertainty. Do not infer real packet proof from `ok`, a matching revision, or `nativeKernelConfirmed`; target compatibility remains explicitly unverified until acceptance.

Reject stale revisions and same-revision conflicting policy. On reconnect, first fetch the router desired revision and preserve the exact normalized payload for an equal-revision replay, including expired metadata retained for equality. Removing expired pause records changes that payload and requires a greater revision; never replay an obsolete grant or resurrect an expired pause. Router-local pause/resume also advance revisions. A proposed service transaction must allocate monotonically beyond both stored and observed revisions, reconcile concurrent router changes, and refuse or explicitly resolve conflicts rather than silently clobber them. Idempotency keys and revision preconditions are required at the service boundary; conflict ownership/resolution remains a future service design decision. Router-local cron, not service availability, owns expiry.

## Proposed API and result semantics

| Route | Proposed responsibility |
|---|---|
| `GET /people` | Role-scoped latest confirmed status and freshness |
| `GET /devices` | Admin device assignment/inventory |
| `GET /operations/:id` | Pending, confirmed, failed or unknown outcome |
| `POST /people/:id/pause` | Immediate/timed manual pause with idempotency and revision precondition |
| `POST /people/:id/resume` | Clear manual pause; describe remaining schedule block |
| Admin device/schedule routes | Validated revisions, protected overlap refusal, audit |

HTTP 200 means the requested revision was applied and confirmed by the router. HTTP 202, if asynchronous processing is adopted, means pending and includes an operation URL; it never means enforcement succeeded. Router timeout becomes unknown/pending until reconciliation, while explicit failure is recorded as failure. Revision conflicts return a conflict requiring refreshed state. A service database commit alone cannot confirm enforcement.

Audit authenticated actor, operation, desired revision, timestamp and sanitized router outcome. Enforce authorization on every route. A future reconcile loop may run on writes and every minute, with bounded retries and explicit drift/unreachable alerts. Offline PWA status is timestamped read-only cache; it cannot enqueue blind policy mutations. Reconnect refreshes before an explicit user action.

Acceptance for a future service PR: passkey/role/session tests, stable-origin recovery, SQLite migration and backup restore, replay/idempotency/conflict tests, fake-router error tests, then separately approved real confirmation and deployment. Tailnet membership, a fake adapter and local fixtures cannot substitute for these gates.

## Persisted parent alerts

The demo service stores alerts in SQLite (`parent_alerts`, migration `003.sql`) and serves them to the parent PWA. Alerts describe policy and router evidence plus two input interfaces; they do not infer presence, content or intent. The integration build does not mount these routes yet.

| Route | Behavior |
|---|---|
| `GET /alerts` | Newest 25 visible alerts plus `openCount` (unacknowledged) and `nextBefore` |
| `GET /alerts/before/:id` | Next page of 25 below the cursor (the server rejects query strings, so the cursor is a path segment) |
| `POST /alerts/:id/acknowledge` | `open` becomes `acknowledged`; idempotent; 409 `alert_resolved` once resolved; CSRF and origin checks as for other writes |

Visibility is enforced on the server: a parent sees alerts for assigned people only; system alerts (no person) are visible only to admins. An alert outside the caller's scope is reported as `alert_not_found`.

Rows: `id`, `person_id` (null for system), `kind`, `severity` (`info`/`warning`/`critical`), `created_at`, `first_seen`, `last_seen`, `count` (evaluation seconds in which the condition was seen), `state` (`open`/`acknowledged`/`resolved`), `acknowledged_at/by`, `resolved_at`, `details` (JSON, at most 1024 bytes: counts, windows, operation ids; never MACs, addresses, domains or router diagnostics). One unresolved row exists per (kind, person); an acknowledged alert stays deduplicated while its condition persists, and a recurrence after resolution is a new row. Resolved rows are deleted 90 days after `resolved_at`.

### Rules (`service/src/alert-rules.ts`, pure functions)

| Kind | Severity | Fires when | Clears when |
|---|---|---|---|
| `enforcement_unhealthy` | critical if drift, else warning | Fresh observation reports drift; or observation unavailable/stale/unreachable and older than 300 s (or never seen). A system alert fires when router status has errors or is older than 300 s | Condition absent in a later evaluation |
| `sync_failed` | warning | Latest operation is `failed`/`conflict` and under 24 h old | Latest operation changes state |
| `apply_pending_too_long` | warning | Latest operation `pending`/`unknown` for more than 120 s | Operation confirms or fails |
| `possible_bypass` | critical | Sum of `txBytes + rxBytes` over deltas with `enforcementActive` exceeds 1 MiB for a person in one evaluation batch | A later batch for that person is clean, or 30 min pass without a breach |
| `repeated_blocked_attempts` | info | Sum of `blockedPackets` is at least 100 | As above |
| `time_request_pending` | info | Any pending request for the person | No pending request remains |

The 1 MiB and 100-packet thresholds are heuristics: ARP, DHCP and keepalive leakage is far smaller, but a legitimate exempt device or a counter mismatch can still trip them. Alerts say "possible", not "proven".

Input interfaces, supplied by separate changes (nothing here collects traffic or builds requests):

- `ActivityDelta {person, mac, windowStart, windowEnd, txBytes, rxBytes, blockedPackets, enforcementActive}`: windows must be 1 to 3600 s long, end no more than 60 s in the future and no more than 1 h in the past; invalid deltas are ignored. `mac` is accepted but never stored.
- `PendingTimeRequest {person, requestId, createdAt}`.

Wire them with `new ParentAlerts(store, {people, activity, timeRequests})`; `main.ts` currently supplies only `people`. An input that is omitted or whose provider throws is "not evaluated": its alerts are left alone and never auto-resolved.

## Audit log of parent actions (flagged off)

Both parents can see who did what. Real-router integration only; **unverified on a router** (the log records what the service accepted, not what a router did). Flag: `"auditLog": {"enabled": true}` in the private manifest (strictly validated, `enabled` must be a boolean; absent means **off**). When off, nothing is written and `GET /audit` is 404 `route_not_found`, exactly as for a route that does not exist.

| Route | Behavior |
|---|---|
| `GET /audit` | Newest 50 visible entries plus `nextBefore` |
| `GET /audit/limit/:n` | Page size `n`: 1 to 4 digits are accepted; values above 100 are clamped to 100, `0` is 400 `invalid_limit`, and a longer segment is 404 `route_not_found` |
| `GET /audit/before/:id`, `GET /audit/limit/:n/before/:id` | Next page below the cursor (`id` is at most 15 digits, a longer segment is 404; the server rejects query strings, so size and cursor are path segments, as for `/alerts/before/:id`) |

Entry: `id`, `at`, `actorId`, `actorName` (the account's display name, null for `system`), `action`, `personId` (null when no child applies), `operationId` (null when nothing was queued), `result`. Newest first, never an unbounded query.

**Privacy gate.** Table `parent_audit` (migration `010.sql`, counted by `PRAGMA user_version`) holds ids and closed enums only: actor account id, `action` in `pause`, `resume`, `pause_all`, `resume_all`, `device_assign`, `device_move`, `device_remove`, `grant_approve`, `grant_decline`, `grant_end`; child id; time; operation id; `result` in `applied`, `failed`, `refused`. CHECK constraints close the enums and bound id lengths. There is no free-text column and the service never stores a request body, a child's reason text, a domain, URL, MAC, address or hostname here. Grant minutes are not recorded.

**Meaning of `result`.** `applied`: the service accepted the action and queued it as router operation `operationId` (the router's own outcome stays on that operation, `GET /operations/:id`); a decline is `applied` with no operation. `refused`: rejected before anything was queued (a 4xx such as a revision conflict, a missing precondition, a device already on that child). `failed`: the action could not be carried out (a 5xx such as no fresh router observation, or an unexpected error); an approved grant that the router did not take, or that never came into force, adds a `failed` `grant_approve` entry. `grant_end` (actor `system`) is written when a later pause or bulk pause removes a confirmed grant. One grant can produce two rows for the same operation: `grant_approve` `applied` when the approval was accepted and queued, and a later `grant_approve` `failed` if the router never took it. Clients must treat the latest result per operation id as current. A replay with the same idempotency key is one entry. Out-of-scope attempts (404), failed step-ups and other authentication/authorization errors (401/403) and rate limits (429) are not recorded. A bulk action writes one entry per affected child with the shared operation id; a device move writes one for each of the two children.

**Attribution and volume.** An approval is one `grant_approve` entry, never an extra `resume` entry. The background re-pause after an allowance ends (legacy path) is recorded as actor `system`, action `pause`, not as the parent whose account it runs under. Refused entries have no operation id to dedupe on, so an actor's refused entries stop being stored once 20 exist in the last 60 seconds. With the flag off the audit code does no extra database work.

**Scoping** matches parent alerts exactly: an actor sees only entries whose child is in their `personIds`; entries with no child (a bulk action refused before the child list was known) are visible to admins only. An actor with no children, or reading another family's children, gets 200 with an empty list. There is no per-child route.

**Failure isolation.** The entry is written after the operation's own transaction has committed. If the audit write fails the service logs `parent_audit_write_failed` (no ids) to stderr and carries on; a successful router operation is never turned into an error.

**Retention.** Rows older than 90 days are deleted at startup and then hourly by the existing prune timer, in bounded batches (at most 2000 rows per call), whether or not the flag is still on.

### Gap: notification delivery beyond the app

Alerts are visible only inside the PWA while open. Web Push is out of scope. Sketch: generate a VAPID key pair on the service (private key in an environment secret, never in the repo); `POST /push/subscriptions` stores each parent's browser `PushSubscription` (endpoint, keys) bound to the account and revoked on logout or permission change; on alert creation (not on every count increment) send an encrypted, content-free payload ("Couvre-feu: new alert") with the `web-push` protocol directly to the browser vendor's push service, the only third party involved, and have the service worker fetch the actual alert over the authenticated session when the notification is tapped. Open design points: quiet hours, per-severity opt-in, expired-subscription cleanup (HTTP 404/410), and the service needing outbound HTTPS to the push service even when its own listener is tailnet-only.

## Child time requests

A child asks for more time through a per-child request link; there are no child accounts. All state lives in the service (migration `006.sql`); the router and the policy write path are untouched.

| Route | Caller | Purpose |
|---|---|---|
| `POST /people/:id/request-link` | Assigned parent (session + CSRF) | Issue a link, revoking the previous one. The token is returned once as `path` (`/request.html#<token>`); only its SHA-256 is stored. |
| `POST /people/:id/request-link/revoke` | Assigned parent | Turn the link off; its pending request is cancelled. |
| `GET /time-requests` | Parent | Pending and 24 h of recent requests, plus link active/inactive, for assigned people only. |
| `POST /time-requests/:uuid/approve` `{minutes: 15\|30\|60}` | Assigned parent | Approve; the parent may grant less than requested. |
| `POST /time-requests/:uuid/decline` | Assigned parent | Decline. |
| `POST /child/request` `{token, minutes, reason?}` | Child (token in body only) | Submit; one pending request per link, 5 minute cooldown after each request, reason at most 140 characters of plain text without control or bidirectional-override characters. |
| `POST /child/status` `{token}` | Child | Own latest request: `pending`, `approved` (with `allowanceUntil`), `declined`, `expired`, `unsupported`, `apply_failed` or `cancelled`. Nothing else is returned. |

Unanswered requests expire after 15 minutes. Link failures are indistinguishable (`404 link_invalid`) and flood-limited (`429`) per client: each TCP source address has its own bad-token bucket (at most 1024 tracked, then one shared overflow bucket), and a valid link is never refused by it, so one hostile client cannot lock other children's links. Status polls and submissions are limited to 30 per minute per child (reissuing a link does not reset it). The reason additionally refuses unpaired surrogates and invisible or line-breaking code points (U+061C, U+200B/C/E/F, U+2028/9, U+2060, U+FEFF); it is stored verbatim, rendered with `textContent` only, and never placed in alerts or the router policy.

Approval effect in the synthetic demo (and for legacy rows), through the existing revision-CAS `PolicyService.mutate` / `IntegrationPolicy.mutate` path using the approving parent's identity. Real-router integration with time requests enabled uses grants instead; see [Grants as router allowances](#grants-as-router-allowances-real-router-integration):

- Active manual pause: `resume` now. The pause is restored by a later `pause` once the allowance ends, with its original expiry (or indefinite). The re-pause is skipped when the original pause would have ended inside the allowance, or when a later *pending or confirmed* policy operation for that child exists (failed and conflicted operations do not count). It runs as any active account assigned to the child, not the approver's session, and is retried without limit every few seconds until it succeeds or is provably unnecessary; while overdue the parent UI shows an alert. There is no terminal failure state that leaves the child unpaused. If the resume operation ends `failed` or `conflict`, the request becomes `apply_failed`.
- Nothing blocking: approved with no policy change.
- Schedule blocking (demo only; the demo router has no allowances): approval returns request state `unsupported` with code `schedule_override_unsupported` ("Not supported yet: schedules cannot be overridden") to both the parent and the child, and writes nothing. `TimeRequestService` accepts an optional `ScheduleOverride` hook; when provided it is called before approval proceeds and may refuse by throwing `AppError`.
- Schedule state unknown: `503 schedule_state_unknown`; the request stays pending.

The allowance is `approval time + minutes`; on the integration path a `202` resume may take effect after operator dispatch, so the child can see "approved" slightly before enforcement lifts. Audit rows record `time_request_create|approve|decline|unsupported|expire|apply_failed|repause` and `request_link_issue|revoke`, with the deciding account in `time_requests.decided_by` and `decided_at`.

Approval intent and fail-open window: the restore step (`TimeRequestService.repause`, the single place to replace with a router-side allowance once the policy contract has one) runs from the service. Intent is durable before the resume is attempted: one transaction moves the request to `approving` and records the original pause expiry, allowance end and restore obligation. A refused `mutate` (it refuses before writing) releases the claim back to `pending`; any unknown outcome (other error, 409/502 result) counts as approved so the pause is still restored; an `approving` row found after a restart is completed as approved. Revoking a link cancels only unanswered requests; `approving` and `approved` ones still complete. **Known fail-open window:** if the service is down when the allowance ends, the child stays unpaused until the service returns and restores the pause. On the real router this window applies only to rows approved before grants existed; new approvals use router-side expiry (below).

Enablement: in the synthetic demo, time requests are always on. In real-router integration they are **off by default**; the private manifest must set `"timeRequests": {"mode": "owner"|"parents"}` (legacy `{"enabled": true}` means `parents`; strictly validated; see [integration-004](integration-004.md)). `owner` needs `"ownerAccountId"` (an account in `accounts`) and only that account sees or decides requests and their alert; `parents` lets every parent and admin. `ownerAccountId` is validated but ignored outside `owner` mode. Child routes and the timer run in both modes. Mode `off` hides existing `time_request_pending` alerts from everyone; the rows are kept and reappear when the mode is turned back on. When off, the child routes and request page return 404, no link can be issued and the 5 second follow-up timer is not armed. When on without automatic dispatch, each grant waits for an operator permit and stays `approving` until it is confirmed in force.

Disabling time requests in integration does not abandon obligations: a drain-only timer continues to restore lifted pauses (no routes, no new requests) until none remain, then stops.

### Parent ask-for-time card (web)

The parent PWA (`web/public/time-requests.js`) shows one card per pending request: child name, requested minutes, and the child's reason text (rendered only with `textContent`, only in the signed-in parent's page, never in alerts or pushes). Controls are named for the child:

- **Grant N min**: one tap, N = requested minutes up to the 60 minute cap (sends `POST /time-requests/:id/approve {minutes: N}`). **Grant less** is a secondary control that offers only the durations below the requested minutes from 15 and 30 (a 15 minute request shows none); each is the same approve route with that `minutes` value (the service accepts 15, 30 or 60 per request). **Decline** sends the decline route. All of these are disabled while either is in flight, and a repeat tap sends nothing (the service also answers a second decision with `409 request_not_pending`).
- **Honest states, never optimistic.** After a tap the card says "Applying..." until a later `GET /time-requests` reports `approved`; only then it says "Granted until HH:MM" (the router's `allowanceUntil`, formatted by the browser). `apply_failed` shows "Couldn't apply" with short parent-friendly text for the reason; an unknown code gets a generic line and the raw code is never shown to the parent (it stays in a `data-code` attribute on the row for support). The legacy path stores `approval_not_applied`; the grants path stores `grant_not_applied` (the operation failed or conflicted) and `grant_not_in_force` (the deadline passed first). Grants still in force are pinned above the 8 row history cap. `grant_ended` and the demo's schedule-block `unsupported` keep their existing wording.
- **End extra time** appears on a grant that is still in force. The router has no remove-allowance operation, so it sends the existing single-child Pause with no end time (`until=0`, an INDEFINITE pause that stays until a parent resumes; pause wins, which ends the grant). The card says "Pause requested for X" only when the service accepted the request; if control was lost, the revision changed, or the call failed it says "Couldn't send the pause" with the reason. Either way the grant is shown until the service reports it ended.
- **Flag.** A `404` from `GET /time-requests` (mode `off`, or a parent the owner mode excludes) hides the card and stops polling. The demo keeps time requests always on (its router has no allowances, so the demo uses the legacy resume path and settles within one request, so the card does not normally sit in `approving`).
- Accessibility: tap targets at least 44 px, status text in an `aria-live="polite"` region plus the app status line, no domains or device identifiers shown.
- Status: **unverified on this router**; the card carries that note until the live grant test passes.

### Grants as router allowances (real-router integration)

Status: **unverified on this router.** Offline tests only (service fake router and router fixtures); no live run.

- **What a grant is.** Approving a request on the real router queues an `allow` operation through `IntegrationPolicy.queue()`: the same CAS, single operation in flight and managed-policy validation as pause and resume. `IntegrationGrants` (`service/src/integration-allowance.ts`) writes it, and `TimeRequestService` uses it whenever the port is present.
  - The router policy gains `allowances: [{person, until}]`. Pauses and schedules are left in place.
  - The router lifts both a manual pause and a schedule while the allowance is active, and restores them at `until` by itself (`core.sh` `cf_enforced_policy`, `cf_gated_plan`). No service re-pause is needed.
- **Limits.**
  - At most 60 minutes per grant (owner decision), checked server-side. The router's horizon is 4 h.
  - `until` = **router time** of the fresh observation + minutes, never the service clock.
  - A later grant never shortens an active longer one.
  - The idempotency key is `tr-<request>-a<n>`. A replay returns the same operation and deadline.
- **Honest states.** The request becomes `approving` (`apply_via='allowance'`), not `approved`, when the parent taps. It becomes `approved` only when two things hold: the operation is confirmed, and a fresh healthy observation reports the allowance in `effectiveAllowances`.
  - It becomes `apply_failed` with `grant_not_applied` when the operation fails or conflicts.
  - It becomes `apply_failed` with `grant_not_in_force` when the deadline passes first. For example, an operator dispatches it late and the router admits it as an inert expired entry.
  - An approval interrupted before its operation was queued goes back to `pending`. If the operation exists, it is found again by its key. Neither case is ever promoted blindly.
  - A refused CAS writes nothing and releases the request.
  - The child sees `approving` as `pending` ("Starting…").
- **Pause wins.** A single-child Pause during a grant removes that child's allowance in the router-facing policy, as `cfctl pause` does locally. Bulk "block all" already did this. Resume keeps the allowance.
  - Once the router no longer holds an approved grant before its deadline, the request keeps `approved` but gets code `grant_ended`. The child status returns that code.
  - A legacy re-pause is deferred while a newer grant is in force, so it cannot end that grant.
- **Display.** `PersonDTO.allowance` is the router-confirmed allowance in force (healthy observations only). While it is set, `scheduleBlocked` is `false`, bounded by the allowance end and the observation validity. The shared demo `scheduleBlocked()` also ignores schedules for a person with an active allowance.
- **Approvers.** In `parents` mode approvers are any account whose scope includes the child: assigned parents, and admins through their scope (`scope_all` admins see every child). In `owner` mode only `ownerAccountId` may approve or decline. There is no passkey step-up, because a grant is at most 60 minutes, no more than a Resume.
- **Alerts.** On the real path the 5 s time-request timer also reconciles the `time_request_pending` alert (counts only, no reason text). No other alert kind starts reconciling on the real router.
- **Flag.** Grants are created only when the private manifest sets `"timeRequests": {"mode": "owner"|"parents"}` (or legacy `{"enabled": true}`), which is off by default. The routes, the child page, the 5 s alert timer and the grant-writing port are mounted only then. The demo keeps its old path (no allowances). Some pieces are **always on**, flag or not:
  - **Pause wins.** A single-child Pause strips that child's allowance in the router-facing policy (`IntegrationPolicy.mutate`), so it also applies with the flag off.
  - **People reads.** `PersonDTO.allowance` is always filled from healthy observations and `scheduleWithAllowance` is always applied, so an allowance already on the router lifts the displayed schedule block even with the flag off. An unknown schedule claim (`scheduleBlocked === null`) stays unknown.
  - **Migrations.** `009.sql` (adds `time_requests.apply_via` and `grant_operation_id`) and `integration-007.sql` (admits `operations.action='allow'`) always run.
  - **Drain.** With the flag off, a drain-only timer still follows in-flight grants (`approving` to `approved` or `apply_failed`) and owed re-pauses, then stops. No route is mounted.
  - **Behaviour change for existing rows (demo and legacy).** The per-child poll limit (30 per minute; status polls and submits have separate budgets) and the stricter `normalizeReason` (no invisible, line-breaking or unpaired code points) apply everywhere the service runs. The child `code` is now `decision_code`, falling back to the old state mapping (`unsupported` gives `schedule_override_unsupported`, `apply_failed` gives `approval_not_applied`), so legacy rows without a `decision_code` read as before.
  - **Child status.** `allowanceUntil` is shown only for an `approved` request whose grant has not ended (never while `approving`).
  - **Web copy.** An `approved` request with code `grant_ended` reads as ended on the child and parent pages, not as time in force.
**Residuals and UNVERIFIED:**
- **Kernel time gate.** Whether the xt_time `--datestart` gate re-blocks at `until` on this firmware with flow offload on is UNVERIFIED.
- **Installed release.** Whether the router release currently installed includes allowances (#31) is UNVERIFIED. An older release is expected (not tested against one) to refuse the `allowances` key, so the grant would end `apply_failed`.
- **Limited web UI.** The parent and child pages show the `grant_ended` state, but there is no other grant-specific UI (no "End extra time" action, no countdown).
- **No ending action.** There is no "End extra time" action, and no alert when a grant stays unconfirmed for a long time.
- **Shared bad-token bucket.** In trusted-proxy mode every LAN client shares the proxy's address, so the bad-token bucket is effectively global again. Valid links are still never blocked. Guessing is prevented by the 256-bit tokens, not by the limiter.
