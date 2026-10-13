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

Unanswered requests expire after 15 minutes. Link failures are indistinguishable (`404 link_invalid`) and flood-limited (`429`).

Approval effect, all through the existing revision-CAS `PolicyService.mutate` / `IntegrationPolicy.mutate` path using the approving parent's identity:

- Active manual pause: `resume` now. The pause is restored by a later `pause` once the allowance ends, with its original expiry (or indefinite). The re-pause is skipped when the original pause would have ended inside the allowance, or when a later *pending or confirmed* policy operation for that child exists (failed and conflicted operations do not count). It runs as any active account assigned to the child, not the approver's session, and is retried without limit every few seconds until it succeeds or is provably unnecessary; while overdue the parent UI shows an alert. There is no terminal failure state that leaves the child unpaused. If the resume operation ends `failed` or `conflict`, the request becomes `apply_failed`.
- Nothing blocking: approved with no policy change.
- Schedule blocking: the policy contract has no override or allowance concept yet, so approval returns request state `unsupported` with code `schedule_override_unsupported` ("Not supported yet: schedules cannot be overridden") to both the parent and the child, and writes nothing. `TimeRequestService` accepts an optional `ScheduleOverride` hook; when provided it is called before approval proceeds and may refuse by throwing `AppError`.
- Schedule state unknown: `503 schedule_state_unknown`; the request stays pending.

The allowance is `approval time + minutes`; on the integration path a `202` resume may take effect after operator dispatch, so the child can see "approved" slightly before enforcement lifts. Audit rows record `time_request_create|approve|decline|unsupported|expire|apply_failed|repause` and `request_link_issue|revoke`, with the deciding account in `time_requests.decided_by` and `decided_at`.

Approval intent and fail-open window: the restore step (`TimeRequestService.repause`, the single place to replace with a router-side allowance once the policy contract has one) runs from the service. Intent is durable before the resume is attempted: one transaction moves the request to `approving` and records the original pause expiry, allowance end and restore obligation. A refused `mutate` (it refuses before writing) releases the claim back to `pending`; any unknown outcome (other error, 409/502 result) counts as approved so the pause is still restored; an `approving` row found after a restart is completed as approved. Revoking a link cancels only unanswered requests; `approving` and `approved` ones still complete. **Known fail-open window:** if the service is down when the allowance ends, the child stays unpaused until the service returns and restores the pause. Router-side expiry (a future `allowances` policy entry) removes this window.

Enablement: in the synthetic demo, time requests are always on. In real-router integration they are **off by default**; the private manifest must set `"timeRequests": {"enabled": true}` (strictly validated; see [integration-004](integration-004.md)). When off, the child routes and request page return 404, no link can be issued and the 5 second follow-up timer is not armed. When on without automatic dispatch, the resume and the later re-pause each wait for an operator permit, and the router-local allowance (PR #31) is expected to replace the service-side re-pause.

Disabling time requests in integration does not abandon obligations: a drain-only timer continues to restore lifted pauses (no routes, no new requests) until none remain, then stops.
