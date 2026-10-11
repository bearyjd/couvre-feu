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
