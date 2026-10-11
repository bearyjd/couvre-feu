# Local authenticated service runbook

This runs fictional controls against the separate file-backed fake router. It neither connects to nor configures a real router. The [PWA demo](demo-002.md) describes the browser interface; [PRP-003](prp/PRP-003-policy-service.md) defines the service boundary.

## Start and enroll

Use the repository root with Node **26.8.1** and npm **11.19.0**. Install the pinned lockfile with a project-local temporary cache:

```sh
npm ci --ignore-scripts --cache /tmp/couvre-feu-npm-cache
```

In one terminal, start the independent fictional router:

```sh
npm run demo:router
```

In a second terminal, start the authenticated service:

```sh
npm run demo:start
```

Open **http://localhost:4173/**. The service listens only on `127.0.0.1` and requires the exact localhost Host/origin; opening the numeric address is intentionally rejected. The default database directory is private `.demo-data/`, with separate `service.sqlite` and `fake-router.sqlite` files. Only `CF_DEMO_PORT` (1024–65535) and `CF_DEMO_DATA_DIR` configure the demo. The CLI and both processes must use the same data directory. Changing port changes the WebAuthn origin and needs fresh fictional enrollment.

In another terminal, mint a short-lived enrollment token for one seeded account:

```sh
npm run demo:bootstrap -- bryn
```

Paste the printed token into the PWA enrollment form and use the browser's passkey prompt. Fictional Bryn can control Alex only. For fictional JD admin, use `npm run demo:bootstrap -- jd` in a separate browser profile. The form never chooses an account or role. Tokens are one-use, expire after ten minutes and are not URL parameters. Reissuing an unused token invalidates its predecessor. The local demo cannot enroll a second credential for an already enrolled account.

The browser needs WebAuthn support in the localhost secure context. Automated acceptance uses a test-only virtual authenticator with genuine server verification. No household credentials are required. A localhost desktop browser run is not private HTTPS installation or actual phone acceptance.

## Controls and scenarios

Pause, timed pause and resume issue authenticated requests with the current opaque revision token, idempotency key and CSRF secret. The default fake apply delay is 350 ms, making accepted operations visibly pending before confirmation. An active fictional UTC 22:00–06:30 schedule can remain blocked after resume.

These CLI scenarios modify only fictional fake-router state; they expose no HTTP identity or role bypass:

```sh
npm run demo:scenario -- pending
npm run demo:scenario -- drift
npm run demo:scenario -- errors
npm run demo:scenario -- coverage
npm run demo:scenario -- stale
npm run demo:scenario -- failed
npm run demo:scenario -- timeout
npm run demo:scenario -- unreachable
npm run demo:scenario -- healthy
npm run demo:scenario -- local-advance
npm run demo:scenario -- status
```

`pending`, `drift`, `errors`, `coverage`, `stale`, `failed` and `timeout` select the next fictional write. Drift/error/coverage cases can have matching revisions while remaining unconfirmed. `failed` consumes one injection without applying; after refreshing, another deliberate action gets a greater revision. `timeout` means the policy may have applied and remains unknown until an exact healthy observation. `unreachable` immediately denies observation. `healthy` clears the current fault and permits reconciliation. `local-advance` models a router-local revision change; refreshing before another explicit action resolves the stale revision token.

To check expiry without the service, first confirm a short timed pause. Stop **only** `demo:start` with Ctrl+C and leave `demo:router` running. After expiry, `demo:scenario -- status` shows the original desired pause metadata with empty effective membership. Restart the service; it observes before any replay and cannot recreate the expired pause. Stopping the fake engine makes its heartbeat stale after three seconds; a database read alone cannot report fresh confirmation.

## Reset, shutdown and state

Stop both terminals with Ctrl+C before changing database files. To start a new fictional household, move the entire data directory to an unused private temporary name, preserving all SQLite/WAL files together:

```sh
test ! -e /tmp/couvre-feu-demo-retired-002 && mv -- .demo-data /tmp/couvre-feu-demo-retired-002
```

Then start both processes again and issue new bootstrap tokens. The retired directory contains authentication material; keep it private. Do not copy a single active SQLite file or overwrite only one database while either process is running. The two CLI processes are independent; stopping the service intentionally leaves router expiry available.

Schema migration is transactional. Service version 2 revokes sessions and challenges from version 1 because they lack browser-context binding, while preserving policy/accounts. Unknown versions or missing required columns fail before listening. Early development databases with a different version-1 shape should be retired using the reset procedure. There is no production restore or household recovery CLI in this milestone.

## Verify and interpret

```sh
npm run typecheck
npm run test:service
npm run test:web
```

Local HTTP/browser tests need permission to bind loopback. Browser test setup is documented in [demo-002](demo-002.md); CI supplies its isolated Chromium runtime. Node's test runner uses `--test-isolation=none` to report each scenario; fixture identities are constructor-only test data and cannot be supplied over HTTP.

`GET /people` distinguishes desired pause metadata, effective manual pause, schedule block, historical operation state and current observation health/age. `GET /operations/:id` reports historical outcomes within the actor's assigned-person scope. Mutation 200 means a fresh exact healthy synthetic witness; 202 is pending/unknown, never enforcement success. Every result states synthetic provenance and unverified router compatibility. No synthetic outcome proves actual packet behavior or the five-second cutoff.

Deployment, a real transport, stable private HTTPS/RP recovery, household enrollment and the real-router integration gates remain pending. [Service acceptance](acceptance-003.md) records measured local evidence and its limits.
