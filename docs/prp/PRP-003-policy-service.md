# PRP-003 — authenticated local policy service

Session 002 implements a fictional local vertical slice. The service uses `shared/`, `service/` and the separate `demo-router/` package; the parent interface remains [PRP-002](PRP-002-parent-pwa.md). The original [PRP-001](PRP-001-enforcement-core.md) is preserved. Its router implementation and remaining integration gates are described in the [enforcement contract](../enforcement-contract.md).

## Scope and isolation

The runnable service binds `127.0.0.1`, accepts the exact configured `localhost` Host/origin, and uses fictional people Alex and Blair. Fictional JD is admin; fictional Bryn is parent assigned only Alex. People/device/schedule administration is seeded read-only. Usage, domains and app history are unavailable. There is no bonus/Allow-until route.

The only transport is a file-backed fake router. It contains no SSH client, credentials, router hostname or production transport. Production-target and authentication-bypass environment variables are rejected. Node's local HTTP and SQLite APIs are used directly; no general web framework is required. Real packet enforcement, actual router compatibility, stable private HTTPS, household account enrollment/recovery and deployment remain outside this milestone.

## Authentication and permission boundary

Local CLI bootstrap creates a 256-bit random, hashed, one-use token with a ten-minute lifetime, bound to an already seeded fictional account. Registration JSON accepts only that token; the server chooses account, role, person assignments and WebAuthn user ID. One credential can be bound to each fictional account. Reissuing an unused bootstrap invalidates its predecessor; enrolled accounts require a fresh fictional demo reset rather than an undocumented recovery shortcut.

`@simplewebauthn/server` verifies WebAuthn challenges, exact origin, RP ID `localhost`, presence, user verification, credential public key/signature, account/user-handle binding and signature counter. Challenges expire after two minutes and are consumed once. Failed verification cannot reuse a challenge. Server permissions and their durable version are rechecked before creating a session.

An HttpOnly, SameSite=Strict browser-context cookie binds challenges and sessions. Durable logout epochs cancel authentication in progress; authentication generations prevent concurrent or abandoned verification from issuing overlapping sessions. Both are checked after asynchronous options/verification work in the final transaction. Successful authentication revokes prior sessions in the same browser episode. Logout can invalidate a just-rotated episode using its bounded, same-browser stored CSRF proof, even when the original session has just been revoked. This exception applies only to logout. A repeated old-epoch logout cannot cancel a later deliberate login. A late response cookie refers to a revoked session and grants no API access.

Sessions expire after one hour, carry the server account permission version, and require both session and browser-context cookies. Every authenticated mutation requires the exact Origin, JSON Content-Type and session CSRF secret. Policy/status/operation/device routes enforce roles and assigned people on the server. Untrusted identity headers cannot select an actor. API/auth/session responses are `no-store`.

## Policy and durable operations

The shared router parser implements the bounded ASCII JSON subset and v1 schema from the enforcement contract, including duplicate/unknown keys, canonical integer bounds, MAC ownership/protection, address canonical duplicates, weekdays and expanded per-device schedule limits. Serialization is tested against the actual `router/lib/json.awk` parser. Expired pause metadata remains in normalized policy equality; it is separate from effective manual pause.

The service stores desired policy, revision high-water, observed router state, operation journal and sanitized audit in SQLite. Transactions use `BEGIN IMMEDIATE`, WAL and `synchronous=FULL`; migrations are transactional. Service schema version 2 adds browser context binding and revokes legacy unbound sessions/challenges. Unknown schema versions or missing required columns fail before listening. Fake-router state is a separate database with schema version 1.

`GET /people` returns a quoted opaque revision token combining durable service high-water, freshly observed router revision and normalized policy digest. A mutation must send that exact token as `If-Match` and a bounded `Idempotency-Key`. Under the service transaction it rechecks the precondition, refuses another unresolved operation, and allocates a revision greater than both durable service and router state. A refreshed, deliberate action can follow a known failed apply without reusing its revision.

Each operation preserves its exact base and candidate JSON, actor, person, original normalized request and idempotency key before application. Same actor/key/request returns the same operation, including after expiry or restart; a changed request conflicts. The fake transport compares base revision and policy inside its own transaction before applying a new revision. Router-local writes between observation and application therefore conflict. Current `cfctl sync` does not expose this atomic observed-base precondition, and its status protocol does not contain the fake operation ID witness. A future real adapter requires a separately reviewed concurrency and confirmation design, router protocol work and target acceptance; adding SSH alone cannot provide these guarantees.

Replay eligibility, synchronous fake application and durable outcome are serialized under the service write transaction, always locking service then fake. No network call or asynchronous work occurs while either lock is held. Terminal confirmed/failed/conflict outcomes cannot regress when another reconciler holds a stale snapshot. A future remote transport would need a separate durable claim/lease design rather than copying this local lock pattern.

Restart/reconnect first observes the router. Pending/unknown operations may replay only their exact original payload against their preserved base. Expired pause metadata is not converted into a new pause. The independent fake-router process owns heartbeat, time high-water and effective expiry; the service never ticks it. A stale heartbeat produces unknown/unreachable current status rather than a fresh healthy observation.

## API

| Route | Result and authority |
|---|---|
| `POST /auth/register/options` | `{token}` → browser-bound creation options |
| `POST /auth/register/verify` | `{challengeId,response}` → verified session |
| `POST /auth/login/options` | `{}` → discoverable credential request options |
| `POST /auth/login/verify` | `{challengeId,response}` → verified session |
| `GET /auth/session` | Active browser-bound actor, permission version, CSRF and expiry |
| `POST /auth/logout` | `{}` plus same-browser CSRF → episode revocation |
| `GET /people` | Assigned people, stored/effective pause, schedule explanation, current observation health, revisions and age |
| `GET /devices` | Fictional admin inventory only |
| `GET /operations/:id` | Assigned-person operation history; unauthorized IDs are not disclosed |
| `POST /people/:id/pause` | `{until:0}` indefinitely, or future absolute epoch; token/key/CSRF required |
| `POST /people/:id/resume` | `{}` removes only manual pause; active schedule can still block |

All timestamps are epoch seconds. The seeded fake schedule uses UTC explicitly. Every policy/operation/status result carries `source: synthetic-fake-router` and `routerCompatibilityVerified: false`. Shared DTOs are defined in `shared/src/contracts.ts`.

Mutation HTTP 200 requires a fresh observation of the exact operation identity, exact normalized payload, desired/confirmed revision, `ok=true`, no drift/errors, both-family demo capability evidence, native/conntrack evidence, required address coverage and expected observed MAC sets. A matching revision alone cannot confirm. HTTP 202 includes the operation URL and means pending/unknown; 409 requires refresh and another deliberate action; explicit apply failure is 502. A historical confirmed operation remains historical when current health changes, but its replay cannot return mutation 200 without a fresh exact witness.

## Acceptance and remaining gates

Committed tests cover genuine signed WebAuthn and HTTP controls, account/resource denial, replay/origin/UV/binding failures, concurrent enrollment/login/logout, schema bounds, concurrent SQLite writers, fake base conflicts, timeout/failure/unconfirmed outcomes, restart/idempotency/expired replay, storage/migration failure and process-crash durability. See [measured service acceptance](../acceptance-003.md) and the [local runbook](../service-demo-003.md).

Passing synthetic tests establish this local behavior only. Node 26.8.1's `node:sqlite` is a release-candidate API; a WAL crash fixture is not a hardware power-loss guarantee. Real-router packet cutoff, protected adult safety, acceleration, timezone/DST, firmware persistence, production transport/auth recovery and deployment retain their separate acceptance gates.
