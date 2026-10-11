# Service acceptance — session 002

This evidence concerns the authenticated local fake-router service in [PRP-003](prp/PRP-003-policy-service.md), not production deployment or real packet enforcement. See the [runbook](service-demo-003.md) for reproduction and [PWA acceptance](acceptance-002.md) for browser evidence.

## Measured local checks

On 2026-10-11, Node **26.8.1** / npm **11.19.0** ran `npm run typecheck` and `npm run test:service`. The completed service run passed **45 scenarios**, including terminal reconciliation, monotonic confirmation, migration and authentication cancellation regressions. Tests use fictional data, native SQLite, real cryptographic assertions and a separate fake-router state database. No host/router privileged command or live router operation ran.

| Boundary | Committed evidence |
|---|---|
| Server WebAuthn validation | Genuine ES256 credential enrollment and signed assertion; wrong origin/RP/challenge, missing UV, replay, browser mismatch and cross-account user handle denial |
| Seeded authority | Registration cannot choose account, role or person assignment; one-use/reissued/expired bootstrap; simultaneous signed enrollment on two SQLite connections commits once |
| Sessions and shared browser | Server permission version, expiry, CSRF, logout/revocation, durable context epoch and generation; in-flight options/verification cancellation, overlapping cross-account and same-account verification |
| HTTP access | Exact Host/Origin, rejected identity headers, JSON/body bounds, no-store auth/API responses, permitted parent control and denied Blair/admin inventory |
| Confirmation | Exact operation/payload/revision, healthy status, no drift/errors, immutable dual-family fake capability profile, required coverage and matching observed sets |
| Uncertain outcomes | 202 pending, timeout after possible apply unknown, explicit failure, stale/mismatched confirmation, drift/errors/coverage and unreachable/stale engine |
| Revision and replay | Opaque durable/router/digest precondition; two service processes racing fresh and duplicate writes; router-local and same-revision policy base conflicts |
| Durable recovery | Restart/idempotency persistence, exact expired replay, pending before apply, SIGKILL after acceptance with WAL/FULL, independent fake expiry and backward clock high-water |
| Storage boundary | Operation/audit/state rollback before fake apply, transactional failed migration, unsupported schema, migration 002 invalidating legacy unbound authentication |
| Historical outcomes | Terminal confirmation/failure cannot be erased or automatically reapplied by stale or competing reconcilers; confirmation timestamp does not move backwards |
| cfctl schema seam | Strict ASCII/duplicate-key/depth/integer limits, protected/shared MACs, expanded schedules, canonical IPv6 duplicates and actual `router/lib/json.awk` serialization acceptance |
| Demo isolation | Rejected production/router/SSH/auth-bypass environment configuration; no production transport or target selection |

`service/tests/authenticator.ts` generates fixture credentials/assertions only. It is never imported by runtime source. HTTP tests enroll through the actual server routes; they do not inject request identity. Concurrent/crash fixtures run only as test child processes. The fake engine's immutable profile requires both-family evidence, regardless of what a supplied status claims.

## Limits and pending gates

The native SQLite API is stability 1.2 (release candidate) in the [version-matched Node documentation](https://nodejs.org/download/release/v26.8.1/docs/api/sqlite.html). Transactions configure WAL, FULL synchronization and foreign keys. The SIGKILL fixture establishes journal recovery after a process crash in this filesystem/runtime; it does not establish physical power-loss behavior, a production storage SLA or deployment compatibility.

The fake process owns its expiry high-water and heartbeat independently of service availability. Its file-backed compare-and-set and operation identity are simulator evidence, not implemented SSH semantics. There is no deployed service, live router adapter, production account recovery, stable private HTTPS installation, actual phone acceptance or real packet proof.

Actual OpenWrt/GL compatibility, five-second cutoff, protected adult safety, address/acceleration coverage, timezone/DST and firmware persistence retain the gates in [acceptance-001](acceptance-001.md). The original changed-policy/drift/reload non-atomic limitation remains documented. No synthetic confirmation clears those gates.

Independent review and exact-head CI must cover the final source, including fixes and documentation. The orchestrator records that final review/CI evidence separately; this document does not self-approve a merge.
