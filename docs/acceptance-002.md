# PWA acceptance — session 002

Scope: local, authenticated, fictional parent PWA and fake-router behavior. No router/household data, remote operations, device installations, telemetry or deployment were used.

## Measured environment and evidence

On 2026-10-11, Node 26.8.1, npm 11.19.0 and project Playwright 1.61.0 exercised cached Chromium 153.0.8010.12. The primary viewport was 390 × 844. The browser used real CTAP2 resident credentials with user verification; `@simplewebauthn/server` verified actual registration/assertion responses against the localhost RP/origin and server-owned bootstrap account. No runtime identity header or role selector was used.

The final local suite passed **14/14 scenarios in 20.8 seconds** after auth cancellation and server browser-episode fixes. `npm run typecheck` passed on the same source. Tests used reduced motion for stable evidence. Latest final independent source review and exact-head CI evidence are recorded in [PR #2](https://github.com/bearyjd/couvre-feu/pull/2).

The initial renderer failed with `SkFontMgr_FontConfigInterface.cpp:163 Not implemented`. An isolated `/tmp` Fontconfig file/cache using existing Liberation fonts restored rendering. No system/font installation or host cache modification was performed. Loopback/browser execution required the environment’s sandbox escalation, within the approved synthetic-local scope. CI uses its normal browser/font environment unless explicitly configured otherwise.

## Scenario evidence

| Gate | Current evidence |
|---|---|
| Genuine authenticated controls | Pass: actual browser registration, server verification, parent-only people and subsequent passkey login |
| Pause → pending → healthy exact confirmation | Pass: accepted request shows pending, repeated controls disabled, then fake confirmation and observed manual pause |
| Timed pause and service-off expiry | Pass: HTTP service stopped, independent fake-engine clock advanced 61 seconds, effective pause expired while metadata persisted; restarted UI observed expiry |
| Resume during active schedule | Pass: manual pause removed, active fictional UTC schedule and continued block explained |
| Explicit failure and timeout/unknown | Pass: failure distinct; unknown disables controls and resolves through observation/explicit refresh; exactly one mutation, no queued retry |
| Stale intent and HTTP 409 race | Pass: local revision change cancels stale intent; router change after preflight receives conflict, requiring refresh and a new click |
| Offline shell/status and reconnect | Pass: only public shell assets cached, scoped timestamped status read-only, zero writes offline/reconnect, session and status refreshed before controls |
| Clock-ahead expiry truth | Pass: offline browser clock advanced two minutes; observed pause stayed paused, countdown said awaiting router observation, no fabricated observed expiry |
| Offline logout | Pass: local snapshot cleared immediately; server sign-out explicitly pending offline and completed online |
| Role and cache isolation | Pass: parent admin endpoint denied, cross-person mutation denied, registration replay/account-role fields rejected, permission revocation purged status, reauthentication used new scope namespace |
| Shared browser | Pass: cross-tab logout clears views; admin→parent switch removes prior person/device status from cache |
| Wrong WebAuthn origin | Pass: modified client-data origin rejected with no stored credential |
| Required user verification | Pass: UV flag removed from an actual browser attestation, server rejected it and stored no credential |
| Auth/logout response races | Pass: cross-tab logout cancels outstanding options and held verified responses; no verification continuation/new browser session survives logout |
| Phone/keyboard/basic accessibility | Pass: no phone/desktop horizontal overflow, first keyboard skip link targets main, explicit duration/action labels, textual state reasons, unavailable activity labels, no page errors; normal text palette contrast measured at 5.57:1 or higher |

Timed expiry uses a deterministic fake clock and an independent fake-engine timer in the browser fixture process while the HTTP server is stopped. It demonstrates fake service-off authority, not real router cron, real-time boundary latency or packet cutoff. The runnable CLI also separates fake-router and service processes. Service storage/restart/idempotency/schema evidence belongs in [acceptance-003](acceptance-003.md).

## Reproduction and review gates

Run `npm run test:web` and `npm run typecheck`; local startup and the optional isolated font workaround are in [demo-002](demo-002.md). Browser fixtures use localhost port 4273, temporary fictional databases and direct fixture constructors/CLI token issuance, never test-identity HTTP routes. No authentication traces or credential/token screenshots are recorded. The parent screenshots are `/tmp/couvre-feu-parent-phone.png` and `/tmp/couvre-feu-parent-desktop.png`, local artifacts, not tracked household captures.

Latest final independent review, exact-head CI and merge evidence are recorded in [PR #2](https://github.com/bearyjd/couvre-feu/pull/2). A passing local browser suite alone cannot satisfy those gates.

Actual target router compatibility, packet behavior/five-second cutoff, private HTTPS PWA installation, genuine phone/device browser matrix, production recovery/auth enrollment and household deployment are **pending, untested and outside this prototype’s acceptance**. Usage/domain/app-history collectors are excluded and unavailable.
