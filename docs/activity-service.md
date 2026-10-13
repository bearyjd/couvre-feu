# Estimated network activity (service side)

The service ingests per-device router byte counters and shows each assigned parent an **estimate of network activity** for their own children. It is not app use, websites or screen time, and the UI says so. This is separate from the offline focused-browser evaluator in [activity-evidence-prototype.md](activity-evidence-prototype.md).

## What is measured

Source: `cfctl rpc-activity --json`, version 1 (provided by the separate router-counters change; this service depends on it for live use):

```json
{"version":1,"router_epoch":1,"counter_epoch":7,"offload":"off","devices":[{"person":"alex","mac":"02:00:00:00:02:01","ip":"192.168.8.20","neighbor":"REACHABLE","tx_bytes":0,"rx_bytes":0,"tx_packets":0,"rx_packets":0,"blocked_packets":0}],"errors":[]}
```

Counters are cumulative and reset when `counter_epoch` changes. `parseRouterActivity` in `shared/src/router-activity.ts` is strict: unknown, missing or duplicate fields, non-canonical or multicast MACs, malformed IPv4, more than 256 devices, more than 16 error codes, more than 131072 bytes, and integers above 2^53 - 1 (the largest exactly representable value) are rejected. Nothing is stored from a rejected payload.

Stored per device and poll: person, MAC, service-side sample time, router and counter epochs, offload state, tx+rx byte counters, blocked-packet counter and the derived delta. Not stored: IP address, neighbor state, packet counts, domains, contents. The sample time is the service clock at receipt; the router contract has no wall clock.

Estimated per child per UTC day (evaluation by `service/src/activity-report.ts`):

- **Estimated online minutes**: minutes in which the child's devices moved more than 30,000 bytes (tx+rx). The threshold is a documented heuristic, not calibrated; background chatter from an idle phone is intended to fall below it.
- **Total bytes** and **blocked attempts** (growth of `blocked_packets`): sums over all observed deltas for the day.

## What is not measured

App use, websites, DNS, content, screen time, whether a person is present or attentive, or traffic the router cannot count. Hardware flow offload can bypass the counters, so a day whose samples report offload `on` or `unknown` is flagged "possibly undercounted" and online minutes are shown as "at least". Shared or guest devices, VPNs and a device on another network are invisible or misattributed. Router-reported blocked packets include retries, so they are not distinct attempts.

## Deltas, resets and coverage

- First sample of a device: baseline only. No delta.
- `counter_epoch` or `router_epoch` change, or any decrease of tx, rx or blocked: **reset**. No delta is derived (never negative); the next sample after a reset yields a delta again.
- More than 90 s since the previous sample: **gap**. The interval cannot be attributed to minutes and is unknown. Samples at or before the previous sample time are dropped.
- Each valid interval is split across the minutes it overlaps. A device covers a minute when at least 30 s of valid intervals overlap it; a child's minute is covered only if **every** currently assigned device covers it. All other minutes (service down, router unreachable, reset, no sample, retention) are **unknown**, never zero. A day with no covered minute reports `null` figures and the UI says "No data". Today is evaluated up to the last completed minute.
- A poll that reports router `errors` is not stored.

## Privacy model

- Only devices whose (person, MAC) pair is assigned to a child in the service's current policy are stored. Other devices in a payload are dropped before any write, including a MAC enrolled for one child but reported for another. A device or person removed from policy has its stored samples deleted at the next ingest, report, prune or live observation, not only by retention.
- `GET /people/:id/activity` (read-only) requires a session and returns 404 `person_not_found` unless the person is in the actor's assigned people and enrolled in policy. There is no write route. The PWA hides the panel offline or signed out, renders with `textContent` only and does not cache activity in browser storage; the service worker never caches it.
- Retention defaults to 30 days; set `CF_ACTIVITY_RETENTION_DAYS` (1 to 365) for the demo or integration service. A pruning job runs at startup and hourly and deletes everything older than the window. Reports cover today and the previous seven UTC days.

## Collection paths

- **Demo**: the fictional router (`demo-router/src/activity.ts`) emits deterministic synthetic counters, with a weekly counter reset so the reset path runs. The demo service polls every 15 s. History starts when the service starts, so earlier days correctly show no data.
- **Live integration**: `integration-dispatch prepare <manifest> <permit> activity` renders one reviewable single-use invocation of `cfctl rpc-activity --json`; `execute` consumes it like `observe`. It uses the same manifest binding, 900 s expiry, dispatch epoch, permit digest and one-attempt rules and is read-only. It does not alter the policy observation, receipts or active operation. The owner-enabled automatic dispatcher refuses `activity` (`activity_requires_operator_permit`), so continuous live polling is not wired and each live sample needs its own permit. Fresh and existing integration databases pass through `integration-002.sql`, which rebuilds `dispatch_steps` with an explicit column list to accept the new step kind. Nothing here contacts a real router; live use needs a separately approved invocation.

## Validation

`shared/tests/router-activity.test.ts` (parser), `service/tests/activity-store.test.ts` (deltas, resets, retention, estimation, coverage, permissions, demo router), `service/tests/integration-activity.test.ts` (permit path, failure handling, database upgrade) and `web/tests/activity.spec.ts` (panel and server enforcement in a real browser).
