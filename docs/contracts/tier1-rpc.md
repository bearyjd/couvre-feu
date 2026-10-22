# Tier-1 RPC and schema contracts (DRAFT)

Status: DRAFT, nothing here is implemented. It lets router (R) and service (S) work proceed in parallel. Router-side
validation and service-side parsing must both reject anything outside these bounds. All MACs below are fictional.
Line references are to this branch (`chore/m0-contracts`). A claim marked UNVERIFIED was not confirmed against code.

Deploy order: service first, then router. The service parser accepts both old and new replies before any router changes.

## 1. rpc-status: optional scope fields

`rpc-status` (`router/lib/rpc.sh`) gains two optional top-level fields, added in one change on both sides
(`shared/src/router-rpc.ts:78` `normalizeObservation` uses a strict `object()`, so an unknown key is rejected today).

| field | type | rule |
|---|---|---|
| `scope` | string[] | canonical lowercase colon MACs, unique, strictly ascending (`LC_ALL=C`), 1..256 entries |
| `scopeSha` | string | 64 lowercase hex |

Rules for the service parser:
- `scope` and `scopeSha` appear together or not at all. `scope:null` is invalid (distinct from absent).
- The service recomputes `sha256(scope.join('\n') + '\n')` and requires it to equal `scopeSha`.
- `scope` must contain the floor, be disjoint from `protectedMacs`, and contain every MAC in `acceptedPolicy`.
- Absent, busy or failed replies mean scope is `unknown` for alerting and audit, and only "the floor" for authorization.
  A busy reply must never look like scope shrinkage (see `scope_changes` below).
- `rpc-allowed` lives in `/etc/couvrefeu` (`router/lib/rpc.sh:31` reads `$CF_DIR/rpc-allowed`; `router/install.sh:200`
  writes it). Only a per-call snapshot may live in the private runtime dir. The snapshot is UNVERIFIED: no such snapshot
  exists in `rpc.sh` today, so the "status and validation read the same bytes" property is a router requirement, not current
  behaviour.

## 2. rpc-inventory v1 (read-only, LOCKED format)

Exact argv: `cfctl rpc-inventory --json`. One JSON object, strict keys, no unknown fields:

```
{"inventory_version":1,"generation":"<64 hex>","routerTime":<int>,
 "devices":[{"mac":"02:00:00:00:00:01","ipv4":["192.0.2.10"],"hostname":"host-a"|null,
             "source":"lease"|"neigh"|"both"}],
 "truncated":<bool>,"errors":["<code>"]}
```

| field | bound |
|---|---|
| `inventory_version` | integer 1. The service checks it BEFORE the strict key check, so a future version is "unknown version", not "bad keys" |
| `generation` | 64 lowercase hex and equal to the configured generation |
| `routerTime` | integer; an invalid clock gives `0` plus error `invalid_clock` |
| `devices` | <= 256 entries, canonical unicast MACs (`cf_mac_valid`), unique, ascending |
| `ipv4` | <= 4 per device, canonical dotted quad, sorted, unique. No IPv6, no lease expiry, no protected count |
| `hostname` | see section 2.1 |
| `source` | `lease`, `neigh` or `both` |
| `truncated` | bool |
| `errors` | <= 16 codes, each matching `^[a-z][a-z0-9_]{0,63}$` |

Size bound holds by construction: 256 devices x 4 addresses is about 51 KB, under the 131072 byte stdout cap
(`service/src/ssh-router.ts:82`). There is no "set truncated when over the size limit" rule.

Scope of the listing: br-lan only. Sources are br-lan neighbours (`ip -4 neigh show dev br-lan`,
`router/lib/core.sh:296`) and leases whose IPv4 lies in the br-lan subnet. `/tmp/dhcp.leases` covers every dnsmasq pool
including guest (`core.sh:313-315`), so the subnet filter is required. `neigh` means state REACHABLE, PERMANENT, STALE,
DELAY or PROBE (the set `cf_addresses` already treats as live, `core.sh:305-340`).

Truncation: whole devices only. Neighbour-present devices are kept before lease-only ones, and kid MACs first. The service
must not infer "gone" or "New" from a truncated reply.

Refusal body: the same keys with `devices` empty, mirroring `cf_activity_refuse` (`router/lib/activity.sh:248-251`),
which carries the error code in `errors`. An invalid clock yields `routerTime:0` and `invalid_clock`.

Protected management MACs are never listed. The reader is new: the lease parse in `core.sh:315` is
`awk 'NF>=3{print "L\t" $3 "\t" tolower($2) "\t" $1}'`, which drops field 4 (hostname) (VERIFIED), and `cf_addresses`
emits only kid and protected bindings (VERIFIED, `core.sh:341-345`).

### 2.1 Hostnames

- The router maps dnsmasq `*` or empty to `null`. Any character outside `[A-Za-z0-9._-]`, length > 63, or a first
  character that is not alphanumeric gives `null`. REJECT, never strip.
- The service validates again and rejects the WHOLE reply on any violation. It uses the non-router parse mode (`parseJSON(text, false, ...)`: router mode rejects the camelCase `routerTime` key) behind a raw-text
  pre-check: printable ASCII only, no backslash (so no `\u` escapes) and integer-only numbers (`1.0`, `5e0` and `-0` are rejected). Field patterns then pin every string.
- One shared sanitiser is used for both inventory hostnames and scope-preview terminal output.
- The UI renders with `textContent` only, labelled "name reported by device". Hostnames are never identity, never in
  alerts, audit rows or logs. Any alert text defangs dots.

### 2.2 Old routers and errors

Anything other than a valid v1 reply gives `inventory_unavailable:<code>`, stored ONLY in `inventory_state`, NEVER in
`integration_state.observation_error`, and never thrown out of the dispatch cycle. Accepted old-router outcomes:

| case | observable | verified at |
|---|---|---|
| new `cfctl-ssh`, old `cfctl` | exactly `{"ok":false,"errors":["invalid_command"]}`, exit 2 | `router/lib/core.sh:572,574` |
| old `cfctl-ssh` | empty stdout, exit 2 (silent `exit 2`) | `router/cfctl-ssh:35` (`--rpc-only`), `:58` (default arm) |
| transport error, empty output, unknown version, parse failure | any | service side |

Exit code problem: `boundedChild` (`service/src/ssh-router.ts:60`, close handler `:91`) drops the exit code. A nonzero exit
with empty output becomes `ssh_exit_failed`, indistinguishable from ssh's own 255 (host-key mismatch, auth failure). The
change must surface the exit code (e.g. on `RouterTransportError`) so exit 2 maps to "old router" and 255 is NOT hidden as
"unavailable". With `allowNonzeroOutput=true` (`ssh-router.ts:55`) the invalid_command body reaches the parser today, and the
parser must map it to `inventory_unavailable:invalid_command`.

Execution model:
- Inventory runs inside the existing single dispatch loop, at the start of `cycle()`, only when no operation is active.
- Own 8 s deadline, modelled on `runActivity` (`service/src/integration-worker.ts:134-152`).
- New automatic permit kind: `executeAutomatic` refuses `'activity'` today (`integration-worker.ts:71`). Note `runActivity`
  sets `dispatch_stopped=1` after a poll (`:150`); inventory is automatic and must not.
- Admin refresh only sets `refresh_requested_at` (1 per 10 s across admins; 409 when dispatch is off). It never opens SSH.
- Inventory failure never triggers dispatch backoff and never affects policy observation or operations.

### 2.3 cfctl-ssh and cfctl grammar edits

- `router/cfctl-ssh:35`: append `|rpc-inventory` to the `--rpc-only` allowlist.
- `router/cfctl-ssh:46`: add `rpc-inventory` to the `status|activity|rpc-activity` arm (`[ "$#" = 2 ] && [ "$2" = --json ]`).
- `router/lib/core.sh:565`: add `rpc-inventory` to the `activity|rpc-activity` arm.

## 3. Receipt semantics the service relies on

A `null` receipt for the service's own attempted operation is "unknown" (`receipt_missing_remote_outcome_unknown`), not
success and not failed, unless the router's own pre-write refusal is proven (`integration-worker.ts:207`
`refusedBeforeWrite`). Today the router REFUSES new changes at 128 receipts (`router/lib/rpc.sh:109`
`receipt_capacity`). Labelling eviction is a ROUTER-SIDE CHANGE: evict the oldest, never the current receipt, in the same
metadata write. After it, absence can no longer imply "never applied". Tests: `service/tests/integration-worker.test.ts`.

## 4. integration-004 DDL (DRAFT)

Placement: integration migrations (`service/migrations/integration-NNN.sql`, applied by `IntegrationStore`,
`service/src/integration-db.ts:50-62`) are a separate chain from the main chain (`001`..`008`). 004 needs main migration
008 (`people`) to have run first, because `scope_requests.person_id` references `people(id)`.

Detection: one marker for 004. Run it unless `operations` sql contains `'pause_all'` (from `sqlite_master`; 003 detects `"'enroll'"`, `integration-db.ts:57`). The
`dispatch_steps` `'inventory'` marker belongs to integration-006 (M2c), which carries the `inventory` step kind; 004 does not touch it. Rebuilds: `operations` follows
003's `_next` pattern; `dispatch_steps` follows integration-002's RENAME-to-`_v1` pattern. Set `PRAGMA foreign_keys=OFF`
OUTSIDE the transaction (a no-op inside), then `PRAGMA foreign_key_check` before commit. Never rename a parent table away
first: SQLite >= 3.26 rewrites child FK references to the renamed name. Always create `X_next`, copy, drop `X`, rename.
`INSERT ... SELECT` uses explicit column lists. Conventions: `STRICT`, `CHECK` enums, integer epoch seconds, text ids.

```sql
-- 1. operations: add pause_all, resume_all, move (columns unchanged; explicit lists).
CREATE TABLE operations_next ( ...same as integration-003..., action TEXT NOT NULL CHECK(action IN
 ('pause','resume','enroll','unenroll','pause_all','resume_all','move')), ... ) STRICT;
INSERT INTO operations_next(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,
 idempotency_key,created_at,updated_at,error,confirmed_at)
 SELECT id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,
 idempotency_key,created_at,updated_at,error,confirmed_at FROM operations;
DROP TABLE operations; ALTER TABLE operations_next RENAME TO operations;

-- 2. operation_people is the AUTHORITY for multi-child operations (operations.person_id is a representative only).
CREATE TABLE operation_people (
 operation_id TEXT NOT NULL REFERENCES operations(id), person_id TEXT NOT NULL REFERENCES people(id),
 PRIMARY KEY(operation_id,person_id)) STRICT;
-- Every pause_all/resume_all/move operation has >= 1 row.

-- 3. dispatch_steps: kind IN ('observe','apply','receipt','activity','inventory') via the 002 RENAME-to-_v1 pattern;
--    recreate dispatch_live_claims.
-- 4. automatic_read_summary: kind CHECK IN ('observe','receipt') is created by CREATE TABLE IF NOT EXISTS
--    (integration-db.ts:78), so existing DBs keep the narrow CHECK. 004 rebuilds it (_next, copy, drop, rename) with
--    kind IN ('observe','receipt','inventory').

-- 5. Scope requests (kept after resolution for audit).
CREATE TABLE scope_requests (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES people(id),
 mac TEXT NOT NULL CHECK(length(mac)=17 AND mac GLOB '[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]'),
 requested_by TEXT NOT NULL REFERENCES accounts(id),
 state TEXT NOT NULL CHECK(state IN ('pending','observed','expired','cancelled')),
 scope_sha_before TEXT CHECK(scope_sha_before IS NULL OR (length(scope_sha_before)=64 AND scope_sha_before NOT GLOB '*[^0-9a-f]*')),
 scope_sha_after  TEXT CHECK(scope_sha_after  IS NULL OR (length(scope_sha_after)=64  AND scope_sha_after  NOT GLOB '*[^0-9a-f]*')),
 generation TEXT NOT NULL, created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+604800),
 resolved_at INTEGER, resolved_by TEXT REFERENCES accounts(id)) STRICT;
CREATE UNIQUE INDEX scope_requests_pending ON scope_requests(mac) WHERE state='pending';
CREATE INDEX scope_requests_person ON scope_requests(person_id,state);
-- Application rule: at most 4 pending per child. No UNIQUE(person_id,mac): resolved rows stay.

-- 6. Router scope observation, so growth/removal and growth while the service was down are recorded and alertable.
CREATE TABLE router_scope_observed (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 scope_sha TEXT NOT NULL, observed_at INTEGER NOT NULL) STRICT;
CREATE TABLE scope_changes (id INTEGER PRIMARY KEY, observed_at INTEGER NOT NULL, sha_before TEXT, sha_after TEXT NOT NULL,
 added_json TEXT NOT NULL, removed_json TEXT NOT NULL, matched_request_id TEXT REFERENCES scope_requests(id)) STRICT;
-- matched_request_id NULL means unmatched growth/removal: alertable.

-- 7. Inventory snapshot, scoped by generation.
CREATE TABLE inventory_devices (
 generation TEXT NOT NULL, mac TEXT NOT NULL CHECK(length(mac)=17 AND mac GLOB '[0-9a-f][0-9a-f]:*'),
 ipv4_json TEXT NOT NULL CHECK(json_valid(ipv4_json) AND json_array_length(ipv4_json)<=4),
 hostname TEXT CHECK(hostname IS NULL OR (length(hostname)<=63 AND hostname NOT GLOB '*[^A-Za-z0-9._-]*')),
 source TEXT NOT NULL CHECK(source IN ('lease','neigh','both')),
 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 acknowledged_at INTEGER, acknowledged_by TEXT REFERENCES accounts(id),
 PRIMARY KEY(generation,mac)) STRICT;
-- Row cap 1024 per generation. Retention 30 days default, configurable up to 90 (cf. activity-store.ts:11-12, which
-- uses DEFAULT_RETENTION_DAYS=30 and MAX_RETENTION_DAYS=365). last_seen advances only for source neigh or both.

-- 8. Inventory state singleton.
CREATE TABLE inventory_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 baseline_at INTEGER, last_ok_at INTEGER, last_error TEXT, refresh_requested_at INTEGER,
 alert_day_start INTEGER, alert_day_count INTEGER NOT NULL DEFAULT 0, last_alert_at INTEGER) STRICT;
```

Required code changes for `operation_people` (not in M0): `integration-worker.ts:95` currently checks only
`actor.person_ids.includes(op.person_id)`, so the actor must instead be authorized for EVERY `operation_people` row at
dispatch; visibility (`service/src/integration-policy.ts:57`, `:129`) becomes "any row".

## 5. Flags and alerts

- Baseline and alerts come only from a COMPLETE poll (no `errors`, not `truncated`).
- Re-baseline silently when the store is empty or `last_ok_at` is older than retention.
- "New" = unacknowledged and first seen after the baseline.
- Alerts are coalesced: 1 per poll, <= 1 per hour per admin, <= 12 per day.
- "Private address" = locally-administered bit (second hex digit of the first octet in `2367abef`). A hint only, never a
  gate. Pinned by `tests/test-core.py` (`cf_mac_valid` itself does NOT test this bit; it checks unicast, `core.sh:56-59`).
- MAC rotation is never merged, transferred or used to suppress an alert.
- Tap-to-assign warns: "confirm in the device's Wi-Fi settings".

## 6. Open points

Exact `operations.person_id` representative value for multi-child operations, and the alert settings UI, are decided in
M2a/M2c.

## 7. M2a decisions (resolved from the open points above)

- Parser context: `normalizeObservation(value, {protectedMacs, floor})` and `parseObservation(text, context)`. The shared parser checks format,
  order, digest and the accepted-policy superset on its own; the disjoint-from-protected and floor-superset rules need the manifest, so the
  worker always passes it. The context argument is required: `ssh-router.ts` parses with the named `FORMAT_ONLY` marker first (format only);
  the worker's second pass enforces the manifest rules.
  Any violation rejects the whole observation (fail closed, `router_observation_invalid`).
- A reply with `errors` is treated like a reply without scope: scope stays unknown and the remembered scope is not replaced.
- integration-004 holds only what M2a needs: the `operations.action` widening (pause_all, resume_all, move), `operation_people`,
  `scope_requests`, `router_scope_observed`, `scope_changes` and `parent_alerts` (the integration chain skips main 004.sql, so ParentAlerts had
  no table; new kind `router_scope_change`). One detection marker: `operations` sql contains `'pause_all'`. The `dispatch_steps` /
  `automatic_read_summary` rebuilds and `inventory_*` tables are NOT in 004; M2c adds them (integration-006), so 004 is not amended after M2a ships.
- integration-005 (M2b) is the device move migration: `devices.state` gains `moving` and `devices.move_to` (target child) is added; the table is rebuilt in place
  (marker: `devices` sql contains `'moving'`). Routes: `POST /bulk/pause-all`, `POST /bulk/resume-all` (one operation, one rpc-sync, one receipt) and the admin device
  move; every one needs a fresh step-up bound to the exact change. Operations returned for `pause_all`/`resume_all` carry an `effect` field
  (`blocking`, `not_blocking`, `unblocked`, `unchanged`, `may_still_be_blocked`); it states what the router is doing now, not what was requested.
  `tr-` is a reserved idempotency-key prefix (the time-request service's re-pause keys); client keys starting with it are refused as missing.
  A move whose observation shows the device under neither child, or under a child that is no longer active, keeps the device active under its source child and the
  operation carries `device_move_drift`.
- `router_scope_observed` gains `generation` and `scope_json` (the contract table had only the digest, which cannot yield added/removed MACs).
- Baseline: with no remembered scope the comparison base is the manifest floor, so growth that happened while the service was away alerts.
  A rebind deletes `router_scope_observed` (new generation, new baseline).
- A change is "matched" only when it is pure growth and every added MAC has a pending request of the same generation; mixed changes alert
  but still resolve the requests whose MAC appeared. Removal is always unmatched (warning). Every change raises one `router_scope_change` alert
  (admins only): `info` when matched, `critical` for unmatched growth, `warning` for pure removal. Alert details carry counts, `matched` and the change
  id, never MACs; the `audit` row (never pruned) carries the MACs, requesters, request ids and digests as JSON.
- A rebind cancels every pending scope request (`cancelled`); pending rows are also keyed by generation (dedupe, per-child cap, matching).
- The first observation after a rebind onto a router whose live scope is larger than the new manifest floor raises exactly one `critical` unmatched
  alert, because the baseline is the floor. That is intended: the admin acknowledges it after checking the router.
- `device_add` checks the device limits and the revision precondition before it may create a scope request, and reads the router scope only from the
  generation-checked `router_scope_observed` row. `scope_request_conflict` (another child already has a pending request for that MAC) is an accepted
  information leak of the same kind as `device_already_enrolled`.
- `scope_requests` caps: 4 pending per child (`scope_request_limit`), one pending per MAC (a second child asking gets `scope_request_conflict`),
  7-day expiry (also enforced by CHECK). Resolved rows older than 90 days go unless a scope change references them.
- `device_add` for a MAC outside the floor and outside a fresh observed scope answers 409 `device_pending_router_scope` (committed, not thrown, so
  the request and audit row persist). The body carries `mac` and `requestId` as fields and only the placeholder text
  `cfctl scope-add <ADDRESS FROM DEVICE SETTINGS> --base <router-read>`.
- Protected cap is 128 in the service (`PROTECTED_MAC_LIMIT`), pinned to `router/lib/install-common.sh` `valid_protection` by a drift test.
- Observed scope is not part of `targetDigest`; rebind validates stored devices against the NEW manifest floor only.

## 8. M2c decisions (inventory, service side)

- Parser: `shared/src/router-inventory.ts` uses `parseJSON(text, false, 131071)`, not router mode, because router mode rejects the contract's camelCase key `routerTime`. ASCII is enforced field by field
  (hostname, address, code and generation patterns). `inventory_version` is checked before the strict key check; a missing or non-1 version is `unknown_inventory_version`. The reply is rejected as a whole for a
  protected MAC (`protected_mac_listed`), any hostname outside `[A-Za-z0-9][A-Za-z0-9._-]{0,62}`, an unsorted or duplicate address or MAC, or a size of 131072 bytes or more.
- `ipv4` "sorted" means C-locale string order (what `sort -u` prints: `192.0.2.10` before `192.0.2.9`). M1e must emit exactly that. MACs are strictly ascending.
- Error strings stored only in `inventory_state.last_error`: `inventory_unavailable:<code>` for old routers (`old_router` for an empty exit 2, `invalid_command` for the exact body), `unknown_inventory_version`,
  `invalid_router_inventory`, `empty_reply`, `protected_mac_listed` and transport codes such as `ssh_timeout`; ssh exit 255 is stored as `inventory_transport_error:ssh_exit_255` so it is never shown as an unavailable inventory;
  an incomplete (errors or truncated) reply is `inventory_incomplete:<code|truncated>`. `RouterTransportError.exitCode` carries the remote exit status.
- integration-006: `dispatch_steps.kind` gains `inventory`, `parent_alerts.kind` gains `new_device` (ids and AUTOINCREMENT high-water kept), plus `inventory_devices` (with `alerted_at`), the 1024-row trigger and
  `inventory_state` (with `generation`, `last_attempt_at`, `refresh_pending`). `automatic_read_summary` is not widened: an inventory poll records `automatic_read_polls` only, so its steps are pruned with the other automatic reads.
- Execution: a poll is a generated permit under the automatic owner only (no operator form). It runs at the start of `cycle()` when no operation is active, every 60 s (`last_attempt_at`) or when `refresh_pending`.
  The step is always settled `resolved`; the result is fenced by epoch and step ownership; `dispatch_stopped` is neither read nor written. Failures are caught inside `pollInventory`.
- Incomplete polls (errors or truncated) refresh devices already known and store nothing new, so they can neither baseline nor produce "New" nor imply "gone". "New" rows carry `alerted_at`: a device whose alert was
  coalesced away is alerted by a later complete poll. Alert limits (1 per poll, 1 per hour, 12 per 24 h from the first alert of the window) are global because all admins share one system `new_device` alert; its details are a count only.
- "Unassigned" = the MAC is in neither the `devices` table nor the desired policy. Routes (admin only, 403 `admin_required` otherwise): `GET /admin/inventory`, `POST /admin/inventory/acknowledge {mac}`,
  `POST /admin/inventory/refresh {}` (202; 409 `inventory_dispatch_disabled`; 429 `inventory_refresh_rate_limited`). Retention: `CF_INVENTORY_RETENTION_DAYS`, default 30, at most 90.
- Review fixes (M2c):
  - Parser: `ipv4` must be strictly ascending C-locale order; a violation is reported as `ipv4_not_sorted` (stored as `inventory_unavailable:ipv4_not_sorted`) so the router side knows exactly what failed. The raw-text pre-check of section 2.1 applies.
  - `invalid_clock` (routerTime 0) is the one non-structural router error: devices still ingest (the service clock stamps first_seen/last_seen; routerTime is never used) and the poll may baseline and alert, with
    `last_error` `inventory_warning:invalid_clock`. Any other error code, truncation, or a refusal body with no devices is an incomplete poll.
  - Stalls (SM-1): no complete poll for 30 minutes raises the system alert `inventory_stalled` (counts and a cause only, at most once per 6 hours, shared with the row-cap alert). A re-baseline over an existing baseline
    (store emptied, or the last complete poll older than the retention) is not silent: it raises `new_device` with `{count, rebaselined: true}` ("accepted without review"). The very first baseline stays silent.
    Truncated replies still never imply gone or New.
  - Row cap (1024): eviction takes only long-unseen rows the reply does not list, that nobody acknowledged and that are not New devices still waiting for their alert. At the cap with nothing evictable no new row is stored,
    `last_error` is `inventory_row_cap` and `inventory_stalled` (cause `row_cap`) is raised.
  - Daily alert cap: once 12 alerts were raised in a window, further New devices are marked alerted and only increment the existing `new_device` alert's count; it is never re-opened.
  - Execution: the inventory step is settled `resolved` by claim token and dispatch epoch alone (reads have no lease semantics). A reply later than the 10 s lease is not applied (`inventory_unavailable:lease_expired`). Bookkeeping runs in a
    savepoint, so a failing bookkeeping step cannot leave the step `consumed` or `uncertain`. A poll that could not start (refused claim, fence) is `inventory_not_run:<code>`, distinct from a router failure. After an inventory poll
    the next cycle's delay is `max(0, pollSeconds - inventorySeconds)` so poll + inventory + observe stays inside the 30 s observation freshness window.
  - DTO: `personId` / `personName` name the child that owns the MAC (children admin `devices`, else the desired policy) only when the viewing admin manages that child; otherwise both are null (`flags.unassigned` still reflects
    assignment). There is no protected-device count.
  - Privacy: the acknowledge audit row records the inventory row id, never the MAC. Rows whose MAC is protected are purged at startup and on every ingest.
  - integration-006 also widens `parent_alerts.kind` with `inventory_stalled` and gives `inventory_state` `incomplete_since` and `last_stall_alert_at`; its inventory objects stay `IF NOT EXISTS`, because a database whose `dispatch_steps` is rebuilt by 002 re-runs the file (the integration-002 upgrade test).
