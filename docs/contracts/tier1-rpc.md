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
- `rpc-allowed` lives in `/etc/couvrefeu` (`router/lib/rpc.sh` `cf_scope_bind`; written by `router/install.sh`). The install-time set is the
  immutable **floor** (`backup/etc_couvrefeu_rpc-allowed.staged`); the live file may be any valid superset of it.
- Implemented behaviour: each call copies the live file once (bounded to 4609 bytes) into a private `runtime/.scope.<pid>` snapshot and
  validates the format, the floor, and computes `scopeSha` on exactly those bytes; the live path is never re-read for that call. The snapshot
  is removed at once (and on HUP/INT/TERM/PIPE); a leftover from a SIGKILLed reader is swept under `cf_lock` when its pid is gone.
- `rpc-status` reports `scope`/`scopeSha` from a snapshot whose sha equals the one safety-checked under `cf_lock`; a reload whose sha differs
  is refused as `operation_in_progress` (never a reply carrying an unchecked scope).
- `remove-fw` (uninstall) ignores the live scope, so uninstall works whatever the file became. Legacy unscoped installs omit both fields.
  A missing floor MAC, an invalid file, or a protected overlap gives `invalid_rpc_scope` / `protected_mac_overlap`.
- **M1d requirement:** any writer of the live `rpc-allowed` MUST hold `cf_lock` for the whole replace (write a temp file, `rename` over the live
  path, mode 600) and keep the floor; a writer that does not can make an in-flight call refuse as busy, and must not be relied upon for safety.

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
- The service validates again with `parseJSON(text, true, ...)` and rejects the WHOLE reply on any violation.
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
`refusedBeforeWrite`). The router now EVICTS the oldest receipt at 128 (`router/lib/rpc.sh:124`; never the current receipt, in the same
state write as the policy change) instead of refusing with `receipt_capacity`. Absence can therefore no longer imply
"never applied"; a replay of an evicted operation returns `policy_conflict` and `rpc-status` returns `receipt: null`. Tests: `service/tests/integration-worker.test.ts`.

## 4. integration-004 DDL (DRAFT)

Placement: integration migrations (`service/migrations/integration-NNN.sql`, applied by `IntegrationStore`,
`service/src/integration-db.ts:50-62`) are a separate chain from the main chain (`001`..`008`). 004 needs main migration
008 (`people`) to have run first, because `scope_requests.person_id` references `people(id)`.

Detection: one marker for 004. Run it unless `operations` sql contains `'pause_all'` AND `dispatch_steps` sql contains
`'inventory'` (both from `sqlite_master`; 003 detects `"'enroll'"`, `integration-db.ts:57`). Rebuilds: `operations` follows
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
