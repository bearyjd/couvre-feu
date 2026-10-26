# Tier-1 RPC and schema contracts (DRAFT)

Status: DRAFT. Sections 1 (router side), 3 and 9 are implemented on the router; the rest is a contract. It lets router (R) and service (S) work proceed in parallel. Router-side
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
(`service/src/ssh-router.ts:82`). The router also keeps a defensive byte guard (`CF_INVENTORY_MAX_BYTES`): it would drop
whole trailing devices and set `truncated` if a reply reached the cap. It is unreachable in production and is exercised only
by the test hook that lowers the limit (`tests/test-inventory.py` SizeGuardTests).

Scope of the listing: br-lan only. Both sources are filtered to the br-lan IPv4 subnet: br-lan neighbours
(`ip -4 neigh show dev br-lan`) and dnsmasq leases. `/tmp/dhcp.leases` covers every dnsmasq pool including guest, and
ARP lets any LAN host place any address in the neighbour table, so the subnet filter applies to both. The subnet is the
prefix of the br-lan `inet` entry carrying the LAN address (`cf_lan_prefix`, `router/lib/core.sh:396`, shared with
`cf_scope_evidence`), /8 to /32. No such entry (no mask, IPv6-only br-lan, a prefix below /8, or only other
addresses) refuses with `lan_address_mismatch`; failing `ip -4 addr` refuses with `lan_inspection_failed`. A failing
`ip -4 neigh` or a lease file that is a symlink, not a regular file or unreadable is not a refusal: the other source is
still listed, with `neighbor_inspection_failed` or `lease_inspection_failed`. `neigh` means state REACHABLE, PERMANENT,
STALE, DELAY or PROBE (the set `cf_addresses` already treats as live, `core.sh:302-360`).

Row order and `inventory_row_dropped`: each row is scoped first (subnet, then lease expiry) and validated afterwards. Rows
any LAN or guest client can induce are skipped SILENTLY: off-subnet or expired rows, and rows whose MAC is not a canonical
unicast MAC (dnsmasq's hwtype-prefixed form for htype != 1, a wrong length, multicast or all-zero). `inventory_row_dropped`
is reported, once, only for a row inside the subnet whose address or expiry field is malformed, which dnsmasq and `ip`
never write. A NUL byte in the lease file becomes \001 before parsing, so a hostname holding one is null: a shell command
substitution would drop the NUL (a strip, `ok\0evil` -> `okevil`), and BusyBox awk would end the record at the NUL and
parse the rest of the line as a lease row of its own. The SERVICE must treat `inventory_row_dropped` as a
non-structural WARNING, like `invalid_clock`, that does not make the poll incomplete. That service-side change is made
separately on its own branch.

Truncation: whole devices only. Neighbour-present devices are kept before lease-only ones, and kid MACs first. Intake is
also capped at 4096 distinct MACs per poll (`CF_INVENTORY_MAX_INTAKE`; kid MACs exempt, neighbours read before leases) to
bound time and memory under a flood; reaching it sets `truncated`, and the lease-only tier is then the lowest MACs among
those taken in, not among all. The service must not infer "gone" or "New" from a truncated reply.

Refusal body: the same keys with `devices` empty, mirroring `cf_activity_refuse` (`router/lib/activity.sh:248-251`),
which carries the error code in `errors`. Collection failures name their code (for example `lan_address_mismatch`),
not a generic `inventory_unavailable`. An invalid clock yields `routerTime:0` and `invalid_clock`, and expired leases are
then kept, as in `cf_scope_evidence`.

Protected management MACs are never listed. The protected list is checked at admission (`cf_protected_valid`) and read
again for the listing; if that read fails or yields an invalid MAC the reply is a refusal with
`inventory_protected_unreadable`, and an empty list refuses with `inventory_protected_empty` (an installation always has
at least one protected MAC). It never fails open into a listing. The reader is new: the lease parse in
`cf_addresses` (`core.sh:326`) is `awk 'NF>=3{print "L\t" $3 "\t" tolower($2) "\t" $1}'`, which drops field 4
(hostname) (VERIFIED), and `cf_addresses` emits only kid and protected bindings (VERIFIED, `core.sh:340-360`).

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
- `router/lib/core.sh:786-787`: add `rpc-inventory` to the `activity|rpc-activity` arm.

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
  - `invalid_clock` (routerTime 0) and `inventory_row_dropped` (the router skipped a malformed in-subnet unexpired lease row) are the only non-structural router errors (`BENIGN_ROUTER_ERRORS`): devices still ingest (the service clock stamps
    first_seen/last_seen; routerTime is never used) and the poll may baseline and alert, with `last_error` `inventory_warning:<first code>` (e.g. `inventory_warning:inventory_row_dropped`). Any other error code, truncation, or a refusal body
    with no devices is an incomplete poll.
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

## 9. M1d scope administration (router, admin-only)

The live `rpc-allowed` changes ONLY through three root, interactive `cfctl` verbs (`router/lib/core.sh` `cf_scope_main`,
`router/cfctl` before the bootstrap boundary). None of them is in the `cfctl-ssh` grammar (unchanged allow-list), and
nothing in `rpc.sh` or `activity.sh` writes the scope.

| command | effect |
|---|---|
| `cfctl scope-preview <MAC>` | read-only. Prints the address type (locally administered bit), current br-lan evidence (neighbour state; unexpired lease inside the br-lan IPv4 subnet, with the hostname through the shared sanitiser: `[A-Za-z0-9][A-Za-z0-9._-]{0,62}`, else `(unnamed)`), the current `scopeSha`, whether add/remove would be refused (and why), and a WARNING listing protected MACs with no evidence now (a rotated adult address hint). Final line is JSON (`addRefusal`, `removeRefusal`, `protectedAbsent`, ...). |
| `cfctl scope-add <MAC> --base <scopeSha>` | adds one MAC. |
| `cfctl scope-remove <MAC> --base <scopeSha>` | removes one MAC. |

Commit flow (add/remove): (1) argv shape, the service marker and a TTY on stdin are checked and the typed confirmation
(the last 6 hex digits of the MAC, no colons) is read in `cfctl` BEFORE platform admission, so no platform lock, policy lock or
admission deadline is held while a human types (`trap '' TSTP TTIN TTOU` and, on an output TTY, `stty -ixon` are set first, for all three
verbs); (2) admission, read-only load; (3) `cf_lock`; (4) under the lock:
install gate, ready+complete generation, single-read scope snapshot, `--base` CAS against it, every refusal, then `cf_ssh_guard`;
(5) `logger -t couvrefeu` INTENT line (refused if it cannot be logged); (6) candidate `runtime/.scope.<pid>` created with `set -C`, umask
077, mode 600, same filesystem as `/etc/couvrefeu`, re-validated with the runtime validators (format, floor, protected-disjoint, every
P MAC kept), `sync`, rename over `rpc-allowed`, `sync`; (7) COMMIT log line; (8) `cf_unlock` and platform lock release, THEN the buffered
result (old and new `scopeSha`, or the refusal) is printed. A crash at any step leaves the
old or the new complete file; a leftover candidate is swept under `cf_lock` and allowed by the uninstall runtime whitelist. The floor
(`backup/*.staged`, `*.after`) is never written.

Terminal and lock hazard (review S-M1): a write to a stopped or flow-controlled terminal blocks, and a write under a lock would hold
`cf_lock` and the platform lock (and so every `rpc-sync`, cron `expire` and fw3-include `apply-fw`, which then fail with
`locked`/`transaction_contention`). Solved: preview and commit output (and refusals under the lock, and the commit-audit warning on
stderr) are buffered and written only after both locks are released. M4b generalizes this for EVERY `cfctl` command (`sync`,
`rpc-*`, `pause`/`resume`, `expire`, `apply-fw`, `status`, scope verbs): from the first held lock (vendor admission's platform
lock, otherwise the passed transaction gate) stdout goes to an unlinked private file under the root-owned sticky `/tmp`
(if it cannot be made, a stderr warning and the pre-M4b direct output: never a refusal), and only after `cf_lock`, the platform lock and the permanent transaction mutex
(fd 9, closed, never `LOCK_UN`) are released is it written; every EXIT trap does the same, so later refusals and `platform_fail`
JSON lines are also written lock-free. Nothing is created before a lock is held, so a refusal at admission leaves `/tmp` untouched. Install/uninstall output legitimately stays inside their
transaction fence. Job-control stops (Ctrl-Z, TTIN, TTOU) are ignored from the
early block to exit; XON/XOFF is switched off on an output TTY (`stty` presence in the GL BusyBox build is UNVERIFIED-on-device; absence
is tolerated). Residual, documented, not solved: (a) SIGSTOP cannot be ignored: only another root process can send it to this
process (the admin's forced-command session cannot); it then holds whatever lock it holds until continued or killed; (b) stderr is
not buffered, and a refusal by admission or by the transaction gate itself (before the buffer exists, e.g. `transaction_contention`,
`explicit_install_recovery_required`) still writes
its one short stdout/stderr line while that lock is held (the trap
releases it right after; with `-ixon` and under 4 KiB of prior output this cannot block); (c) buffered stdout is lost if the process
is killed, if the tmp buffer write fails (ENOSPC), or if releasing the platform lock itself fails (`lock_owner_changed`/`lock_cleanup`). Ending the SSH session sends SIGHUP (and SIGCONT to an orphaned
stopped group; kernel job-control behaviour, not tested on the device), whose trap releases both locks. A stopped or dead recorded PID does not authorize lock removal. Interrupted-install recovery uses a complete authenticated external
`cfctl recover-install-lock`, then that source's single ordinary `uninstall.sh`, after separately approved inspection; see
[recovery](../runbooks/live-first-rehearsal.md#stale-install-lock-recovery). Live workers or ambiguous/legacy ownership refuse. A "stopped owner counts as dead" lock watchdog was evaluated and
rejected: it would break mutual exclusion when the owner is continued (two writers) and the fixture checkpoints that deliberately hold
the lock stopped.

Exit status: 2 for `invalid_command`, 1 for every other refusal, on both the early (`cfctl`, pre-admission) and the core path.

Refusal codes (JSON `{"ok":false,"errors":[code]}`): `invalid_command`, `scope_mac_not_canonical` (only lowercase colon form),
`scope_mac_invalid` (multicast/zero), `scope_forced_command_refused` (`CF_SERVICE_FORCED_COMMAND` set; `cfctl-ssh` now exports it to its
child), `scope_base_invalid`, `scope_tty_required`, `scope_confirmation_mismatch`, `scope_confirmation_required`, `scope_admin_invalid`,
`scope_unscoped_install`, `inactive_generation` (not ready+complete; a `ready` journal with no `complete` is an interrupted installation and is refused earlier by the M4b transaction gate as `platform_admission_refused`, stderr `incomplete_installation`), `installation_in_progress`, `locked`, `scope_base_conflict` (stale
`--base`), `scope_mac_is_ssh_client`, `scope_mac_protected`, `scope_no_evidence` (add only; remove works for an absent/rotated MAC),
`scope_mac_present`, `scope_full` (256), `scope_mac_absent`, `scope_mac_in_floor` (needs a fresh install + rebind), `scope_mac_in_use` (a
person record uses it), `scope_audit_unavailable`, `scope_mac_is_router_interface` (equals one of the router's own interface MACs,
`/sys/class/net/*/address`; preview prints a WARNING), `scope_router_interfaces_unreadable` (no interface, or an unreadable/malformed
address file: fail closed), `scope_state_unreadable` (the protected list or the floor could not be read while checking membership: fail
closed), plus the guard's `ssh_client_*` codes. The service host (CT107) has no router-side
configuration; it is refused because it MUST be protected (SAD-H1), never by a hardcoded address.

Per-admin wrapper `/usr/sbin/cfctl-scope <admin>` (`router/cfctl-scope`): `<admin>` is `[a-z]{1,16}` from its single argv (set by the
`command=` option); `SSH_ORIGINAL_COMMAND` must be exactly one of the three forms above (canonical MAC, 64 lowercase hex base, at most 128
bytes, tokens only); anything else exits 2 without running anything. It execs `env -i PATH LC_ALL SSH_CONNECTION SSH_CLIENT
CF_SCOPE_ADMIN=<admin> /usr/sbin/cfctl ...`; the admin name appears in both audit lines. It is installed like `cfctl-ssh`: copied from the
verified release (mode 755), journaled (`usr_sbin_cfctl-scope.*`, fresh installs only; older journals keep their inventory), drift-checked,
in sysupgrade.conf and `release.sha256`, removed on uninstall. Its CF_TEST_MODE fixture block (14 lines; marked private root under
`/tmp/couvre-feu-*`, canonical paths, and owned by the caller: root `700`, backend directory, marker and target not group/other-writable)
has the same marker as `cfctl-ssh`'s. M4's production copy MUST be generated WITHOUT the CF_TEST_MODE block for BOTH wrappers:
`tools/strip-test-mode.py OUTPUT cfctl-ssh` and `tools/strip-test-mode.py OUTPUT cfctl-scope` (prints the SHA-256 to disclose).

Trust limits (review S-L6/L-7): the `admin=` attribution is trustworthy only through `cfctl-scope`; a direct root login (Dropbear root
password login is enabled on the target) can set `CF_SCOPE_ADMIN` to any valid name. The TTY requirement and the typed confirmation are
typo guards, not authentication: the admin key (or root) is the gate. The intent line is refused if `logger` fails, but BusyBox `logger`
usually exits 0 even when logd is down and logd keeps a RAM ring buffer, so a router audit line is UNVERIFIED-on-device and may be lost; the
app-side database audit (`scope_requests`, `scope_changes`) is the real record. `scope-preview` marks STALE neighbour entries and IPv6
link-local-only rows as "weak evidence"; evidence is never a gate.

Operator procedure (each run is its own approved invocation; release id cited):
1. Read the address from the device's OWN Wi-Fi settings ("Fixed"/non-rotating private address). Never copy a MAC from the app: the app
   only shows `cfctl scope-add <ADDRESS FROM DEVICE SETTINGS> --base <router-read>` and never a paste-ready command.
2. From your own LAN computer, which is protected and has a fixed MAC, use your OWN admin key. Never use the service key, and never run this
   on or through CT107: `ssh -t router 'cfctl scope-preview <MAC>'`. Check the evidence, the address type and any WARNING. The evidence can be
   forged by a LAN host; it is not a gate. Never scope a router interface or infrastructure: Wi-Fi extenders in NAT mode, access points and
   other infrastructure belong in `--protect` at install time (`scope_mac_is_router_interface` catches only the router's own addresses).
3. `ssh -t router 'cfctl scope-add <MAC> --base <scopeSha from step 2>'`, then type the last 6 hex digits when asked. `-t` is required,
   because the confirm needs a TTY; the admin key line must allow a pty (unlike the service template's `restrict`).
4. Wait for the app to observe the new `scope`/`scopeSha`, then enroll in the UI. Rollback: unenroll in the UI, then `scope-remove`;
   a floor MAC needs a fresh install and rebind. Uninstall restores the original bytes whatever the scope became.

Admin key line (template; JD and Bryn each have their own key, both keys are passphrase-protected, never on CT107, no agent forwarding):
`command="/usr/sbin/cfctl-scope <admin>",no-port-forwarding,no-agent-forwarding,no-X11-forwarding <key-type> <PUBLIC_KEY_BLOB> <label>`.
UNVERIFIED on the target Dropbear: logging of the key fingerprint, and pty behaviour with a forced command (rehearsal GL1).
Rehearsal checklist additions (M1d review): (a) with logd stopped, does `logger` exit non-zero (is `scope_audit_unavailable` reachable on
the device)? Record the answer; until then the router audit line is UNVERIFIED-on-device; (b) is `stty` present, and does `ssh -t`
leave IXON off for the session; (c) Ctrl-Z / Ctrl-S during `scope-preview` and during the confirmation prompt leave `rpc-status` usable.
(d) every `/sys/class/net/*/address` on the GL device is readable and one line (a tunnel or cellular interface that is not
would make every scope-add refuse with `scope_router_interfaces_unreadable`, fail closed).

## Administrator install recovery boundary

`cfctl recover-install-lock` is administrator-only and rejects service forced-command
context. It is absent from the `cfctl-ssh` allow-list; M4b adds no service RPC verb,
argument grammar, shell privilege or scope-administration capability. It must run
from a complete independently authenticated external source, with fresh vendor
attestation where selected, even when the installed recovery copy is absent/partial.
It validates permanent kernel exclusion, boot/PID/starttime/token/mutex binding and
immutable PREPARED before publishing the durable recovery-required fence. Runtime
and fresh installation remain fenced until the single ordinary uninstaller retires
owned transaction state; the permanent mutex inode remains. Cron/firewall callbacks
use immutable generation-bound sources and reject stale generations. Ambiguous or
production legacy state refuses; historical fixture recovery is data-only. Operator
password login, full administrator shell/edit rights and PTY access remain available.
