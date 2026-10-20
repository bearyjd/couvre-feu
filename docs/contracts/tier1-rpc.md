# Tier-1 RPC and schema contracts (DRAFT)

Status: DRAFT, nothing here is implemented. It lets router (R) and service (S) work proceed in parallel. Router-side
validation and service-side parsing must both reject anything outside these bounds. All MACs below are fictional.

## 1. rpc-status: optional scope fields

`rpc-status` (`router/lib/rpc.sh`) gains two optional top-level fields, added in one change on both sides
(`shared/src/router-rpc.ts` `normalizeObservation` uses a strict `object()`, so an unknown key is rejected today).

| field | type | rule |
|---|---|---|
| `scope` | string[] | canonical lowercase colon MACs, unique, strictly ascending (`LC_ALL=C`), 1..256 entries |
| `scopeSha` | string | 64 lowercase hex, SHA-256 of the exact snapshot bytes the router validated |

Rules for the service parser:
- Absent `scope` means the manifest floor, never "unbounded".
- `scope` must contain the floor, be disjoint from `protectedMacs`, and contain every MAC in `acceptedPolicy`.
- `scope` and `scopeSha` appear together or not at all.
- The snapshot is taken once per call from `rpc-allowed` (private runtime dir); status and the strict validation read the
  same bytes, so `scopeSha` describes what was checked.

## 2. rpc-inventory v1 (read-only)

Output of `cfctl-ssh rpc-inventory`, one JSON object, strict keys, no unknown fields:

```
{"inventory_version":1,"generation":"<router generation>","routerTime":<int>,
 "devices":[{"mac":"02:00:00:00:00:01","addresses":["192.0.2.10"],"hostname":"host-a"|null,
             "source":"lease"|"neigh"|"both","leaseExpires":<int>|null}],
 "protectedCount":<int>,"truncated":<bool>}
```

| field | bound |
|---|---|
| `devices` | <= 256 entries, canonical unicast MACs, unique, ascending |
| `addresses` | <= 8 per device, valid IPv4/IPv6 text |
| `hostname` | <= 63 chars, `[A-Za-z0-9._-]`, or `null` |
| `source` | one of `lease`, `neigh`, `both` |
| whole reply | < 131072 bytes (the existing stdout cap); over-limit sets `truncated:true` rather than growing |

Protected management MACs are never listed; only their count is exposed (`protectedCount`). The reader is new: the lease
parse in `core.sh` drops the hostname field and `cf_addresses` filters to kids and protected devices.

### Old routers

A router without the command answers either `{"errors":["invalid_command"]}` with exit 2 (new `cfctl-ssh`, old `cfctl`),
or empty output with exit 2 (old `cfctl-ssh` that rejects the argv). Both map to the service state
`inventory_unavailable`. Neither is a transport failure, neither triggers dispatch backoff, and neither affects policy
observation or operations.

## 3. Receipt semantics the service relies on

A `null` receipt for the service's own attempted operation is "unknown" (`receipt_missing_remote_outcome_unknown`), not
success and not failed, unless the router's own pre-write refusal is proven (`service/src/integration-worker.ts`
`refusedBeforeWrite`). The router will evict the oldest receipt beyond 128, so absence can no longer imply "never applied".

## 4. integration-004 DDL (DRAFT)

One forward-only migration owns all Tier-1 schema (plan D1), applied by `IntegrationStore` after integration-003 using the
same detect-by-`sqlite_master` pattern and `PRAGMA foreign_keys=OFF` + `foreign_key_check` for the `operations` rebuild.
Conventions followed: `STRICT` tables, `CHECK` enums, integer epoch seconds, text ids.

```sql
-- 1. operations.action: add pause_all, resume_all, move (rebuild like integration-003; columns unchanged).
CREATE TABLE operations_next (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES accounts(id), person_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('pause','resume','enroll','unenroll','pause_all','resume_all','move')),
 revision INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','confirmed','unknown','failed','conflict')),
 payload_json TEXT NOT NULL, base_json TEXT NOT NULL, request_json TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, error TEXT, confirmed_at INTEGER,
 UNIQUE(actor_id,idempotency_key)
) STRICT;
INSERT INTO operations_next SELECT * FROM operations;
DROP TABLE operations;
ALTER TABLE operations_next RENAME TO operations;

-- 2. Multi-person operations (pause_all/resume_all/move): person_id above holds a representative or '*'.
CREATE TABLE operation_people (
 operation_id TEXT NOT NULL REFERENCES operations(id), person_id TEXT NOT NULL,
 PRIMARY KEY(operation_id,person_id)
) STRICT;

-- 3. dispatch_steps.kind: add 'inventory' (rebuild like integration-002, copy rows, recreate dispatch_live_claims).
--    kind CHECK becomes IN ('observe','apply','receipt','activity','inventory').

-- 4. Pending router-scope requests raised when a device is outside the router scope.
CREATE TABLE scope_requests (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES people(id),
 mac TEXT NOT NULL, requested_by TEXT NOT NULL REFERENCES accounts(id),
 state TEXT NOT NULL CHECK(state IN ('pending','observed','expired','cancelled')),
 scope_sha_before TEXT CHECK(scope_sha_before IS NULL OR length(scope_sha_before)=64),
 scope_sha_after TEXT CHECK(scope_sha_after IS NULL OR length(scope_sha_after)=64),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
 UNIQUE(person_id,mac)
) STRICT;
CREATE INDEX scope_requests_person ON scope_requests(person_id,state);
-- Application rules: at most 4 pending per child; expiry 7 days; MAC canonical unicast.

-- 5. Last inventory snapshot (silent baseline on first successful poll).
CREATE TABLE inventory_devices (
 mac TEXT PRIMARY KEY, addresses_json TEXT NOT NULL, hostname TEXT,
 source TEXT NOT NULL CHECK(source IN ('lease','neigh','both')), lease_expires INTEGER,
 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1))
) STRICT;
```

Open points: the exact `person_id` value for multi-person operations, and whether `acknowledged` belongs in
`inventory_devices` or an audit-only record, are decided in M2a/M2c.
