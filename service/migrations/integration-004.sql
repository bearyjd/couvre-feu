-- M2a: router scope tracking, and the operation shapes that bulk/move (M2b) will need. One forward-only step.
-- operations is a parent table (integration_state, operation_rpc, dispatch_steps reference it): IntegrationStore runs this
-- with foreign keys off, in one transaction, and checks foreign_key_check before commit. As in integration-003 the new table
-- is created under a temporary name and renamed, so existing child references keep pointing at "operations".
CREATE TABLE operations_next (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES accounts(id), person_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('pause','resume','enroll','unenroll','pause_all','resume_all','move')), revision INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','confirmed','unknown','failed','conflict')),
 payload_json TEXT NOT NULL, base_json TEXT NOT NULL, request_json TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, error TEXT, confirmed_at INTEGER,
 UNIQUE(actor_id,idempotency_key)
) STRICT;
INSERT INTO operations_next(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error,confirmed_at)
 SELECT id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error,confirmed_at FROM operations;
DROP TABLE operations;
ALTER TABLE operations_next RENAME TO operations;

-- The authority for which children a multi-child operation touches (operations.person_id is only a representative).
CREATE TABLE operation_people (
 operation_id TEXT NOT NULL REFERENCES operations(id), person_id TEXT NOT NULL REFERENCES people(id),
 PRIMARY KEY(operation_id,person_id)
) STRICT;

-- Who asked for a device to be added to the router scope, when, and the router scope digests around it. Rows stay after resolution.
CREATE TABLE scope_requests (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES people(id),
 mac TEXT NOT NULL CHECK(length(mac)=17 AND mac GLOB '[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]'),
 requested_by TEXT NOT NULL REFERENCES accounts(id),
 state TEXT NOT NULL CHECK(state IN ('pending','observed','expired','cancelled')),
 scope_sha_before TEXT CHECK(scope_sha_before IS NULL OR (length(scope_sha_before)=64 AND scope_sha_before NOT GLOB '*[^0-9a-f]*')),
 scope_sha_after TEXT CHECK(scope_sha_after IS NULL OR (length(scope_sha_after)=64 AND scope_sha_after NOT GLOB '*[^0-9a-f]*')),
 generation TEXT NOT NULL, created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+604800),
 resolved_at INTEGER, resolved_by TEXT REFERENCES accounts(id)
) STRICT;
CREATE UNIQUE INDEX scope_requests_pending ON scope_requests(mac,generation) WHERE state='pending';
CREATE INDEX scope_requests_person ON scope_requests(person_id,state);

-- Last router scope seen (with its list, to compute growth and removal), so a change made while the service was down is still recorded.
CREATE TABLE router_scope_observed (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation TEXT NOT NULL,
 scope_sha TEXT NOT NULL CHECK(length(scope_sha)=64 AND scope_sha NOT GLOB '*[^0-9a-f]*'),
 scope_json TEXT NOT NULL CHECK(json_valid(scope_json) AND json_array_length(scope_json) BETWEEN 1 AND 256),
 observed_at INTEGER NOT NULL
) STRICT;
-- matched_request_id NULL means unmatched growth or removal: alertable.
CREATE TABLE scope_changes (
 id INTEGER PRIMARY KEY, observed_at INTEGER NOT NULL, sha_before TEXT, sha_after TEXT NOT NULL,
 added_json TEXT NOT NULL CHECK(json_valid(added_json)), removed_json TEXT NOT NULL CHECK(json_valid(removed_json)),
 matched_request_id TEXT REFERENCES scope_requests(id)
) STRICT;

-- ParentAlerts storage for integration databases (the demo chain has it in 004.sql; the integration chain skips that file).
-- Same shape plus the router_scope_change kind.
CREATE TABLE parent_alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 person_id TEXT,
 kind TEXT NOT NULL CHECK(kind IN ('enforcement_unhealthy','sync_failed','apply_pending_too_long','possible_bypass','repeated_blocked_attempts','time_request_pending','router_scope_change')),
 severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
 created_at INTEGER NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 count INTEGER NOT NULL CHECK(count >= 1),
 state TEXT NOT NULL CHECK(state IN ('open','acknowledged','resolved')),
 acknowledged_at INTEGER, acknowledged_by TEXT, resolved_at INTEGER,
 details TEXT NOT NULL CHECK(json_valid(details) AND length(details) <= 1024)
) STRICT;
CREATE UNIQUE INDEX parent_alerts_unresolved ON parent_alerts(kind, COALESCE(person_id, '')) WHERE state IN ('open','acknowledged');
CREATE INDEX parent_alerts_person ON parent_alerts(person_id, id);
