-- M2c: network inventory. Applied in one transaction by IntegrationStore (marker: dispatch_steps sql contains 'inventory').
-- The inventory objects are IF NOT EXISTS so a database whose dispatch_steps is rebuilt again (e.g. by 002) can safely re-run this file.
-- 1. dispatch_steps admits the read-only `inventory` permit kind (the 002 RENAME-to-_v1 pattern; nothing references dispatch_steps).
ALTER TABLE dispatch_steps RENAME TO dispatch_steps_v1;
CREATE TABLE dispatch_steps (
 batch_id TEXT NOT NULL REFERENCES dispatch_batches(id), ordinal INTEGER NOT NULL CHECK(ordinal=1),
 operation_id TEXT REFERENCES operations(id), kind TEXT NOT NULL CHECK(kind IN ('observe','apply','receipt','activity','inventory')),
 request_digest TEXT NOT NULL, argv_json TEXT NOT NULL, stdin_text TEXT NOT NULL,
 deadline_ms INTEGER NOT NULL CHECK(deadline_ms BETWEEN 1000 AND 30000),
 state TEXT NOT NULL CHECK(state IN ('consumed','resolved','uncertain','revoked')),
 claim_token TEXT NOT NULL, lease_until INTEGER NOT NULL,
 PRIMARY KEY(batch_id,ordinal)
) STRICT;
INSERT INTO dispatch_steps(batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until)
 SELECT batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until FROM dispatch_steps_v1;
DROP TABLE dispatch_steps_v1;
CREATE INDEX dispatch_live_claims ON dispatch_steps(state,lease_until);

-- 2. parent_alerts admits the `new_device` kind. Ids and the AUTOINCREMENT high-water mark are kept, so an old id is never reused.
ALTER TABLE parent_alerts RENAME TO parent_alerts_v1;
CREATE TABLE parent_alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 person_id TEXT,
 kind TEXT NOT NULL CHECK(kind IN ('enforcement_unhealthy','sync_failed','apply_pending_too_long','possible_bypass','repeated_blocked_attempts','time_request_pending','router_scope_change','new_device')),
 severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
 created_at INTEGER NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 count INTEGER NOT NULL CHECK(count >= 1),
 state TEXT NOT NULL CHECK(state IN ('open','acknowledged','resolved')),
 acknowledged_at INTEGER, acknowledged_by TEXT, resolved_at INTEGER,
 details TEXT NOT NULL CHECK(json_valid(details) AND length(details) <= 1024)
) STRICT;
INSERT INTO parent_alerts(id,person_id,kind,severity,created_at,first_seen,last_seen,count,state,acknowledged_at,acknowledged_by,resolved_at,details)
 SELECT id,person_id,kind,severity,created_at,first_seen,last_seen,count,state,acknowledged_at,acknowledged_by,resolved_at,details FROM parent_alerts_v1;
DELETE FROM sqlite_sequence WHERE name='parent_alerts';
INSERT INTO sqlite_sequence(name,seq) SELECT 'parent_alerts',seq FROM sqlite_sequence WHERE name='parent_alerts_v1';
DROP TABLE parent_alerts_v1;
CREATE UNIQUE INDEX parent_alerts_unresolved ON parent_alerts(kind, COALESCE(person_id, '')) WHERE state IN ('open','acknowledged');
CREATE INDEX parent_alerts_person ON parent_alerts(person_id, id);

-- 3. Inventory snapshot, scoped by generation. last_seen advances only for source neigh or both; alerted_at is when a "New" device was
-- last counted in an alert (NULL = not yet alerted, so a device whose alert was coalesced away still alerts on a later complete poll).
CREATE TABLE IF NOT EXISTS inventory_devices (
 generation TEXT NOT NULL CHECK(length(generation)=64),
 mac TEXT NOT NULL CHECK(length(mac)=17 AND mac GLOB '[0-9a-f][0-9a-f]:*'),
 ipv4_json TEXT NOT NULL CHECK(json_valid(ipv4_json) AND json_type(ipv4_json)='array' AND json_array_length(ipv4_json)<=4),
 hostname TEXT CHECK(hostname IS NULL OR (length(hostname) BETWEEN 1 AND 63 AND hostname GLOB '[A-Za-z0-9]*' AND hostname NOT GLOB '*[^A-Za-z0-9._-]*')),
 source TEXT NOT NULL CHECK(source IN ('lease','neigh','both')),
 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 acknowledged_at INTEGER, acknowledged_by TEXT REFERENCES accounts(id),
 alerted_at INTEGER,
 PRIMARY KEY(generation,mac)) STRICT;
CREATE INDEX IF NOT EXISTS inventory_devices_last_seen ON inventory_devices(last_seen);
-- Row cap 1024 per generation.
CREATE TRIGGER IF NOT EXISTS inventory_devices_cap BEFORE INSERT ON inventory_devices
 WHEN (SELECT count(*) FROM inventory_devices WHERE generation=NEW.generation) >= 1024
 BEGIN SELECT RAISE(ABORT,'inventory_row_cap'); END;

-- 4. Inventory state singleton. The alert counters are global: all admins share one system alert row.
CREATE TABLE IF NOT EXISTS inventory_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 generation TEXT, baseline_at INTEGER, last_ok_at INTEGER, last_attempt_at INTEGER, last_error TEXT, refresh_requested_at INTEGER,
 refresh_pending INTEGER NOT NULL DEFAULT 0 CHECK(refresh_pending IN (0,1)),
 alert_day_start INTEGER, alert_day_count INTEGER NOT NULL DEFAULT 0, last_alert_at INTEGER) STRICT;
