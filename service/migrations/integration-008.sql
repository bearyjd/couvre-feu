-- Content filtering (PRP-006 A5): parent_alerts admits the `filter_drift` kind. Same rebuild as integration-006: ids and the AUTOINCREMENT
-- high-water mark are kept, so an old id is never reused; the indexes are recreated.
ALTER TABLE parent_alerts RENAME TO parent_alerts_v2;
CREATE TABLE parent_alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 person_id TEXT,
 kind TEXT NOT NULL CHECK(kind IN ('enforcement_unhealthy','sync_failed','apply_pending_too_long','possible_bypass','repeated_blocked_attempts','time_request_pending','router_scope_change','new_device','inventory_stalled','filter_drift')),
 severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
 created_at INTEGER NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 count INTEGER NOT NULL CHECK(count >= 1),
 state TEXT NOT NULL CHECK(state IN ('open','acknowledged','resolved')),
 acknowledged_at INTEGER, acknowledged_by TEXT, resolved_at INTEGER,
 details TEXT NOT NULL CHECK(json_valid(details) AND length(details) <= 1024)
) STRICT;
INSERT INTO parent_alerts(id,person_id,kind,severity,created_at,first_seen,last_seen,count,state,acknowledged_at,acknowledged_by,resolved_at,details)
 SELECT id,person_id,kind,severity,created_at,first_seen,last_seen,count,state,acknowledged_at,acknowledged_by,resolved_at,details FROM parent_alerts_v2;
DELETE FROM sqlite_sequence WHERE name='parent_alerts';
INSERT INTO sqlite_sequence(name,seq) SELECT 'parent_alerts',seq FROM sqlite_sequence WHERE name='parent_alerts_v2';
DROP TABLE parent_alerts_v2;
CREATE UNIQUE INDEX parent_alerts_unresolved ON parent_alerts(kind, COALESCE(person_id, '')) WHERE state IN ('open','acknowledged');
CREATE INDEX parent_alerts_person ON parent_alerts(person_id, id);
