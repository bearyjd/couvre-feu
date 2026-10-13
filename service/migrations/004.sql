CREATE TABLE parent_alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 person_id TEXT,
 kind TEXT NOT NULL CHECK(kind IN ('enforcement_unhealthy','sync_failed','apply_pending_too_long','possible_bypass','repeated_blocked_attempts','time_request_pending')),
 severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
 created_at INTEGER NOT NULL,
 first_seen INTEGER NOT NULL,
 last_seen INTEGER NOT NULL,
 count INTEGER NOT NULL CHECK(count >= 1),
 state TEXT NOT NULL CHECK(state IN ('open','acknowledged','resolved')),
 acknowledged_at INTEGER,
 acknowledged_by TEXT,
 resolved_at INTEGER,
 details TEXT NOT NULL CHECK(json_valid(details) AND length(details) <= 1024)
) STRICT;
-- One unresolved alert per (kind, person); NULL person is the system scope.
CREATE UNIQUE INDEX parent_alerts_unresolved ON parent_alerts(kind, COALESCE(person_id, '')) WHERE state IN ('open','acknowledged');
CREATE INDEX parent_alerts_person ON parent_alerts(person_id, id);
