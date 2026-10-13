-- Child time requests. A request link is a per-child capability; only the SHA-256 of its token is stored.
CREATE TABLE request_links (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
 created_by TEXT NOT NULL REFERENCES accounts(id), created_at INTEGER NOT NULL,
 revoked_at INTEGER, revoked_by TEXT REFERENCES accounts(id)
) STRICT;
-- At most one live link per child; issuing a new one revokes the previous one.
CREATE UNIQUE INDEX request_links_one_active ON request_links(person_id) WHERE revoked_at IS NULL;
CREATE TABLE time_requests (
 id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES request_links(id), person_id TEXT NOT NULL,
 minutes INTEGER NOT NULL CHECK(minutes IN (15,30,60)), reason TEXT NOT NULL CHECK(length(reason)<=140),
 state TEXT NOT NULL CHECK(state IN ('pending','approving','approved','declined','expired','unsupported','apply_failed','cancelled')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 decided_by TEXT REFERENCES accounts(id), decided_at INTEGER, granted_minutes INTEGER, allowance_until INTEGER, decision_code TEXT,
 attempts INTEGER NOT NULL DEFAULT 0,
 resume_operation_id TEXT, resume_revision INTEGER, original_pause_until INTEGER,
 repause_state TEXT NOT NULL DEFAULT 'none' CHECK(repause_state IN ('none','waiting','applying','not_needed','done','superseded')),
 repause_operation_id TEXT, repause_error TEXT,
 repause_failures INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER
) STRICT;
-- Server-side rate limit: a link can never hold more than one pending request.
CREATE UNIQUE INDEX time_requests_one_pending ON time_requests(link_id) WHERE state='pending';
CREATE INDEX time_requests_person ON time_requests(person_id, created_at);
