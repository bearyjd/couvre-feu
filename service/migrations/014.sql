-- Content filtering (PRP-006 A3): parent_audit.action admits 'content_filter_set' and 'content_filter_loosened' (action types only: no ids, no domains).
-- CHECK constraints cannot be altered, so the table is rebuilt exactly as in 013 (nothing references it); rows and ids are carried over unchanged.
CREATE TABLE parent_audit_next (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 at INTEGER NOT NULL,
 actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
 action TEXT NOT NULL CHECK(action IN ('pause','resume','pause_all','resume_all','device_assign','device_move','device_remove','grant_approve','grant_decline','grant_end','reward_add','focus_start','owner_guard_refused','content_filter_set','content_filter_loosened')),
 person_id TEXT CHECK(person_id IS NULL OR length(person_id) BETWEEN 1 AND 64),
 operation_id TEXT CHECK(operation_id IS NULL OR length(operation_id) BETWEEN 1 AND 64),
 result TEXT NOT NULL CHECK(result IN ('applied','failed','refused'))
) STRICT;
INSERT INTO parent_audit_next(id,at,actor_id,action,person_id,operation_id,result) SELECT id,at,actor_id,action,person_id,operation_id,result FROM parent_audit;
-- AUTOINCREMENT never reuses an id: carry the old counter onto the new table's sqlite_sequence row (see 013).
DELETE FROM sqlite_sequence WHERE name='parent_audit_next';
INSERT INTO sqlite_sequence(name,seq) SELECT 'parent_audit_next',seq FROM sqlite_sequence WHERE name='parent_audit';
DROP TABLE parent_audit;
ALTER TABLE parent_audit_next RENAME TO parent_audit;
CREATE INDEX parent_audit_person ON parent_audit(person_id,id);
CREATE INDEX parent_audit_at ON parent_audit(at);
CREATE UNIQUE INDEX parent_audit_once ON parent_audit(operation_id,action,person_id,result) WHERE operation_id IS NOT NULL AND person_id IS NOT NULL;

-- The parent-configured desired filter per child. desired_json holds parent-chosen domains (applying them needs them): they are read only by the
-- filter routes and the reconciler, and are never copied to audit rows, logs, alerts or error text. 'applied' needs the read-back hash to equal the desired hash.
CREATE TABLE content_filter_desired (
 person_id TEXT PRIMARY KEY CHECK(length(person_id) BETWEEN 1 AND 64),
 revision INTEGER NOT NULL CHECK(revision >= 1),
 desired_json TEXT NOT NULL CHECK(length(desired_json) <= 262144),
 desired_sha256 TEXT NOT NULL CHECK(length(desired_sha256) = 64),
 state TEXT NOT NULL CHECK(state IN ('applied','pending','not_confirmed','drift')),
 applied_sha256 TEXT CHECK(applied_sha256 IS NULL OR length(applied_sha256) = 64),
 state_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 updated_by TEXT NOT NULL CHECK(length(updated_by) BETWEEN 1 AND 64),
 CHECK(state <> 'applied' OR (applied_sha256 IS NOT NULL AND applied_sha256 = desired_sha256))
) STRICT;
