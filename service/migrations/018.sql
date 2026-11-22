-- Schedule allowances (roadmap item 2, S4): add two closed parent audit actions.
-- Copy existing rows and the AUTOINCREMENT sequence, then restore the indexes.
CREATE TABLE parent_audit_next (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 at INTEGER NOT NULL,
 actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
 action TEXT NOT NULL CHECK(action IN ('pause','resume','pause_all','resume_all','device_assign','device_move','device_remove','grant_approve','grant_decline','grant_end','reward_add','focus_start','owner_guard_refused','content_filter_set','content_filter_loosened','inventory_classify','inventory_undo','inventory_link','inventory_unlink','inventory_stable','schedule_set','schedule_loosened','schedule_extra_time','schedule_skip_tonight')),
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
