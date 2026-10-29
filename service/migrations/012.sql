-- Focus window (F5): parent_audit.action admits 'focus_start'. CHECK constraints cannot be altered, so the table is rebuilt (nothing references it).
-- Ids and enums only, exactly as in 010 and 011; rows and ids are carried over unchanged.
CREATE TABLE parent_audit_next (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 at INTEGER NOT NULL,
 actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
 action TEXT NOT NULL CHECK(action IN ('pause','resume','pause_all','resume_all','device_assign','device_move','device_remove','grant_approve','grant_decline','grant_end','reward_add','focus_start')),
 person_id TEXT CHECK(person_id IS NULL OR length(person_id) BETWEEN 1 AND 64),
 operation_id TEXT CHECK(operation_id IS NULL OR length(operation_id) BETWEEN 1 AND 64),
 result TEXT NOT NULL CHECK(result IN ('applied','failed','refused'))
) STRICT;
INSERT INTO parent_audit_next(id,at,actor_id,action,person_id,operation_id,result) SELECT id,at,actor_id,action,person_id,operation_id,result FROM parent_audit;
-- AUTOINCREMENT never reuses an id, so pruned ids must stay retired (an /audit/before/:id cursor must not land on a different row):
-- copy the old counter (>= max(id)) onto the new table's sqlite_sequence row; the rename below moves that row to the final name.
DELETE FROM sqlite_sequence WHERE name='parent_audit_next';
INSERT INTO sqlite_sequence(name,seq) SELECT 'parent_audit_next',seq FROM sqlite_sequence WHERE name='parent_audit';
DROP TABLE parent_audit;
ALTER TABLE parent_audit_next RENAME TO parent_audit;
CREATE INDEX parent_audit_person ON parent_audit(person_id,id);
CREATE INDEX parent_audit_at ON parent_audit(at);
CREATE UNIQUE INDEX parent_audit_once ON parent_audit(operation_id,action,person_id,result) WHERE operation_id IS NOT NULL AND person_id IS NOT NULL;
