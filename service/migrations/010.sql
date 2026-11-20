-- Audit log of parent actions (F2). Ids and enums only: no free text, domains, URLs, MACs, addresses, hostnames or child reason text.
-- Written only when the private manifest sets auditLog.enabled; pruned after 90 days by the service.
CREATE TABLE parent_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 at INTEGER NOT NULL,
 actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
 action TEXT NOT NULL CHECK(action IN ('pause','resume','pause_all','resume_all','device_assign','device_move','device_remove','grant_approve','grant_decline','grant_end')),
 person_id TEXT CHECK(person_id IS NULL OR length(person_id) BETWEEN 1 AND 64),
 operation_id TEXT CHECK(operation_id IS NULL OR length(operation_id) BETWEEN 1 AND 64),
 result TEXT NOT NULL CHECK(result IN ('applied','failed','refused'))
) STRICT;
CREATE INDEX parent_audit_person ON parent_audit(person_id,id);
CREATE INDEX parent_audit_at ON parent_audit(at);
-- A replayed request (same operation) is one entry, not two.
CREATE UNIQUE INDEX parent_audit_once ON parent_audit(operation_id,action,person_id,result) WHERE operation_id IS NOT NULL AND person_id IS NOT NULL;
