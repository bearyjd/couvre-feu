-- Inventory decisions (UI plan D): parent_audit.action admits 'inventory_classify', 'inventory_undo', 'inventory_link', 'inventory_unlink' and 'inventory_stable'
-- (action types only; the row id travels in operation_id as 'inventory_row:<id>', never a MAC, hostname, vendor or label).
-- ONE-WAY: CHECK constraints cannot be altered, so the table is rebuilt exactly as in 014 (nothing references it); rows and ids are carried over unchanged,
-- but the previous binary refuses a database at this user_version (docs/service-contract.md, Integration admin inventory).
CREATE TABLE parent_audit_next (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 at INTEGER NOT NULL,
 actor_id TEXT NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 64),
 action TEXT NOT NULL CHECK(action IN ('pause','resume','pause_all','resume_all','device_assign','device_move','device_remove','grant_approve','grant_decline','grant_end','reward_add','focus_start','owner_guard_refused','content_filter_set','content_filter_loosened','inventory_classify','inventory_undo','inventory_link','inventory_unlink','inventory_stable')),
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

-- Parent decisions about inventory rows. They are bound to the row's NATURAL key (generation, mac), never to its implicit rowid: inventory_devices has no
-- INTEGER PRIMARY KEY, so a table rebuild, .recover or a delete can renumber rowids, and a rowid-keyed decision would then attach to a different device.
-- The foreign key makes the binding structural (a decision goes with its row). It is declared against a table that integration-006 creates later (SQLite
-- resolves it lazily): this numbered migration also runs on demo databases, where inventory_decisions simply stays empty.
-- The row id (rowid) stays the route/audit identifier and is only ever resolved through this key (InventoryStore joins on it). A link names the older row
-- by its mac in the same generation. The label is free text a parent typed (at most 40 characters): read only by the admin inventory DTO, never copied
-- to audit rows, alerts or logs.
CREATE TABLE inventory_decisions (
 generation TEXT NOT NULL CHECK(length(generation)=64),
 mac TEXT NOT NULL CHECK(length(mac)=17),
 role TEXT NOT NULL CHECK(role IN ('new','kid','adult','infrastructure','home','guest','ignored')),
 label TEXT CHECK(label IS NULL OR length(label) BETWEEN 1 AND 40),
 previous_role TEXT CHECK(previous_role IS NULL OR previous_role IN ('new','kid','adult','infrastructure','home','guest','ignored')),
 linked_from_mac TEXT CHECK(linked_from_mac IS NULL OR (length(linked_from_mac)=17 AND linked_from_mac <> mac)),
 stable_confirmed INTEGER NOT NULL DEFAULT 0 CHECK(stable_confirmed IN (0,1)),
 stable_at INTEGER,
 decided_by TEXT NOT NULL CHECK(length(decided_by) BETWEEN 1 AND 64),
 decided_at INTEGER NOT NULL,
 PRIMARY KEY(generation, mac),
 FOREIGN KEY(generation, mac) REFERENCES inventory_devices(generation, mac) ON DELETE CASCADE,
 CHECK(stable_confirmed = 0 OR stable_at IS NOT NULL)
) STRICT;
CREATE INDEX inventory_decisions_linked ON inventory_decisions(generation, linked_from_mac) WHERE linked_from_mac IS NOT NULL;
