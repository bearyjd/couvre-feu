-- M2b: a device that is moving between children. devices gains state 'moving' and move_to (the target child); the row keeps its
-- source person_id and its UNIQUE(identifier_kind,identifier) until an OBSERVATION shows the MAC under the target. Nothing references
-- devices, so the rebuild is table-local; the name swap keeps the existing people reference. M2c's integration tables follow as 006.
CREATE TABLE devices_next (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES people(id),
 label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
 identifier_kind TEXT NOT NULL CHECK(identifier_kind IN ('mac')), identifier TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('enrolling','active','removing','moving')), operation_id TEXT, created_at INTEGER NOT NULL,
 move_to TEXT REFERENCES people(id),
 UNIQUE(identifier_kind,identifier),
 CHECK((state='moving')=(move_to IS NOT NULL))
) STRICT;
INSERT INTO devices_next(id,person_id,label,identifier_kind,identifier,state,operation_id,created_at)
 SELECT id,person_id,label,identifier_kind,identifier,state,operation_id,created_at FROM devices;
DROP TABLE devices;
ALTER TABLE devices_next RENAME TO devices;
CREATE INDEX devices_person ON devices(person_id);
