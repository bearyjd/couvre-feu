-- Schedule edits are durable operations too. SQLite cannot alter a CHECK, so rebuild the (child-free) demo table.
CREATE TABLE operations_next (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES accounts(id), person_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('pause','resume','schedule_create','schedule_update','schedule_delete')), revision INTEGER NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN ('pending','confirmed','unknown','failed','conflict')),
 payload_json TEXT NOT NULL, base_json TEXT NOT NULL, request_json TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, error TEXT, confirmed_at INTEGER,
 UNIQUE(actor_id,idempotency_key)
) STRICT;
INSERT INTO operations_next SELECT * FROM operations;
DROP TABLE operations;
ALTER TABLE operations_next RENAME TO operations;
