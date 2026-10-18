-- Widen operations.action for device enrollment changes. SQLite cannot alter a CHECK, so the table is rebuilt.
-- operations is a parent table (integration_state, operation_rpc, dispatch_steps reference it): IntegrationStore runs this
-- with foreign keys off, in one transaction, and checks foreign_key_check before commit. The new table is created under
-- a temporary name and renamed, so existing child references keep pointing at "operations". Revision stays non-unique.
CREATE TABLE operations_next (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES accounts(id), person_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('pause','resume','enroll','unenroll')), revision INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','confirmed','unknown','failed','conflict')),
 payload_json TEXT NOT NULL, base_json TEXT NOT NULL, request_json TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, error TEXT, confirmed_at INTEGER,
 UNIQUE(actor_id,idempotency_key)
) STRICT;
INSERT INTO operations_next SELECT * FROM operations;
DROP TABLE operations;
ALTER TABLE operations_next RENAME TO operations;
