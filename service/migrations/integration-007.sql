-- Ask-for-time: operations.action admits 'allow' (a router-side time allowance). Same rebuild pattern as integration-004:
-- foreign keys off, one transaction, foreign_key_check before commit; the table is renamed so child references keep pointing at it.
CREATE TABLE operations_next (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES accounts(id), person_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('pause','resume','enroll','unenroll','pause_all','resume_all','move','allow')), revision INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','confirmed','unknown','failed','conflict')),
 payload_json TEXT NOT NULL, base_json TEXT NOT NULL, request_json TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, error TEXT, confirmed_at INTEGER,
 UNIQUE(actor_id,idempotency_key)
) STRICT;
INSERT INTO operations_next(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error,confirmed_at)
 SELECT id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error,confirmed_at FROM operations;
DROP TABLE operations;
ALTER TABLE operations_next RENAME TO operations;
