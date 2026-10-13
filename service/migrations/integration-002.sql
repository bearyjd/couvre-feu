-- Widen dispatch_steps.kind to admit the read-only 'activity' permit type. Applied inside one transaction by IntegrationStore.
ALTER TABLE dispatch_steps RENAME TO dispatch_steps_v1;
CREATE TABLE dispatch_steps (
 batch_id TEXT NOT NULL REFERENCES dispatch_batches(id), ordinal INTEGER NOT NULL CHECK(ordinal=1),
 operation_id TEXT REFERENCES operations(id), kind TEXT NOT NULL CHECK(kind IN ('observe','apply','receipt','activity')),
 request_digest TEXT NOT NULL, argv_json TEXT NOT NULL, stdin_text TEXT NOT NULL,
 deadline_ms INTEGER NOT NULL CHECK(deadline_ms BETWEEN 1000 AND 30000),
 state TEXT NOT NULL CHECK(state IN ('consumed','resolved','uncertain','revoked')),
 claim_token TEXT NOT NULL, lease_until INTEGER NOT NULL,
 PRIMARY KEY(batch_id,ordinal)
) STRICT;
INSERT INTO dispatch_steps(batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until)
 SELECT batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until FROM dispatch_steps_v1;
DROP TABLE dispatch_steps_v1;
CREATE INDEX dispatch_live_claims ON dispatch_steps(state,lease_until);
