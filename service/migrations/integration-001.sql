CREATE TABLE integration_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), mode TEXT NOT NULL CHECK(mode='integration'),
 schema_version INTEGER NOT NULL CHECK(schema_version=1), target_digest TEXT NOT NULL, manifest_digest TEXT NOT NULL,
 generation TEXT NOT NULL, dispatch_epoch INTEGER NOT NULL DEFAULT 0 CHECK(dispatch_epoch>=0),
 dispatch_stopped INTEGER NOT NULL DEFAULT 1 CHECK(dispatch_stopped IN (0,1)),
 active_operation_id TEXT REFERENCES operations(id), observation_sequence INTEGER NOT NULL DEFAULT 0 CHECK(observation_sequence>=0),
 observation_error TEXT
) STRICT;
CREATE TABLE operation_rpc (
 operation_id TEXT PRIMARY KEY REFERENCES operations(id), generation TEXT NOT NULL, base_digest TEXT NOT NULL,
 request_digest TEXT NOT NULL, envelope_json TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('queued','claimed','uncertain','resolved')),
 claim_token TEXT, claim_epoch INTEGER, lease_until INTEGER,
 attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 1),
 delivery TEXT NOT NULL DEFAULT 'not_dispatched' CHECK(delivery IN ('not_dispatched','possible','accepted','not_delivered')),
 receipt_json TEXT
) STRICT;
CREATE TABLE dispatch_batches (
 id TEXT PRIMARY KEY, script_sha256 TEXT NOT NULL UNIQUE, target_digest TEXT NOT NULL, generation TEXT NOT NULL,
 dispatch_epoch INTEGER NOT NULL CHECK(dispatch_epoch>=0), approved_at INTEGER NOT NULL CHECK(approved_at>=0),
 expires_at INTEGER NOT NULL CHECK(expires_at>=approved_at),
 state TEXT NOT NULL CHECK(state IN ('running','spent','revoked'))
) STRICT;
CREATE TABLE dispatch_steps (
 batch_id TEXT NOT NULL REFERENCES dispatch_batches(id), ordinal INTEGER NOT NULL CHECK(ordinal=1),
 operation_id TEXT REFERENCES operations(id), kind TEXT NOT NULL CHECK(kind IN ('observe','apply','receipt')),
 request_digest TEXT NOT NULL, argv_json TEXT NOT NULL, stdin_text TEXT NOT NULL,
 deadline_ms INTEGER NOT NULL CHECK(deadline_ms BETWEEN 1000 AND 30000),
 state TEXT NOT NULL CHECK(state IN ('consumed','resolved','uncertain','revoked')),
 claim_token TEXT NOT NULL, lease_until INTEGER NOT NULL,
 PRIMARY KEY(batch_id,ordinal)
) STRICT;
