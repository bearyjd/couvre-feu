CREATE TABLE accounts (
 id TEXT PRIMARY KEY, display_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','parent')),
 person_ids TEXT NOT NULL, permission_version INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1,
 webauthn_user_id TEXT NOT NULL UNIQUE
) STRICT;
CREATE TABLE credentials (
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id),
 public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL
) STRICT;
CREATE TABLE bootstrap_tokens (
 hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE challenges (
 id TEXT PRIMARY KEY, challenge TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('register','login')),
 account_id TEXT REFERENCES accounts(id), account_version INTEGER, bootstrap_hash TEXT REFERENCES bootstrap_tokens(hash),
 credential_ids TEXT NOT NULL, browser_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE sessions (
 hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), csrf TEXT NOT NULL,
 permission_version INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE service_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), desired_json TEXT NOT NULL, highwater INTEGER NOT NULL,
 observation_json TEXT, observed_at INTEGER, last_confirmation_at INTEGER
) STRICT;
CREATE TABLE operations (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES accounts(id), person_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('pause','resume')), revision INTEGER NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN ('pending','confirmed','unknown','failed','conflict')),
 payload_json TEXT NOT NULL, base_json TEXT NOT NULL, request_json TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, error TEXT, confirmed_at INTEGER,
 UNIQUE(actor_id,idempotency_key)
) STRICT;
CREATE TABLE audit (
 id INTEGER PRIMARY KEY, actor_id TEXT NOT NULL, operation_id TEXT,
 action TEXT NOT NULL, revision INTEGER, timestamp INTEGER NOT NULL, outcome TEXT NOT NULL
) STRICT;
