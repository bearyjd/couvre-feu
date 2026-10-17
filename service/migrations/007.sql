-- Design 008 PR-B: many passkeys per account, approval-pending devices, per-passkey sessions, add-device tokens, step-up.
-- No table references credentials, so it is rebuilt without UNIQUE(account_id). Existing passkeys stay active.
CREATE TABLE credentials_next (
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL,
 label TEXT NOT NULL DEFAULT '' CHECK(length(label)<=64),
 state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','pending')),
 created_at INTEGER NOT NULL DEFAULT 0, last_used_at INTEGER
) STRICT;
INSERT INTO credentials_next(id,account_id,public_key,counter,transports) SELECT id,account_id,public_key,counter,transports FROM credentials;
DROP TABLE credentials;
ALTER TABLE credentials_next RENAME TO credentials;
CREATE INDEX credentials_account ON credentials(account_id);
-- Revoking one passkey ends exactly the sessions it created. No FK: a revoked passkey row is deleted.
ALTER TABLE sessions ADD COLUMN credential_id TEXT;
-- Before 007 an account held at most one passkey, so every existing session came from that passkey.
UPDATE sessions SET credential_id=(SELECT id FROM credentials WHERE credentials.account_id=sessions.account_id);
-- A session that no passkey can account for could never be ended by passkey removal.
UPDATE sessions SET revoked=1 WHERE credential_id IS NULL;
-- 'bootstrap' (operator CLI) yields an active passkey; 'add_device' (admin UI) yields a pending one that an admin must approve.
ALTER TABLE bootstrap_tokens ADD COLUMN purpose TEXT NOT NULL DEFAULT 'bootstrap' CHECK(purpose IN ('bootstrap','add_device'));
ALTER TABLE bootstrap_tokens ADD COLUMN created_by TEXT;
ALTER TABLE bootstrap_tokens ADD COLUMN label TEXT NOT NULL DEFAULT '' CHECK(length(label)<=64);
-- 1 only when issued for an account without an active passkey. A passkey is active only if its token says so AND the
-- account still has no active passkey at enrollment. Existing tokens default to 0 (pending), the safe side.
ALTER TABLE bootstrap_tokens ADD COLUMN first_enrollment INTEGER NOT NULL DEFAULT 0 CHECK(first_enrollment IN (0,1));
-- Fresh passkey confirmation for one exact account/passkey change, bound to the session and a digest of that change.
CREATE TABLE step_ups (
 id TEXT PRIMARY KEY, challenge TEXT NOT NULL, session_hash TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id),
 binding TEXT NOT NULL, credential_ids TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
) STRICT;
