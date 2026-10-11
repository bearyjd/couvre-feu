CREATE TABLE auth_contexts (
 browser_hash TEXT PRIMARY KEY, epoch INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 0
) STRICT;
ALTER TABLE challenges ADD COLUMN browser_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE challenges ADD COLUMN browser_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN browser_hash TEXT REFERENCES auth_contexts(browser_hash);
ALTER TABLE sessions ADD COLUMN browser_epoch INTEGER NOT NULL DEFAULT 0;
-- Existing sessions/challenges predate browser-context binding and cannot be upgraded into authenticated access.
UPDATE sessions SET revoked=1;
DELETE FROM challenges;
