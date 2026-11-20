-- Additive first-run batches: no user_version change, action widening or existing-table rebuild.
-- The previous binary ignores these tables and can still open this database.
CREATE TABLE IF NOT EXISTS admin_batches (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES accounts(id),
    client_key TEXT NOT NULL,
    digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    operation_id TEXT REFERENCES operations(id),
    created_at INTEGER NOT NULL,
    UNIQUE(actor_id, client_key)
) STRICT;
CREATE INDEX IF NOT EXISTS admin_batches_created ON admin_batches(created_at);

-- Kept separately from the 90-day retry records so retention never reopens first-run setup.
CREATE TABLE IF NOT EXISTS admin_batch_setup (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    setup_completed INTEGER NOT NULL
) STRICT;

-- last_seen means neighbour presence and intentionally does not advance on lease-only polls.
-- Track address coverage separately, replacing the snapshot on each complete inventory poll.
CREATE TABLE IF NOT EXISTS inventory_coverage (
    generation TEXT NOT NULL,
    mac TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY(generation, mac)
) STRICT;
