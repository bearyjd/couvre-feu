-- Integration schedule labels, applied after the schedule tables exist.
ALTER TABLE schedule_windows ADD COLUMN kind TEXT NOT NULL DEFAULT 'bedtime' CHECK(kind IN ('bedtime','focus'));
CREATE TABLE schedule_kind_intents (
 operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
 digest TEXT NOT NULL CHECK(length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*')
) STRICT;
