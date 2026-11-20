-- Schedule truth in the service database (roadmap item 2, S1; flag schedules.editable; unverified on this router).
-- Additive and idempotent: an empty table changes nothing while the flag is off. Window clocks and weekday sets only, no free text.
CREATE TABLE IF NOT EXISTS schedule_windows (
 person_id TEXT NOT NULL REFERENCES people(id),
 id TEXT NOT NULL CHECK(id GLOB '[a-z]*' AND length(id) <= 32 AND id NOT GLOB '*[^a-z0-9_]*'),
 weekdays TEXT NOT NULL CHECK(length(weekdays) BETWEEN 3 AND 27 AND weekdays NOT GLOB '*[^A-Za-z,]*'),
 start TEXT NOT NULL CHECK(start GLOB '[0-2][0-9]:[0-5][0-9]'),
 stop TEXT NOT NULL CHECK(stop GLOB '[0-2][0-9]:[0-5][0-9]' AND stop <> start),
 PRIMARY KEY(person_id, id)
) STRICT;
-- Cap: 8 windows per child, enforced where the rows live.
CREATE TRIGGER IF NOT EXISTS schedule_windows_cap BEFORE INSERT ON schedule_windows
WHEN (SELECT count(*) FROM schedule_windows WHERE person_id = NEW.person_id) >= 8
BEGIN SELECT RAISE(ABORT, 'schedule_window_limit'); END;
-- One-time manifest seed marker: a parent who empties the set is never re-seeded from the manifest.
CREATE TABLE IF NOT EXISTS schedule_seed (singleton INTEGER PRIMARY KEY CHECK(singleton = 1)) STRICT;
