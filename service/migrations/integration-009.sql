-- Schedule truth in the service database (roadmap item 2, S1; flag schedules.editable; unverified on this router).
-- Additive and idempotent: an empty table changes nothing while the flag is off. Window clocks and weekday sets only, no free text.
CREATE TABLE IF NOT EXISTS schedule_windows (
 person_id TEXT NOT NULL REFERENCES people(id),
 id TEXT NOT NULL CHECK(id GLOB '[a-z]*' AND length(id) <= 32 AND id NOT GLOB '*[^a-z0-9_]*'),
 -- Comma-separated Mon..Sun names: only day names and commas remain after stripping the names, no empty or glued segment (k names, c commas, 3k+c = 4(c+1)-1).
 weekdays TEXT NOT NULL CHECK(length(weekdays) BETWEEN 3 AND 27 AND weekdays NOT GLOB '*,,*' AND weekdays NOT GLOB ',*' AND weekdays NOT GLOB '*,'
  AND replace(replace(replace(replace(replace(replace(replace(replace(weekdays,'Mon',''),'Tue',''),'Wed',''),'Thu',''),'Fri',''),'Sat',''),'Sun',''),',','') = ''
  AND length(weekdays) + 1 = 4 * (length(weekdays) - length(replace(weekdays, ',', '')) + 1)),
 start TEXT NOT NULL CHECK(start GLOB '[01][0-9]:[0-5][0-9]' OR start GLOB '2[0-3]:[0-5][0-9]'),
 stop TEXT NOT NULL CHECK((stop GLOB '[01][0-9]:[0-5][0-9]' OR stop GLOB '2[0-3]:[0-5][0-9]') AND stop <> start),
 PRIMARY KEY(person_id, id)
) STRICT;
-- Cap: 8 windows per child, enforced where the rows live.
CREATE TRIGGER IF NOT EXISTS schedule_windows_cap BEFORE INSERT ON schedule_windows
WHEN (SELECT count(*) FROM schedule_windows WHERE person_id = NEW.person_id) >= 8
BEGIN SELECT RAISE(ABORT, 'schedule_window_limit'); END;
CREATE TRIGGER IF NOT EXISTS schedule_windows_cap_owner BEFORE UPDATE OF person_id ON schedule_windows
WHEN NEW.person_id <> OLD.person_id AND (SELECT count(*) FROM schedule_windows WHERE person_id = NEW.person_id) >= 8
BEGIN SELECT RAISE(ABORT, 'schedule_window_limit'); END;
-- One-time manifest seed marker: a parent who empties the set is never re-seeded from the manifest.
CREATE TABLE IF NOT EXISTS schedule_seed (singleton INTEGER PRIMARY KEY CHECK(singleton = 1)) STRICT;
-- Windows a queued schedule change proposes, tied to its operation. They become schedule_windows only when the router confirms; a failed or
-- conflicted operation discards them. Not the truth until then, so a refused or undelivered change leaves nothing behind.
CREATE TABLE IF NOT EXISTS schedule_staged (
 operation_id TEXT NOT NULL PRIMARY KEY,
 person_id TEXT NOT NULL REFERENCES people(id),
 windows_json TEXT NOT NULL
) STRICT;
