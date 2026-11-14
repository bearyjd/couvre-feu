-- PRP-006 C (D5): NextDNS analytics counts per child per local day (America/New_York calendar day). Integers and fixed codes only: no domain, reason id,
-- reason name, device, client address or profile id is stored. Rows are written by the counts fetcher only and read by the counts store; with
-- contentFilter.counts off the tables exist and stay empty (as content_filter_desired does with the filter off). Additive; created for both
-- database kinds like 014. The number must be re-checked at merge: it is the next free one after 015 (inventory decisions).
CREATE TABLE content_filter_day (
 person_id TEXT NOT NULL CHECK(length(person_id) BETWEEN 1 AND 64),
 day TEXT NOT NULL CHECK(day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
 state TEXT NOT NULL CHECK(state IN ('ok','unavailable','logs_off','suspect_zero')),
 total INTEGER CHECK(total IS NULL OR total >= 0),
 blocked INTEGER CHECK(blocked IS NULL OR blocked >= 0),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
 fetched_at INTEGER NOT NULL,
 PRIMARY KEY(person_id, day),
 CHECK((state IN ('ok','suspect_zero')) = (total IS NOT NULL AND blocked IS NOT NULL))
) STRICT;
CREATE TABLE content_filter_day_class (
 person_id TEXT NOT NULL CHECK(length(person_id) BETWEEN 1 AND 64),
 day TEXT NOT NULL CHECK(day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
 class TEXT NOT NULL CHECK(class IN ('adult','gambling','dating','piracy','social','gaming','video','apps','bypass','denylist','ads_trackers','security','other')),
 queries INTEGER NOT NULL CHECK(queries >= 0),
 PRIMARY KEY(person_id, day, class),
 FOREIGN KEY(person_id, day) REFERENCES content_filter_day(person_id, day) ON DELETE CASCADE
) STRICT;
CREATE INDEX content_filter_day_day ON content_filter_day(day);
