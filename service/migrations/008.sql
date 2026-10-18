-- Design 008 PR-C: children ("people"; kind 'child', or 'device_group' for a named set of shared devices such as a TV) and their devices live in the database; the manifest only seeds the first one.
-- scope_all=1: the account is granted every child, including children added later (child creation appends the new id
-- to its person_ids, so sessions and permission_version stay untouched). 0: exactly the listed person_ids.
ALTER TABLE accounts ADD COLUMN scope_all INTEGER NOT NULL DEFAULT 0 CHECK(scope_all IN (0,1));
CREATE TABLE people (
 id TEXT PRIMARY KEY, name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 kind TEXT NOT NULL DEFAULT 'child' CHECK(kind IN ('child','device_group')),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), created_at INTEGER NOT NULL
) STRICT;
-- identifier_kind leaves room for a later kind (e.g. a Tailscale node id); only canonical unicast MACs exist today.
-- 'enrolling'/'removing' rows belong to a queued router operation and settle when it resolves.
CREATE TABLE devices (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES people(id),
 label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
 identifier_kind TEXT NOT NULL CHECK(identifier_kind IN ('mac')), identifier TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('enrolling','active','removing')), operation_id TEXT, created_at INTEGER NOT NULL,
 UNIQUE(identifier_kind,identifier)
) STRICT;
CREATE INDEX devices_person ON devices(person_id);
