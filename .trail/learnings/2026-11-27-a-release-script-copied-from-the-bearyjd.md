---
title: A release script copied from the last deploy carries assumptions that only held for that upgrade
author: Bearyjd
date: 2026-11-27
branch: docs/learning-schedule-recovery-redesign
cost: { minutes: 61, tokens: 709590 }
id: l-c0b0c873
scope: repo
status: active
src: agent
touches:
  - service/src/inventory-store.ts
---

## Decided
Adapt the script that last ran in production, then check each inherited assumption against the new upgrade before rehearsing. For a release with no database migration the schema version check must allow an unchanged version, and the list of tables skipped by the row-count check must be derived again for the schema the upgrade starts from.

## Tried and ruled out
Re-pinning hashes and versions only. The script would have rolled back every deploy, because it required the schema version to increase. The skip list had been written for a much older starting schema, so tables the app rewrites in normal running were about to be compared for the first time and could roll back a healthy deploy. Shell rehearsals with stub services did not show this; a boot of the real old and new releases on seeded data did.

## Watch out
Skipping the parent decision table also stops guarding labels a parent entered; the pre-deploy backup is then the only record. The old releases directory and an older bundle in the cache look current but are not: check the live log for what is actually running.

In the code:
- `deploy-ct107.sh` (rendered outside the repo under `~/.cache/cf-overnight/release-<sha>/`): `step_verify` user_version check, `VOLATILE_TABLES`.
- `service/src/inventory-store.ts`: poll and startup deletes from `inventory_coverage` and `inventory_decisions`.
- `.omc/research/live-log.txt` records the release really applied.
