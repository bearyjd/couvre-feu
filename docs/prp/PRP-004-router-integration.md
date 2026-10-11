# PRP-004 — one-device router integration

Status: **implemented source contract; target acceptance pending**. The independently
reviewed release identity and final source/check evidence are recorded in
[PR #3](https://github.com/bearyjd/couvre-feu/pull/3) and its
[checks](https://github.com/bearyjd/couvre-feu/pull/3/checks).
This extends [PRP-003](PRP-003-policy-service.md) with a separate integration
entry point. The fictional, loopback demo keeps its existing defaults.
Read [integration-004](../integration-004.md) for operation and
[acceptance-004](../acceptance-004.md) for evidence boundaries.

## Outcome and limits

Connect the authenticated parent controls to one explicitly admitted network MAC
through a constrained SSH channel. Support observed status, pause, timed pause,
resume and router-owned expiry while the service is stopped. Private configuration
supplies the accounts, person/device bindings, target and protected identities;
integration must never seed fictional identities or fall back to a fake router.
Current source includes the RPC, scoped installer and separate async service path;
author checks are recorded in acceptance-004. No assistant target command has run
in this session; read-only inspection still awaits exact-command approval.

This is a controlled one-device pilot. Household production remains blocked by
the [non-atomic transition limitation](../router-transition-design.md): rebuilding
rules, sets and fw3 hooks can expose a gap during changed policy, drift or reload.
CAS and receipts protect accepted policy ownership; they do not make those kernel
transitions atomic. A successful control round trip does not clear this blocker.

## Router RPC version 1

The restricted channel accepts only `cfctl rpc-sync` and
`cfctl rpc-status --json [operation_id]`. The sync command reads one bounded JSON
document from stdin; values never become shell command fragments.

| Request field | Meaning |
|---|---|
| `rpc_version` | Integer `1` |
| `generation` | Installation's 64-character lowercase hexadecimal identity |
| `operation_id` | 1–64 ASCII characters from `[a-z0-9_-]`; reserved `-` excluded |
| `expected_revision` | Exact current accepted revision, integer 0–2147483647 |
| `expected_digest` | SHA256 of the router's canonical current policy records |
| `policy` | Complete policy v1; revision is exactly expected revision plus one |

Under the router lock, compare generation, revision **and** digest before any
policy, protection or firewall write. A same-revision different policy conflicts.
The digest covers canonical V/R/P/A/S/D4/D6 records, with one final LF; it is not a
hash of JSON formatting. The request digest binds generation, operation ID, exact
base and canonical next-policy digest. Whitespace changes cannot create a new
logical request. Version, grammar, duplicates, unknown fields and size are checked.
Input is at most 65536 bytes with bounded EOF; response is at most 131072 bytes.

Accepted policy and receipt history share one atomic state replacement. A receipt
contains `operationId`, `requestDigest`, `baseRevision`, `baseDigest`,
`acceptedRevision`, `acceptedDigest`, `outcome: "accepted"` and `current`.
An exact replay returns that receipt with fresh status, without writing or retrying
the apply. Reusing the ID for another request conflicts. History holds at most
128 unique accepted operations; it never evicts. At capacity, new acceptance fails
closed with `receipt_capacity`; existing exact receipt reads/replays still work.
Compaction requires a separate design and authorization.
State commit uses sync/rename/sync; local crash fixtures do not prove power-loss
durability on the router filesystem.

## Three different witnesses

1. **Historical acceptance:** a durable receipt proves that exact policy was
   accepted in that installation. Its expiry timestamps never restart on retry.
2. **Current runtime confirmation:** fresh status must bind current generation,
   operation, policy/digest/revisions, healthy rules/sets, native enforcement and
   address coverage. A historical receipt or `confirmedAt` alone is insufficient.
3. **Packet acceptance:** client traffic measurements establish actual cutoff,
   resume, DNS behavior and applicable IPv6/acceleration coverage. RPC cannot prove it.

Legacy policy mutations preserve history and clear the current-operation pointer.
Expiry and apply-only recovery preserve accepted policy identity. Historical replay
never restores old policy. Malformed state, drift, stale observations, missing
coverage or ambiguous receipts stay visibly unhealthy.

## Installation and scope fences

Scoped activation uses `--rpc-allow <TEST_NETWORK_MAC>` plus protected identities.
The scope is installer-owned, root-private and journaled; RPC cannot choose it.
Every admission path, including legacy mutations, rejects other enrolled MACs,
protected overlap and ambiguous control-client attribution before writes.
The service independently admits only the configured person/device/MAC binding.

Fresh activation creates a random generation. Interrupted activation reuses its
staged generation; completed uninstall followed by activation creates a different
one. Active installation journals and immutable scope/generation must match before
writes. Runtime/install lock interlocks prevent restoration beneath an active write.
Delayed pre-lock requests reject absent installation or the new generation.
An existing legacy installation requires a separately reviewed migration.

## Service dispatch and uncertain delivery

Persist the intent, exact envelope/base, audit and dispatch claim in short SQLite
transactions. Commit before awaiting SSH; never hold SQLite open around network
I/O. Complete only when claim token, epoch and generation still match. One unresolved
operation owns dispatch; stale callbacks cannot change current state.
Before SQLite opens, lstat admission checks the DB, WAL, SHM and `-journal` paths,
including dangling symlinks. Manifest, target, mode and generation pin the database.

An operator CLI prepares one exact invocation: target, argument array, stdin,
digest, bounds and abort/rollback. An approved one-use permit admits
only that frozen invocation. HTTP writes create intent; GETs, browser polls, restarts
and exhausted permits never launch SSH. Missing dispatch shows
`awaiting_operator_dispatch`. There is no automatic polling or unrestricted worker.
Permits expire after 15 minutes; apply also requires an approved cached exact-base
observation no older than 30 seconds. Cache identity separates source, generation
and account. Real-source labeling continues to report unmeasured packet acceptance.

Possible delivery followed by timeout, disconnect, crash or truncated response is
`unknown`. Killing local SSH or expiring a lease does not prove remote completion.
Even locked receipt absence cannot exclude a delayed queued invocation. Do not
replace/reapply it until positive remote completion or an approved generation fence.
Rollback first revokes local dispatch; restoration needs its own approved fence.

## Identity and future platform work

MACs identify an admitted interface on this network. Randomized per-network MACs
can change; a changed or unknown MAC is not automatically quarantined, and this
pilot does not provide infallible physical-device tracking. Rebinding requires
fresh identity/protection checks and a separately approved scope change.
Android, ChromeOS, iOS and Windows companion applications are future work outside
this session; platform enrollment, agent controls and identity continuity need
their own design and acceptance. No companion installation is authorized here.
