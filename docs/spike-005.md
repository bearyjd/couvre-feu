# Spike 005 — supplemental read-only target inspection

Status: **collection completed with unresolved checks; installation remains blocked**.
This supplements [spike-004](spike-004.md). The explicitly approved collection ran
on 2026-10-11, reached its final boundary and deliberately returned exit 2. The
boundary reports 22 unresolved checks and 11 metadata-command attempts; attempts
are not successful metadata retrievals. This is collection evidence, not an
installation or acceptance pass, and does not authorize a retry.

No Couvre-feu writes, package installation, configuration/key edits, symlink
changes or installation/restoration rehearsal occurred. Raw capture and household
identities remain private.

## Confirmed tool and inventory blockers

Standalone `stat` and callable `od` are missing. BusyBox returned
`stat: applet not found` for help and every attempted metadata format. A symlink
to that BusyBox cannot provide the absent applet. The remaining discovered tools
were observed as callable; their required runtime semantics were not accepted.

Source review establishes that the metadata prerequisite rejects before
installer/uninstaller staging or managed writes. Exact ownership, permissions,
size and filesystem identity remain required; content hashes or guessed metadata
cannot replace them. `od` encodes the installer's checked random bytes and is an
additional missing dependency, not the entropy source.

Scoped managed, staging and recovery paths were absent at the sampled locations.
Existing configuration, include/helper files and a key-backup artifact lacked
readable metadata. Their ownership, modes and restoration suitability remain
unverified; the scoped inventory does not prove conflict-free activation. The
bounded kernel set-name read found one vendor-owned set; no membership or packet
behavior was tested.

## Identity and recovery limits

The corrected scoped renderer recorded one fresh matching child neighbor and
current SSH-control neighbor/lease observations. The other child neighbor was
`FAILED` without a MAC. Its lease did not establish current link identity, so it
was not enrollable at that instant. Neither child observation establishes
authorization, unique ownership across all sources or protection readiness.

The user separately reported current primary adult endpoint details and successful
router-admin access after reconnecting. That report is not a fresh router-side
binding, continuous adult connectivity/DNS probes or a tested recovery action.
The active SSH-control observation is not independent recovery access. No adult
identity is eligible for child enrollment.

## Next boundary

A narrowly scoped firmware-compatible `stat`/`od` package path remains a proposal.
Exact vendor-feed availability, architecture/libc compatibility, artifact and
dependency review, file collisions/alternatives and package rollback are
unverified. No package was selected or installed. Couvre-feu's recovery journal
does not automatically cover external package-manager changes.

Further inspection requires fresh approval of its exact invocation. Package
changes and on-target tool checks also require separately disclosed approval.
Before enrollment, the existing scoped empty activation/uninstall, exact-original
restoration, protected adult/control probes and runtime service-key restrictions
must pass. Clock, IPv6, offload, real packets and lifecycle gates remain open in
the [acceptance record](acceptance-004.md). This inspection clears neither those
gates nor the non-atomic policy/drift/reload production blocker.
