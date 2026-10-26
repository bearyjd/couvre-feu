# Explicit vendor admission and recovery

A missing platform selector uses `strict`. The installer accepts one
`--platform-profile strict|gl-xe3000-4.8.3-logd-011-v1|gl-xe3000-4.8.3-os-trust-v1`;
runtime commands do not
accept a selector. `/etc/couvrefeu/platform-profile` is one exact LF-terminated
line, root:root600 beneath700. It must agree with the private staged journal.
Unknown, malformed, duplicate, changed or conflicting evidence refuses.

The strict branch retains ordinary supported dependencies and strict metadata.
It does not load vendor payloads or scan vendor processes. The 011 vendor branch
requires the approved012 helper bytes and exact libc/libgcc/stat/loader pins.
The stat payload runs with a cleared environment and fixed library path; its
numeric metadata results authenticate the source closure before other modules.
The provisional `/usr/libexec775` permission applies only to this pinned stat
bootstrap. The approved `/etc775` permission never extends to private records.

Compile source pins and the full manifest with
`python3 tools/freeze-router-release.py`, then independently review and freeze
**every byte**, including entry scripts, manifest and bootstrap. The manifest
is the outer reviewed release proof. Entry scripts do not recursively
self-authenticate their own bytes. Never supply a replacement manifest, source
or hash through the environment. A production source release has canonical
root-owned700 release/lib directories,755 entries,644 modules and600 manifest.

Mutating transaction admission validates the permanent `/etc/.couvrefeu-mutex`
inode and acquires its kernel exclusion; direct transaction workers retain the
descriptor. Fresh vendor attestation and profile validation precede persistent
control-record creation. Vendor entry also acquires `/tmp/couvrefeu-platform.lock`
under verified root-owned sticky1777 `/tmp` before private policy reads, ordinary
locks or mutation. Lock contention refuses. The mutex is never unlinked; a dead
PID or elapsed time cannot authorize takeover.
Nested core and firewall-journal calls run in isolated verified subshells;
independent executable invocations always initialize admission again. Only the
existing exact live-owner/private reload token can return read-only deferred
JSON before admission. It never admits a transaction. For an interrupted installation, use the
administrator-only external-source
`cfctl recover-install-lock` flow below. `cfctl recover-platform-lock` retains
fresh vendor attestation and transaction admission; it is not a substitute for
install recovery. Missing, foreign or legacy ownership remains for separately
reviewed recovery.

Activation retains an external immutable private release at
`/etc/.couvrefeu-release-<release-id>` and preserves it in
sysupgrade configuration. Recovery must execute the uninstaller from that
verified closure. ID collisions, changed manifests and incomplete copies
refuse; they are never overwritten or removed automatically. Keep this closure
through recovery even after installed/staged helpers have been restored or
removed. Original bytes, modes, owners and exact mtimes remain journaled.
New-format PREPARED is complete, immutable and digest-bound before managed
writes. Ownership binds boot/PID/starttime/token, profile/release, baseline and
permanent mutex identity. Integration intent precedes executable/include/cron
publication. Cron and firewall callbacks invoke the immutable versioned source
with an installation generation; a stale callback refuses after retirement or a
later installation of the same release. Recovery reconciles the audited service
state; daemon exit alone is not a job-drain proof or whole-system quiescence.
Production admission requires exact audited cron init, `rc.common`, `procd.sh`
and firewall init hashes plus the admitted procd image binding. Unknown sources
refuse before managed writes. Target source bytes, flock/setsid and service
behavior remain UNVERIFIED; this narrows eligibility, not a hardware admission.

An administrator uses a complete independently authenticated external release:
`<AUTHENTICATED_RELEASE>/cfctl recover-install-lock`, then
`<AUTHENTICATED_RELEASE>/uninstall.sh` once, without arguments. Another complete
authenticated source may replace an absent/partial installed recovery copy;
partial or old helpers and environment-selected targets are refused. Fresh vendor
attestation remains required. Recovery validates ownership, worker exclusion and
baseline, then keeps a durable recovery-required fence until the single
uninstaller finishes. Never delete locks or the journal manually. Password login,
full administrator shell/edit rights and PTY access remain available; no service
SSH grammar is added.

The durable `CFRETIREMENT 2` receipt binds the authenticated SOURCE separately
from the owned TARGET release, target inventory and validated restoration
baseline. It survives retirement of journal, PREPARED, owned target release,
compatibility locks, owner, recovery fence and DONE, and is unlinked last under
the permanent mutex. A further interruption uses authenticated recovery again;
ambiguity preserves evidence. A pre-existing release remains unchanged. Only the
permanent mutex is intentional new residue; all owned transaction transients
must retire. SIGKILL fixtures do not establish power-loss or reboot durability.

Production legacy journals, DONE and retirement state without new-format binding
refuse automatic restoration: old generic callbacks cannot be proven quiescent.
Complete-legacy compatibility therefore remains an outstanding scope decision,
with a separately approved maintenance/reboot recovery design required. The
pinned historical main4ff source fixture exercises isolated byte/metadata restore,
authentication and receipt parsing only; it is data, not production legacy proof.
No old helper is executed by current recovery.

Do not remove prerequisite stat/od while any installation, recovery, DONE,
publication-temporary, owned lock or external release path remains. The frozen
private prerequisite012 package bodies are unchanged; a separately reviewed
launcher/pre-removal guard must enforce this condition before rollback.

## Explicit OS-trust profile

`gl-xe3000-4.8.3-os-trust-v1` is a distinct, explicitly selected trust model.
It never substitutes for `strict` or `gl-xe3000-4.8.3-logd-011-v1`, migrates an
existing journal, or reinterprets an earlier refusal or UNKNOWN result. Its
exact name remains bound in the installed marker, staged journal, DONE and
external release. Empty install/uninstall restoration must pass before device
enrollment; prerequisite and first-launch procedures require their own review.

This profile trusts the router OS, root administration, privileged launchers,
credential assignment, vendor logd, and every principal able to write the
exceptional ancestry. A private child beneath a group-writable ancestor does
not exclude replacement by those writers. Compromised trusted actors, including
unobserved nonroot GID0 holders, can undermine policy, enforcement and recovery.
Static pins and configured accounts are drift/baseline witnesses, not proof of
writer exclusion, complete firmware provenance or all running process images.

Fresh checks retain the pinned libc/libgcc/stat/loader and source closure,
exact canonical type/owner/mode exceptions, measured `/etc/glversion` identity
`4.8.3` plus LF, bounded account parsing and before/after metadata/size/digest
checks, files-only NSS configuration and provider path/socket checks. Unique
logd UID/GID514 and configured GID0 membership rules remain. The complete fixed
PID1 root/procd credential, comm, starttime and image bracket remains; service
file pins remain. There is no logd population discovery or global task census.
`OS_TRUST_PROFILE_ATTESTED` states this distinction explicitly. The 011 census
and its refusal for disappearance before classification remain unchanged.

The new profile captures one validated `/proc/uptime` anchor before bootstrap
and checks elapsed **centiseconds**, with an exclusive candidate cutoff of
1300 centiseconds (13 seconds). Repeated admission and nested source loads do
not reset the anchor. Guards run after blocking prerequisites, source/input
and lock phases, before private policy, and immediately before the initial
protected record/configuration/kernel write. Admission locks and scratch are
owned temporary effects; refusal can release only those owned resources.
After the first eligible protected write attempt, existing UNKNOWN and journal restoration
rules own interruption. No arbitrary deadline abort is inserted mid-restore.
The new profile's internal `remove-fw` receipt separately reports whether a
protected write attempt started. The existing zero-owned-mutation proof concerns
kernel effects; it does not imply that no filesystem records were removed.
The parent validates the exact profile/source-bound receipt before continuing.
A readonly empty proof keeps the deadline active; contradictory or missing
receipt fields refuse. Strict and 011 retain their original receipt bytes.

This is a logical permission deadline. Bounded producers remain, but there is
no hard syscall termination, scheduler-gap, atomic wall-time or remote-drain
guarantee. A slow check that resumes after expiry cannot grant initial write
permission. The existing ten-second input and fifteen-second host SSH budgets
are unchanged; the nominal two-second reserve is **not production timing
clearance**. Measure complete successful status/sync/expire, nested journal and
reload, refusal/cancellation and slow-input flows on the target before live
MVP use. If the reserve is insufficient, reduce the admission cutoff based on
measurement; do not increase the SSH budget. Native fixture timings do not
establish target latency, OS trust, packet behavior or production readiness.

Authentication, protected management identities and self-lockout fences,
installer scope, revision/generation/CAS, atomic desired state and receipts,
drift/collision refusal and exact restoration remain mandatory. WAN, dnsmasq,
offload and firmware are unchanged.

Focused fixtures exercise native ash admission call counts, source and profile
refusals, cleanup interruptions and exact new-format restoration; historical legacy
restoration runs only in inert data fixtures. Vendor
payload/attestation boundaries are explicit inert stand-ins in adapter tests;
the unchanged helper has its separate135 native cases and the unchanged private
prerequisite wrapper49 cases. No fixture proves live packet behavior or router
latency.

The service SSH deadline remains15000ms. Before MVP dispatch, measure complete
status/sync/expiry, nested journal/reload, refusal and transport-cancellation
flows under representative router load. Maximum plus documented scheduling
margin must fit below15000ms. Failure blocks dispatch pending a separately
reviewed resolution. No cached census or silent deadline increase is permitted.
