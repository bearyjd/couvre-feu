# Explicit vendor admission and recovery

A missing platform selector uses `strict`. The installer accepts one
`--platform-profile strict|gl-xe3000-4.8.3-logd-011-v1`; runtime commands do not
accept a selector. `/etc/couvrefeu/platform-profile` is one exact LF-terminated
line, root:root600 beneath700. It must agree with the private staged journal.
Unknown, malformed, duplicate, changed or conflicting evidence refuses.

The strict branch retains ordinary supported dependencies and strict metadata.
It does not load vendor payloads or scan vendor processes. The vendor branch
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

Vendor entry acquires `/tmp/couvrefeu-platform.lock` under verified root-owned
sticky1777 `/tmp`, then performs one full fresh012 two-pass attestation before
private policy reads, ordinary locks or mutation. Lock contention refuses.
Nested core and firewall-journal calls run in isolated verified subshells;
independent executable invocations always initialize admission again. Only the
existing exact live-owner/private reload token can return read-only deferred
JSON before admission. It never admits a transaction. The explicit
`cfctl recover-platform-lock` operation validates metadata and fresh vendor
attestation, then removes only a recorded demonstrably dead owner. Missing or
foreign records remain for separately reviewed recovery.

Activation retains an external immutable private release at
`/etc/.couvrefeu-release-<compiled-module-closure-id>` and preserves it in
sysupgrade configuration. Recovery must execute the uninstaller from that
verified closure. ID collisions, changed manifests and incomplete copies
refuse; they are never overwritten or removed automatically. Keep this closure
through recovery even after installed/staged helpers have been restored or
removed. Original bytes, modes, owners and exact mtimes remain journaled.
Legacy journals derive inventory from their original records and retain strict
version2 completion behavior. Activated legacy cleanup executes the verified
current immutable external release, including its AWK/module dependencies;
installed-file drift still checks the validated original journal. Older unpinned
installed programs are never executed. The committed deterministic fixture
archive contains genuine pre-adapter public source bytes, not router captures.

After exact restoration succeeds, version3 DONE binds the exact profile and
compiled module closure ID. It survives each staged record deletion, journal
removal and owned-lock release. Cleanup disarms traps before deleting DONE as
its final filesystem operation. A DONE-only retry still verifies the external
closure and performs a fresh vendor attestation. The external release remains
as recovery evidence after completion; retiring it is a separate operation.

Do not remove prerequisite stat/od while any installation, recovery, DONE,
publication-temporary, owned lock or external release path remains. The frozen
private prerequisite012 package bodies are unchanged; a separately reviewed
launcher/pre-removal guard must enforce this condition before rollback.

Focused fixtures exercise native ash admission call counts, source and profile
refusals, cleanup interruptions and exact strict/legacy restoration. Vendor
payload/attestation boundaries are explicit inert stand-ins in adapter tests;
the unchanged helper has its separate135 native cases and the unchanged private
prerequisite wrapper49 cases. No fixture proves live packet behavior or router
latency.

The service SSH deadline remains15000ms. Before MVP dispatch, measure complete
status/sync/expiry, nested journal/reload, refusal and transport-cancellation
flows under representative router load. Maximum plus documented scheduling
margin must fit below15000ms. Failure blocks dispatch pending a separately
reviewed resolution. No cached census or silent deadline increase is permitted.
