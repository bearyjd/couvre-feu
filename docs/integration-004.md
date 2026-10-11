# One-device integration runbook

Status: **implemented source runbook; target acceptance pending**. Independently
reviewed release identity is recorded in [PR #3](https://github.com/bearyjd/couvre-feu/pull/3);
consult its [checks](https://github.com/bearyjd/couvre-feu/pull/3/checks) for final exact-head CI.
No command
in this runbook authorizes a live connection or mutation. Maintenance live batches require
approval of its exact script, hash, target, admitted MAC, protected identities,
effects, bounds and rollback. [PRP-004](prp/PRP-004-router-integration.md) defines
the protocol; [acceptance-004](acceptance-004.md) records measured versus pending gates.

## Private preparation

Keep the manifest, database, captures, approval records and backups outside tracked
public files, in an owner-only directory. Reject symlinks and group/world-readable
configuration. The manifest selects an explicit integration mode, loopback listener,
private data directory, expected target, trusted host key, dedicated known-hosts
file, unlocked agent socket/public identity, installation generation, one admitted
network MAC, protected recovery/adult identities and explicit account/person roles.
Never put a private key, passphrase, token or household inventory in the repository.
The service selects an agent-held identity; it does not load private-key bytes.
The known-hosts file must contain one exact pinned entry; the `.pub` identity and
agent socket must pass owner/type/permissions checks. The pilot accepts only its
predefined target; changing the host does not select an arbitrary router.

Use a separate integration entry and database. The demo remains fictional. Refuse
missing identity/scope, protected overlap, unsafe files, demo/foreign databases,
changed installation or mismatched host identity. A new installation needs explicit
private configuration and fresh database/enrollment; a revision reset is insufficient.
The manifest's enrollment policy is a local template; startup does not enroll the
router. Enrollment requires its own approved live command, followed by an approved
observation before controls. In owner-enabled mode the supervisor supplies that observation;
activating this mode requires separately reviewed deployment authorization. The manifest can
configure up to eight weekly schedule windows for the admitted person; parent pause/resume
preserves these exact windows. Router-native schedules enforce independently of the service.
Current schedule truth requires the explicit clock calibration described below.
Before opening SQLite, lstat checks the DB, WAL, SHM and rollback `-journal` paths;
unsafe files and dangling symlinks fail rather than being followed or repaired.

Required manifest groups are `version: 1`, `mode: "integration"`, `port`, `dataDir`,
`router`, `person`, `protectedMacs`, `accounts` and full v1 `enrollment`.
`router` supplies host/user/port, knownHosts, hostFingerprint, agentSocket,
publicIdentity, publicKeyFingerprint and generation. `person` binds one device MAC;
accounts bind explicit roles/person IDs. Sensitive values stay private.

Owner schedules are the full normalized `enrollment.schedules` array, using existing
v1 `{person, id, weekdays, start, stop}` records. Windows include the start minute and
exclude the stop minute; cross-midnight windows use the weekday on which they start.
No schedule editor or parent bypass is provided. Any unexpected observed schedule
change refuses the observation rather than copying it into a new parent operation.
Empty unenrolled router policy stays read-only and displays the configured windows
with unknown current state.

Schedules require optional manifest `scheduleClock`, an exact object with a canonical
IANA `timezone` such as `America/New_York` and optional `conformance`. Without
conformance, configured windows are visible but their current state is unknown.
The exact conformance record has `utcOffsetMinutes` (integer −840 through 840),
`verifiedAt`, `validUntil` (epoch seconds, a positive interval of at most seven days),
and `evidenceSha256` (lowercase SHA256 of the private reviewed evidence). It is an
explicit owner assertion bound by the manifest's existing target, installation
generation and manifest digest, not a router-reported capability. Do not create a
record until the exact target's shell clock, kernel `--kerneltz` schedule behavior,
schedule boundary/stream acceptance and protected-device checks have passed review.
Evidence must identify that target/generation and the reviewed timezone/offset.
Source fixtures do not supply that evidence or authorize activation.

Validation checks the declared offset across the admitted interval, using hourly
samples and both endpoints (the last included second at
`validUntil - 1`). This is a bounded check for supported modern IANA transitions,
not a universal historical proof of subhour timezone changes. A transition exactly
at `validUntil` is outside the record. Both observed router time and current service
time must still have the reviewed offset when state is evaluated.

Current schedule state uses the actual freshly observed `routerTime` in the declared
timezone, only with healthy runtime and a record covering both observation and current
service time. Missing/expired records, unhealthy/stale observations or a timezone
offset differing from the calibrated kernel offset display **schedule state unknown**,
never an inactive claim. An offset change at DST therefore makes the state unknown;
automatic DST support is not implemented. `routerCompatibilityVerified` remains false
and packet acceptance remains unmeasured in API/UI source. Safe manual pause/resume
still requires fresh router health/CAS and preserves schedules even while calibration
is unknown. Resume never bypasses bedtime.

Configured schedule results include `scheduleCheckedAt` (service evaluation epoch)
and exclusive `scheduleValidUntil`, bounded by calibration expiry and the existing
observation freshness deadline. Unknown results have null timing fields. The browser
checks receipt wall time within one second of the evaluation time; high latency or
detected skew makes the schedule claim unknown. It advances the received deadline
using a monotonic clock and a conservative maximum with wall time, so a wall-clock
rewind cannot extend a previously received deadline. These schedule-only checks do
not change manual controls or establish a general browser/server time authority;
the informational startup tolerance is at most one second. Cached timing fields keep
their original values, so reloaded old cache never renews schedule confidence.

This calibration has an operator maintenance gap: it expires within seven days and
renewal changes the manifest digest. Renew through reviewed private backup/recovery
or fresh explicit enrollment while preserving uncertain operations; do not hot-edit
the record or database identity marker. The MVP cannot claim continuously calibrated
or automatic DST-aware schedule truth across that expiry. Router enforcement itself
continues when the service or calibration expires.

RPC v1 has no boot identity. Installation generation does not establish that a
kernel clock calibration survived reboot, timezone changes or restore. Deployment
must invalidate the record externally after any such reviewed event and re-establish
exact-target clock/schedule evidence before definitive schedule state. This is an
operational acceptance gate; local date/IANA conversion cannot substitute for it.

Optional `dispatch` is an exact object with `enabled` (boolean), `pollSeconds`
(integer 2–15) and `maxBackoffSeconds` (integer from `pollSeconds` through 300).
Omitting it or using `enabled: false` preserves exact one-use maintenance permits.
`enabled: true` starts the serialized supervisor from `integration:start`; each
authenticated queued intent gets at most one durable apply attempt. Every cycle
first observes the pinned generation and accepted base. Failures back off read-only
polling; uncertain operations receive receipt reads and never automatic reapply.
Dispatch binds the exact manifest/target digests, public identity, protected MACs,
installation generation and a revocable local owner epoch. Actor permission changes
before the claim fail the intent without applying it. Accounts still require genuine
passkeys, CSRF, resource scope and revision preconditions.

Automatic observe and receipt polling retain at most 64 completed read invocations,
plus consumed callbacks that remain in flight. A bounded summary per read kind
records the cumulative dispatch count and latest timing/outcome. Unchanged operation
state/error outcomes are coalesced, while fresh observation timestamps still update.
Apply claims, operation envelopes/expiry, accepted receipt evidence, meaningful
operation/security/revocation audits and manually approved permit history are never
removed by this retention policy. Old unmarked history remains conservative evidence;
only explicitly marked automatic reads are compacted. Claim and lease cleanup use
an index, so continuous polling does not scan retained dispatch history.

Optional `origin` is an exact canonical HTTPS origin with a DNS hostname, for
example `https://parent.example.test` (a fictional documentation placeholder).
Choose the stable private hostname before creating passkeys. The RP ID derives
from its hostname; Host and Origin must match exactly, and auth cookies use Secure.
Without this field, origin remains `http://localhost:<port>`. The service always
binds `127.0.0.1`: supply a separately deployed private TLS reverse proxy that
preserves the configured Host and browser Origin and forwards only to loopback.
Forwarded headers never select origin, host, user or RP identity. This change
installs no proxy, certificate or phone/network deployment.

Any manifest edit changes its digest and existing database bindings refuse it.
Restart is mandatory; use reviewed private backup/recovery or fresh explicit
database/account enrollment rather than editing identity markers to bypass refusal.
Do not discard unresolved operations when migrating configuration. Source support
for continuous dispatch does not establish router safety or packet acceptance.

The following names are placeholders, **not runnable provisioning commands**:

| Placeholder | Private value supplied for an approved batch |
|---|---|
| `<PRIVATE_MANIFEST>` / `<PRIVATE_DATA_DIR>` | Reviewed owner-only paths |
| `<ROUTER_HOST>` / `<ROUTER_USER>` | Exact expected SSH endpoint/account |
| `<PINNED_KNOWN_HOSTS>` / `<PUBLIC_IDENTITY>` | Dedicated trusted host record and agent identity selector |
| `<AGENT_SOCKET>` | Explicit accessible unlocked agent socket |
| `<INSTALLATION_GENERATION>` | Generation from that approved installation |
| `<TEST_NETWORK_MAC>` / `<PROTECTED_MAC>` | Verified admitted and protected network identities |
| `<BATCH_SHA256>` / `<OPERATION_ID>` | Exact prepared script digest and durable request identity |

The implemented CLI is below. Replace quoted placeholders with reviewed private
values; `execute` needs the exact invocation approval before it can be used:

```sh
npm run integration:start -- "<PRIVATE_MANIFEST>"
npm run integration:bootstrap -- "<PRIVATE_MANIFEST>" "<ACCOUNT_ID>"
npm run integration:dispatch -- prepare "<PRIVATE_MANIFEST>" "<PRIVATE_PERMIT>" observe
npm run integration:dispatch -- prepare "<PRIVATE_MANIFEST>" "<PRIVATE_PERMIT>" apply "<OPERATION_ID>"
npm run integration:dispatch -- prepare "<PRIVATE_MANIFEST>" "<PRIVATE_PERMIT>" receipt "<OPERATION_ID>"
npm run integration:dispatch -- execute "<PRIVATE_MANIFEST>" "<PRIVATE_PERMIT>" "<BATCH_SHA256>"
npm run integration:dispatch -- stop "<PRIVATE_MANIFEST>"
```

`prepare` performs no SSH. Inspect its exact frozen invocation and obtain explicit
approval before `execute`; each permit covers one invocation, with no automatic
retry. The alternatives above need distinct private permit paths. Bootstrap output
is sensitive and stays private. `stop` stops local dispatch; it is not uninstall.
Preparation exclusively creates a mode-600 permit with fixed argv/stdin, not a
standalone executable shell script. It is epoch-bound and expires after 15 minutes.
Apply requires an approved cached exact-base/runtime observation within 30 seconds.

## Ordered live gates

1. **Access and inspection:** independently approve any public-key provisioning;
   preserve exact original authorization bytes/modes/absence. Establish trusted host
   identity and public-key-only access. Then approve bounded read-only inspection
   of firmware, individually callable tools, clock/timezone, LAN IPv6, includes,
   DNS owners, acceleration and protection. Retain usable recovery access.
2. **Empty-policy rehearsal:** review/stage the exact source, perform a scoped empty
   activation with the admitted MAC/protected control identities, then
   monitor protected adult access/DNS, uninstall and compare originals,
   metadata and prior absence. Empty activation can reload firewall and is a write.
   Do this before enrolling the test device. Existing install/recovery/foreign-state
   conflicts abort; never clear locks or perform blanket object deletion.
3. **One-device controls:** approve a fresh scoped activation, separate restricted
   service-key provisioning and runtime confinement checks. Admit only the supplied
   network MAC after unique fresh attribution. Run the disclosed finite status,
   pause, resume, timed-pause and service-off-expiry sequence with child/adult probes.
4. **Resilience:** reload, reboot and recovery each need their own approved script
   and evidence. Upgrade is outside this pilot and remains unperformed.

Do not change WAN policy, dnsmasq, GL parental controls or offload to manufacture a
pass. Stop on adult disruption, uncertain identity/outcome, foreign drift or lost
recovery access. Preserve evidence and execute only the already approved bounded
rollback; a new conflict requires a separately reviewed resolution.

## Service operation and results

Enrollment uses only supplied private accounts, assigned resources and genuine
WebAuthn. Parent HTTP requests retain session/CSRF/role/resource/precondition and
idempotency checks. GET `/people` and GET `/operations/:id` use cached observations;
UI polling cannot make a remote call. POST `/people/:personId/pause` and
`/people/:personId/resume` create intent. Default mode waits for operator dispatch;
explicit owner-enabled mode dispatches through the background supervisor.

Prepare one invocation locally, inspect its exact target/argv/stdin/hash/deadlines
and abort/rollback, obtain approval, then execute its one-use CLI permit.
In maintenance mode each observation, apply or receipt lookup needs its own disclosed step.
Changed payload/target/generation or a spent permit refuses dispatch. Shutdown
revokes ready steps and fences late completions; it does not invoke router cleanup.

200 requires a fresh exact healthy runtime witness. 202 means pending/unknown;
`confirmedAt` is historical. Stale/unreachable observations disable controls and
show unknown. Responses identify `real-router-integration`, leave
`routerCompatibilityVerified: false` and report packet acceptance as unmeasured.
No failed integration branch returns synthetic confirmation.
Read-only cache namespaces include source, installation/scope and account; an old
demo or different-installation observation cannot label current integration healthy.

After possible delivery, preserve the original envelope, base and expiry. Approve
a receipt/status read first. A historical receipt prevents a replacement apply;
absence alone does not drain an old queued request. Conclusively complete/fence it
before restoration or another mutation. Keep current runtime and historical outcome
separate after local changes, expiry, restart or drift.

`integration:dispatch -- stop <PRIVATE_MANIFEST>` revokes the automatic epoch as
well as outstanding permits. The running supervisor then makes no further calls;
starting a new explicitly enabled service creates a new epoch. Shutdown waits for
bounded local work and fences late replies. Neither stopping a service nor expiry
of a local lease proves a remote SSH command ended. Preserve uncertain envelopes
and perform receipt reconciliation or a reviewed remote generation fence before
restoration/uninstall; never treat a local kill as remote drain.

At handoff record the exact reviewed source, batch hashes, measured/unavailable
checks, private evidence locations, dispatch state, final router installation and
ownership of retained recovery/key backups. Household production remains blocked
by the documented non-atomic transition and unmeasured target gates.

## Prepared client observation

The [temporary client probe](../tests/client-probe/README.md) has four passing
offline fixtures. After separate approval, its short-lived helper may bind only the
explicit protected LAN address and create an unused private mode-600 log. Its URL
fragment capability and downloaded browser observations remain private.

One foreground WebSocket sends fresh nonces without reconnecting. The documented
provider candidate is [Postman Echo](https://learning.postman.com/docs/reference/developer-resources/echo-api/),
`wss://ws.postman-echo.com/raw`; browser-Origin acceptance, uptime and RTT are
unmeasured. Baseline both admitted and protected clients before mutation. Provider
failure, missing adult echoes or uncertain clock/lifecycle makes the trial unavailable.
Echo results are application observations only. Correlate approved router timestamps,
actual source interface/family and acceleration separately; the probe never declares
packet acceptance. A later expiry needs its own short observation window.

## Check a supplied empty-installation witness

This local read-only gate consumes an already supplied raw version-1 RPC observation;
legacy status JSON is insufficient. It generates no router command and makes no
network call. Replace the argument placeholders with independently established
values, and supply the private capture through stdin:

```sh
node tests/empty-witness.ts EXPECTED_GENERATION MIN_ROUTER_TIME MAX_ROUTER_TIME < /absolute/private/rpc-observation.json
```

`EXPECTED_GENERATION` must come from independent installer-journal evidence for
this same activation, never from the response being checked. It must be exactly
64 lowercase hexadecimal characters. Supply explicit trusted inclusive router-time
bounds: positive integers through 2147483647, with minimum no greater than maximum.
Do not guess the bounds from `Date.now()`.
Checking supplied bounds does not certify capture freshness, clock synchronization,
monotonic lifecycle or the caller's window; final rehearsal needs inspected evidence.
The CLI limits input to 128 KiB of ASCII and waits at most ten seconds for EOF.
It imports the production RPC parser and full runtime-health predicate.

The witness requires exactly revision 0, empty people/pauses/schedules and both DoH
arrays, no current operation or receipt, no errors, and complete healthy empty
runtime state. Required IPv6 capability remains part of the service contract;
unavailable or missing evidence does not pass. A successful result validates supplied
data only: it proves neither transport authenticity, admitted/protected scope,
lifecycle completion, adult probes, exact uninstall restoration, packets nor approval.
Only `PASS_EMPTY_WITNESS` exits 0; `FAIL` and `UNAVAILABLE` exit nonzero. Output keeps
router compatibility unverified, packet acceptance unmeasured and restoration unverified.
