# Integration acceptance 004

Status: **implemented source; target acceptance pending**.

## Initial source checkpoint

At `d070ccf`, independent code/security review approved source. The verifier passed
typecheck, 70 service/schema scenarios, 15 browser scenarios, 43 installer fixtures
and four offline client-probe tests. The author additionally recorded three focused
rollback-journal configuration checks. Full 73-core/36-RPC completion and genuine
BusyBox ash/awk/timeout acceptance were not established at this checkpoint.
[PR #3](https://github.com/bearyjd/couvre-feu/pull/3) records the independently reviewed
release identity and final evidence; its [checks](https://github.com/bearyjd/couvre-feu/pull/3/checks)
are authoritative for final exact-head CI. This checkpoint is not a claim about
later revisions or future checks. Host fixtures and local wire/parser agreement
establish no target compatibility or packet acceptance.
No assistant target command ran this session; inspection awaits explicit approval.

## Local checks

Run from the repository root in an authorized local test environment:

```sh
sh tests/acceptance.sh --preflight
sh tests/run.sh
npm run typecheck
npm run test:service
npm run test:web
python3 tests/test-client-probe.py
```

Fixtures use temporary local storage/fake transport. Browser/service tests bind
loopback. Record runtime versions, command, source identity, totals and failures.
Host sh alone is not BusyBox ash/awk/timeout proof. Run the router fixture suite
under genuine BusyBox as well; no local pass authorizes live use.

| Required local evidence | Source contract and final verification condition |
|---|---|
| Parser and bounds | Reject duplicate/unknown fields, malformed identity, oversized/deep/non-ASCII/trailing JSON and open stdin within deadline; local expiry remains available |
| Exact CAS | Generation/revision/digest checked under lock; concurrent/local/same-revision different-policy changes conflict before writes |
| Durable acceptance | Crash boundaries preserve policy plus exact receipt together; replay writes nothing and retains original expiry; conflicting reuse fails |
| Receipt capacity | 128 accepted identities retained; next new acceptance fails closed while exact historical lookup/replay works |
| Lifecycle and scope | Legacy mutations clear current identity; expiry preserves it; protected/other MACs refuse; journal/scope mismatch and delayed old-generation requests reject |
| Async worker | Deferred transport sees no SQLite transaction; one unresolved operation, durable claims/epochs and stale-callback fences hold across processes |
| Dispatch permits | No permit means zero transport calls, including GET/polls/restart; exact steps consumed once; changed payload/target/retry refused |
| Unknown delivery | Consumption/spawn/reply/completion crash, timeout and lease takeover never fabricate no-delivery or reapply without conclusive fence |
| SSH boundary | Fixed argv/remote grammar; host/key/agent failure, forwarding, prompts, malformed or excessive output fail visibly without fake fallback |
| HTTP/storage/cache | Auth/CSRF/roles/preconditions remain; unsafe/foreign/demo config and lstat DB/WAL/SHM/`-journal` symlinks refuse; source/generation/account caches stay separate; historical success cannot replace fresh health |

## Separately approved live measurements

Every row below is **unperformed/pending**, including on-router uninstall. Freeze
the exact script, target, one verified test MAC, protected recovery host, probe
endpoints, timestamp method, maximum attempts and rollback before approval.
Keep raw identities/captures private; publish only sanitized results/source hashes.

| Gate | Measurement and required result |
|---|---|
| Target prerequisites | Fixed firmware identity; individually callable conntrack/ip6tables/timeout; clock/timezone; GL marks/includes; actual DNS ownership; current IPv6/offload state |
| Key confinement | Approved allowed-status, unsupported-command and disallowed SSH-feature checks; no shell escape, arbitrary command, forwarding or mode selection |
| Empty install/uninstall | Scoped empty activation; protected adult/control access/DNS unchanged; exact originals, modes and prior absence restored; no owned leftovers; pass before enrollment |
| Admission | Fresh unique supplied network MAC; protected/SSH overlap and ambiguous/shared/stale attribution reject before writes |
| IPv4 cutoff | Timestamp actual continuing and new client-origin traffic; pause stops both within five seconds with acceleration left active |
| Resume and expiry | Resume clears manual pause while schedule can remain; service-off timed expiry occurs within predeclared tolerance without restart renewal |
| DNS and inbound UDP | Client DNS redirect/known DoH/DoT/DoQ blocks measured; adult DNS unchanged; continuing inbound UDP blocked while applicable pause/schedule remains |
| IPv6 | Test actual globally routed client IPv6 and relevant endpoints; unavailable IPv6 is unavailable, never pass |
| Acceleration | Measure active offload coverage and existing-session cutoff; absent FLOWOFFLOAD rule alone proves nothing |
| Time/resilience | Actual timezone/DST/cross-midnight, reload/reboot and firmware persistence measured only in separately approved batches; upgrade remains unperformed |
| Uncertain outcome/teardown | Approved lost-response observation resolves exact receipt; remote completion/generation fence precedes restoration; no unsafe replay |

Probe traffic must originate on the admitted interface and a separate protected
adult host. A router ping, buffered video or viewport screenshot cannot establish
packet cutoff. Client endpoints and timestamp capture remain manual preparation
until available; the service's runtime witness is a separate check.
The [prepared WebSocket probe](../tests/client-probe/README.md) has offline evidence
only. [Postman documents its public echo](https://learning.postman.com/docs/reference/developer-resources/echo-api/);
live availability/browser compatibility is untested. Nonce echoes are application
observations, with router-time correlation, family, acceleration and packet gates
separate. This helper never reports packet acceptance or retries a remote apply.

## Recording outcomes

For each row record `pass`, `fail`, `unavailable` or `not run`, exact source/batch
hash, time interval, measured values and private evidence path. Report historical
acceptance, current runtime health and packet measurements independently. Actual
phone usability, key confinement, upgrade, uninstall-on-router, IPv6 and offload
must remain pending unless their own evidence exists.

Process-kill/rename/SQLite fixtures do not establish physical power-loss durability.
Keep household production blocked by the existing non-atomic changed-policy/drift/
reload transition even if the one-device normal-path measurements pass. Record final
dispatch/router state, retained recovery/key records and any incomplete milestone.

## Supplied empty witness gate

This additional local read-only check does not revise the PR #3 checkpoint above
or establish a live rehearsal result:

```sh
node tests/empty-witness.ts EXPECTED_GENERATION MIN_ROUTER_TIME MAX_ROUTER_TIME < /absolute/private/rpc-observation.json
```

Supply raw version-1 RPC JSON, not legacy status JSON. Independently establish the
expected generation from the same activation's installer journal and explicit
trusted router-time bounds; deriving generation from the response or time bounds
from `Date.now()` alone defeats the gate. Input is bounded to 128 KiB ASCII with a
ten-second EOF deadline; parsing reuses production code.
The supplied window does not itself prove freshness, clock synchronization,
monotonic lifecycle or its own truth; those require inspected capture/clock evidence.

Require exact empty revision-0 policy, empty people/pauses/schedules/DoH arrays,
null current operation/receipt, empty errors and the existing full-health predicate.
IPv6 capability is still required; unavailable evidence is not a pass. The result
does not authenticate the capture or certify scope/protection, completed lifecycle,
adult connectivity/DNS, uninstall restoration, packet behavior or authorization.
Only `PASS_EMPTY_WITNESS` exits 0; failure/unavailable exits nonzero and never relaxes
the existing service IPv6/full-health requirement.

## Later read-only inspection checkpoint

The approved collection documented in [spike-004](spike-004.md) reached its deliberate
exit-2 boundary with partial prerequisite evidence; it updates the earlier pending-
inspection note only. Firmware/tool versions, saved fw3 topology and DNS listener
ownership were observed, with no LAN IPv6 service in that snapshot. Standalone
`stat` was absent; BusyBox `stat` compatibility remains untested. A scoped renderer
error prevents fresh target-identity acceptance. No installation, target mutation or
on-router uninstall occurred. Metadata, protection/recovery/adult probes, clock,
offload, AdGuard health, key confinement, lifecycle/restoration and packet gates
remain unresolved; this checkpoint neither changes the PR #3/#4 source evidence
nor approves an empty-policy rehearsal or household production.
Those remain separate evidence gates; no new test total or live pass is claimed here.
