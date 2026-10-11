# Integration acceptance 004

Status: **implemented source; author checks recorded, final independent gates pending**.
Author evidence reports 70 service/schema scenarios, 15 browser scenarios,
43 installer fixtures and four offline client-probe tests passing. Typecheck passed;
the final rollback-journal guard additionally passed three focused configuration tests.
The broad 73-core/36-RPC run is still running. Genuine BusyBox ash/awk/timeout,
independent final review and exact-head CI remain pending. These host fixtures and
local wire/parser agreement establish no target compatibility or packet acceptance.
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
