# Couvre-feu

Router-local internet pause and schedules, an authenticated fictional parent demo, and a separate operator-dispatched one-device integration path. The shell core targets GL.iNet GL-XE3000 / OpenWrt 21.02 / fw3 + legacy iptables. Integration source implements exact policy CAS, durable receipts and asynchronous SSH; it is not installed or accepted on the target router. Real packet behavior and household production remain pending; companions, activity collection and bonus grants are later work.

AGPL-3.0; see [LICENSE](LICENSE). The original [PRP-001](docs/prp/PRP-001-enforcement-core.md) and [inspection report](docs/spike-001.md) explain the target. [Enforcement contract](docs/enforcement-contract.md), [acceptance and recovery](docs/acceptance-001.md), [parent PWA specification](docs/prp/PRP-002-parent-pwa.md), [policy service specification](docs/prp/PRP-003-policy-service.md), and [companion limits](docs/companion-capabilities.md) describe each phase. [PRP-005](docs/prp/PRP-005-domain-observations.md) is a proposal only for privacy-scoped domain observations; collection stays off. No Fengard source was copied.

## Run the local parent demo

Use Node 26.8.1 and npm 11.19.0. Install locked dependencies with `npm ci`, then run these in separate terminals from the repository:

```sh
npm run demo:router
```

```sh
npm run demo:start
```

```sh
npm run demo:bootstrap -- bryn
```

Open `http://localhost:4173`, enter the generated one-use token and create a demo passkey. Bryn is a fictional parent assigned only Alex; `jd` creates a fictional administrator token. Permissions are fixed by the server. The app provides pause, timed pause, resume, schedule explanations, device enrollment evidence and read-only offline status. Device evidence shows policy enrollment, source and age; it does not show presence or activity. “Recent alerts in this browser” retains scoped operational warnings and verified recoveries; its history is local and partial. Usage, domains and app history are unavailable.

The listener binds to loopback, and the demo has no SSH or production-router transport. Its separate fake engine owns expiry while the service is stopped. Local passkeys are tied to this localhost origin; household enrollment and private HTTPS deployment are separate work. The [activity prototype](docs/activity-evidence-prototype.md) runs fictional focused-browser interval checks; it collects no household data. The [companion guide](docs/companion-capabilities.md) describes planned Android, ChromeOS, iOS and Windows coverage and limits. [Demo runbook](docs/demo-002.md), [PWA acceptance](docs/acceptance-002.md), [service acceptance](docs/acceptance-003.md), and [dependency review](docs/dependencies-002.md) explain scenarios, reset, tested behavior and remaining gates.

```sh
npm run typecheck
npm run test:service
npm run test:web
```

## Operate the separate integration path

Before unattended router maintenance, follow the [operator SSH agent guide](docs/runbooks/operator-ssh-agent.md).

Use the [integration runbook](docs/integration-004.md), [PRP-004](docs/prp/PRP-004-router-integration.md) and [acceptance record](docs/acceptance-004.md). This limited mode admits one explicitly bound person/device/network MAC, with protected adult/control identities and a separate owner-only manifest/database outside the source tree. It selects an agent-held public identity and pinned host record; it never reads a private key or seeds demo accounts. Startup does not enroll the router or invoke SSH.

Replace the quoted placeholders with reviewed private absolute paths and account identifiers. The first commands are local; `execute` invokes SSH and requires approval of that exact prepared invocation first:

```sh
npm run integration:start -- "<PRIVATE_MANIFEST>"
npm run integration:bootstrap -- "<PRIVATE_MANIFEST>" "<ACCOUNT_ID>"
npm run integration:dispatch -- prepare "<PRIVATE_MANIFEST>" "<UNUSED_PRIVATE_PERMIT>" observe
npm run integration:dispatch -- execute "<PRIVATE_MANIFEST>" "<PRIVATE_PERMIT>" "<EXACT_SCRIPT_SHA256>"
npm run integration:dispatch -- stop "<PRIVATE_MANIFEST>"
```

`prepare` writes a private review artifact containing fixed argv and exact stdin; it does not connect. Each permit covers one invocation, expires after 15 minutes and has no automatic retries. HTTP requests and app polling only read cache or persist pending intent. Apply needs a separately approved cached observation no older than 30 seconds. Missing receipts, local timeouts and stopped processes cannot prove a delayed remote request is drained. Historical acceptance, fresh runtime health and real packet measurements are distinct; caches separate source, generation and account.

The approved supplemental read-only inspection reached its deliberate exit-2 boundary with unresolved checks; [spike-005](docs/spike-005.md) records the findings. Standalone `stat` and callable `od` are missing, and BusyBox reports `stat: applet not found`; source review shows the metadata prerequisite rejects before installer/uninstaller staging or managed writes. Installation remains blocked, and an exact firmware-compatible package/dependency/rollback plan is unverified. No Couvre-feu writes or package installation occurred. One child had a fresh matching neighbor; the other was `FAILED` without a MAC and was not enrollable at that instant. User-reported primary adult router-admin access does not establish fresh router-side binding, continuous connectivity/DNS probes or tested recovery action. The earlier snapshot showed no LAN IPv6 address or route; offload, recovery and packet evidence remain unresolved. The next inspection requires fresh exact-command approval. Before one-device enrollment, an approved scoped empty activation/uninstall must restore originals, modes and prior absence exactly while protected adult/control access remains usable. A temporary separate service key must pass runtime restrictions before enrollment. Every live read, apply, recovery, retry and disruptive test needs its disclosed approval. Production remains blocked by non-atomic changed-policy/drift/reload transitions and unmeasured IPv6/offload/packet gates.

The temporary [client probe](tests/client-probe/README.md) is prepared and tested offline only. Public WebSocket echoes are application observations, not packet acceptance or proof of family/offload coverage.

## Local verification

```sh
sh tests/run.sh
sh tests/acceptance.sh --preflight
sh tests/acceptance.sh --fixtures
```

The runner executes installer recovery fixtures, offline probe fixtures, core/RPC fixtures and available shell checks. Fixtures use private marked roots below `/tmp/couvre-feu-*`, with simulated router tools. They do not prove packet forwarding, stream cutoff, DNS behavior, target ash/awk compatibility or firmware persistence. The acceptance script defaults to read-only local prerequisites; `--fixtures` runs local fixtures, while `--installed` is a separately approved read-only router invocation.

Reviewed releases include [PR #3](https://github.com/bearyjd/couvre-feu/pull/3) for RPC/integration, [PR #4](https://github.com/bearyjd/couvre-feu/pull/4) for the supplied empty witness and [PR #5](https://github.com/bearyjd/couvre-feu/pull/5) for the partial inspection record. PR #5's exact-head [CI](https://github.com/bearyjd/couvre-feu/pull/5/checks) passed 156 router/probe fixtures, 80 service/schema tests and 15 browser scenarios, including genuine BusyBox ash/awk/timeout checks. CI BusyBox is distinct from the target vendor build and its required tool semantics. See [acceptance-004](docs/acceptance-004.md) for evidence limits; source review and fixtures establish neither installed compatibility nor real packet behavior.

## Installation boundary

`router/install.sh` validates and stages by default; only `--activate` installs files and applies enforcement. Even staging on the router needs approval of its exact invocation. Scoped integration uses `--rpc-allow <TEST_NETWORK_MAC>` and protected identities; legacy installations require a separately reviewed migration. No live activation or on-router uninstall acceptance has occurred.

Installation records original contents, permissions and absent paths before mutation. The journal and expected checksums protect against overwriting unrelated later changes. `router/uninstall.sh` restores originals only after drift checks; it refuses destructive restoration on drift. Preserve the journal and changed files for explicit resolution. Durable cleanup intent and uninstall phase markers block ordinary mutations through interrupted recovery; safe retries validate remaining owned objects and exact originals. Only validated durable zero-owned-mutation proof skips recovery firewall reload; partial-owned cleanup still reloads. Read the recovery runbook before activation. Do not delete the journal or replace refusal with blanket firewall restoration.

The installer does not install an SSH key. A future approved manual dedicated-key setup uses this authorized-key prefix:

```text
command="/usr/sbin/cfctl-ssh --rpc-only",no-port-forwarding,no-agent-forwarding,no-pty ssh-ed25519 <dedicated-public-key> <key-label>
```

Dropbear runtime restriction remains untested. Keep a separately protected recovery session and original authorized-key bytes/mode before any approved edit; do not reuse an unrestricted administrator key for the service.

## Router interface

These are reference commands for a future approved installation; no live command is authorized merely by appearing here.

| Command | Behavior |
|---|---|
| `cfctl status --json` | Desired/confirmed revision, effective pauses, observed sets, drift, capabilities and errors |
| `cfctl pause child` | Indefinite manual pause for all assigned MACs |
| `cfctl pause child --until 1800000000` | Manual pause ending at an absolute Unix epoch |
| `cfctl resume child` | Remove manual pause; an active schedule can still block |
| `cfctl expire` | Router-local expiry and policy reconstruction, normally from minute cron |
| `cfctl sync` | Read bounded desired JSON from stdin; apply and return observed status |
| `cfctl rpc-status --json [operation_id]` | Read accepted policy, installation generation, receipt and current runtime witness |
| `cfctl rpc-sync` | Exact generation/revision/digest CAS envelope from stdin; persist acceptance receipt, then apply |

The `--rpc-only` service wrapper admits only the two RPC commands; legacy commands above need a separately authorized management path. Accepted history retains 128 identities without eviction and fails closed for new acceptance at capacity. `check` is the local dependency/parser gate; `apply-fw` is include reconstruction. `remove-fw` is internal recovery. A status exit or receipt alone is insufficient: require fresh exact identity, healthy runtime/address coverage and no drift/errors. `routerCompatibilityVerified=false` remains explicit.

Example policy uses a fictional child MAC `02:00:00:00:00:20`; a fictional protected adult could be `02:00:00:00:00:10`. Neither is an enrollment instruction:

```json
{"version":1,"revision":1,"people":[{"id":"child","macs":["02:00:00:00:00:20"]}],"pauses":[],"schedules":[{"person":"child","id":"school","weekdays":["Mon","Tue","Wed","Thu","Fri"],"start":"22:00","stop":"06:30"}],"doh":{"ipv4":[],"ipv6":[]}}
```

Each MAC belongs to one person; protected overlap and unresolved/ambiguous current SSH identity are refused. Protection persists for cron/include execution. Sync requires a newer revision for changed policy; identical same-revision sync is idempotent and conflicting/stale revisions are rejected. `until:0` means indefinite. The bounded schema allows at most 64 people, 256 assigned MACs, 256 input schedules, at most 256 expanded per-device native windows, and 256 DoH addresses per family; revisions/epochs are integers at most 2147483647. JSON is normalized to one atomically replaced TSV state file at `/etc/couvrefeu/state`; runtime confirmation/lock/error data are auxiliary. Do not edit state by hand. The shipped strict POSIX awk parser intentionally accepts a bounded policy subset, not arbitrary JSON strings; target runtime behavior remains a gate. Sync input has a ten-second pre-lock deadline; the new timeout dependency is unverified on the router.

## Enforcement limits and PRP corrections

Manual pause and schedule decisions enter an unconditional early forwarding hook before established acceptance, with LAN-scoped outbound MAC rules and inbound destination/time mirrors for fresh unambiguous child IP mappings. Uncertain child addresses are omitted while plausible protected addresses retain exclusions; strict sync/pause require coverage for active policy, and inactive policy needs no offline-child address proof. Native fw3 schedule rules are retained with early time-match mirrors because zone-only rules cannot stop an existing stream. Native fallback alone does not guarantee the five-second cutoff if helpers fail. Native rules use local time (`utc_time=0`), early mirrors use `--kerneltz`, and cross-midnight windows split into two day-adjusted halves with exclusive stop boundaries. Clock, DST and accelerated-flow behavior require target testing.

IPv4 kids DNS redirection includes a narrowly scoped UDP INPUT allowance to precede GL leak drops; it must be validated with GL marks without editing dnsmasq or WAN configuration. IPv6 forwarded external DNS is blocked rather than NAT6 redirected; local UDP/53 allowance is scoped to validated observed router IPv6 addresses. This is a deliberate PRP deviation, with local IPv6 DNS usability still requiring verification. Known DoH address lists give limited bypass resistance and need a future refresh owner. Cellular, VPNs, unknown/rotating MACs and unlisted encrypted resolvers are outside the claimed coverage. Adults and existing GL controls must remain unaffected.

Healthy unchanged `expire`, `apply-fw` and identical same-revision sync verify actual objects and leave kernel rules/sets and conntrack intact. Fresh address/protection, effective policy or configuration changes and drift require reconstruction; higher revisions deliberately rebuild. Persistent native configuration and kernel witnesses are both checked before reporting health.

Reconstruction for changed policy, drift or reload is **not atomic**: it can briefly open enforcement, and a mid-apply failure can leave enforcement open until successful repair. Production activation is blocked pending explicit design acceptance and actual integration evidence for this behavior. Local fixture passes do not remove this gate.

Timed pauses expire through router cron even if the service is absent; normal cron tolerance is about one minute after expiry, subject to clock/cron health. Firmware file preservation is configured, but actual upgrade compatibility and enforcement recovery are unverified. This package has no production-readiness claim.
