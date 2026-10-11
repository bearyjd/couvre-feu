# Couvre-feu

Router-local internet pause and schedules for assigned devices, plus an authenticated local parent-app prototype. The shell core targets GL.iNet GL-XE3000 / OpenWrt 21.02 / fw3 + legacy iptables. The app uses fictional accounts and an independent fake-router process: it cannot control a household router. Real packet behavior, target acceptance and deployment remain pending; companions, activity collection and bonus grants are later work.

AGPL-3.0; see [LICENSE](LICENSE). The original [PRP-001](docs/prp/PRP-001-enforcement-core.md) and [inspection report](docs/spike-001.md) explain the target. [Enforcement contract](docs/enforcement-contract.md), [acceptance and recovery](docs/acceptance-001.md), [parent PWA specification](docs/prp/PRP-002-parent-pwa.md), [policy service specification](docs/prp/PRP-003-policy-service.md), and [companion limits](docs/companion-capabilities.md) describe each phase. No Fengard source was copied.

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

Open `http://localhost:4173`, enter the generated one-use token and create a demo passkey. Bryn is a fictional parent assigned only Alex; `jd` creates a fictional administrator token. Permissions are fixed by the server. The app provides pause, timed pause, resume, schedule explanations and read-only offline status. Usage, domains and app history are unavailable.

The listener binds to loopback, and the demo has no SSH or production-router transport. Its separate fake engine owns expiry while the service is stopped. Local passkeys are tied to this localhost origin; household enrollment and private HTTPS deployment are separate work. [Demo runbook](docs/demo-002.md), [PWA acceptance](docs/acceptance-002.md), [service acceptance](docs/acceptance-003.md), and [dependency review](docs/dependencies-002.md) explain scenarios, reset, tested behavior and remaining gates.

```sh
npm run typecheck
npm run test:service
npm run test:web
```

## Local verification

```sh
sh tests/run.sh
sh tests/acceptance.sh --preflight
sh tests/acceptance.sh --fixtures
```

The runner executes installer recovery fixtures before core fixtures and available shell checks. Fixtures use private marked roots below `/tmp/couvre-feu-*`, with simulated router tools. They do not prove packet forwarding, stream cutoff, DNS behavior, target ash/awk compatibility, or firmware persistence. The acceptance script defaults to read-only local prerequisite discovery. `--fixtures` runs the fixture suite with PRP §8 coverage mapping. `--installed` performs read-only installed checks when deliberately run as router root and still requires approval of its exact live invocation; it does not run packet probes. The merged router baseline passed 43 installer and 73 core fixtures, genuine BusyBox ash/awk/timeout checks and ShellCheck. Independent source review passed at its reviewed head. Final latest-head CI and independent review remain merge gates; their current status is available in [PR checks](https://github.com/bearyjd/couvre-feu/pull/2/checks).

## Installation boundary

`router/install.sh` validates and stages by default; only `--activate` installs files and applies enforcement. Even staging on the router needs approval of its exact invocation. Activation is a later separately approved action with one approved test MAC, protected adults/control client, and reviewed rollback. No live test MAC has been supplied.

Installation records original contents, permissions and absent paths before mutation. The journal and expected checksums protect against overwriting unrelated later changes. `router/uninstall.sh` restores originals only after drift checks; it refuses destructive restoration on drift. Preserve the journal and changed files for explicit resolution. Durable cleanup intent and uninstall phase markers block ordinary mutations through interrupted recovery; safe retries validate remaining owned objects and exact originals. Only validated durable zero-owned-mutation proof skips recovery firewall reload; partial-owned cleanup still reloads. Read the recovery runbook before activation. Do not delete the journal or replace refusal with blanket firewall restoration.

The installer does not install an SSH key. A future approved manual dedicated-key setup uses this authorized-key prefix:

```text
command="/usr/sbin/cfctl-ssh",no-port-forwarding,no-agent-forwarding,no-pty ssh-ed25519 <dedicated-public-key> couvre-feu
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

`check` is the local dependency/parser gate; `apply-fw` is include reconstruction. `remove-fw` is an internal recovery command and is denied by the restricted SSH wrapper. A status process exit alone is not a success signal: consumers must require JSON `ok=true`, matching desired/confirmed revisions and no drift/errors. Active address coverage gaps are explicit through `capabilities.addressCoverageComplete=false` and `incomplete_address_coverage`; expiry/resume/reconstruction still clear obsolete enforcement without claiming healthy active coverage. `routerCompatibilityVerified=false` remains explicit.

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

Timed pauses expire through router cron even if the future service is absent; normal cron tolerance is about one minute after expiry, subject to clock/cron health. Firmware file preservation is configured, but actual upgrade compatibility and enforcement recovery are unverified. This package has no production-readiness claim.
