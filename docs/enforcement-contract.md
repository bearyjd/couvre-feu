# Enforcement contract — router core v1

This describes the current router implementation, not completed packet acceptance. The original [PRP-001](prp/PRP-001-enforcement-core.md) is preserved; its corrected implementation choices are explicit below. No service/PWA is included. [Acceptance gates](acceptance-001.md) govern target runtime, packet behavior and separately approved live actions.

## Commands and confirmation

`cfctl status --json`, `pause <person> [--until <epoch>]`, `resume <person>`, `sync` (JSON stdin), `expire`, and `apply-fw` implement control/reconstruction. `check` is a read-only dependency/parser probe. `remove-fw` is internal recovery and unavailable through `cfctl-ssh`; the wrapper accepts only its explicit control grammar without shell evaluation. Status can exit zero with uncertainty; mutations fail nonzero on failed application. Require JSON `ok`, matching revisions, no drift/errors and sufficient observed evidence, not merely an exit code.

Status fields:

| Field | Meaning |
|---|---|
| `ok` | Current observation agrees with accepted policy and runtime confirmation |
| `desiredRevision`, `confirmedRevision` | Durable desired revision and runtime-confirmed revision; confirmation can be null |
| `desiredPauses`, `effectivePauses` | Stored pause records versus unexpired manual pauses |
| `observed.kids`, `observed.paused` | Actual MAC set observations |
| `drift`, `errors` | Mismatch, interrupted application, busy transaction or other uncertainty |
| `capabilities.ipv6`, `.conntrack`, `.nativeKernelConfirmed` | Backend observations; no guarantee of end-to-end packet acceptance |
| `capabilities.addressCoverageComplete` | Whether required active pause/schedule address coverage is established; gaps return `incomplete_address_coverage` |
| `capabilities.routerCompatibilityVerified` | Explicitly false until separately established compatibility; the current implementation does not assert it |

A successful dependency probe or native-rule witness cannot establish the five-second cutoff, adult DNS safety, acceleration coverage or firmware durability.

## Desired JSON

Required top-level fields are `version:1`, integer `revision`, `people`, `pauses`, `schedules`; optional `doh` requires both address arrays when present. Unknown/duplicate keys, invalid values and conflicting/shared MAC assignment are rejected. The [README](../README.md) provides a fictional example.

| Entity | Fields and bounds |
|---|---|
| People | `id`, `macs`; up to 64 people, 32 MACs/person, 256 MACs total |
| IDs | Lowercase ASCII letter first, then lowercase letters/digits/underscore; at most 32 characters |
| MACs | Canonical lowercase colon-separated nonzero unicast addresses, unique across all people; empty person device list permitted |
| Pauses | `person`, `until`; one per defined person, at most 64; 0 indefinite, otherwise absolute epoch |
| Schedules | `person`, `id`, `weekdays`, `start`, `stop`; defined person, unique person/schedule ID, at most 256 input schedules |
| Weekdays / clocks | Unique nonempty subset of Mon–Sun; `HH:MM` in 00:00–23:59; equal start/stop rejected |
| Expanded windows | At most 256 total per-device native windows after cross-midnight expansion; input count alone is insufficient |
| DoH | `ipv4`, `ipv6`; at most 256 unique addresses each; IPv6 addresses canonicalized for duplicate detection |
| Integers | Canonical nonnegative integer syntax, at most 2147483647 for revision/epoch |

The shipped strict POSIX awk parser accepts a bounded ASCII subset: strings/keys must contain no escapes, Unicode or control characters. Input is limited to 65536 bytes, depth 12, 8192 nodes and 128 characters/string. Sync stages and validates stdin before acquiring the mutation lock, using a ten-second read deadline (`timeout 10 dd ...`). A callable `/usr/bin/timeout` or `/bin/timeout` is a new required dependency; its availability and behavior on the actual router were not established by the spike. The explicit fixture hook `CF_TEST_TIMEOUT="busybox timeout"` exercises genuine BusyBox timeout when available; production uses only the trusted fixed paths. Host/CI timeout behavior cannot establish target compatibility. This deliberately excludes valid general-purpose JSON encodings; future clients must emit this subset, not assume arbitrary JSON serialization is compatible. Actual target ash/awk runtime remains a gate.

Changed policy needs a newer revision; identical normalized same-revision sync is idempotent, and conflicting/stale revisions fail. Pause/resume advance the revision. Resume removes only manual pause; an active schedule still blocks. No bonus or Allow-until exists.

## Durable state and safety

One atomically replaced normalized TSV file, `/etc/couvrefeu/state`, stores version/revision, person-to-MAC ownership, manual pause metadata, schedules and DoH addresses. This replaces the PRP's raw MAC/expiry format. Record kinds are `V`, `R`, `P`, `A`, `S`, `D4`, `D6`; clients use JSON rather than editing TSV. Expired pause metadata can remain for replay equality, while effective membership excludes it.

Persisted protection, serialized mutation locks, confirmation/error records, firewall snapshots/intents and expiry high-water are auxiliary runtime/recovery data. Clock values before 2020 are rejected; expiry uses the greater of current clock and persisted high-water to resist resurrection after backward jumps. Minute cron re-evaluates policy without a service; clock/cron health and target boundary latency remain acceptance conditions.

Protected MAC overlap is refused. Current SSH-client identity must resolve uniquely from validated LAN observations for controlling operations; absence of SSH context does not erase persisted protection for cron/include. Address/lease data are treated as data, never executed. Unknown devices are not quarantined and rotating identities remain a coverage limit.

## Firewall behavior and deviations

Both families use an unconditional early jump to `cf_fwd` before established acceptance; rules inside it remain LAN/interface scoped. Manual pause and schedule mirrors cover outbound source MACs and inbound destinations on `-o br-lan`, using verified current child IP mappings. This closes the inbound established UDP path across a schedule boundary; real packet proof remains pending. Protected destination mappings return without child enforcement. Child IP rules/conntrack eviction require unique fresh attribution through a current DHCP lease (expiry 0 or in the future) or REACHABLE/PERMANENT neighbor observation. Uncertain child addresses are omitted; plausible protected bindings retain destination exclusions even when stale. Strict sync/pause reject missing coverage when an active pause/schedule needs it. Expire/resume/apply-fw can still reconstruct safe rules and clear obsolete MAC/IP enforcement during coverage gaps, but must not report healthy active coverage: `addressCoverageComplete=false` and `incomplete_address_coverage` remain explicit. With no active pause/schedule, stale/offline children need no address proof for confirmation. Omitted neighbor `dev` is accepted only from the fixed `br-lan` collector; IPv6 destination host forms permit only /128, not broader prefixes. DNS-port and DoH destination rejects remain kids-source scoped. Native schedule rules also persist as owned fw3 sections. Cross-midnight windows split at midnight and rotate the second half's weekdays; exclusive stop boundaries become inclusive kernel stops one second earlier. Native `utc_time=0` and early `--kerneltz` use router local-time semantics, subject to timezone/DST acceptance.

Native rules explicitly set `proto=all`: fw3's omitted-protocol default would cover TCP/UDP only. `dest=wan,target=REJECT` may compile through `zone_wan_dest_REJECT` to `reject`, rather than a direct REJECT. Verification requires the complete supported named MAC/time rule in both families, with no extra selectors, and checks earlier rule/chain reachability so a preceding ACCEPT/RETURN cannot silently shadow it. Earlier called chains must have supported non-ACCEPT behavior; unknown nested paths remain pending. The read-only existing `fw3 -q zone wan` command resolves a bounded validated list of concrete WAN devices; the reject path must match exact members and cover all listed devices. Empty, wildcard, partial or unknown mappings keep confirmation pending. This performs no WAN configuration write. Native edits use a private UCI configuration directory (`-c`) and private delta directory (`-t`), then validated journaled replacement/reload; they must not commit unrelated saved deltas.

These choices were checked against official [fw3 rules.c](https://github.com/openwrt/firewall3/blob/master/rules.c), [fw3 main.c](https://github.com/openwrt/firewall3/blob/master/main.c) and [UCI cli.c](https://github.com/openwrt/uci/blob/master/cli.c). No upstream source was copied. Native zone rules alone cannot stop established traffic; broken-helper fallback does not promise stream cutoff.

IPv4 kids TCP/UDP external DNS is DNATed to the validated LAN router address; a narrow kids-only UDP INPUT allowance precedes GL leak protection. IPv6 forwarded TCP/UDP port 53 is rejected rather than NAT6 redirected; local kids UDP DNS allowance uses validated observed router IPv6 addresses. This is a PRP deviation, not a claim that local IPv6 DNS or GL integration is verified. No dnsmasq/WAN configuration change is included. Existing GL controls and protected adults must remain unaffected.

Kernel cleanup first writes an atomic private `runtime/firewall.cleanup` inventory through a `.cleanup.<pid>` temporary file. Retry verification permits recorded exact remaining objects, already-flushed empty owned chains, or absent objects; remaining sets must be unchanged or absent. Foreign references, additions or modified remaining objects are refused. The intent prevents ordinary mutation until internal recovery resumes. Durable uninstall markers and `/etc/.couvrefeu-recovery`/`.done` also block sync, pause, resume, expire and apply-fw before and after locking, even between transient installer locks; only the authenticated installer remove-fw handoff may bypass the filesystem recovery barrier. Status/check remain read-only. Pending `.next` phase markers also gate ordinary mutations. A validated explicit zero-owned-kernel-mutation cleanup proof persists the `no-kernel-mutations` phase; uninstall alone may then skip original-firewall reload to preserve foreign objects. Partial owned mutation still requires cleanup and reload. Activation failure alone never authorizes skipping reload.

Installation defaults to staging and requires explicit activation. Exact-original recovery, drift refusal and resumable uninstall phases are described in the [runbook](acceptance-001.md). Neither file preservation nor local fixtures establish live compatibility. Known DoH lists are limited and have no implemented service refresh owner; cellular/VPN/unknown identities remain outside the claimed coverage.
