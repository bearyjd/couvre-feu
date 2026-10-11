# Spike 004 — partial read-only target inspection

Status: **inspection evidence recorded; empty-installation rehearsal not ready**.
This supplements [spike-001](spike-001.md) without changing that earlier snapshot.
An explicitly approved read-only collection ran on 2026-10-11. Raw capture,
network identities, key records and backup details remain private. No target
mutation, Couvre-feu installation or on-router uninstall was performed.

The collection reached its final boundary and deliberately returned exit 2 to
retain unresolved checks. This was not an SSH transport failure, activation pass
or permission to retry. Further target reads need a new exact reviewed approval.

## Established observations and their limits

| Observation | What it establishes |
|---|---|
| GL firmware 4.8.3; OpenWrt 21.02-SNAPSHOT | Current firmware identity; no installation, upgrade or enforcement compatibility result |
| BusyBox 1.33.2 | Recorded version; not availability or compatible flags for every applet |
| iptables and ip6tables 1.8.7, legacy backend | Individually callable executables and both-family saved rules |
| conntrack 1.4.6; ipset 7.6 | Individual presence/version, without eviction or set mutation tests |
| fw3, jsonfilter, timeout, sha256sum, UCI and awk present | Tool discovery; required parser, argument and runtime semantics still need evidence |
| Standalone `stat` absent | Concrete metadata-dependency blocker; BusyBox `stat` availability and required formats remain untested |

The timeout guard completed, but this does not validate every shipped timeout use.
The unsupported desktop `awk -W version` option does not mean awk is absent or the
production parser is broken. The shipped policy/RPC parser uses POSIX AWK;
jsonfilter presence does not demonstrate that parser's target behavior.

Source review shows installer/uninstaller recovery-parent metadata checks reject
missing `stat` before install-lock creation, staging or managed writes. This is a
fail-closed prerequisite boundary, not a tested target installation. Metadata is
needed for ownership, modes, sizes and filesystem identity; guessing permissions
or substituting an untested applet would weaken restoration guarantees.

## Captured topology

Saved IPv4/IPv6 fw3 forwarding hooks precede established-connection acceptance.
Offline host-AWK checks accepted the captured parent-chain shapes. These are static
snapshot results, not execution of the shipped rules/parser on the target, native
schedule acceptance, foreign-set ownership or packet cutoff.

Existing GL MAC blocking, DNS dispatcher marks and LAN DNS leak-drop ordering
remain present. Fixed include hashes were recorded; contents, ownership and reload
behavior were not established. No exhaustive ipset-name or staging/lock inventory
was collected, so absent managed paths do not prove conflict-free activation.

dnsmasq owned the captured TCP/UDP DNS listeners on network and loopback bindings.
Interface binding does not establish external reachability. An AdGuard boot
link existed, but no matching process-name line was emitted; that does not prove
enabled state, definitive process absence or application health. Adult DNS behavior
and any future child redirect still require separate probes.

No LAN IPv6 address or route appeared in this snapshot, and RA/DHCPv6 were disabled
while some IPv6 settings remained. IPv6 firewall tools/rules were present. This is
neither permanent IPv6 closure nor real IPv6 coverage; unavailable IPv6 cannot be
counted as a packet pass or used to relax the full-health contract.

Selected offload modules/refcounts were captured, with no FLOWOFFLOAD rule observed.
Neither fact establishes acceleration disabled, active or covered by enforcement.
Clock output was plausible; synchronization, skew and scheduling/DST truth remain
unproved.

## Identity and recovery gaps

The scoped neighbor renderer failed with an AWK syntax error. Although control
identity extraction and scoped lease records produced private evidence, fresh
target neighbor state and unique current ownership were not rendered. Those partial
records cannot satisfy admission/protection checks or prove client traffic origin.

Expected Couvre-feu managed/recovery paths were absent. Provisioning-backup existence
was observed, but metadata could not be read without `stat`; backup usability,
independent recovery access and exact restoration remain unverified.

Before an empty-policy rehearsal, require reviewed metadata/tool compatibility,
corrected fresh scoped identity evidence, complete conflict/original-file inventory,
trusted clock evidence, a usable protected recovery channel and simultaneous adult
DNS/access probes. The final approved batch must bind source/fixtures, positive
mutation-child completion/drain, typed empty runtime witness and exact restoration.
Receipt absence, timeout or a missing lock does not prove completion.

Runtime service-key confinement, packets, acceleration, IPv6, service-off expiry,
reload/reboot/upgrade and actual app round trips remain separate unresolved gates.
The [acceptance record](acceptance-004.md) retains them. Inspection clears neither
the non-atomic transition production blocker nor household readiness.
