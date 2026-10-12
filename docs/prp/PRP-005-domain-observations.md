# PRP-005 — privacy-scoped domain observations (design proposal)

Status: **proposal only. Nothing here is implemented, installed or enabled. Collection stays OFF.** No code, schema, router command or UI changes accompany this document. It needs explicit owner review and approval before any implementation PR. Statements about router capability (NFLOG, tooling, memory) are **unverified** on the target GL-XE3000 / OpenWrt 21.02; the cited router state is from [spike-001](../spike-001.md), [spike-005](../spike-005.md) and the [enforcement contract](../enforcement-contract.md).

## Goal

Give a parent an honest, coarse answer to "which sites did this child's devices look up, roughly when?", limited to enrolled children's known devices, without breaking the project's existing privacy posture ([companion capabilities](../companion-capabilities.md), [activity prototype](../activity-evidence-prototype.md)).

## Non-goals

- No TLS interception, no custom CA, no decrypted traffic.
- No URLs, paths, query strings, page titles, screenshots or keystrokes.
- No adults, no protected management identities, no unknown or unassigned MACs.
- No policy authority: observations never pause, resume or schedule anything.
- No claim of visits or time. Three distinct things, never merged or summed:

| Term | Meaning |
|---|---|
| Observation | A DNS lookup for a domain by a child's device was seen. Includes prefetch, ads, trackers, background apps, OS telemetry and retries. |
| Visit | A person intentionally opened a site. Not establishable from DNS. |
| Attention time | Time a person actively used something. Needs focus evidence (companions); see the activity prototype. |

## Candidate sources

All router-side candidates see only traffic that crosses the router. The existing enforcement already redirects kids' IPv4 UDP/TCP port 53 to the router's LAN address, blocks forwarded IPv6 external port 53, and blocks known DoH/DoT/DoQ addresses. That redirect is what makes (a) and (b) possible at all.

| | Source | Needs | Pros | Cons | Coverage |
|---|---|---|---|---|---|
| a | dnsmasq query logging (`log-queries`) | **dnsmasq config change** | Simplest; resolver already parses names; sees cache hits | **Forbidden today**: AGENTS.md and the contract say never change dnsmasq configuration. Logs go to syslog ring or a file, mixing adults' queries with kids' (privacy leak before filtering); restart or reload of the resolver on a shared GL device risks household DNS; GL firmware may overwrite config | Kids IPv4 redirected DNS, adults too (unfiltered at source) |
| b | Passive capture of kids' redirected UDP/53 via a Couvre-feu-owned iptables `NFLOG` rule feeding a small reader | A rule in a `cf_`-owned chain; a reader process; NFLOG kernel module and reader tooling **(availability unverified)** | **No dnsmasq change.** Rule matches only the existing `cf_kids` set, so adult and unknown-MAC traffic never reaches the reader. Fits the existing owned-rule model, install and uninstall. Query names only, with packet range capped to the DNS header plus question (a few hundred bytes), so no payload beyond that | Adds a firewall rule and a long-lived process on a constrained router; rule ordering vs GL marks and flow offload needs testing; UDP only (TCP/53 gaps); parser must be hardened against malformed packets; EDNS/case randomization needs normalization | Kids' IPv4 plain DNS (redirected) and local IPv6 UDP/53 to the router if the rule is mirrored there |
| c | conntrack plus reverse DNS | Read-only conntrack, PTR lookups | No new rule | **Weak.** Yields IPs, not names. PTR is mostly CDN or hosting names, wrong or absent; shared IPs defeat attribution; PTR lookups send child-correlated queries to a third party. Not recommended even as a fallback | Poor |
| d | Companion apps (browser focus, app usage) | Per-platform apps, parent-owned enrollment | Sees through DoH/VPN/cellular; supports focus and attention evidence | Not built; per-platform entitlement and permission limits; self-reported and tamperable; large separate scope | Per device, off-network too |

### Recommendation

**Option (b), as a measurement-first spike, with (d) as the complement later.** Rationale: (b) is the only router-side option that avoids the dnsmasq prohibition, scopes to children at the kernel match (before any software sees a packet), and reuses the owned-rule install, drift and uninstall model. (a) is rejected unless the owner explicitly lifts the dnsmasq rule, which this PRP does not request. (c) is rejected as inaccurate and leaky. If NFLOG or reader tooling cannot be shown to run safely on the target, the outcome is "not feasible on this router" and the work stops at (d) rather than reaching for (a).

### What defeats it

Router capture sees nothing when queries never cross the router as plain DNS:

| Bypass | Effect | Note |
|---|---|---|
| DoH / DoT / DoQ to unlisted resolvers | Invisible | Known-address lists are partial and need a refresh owner; browser "secure DNS" can use new endpoints |
| VPN, iCloud Private Relay, other relays | Invisible | Private Relay also hides names from the network |
| Cellular or other Wi-Fi | Invisible | Device off this network |
| ECH, QUIC | Hides SNI, not DNS | Irrelevant to DNS capture but rules out an SNI fallback; DNS alone remains the signal |
| Hardcoded resolver over TCP, DNS caching, hosts files | Gaps or undercount | A client cache hides repeat lookups; counts are lookups, not use |
| Randomized, rotating or unknown MACs | Child unattributed | Unknown MACs are excluded by design, so undercount |
| Shared or multi-user devices | Misattribution | Attribution is device to child, not person |

Absence of an observation never means a child did not visit a site. Every output must state its coverage limits.

## Data minimization

- Reduce each query name to its **registrable domain (eTLD+1)** immediately in the reader, in memory. Full hostnames, subdomains, query types, client IPs and MACs are not stored. Reduction uses a versioned Public Suffix List snapshot shipped with the release; the PSL version is recorded with the data.
- Stored record: `(child_id, hour_bucket_utc, registrable_domain, count)`. Hourly buckets; no per-query timestamps.
- Only enrolled children's assigned devices attribute to a `child_id`; others are dropped before counting.
- Per-child, per-hour and global caps on distinct domains; overflow goes to a single `other` bucket count.
- **Sensitive-category denylist (option to discuss):** a maintained list of categories (for example health, sexuality, mental health, religion, abuse support lines, crisis resources) whose domains are counted into one `sensitive` bucket without domain names, so a child's help-seeking is never exposed. Categories need a source and a refresh owner. See open questions.
- Optional later: a coarse category mapping from a local, offline list. No per-lookup third-party calls.

## Retention, control and transparency

- **Retention:** 14 days default, hard-deleted by a daily job; owner may shorten, not exceed a bounded maximum (proposal: 30 days).
- **Deletion on unenroll:** removing a child or device deletes that child's observations within one deletion pass, and stops attribution immediately.
- **Parent export and delete:** an authenticated parent can export (JSON) and delete observations for assigned children, subject to existing permission boundaries; actions are audited without recording domains in the audit log.
- **Child transparency:** enabling collection for a child requires showing that child an age-appropriate notice stating what is seen (the sites your devices look up, not what you do on them), who can see it, how long it is kept, and what is not collected (no passwords, messages, pages or photos). The notice text is versioned; the child's acknowledgement or the parent's record that it was shared is stored.
- **Consent model:** off by default, enabled per child by an authorized parent, with a recorded notice version and timestamp. Enabling, disabling and the notice version are visible in the parent UI. Adults get no collection. Legal and school-managed-device considerations are an owner decision (see open questions).
- **Labels:** the UI must say "lookups", never "visits" or "screen time", and show coverage limits and freshness.

## Security

- **On-router buffer:** RAM only (tmpfs), fixed ring of aggregated counters, bounded entries and bytes, oldest-hour eviction. No raw packets or full names on flash. Reader has a CPU and memory ceiling and is killed, not retried, when exceeded. Loss and overflow are counted and surfaced as coverage gaps.
- **Failure isolation:** reader failure or rule removal must never affect enforcement, DNS redirection or the internet pause path. The NFLOG rule is owned, versioned, drift-checked and removed by the installer and uninstaller.
- **Parsing:** treat packets as hostile; bounded length, label-count and compression-pointer checks; fixtures with malformed input.
- **Transport:** only through the existing restricted RPC channel and permit model ([PRP-004](PRP-004-router-integration.md)); a new read-only command is added only after separate review, with bounded request and response sizes. No new listener, no new credential, no push from the router.
- **Integrity:** responses carry generation, PSL version, window and sequence; the service rejects replay and out-of-range buckets, and records loss rather than inventing zeros.
- **Service storage:** observations in the service database, never in the audit log or application logs; parent-scope checks on every read.
- **No third-party lookups by default:** no reputation, category or geo API calls with child-correlated data.
- Raw captures stay private and are never committed, per AGENTS.md.

## Rollout gates

1. **Owner approval of this PRP**, including the dnsmasq decision (reject (a)), consent model, retention and denylist stance.
2. **Fixture tests:** DNS packet parser and eTLD+1 reduction with malformed and adversarial inputs, bounds and overflow, deletion and retention jobs, scope exclusion of adults and unknown MACs. Fixtures do not establish real packet behavior.
3. **Live read-only measurement with one consenting child device**, under per-invocation approval for each router command: confirm NFLOG availability, rule ordering with GL marks, memory and CPU headroom, and that adult DNS and enforcement are unaffected.
4. **Accuracy check:** compare captured lookups with a known script of browsing on the test device; record undercount causes (cache, DoH, TCP) and publish the coverage statement.
5. **UI with truthful labels:** lookups, coverage limits, freshness, consent state and child notice. Collection stays default OFF until this gate passes.

Any gate failure stops the work; the fallback is no collection.

## Open questions for the owner

1. Do you reject dnsmasq query logging (a) outright, or would you ever lift the dnsmasq rule for a narrow, reviewed change?
2. Is a router-resident reader acceptable given the constrained device, or should this wait for a dedicated observer outside the router?
3. Do you want the sensitive-category denylist, and who maintains it? Should sensitive domains be dropped entirely or counted as one `sensitive` bucket?
4. Is 14 days right, and is a 30-day cap acceptable?
5. May a child see their own observations, and should older children be able to view what parents see?
6. What is the consent and notice wording per age band, and is acknowledgement by the child required or is a parent record enough?
7. Are any enrolled devices school-managed or shared with adults, where collection would be inappropriate or require third-party consent?
8. Who owns the PSL and the DoH/DoT endpoint list refresh?
9. Should TCP/53 and local IPv6 UDP/53 be in scope for the first measurement, or only redirected IPv4 UDP/53?
10. Should router-side counts be shown at all before companion evidence exists, given the visit/attention misreading risk?
