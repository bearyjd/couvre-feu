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
| b | Passive capture of kids' redirected UDP/53 via a Couvre-feu-owned iptables `NFLOG` rule feeding a small reader | One rule inside each generation's owned input chain (see [Attachment point](#attachment-point-for-option-b)); a reader process; `kmod-ipt-nflog`, `kmod-nfnetlink-log` and `ulogd` or a custom binary **(none verified present; package installation is currently blocked)** | **No dnsmasq change.** Rule matches only a dedicated per-slot set of **consenting** children's MACs (not the all-children set), so adult, unknown-MAC and non-consenting-child traffic never reaches the reader. Fits the existing owned-rule model, install and uninstall. Copied bytes bounded with `--nflog-size` and `--nflog-threshold` (DNS header plus question), so no payload beyond that | Adds a firewall rule and a long-lived process on a constrained router; BusyBox has no NFLOG reader, so a kernel module and userspace package (or a custom binary) must be added; rule ordering vs GL marks and flow offload needs testing; UDP only (TCP/53 gaps); parser must be hardened against malformed packets; EDNS/case randomization needs normalization | Kids' IPv4 plain DNS (redirected) and local IPv6 UDP/53 to the router if the rule is mirrored there |
| c | conntrack plus reverse DNS | Read-only conntrack, PTR lookups | No new rule | **Weak.** Yields IPs, not names. PTR is mostly CDN or hosting names, wrong or absent; shared IPs defeat attribution; PTR lookups send child-correlated queries to a third party. Not recommended even as a fallback | Poor |
| d | Companion apps (browser focus, app usage) | Per-platform apps, parent-owned enrollment | Sees through DoH/VPN/cellular; supports focus and attention evidence | Not built; per-platform entitlement and permission limits; self-reported and tamperable; large separate scope | Per device, off-network too |

### Recommendation

**Option (b), as a measurement-first spike, with (d) as the complement later.** Rationale: (b) is the only router-side option that avoids the dnsmasq prohibition, scopes to children at the kernel match (before any software sees a packet), and reuses the owned-rule install, drift and uninstall model. (a) is rejected unless the owner explicitly lifts the dnsmasq rule, which this PRP does not request. (c) is rejected as inaccurate and leaky. If NFLOG or reader tooling cannot be shown to run safely on the target, the outcome is "not feasible on this router" and the work stops at (d) rather than reaching for (a).

### Attachment point for option (b)

Facts from the [enforcement contract](../enforcement-contract.md): IPv4 kids port 53 is DNATed to the LAN router address in `nat` PREROUTING (via the `cf_dns` dispatcher), followed by a kids-only UDP INPUT allowance in `filter` `cf_input`. Raw or mangle PREROUTING sees the **pre-DNAT** destination and would log queries aimed at external resolvers, which is not what is wanted. Therefore:

- **Table and chain:** `filter` INPUT, reached through the `cf_input` dispatcher, post-DNAT, so every logged query is addressed to the router's own resolver.
- **Position:** the `NFLOG` rule must come **before** the kids-only UDP/53 `ACCEPT`. NFLOG is non-terminating, but an earlier `ACCEPT` (or a GL leak drop that precedes it) would skip the rule entirely. The first measurement must verify ordering against GL marks.
- **Match:** `-i br-lan -p udp --dport 53 -d <router LAN address>`, plus `-m set --match-set cf2_<slot>_o src`. `cf2_<slot>_o` is a **new dedicated `hash:mac` set holding only the MACs of children with recorded consent** (a subset of `cf2_<slot>_k`, which holds all enrolled children). `src` matches the source MAC, so the kernel itself enforces per-child consent: adults, protected identities, unknown MACs and enrolled children without consent never match and never reach the reader. Matching the all-children `_k` set is explicitly not proposed, because it would send a non-consenting child's DNS to the reader.
- **Options:** `--nflog-group <n>`, `--nflog-size` and `--nflog-threshold` to bound copied bytes and batching. `--nflog-range` is not used; it is non-functional on the supported kernels.
- **IPv6:** local kids UDP/53 to validated router IPv6 addresses gets a mirrored rule in the IPv6 input chain, only if the owner includes it (open question 9). Forwarded IPv6 external DNS is rejected today and is not observed.

**Fit with the generation scheme.** The current design replaced the PRP-001 `cf_kids` set with immutable per-slot sets. Stable `cf_fwd`, `cf_input` and IPv4 `cf_dns` dispatchers jump to slot objects: filter chains `cf2_<slot>_f` and `cf2_<slot>_i` and MAC sets `cf2_<slot>_k`/`p` (and, proposed here, `_o`) for slots `a` and `b`. The observation rule is therefore **not a standalone rule** on a stable chain:

1. Each generation's input chain `cf2_<slot>_i` contains the `NFLOG` rule immediately before its UDP/53 `ACCEPT`, matching that slot's own `cf2_<slot>_o` set. The set is immutable like its siblings, so there is no flush window where the rule matches nothing or everything.
2. A policy change stages a complete inactive generation, including the observation rule. The existing guarded dispatcher switch then moves logging to the new slot with the rest of enforcement, so it follows slot switches and set membership changes with no extra transition step.
3. Enabling or disabling collection for a child is a generation change (a child's MAC is added to or omitted from the staged `cf2_<slot>_o` set; with no consenting children the set is empty and the rule may be omitted), covered by the same digest, receipt and drift checks. Collection state is part of what the router confirms, never a side flag.
4. Behavior of observation during dispatcher switches and the transition guards (`cf2_<slot>_g`) is **unverified**; it is an explicit item for measurement gate 4. Until measured, any switch window is treated as a possible coverage gap and gaps are never inferred as zero.
5. This needs code changes in a later PR, not here: the owned-set allowlist (`cf_owned_set`, `router/lib/firewall.sh`, currently `k|p|d4|d6|u`), the matching `--match-set` reference pattern in the owned-rule checks, and the owned-chain and rule allowlists must be extended to admit `_o` and the NFLOG rule. The transition descriptor inventory, accepted-policy digest, drift checks and uninstall must also cover the new set and rule, and a consent change must flow through the same policy revision and receipt path. Install, uninstall and recovery inventories must list the rule so that an uninstall removes it and a drift check detects its absence. The reader's group number is part of the inventory.

The reader process is outside the firewall inventory; if it stops, the rule only drops copies into the netlink socket and enforcement is unchanged.

### What defeats it

Router capture sees nothing when queries never cross the router as plain DNS:

| Bypass | Effect | Note |
|---|---|---|
| DoH / DoT / DoQ to unlisted resolvers | Invisible | Known-address lists are partial and need a refresh owner. Browser DoH defaults matter: Firefox enables DoH by default in some regions, Chrome and Edge only auto-upgrade to DoH when the system resolver is a known DoH-capable provider; here the system resolver is a DNAT'd private LAN address, so that upgrade should not trigger (to be confirmed by measurement), and Safari/Apple devices can use encrypted DNS profiles. Android **Private DNS** (DoT, "Automatic") tries port 853 |
| VPN, iCloud Private Relay, other relays | Invisible | Private Relay also hides names from the network |
| Blocking Private Relay / Private DNS to force fallback | Visible again, with side effects | Networks can block these (Android Private DNS falls back or fails when port 853 is blocked; the existing DoT/DoQ blocks already do this). The documented DNS signals do **not** help here: Apple's `mask.icloud.com` / `mask-h2.icloud.com` signal for Private Relay and Firefox's canary domain `use-application-dns.net` both work by changing the resolver's answer (NXDOMAIN or empty), which requires a dnsmasq change that is forbidden. Only fragile firewall IP blocking of relay and DoH endpoints remains, with the same refresh-owner problem as the DoH lists; forcing fallback can break apps or push a child onto cellular, which is invisible. Whether to force it is an owner decision, not part of this PRP
| Cellular or other Wi-Fi | Invisible | Device off this network |
| ECH, QUIC | Hides SNI, not DNS | Irrelevant to DNS capture but rules out an SNI fallback; DNS alone remains the signal |
| Hardcoded resolver over TCP, DNS caching, hosts files | Gaps or undercount | A client cache hides repeat lookups; counts are lookups, not use |
| Randomized, rotating or unknown MACs | Child unattributed | Unknown MACs are excluded by design, so undercount |
| Shared or multi-user devices | Misattribution | Attribution is device to child, not person |

Absence of an observation never means a child did not visit a site. Every output must state its coverage limits.

## Data minimization

- Reduce each query name to its **registrable domain (eTLD+1)** immediately in the reader, in memory. Full hostnames, subdomains, query types, client IPs and MACs are not stored. Reduction uses a versioned Public Suffix List snapshot shipped with the release; the PSL version is recorded with the data.
- eTLD+1 rules, to be fixed by fixtures:
  - **PSL private section:** proposal is to use the ICANN section only by default, so `alice.github.io` reduces to `github.io`. Using the private section would record per-user hosting subdomains (`*.github.io`, `*.blogspot.com`), which identify individual pages and are more revealing. Owner may choose otherwise (open question).
  - **Case and IDN:** lowercase ASCII, compare and store in punycode (`xn--`) form; invalid labels, over-length names and malformed packets are dropped. Display conversion to Unicode happens only in the UI.
  - **Dropped entirely:** IP literals, and `.arpa` reverse lookups (`in-addr.arpa`, `ip6.arpa`), which leak addresses; `.local`, `.lan`, `.home.arpa` and other special-use names; single-label names; names with no PSL match (never guess a suffix).
  - Dropped lookups are not counted into any bucket other than an aggregate `dropped` counter without name or child detail.
- Stored record: `(child_id, hour_bucket_utc, registrable_domain, count)`. Hourly buckets; no per-query timestamps.
- Only enrolled children's assigned devices attribute to a `child_id`; others are dropped before counting.
- Per-child, per-hour and global caps on distinct domains; overflow goes to a single `other` bucket count.
- **Sensitive-category denylist (proposal: on by default if any category mapping exists):** a maintained list of categories (for example health, sexuality, mental health, religion, abuse support lines, crisis resources). Matching lookups are **dropped entirely**: not stored, not counted, not bucketed. A `sensitive` bucket would still disclose help-seeking through its count and hour, so it is not the default. The tradeoff is that parents see a true-looking but incomplete picture; the UI must say that some categories are never recorded. Categories need a source and a refresh owner. See open question 3.
- Optional later: a coarse category mapping from a local, offline list. No per-lookup third-party calls.

## Retention, control and transparency

- **Retention:** 14 days default, hard-deleted by a daily job; owner may shorten, not exceed a bounded maximum (proposal: 30 days).
- **Deletion pass (defined):** a bounded transactional job that deletes rows older than the retention horizon (by bucket hour), and, on request, all rows for a child. After deleting it checkpoints and truncates the SQLite WAL (`wal_checkpoint(TRUNCATE)`) and then runs `VACUUM` or an incremental equivalent so freed pages do not retain domains. It records only counts and times in the audit log, never domains. A failed pass is retried and surfaced; retention is not considered met until it succeeds.
- **Backups:** observations are excluded from general database backups, or backups carry the same horizon: any backup containing observations expires no later than the retention period plus a stated grace, and deletion for a child must also be applied to or invalidate those backups. If that cannot be guaranteed, observations live in a separate database file that is not backed up. Open question 11.
- **Exports:** parent exports are generated on demand, not stored, are marked with the data window, and are the parent's responsibility once downloaded; the service keeps no copy and never emails them.
- **Deletion on unenroll:** removing a child or device runs the deletion pass for that child promptly (target: same day), stops attribution immediately, and drops any unflushed router-side counters for that child.
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
3. **Package and tooling gate:** verify that `kmod-ipt-nflog`, `kmod-nfnetlink-log` and a reader (`ulogd` or a custom binary) exist for the exact firmware and can be installed and rolled back. Package installation is currently blocked (README, [spike-005](../spike-005.md)); without a firmware-compatible package, dependency and rollback plan this feature does not proceed.
4. **Live read-only measurement with one consenting child device**, under per-invocation approval for each router command: confirm NFLOG availability, rule ordering in `cf2_<slot>_i` against the UDP/53 `ACCEPT` and GL marks, behavior across a slot switch, memory and CPU headroom, and that adult DNS and enforcement are unaffected.
5. **Accuracy check:** compare captured lookups with a known script of browsing on the test device; record undercount causes (cache, DoH, TCP) and publish the coverage statement.
6. **UI with truthful labels:** lookups, coverage limits, freshness, consent state and child notice. Collection stays default OFF until this gate passes.

Any gate failure stops the work; the fallback is no collection.

## Open questions for the owner

1. Do you reject dnsmasq query logging (a) outright, or would you ever lift the dnsmasq rule for a narrow, reviewed change?
2. Is a router-resident reader acceptable given the constrained device, or should this wait for a dedicated observer outside the router?
3. Do you want the sensitive-category denylist, and who maintains it? Default is to drop sensitive lookups entirely (strongest privacy, but parents see an incomplete picture); a `sensitive` bucket count would still reveal help-seeking by count and hour. Which tradeoff do you accept?
4. Is 14 days right, and is a 30-day cap acceptable?
5. May a child see their own observations, and should older children be able to view what parents see?
6. What is the consent and notice wording per age band, and is acknowledgement by the child required or is a parent record enough?
7. Are any enrolled devices school-managed or shared with adults, where collection would be inappropriate or require third-party consent?
8. Who owns the PSL and the DoH/DoT endpoint list refresh?
9. Should TCP/53 and local IPv6 UDP/53 be in scope for the first measurement, or only redirected IPv4 UDP/53?
10. Should router-side counts be shown at all before companion evidence exists, given the visit/attention misreading risk?
11. Do database backups include observations? If so, how do deletes and the retention horizon propagate to backups, or should observations live in an unbacked-up file?
12. Use the PSL ICANN section only (proposed) or also the private section?
13. Should the network force fallback from Private Relay or Android Private DNS, accepting breakage and cellular escape?
