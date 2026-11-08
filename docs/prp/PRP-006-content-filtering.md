# PRP-006 — content filtering, device coverage and bypass detection

Status: **proposal only.** Nothing here is built, installed, enabled or measured on the router. Every router-side claim is UNVERIFIED until a live, separately approved measurement records it ([spike-001](../spike-001.md), [spike-005](../spike-005.md), [enforcement contract](../enforcement-contract.md)). Public facts about NextDNS and Family Link were read on 2026-11-08 (sources at the end) and must be re-checked before the step that depends on them.

Owner decisions recorded 2026-11-08: content filtering is done by NextDNS, with the NextDNS CLI on the router mapping each child's devices to a per-child profile; Couvre-feu manages the profiles; Family Link stays the off-network layer for Android. This supersedes the "content filtering stays with NextDNS or AdGuard Home" non-goal in [PRP-001 §4](PRP-001-enforcement-core.md): Couvre-feu still does no filtering of its own, but it now orchestrates the thing that does.

## 1. What this PRP solves for, in the project's own terms

Couvre-feu today answers one question well: *is this child's traffic allowed to cross the router right now?* (Tier 1 pause, schedules, allowances; [ROADMAP](../ROADMAP.md).) It deliberately does not answer *what* the child reaches, and it records no domains ([privacy design gate](../ROADMAP.md#privacy-design-gate), [PRP-005](PRP-005-domain-observations.md) kept OFF).

Two gaps remain, and they are the ones a motivated child actually uses:

1. **Content.** When the internet is on, nothing between the child and the site is filtered by this project. Filtering has been "someone else's job" (NextDNS, GL's AdGuard Home) with no shared truth, no audit, no per-child model and no parent UI.
2. **Evasion.** The enforcement is MAC-based and router-local. The [roadmap's stated limits](../ROADMAP.md#limits-to-state-to-users) already admit that cellular, hotspots, VPN, Tor and a determined child are outside it. Nothing today tells a parent *that evasion is happening*; `possible_bypass` fires only on bytes seen during an active block.

This PRP adds three layers, each inside the existing rules:

| Layer | Owner | What it does | Framework it must fit |
|---|---|---|---|
| A. Filtering | NextDNS (profiles) driven by the Couvre-feu service | Per-child categories, apps, SafeSearch, denylist | Flags off by default; strict manifest keys ([service contract](../service-contract.md)); audit log; step-up on loosening; privacy gate |
| B. Delivery | NextDNS CLI on the router, child MAC → profile | Routes each enrolled device to its profile; strict default for everything else | **Conflicts with `AGENTS.md` (no dnsmasq change)**; needs a scoped owner exception, read-only inspection and rehearsed uninstall exactly as PRP-004 requires |
| C. Device coverage and detection | Couvre-feu inventory + alerts; OS controls (Family Link, Screen Time) | Knows which device is covered by which layer; alerts on the bypass signatures the router can see | Counts only, no domains; `parent_alerts` rules; roadmap item 3 (unknown devices) and item 8 (activity estimates) |

The design principle from the enforcement contract carries over: **the router confirms, the service never assumes.** A filter that the service wrote to NextDNS but cannot read back as applied is shown as "not confirmed", never as on.

## 2. Non-goals

- No domain, URL, search-term, page-title or per-query logging anywhere in Couvre-feu. The service never reads NextDNS logs. It may read **counts** from NextDNS analytics only if the owner approves that in §6 (decision D5); otherwise not at all.
- No NextDNS Recreation Time, Parental Control schedules or "block during" windows. Time lives in Couvre-feu only, so there is one truth for "why is this blocked right now". (Time-zone complaints about Recreation Time in the NextDNS community are an additional reason; UNVERIFIED.)
- No TLS interception, no custom CA, no block page. HTTPS to a blocked domain fails without explanation; the UI must say so.
- No VPN/Tor IP lists ([Do not build](../ROADMAP.md#do-not-build), owner decision 2026-10-28). Detection of VPN-like behaviour is in scope; blocking by provider list is not.
- No companion app on the child's device in this PRP ([companion capabilities](../companion-capabilities.md) stays later work). OS controls are configured by hand and recorded, not driven.
- No change to adult or protected-management DNS, DHCP, or the WAN zone.

## 3. Threat model: the sneaky kid

Written from the child's side, ordered by effort. "Stops" means the layer prevents it; "Sees" means a parent gets a count-only signal; "—" means neither. Grade bands are approximate.

| # | Effort | What the child does | A. NextDNS filter | B. Router delivery | C. Detection | OS controls (Family Link / Screen Time) |
|---|---|---|---|---|---|---|
| 1 | Trivial | Opens a blocked site in the normal browser | Stops (domain) | — | Sees: blocked-query count rises (if D5 allows reading counts) | — |
| 2 | Trivial | Uses a different browser or an app with the content inside it (YouTube in-app, Discord embeds) | Partly: app/service blocks are domain-level; content inside an allowed app is invisible | — | — | **Stops** if app installs need approval |
| 3 | Low | Changes the device's Private DNS / DNS-over-HTTPS setting to a public resolver | — | **Stops**: kids' DoH/DoT/DoQ rejects for listed resolvers ([DNS enforcement today](../enforcement-contract.md#dns-enforcement-today)); plain port 53 is redirected to the router | Sees: hits on the kids' DNS/DoH reject rules (today unattributed per child, see §5.3) | Stops only if the setting is locked (UNVERIFIED for Family Link) |
| 4 | Low | Enables Chrome/Firefox secure DNS to an unlisted endpoint, or an app with hard-coded DoH | — | Partly: only listed addresses are rejected ([known gaps](../dns-hardening.md#known-gaps-list-on-does-not-mean-doh-is-blocked)) | Sees: **traffic with no DNS** (§5.1) | Stops if browser settings are managed |
| 5 | Low | Types an IP address, uses a proxy/translate/cache site | Partly: proxy sites are a NextDNS category | — | Sees: traffic with no DNS (IP literal) | — |
| 6 | Medium | Installs a VPN app or Tor | — | — (decided not to list) | Sees: one long-lived encrypted flow to one destination (§5.2); traffic with no DNS | **Stops** via install approval; Family Link cannot block a VPN already allowed |
| 7 | Medium | Turns on MAC randomization, or forgets to turn it off for the home SSID; or factory-resets the device | — | **Falls to the default profile** — strict default (D1) keeps filtering | Sees: `new_device` (exists) and child MAC absent while household is active (§5.4); also escapes Couvre-feu pause rules (known limit) | Family Link survives a reset only if the account is re-added |
| 8 | Medium | Uses the guest SSID, a sibling's or an adult's device, or a console/TV | — | Partly: strict default profile covers unmapped devices on the kids' path; an adult device is outside scope by design | Sees: nothing for adult devices | Per-device controls on the borrowed device, if any |
| 9 | Low–medium | Cellular data, a friend's hotspot, a second SIM | — | — | Sees: child device *known to be present* (phone on Wi-Fi) with near-zero bytes while screen is in use is **not** observable by the router. Weak signal: device absent from Wi-Fi during normal home hours (§5.4) | **The only layer**: Family Link / Screen Time apply on any network |
| 10 | High | Rooted / unmanaged device, sideloaded builds, a second device the parents don't know about | — | Strict default profile | Sees: `new_device` | — |

Takeaways that drive the design:

- Rows 1–5 and 7 are where the router and NextDNS earn their keep. The **strict default profile (D1)** is the single most valuable choice: it turns MAC rotation (row 7) and unknown devices (row 10) from a bypass into a nuisance.
- Rows 2, 6 and 9 are only stopped on the device. **App-install approval** in Family Link is the control that matters most there; the inventory (§5.5) must record whether each child device has it.
- Detection (§5) is not enforcement. Its job is to turn silent bypass into a count-only alert a parent can act on in person. It must never claim certainty: "traffic with no DNS" has benign causes (cached names, long-lived app connections, IPv6 paths the counters miss).
- On-device NextDNS (Private DNS / iOS profile) is **not** adopted as a layer: at home it collides with row 3's reject rules (strict Private DNS would then fail entirely), and away from home it is only as strong as the child's inability to change it, which Family Link does not clearly guarantee. The off-network layer is the OS control, not a DNS setting.

## 4. Architecture

```
child device --UDP/TCP 53--> router (kids DNAT to LAN addr; unchanged) --> NextDNS CLI listener
                                                                            |-- profile <child MAC>=<id>   (one line per enrolled MAC, first match wins)
                                                                            |-- profile <strict default id>  (everything else)
                                                                            `--DoH from the router--> dns.nextdns.io
adult / protected MACs -----------------------------------------------------> unchanged resolution path (out of scope)

service --HTTPS X-Api-Key--> api.nextdns.io/profiles/<id>/parentalControl|denylist|allowlist|settings   (write desired, read back, never logs)
service --existing RPC--> router rpc-activity / rpc-inventory (+ proposed rpc-dns-counters)             (counts only)
```

**4.1 Filtering (A).** `service/src/nextdns-client.ts`: a thin client over the NextDNS API (base `https://api.nextdns.io`, header `X-Api-Key`), injectable transport, retries on 429 with backoff, and a strict response schema. Per child it manages `parentalControl.categories`, `parentalControl.services`, `parentalControl.safeSearch` / `youtubeRestrictedMode`, `denylist`, `allowlist`, and `settings.logs` (set to the owner's D4 choice). Desired state lives in the Couvre-feu database (new table, migration), is written to NextDNS, read back, and compared; the diff is the "applied / not confirmed / drift" state shown to parents. Nothing from NextDNS analytics or logs is fetched unless D5 is approved, and then counts only.

Why not the CLI's own filtering or GL's AdGuard Home: the ROADMAP already records that per-child AdGuard profiles likely break GL's filtering and model schedules inversely. NextDNS profiles are the per-child model the UI needs, with an API.

**4.2 Delivery (B).** The NextDNS CLI's conditional profile selection: `profile <MAC>=<id>` repeated, first match wins, bare `profile <id>` as fallback. The service generates the profile lines from the same enrollment truth it already holds (enrolled child MACs by person) and exposes them as a *proposed router config artifact*; applying it is a separately approved live step, as every router write is. The CLI's upstream DoH connections originate on the router, so the kids' forwarded-traffic DoH rejects should not catch them, and NextDNS stays on the `doh-list.ts` block list (a child cannot pick a different profile from the device). **Both halves of that sentence are UNVERIFIED on this router and are gate G3.**

The rule conflict: the CLI either listens on port 53 itself or sits behind dnsmasq as its upstream, and GL's firmware also puts AdGuard Home on that path. Either arrangement is a DNS-plumbing change. `AGENTS.md` forbids changing dnsmasq configuration; the 2026-10-27 lift covered the kids' firewall DNS rules only. **No B step starts before the owner records exception E1 (§6).** Installation itself is also blocked today (spike-005: package install not verified; BusyBox `stat`/`od` missing), so B begins with a read-only inspection, not an install.

**4.3 Device coverage and detection (C).** Extends what exists: inventory rows gain an owner-maintained *coverage record* per child device (platform, OS-control present, install approval on, DNS locked, last checked); `alert-rules.ts` gains the signatures in §5; the weekly digest (B7) gains their counts. The router contributes per-child counters only; no domains.

## 5. Detection design (counts only)

Each signal is a `parent_alerts` candidate with the existing `details` rule (≤1024 bytes; counts, windows, operation ids; never MACs, addresses, hostnames or domains). All are hints with stated false-positive causes; none pause or block anything.

**5.1 `traffic_without_dns`.** Per child, over an evaluation window: bytes from `rpc-activity` (exists) are high while **DNS queries counted for that child's MACs** are near zero. Needs a new read-only counter: a per-child-MAC `udp/tcp dport 53` packet count on the redirected path (mangle, no verdict, same pattern as `cf_acct`). The ratio threshold comes from a measurement spike, not a guess. Benign causes to state in the UI: long-lived app sessions, aggressive OS caching, IPv6 paths the counters miss, flow offload undercounting bytes (`offload: on` makes this signal unreliable; suppress it then).

**5.2 `long_lived_single_flow`.** Per child: one conntrack entry carrying most of the window's bytes to a single destination, lasting longer than N minutes. Read-only conntrack listing already exists for address binding; this adds a scoped read. It looks like a VPN; it also looks like a video call or a game. Severity `info`, never `critical`.

**5.3 `dns_bypass_attempts`.** Per child: hits on the kids' DoH/DoT/DoQ reject rules and the IPv6 port-53 reject. Today these hits are explicitly **unattributed** (`blocked_unattributed`, [activity counters](../activity-counters.md)) because the rules are set-based. Attribution needs per-MAC counting rules, i.e. a router change and a new release id — it belongs in the Phase 4 release of the roadmap, not before. Until then the unattributed total is shown household-wide.

**5.4 `child_device_absent`.** Per child: a device enrolled for that child has not been seen by `rpc-inventory` during hours when the household schedule expects it home, while other household devices are present. Weak by design (cellular, battery off). Default off; owner-only.

**5.5 Coverage model.** For each child device: platform, OS-control (Family Link / Screen Time / Family Safety / console / none), install-approval on, DNS or VPN setting locked, NextDNS profile mapped, last hand-checked date. The parent UI shows a per-child coverage matrix and the gaps. This is the one place where the plan admits what the router cannot see (rows 2, 6, 9) and points at the control that can.

**5.6 Weekly digest additions (counts).** Blocked queries per child (only with D5), bypass-attempt count, traffic-without-DNS windows, new/rotated devices, coverage gaps open.

## 6. Owner decisions and exceptions

| Id | Decision | Options | Recommendation and why |
|---|---|---|---|
| D1 | Default (unmapped) profile | Strict kids-level; permissive household | **Strict.** Converts MAC rotation and unknown devices into "filtered, not escaped". Adults then need explicit mappings (their MACs are already protected identities). |
| D2 | Profile granularity | One per child; per age band; one "kids" | **One per child.** The UI, audit and step-up are per child already. Plan limits on profile count: UNVERIFIED. |
| D3 | Who edits filters | Owner only → all parents (`contentFilter.mode`, like `timeRequests.mode`) | Owner only first; loosening needs step-up. |
| D4 | NextDNS logging | Disabled; 1 h; longer | **Disabled**, so "no domains stored" is true end to end. |
| D5 | Read NextDNS analytics counts | Never; counts only (blocked total per profile per day) | Counts only, owner-visible first. No domains, no device names. |
| D6 | Drift handling | Alert only; auto-correct | Alert only; auto-correct later if drift is frequent. |
| D7 | Cellular / off-network | Family Link + Screen Time by hand; companion app later | By hand, recorded in the coverage model. |
| E1 | **Exception to `AGENTS.md:39`** | Which exact DNS service files/UCI sections may change, for the kids' resolution path only; adult/management DNS, DHCP and WAN stay untouched | Required before any B step; scoped like the 2026-10-27 lift; recorded here and in the enforcement contract. |

## 7. Plan

Follows the roadmap's shared rules: one PR per step, tests first, strict manifest key `contentFilter` (absent = off), every unproven claim labelled "unverified on this router", every live step separately approved with its exact invocation. Numbering continues the roadmap's planned additions as items **11 (filtering), 12 (delivery), 13 (coverage and detection)**.

### Phase A — service and web, no router (item 11)

1. **Client + schema.** `nextdns-client.ts` with a fake NextDNS server in tests (200, 400 shapes, 429 retry, pagination cursors, unknown profile, hex-encoded service ids). Shared schema for a child filter. Manifest `contentFilter: {mode, apiKeyFile, profiles: {<personId>: <profileId>}, defaultProfile}`; the key is read from a root-only file, never stored in the manifest or database.
2. **Desired state + reconcile.** Migration; write–read-back–diff; states `applied | pending | not_confirmed | drift`. Audit rows as action types only. Tests: diff correctness, no free text, key never logged (snapshot test on stderr).
3. **Routes + gate.** `GET/PUT /people/:id/filter`, owner → parents per `contentFilter.mode`; loosening (removing a category/service, adding an allowlist entry) requires the existing step-up. 404 scoping tests.
4. **Web.** Per-child filter card: categories, apps, SafeSearch, denylist/allowlist; honest state pill; copy stating "unverified on this router" and that HTTPS blocks show no page. Playwright on the demo with a fake NextDNS.
5. **Digest + alerts (D5 permitting).** Blocked-count per child in the weekly digest; `filter_drift` alert.
6. **Docs.** Service contract section, operating notes, dns-hardening cross-reference (NextDNS stays blocked for kids).

Entry: none beyond CI. Exit: merged, flags off. Rollout: owner only one week, then parents. Stop: any filter shown "applied" that NextDNS did not confirm → flag off.

### Phase B — delivery on the router (item 12)

1. **E1 recorded** by the owner (§6).
2. **Read-only inspection** (each command approved): what listens on 53 and 5353; AdGuard Home state and config on GL firmware 4.8.x; dnsmasq `server=` and `port`; whether an `opkg` NextDNS package or static binary fits OpenWrt 21.02 on this device; flash/RAM headroom. Outcome is a spike doc (spike-006). If install is not feasible without touching more than E1 allows, **stop**: Phase A still stands alone and the owner reconsiders per-device delivery.
3. **Design the install/uninstall** as owned, inventoried, drift-checked changes, mirroring PRP-004: exact pre-images of every file touched, restore-on-uninstall, refusal on drift, journal preserved. Generated `profile` lines come from enrolled MACs; the strict default is `defaultProfile`.
4. **Rehearsal on an empty policy** (owner at home): install, prove default profile via `test.nextdns.io` from an unmapped test device, uninstall, prove byte-exact restore of every touched file and that adult/management resolution never changed. Then **one authorized child device**: profile reported matches; a blocked category fails; the device still cannot reach NextDNS anycast directly (G3 part 1); the CLI's own upstream works (G3 part 2); pause/resume behaviour unchanged.
5. **Permanent install** only after 4 passes once with no retry in the session.

Entry: Phase 0 (first live rehearsal) passed; A merged; E1 recorded. Exit: live receipt filled. Stop: any adult or management DNS change, any unrecoverable diff → console rollback, report.

### Phase C — coverage and detection (item 13)

1. **Coverage model** (service + web, no router): per-device coverage record, matrix per child, gaps list. Tests: scoping; no MAC in alert details.
2. **Measurement spike** for §5.1/5.2 on a test device (offload off, then on): what the bytes-to-queries ratio and single-flow share look like during normal use vs a DoH/VPN bypass; publish the numbers and false-positive rate.
3. **`traffic_without_dns`** behind `detection.enabled`: new read-only per-MAC port-53 counter in the `cf_acct` pattern (mangle, no verdict). This is a **router change** and rides the Phase 4 release with item 3; the service side can merge earlier against fixtures.
4. **`long_lived_single_flow`** (read-only conntrack, service-side heuristic). `info` only.
5. **`dns_bypass_attempts`** attribution: per-MAC counting rules for the kids' DNS/DoH rejects; same release.
6. **`child_device_absent`**, owner-only, default off.
7. **Digest** counts; docs: limits to state to users updated with the sneaky-kid table.

Entry: A merged; 3 and 5 wait for the Phase 4 release. Exit: measured thresholds recorded; alerts visible to the owner only for two weeks before parents see them. Stop: any alert detail carrying a MAC, address, hostname or domain → flag off.

### Rollout order across phases

A1–A6 → C1 (both offline) → Phase 0 → B1–B5 → C2 → Phase 4 release carrying C3/C5 → C4/C6/C7.

## 8. Gates (what must be shown, not assumed)

| Gate | Statement to prove live | Phase |
|---|---|---|
| G1 | A profile change written by the service is visible on `test.nextdns.io` from a mapped device within N minutes | B4 |
| G2 | Unmapped, rotated-MAC and unknown devices land on the strict default profile | B4 |
| G3 | Kids still cannot reach NextDNS anycast directly (DoH/DoT rejects hold) **and** the router-originated CLI upstream is not caught by those rejects | B4 |
| G4 | Uninstall restores every touched DNS file byte-exact; adult and management resolution unchanged throughout | B4 |
| G5 | Pause, schedule and allowance behaviour unchanged with the CLI in the path | B4 |
| G6 | `traffic_without_dns` separates a scripted DoH/VPN bypass from normal use at a stated false-positive rate | C2 |
| G7 | No alert, digest or log line ever contains a domain, MAC, address or hostname (snapshot tests, CI) | A, C |

## 9. Risks

- E1 is a real widening of the project's hard constraints. If the inspection shows that AdGuard Home or GL's own DNS handling cannot coexist with the CLI inside E1's scope, Phase B stops and filtering stays service-only.
- NextDNS is a cloud dependency and a single vendor; API shape is beta and has changed (hex-encoded service ids). The client is isolated behind an interface for that reason.
- A strict default profile will also catch new adult devices and guests until mapped; the UI must make "map this device" a one-tap admin action (roadmap item 3).
- Detection false positives erode trust faster than misses. Thresholds come from measurement (C2), alerts start owner-only, and every alert names its benign causes.
- The child-side truth: cellular and a trusted friend's hotspot defeat everything in this PRP. The coverage model exists so that gap is visible, not hidden.

## 10. Unverified

NextDNS CLI package availability and behaviour on this firmware; coexistence with GL AdGuard Home; that router-originated DoH is not caught by the kids' reject rules; NextDNS profile-count limits; Family Link's ability to lock Private DNS/VPN settings; usefulness of the bytes-to-queries ratio with flow offload on; everything in §8.

## 11. Sources (read 2026-11-08)

- NextDNS CLI conditional profile: https://www.github.com/nextdns/nextdns/wiki/Conditional-Profile
- NextDNS API: https://nextdns.github.io/api
- OpenWrt feed `nextdns.config` (first matching host config wins): https://git-03.infra.openwrt.org/feed/packages/plain/net/nextdns/files/nextdns.config
- Comparable products, incl. NextDNS and Lantern Watch bypass protection: [research](../research/comparable-products-features.md)
