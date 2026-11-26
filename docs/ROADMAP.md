# Roadmap

Updated 2026-11-22. The planned additions date to 2026-10-27, with items 11–13 added on 2026-11-08. “Built” means merged and tested in CI. Hardware verification requires separate observations. [Live proof](#live-proof) records which behavior was observed on hardware and which acceptance checks remain.

## Planned additions at a glance

Ten additions picked from the comparable-products research (PR #90), plus three content-filtering items (11-13, [PRP-006](prp/PRP-006-content-filtering.md), owner decision 2026-11-08), phased in. Items 11-13 use PRP-006's own phases A-C, separate from Phases 0-5. Details, owner decisions and rules: [Planned additions](#planned-additions) and [Plan](#plan).

| # | Addition | Phase | State |
|---|---|---|---|
| 1 | Ask for time: web UI + parent one-tap approve | 1 | Built and merged, all behind `timeRequests.mode` (off by default): service (PR #86, #88), per-account gate off/owner/parents (F1, PR #92), parent card with Grant, Grant less, Decline and End extra time (F3, PR #94). Unverified on this router: live proof remains |
| 5 | Reward Time (extra minutes on a grant) | 1 | Service built and merged (F4, PR #95) behind `rewardTime.enabled` (off; unverified on this router); parent UI built (PR #107) behind `rewardTime.enabled`, shown per viewer via the `rewardTime` field of `GET /people` (unverified on this router) |
| 7 | Focus / homework window (one-shot in 1, recurring in 3) | 1 and 3 | The one-shot service (#104) and parent controls and status chip (#176) are merged behind `focus.enabled`. The recurring-focus service (#193) stores a weekly window kind behind both `schedules.editable` and `focus.enabled`. Recurring controls and hardware proof remain. |
| 6 | Audit log of parent actions (1); weekly digest, counts only (2) | 1 and 2 | Audit log built and merged (F2, PR #93) behind `auditLog.enabled` (off; unverified on this router; web "Activity log" view built behind `auditLog.enabled` (unverified on this router), shown per viewer via the `auditLog` field of `GET /people`); B5 follow-up: refused owner-guard attempts audited as `owner_guard_refused` (migration 013, admin-visible only); weekly counts-only digest built behind `digest.enabled` (B7, off, service-only, unverified; see [service contract](service-contract.md#push-and-weekly-digest-b7-service-only-off)) |
| 4 | Push notifications (self-hosted ntfy or Web Push) | 2 | Service side built behind `push.enabled` (B7: ntfy adapter, content-free, admin topic; off, unverified, no web UI or Web Push); alert pushes hold low-urgency kinds (`time_request_pending`, `repeated_blocked_attempts`) from 21:00 to 07:00 New York per owner decision D3; the held list is owner-confirmed 2026-11-24; settings read (`GET /push/settings`) and test push (`POST /push/test`) built behind `push.enabled` (admin only, off, unverified on this router; receipt on the phone is the Phase 2 exit and is not yet checked; [contract](service-contract.md#push-settings-and-test-push)); settings screen and subscriptions not started ([service contract](service-contract.md#push-and-weekly-digest-b7-service-only-off)) |
| 2 | Weekly schedules / bedtime with age-band templates | 3 | Merged behind `schedules.editable`: database schedule truth (#177, #185), queued admission and receipt settlement (#189), create/update/delete with audit and schedule DTOs (#190), passkey step-up for loosening or deletion (#191), and Extra time / Skip tonight routes (#192). The existing browser editor still needs full integration wiring. The S4 parent controls, age-band templates and scoped hardware proof remain. See [Phase 3](#phase-3-schedules-and-age-band-templates-items-2-7-recurring). |
| 3 | Unknown-device alerts + new devices default to restricted | 4 | Alerts, device list and admin web panel built and merged (service: `inventory-store.ts`, `inventory-http.ts`, router `rpc-inventory`; web: "Devices on the network"; `new_device` and `inventory_stalled` alerts). Unverified on this router. Default-restricted for unassigned devices not started |
| 10 | Guest / visitor profile (internet only, no LAN) | 4 | Not started |
| 8 | Per-child daily online time, labelled an estimate | 5 | Not started |
| 9 | DNS hardening (wider DoH list; port 853 is already blocked for kids). The VPN/Tor list (9c) is NOT BUILT, see [Do not build](#do-not-build) | 5 (or 4) | Rule lifted for the kids' firewall DNS rules only (2026-10-27); VPN/Tor list decided not to build (2026-10-28) |
| 11 | Content filtering: per-child NextDNS profiles managed by the service ([PRP-006](prp/PRP-006-content-filtering.md), [stack and risks](content-filtering-stack.md)) | A (no router) | Phase A built and merged behind `contentFilter.mode` (off; unverified on this router); owner decided NextDNS + CLI on router, Family Link off-network. Phase C counts C1-C4 merged behind `contentFilter.counts` (analytics client, counts store and fetcher, filter-card block, weekly digest line; see [runbook](runbooks/content-filter-counts.md)); C5 bypass alert and the C0 live probe NOT done, pending owner approval |
| 12 | Filter delivery: NextDNS CLI on the router, child MAC → profile, strict default | B (router; needs exception E1 to `AGENTS.md:39`) | Proposal only; blocked on E1 and a read-only inspection |
| 13 | Device coverage matrix and bypass detection (traffic without DNS, single long flow, per-child DNS-reject attribution), counts only | C (service first; attribution rides the Phase 4 release) | Daily blocked-lookup counts built (PRP-006 C1-C4, flag off, unverified); coverage matrix, bypass detection and the C5 alert not started; C0 measurement probe pending owner approval |

Phase 0 gates live rollout. Eligible offline feature work can merge behind flags while hardware acceptance continues.

## Tier 1: basics and live acceptance

Block or unblock one child, block or unblock all children, assign and move devices, parent sign-in with passkeys, and router-local timed pauses.

Earlier hardware evidence and remaining rollout gates:

| Item | State |
|---|---|
| Empty-policy rehearsal, one-device pilot and permanent install | The earlier empty-policy rehearsal and one-device pilot passed with restoration. Permanent installation on the approved MVP scope remains a separately authorized live step. See [Live proof](#live-proof) and the [rehearsal runbook](runbooks/live-first-rehearsal.md). |
| Install watchdog (bound the install step) | Deferred. A measurement under load exceeded the 80-second stop rule, and a TERM at the `intent` phase can leave the router needing `recover-install-lock`. The owner accepted an unbounded INSTALL for the reviewed rollout on 2026-11-08. |
| M4b evidence receipt | The unsigned receipt was waived for the reviewed rollout on 2026-11-08. Each exact live invocation still requires approval. |
| Service key entry, confinement and dispatch | The pilot exercised direct router controls. Permanent-install service key entry, confinement, appliance dispatch and current-release hardware checks remain. |
| Fixed Wi-Fi address for children's devices | Household rule: scope and protection are MAC-based, so a device that rotates its address escapes them. |

## Tier 2: next

| Item | State |
|---|---|
| Ask for time (child requests, parent one-tap approval as timed grants) | Built behind `timeRequests.mode` (off by default; legacy `enabled` reads as `parents`): service in PR #86 and follow-up PR #88, per-account gate in PR #92, parent card in PR #94 (all merged). Grants are router allowances, 60 min cap, lift pauses and schedules, a parent's Pause ends a grant. Live proof remains: [Planned additions](#planned-additions) item 1, Phase 1. The design is in the maintainer's local planning notes (not in this repository). |
| Weekly schedules / bedtime per child | The integration service supports committed weekly windows, audited changes and step-up on loosening or deletion. Parent-editor integration, schedule allowance controls and current-release packet checks remain. See item 2 and [Phase 3](#phase-3-schedules-and-age-band-templates-items-2-7-recurring). |
| Device recognition and unknown-device alerts | Built and merged on the service side (`service/src/inventory-store.ts`, `service/src/inventory-http.ts`, read-only `rpc-inventory`, [tier1-rpc §2](contracts/tier1-rpc.md)) with the admin "Devices on the network" web panel and `new_device` / `inventory_stalled` alerts; unverified on this router. Item 3, Phase 4. "New devices default to restricted" is not started and is the only part that needs a router change. |
| DNS enforcement | Shipped controls include kids' IPv4 port 53 redirect (IPv6 port 53 rejected), kids' DoT/DoQ block (TCP/UDP 853, UDP 784 and 8853, unconditional: `router/lib/firewall.sh:53-58`), and a DoH reject set filled from the policy `doh` arrays (up to 256 per family). The service ships a flagged-off list of seven providers, with 32 IPv4 and 28 IPv6 addresses. Setting `dnsHardening.dohList` to true or false strips twelve retired Mullvad resolver addresses. An absent flag preserves existing entries. See [enforcement contract](enforcement-contract.md#dns-enforcement-today). Item 9, Phase 5: wider DoH list (VPN/Tor list not built, see Do not build). The owner lifted the "no DNS changes" rule on 2026-10-27 for the kids' firewall DNS rules only. `AGENTS.md:39` still forbids changing dnsmasq or the WAN zone. DHCP and adult/management traffic stay out of scope. The DNS baseline still has to be re-measured. |
| Per-child AdGuard profiles | Not recommended: on the GL firmware it likely breaks GL's own filtering, and AdGuard's per-client schedule is an inverse window that does not match this project's schedule model. Research notes are local (not in this repository). |

## Tier 3: later

Now planned as items 4 to 10 of [Planned additions](#planned-additions): DNS hardening (item 9, without a VPN/Tor list), focus/homework window (item 7), guest profile (item 10), daily time quota as an estimate (item 8), weekly summary and audit log (item 6), push notifications (item 4), Reward Time (item 5). The existing activity view shows scoped estimates and coverage. A calibrated daily online-time balance remains item 8.

## Planned additions

Source: the comparable-products research (PR #90, `docs/research/comparable-products-features.md` once merged), section 4 shortlist, corrected against the current code and contracts. Effort: S = one or two PRs, M = three to five, L = more, with live measurement. "Router change" means new router bytes and so a new release id. Every flag is OFF by default; nothing changes for the household until the owner turns a flag on.

| # | Addition | Value | Effort | Router change | Privacy risk | Needs live proof | Depends on | Owner decisions still needed | Flag (proposed) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Ask for time: web UI + parent one-tap approve | High: service and parent card merged | M | No. Uses existing router allowances | Low: the child’s reason is visible only to scoped parents and admins. Pushes and router policy omit it. | Grant lifts a manual pause or a weekly schedule block. The kernel restores the applicable block at `until` with the service stopped. Reboot remains a separate check. | #86, #88, #92, #94 merged | Decided: 60-minute cap, no daily limit, a grant lifts pauses and schedules, a parent’s Pause ends it, and scoped parents and admins can approve | `timeRequests.mode` (off, owner, parents) |
| 2 | Weekly schedules / bedtime with age-band templates | High | M | No for steps S1-S4; optional S5 (router reports kernel tz) | Low | Windows with flow offload off then on, cross-midnight, DST | Item 1 merged (Extra time reuses its allowance path); item 6 audit log | Age bands and template times (new). Already decided: who edits, step-up only on loosening/deleting, Extra time/Skip tonight = allowance with the 60 min cap, merge behind a flag before live proof, cap 8 windows per child | `schedules.editable` |
| 3 | Unknown-device alerts + new devices default to restricted/unassigned | Medium-high: closes the "new phone escapes" gap | M | Alerts: no (existing read-only `rpc-inventory`). Default-restricted: yes | Low: MAC, vendor prefix, sanitised hostname only; stored for the parent view, never pushed | MAC rotation on phones with private Wi-Fi addresses; default rule never touches protected or management MACs | Item 4 (to notify); Phase 0 router release settled | What "restricted" means (blocked, or guest profile from item 10); whether to default-restrict at all | `deviceAlerts.enabled` (service); router: off unless the desired JSON carries the new field |
| 4 | Push notifications for approvals, expiries, unknown devices, drift | High: alerts are only visible while the app is open today unless `push.enabled` is on (B7) | M | No | Low if payloads stay content-free (see [Privacy gate](#privacy-design-gate)) | Delivery while WAN/DNS is flaky; honest "not delivered" state | Existing `parent_alerts` | Push provider (self-hosted ntfy vs browser Web Push); quiet hours | `push.enabled` |
| 5 | Reward Time: extra minutes added to a grant without changing the schedule | Medium | S | No | None | Grant arithmetic against the 60 min cap (the 14400 s router horizon stays as a defence-in-depth guard) | Item 1 | None. Decided and built: reward and grant together never exceed 60 min from router time | `rewardTime.enabled` |
| 6 | Audit log of parent actions; weekly digest (counts only) | Medium: both parents can see who did what | S (log) + S (digest) | No | Low: counts and action types only, no domains | None beyond status fidelity | Log: none. Digest: item 4 or the in-app view | Digest recipients and day/time. Audit retention is decided (90 days) | `auditLog.enabled`, `digest.enabled` |
| 7 | Focus / homework window: one-shot or recurring | Medium | S | No (one-shot reuses timed pause; recurring reuses schedules) | None | Same as timed-pause expiry; recurring = item 2's proof | One-shot: none. Recurring: item 2 | Decided (owner, 2026-10-27): the focus window ends only by a parent/admin (Pause/Resume, or approving the request); a child's ask never ends it. [Recurring focus service](service-contract.md#recurring-focus-roadmap-item-7) built, unverified on this router | One-shot `focus.enabled`. Recurring also needs `schedules.editable` |
| 8 | Per-child daily online time, labelled an estimate | Medium, with real accuracy risk | L | Probably none (estimate from existing `rpc-activity` counters, enforcement through the existing pause op); UNVERIFIED | Medium: usage pattern of a minor; store daily totals only | Counter accuracy vs real use: flow offload bypasses the counters, background traffic, IPv6 | Phase 0; item 4 | Semantics (estimate only, or auto-pause at the limit), limits per child, what counts as "online" | `quota.enabled` |
| 9 | DNS hardening: wider DoH list (port 853 for kids is already blocked). VPN/Tor list (9c): NOT BUILT, see Do not build | Medium | M | No for a wider DoH list alone (rides the existing `doh` policy field); any provider list would be a separate decision with a new field and release id | Low (no logging; block lists only) | Real bypass attempts from a test device; DNS baseline re-measured before and after | Rule lifted 2026-10-27 for the kids' firewall DNS rules only (`AGENTS.md:39` still forbids dnsmasq and WAN changes; DHCP and adult/management traffic stay out of scope) | Source and refresh owner for the wider DoH list; 9c is decided not built, and any provider list would be a separate decision | Router: off unless the desired JSON carries the new field |
| 10 | Guest / visitor profile: unassigned devices get internet only, no LAN | Medium | M | Yes | Low | Isolation actually blocks LAN, including the router admin page from a guest device, while password login from adult devices still works | Item 3 (same unassigned-device rule) | Isolation scope (no LAN at all, or allow printers/casting); whether guests are time-limited | `guest.enabled` (service); router as item 3 |

Corrections to the research table: item 3 needs a router change only for default-restriction (alerts use the existing inventory RPC); item 8 probably needs no router change; item 6's audit log and the schedules design's audit step are one piece of work; item 5 and schedules S4 "Extra time" are one allowance path.

### Do not build

| Not building | Why |
|---|---|
| Message, SMS or social-media scanning | Needs an app on the child's device or TLS interception (both outside this project's hard constraints), and is surveillance of minors |
| Location tracking | A router cannot see location; needs an on-device app; tracks minors |
| Search-term, video-title or per-domain browsing logs | Needs DNS/TLS inspection; the reviewed-privacy-design rule forbids domain logging; research found parental-control products routinely over-collect and leak minors' data (PoPETs 2020, ACSAC 2020, an FTC case; citations in the research doc). If domain logging is ever proposed, it starts hidden by default (Pi-hole-style privacy levels) and needs its own privacy review |
| VPN / Tor block list (item 9c) | Owner decision 2026-10-28, reasons below. Revisit only if the owner wants provider-specific blocking: then a separate optional policy field, after a terms check for Mullvad and X4BNet and an explicit size and release decision |

**Why no VPN/Tor list** (research fetched 2026-10-28):

1. Tor: a Tor client's first hop is a guard relay (Tor Project: "Tor selects a stable and trusted \"guard relay\" to be the first hop in your circuit", https://support.torproject.org/tor-browser/security/guard-relay/, fetched 2026-10-28) or a bridge, so the exit list (https://check.torproject.org/torbulkexitlist: about 1,225 IPv4 (1,224 on a second fetch), 0 IPv6; CC0 per Tor Metrics/CollecTor) would not stop a child's device. That a client never connects to exit nodes directly is our inference from the guard being the first hop (path guard, middle, exit); UNVERIFIED as a direct quote. Blocking the public guard and relay addresses (several thousand, not measured here) would partly work against default Tor Browser, but bridges bypass it trivially: bridges are not publicly enumerable, so a public relay list does not cover them ("Bridges are non-public Tor relays that aren't listed in the public directory", https://support.torproject.org/censorship/censorship-7/, fetched 2026-10-28).
2. VPN: X4BNet/lists_vpn (https://github.com/X4BNet/lists_vpn; MIT per its README, the GitHub API shows no licence) is 10,947 CIDR lines and 179,678 bytes (about 175 KiB, measured 2026-10-28). A list that size would need a new policy field, new sets and a new cap, and exceeds the 65,536-byte policy input limit (`router/lib/core.sh:870`) by about 2.7x. Datacenter netblocks would also block unrelated services. Mullvad's relay API (553 relays, v4 and v6; https://api.mullvad.net/public/relays/wireguard/v2) has unverified terms. Findings with a source: ipcat is archived (2023-02-02 per its repository); the firehol README says some of its lists may carry special licences; for NordVPN and ProtonVPN no public licence or terms for a block list were found in the 2026-10-28 search (not proven absent). UNVERIFIED: that firehol lists are stale, and that either provider publishes no list. A VPN on an arbitrary port to an unlisted VPS cannot be blocked by IP, and IPv6 coverage of the lists is thin.
3. Any list needs a new optional policy field, new sets, a router release, a refresh owner and a licence review.

Also avoid OpenAppFilter code (GPL-2.0, not combinable with this AGPL-3.0 project, and a kernel DPI module).

## Plan

### Shared rules for every phase

- **PR shape:** service, then web, then docs, each its own PR where it is more than a few lines. Tests come first in each PR (write the failing test, then the code). CI is the authority.
- **Flags:** every addition gets a manifest key, absent = off, following the existing `timeRequests` pattern in `service/src/integration-config.ts` (strict optional keys, so each new key is a small, reviewable manifest-schema change). Router-side features are off unless the desired JSON carries the new field, so an older service never turns them on.
- **Rollout per flag:** off, then owner only, then all parents. Today a flag is manifest-wide; "owner only" needs a per-account gate: `timeRequests.mode` `owner` (F1, PR #92) does this for time requests and Reward Time. It is not a security boundary against other admins (see [service contract](service-contract.md#operating-notes-for-the-flagged-features)); `auditLog` and `rewardTime` flags are still manifest-wide.
- **Labels:** anything not proven on the real router is shown and documented as "unverified on this router".
- **Live steps** (only after Phase 0's rehearsal passes, owner at home): log the invocation and release hash first; one run; on failure stop and report; console rollback ready; never disable or confine router or CT107 password login.
- **Shared files.** These are touched by many items, so the phases are ordered to keep one open PR per file at a time where possible:
  - `service/src/integration-policy.ts`: items 1 (already), 5, 7, 2-S4, 8 (pause op). Phase 1 lands 5 and 7 one after the other, not in parallel.
  - `service/src/http.ts`: one route PR per phase; rebase, do not stack.
  - `shared/src/router-schema.ts`: only Phase 4 (new desired-JSON fields) and Phase 3 if S5 is taken.
  - Keep one UI PR in flight per shared file. Tab routing landed in `web/public/tabs.js` (#140, `04ebaf2`).
  - `router/` release bytes: at most two new release ids for items 1-10; items 11-13 (PRP-006) add the E1 delivery release and C3/C5 counters, where the read-only C3/C5 counters ride the Phase 4 release and the E1 delivery release needs E1 first (Phase 4, and Phase 5 only if DNS is not ready in time).

### Privacy design gate

Every PR in Phases 1-5 and PRP-006 phases A-C states in its description how it meets these; reviewers block on a miss.

- No domains, URLs, page titles, search terms or content anywhere: database, logs, alerts, pushes, digests. One owner-approved exception (PRP-006 D8, 2026-11-09): parent-entered content-filter deny/allow domains live in the `content_filter_desired` table only, never in audit, logs, alerts, pushes, digests or errors. Browsing data of any kind is still never stored.
- Counts and action types only. Alert `details` keep the existing rule: at most 1024 bytes; counts, windows, operation ids; never MACs, addresses, domains or router diagnostics.
- Push payload: content-free (for example "Couvre-feu: new alert"). The app fetches the details over the signed-in session when tapped. No child names, no reason text, no device names in the payload.
- Digest: per child, counts for the week (pauses, grants and minutes granted, schedule nights enforced, requests, new devices, alerts by kind). No timelines, no per-device detail, no domains. Sent only to the recipients the owner picks.
- Unknown-device records: MAC, vendor prefix and sanitised hostname, visible in the parent app only, deleted after a fixed retention (proposal 30 days for dismissed devices).
- Online-time estimate: daily totals per child only, not per hour or per device; retention proposal 8 weeks.
- Child text (ask-for-time reason) is hostile input: escaped, length-limited, never in pushes, digests or router policy.

### Notification design constraints

- Self-hosted first. Option A: ntfy on the owner's own host; nothing leaves the house network except what ntfy is configured to relay. Option B: browser Web Push; the payload goes encrypted through the browser vendor's push service, a third party, and the service needs outbound HTTPS to it. The owner picks (decision list below).
- Honest delivery state: the service can only know the push was accepted by ntfy or the push service. It never claims "delivered" or "seen". States shown: "sent to push service", "push failed (reason)", "no push set up". A failed push leaves the in-app alert open.
- Triggers: alert creation only, not every count increment. Expired subscriptions (HTTP 404/410) are removed. Subscriptions are per account and revoked on logout.
- Keys: VAPID private key or ntfy token in an environment secret, never in the repo.

### Phase 0: prove what exists

- Earlier empty-policy rehearsal and one-device pilot passed with restoration. Appliance release `54f294f9` deployed at integration schema 17 and passed its external health check. Those results are scoped to the actions observed.
- The remaining MVP sequence starts with permanent installation and management protection. It then verifies one approved fixed-MAC device and its scoped service path, followed by the grant and activity checks in [Live proof](#live-proof).
- The 2026-11-08 decision accepted unbounded INSTALL and waived the unsigned M4b receipt for the reviewed rollout. Each exact live invocation requires its own approval. Router-byte follow-ups remain separate unless approved for a release.
- Record the installed router release and observe one 15-minute grant lifting an active schedule block, followed by router-local re-blocking at expiry while the appliance is stopped. Flow offload variants, DST, reboot and power loss need separate evidence.
- Keep `timeRequests.mode` off for household rollout until the scoped live grant test passes. Use an explicitly approved flag window for the test.
- Stop after a failed or uncertain mutation, preserve evidence, and use only the separately approved recovery action.

### Phase 1: no-router wins on built foundations (items 1, 5, 7 one-shot, 6 audit log)

Phase 1 service and parent controls are merged, including the one-shot focus controls and status chip (#176). Live acceptance for grants, Reward Time and focus remains scoped to its respective test. Schedule service progress is tracked in Phase 3.

Can be built and merged offline behind flags before Phase 0 finishes; turning flags on waits for Phase 0.

- **Steps (PR-sized):**
  1. Service: per-account flag gate (owner only / all parents). Tests: gate off, owner only, all. **Built (F1, PR #92, merged): `timeRequests.mode` off, owner or parents plus `ownerAccountId`; unverified on this router.**
  2. Service: audit log table (actor account, action type, child, time, operation id, result; no free text). Writes from pause, resume, bulk, move, grant. Route `GET /audit`: admins see every row, other parents their assigned children. Tests: scoping 404s, no reason text stored. **Built (F2, PR #93, merged; flag `auditLog.enabled`, off; unverified on this router; see [service contract](service-contract.md#audit-log-of-parent-actions-flagged-off)).**
  3. Web: ask-for-time parent card (applying, then confirmed or "couldn't apply"; never optimistic), Grant and End, child "starting..." state; demo router keeps the feature disabled. Tests: Playwright on the demo; update the parent PWA spec. **Built (F3, PR #94, merged): Grant, Grant less, Decline, End extra time, honest Applying/Granted states; the child "starting..." copy was not part of it. Unverified on this router.**
  4. Reward Time landed in the service (#95) and parent UI (#107) behind `rewardTime.enabled`. The per-viewer `rewardTime` field of `GET /people` gates the controls. A reward extends an allowance through `queue()` and refuses totals over 60 minutes from router time. Pause ends the allowance, and a child with a pause and no active allowance is refused. The router horizon adds a second bound. See the [service contract](service-contract.md#reward-time-flagged-off). Live proof remains.
  5. One-shot focus is a timed pause with a Focus label. The service (#104) and parent controls (#176) are merged behind `focus.enabled`, off by default. See the [service contract](service-contract.md#focus-window-flagged-off) for expiry and the ask-for-time interaction. Live proof remains.
  6. Docs: service contract, operating guide. **Done (F6): [operating notes](service-contract.md#operating-notes-for-the-flagged-features).**
- **Entry:** #86 and #88 merged.
- **Exit / done:** all merged with flags off; CI green; each item labelled unverified until its live check (grant lift and re-block, reward arithmetic on the router, focus expiry) passes after Phase 0.
- **Owner decisions before start:** Decided (owner, 2026-10-27) and built: the focus window ends only by a parent/admin; a child's ask never ends it (F5); Reward Time total cap (reward + grant together at most 60 min), audit retention (90 days).
- **Router release:** none.
- **Rollout:** owner only for a week, then all parents.
- **Stop / rollback:** any grant shown "approved" that the router did not confirm, or any unscoped audit read: flag off, fix, re-review.

### Phase 2: notifications and digest (items 4, 6 digest)

The B7 service backend (#118) is merged behind `push.enabled` and `digest.enabled`. It sends content-free ntfy alerts and a counts-only weekly digest. C4 (#168) can add a household blocked-lookup count when content-filter counts are enabled.

- Finish the selected provider and subscription lifecycle, parent settings and test-push, honest delivery states, and in-app digest and schedule controls. Use the existing sender and digest job as the starting point.
- **Tests:** payload snapshot test asserting no names, MACs, addresses or domains; adapter tests against a local fake push endpoint; digest counts from fixtures; quiet-hours boundaries.
- **Entry:** Phase 1 audit log merged; owner has picked the provider.
- **Exit / done:** a test push reaches the owner's phone at home (live, but no router needed); a forced failure shows "push failed". Unverified: delivery during a WAN outage beyond what was tried.
- **Owner decisions before start:** decided 2026-11-24 (see Decisions only the owner can make): self-hosted ntfy with the iPhone relay on; digest to admins only, Sunday 18:00; digest quiet hours 21:00 to 07:00, alerts at any hour except a short list of low-urgency kinds held until morning.
- **Router release:** none.
- **Rollout:** owner only, then all parents; digest off until two weekly digests have been checked by the owner.
- **Stop / rollback:** any payload with a name, address or domain, or any push to a revoked subscription: flag off.

### Phase 3: schedules and age-band templates (items 2, 7 recurring)

- S1 landed database schedule truth and identity-checked seeding (#177, #185). S2a added admission and receipt settlement (#189). S2m landed audited mutation routes and schedule DTOs (#190), and S2b added passkey step-up for loosening and deletion (#191). The S2a recovery fence leaves a known limit for a router apply that lands after the fence. Unrouted children are refused. Staged windows, late promotion and an operator abandon path remain outside this implementation.
- S4 landed the [Extra time / Skip tonight service routes](service-contract.md#schedule-extra-time-and-skip-tonight-roadmap-item-2-s4) (#192). The [recurring focus kind](service-contract.md#recurring-focus-roadmap-item-7) landed in #193. The service changes ship behind the applicable flags.
- Connect the existing editor to integration create/update/delete and passkey step-up, with router time, freshness and confirmed operation states. Expose the S4 controls and recurring kind. The age-band template model (`web/public/schedule-templates.js`, D1 times) is built behind `schedules.editable` and is unverified on this router; the add-form picker ("Age band (optional)", create mode only, nothing sent until Save) is built behind the same flag and is unverified on this router. Optional S5, exposing kernel timezone, stays with the next approved router release.
- The Phase 1 allowance and audit paths are merged. Use an approved window for live testing and complete Phase 0 before household rollout.
- Merge the remaining controls behind the appropriate flags and observe the live time-window tests with offload off and on, a cross-midnight window, and confirmation of an empty set after cleanup. Kernel timezone behavior across DST requires separate evidence.
- **Owner decisions before start:** age bands decided 2026-11-24 (four bands, each with a school-night and a weekend off-time, editable starting points); timezone strategy (trust `--kerneltz` only if the live test passes, otherwise service-compiled UTC windows) is decided at the live test.
- **Router release:** none (S5 rides Phase 4 if taken).
- **Rollout:** owner only on one test child device first, then all parents.
- **Stop / rollback:** any window that does not block or does not lift as confirmed: flag off, delete test windows, router must confirm an empty set.

### Phase 4: one router release for unassigned devices (items 3, 10; optional 2-S5; 9 if the rule is lifted in time)

- **Steps:** (1) service: unknown-device detection from the existing `rpc-inventory` (new MAC not assigned and not protected), parent list, alerts and pushes (no router change; can merge early in this phase); (2) router: new desired-JSON field for unassigned devices (restricted or guest: internet only, no LAN) with fixture tests in `tests/test-core.py` / `test-rpc.py`, never applied to protected or management MACs; (3) shared schema + service: send the field only when the flag is on; (4) web: device list actions (assign, keep as guest, block); (5) docs: enforcement contract, runbook.
- **Entry:** Phase 0 passed and its release id is known; Phase 2 merged.
- **Exit / done:** separate security and code reviews approved; new release id recorded; live: a new test device lands restricted/guest, cannot reach the LAN or the router admin page, and adult devices keep password login to router and CT107. Unverified: behaviour with every phone OS's private-address rotation.
- **Owner decisions before start:** decided 2026-11-24: "restricted" is internet only for 24 hours pending a parent's choice, starting with alerts only (decide default-restrict after a month); guests get internet only, no LAN, printers or casting, and no time limit at first. Item 9 rides this release (D9).
- **Router release:** the one new release id for items 3, 10 (and S5, and 9 if approved before the release is cut).
- **Rollout:** alerts first (no router effect); then the router field on for one test device window; then household.
- **Stop / rollback:** any loss of password access from an adult or management device, or any protected MAC caught by the rule: stop, console rollback to the previous release, report. Hard rule: the unassigned rule must never apply to protected MACs; surface the `protectedAbsent` warning from `scope-preview` (rotated adult address) before any live step.

### Phase 5: estimates and hardening (items 8, 9)

- **Item 8 steps:** (1) measurement spike, offline then live: compare counter-based "online minutes" with known use on a test device, offload off and on; publish the error found; (2) service: daily estimate from `rpc-activity` deltas, labelled "estimate"; (3) web: per-child view; (4) only if the owner chooses enforcement: auto-pause at the limit via the existing pause op, with a warning push first.
- **Item 9 steps:** (1) re-measure the DNS baseline and record it; (2) router: wider DoH list (port 853 for kids is already blocked, `router/lib/firewall.sh:53-58`), behind a desired-JSON field; no VPN/Tor list (9c, not built); only the kids' firewall DNS rules may change; (3) bypass tests from a test device; (4) docs with the limits (VPN and Tor still work).
- **Entry:** Phase 0; for 8 also Phase 2 (warning push); for 9 the owner's lift of 2026-10-27 (kids' firewall DNS rules only; `AGENTS.md:39` still forbids dnsmasq and WAN changes; DHCP and adult/management traffic stay out of scope).
- **Exit / done:** 8: the measured error is shown next to the estimate. 9: baseline before and after recorded; bypass attempts blocked or the gap documented.
- **Owner decisions before start:** decided 2026-11-24: estimate only, no auto-pause, "online" is forwarded traffic in a minute, no limits until measured; the wider DoH list stays the checked static list refreshed by hand quarterly, with no release of its own.
- **Router release:** 8 none (UNVERIFIED until the spike); 9 (wider DoH list only; 9c not built) joins Phase 4's release if the lift came first, otherwise one more release id.
- **Rollout:** estimate visible to the owner only for two weeks before anyone acts on it; enforcement only after that.
- **Stop / rollback:** an estimate off by more than the published error, or any DNS breakage for adults: flag off or roll back the release.

### Risks

- Phase 0 still needs permanent installation and the current-release one-device MVP. Earlier restored pilots and appliance health each cover only their observed scope.
- Default-restricted or guest rules locking an adult or the management device out (Phase 4 rollback rule).
- Flow offload bypasses activity counters and may affect time rules: estimates (item 8) and windows (item 2) can be wrong.
- DST and kernel timezone on this firmware are unverified.
- Phones rotating their Wi-Fi address escape per-device rules and trigger repeated unknown-device alerts.
- Push via Web Push relies on a browser vendor's service; ntfy relies on the owner's host being up.
- Several open router-byte PRs (#87, watchdog) can each mint a release id; folding them in is an owner call.

### Decisions only the owner can make

On 2026-11-24 the owner accepted every recommendation in the decision briefs D1 to D9; they are recorded in the rows below and the briefs were removed. Decided means the choice is made, not that the feature exists or is verified on the router. D3 changes behaviour: alert pushes have no quiet-hours check today, so the held-until-morning list is new work for Phase 2 step 2.

Asked per phase, not all up front. Already decided (do not re-ask): ask-for-time 60 min cap, no daily limit, lifts pauses and schedules, pause wins; schedule editors, step-up only on loosening/deleting, Extra time/Skip tonight = allowance with the 60 min cap, merge before live proof behind a flag.

| Before | Decision |
|---|---|
| Phase 0 | Approve each exact live invocation and its bound plan. Review future watchdog and router-byte changes separately. |
| Phase 1 | Decided (owner, 2026-10-27): the focus window ends only by a parent/admin; a child's ask never ends it. Reward Time total cap 60 min, audit retention 90 days |
| Phase 2 | Decided (owner, 2026-11-24, D2 to D4): self-hosted ntfy with the iPhone relay on; digest to admins only, Sunday 18:00; digest quiet hours 21:00 to 07:00, alerts at any hour except a short list of low-urgency kinds held until morning |
| Phase 3 | Decided (owner, 2026-11-24, D1): four age bands, each with a school-night and a weekend off-time, as editable starting points. Still open: timezone strategy at the live test |
| Phase 4 | Decided (owner, 2026-11-24, D5, D6, D9): alert first; restricted = internet only for 24 h pending a parent's choice; alerts only at first, decide default-restrict after a month. Guests: internet only, no LAN, printers or casting, no time limit at first. DNS hardening rides this release |
| Phase 5 | Decided (owner, 2026-11-24, D7 to D9): estimate only, no auto-pause; "online" = forwarded traffic in a minute; no limits until measured. Wider DoH list: keep the checked static list, refreshed by hand each quarter with a reminder, and no new router release for it alone (the rule lift for the kids' firewall DNS rules was given 2026-10-27) |

### Unverified

- The permanently installed router release and its allowance behavior on the approved MVP device.
- Kernel time gate and windows with flow offload on; DST.
- Household rollout of the per-account flags beyond the tested account scope.
- That item 8 needs no router change and that counters give a useful estimate.
- That the default-restricted rule can be added without touching DNS or WAN config.
- Push delivery under a flaky WAN.

## Follow-ups

- RPC job durations reached 1,227 s in run 45112488488 and 1,372 s in run 45105254648 with four partitions. With five RPC partitions the stored case weights predict a maximum of 688 s, down from 861 s. Compare the next green CI run with these measurements. Transition still uses four partitions.
- Close fd 9 for `timeout` children, a stderr warning when buffered output is lost, and the remaining full-pipe/signal tests (tracked in [tier1-rpc §9](contracts/tier1-rpc.md)).
- The iOS restyle (#80) still needs the owner’s iPhone check. Check changed web paths before starting another browser slice. The owner decisions draft (#182) covers product choices separately.

## Live proof

Operator records report a passed empty-policy rehearsal and a passed scoped one-device pilot, with restoration in both runs. See the [pilot runbook](runbooks/live-penn-pilot-v2.md#outcomes-and-recovery) for the scope and recovery criteria. The appliance deploy at `54f294f9` passed schema 17 startup and external health on 2026-11-22. These checks are separate from current router installation and packet acceptance.

### One-device MVP acceptance

Use one assigned parent and one approved fixed-MAC device. Compare each observation with the matching fixture evidence. Keep household identifiers, private manifests and raw captures in private operational records.

| Pending live check | Existing offline coverage |
| --- | --- |
| Verify the permanent router release and rollback readiness. Confirm that the approved fixed-MAC test device is outside the full protected set. Observe continued access for the protected management and adult devices and to the appliance, including password recovery access. Confirm the scoped appliance transport before exercising policy. | [Permanent install fixtures](../tests/test-permanent-install.py), [installer and restoration fixtures](../tests/test-install.py) and [RPC fixtures](../tests/test-rpc.py). |
| Observe a weekly block, manual Pause and Resume, and the parent status after router confirmation. Verify the test device’s actual reachability. | [Schedule service fixtures](../service/tests/integration-schedules.test.ts), [demo schedule editor browser scenarios](../web/tests/schedule-editor.spec.ts) and [router core fixtures](../tests/test-core.py). Integration browser wiring remains in [Phase 3](#phase-3-schedules-and-age-band-templates-items-2-7-recurring). |
| While the weekly block is active, approve a 15-minute request and confirm access returns. With separate approval to stop the appliance, keep it stopped through router expiry and observe that the active schedule blocks again. Restart and reconcile the parent status. | [Grant service fixtures](../service/tests/time-requests-grant.test.ts), [parent request scenarios](../web/tests/time-requests-card.spec.ts) and [router-local re-block fixture](../tests/test-core.py). |
| Compare a scoped activity baseline and later sample with the parent view. Confirm that it shows estimates and coverage. | [Integration activity fixtures](../service/tests/integration-activity.test.ts) and [activity browser scenarios](../web/tests/activity.spec.ts). |

Record the result of each check against the specific release, device scope and observed conditions. Reboot, power loss, offload variants, DST, general packet coverage, and sync timing inside the 13-second OS-trust window require separate evidence. NextDNS delivery and continuous activity polling are outside this MVP.

## Limits to state to users

A router cannot reliably stop mobile data or hotspots, VPN, Tor, or a determined child. Device-level tools (Screen Time, Family Link) complement it. Per-device and client-IPv6 traffic, flow offload, inbound UDP, the 5 s cutoff and key confinement are unproven. See "Known limits" in [RUNBOOK.md](RUNBOOK.md).
