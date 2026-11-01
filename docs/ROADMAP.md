# Roadmap

Status as of 2026-10-29; planned additions added 2026-10-27. This is the current plan; the original proposal was an internal planning note that is no longer kept in the repository. "Built" means code merged and tested in CI. It does **not** mean proven on a real router: nothing here has been run live yet (see [Live proof](#live-proof)).

## Planned additions at a glance

Ten additions picked from the comparable-products research (PR #90), phased in. Details, owner decisions and rules: [Planned additions](#planned-additions) and [Plan](#plan).

| # | Addition | Phase | State |
|---|---|---|---|
| 1 | Ask for time: web UI + parent one-tap approve | 1 | Built and merged, all behind `timeRequests.mode` (off by default): service (PR #86, #88), per-account gate off/owner/parents (F1, PR #92), parent card with Grant, Grant less, Decline and End extra time (F3, PR #94). Unverified on this router: live proof remains |
| 5 | Reward Time (extra minutes on a grant) | 1 | Service built and merged (F4, PR #95) behind `rewardTime.enabled` (off; unverified on this router); parent UI built (PR #107) behind `rewardTime.enabled`, shown per viewer via the `rewardTime` field of `GET /people` (unverified on this router) |
| 7 | Focus / homework window (one-shot in 1, recurring in 3) | 1 and 3 | One-shot service built and merged (F5, PR #104) behind `focus.enabled` (off; unverified on this router); no web UI yet; recurring not started (depends on item 2) |
| 6 | Audit log of parent actions (1); weekly digest, counts only (2) | 1 and 2 | Audit log built and merged (F2, PR #93) behind `auditLog.enabled` (off; unverified on this router; web "Activity log" view built behind `auditLog.enabled` (unverified on this router), shown per viewer via the `auditLog` field of `GET /people`); B5 follow-up: refused owner-guard attempts audited as `owner_guard_refused` (migration 013, admin-visible only); weekly counts-only digest built behind `digest.enabled` (B7, off, service-only, unverified; see [service contract](service-contract.md#push-and-weekly-digest-b7-service-only-off)) |
| 4 | Push notifications (self-hosted ntfy or Web Push) | 2 | Service side built behind `push.enabled` (B7: ntfy adapter, content-free, admin topic; off, unverified, no web UI or Web Push); settings screen and subscriptions not started ([service contract](service-contract.md#push-and-weekly-digest-b7-service-only-off)) |
| 2 | Weekly schedules / bedtime with age-band templates | 3 | Designed; owner decisions recorded; not started beyond the design |
| 3 | Unknown-device alerts + new devices default to restricted | 4 | Alerts, device list and admin web panel built and merged (service: `inventory-store.ts`, `inventory-http.ts`, router `rpc-inventory`; web: "Devices on the network"; `new_device` and `inventory_stalled` alerts). Unverified on this router. Default-restricted for unassigned devices not started |
| 10 | Guest / visitor profile (internet only, no LAN) | 4 | Not started |
| 8 | Per-child daily online time, labelled an estimate | 5 | Not started |
| 9 | DNS hardening (wider DoH list; port 853 is already blocked for kids). The VPN/Tor list (9c) is NOT BUILT, see [Do not build](#do-not-build) | 5 (or 4) | Rule lifted for the kids' firewall DNS rules only (2026-10-27); VPN/Tor list decided not to build (2026-10-28) |

Phase 0 (prove what already exists) comes before all of them.

## Tier 1: basics (built, not yet proven live)

Block or unblock one child, block or unblock all children, assign and move devices, parent sign-in with passkeys, and router-local timed pauses.

Open before the first live use:

| Item | State |
|---|---|
| First live rehearsal, then permanent install | Not run. Needs the owner at home and approval of the exact plan hash ([runbook](runbooks/live-first-rehearsal.md)). |
| Install watchdog (bound the install step) | Not merged. The bound must come from a measured install time on a quiet host or the real router; the first measurement under load exceeded the 80 s stop rule. A clean TERM at the `intent` phase leaves the router needing `recover-install-lock`, so the teardown outcome needs a redesign. |
| M4b evidence receipt | Template exists; not filled or signed. |
| Service key entry on the router, confinement probes, dispatch, live pause/resume/expiry/reboot tests | Follow the live rehearsal. |
| Fixed Wi-Fi address for children's devices | Household rule: scope and protection are MAC-based, so a device that rotates its address escapes them. |

## Tier 2: next

| Item | State |
|---|---|
| Ask for time (child requests, parent one-tap approval as timed grants) | Built behind `timeRequests.mode` (off by default; legacy `enabled` reads as `parents`): service in PR #86 and follow-up PR #88, per-account gate in PR #92, parent card in PR #94 (all merged). Grants are router allowances, 60 min cap, lift pauses and schedules, a parent's Pause ends a grant. Live proof remains: [Planned additions](#planned-additions) item 1, Phase 1. The design is in the maintainer's local planning notes (not in this repository). |
| Weekly schedules / bedtime per child | Designed; builds after ask-for-time. Item 2, Phase 3. The first four steps need no router change and can merge behind an off-by-default flag; live proof of the time windows (flow offload off) needs the owner at home. The design is in the maintainer's local planning notes (not in this repository). |
| Device recognition and unknown-device alerts | Built and merged on the service side (`service/src/inventory-store.ts`, `service/src/inventory-http.ts`, read-only `rpc-inventory`, [tier1-rpc §2](contracts/tier1-rpc.md)) with the admin "Devices on the network" web panel and `new_device` / `inventory_stalled` alerts; unverified on this router. Item 3, Phase 4. "New devices default to restricted" is not started and is the only part that needs a router change. |
| DNS enforcement | Partly shipped, all unproven on a live router: kids' IPv4 port 53 redirect (IPv6 port 53 rejected), kids' DoT/DoQ block (TCP/UDP 853, UDP 784 and 8853, unconditional: `router/lib/firewall.sh:53-58`), and a DoH reject set filled from the policy `doh` arrays (at most 256 per family; nothing in the service generates the list yet). See [enforcement contract](enforcement-contract.md#dns-enforcement-today). Item 9, Phase 5: wider DoH list (VPN/Tor list not built, see Do not build). The owner lifted the "no DNS changes" rule on 2026-10-27 for the kids' firewall DNS rules only. `AGENTS.md:39` still forbids changing dnsmasq or the WAN zone; DHCP and adult/management traffic stay out of scope because the lift covered only those rules. The DNS baseline still has to be re-measured. |
| Per-child AdGuard profiles | Not recommended: on the GL firmware it likely breaks GL's own filtering, and AdGuard's per-client schedule is an inverse window that does not match this project's schedule model. Research notes are local (not in this repository). |

## Tier 3: later

Now planned as items 4 to 10 of [Planned additions](#planned-additions): DNS hardening (item 9, without a VPN/Tor list), focus/homework window (item 7), guest profile (item 10), daily time quota as an estimate (item 8), weekly summary and audit log (item 6), push notifications (item 4), Reward Time (item 5). The activity view beyond the digest stays unplanned.

## Planned additions

Source: the comparable-products research (PR #90, `docs/research/comparable-products-features.md` once merged), section 4 shortlist, corrected against the current code and contracts. Effort: S = one or two PRs, M = three to five, L = more, with live measurement. "Router change" means new router bytes and so a new release id. Every flag is OFF by default; nothing changes for the household until the owner turns a flag on.

| # | Addition | Value | Effort | Router change | Privacy risk | Needs live proof | Depends on | Owner decisions still needed | Flag (proposed) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Ask for time: web UI + parent one-tap approve | High: the most asked-for flow; service exists | M (web only) | No (grants up to 4 h use existing allowances) | Low: the child's reason text is shown only to parents, never in pushes or router policy | Grant lifts a pause/schedule; kernel gate re-blocks at `until` with the service stopped; reboot | #86, #88 merged | None. Already decided (60 min cap, no daily limit, lifts pauses and schedules, a parent's Pause ends it, approvers = scoped parents + admins) | `timeRequests.enabled` (exists) |
| 2 | Weekly schedules / bedtime with age-band templates | High | M | No for steps S1-S4; optional S5 (router reports kernel tz) | Low | Windows with flow offload off then on, cross-midnight, DST | Item 1 merged (Extra time reuses its allowance path); item 6 audit log | Age bands and template times (new). Already decided: who edits, step-up only on loosening/deleting, Extra time/Skip tonight = allowance with the 60 min cap, merge behind a flag before live proof, cap 8 windows per child | `schedules.editable` |
| 3 | Unknown-device alerts + new devices default to restricted/unassigned | Medium-high: closes the "new phone escapes" gap | M | Alerts: no (existing read-only `rpc-inventory`). Default-restricted: yes | Low: MAC, vendor prefix, sanitised hostname only; stored for the parent view, never pushed | MAC rotation on phones with private Wi-Fi addresses; default rule never touches protected or management MACs | Item 4 (to notify); Phase 0 router release settled | What "restricted" means (blocked, or guest profile from item 10); whether to default-restrict at all | `deviceAlerts.enabled` (service); router: off unless the desired JSON carries the new field |
| 4 | Push notifications for approvals, expiries, unknown devices, drift | High: alerts are only visible while the app is open today unless `push.enabled` is on (B7) | M | No | Low if payloads stay content-free (see [Privacy gate](#privacy-design-gate)) | Delivery while WAN/DNS is flaky; honest "not delivered" state | Existing `parent_alerts` | Push provider (self-hosted ntfy vs browser Web Push); quiet hours | `push.enabled` |
| 5 | Reward Time: extra minutes added to a grant without changing the schedule | Medium | S | No | None | Grant arithmetic against the 60 min cap (the 14400 s router horizon stays as a defence-in-depth guard) | Item 1 | None. Decided and built: reward and grant together never exceed 60 min from router time | `rewardTime.enabled` |
| 6 | Audit log of parent actions; weekly digest (counts only) | Medium: both parents can see who did what | S (log) + S (digest) | No | Low: counts and action types only, no domains | None beyond status fidelity | Log: none. Digest: item 4 or the in-app view | Digest recipients and day/time. Audit retention is decided (90 days) | `auditLog.enabled`, `digest.enabled` |
| 7 | Focus / homework window: one-shot or recurring | Medium | S | No (one-shot reuses timed pause; recurring reuses schedules) | None | Same as timed-pause expiry; recurring = item 2's proof | One-shot: none. Recurring: item 2 | Decided (owner, 2026-10-27): the focus window ends only by a parent/admin (Pause/Resume, or approving the request); a child's ask never ends it | `focus.enabled` |
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
  - `web/public/app.js`: one UI PR in flight at a time; the planned split of tab logic out of `app.js` (Follow-ups) goes before Phase 3 if it can.
  - `router/` release bytes: at most two new release ids for all ten items (Phase 4, and Phase 5 only if DNS is not ready in time).

### Privacy design gate

Every PR in Phases 1-5 states in its description how it meets these; reviewers block on a miss.

- No domains, URLs, page titles, search terms or content anywhere: database, logs, alerts, pushes, digests.
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

- **Items:** none new. First live rehearsal and permanent install; install watchdog decision; ask-for-time live grant test (item 1's design step S5).
- **Entry:** owner at home and says go; the M4b install-recovery fix (known blocker for the first rehearsal) is in; a measured install time on a quiet host or the real router for the watchdog bound; the watchdog teardown redesign for a TERM at the `intent` phase; #86, #88 merged.
- **Exit / done:** rehearsal receipt filled; the installed release id is recorded and known to include router allowances; one 15 min grant observed to lift a block and re-block at `until` with the service stopped. Verified = only what was observed in that run. Still unverified after Phase 0: DST behaviour, flow offload with time rules on, power loss.
- **Owner decisions before start:** watchdog bound (from the measurement); approve the exact plan hash.
- **Router release:** settles which release id is live. Open router-byte changes (#87 hardening follow-ups, the watchdog) either go into this release or wait for Phase 4; Phase 4 builds on whatever is live.
- **Rollout:** `timeRequests.enabled` stays off until the live grant test passes.
- **Stop / rollback:** any failure in the one run: stop, report, no retry in the same session; console rollback.

### Phase 1: no-router wins on built foundations (items 1, 5, 7 one-shot, 6 audit log)

**Progress (2026-10-29):** steps 1 to 4 and 6 are merged behind flags, all off and unverified on this router; step 5 (item 7, focus window) is half done: the one-shot service is merged (PR #104), the web UI is not started. Per-item live proof waits for Phase 0.

Can be built and merged offline behind flags before Phase 0 finishes; turning flags on waits for Phase 0.

- **Steps (PR-sized):**
  1. Service: per-account flag gate (owner only / all parents). Tests: gate off, owner only, all. **Built (F1, PR #92, merged): `timeRequests.mode` off, owner or parents plus `ownerAccountId`; unverified on this router.**
  2. Service: audit log table (actor account, action type, child, time, operation id, result; no free text). Writes from pause, resume, bulk, move, grant. Route `GET /audit`: admins see every row, other parents their assigned children. Tests: scoping 404s, no reason text stored. **Built (F2, PR #93, merged; flag `auditLog.enabled`, off; unverified on this router; see [service contract](service-contract.md#audit-log-of-parent-actions-flagged-off)).**
  3. Web: ask-for-time parent card (applying, then confirmed or "couldn't apply"; never optimistic), Grant and End, child "starting..." state; demo router keeps the feature disabled. Tests: Playwright on the demo; update the parent PWA spec. **Built (F3, PR #94, merged): Grant, Grant less, Decline, End extra time, honest Applying/Granted states; the child "starting..." copy was not part of it. Unverified on this router.**
  4. Service + web: Reward Time as one allowance op through `queue()` (the same path schedules S4 will reuse); cap per the owner's decision. Tests: arithmetic at the cap from router time (the 14400 s horizon is a defence-in-depth guard behind the cap), pause ends it; a paused child with no active allowance is refused, one with an allowance in force is extended. **Service built (F4, PR #95, merged; flag `rewardTime.enabled`, off; unverified on a router; reward + grant together capped at 60 min, refused not clamped; see [service contract](service-contract.md#reward-time-flagged-off)); web UI built (PR #107, merged; per-viewer `rewardTime` field of `GET /people`) behind `rewardTime.enabled`, unverified on this router.**
  5. Service + web: focus window, one-shot = a timed pause with a "Focus" label. Tests: expiry, ask-for-time interaction per decision. **One-shot service built (F5, PR #104, merged; flag `focus.enabled`, off; unverified on this router; see [service contract](service-contract.md#focus-window-flagged-off)); web UI not started.**
  6. Docs: service contract, operating guide. **Done (F6): [operating notes](service-contract.md#operating-notes-for-the-flagged-features).**
- **Entry:** #86 and #88 merged.
- **Exit / done:** all merged with flags off; CI green; each item labelled unverified until its live check (grant lift and re-block, reward arithmetic on the router, focus expiry) passes after Phase 0.
- **Owner decisions before start:** Decided (owner, 2026-10-27) and built: the focus window ends only by a parent/admin; a child's ask never ends it (F5); Reward Time total cap (reward + grant together at most 60 min), audit retention (90 days).
- **Router release:** none.
- **Rollout:** owner only for a week, then all parents.
- **Stop / rollback:** any grant shown "approved" that the router did not confirm, or any unscoped audit read: flag off, fix, re-review.

### Phase 2: notifications and digest (items 4, 6 digest)

Before Phases 3-5 because later items emit events into it.

- **Steps:** (1) service: push sender behind an interface with ntfy and Web Push adapters, subscription routes, content-free payload, 404/410 cleanup, delivery state per alert; (2) web: settings screen (subscribe, test push, quiet hours, honest state text) and service worker fetch-on-tap; (3) service: digest job (weekly counts per child from the audit log and alerts) delivered through push and shown in-app; (4) docs.
- **Tests:** payload snapshot test asserting no names, MACs, addresses or domains; adapter tests against a local fake push endpoint; digest counts from fixtures; quiet-hours boundaries.
- **Entry:** Phase 1 audit log merged; owner has picked the provider.
- **Exit / done:** a test push reaches the owner's phone at home (live, but no router needed); a forced failure shows "push failed". Unverified: delivery during a WAN outage beyond what was tried.
- **Owner decisions before start:** push provider; digest recipients and day/time; quiet hours default.
- **Router release:** none.
- **Rollout:** owner only, then all parents; digest off until two weekly digests have been checked by the owner.
- **Stop / rollback:** any payload with a name, address or domain, or any push to a revoked subscription: flag off.

### Phase 3: schedules and age-band templates (items 2, 7 recurring)

- **Steps:** the design's S1-S4: (S1) schedule truth moves from the manifest to the service database, atomically; (S2) `scheduleMutate`, step-up on loosening/deleting, writes to the Phase 1 audit log; (S3) web editor with age-band templates as editable starting points, status pills, router-time label; (S4) Extra time / Skip tonight through the Phase 1 allowance path. Then recurring focus windows as a schedule type. Optional S5 (router reports kernel tz) is held for the Phase 4 release.
- **Tests:** validator unit tests (seeded, edited, pending, foreign); HTTP 202 then confirmed via the fake router; 409 races; step-up binding; Playwright with an integration fixture; cross-midnight stored as one record.
- **Entry:** Phase 1 merged (allowance path, audit log). Building does not need Phase 0; turning on does.
- **Exit / done:** merged behind `schedules.editable`; live time-window test passed (offload off, then on; cross-midnight; empty set confirmed after cleanup). Unverified until a DST change has been observed: kernel tz behaviour.
- **Owner decisions before start:** age bands and template times; timezone strategy (trust `--kerneltz` only if the live test passes, otherwise service-compiled UTC windows) is decided at the live test.
- **Router release:** none (S5 rides Phase 4 if taken).
- **Rollout:** owner only on one test child device first, then all parents.
- **Stop / rollback:** any window that does not block or does not lift as confirmed: flag off, delete test windows, router must confirm an empty set.

### Phase 4: one router release for unassigned devices (items 3, 10; optional 2-S5; 9 if the rule is lifted in time)

- **Steps:** (1) service: unknown-device detection from the existing `rpc-inventory` (new MAC not assigned and not protected), parent list, alerts and pushes (no router change; can merge early in this phase); (2) router: new desired-JSON field for unassigned devices (restricted or guest: internet only, no LAN) with fixture tests in `tests/test-core.py` / `test-rpc.py`, never applied to protected or management MACs; (3) shared schema + service: send the field only when the flag is on; (4) web: device list actions (assign, keep as guest, block); (5) docs: enforcement contract, runbook.
- **Entry:** Phase 0 passed and its release id is known; Phase 2 merged.
- **Exit / done:** separate security and code reviews approved; new release id recorded; live: a new test device lands restricted/guest, cannot reach the LAN or the router admin page, and adult devices keep password login to router and CT107. Unverified: behaviour with every phone OS's private-address rotation.
- **Owner decisions before start:** what "restricted" means; guest isolation scope; whether 9 joins this release.
- **Router release:** the one new release id for items 3, 10 (and S5, and 9 if approved before the release is cut).
- **Rollout:** alerts first (no router effect); then the router field on for one test device window; then household.
- **Stop / rollback:** any loss of password access from an adult or management device, or any protected MAC caught by the rule: stop, console rollback to the previous release, report. Hard rule: the unassigned rule must never apply to protected MACs; surface the `protectedAbsent` warning from `scope-preview` (rotated adult address) before any live step.

### Phase 5: estimates and hardening (items 8, 9)

- **Item 8 steps:** (1) measurement spike, offline then live: compare counter-based "online minutes" with known use on a test device, offload off and on; publish the error found; (2) service: daily estimate from `rpc-activity` deltas, labelled "estimate"; (3) web: per-child view; (4) only if the owner chooses enforcement: auto-pause at the limit via the existing pause op, with a warning push first.
- **Item 9 steps:** (1) re-measure the DNS baseline and record it; (2) router: wider DoH list (port 853 for kids is already blocked, `router/lib/firewall.sh:53-58`), behind a desired-JSON field; no VPN/Tor list (9c, not built); only the kids' firewall DNS rules may change; (3) bypass tests from a test device; (4) docs with the limits (VPN and Tor still work).
- **Entry:** Phase 0; for 8 also Phase 2 (warning push); for 9 the owner's lift of 2026-10-27 (kids' firewall DNS rules only; `AGENTS.md:39` still forbids dnsmasq and WAN changes; DHCP and adult/management traffic stay out of scope).
- **Exit / done:** 8: the measured error is shown next to the estimate. 9: baseline before and after recorded; bypass attempts blocked or the gap documented.
- **Owner decisions before start:** quota semantics and limits; whether to cut a new release for a wider DoH list.
- **Router release:** 8 none (UNVERIFIED until the spike); 9 (wider DoH list only; 9c not built) joins Phase 4's release if the lift came first, otherwise one more release id.
- **Rollout:** estimate visible to the owner only for two weeks before anyone acts on it; enforcement only after that.
- **Stop / rollback:** an estimate off by more than the published error, or any DNS breakage for adults: flag off or roll back the release.

### Risks

- Phase 0 is not done; every live claim waits on it, and the install-recovery blocker gates it.
- Default-restricted or guest rules locking an adult or the management device out (Phase 4 rollback rule).
- Flow offload bypasses activity counters and may affect time rules: estimates (item 8) and windows (item 2) can be wrong.
- DST and kernel timezone on this firmware are unverified.
- Phones rotating their Wi-Fi address escape per-device rules and trigger repeated unknown-device alerts.
- Push via Web Push relies on a browser vendor's service; ntfy relies on the owner's host being up.
- Several open router-byte PRs (#87, watchdog) can each mint a release id; folding them in is an owner call.

### Decisions only the owner can make

Asked per phase, not all up front. Already decided (do not re-ask): ask-for-time 60 min cap, no daily limit, lifts pauses and schedules, pause wins; schedule editors, step-up only on loosening/deleting, Extra time/Skip tonight = allowance with the 60 min cap, merge before live proof behind a flag.

| Before | Decision |
|---|---|
| Phase 0 | Watchdog bound from a real measurement; approve the plan hash; which open router changes go into the rehearsal release |
| Phase 1 | Decided (owner, 2026-10-27): the focus window ends only by a parent/admin; a child's ask never ends it. Reward Time total cap 60 min, audit retention 90 days |
| Phase 2 | Push provider (ntfy vs Web Push); digest recipients and day/time; quiet hours |
| Phase 3 | Age bands and template times; timezone strategy at the live test |
| Phase 4 | What "restricted" means for new devices; guest isolation scope; whether DNS hardening joins this release |
| Phase 5 | Quota semantics (estimate only or auto-pause) and limits; new router release for a wider DoH list (the rule lift for the kids' firewall DNS rules was given 2026-10-27) |

### Unverified

- Whether the installed router release includes allowances (Phase 0 checks).
- Kernel time gate and windows with flow offload on; DST.
- That a per-account flag gate fits the current account model.
- That item 8 needs no router change and that counters give a useful estimate.
- That the default-restricted rule can be added without touching DNS or WAN config.
- Push delivery under a flaky WAN.

## Follow-ups

- Longest CI shard is now `test-transition.py` (four partitions, about 904 s predicted, 50% of the 1800 s lane budget), then `test-rpc.py` (about 861 s); a fifth partition each would bring both under about 730 s.
- Split the tab logic out of `app.js` into its own file (needs a service static-file allowlist change).
- Close fd 9 for `timeout` children, a stderr warning when buffered output is lost, and the remaining full-pipe/signal tests (tracked in [tier1-rpc §9](contracts/tier1-rpc.md)).
- Parent iPhone check of the iOS restyle before it merges.

## Live proof

Unproven until a real run: power loss and durability, hardware behaviour, live traffic and packets, reboot, sync timing under the 13 s window with the OS-trust profile, the kernel time gate with flow offload on, and whether the installed release includes router allowances.

## Limits to state to users

A router cannot reliably stop mobile data or hotspots, VPN, Tor, or a determined child. Device-level tools (Screen Time, Family Link) complement it. Per-device and client-IPv6 traffic, flow offload, inbound UDP, the 5 s cutoff and key confinement are unproven. See "Known limits" in [RUNBOOK.md](RUNBOOK.md).
