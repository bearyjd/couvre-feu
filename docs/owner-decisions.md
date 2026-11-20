# Owner decision briefs

Status: decision aid, written 2026-11-20 from `docs/ROADMAP.md` ("Decisions only the owner can make" and the "Owner decisions still needed" column). Nothing here is decided until the owner says so. Once a decision is made, record it in `ROADMAP.md` and delete the brief here.

Rules every option below respects: the [privacy design gate](ROADMAP.md#privacy-design-gate) (counts and action types only, no domains, content or browsing data) and the [Do not build](ROADMAP.md#do-not-build) list. No option here involves reading messages, location, search terms or per-site history. `AGENTS.md:39` still forbids changing dnsmasq or the WAN zone; no option touches them. Every feature stays behind an off-by-default flag and is "unverified on this router" until a live run.

## Contents

- [Summary table](#summary-table)
- [How to read a brief](#how-to-read-a-brief)
- [D1 Age bands and template times](#d1-age-bands-and-template-times)
- [D2 Push provider: ntfy or Web Push](#d2-push-provider-ntfy-or-web-push)
- [D3 Quiet hours](#d3-quiet-hours)
- [D4 Weekly digest: recipients, day and time](#d4-weekly-digest-recipients-day-and-time)
- [D5 What "restricted" means for new devices](#d5-what-restricted-means-for-new-devices)
- [D6 Guest isolation scope and time limits](#d6-guest-isolation-scope-and-time-limits)
- [D7 Daily online time: meaning, limits, "online"](#d7-daily-online-time-meaning-limits-online)
- [D8 Wider DoH list: source and refresh owner](#d8-wider-doh-list-source-and-refresh-owner)
- [D9 New router release for the wider DoH list](#d9-new-router-release-for-the-wider-doh-list)
- [What each answer unblocks](#what-each-answer-unblocks)
- [Sources and dates](#sources-and-dates)

## Summary table

| # | Decision | Phase / item | Recommendation (one line) |
|---|---|---|---|
| D1 | Age bands and template times | 3 / item 2 | Four bands with a school-night and a weekend off-time each; editable starting points, not rules |
| D2 | Push provider | 2 / item 4 | Self-hosted ntfy (already built), with the iPhone relay switched on |
| D3 | Quiet hours | 2 / item 4 | Keep 21:00 to 07:00 for the digest; send alerts at any hour except a short list of low-urgency kinds held until morning |
| D4 | Digest recipients, day, time | 2 / item 6 | Admins only, Sunday 18:00 (what the code does today) |
| D5 | Meaning of "restricted"; default-restrict or not | 4 / item 3 | Alert first; restricted = internet only for 24 h pending a parent's choice; start with alerts only and decide on default-restrict after a month |
| D6 | Guest isolation and time limit | 4 / item 10 | Internet only, no LAN, no printers or casting; no time limit at first |
| D7 | Quota meaning, limits, "online" | 5 / item 8 | Estimate only, no auto-pause; "online" = forwarded traffic in a minute; no limits set until measured |
| D8 | Source and refresh owner for wider DoH list | 5 / item 9 | Keep the checked static list; owner refreshes it by hand every quarter with a reminder |
| D9 | New router release for DoH list | 5 / item 9 | Do not cut a release for this alone; ride the Phase 4 release |

## How to read a brief

Each brief has: the question; two or three options with effort, privacy risk, whether the router changes, and what needs live proof; one recommendation with the reason; and the single sentence the owner must answer. "Router change: yes" means new router bytes and a new release id. "Live proof" means a run on the real router (or phone) with the owner at home, after Phase 0.

---

## D1 Age bands and template times

**Question.** When a parent creates a weekly schedule (bedtime, "internet off"), which age groups should the starting templates cover, and what off and on times should each template suggest?

**What exists.** The design (item 2) lets parents edit every window; templates are only starting points. Already decided: who edits, extra confirmation only when loosening or deleting, Extra time and Skip tonight capped at 60 min, at most 8 windows per child. Not decided: the bands and the times. The research doc lists age presets in eero (Pre-K / Pre-Teen / Teen / Adult) and TP-Link HomeShield ("age templates"); neither publishes the times they use that we could verify (UNVERIFIED). No authoritative external source for "right" bedtimes was fetched for this brief, so the numbers below are the author's illustrative suggestion, not evidence.

**Options.**

| Option | Bands | Effort | Privacy | Router change | Live proof |
|---|---|---|---|---|---|
| A. Three bands | under 10, 10 to 13, 14 and over | S | None; the service stores only the band name chosen, no birth date | No (S1-S4) | Time windows with flow offload off then on, cross-midnight, DST |
| B. Four bands | under 10, 10 to 12, 13 to 15, 16 to 17 | S (one more template) | Same | No | Same |
| C. No templates | Parents type times for every child | Smallest | None | No | Same | 

Suggested starting times for B (illustrative, UNVERIFIED as a standard): under 10: off 19:30, on 07:00, weekend off 20:30, on 07:30. 10 to 12: 20:30 / 07:00, weekend 21:30 / 08:00. 13 to 15: 21:30 / 07:00, weekend 22:30 / 08:00. 16 to 17: 22:30 / 07:00, weekend 23:30 / 08:00.

Consequences: more bands means more to explain and more wrong guesses; fewer means each template fits fewer children. Option C removes the decision but makes the first setup slower for every parent. Templates never apply by themselves; a parent saves each window.

**Recommendation: B**, because the four age steps match common school stages and a template that is slightly wrong costs a parent one edit, while no template costs a parent a blank page.

**The owner must answer:** "Use these four bands and these school-night and weekend times, or give me your own list of bands and times."

---

## D2 Push provider: ntfy or Web Push

**Question.** How should parents' phones be told "there is a new alert"? Through a notification server the owner runs (ntfy), or through the browser's own push system (Web Push)?

**What exists.** The service side for ntfy is built and off (`push.enabled`, content-free text "New alert. Open the app to see it.", one private topic, admins only, no phone ever verified). Web Push is only a sketch in `service-contract.md`; no code. Neither sends names, devices, domains or reasons.

**Options.**

| Option | How it works | Effort | Privacy risk | Router change | Live proof |
|---|---|---|---|---|---|
| A. ntfy, self-hosted, with the iPhone relay | Owner runs ntfy; phones subscribe to a private topic. On iPhone, instant delivery needs the server to tell ntfy.sh a message exists | S (built; setup steps and a test) | Low. The relay gets only a message id and a hash of the topic, no text (ntfy docs, fetched 2026-11-20); iPhone shows a generic "New message" | No | A test push reaches a real phone at home and away from home; behaviour if the ntfy host is down |
| B. ntfy, no relay | Same, no ntfy.sh contact | S | Lowest: nothing leaves the household | No | Same, but on iPhone the docs say delivery can take "hours" without the relay (ntfy docs, 2026-11-20) |
| C. Web Push | Service sends encrypted payloads to the browser vendor's push service (Apple, Google, Mozilla) | M to L: subscription routes, key storage, settings screen, expired-subscription cleanup | Low content risk (payload is content-free and encrypted) but a third party sees that the household's phones get notifications, and when | No | Delivery on each phone; iPhone only works after "Add to Home Screen" on iOS 16.4 or later (WebKit blog, 2023-02-16); outbound HTTPS from the service |

Other consequences. A: needs the ntfy host to be reachable by phones, and the topic name is a secret (an access token is also recommended); the ntfy iOS app is a separate install (UNVERIFIED that it is on the App Store today; not checked). C: no extra server, but a bigger build and a new secret (VAPID key) to keep. All options: the service can only say "sent", never "delivered".

**Recommendation: A**, because it is already built, keeps content in the house, and the only third-party contact is a message id; take B instead if the household has no iPhones or wants nothing to leave the house at all.

**The owner must answer:** "Use ntfy, with or without the ntfy.sh relay for iPhones, or use Web Push."

---

## D3 Quiet hours

**Question.** At what times should the system hold back notifications so nobody is woken?

**What exists.** `service/src/digest.ts` holds the weekly digest from 21:00 to 07:00 America/New_York and sends it at 07:00. Alert pushes are not held back at all (no quiet-hours check in `push-runtime.ts`). The roadmap's phase-2 settings screen would add a per-parent setting, not built.

**Options.**

| Option | What it does | Effort | Privacy | Router | Live proof |
|---|---|---|---|---|---|
| A. Digest only (today) | Alerts always push | None | None | No | None |
| B. Hold low-urgency alerts overnight | Urgent kinds (for example a failed enforcement) push at once; the rest wait until 07:00 | S | None | No | A forced alert at 23:00 shows the right behaviour |
| C. Hold all alerts overnight, per parent | Settings screen with a start and end per parent | M | None | No | Same |

Consequence: A can wake a parent for a new-device alert at 03:00; C can delay a real problem until morning.

**Recommendation: B**, with 21:00 to 07:00 as the default, because it removes the wake-ups that do not need action while keeping real faults loud. Which kinds count as urgent needs the owner's list (the author suggests only "enforcement failed or drifted").

**The owner must answer:** "Quiet hours are [times]; these alert kinds may wake us, everything else waits."

---

## D4 Weekly digest: recipients, day and time

**Question.** Who receives the weekly counts summary, and when?

**What exists.** Built and off (`digest.enabled`, requires push): Sunday 18:00 New York time, text like "Last 7 days: N requests, N grants, N pauses." plus an optional one-line blocked-lookups count. Counts only, one household number, no child names, no per-device detail. Recipients today: whoever is subscribed to the single private ntfy topic, which the contract says should be admins only.

**Options.**

| Option | Consequence |
|---|---|
| A. Admins only, Sunday 18:00 (today) | No work; both parents who are admins see it; non-admin parents do not |
| B. Admins only, different day or time | A one-line constant change; needs a DST sweep test run again |
| C. All parents | Needs per-account push addresses (the service stores none today), so it depends on D2 Web Push or a per-person topic; M effort |

Privacy: all options are counts only; the child-visible question is whether children are told the digest exists. Router change: none. Live proof: the roadmap rule is that the owner checks two real digests against the app's own numbers before relying on them.

**Recommendation: A**, because it is built and the content is minimal; revisit C only if a non-admin parent needs it.

**The owner must answer:** "Send the digest to [which people] on [day] at [time]."

---

## D5 What "restricted" means for new devices

**Question.** When an unknown device joins the Wi-Fi, should it be blocked, treated as a guest (internet only), or just reported? And should this be automatic?

**What exists.** Built (service only, unverified): the device list and a `new_device` alert; a parent can classify a device as kid, adult, infrastructure, home, guest or ignored. Not built: any rule on the router for unassigned devices. Default-restrict is the only part needing a router change and a new release id.

**Options.**

| Option | Effort | Privacy | Router change | Live proof |
|---|---|---|---|---|
| A. Alert only (today) | None | Low: MAC, vendor prefix, sanitised hostname, parent view only, 30-day retention proposed | No | MAC-rotation behaviour on phones with private Wi-Fi addresses |
| B. Default to guest profile (internet only; see D6) | M | Same | Yes | New test device lands as guest, cannot reach LAN or router admin page; adult password login to router and CT107 still works |
| C. Default to blocked until a parent approves | M | Same | Yes | Same, plus no protected or management MAC is ever caught |

Consequences: B and C reduce the "new phone escapes" gap but rotating private addresses may make an owned phone look new each time (alert noise, and a locked-out child device). C risks a visiting adult or a rotated adult phone losing access; the roadmap hard rule is that the rule must never touch protected MACs, and `scope-preview` must warn first.

**Recommendation: A now, then B.** Ship alerts, watch for a month how often addresses rotate in this household, then decide on B with real numbers. C is the most disruptive and the easiest to get wrong.

**The owner must answer:** "New devices should be [only reported / treated as guests / blocked], and automatic or not."

---

## D6 Guest isolation scope and time limits

**Question.** What can a guest device do, and for how long?

**What exists.** Item 10 is not started. It reuses D5's unassigned-device rule. Guest SSID is a separate router change needing approval (research doc).

**Options.**

| Option | Effort | Privacy | Router change | Live proof |
|---|---|---|---|---|
| A. Internet only, no LAN at all | M | Low | Yes | Guest cannot reach LAN devices or the router admin page; adults keep password login |
| B. Internet plus a short allow list (printer, casting device) | M to L | Low, but each exception widens the hole and casting needs device discovery that is hard to prove | Yes | Same, plus each allowed device works |
| C. A or B, and guests expire (for example 24 hours then re-approve) | +S | Low | Yes (or service-side expiry) | Expiry actually removes access |

**Recommendation: A, no expiry at first**, because it is the simplest rule to prove blocks what it claims; add expiry later if guests overstay.

**The owner must answer:** "Guests get internet only with no access to anything on the home network, and [do / do not] expire after [time]."

---

## D7 Daily online time: meaning, limits, "online"

**Question.** Should the app show only an estimate of each child's daily online time, or also cut the connection at a limit? What number, and what counts as "online"?

**What exists.** Not started. The router already counts bytes per child device (`rpc-activity`); these show forwarded traffic, not what it was. Known weaknesses: flow offload skips the counters, IPv6 inbound is not counted, background traffic looks like use (`docs/activity-counters.md`). Privacy gate: daily totals per child only, 8 weeks retention (proposal).

**Options.**

| Option | Effort | Privacy | Router | Live proof |
|---|---|---|---|---|
| A. Estimate only, labelled "estimate", owner-visible two weeks first | L (spike, service, web) | Medium: a minor's usage pattern; daily totals only | Probably none (UNVERIFIED) | Counters vs real use, offload off and on; the measured error is published |
| B. A, then auto-pause at a limit with a warning push first | A plus M | Same | None (existing pause op) | Same, plus the pause fires at the limit; needs D2 first |
| C. Do not build | None | None | None | None |

"Online" definition options: (i) a minute counts if the child's device sent or received more than a small amount of forwarded traffic; (ii) a minute counts only above a higher threshold to skip background chatter. The threshold is a measurement result, not something to guess; the spike picks it.

Consequence: a wrong estimate that cuts off a child at 40 minutes of real use is worse than no limit. Limits per child are meaningless until the error is known.

**Recommendation: A**, no auto-pause and no limits until the measured error is published, because the roadmap already warns the counters can mislead and a visible, labelled estimate harms no one.

**The owner must answer:** "Build the estimate only (or also auto-pause, or not at all), and count a minute as online [by the measured rule / by this rule]."

---

## D8 Wider DoH list: source and refresh owner

**Question.** Where does a longer list of encrypted-DNS (DoH) server addresses come from, and who keeps it up to date?

**What exists.** A static list of seven providers (32 IPv4 and 28 IPv6 addresses, checked 2026-10-27 against vendor pages) ships behind `dnsHardening.dohList`, off. It never refreshes itself. Provider addresses change (Mullvad's public DNS shut down 2026-11-02 and its addresses were retired). The router holds at most 256 per family and rejects those addresses for children's devices only. A VPN/Tor list is decided not built (2026-10-28). Even a perfect list leaves unlisted DoH servers, VPNs, Tor and mobile data open.

**Options.**

| Option | Effort | Privacy | Router | Live proof |
|---|---|---|---|---|
| A. Keep the hand-checked static list; owner re-checks quarterly | S per refresh | None | No | Bypass attempts from a test device; DNS baseline re-measured before and after |
| B. Add more providers by hand now (extend the table in `docs/dns-hardening.md` with sources) | S to M | None | No | Same |
| C. Pull a community list automatically | M | Low, but a third-party feed controls what is blocked; licence and size review needed (the roadmap already notes these problems for VPN lists) | No for the list itself; a refresh job is service-side | Same, plus handling a feed that disappears or grows past 256 |

**Recommendation: A**, with a calendar reminder for the owner, because it keeps each address traceable to an official page and avoids a feed that could block something unrelated; it is honest about the limit. Name one person as refresh owner.

**The owner must answer:** "[Name] refreshes the list from vendor pages every [quarter / other], and we do not use an automatic feed."

---

## D9 New router release for the wider DoH list

**Question.** Is a wider DoH list worth its own router release, or should it wait and ride another one?

**What exists.** The service already merges the list through the existing `doh` policy field, so a list change needs no new router bytes. A release is only needed if the router code must change (for example a new field). The roadmap says several open router-byte PRs (#87, the watchdog) can each mint a release id, and that folding them together is an owner call. The 2026-10-27 lift covers the kids' firewall DNS rules only.

**Options.**

| Option | Consequence |
|---|---|
| A. No release for DoH alone; service-side list rides the live release | No router risk; effort S; live proof of the existing rules is part of Phase 0 anyway |
| B. Join the Phase 4 release (unassigned devices) | One live window, one rollback plan; DoH waits for Phase 4 |
| C. Separate release now | Extra live window, extra rollback risk, extra review for a small gain |

**Recommendation: A, then B** if a router change turns out to be needed, because each release id is a live-install risk and the list does not need one.

**The owner must answer:** "Do not cut a release for DoH alone; fold any router change into the Phase 4 release."

---

## What each answer unblocks

| Decision | Roadmap steps unblocked |
|---|---|
| D1 | Phase 3, step S3 (web editor with age-band templates, `schedules.editable`); recurring focus windows (item 7) that sit on top of schedules |
| D2 | Phase 2 steps 1 and 2 (push sender adapters, subscription routes, settings screen); Phase 2 entry ("owner has picked the provider"); turning on `push.enabled`; every later "alert plus push" (items 3, 8 warning push) |
| D3 | Phase 2 step 2 (settings screen quiet-hours control) and its quiet-hours boundary tests |
| D4 | Phase 2 step 3 (digest job) and its rollout rule (two checked digests before all parents) |
| D5 | Phase 4 steps 2 and 3 (router field for unassigned devices, shared schema, service sending it); Phase 4 step 4 device actions wording |
| D6 | Phase 4 item 10 steps (guest rule, isolation test) and the "keep as guest" action in step 4 |
| D7 | Phase 5 item 8 steps 1 to 4 (spike, estimate, web view, optional auto-pause) |
| D8 | Phase 5 item 9 steps 1 to 3 (baseline, list contents, bypass tests) |
| D9 | Phase 5 item 9 step 2 (router work) and the Phase 4 release scope |

Not blocked by anything here: Phase 0 (live rehearsal, watchdog bound, plan hash), which gates every live proof above.

## Sources and dates

- Repo documents read 2026-11-20: `docs/ROADMAP.md`, `docs/service-contract.md` (push and digest section), `docs/enforcement-contract.md` (DNS enforcement today), `docs/dns-hardening.md`, `docs/activity-counters.md`, `docs/prp/PRP-006-content-filtering.md`, `docs/research/comparable-products-features.md`; code: `service/src/digest.ts` (quiet hours and schedule), `service/src/push-runtime.ts` (no quiet-hours check found).
- ntfy documentation, "iOS instant notifications" and access control, https://docs.ntfy.sh/config/ (fetched 2026-11-20; only the first part of a long page was read).
- WebKit blog, "Web Push for Web Apps on iOS and iPadOS", https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/ (post dated 2023-02-16; fetched 2026-11-20). It does not cover VAPID details.
- UNVERIFIED: current App Store availability of the ntfy iOS app; whether recent iOS releases changed Web Push rules after 16.4; age-appropriate bedtime guidance (no source fetched); eero and TP-Link template times; the accuracy of counter-based online time on this router.
