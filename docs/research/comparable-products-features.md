# Comparable parental-control / household network-control products: feature research

Researched 2026-10-26 (web fetches of vendor pages, official docs, GitHub READMEs/API). Research only; no repo, router or CT107 contact.
Project baseline read: docs/ROADMAP.md, docs/enforcement-contract.md and README.md.
Evidence labels: **[P]** = fetched a primary source (vendor page, official docs, README, license file). **[S]** = only a search-result summary or third-party page (treat as lead). **UNVERIFIED** = not confirmed from a primary source; do not rely on it.
Fetch caveats: some vendor pages are JS-rendered or timed out (Circle Home Plus, Firewalla, Norton, Microsoft, gnu.org). Prices change and are often promos; verify before quoting.

## 1. Products (what they offer, what they need, price, comparison to router-local)

### A. Paid / commercial
- **Circle (now "part of Aura")**: web filter, time limits, internet pause, history, usage monitor; page says it manages "mobile devices across all networks ... using the Aura app" (app on kid device) and adds in-game voice/text monitoring for 200+ PC games (Windows only). 14-day free trial, then a paid plan; Aura promo page showed Kids $10/mo and Family $32/mo (promo, may change). https://meetcircle.com/ [P], https://www.aura.com/parental-controls [P]. Circle Home Plus hardware status/price: UNVERIFIED (meetcircle.com/unbundled-hardware says the old Circle device is no longer sold [S]). Needs cloud account + device app for off-network. Router-local: ours has no content scanning and no off-network reach, but needs no account or cloud.
- **Bark**: App from $14/mo (7-day trial); **Bark Home** (network box) from $6/mo or $79 one-time. Features listed: site/app blocking, location tracking and alerts, "text, app & social media monitoring", alerts for potential dangers, screen-time schedules, remote alarms, app and contact approvals. Bark Home lists blocking + schedules only (location/text monitoring shown as absent). https://www.bark.us/pricing/ [P]. Message monitoring needs on-device app. This is the surveillance bundle we should avoid.
- **Qustodio**: category filtering, activity timeline/browsing history/YouTube views, time limits and routines, "pause the internet at the touch of a button", family locator, call/SMS tracking (Android/iOS), daily/weekly emailed reports, AI alerts on "concerning messages or searches". https://www.qustodio.com/en/features/ [P]. Price UNVERIFIED (pricing pages disagree; search summary ~$55-110/yr [S]). Needs device apps and cloud account.
- **Net Nanny**: screen-time hours/scheduling, website blocker, app blocking, location, family feed, YouTube video titles/length/view date, social media protection, alerts/reports; "as little as $5 per device" (Family Protection Pass). https://www.netnanny.com/features/ [P]. Device apps + cloud.
- **Norton Family**: time supervision (schedules + daily caps), web supervision (blocks + visited sites), location supervision (30-day history, Favorite Locations alerts) on Windows/Android/iOS. https://us.norton.com/norton-family [S]. Price UNVERIFIED (third-party lists $49.99/yr).
- **Kaspersky Safe Kids**: GPS, YouTube/web filtering and Safe Search, daily app time limits, device scheduling, app/web/YouTube reports, battery alerts, child-visible limit bar. Its own FAQ says "Router-level controls apply only within the home network and cease to function once a child leaves or switches to mobile data." https://www.kaspersky.com/safe-kids [P]. Price UNVERIFIED.
- **Google Family Link**: supervised child accounts; bedtime, daily limits, per-app time view, device location (Android/Fitbit), Play content restrictions; needs the Family Link app. https://support.google.com/families/answer/7101025 [P]. Price not on page (commonly free; UNVERIFIED here).
- **Apple Screen Time**: on-device; Ask to Buy / Ask to Browse, Limit Adult Websites (default on under 18), Communication Safety (on-device nudity/violence detection in messages/video), and from iOS 26 a child can "request an exception to the limit" (parent responds). https://support.apple.com/en-us/105121 [P] and https://support.apple.com/en-us/108806 [P]. No separate price on page.
- **Microsoft Family Safety**: app/game and device time limits (Windows, Xbox, Android), parents can approve extra time on request, Edge web/search filtering with SafeSearch, location sharing, activity reports, up to six members. Only 2020 launch coverage found: https://news.microsoft.com/en-cee/2020/07/30/now-available-microsoft-family-safety-app-helping-you-protect-what-matters-most/ [S, stale]. Current price/features UNVERIFIED (vendor page failed to load).
- **Aura (Parental Controls)**: content filter, screen-time alerts, "Messaging Insights", "AI App Monitoring & Alerts", "Digital Wellbeing Score". https://www.aura.com/parental-controls [P]. Messaging scanning = privacy-risky class.
- **Gryphon (router + app)**: profiles with screen-time, device/app time limits and age-based web filters; Premium Protection adds alerts on "inappropriate and dangerous terms searched" in Google/Bing/DuckDuckGo, YouTube watched-video titles, per-device and per-app daily limits. https://gryphonconnect.com/ [P]. Subscription price UNVERIFIED. Router-level product with a vendor cloud; search-term and watch-history logging is the privacy-risky part.
- **eero Plus** ($9.99/mo or $99.99/yr; free trial, per https://eero.com/eero-plus [P]): Content Filters per profile with age presets (Pre-K/Pre-Teen/Teen/Adult), categories incl. Shopping, Social Media, Chat, Streaming, YouTube Restricted, Block Apps, advanced scheduling, activity history, ad blocking, VPN, backup data. Included free: profiles, pause, block device, limit access, guest Wi-Fi. https://support.eero.com/hc/articles/360052742411 [P]. Note [S]: "resuming" a profile overrides an active schedule until the next scheduled pause (similar to our allowance precedence).
- **TP-Link HomeShield (Deco/Archer)**: basic parental tier: content filter, bedtime schedules, profiles, age templates; the comparison table also lists Wi-Fi access control (approve trusted, block unfamiliar devices), guest isolation and device visibility (which tier carries each: UNVERIFIED). Optional paid "Advanced Parental Controls" add-on (1-month trial): time limits, bedtime, category filtering, SafeSearch, app blocker, **Reward Time** ("adds extra screen time without changing daily limits"), **Family Time** pause, usage reports, activity notifications. https://www.tp-link.com/us/homeshield/ [P]. Add-on price not on page: UNVERIFIED.
- **NETGEAR Smart Parental Controls (Orbi/Nighthawk)**: per-child profiles, adult-content blocking; Premium adds schedules, time limits and "screen time rewards"; 30-day trial then subscription (price UNVERIFIED). https://www.netgear.com/home/services/smart-parental-controls/ [P] (support article, updated 2025-07).
- **ASUS AiProtection / Parental Controls**: Time Scheduling per device (Disable/Time/Block), "Block All Devices", Web & Apps filters on Trend Micro models only and requires accepting a Trend Micro EULA; schedules depend on router clock/NTP. https://www.asus.com/support/faq/1008720/ [P]. Free with the router.
- **Firewalla**: rules = Allow/Block/Time Limit/Disturb with target (app, domain, IP, port, region, target list), device, schedule; Family Protect (native or OpenDNS-based), Active Protect IPS, Ad Block; "Kid Lock" because kids with a paired device can disable rules. https://help.firewalla.com/hc/en-us/articles/360008521833 [S]. Price/subscription model UNVERIFIED.
- **Linksys / Plume / Fing**: Linksys Shield (Trend Micro-based paid add-on; $4.99/mo [S, press/app store], UNVERIFIED). Plume HomePass: "set Focus schedules, and quickly freeze devices", screen-time per person, age-appropriate filtering, cloud + ISP oriented: https://www.plume.com/homepass [P]. Fing Agent (Pi/NAS/Docker agent): new-device alerts, block intruders, schedules; "available only with a paid subscription": https://www.fing.com/products/fingbox [P]; price UNVERIFIED.

### B. Free / open source
- **Pi-hole** (EUPL per LICENSE files in pi-hole/pi-hole and pi-hole/FTL; EUPL version not confirmed in lines read; 61k stars): DNS sinkhole; Group Management gives per-client blocking (https://docs.pi-hole.net/group_management/example/ [P]); **no built-in schedules** (only a 2026 feature request [S]); FTL **privacy levels** 0-3 (show everything / hide domains / hide domains+clients / anonymous): https://docs.pi-hole.net/ftldns/privacylevels/ [P]. Needs DNS control (we may not touch dnsmasq).
- **AdGuard Home** (GPL-3.0, 37.7k stars): DNS filtering, parental control (adult domains), forced Safe Search, per-client config, access settings: https://github.com/AdguardTeam/AdGuardHome [P]. Blocked services with schedule per client: ROADMAP notes it is an inverse window; vendor KB not re-read this session. Ships in GL firmware (ROADMAP: per-child profiles not recommended).
- **NextDNS** (cloud DNS; Free $0 up to 300,000 queries/mo, Pro $1.99/mo or $19.90/yr; https://nextdns.io/pricing [P]): categories, SafeSearch, YouTube Restricted Mode, block apps/games, **Recreation Time** (allow only in windows), logs retention 1h-2y or disabled, works "on all networks" via DoH/DoT: https://nextdns.io/ [P]. Cloud dependency, domain-level only, bypassable by other DNS unless forced.
- **Lantern Watch** (MIT, 4 stars, GL.iNet + AdGuard Home; closest comparable): device dashboard, pause (30m/1h/rest of day/indefinite, pause everyone, groups), "Hours of Peace" bedtime, Focus Times, per-device daily limit, social-media profiles, YouTube Restricted, DNS bypass protection (port 53 forced, DoH provider blocks, optional DoT), unknown-device and "possible VPN" alerts, ntfy/Telegram/email push, daily/weekly summaries, per-domain query log with 7-90 day retention. https://github.com/LanternWatchApp/lantern-watch [P]. Admits DNS filtering "cannot inspect content inside an allowed HTTPS app" and HTTPS block pages show a certificate warning. Differences: it logs domains and depends on AdGuard Home and a Python service; no confirmed-state enforcement model.
- **OpenAppFilter (OAF)** (GPL-2.0 per GitHub metadata, 2.9k stars): DPI app identification as OpenWrt package (luci-app, daemon, kernel module), independent of DNS. https://github.com/destan19/OpenAppFilter [P]. Kernel module + DPI on GL stock kernel: UNVERIFIED feasibility.
- **Other OpenWrt pieces** [P unless noted]: adblock-fast (AGPL-3.0-or-later; DNS blocklists for dnsmasq/unbound; https://git-03.infra.openwrt.org/feed/packages/plain/net/adblock-fast/README.md), nlbwmon (per-host/MAC conntrack-netlink traffic accounting, monthly DB; https://github.com/jow-/nlbwmon; license UNVERIFIED, third party says ISC), ntopng (GPLv3, heavy; https://github.com/ntop/ntopng), Nodogsplash (GPL captive portal; https://github.com/nodogsplash/nodogsplash), banIP (GPL-3.0-or-later per OpenWrt 21.02 listing [S]), luci-app-parentcontrol (not located; UNVERIFIED), luci-app-statistics/mwan3 (not reviewed).
- **Technitium DNS** (GPL-3.0, 10k stars): Advanced Blocking app = regex block lists per client IP/subnet: https://github.com/TechnitiumSoftware/DnsServer [P]. **OPNsense/pfSense pfBlockerNG/Squid**: DNSBL not per-group [S forum]; time rules via firewall schedules; needs a firewall box, not our router.
- **Home Assistant**: FRITZ!Box Tools exposes "parental control switches" to enable/disable internet access per device on schedule: https://www.home-assistant.io/integrations/fritz/ [P]. Shows the pattern "automation toggles per-device router block". Router-specific; not for GL.iNet.
- **Other GitHub (top by stars from API queries 2026-10-26; search was flaky, list incomplete)**: destan19/OpenAppFilter 2929 GPL-2.0; cbuijs/sdproxy 60 MIT (DNS proxy); masaleem-oss/Fengard 40 Apache-2.0 (nftables/DNS parental on OpenWrt, not reviewed); Vladikamira/pihole-parental-control 6 MIT; LanternWatchApp/lantern-watch 4 MIT; raymanzhang/openwrt-parental-control 4 Apache-2.0. ActivityWatch/OpenSnitch/Firezone/headscale: not relevant (on-device activity tracking / outbound-app firewall / access control); not reviewed.

## 2. Feature matrix
Legend: Y = offered per a source cited above; - = not listed on the pages read (not proof of absence); ? = UNVERIFIED; d = domain-level only; P = paid, F = free/OSS/bundled-free. Columns: Cir=Circle/Aura(P) Brk=Bark(P) Qst=Qustodio(P/F tier) Eer=eero Plus(P) TPL=TP-Link HomeShield(F basic/P add-on) NG=Netgear SPC(P) Fwl=Firewalla(P hw) Apl=Apple Screen Time(F) FL=Family Link(F) AGH=AdGuard Home(F) PiH=Pi-hole(F) NDN=NextDNS(F/P) LW=Lantern Watch(F)

| Feature | Cir | Brk | Qst | Eer | TPL | NG | Fwl | Apl | FL | AGH | PiH | NDN | LW |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Schedules / bedtime | Y | Y | Y | Y | Y | Y | Y | ? | Y | Y(per ROADMAP) | - | Y | Y |
| Time quotas per app/category | Y | ? | Y | - | Y | Y | Y | ? | Y | - | - | - | Y(per device) |
| Rewards / chores-for-time | - | - | - | - | Y | Y | - | - | - | - | - | - | - |
| Pause button | Y | ? | Y | Y | Y | ? | ? | - | ? | Y | - | - | Y |
| Location | - | Y | Y | - | - | - | - | ? | Y | - | - | - | - |
| App/web category filtering | Y | Y | Y | Y | Y | Y | Y | Y | ? | Y | Y(lists) | Y | Y |
| Safe search / YouTube restricted | ? | ? | ? | Y | Y | ? | Y | ? | ? | Y | - | Y | Y |
| Content/safety alerts (self-harm, bullying) | Y(PC games) | Y | Y | - | ? | - | ? | Y(on-device) | - | - | - | - | d |
| Screen-time reports / timelines | Y | ? | Y | Y | Y | ? | ? | Y | Y | Y(d) | Y(d) | Y(d) | Y(d) |
| New / unknown-device alerts | - | - | - | ? | Y(access ctl) | ? | ? | n/a | n/a | - | - | - | Y |
| Guest network / profiles | - | - | - | Y | Y | - | ? | n/a | n/a | - | - | Y(configs) | - |
| Homework / focus mode | ? | - | ? | - | Y(Family Time) | - | ? | ? | ? | - | - | Y(Recreation) | Y |
| VPN / proxy bypass detection | ? | - | ? | - | ? | - | ? | - | - | - | - | - | Y(heuristic) |
| Ad / tracker blocking | - | - | - | Y | ? | - | Y | - | - | Y | Y | Y | Y |
| Per-device / per-person profiles | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Age-based presets | ? | ? | ? | Y | Y | ? | ? | Y(defaults) | ? | - | - | - | Y(Open/Mod/Strict) |
| Approval requests | - | Y | ? | - | - | - | - | Y | ? | - | - | - | - |
| Multi-parent roles | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? | ? |
| Push notifications | ? | Y | Y | ? | Y | ? | ? | ? | ? | - | - | - | Y |
| Works with vendor cloud down | ? | ? | ? | ? | ? | ? | ? | Y(on-device) | ? | Y | Y | - | Y |
| Weekly digest to parents | ? | ? | Y | ? | Y(reports) | ? | ? | ? | ? | - | - | - | Y |
| Family-wide pause / rules | ? | ? | ? | ? | Y | ? | ? | - | - | Y | - | Y | Y |
| Travel / mobile-data coverage | Y(app) | Y(app) | Y(app) | - | - | - | - | Y | Y | - | - | Y | - |

Row notes: "Approval requests" for Microsoft (extra time on request) [S, 2020]. "Multi-parent roles": no primary page read; UNVERIFIED for all. "Works with vendor cloud down": inferred only for self-hosted/on-device items; others not tested.

## 3. Fit rating for THIS project, per feature
Ratings: FITS = fits router-local; COMP = fits only with a separable optional companion; CONFLICT = conflicts with hard constraints; SKIP = not worth it.
| Feature | Rating | Reason |
|---|---|---|
| Schedules / bedtime | FITS | Built (kernel `xt_time` windows); live proof of windows with flow offload off still pending. |
| Time quotas per app/category | CONFLICT (app/category); FITS (per-child online time, estimated) | Per-app needs DPI/domains/on-device; only a coarse "online time" estimate is honest and must be labelled estimate. |
| Rewards / chores-for-time | FITS | Reward = extra timed grant on existing allowance mechanism; chores tracking is parent-entered, no router change. |
| Pause button | FITS | Built (per child / all kids, timed). |
| Location | CONFLICT | Needs on-device app and tracks minors; privacy-risky; not router-level. |
| App/web category filtering | COMP | Needs DNS lists (blocked by "no DNS changes" rule) or DPI; defer until owner lifts DNS rule; do not take over DNS. |
| Safe search / YouTube restricted | COMP | DNS rewrite on kids' DNS path; needs dnsmasq/DNS change approval; weak without port 853/DoH coverage. |
| Content/safety alerts (self-harm, bullying) | CONFLICT | Needs message/TLS/on-device inspection; surveillance of minors. |
| Screen-time reports / timelines | FITS | Estimated activity already exists; keep byte/time counters per child, no domains. |
| New / unknown-device alerts | FITS | Read-only router helper (ARP/DHCP leases); matches Tier 2 plan. |
| Guest network / profiles | FITS | Unassigned MAC = restricted default profile; guest SSID is a router change needing approval. |
| Homework / focus mode | FITS | A one-off timed window (like timed pause but auto-scheduled); Tier 3. |
| VPN / proxy bypass detection | FITS (limited) | Block lists of VPN/Tor endpoints + heuristic "activity dropped" alert; cannot stop VPN to unknown IP; word it honestly. |
| Ad / tracker blocking | SKIP | GL firmware already ships AdGuard; touches DNS; not a parental feature. |
| Per-device / per-person profiles | FITS | Built (device assignment). |
| Age-based presets | FITS | Pure PWA/service templates (bedtime defaults by age band); no router change. |
| Approval requests | FITS | Ask-for-time built service-side (off by default); web side + live proof remaining. |
| Multi-parent roles | FITS | Exists (parents scoped to children); add an audit log of who did what. |
| Push notifications | FITS | Web Push / self-hosted ntfy; no domains in payloads. |
| Outage / offline behaviour | FITS (core advantage) | Kernel-side expiry works when service/cron/clock fail; keep as a documented promise. |
| Weekly digest | FITS | Counts of pauses/grants/schedule hits/new devices; no domains. |
| Family-wide rules | FITS | "All kids" pause built; add family-wide bedtime default. |
| Travel / mobile-data coverage | CONFLICT | A router cannot see mobile data or hotspots; companion Screen Time/Family Link is the answer (ROADMAP "Limits"). |

## 4. Prioritised shortlist (candidate roadmap additions)
Order = value/risk. "Live proof" = what must be shown on the real router, not only in CI.
| # | Addition | Effort | Router change | Privacy risk | Needs live proof |
|---|---|---|---|---|---|
| 1 | Finish ask-for-time web UI + parent one-tap approve (Apple/TP-Link/MS all have request flows) | M | no (service built) | low (reason text is parent-visible only) | grant lifts pause/schedule, expires at `until` after reboot/service stop |
| 2 | Weekly schedules / bedtime with age-band templates | M | yes later (steps 1-4 no) | low | time windows with flow offload off, cross-midnight, DST |
| 3 | Unknown-device alerts + "new device defaults to restricted/unassigned" (TP-Link access control, Fing, Lantern Watch) | M | yes (small read-only helper) | low (MAC/vendor/hostname only) | MAC rotation behaviour on iOS/Android private Wi-Fi addresses |
| 4 | Push notifications (Web Push / ntfy) for approvals, expiries, unknown devices, drift | M | no | low if no domains | delivery when WAN/DNS flaky; honest "not delivered" state |
| 5 | Reward Time: extra minutes added to a grant without changing schedule (TP-Link, Netgear charge for it) | S | no | none | grant arithmetic vs 60 min cap and 14400 s router horizon |
| 6 | Weekly digest (counts only) + audit log of parent actions (visibility for each parent) | S-M | no | low | none beyond status fidelity |
| 7 | "Focus / homework" one-shot window (pause now for N min, or recurring Focus schedule) | S | no (reuses pause) | none | same as timed pause expiry |
| 8 | Per-child daily online-time quota, labelled as estimate | L | yes | medium (usage patterns of a minor) | accounting vs real traffic, offload, IPv6, background traffic |
| 9 | DNS hardening: port 853 + wider DoH list; VPN/Tor list feed | M | yes (needs owner lift of DNS rule) | low | actual bypass attempts from a test device; baseline re-measured |
| 10 | Guest / visitor profile (unassigned devices get internet-only, no LAN) | M | yes | low | isolation actually blocks LAN access |
Do NOT build: message/SMS/social scanning, location tracking, search-term or YouTube-title logging, per-domain browsing history. Why: they need on-device apps or TLS interception (hard constraint), and research finds parental-control apps routinely over-collect minors' data: ~70% of 46 Android apps shared private data without consent (PoPETs 2020, https://crysp.petsymposium.org/popets/2020/popets-2020-0029.php [P]); routers/apps/extensions had pervasive leakage and takeover flaws (ACSAC 2020, https://acsac.org/2020/program/final/s282.html [P]); the FTC barred Retina-X from selling monitoring apps without legitimacy checks after a cloud breach (https://ftc.gov/news-events/news/press-releases/2019/10/ftc-brings-first-case-against-developers-stalking-apps [S]). Domain logging is gated by the "reviewed privacy design" rule; if ever added, copy Pi-hole's privacy-level idea (hide domains/clients by default).

## 5. Licensing notes (AGPL-3.0 project). Not legal advice; ask counsel if shipping combined code.
Rule (plain): you may copy or link code into an AGPL-3.0 work only if its license is compatible in the "into AGPL-3.0" direction. Permissive (MIT, BSD, ISC, Apache-2.0), GPL-3.0 (AGPL section 13 explicitly allows combining with GPLv3 works; text at https://www.gnu.org/licenses/agpl-3.0.html, not re-fetched this session so UNVERIFIED here), and AGPL-3.0 are fine. **GPL-2.0-only is not compatible** (GPLv3-family and GPLv2-only cannot be combined into one work); GPL-2.0-or-later is fine. EUPL-1.2 is fine: its appendix lists AGPL v3 as a compatible licence (https://eupl.eu/1.2/en/ [P]).
- **Can integrate or reuse (with attribution/notices):** Lantern Watch (MIT) ideas or code, nlbwmon (license UNVERIFIED; check file), adblock-fast / banIP (AGPL/GPL-3.0-or-later; but they touch dnsmasq/firewall, which the project forbids without owner approval).
- **Run as separate processes only (arm's-length; do not copy code):** AdGuard Home (GPL-3.0; already in GL firmware), Pi-hole (EUPL), Technitium (GPL-3.0), ntopng (GPLv3, heavy).
- **Study ideas only:** Pi-hole privacy levels, Lantern Watch DoH canary + notification model, TP-Link Reward Time/Family Time, eero resume-vs-schedule precedence, Firewalla Kid Lock, Home Assistant per-device switch pattern.
- **Avoid:** OpenAppFilter (GitHub shows GPL-2.0; whether "or later" is granted was not confirmed, so treat as GPL-2.0-only and do not combine; kernel DPI module is also a firmware change); any proprietary SDK or cloud list (Trend Micro, OpenDNS Family Protect, Cloudflare for Families) because of offline-first; any code from closed vendors; anything with no license file (default all rights reserved), e.g. variia/openwrt-config shows no license.

## 6. Where competitors do badly (claimable advantages)
1. **Off-network gap is hidden or oversold.** Even a competitor states router-level controls "cease to function" on mobile data (Kaspersky FAQ [P]); Linksys' own help says pauses do not apply on mobile data [S]. Our ROADMAP already states the limit up front.
2. **Surveillance bundling and privacy record.** Message scanning, search-term logging, YouTube watch history (Aura, Bark, Gryphon, Net Nanny pages [P]) plus studies and FTC action above. Ours: no domains, no content, no location; Pi-hole-style privacy levels if logging ever arrives.
3. **Cloud accounts and paywalls for basics.** Netgear trial then subscription, TP-Link add-on for time limits/rewards, eero Plus for filters/scheduling, Fing Agent subscription-only, ASUS web filters require a Trend Micro EULA and supported models [P]. Ours: AGPL, self-hosted, works with vendor cloud absent, kernel-side expiry if the service fails.
4. **DNS-only filtering limits are admitted by the best OSS rival.** Lantern Watch says DNS cannot inspect content in an allowed HTTPS app and HTTPS block pages show cert warnings [P]. Ours makes no content claims.
5. **Ambiguous schedule/pause precedence.** eero: resume overrides schedule until next window [S]; Firewalla warns kids can disable rules [S]. Ours: written precedence (allowance > pause/schedule; local `cfctl pause` clears allowance) and fail-safe on bad clock.
6. **"Honest enforcement."** None of the vendor pages read describe router-confirmed state before claiming a block; this is an absence in the pages read, not proof no vendor does it (UNVERIFIED). Claim carefully: "we show pending/confirmed/drift; we never say blocked until the router confirms."
7. **False-positive blocks:** no primary source found; UNVERIFIED. Lantern Watch's "allow/preview a blocked site" flow hints at the problem for DNS lists, but is not evidence. Our category-free design avoids it by construction.

## 7. Gaps in this research
Not verified from primary pages: Circle Home Plus current status/price; Qustodio, Norton, Kaspersky, Gryphon, Firewalla, Netgear, Linksys, Fing prices; Microsoft Family Safety current features (only 2020 sources); Apple Downtime/App Limits wording; AdGuard Home KB on blocked-services schedules; nlbwmon/Fengard licenses; multi-parent roles for any product; GitHub "parental control router" ranking (API search was flaky). Re-run before quoting numbers externally.
