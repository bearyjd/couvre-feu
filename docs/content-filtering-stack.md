# Content filtering stack: components, configuration, risks

Companion to [PRP-006](prp/PRP-006-content-filtering.md). PRP-006 says *what* and *why*; this page says what each piece does, how it is configured, and what can go wrong with each. Status: **design documentation for work that is not built.** Configuration below is the intended end state. Anything that touches the router is a live step that needs the owner's exact-invocation approval and the `AGENTS.md:39` exception E1 recorded first; do not run it from this page.

## 1. The stack, one line each

| Component | Where it runs | Job | Does **not** do |
|---|---|---|---|
| **Couvre-feu router core** (`cfctl`, owned firewall chains) | GL-XE3000, OpenWrt 21.02 | Decides *whether* a child's device may use the internet now: pause, schedules, allowances. Redirects kids' plain DNS aimed at other addresses to the router; rejects DoT/DoQ by port and listed DoH resolvers (only with `dnsHardening.dohList` on) for kids; counts per-child bytes | Filtering by content; seeing domains; anything for adult or management MACs |
| **Couvre-feu service** (Node, SQLite) | A host in the house (systemd or Docker, [deploy runbook](runbooks/deploy.md)) | Truth for people, devices, schedules, alerts, audit. With PRP-006: holds each child's desired filter, writes it to NextDNS, reads it back, reports applied/drift; evaluates bypass signals as counts | Reading DNS logs; storing domains; acting on the router without an approved dispatch |
| **Couvre-feu parent PWA** | Parents' phones/browsers | Pause/resume, grants, schedules, alerts, filter editor, device coverage matrix | Anything on the child's device |
| **NextDNS profiles** (cloud) | nextdns.io | The filter: categories, apps/services, SafeSearch, YouTube restricted, denylist/allowlist (parent-entered domains, copied in Couvre-feu's database per decision D8), per profile | Time windows (kept off); knowing which child is which (only profiles) |
| **NextDNS CLI** (`nextdns`) | Router | Local resolver that forwards to NextDNS over DoH and picks the profile per client MAC (first match wins, bare profile = default) | Enforcing that devices use it (that is the router core's redirect/reject job) |
| **dnsmasq / GL AdGuard Home** | Router (vendor) | Today's DHCP and DNS path. One of them hands kids' queries to the CLI, or the CLI takes port 53 | Must stay untouched for adults, DHCP and WAN; the exact change is what E1 scopes |
| **Family Link** (Android/ChromeOS) and **Screen Time** (iOS/macOS) | Child devices | The off-network layer: app-install approval, app/time limits, locked settings; Chrome filtering (Family Link) | Network-level anything; alerting Couvre-feu |
| **Tailscale / adult NextDNS** | Adult devices | Household adults' own DNS and VPN. Out of scope; listed so no one points a child device at it | — |

Data flow (delivery mechanism unresolved, §2.3): child device → port 53 → (router resolver or core redirect) → NextDNS CLI → profile by MAC → NextDNS cloud. Service → NextDNS API for profile *configuration*. Service → router RPC for *counts*. From NextDNS the service reads analytics counts only (D5), never log entries.

## 2. Configuration

### 2.1 NextDNS account and profiles

1. Create one profile per child plus one **strict default** profile (decision D1). Name them by role, not by the child's real name, since profile names appear in NextDNS UI and in URLs.
2. On every kids profile and the default: Parental Control categories and services per the owner; SafeSearch on; YouTube Restricted Mode on; **Block Bypass Methods on**; **Logs enabled with 1-week retention** (D4, decided 2026-11-08). Block Page off (it needs a CA; out of scope). Status 2026-11-08: the three child profiles exist with SafeSearch, YouTube Restricted Mode and one-week logs applied; categories, Block Bypass Methods and the Security/Privacy toggles are pending the owner's calls.
3. API key: account page → bottom. Store it on the service host as a private file owned by the service uid (`0600`), e.g. `/etc/couvrefeu/private/nextdns.key`; the service must read it, so "root-only" is not possible. Never in the manifest, repo, logs or a policy sent to the router. If the host is compromised the key can edit or disable every profile; rotate it from the NextDNS account page.
4. Record the profile ids in the private manifest (below). Changing categories later is done in the Couvre-feu UI once Phase A ships; until then, in NextDNS directly.

### 2.2 Couvre-feu service (Phase A)

Manifest addition, strict keys, absent = off:

```json
"contentFilter": {
  "mode": "owner",
  "apiKeyFile": "/etc/couvrefeu/private/nextdns.key",
  "defaultProfile": "<strict default id>",
  "profiles": { "<personId>": "<profile id>", "<personId>": "<profile id>" }
}
```

- `mode`: `off` | `owner` | `parents`, same rollout pattern as `timeRequests.mode`. Loosening a filter needs step-up regardless of mode.
- Rebind/restart the service after a manifest change ([how to turn a flag on](service-contract.md#how-to-turn-a-flag-on)).
- Detection flags (Phase C) are separate: `"detection": {"trafficWithoutDns": true, "singleFlow": false, "deviceAbsent": false}`; all default off; thresholds are code constants set from the measurement spike, not manifest knobs.

### 2.3 NextDNS CLI on the router (Phase B; live, approved steps only)

Intended configuration file (the `nextdns config` file, one option per line). Generated by the service from enrolled MACs and shown as an artifact for review; applied only by an approved dispatch:

```
profile aa:bb:cc:dd:ee:01=<child A profile>
profile aa:bb:cc:dd:ee:02=<child A profile>
profile aa:bb:cc:dd:ee:11=<child B profile>
profile <strict default id>
listen <address:port chosen by the spike-006 inspection and recorded in E1>
report-client-info false
cache-size 10MB
log-queries false
```

- `report-client-info false` and `log-queries false`: no device names or queries leave the house or sit in router logs.
- The listen address/port and how dnsmasq or AdGuard Home hands kids' queries to it are **exactly what E1 must scope**. **No shape is chosen.** The existing DNAT only catches kids' queries sent to addresses other than the router's LAN address; queries sent to the router itself land on whatever listens on LAN:53 and never reach a high-port CLI. So a high-port CLI alone serves only kids who hard-code an outside resolver. Serving all kids-path queries needs the CLI on LAN:53 or dnsmasq/AdGuard forwarding to it, or a DHCP DNS change, all forbidden by `AGENTS.md:39` today. Whatever is chosen is not free: it needs the NextDNS package and init service, UCI `setup_router 0`, a `firewall.sh` DNAT port change plus a matching INPUT allowance (today INPUT accepts UDP/53 to the router), a new release id, and recovery-journal coverage for the new files (a gap today). All of that is in E1's scope, and the 2026-10-27 lift covers none of it by itself. The inspection (spike-006) decides; if no shape fits inside E1, Phase B stops.
- Adults and management MACs are never in the profile list: they must keep their current path. If the chosen shape routes *all* port-53 traffic through the CLI, the default profile would also filter adults, which is not acceptable; that shape is rejected.
- Every file touched gets a pre-image saved in the recovery journal, and `uninstall.sh` must restore it byte-exact (gate G4).

### 2.4 Child devices (by hand, recorded in the coverage matrix)

Android (Family Link; every setting below is UNVERIFIED on these devices): supervised account; **app installs require approval**; Chrome managed with SafeSearch; disallow installing other browsers; Private DNS set to **Automatic** (not a custom host, so the router's redirect works at home); MAC randomization **off for the home SSID** (per-network setting), so the device keeps its enrolled MAC; screen-lock PIN the child does not know for settings that Family Link protects. Verify, on a real child device, whether Private DNS and VPN settings are actually locked (UNVERIFIED).

iOS/iPadOS (Screen Time): Content & Privacy Restrictions on with a passcode; Installing Apps off or Ask to Buy; "Private Wi-Fi Address" off for the home SSID; no DNS profile installed; VPN configuration: whether Content & Privacy Restrictions can block it is UNVERIFIED (it is normally an MDM setting).

Consoles, TVs, laptops: per-device parental controls where they exist; otherwise the device is "network-only covered" in the matrix and the owner knows it.

### 2.5 Verification (what a parent can do in two minutes)

From a child device at home: open `https://test.nextdns.io` → it should report the child's profile id. Try a blocked category → fails. Try `https://1.1.1.1` → expected to fail only if `dnsHardening.dohList` is on (UNVERIFIED on this router). From an adult device: `test.nextdns.io` must **not** report a kids profile.

### 2.6 Weekly review (parents, about ten minutes)

1. Open each child's profile in NextDNS → **Logs** → filter to blocked only.
2. Look for patterns, not single hits: repeated bypass-tool or adult-category domains, the same blocked site on several days.
3. Ignore ads, trackers and one-off hits; they come from prefetch and apps.
4. If something stands out, talk to the child first. Adjust a profile only after that.
5. Logs are kept one week, so a missed week is simply gone. Nothing is copied into Couvre-feu.

## 3. Risk register

Each row: what breaks or is bypassed, which component, how a parent would notice, and the mitigation. "Residual" is what remains after mitigation; be honest about it in the UI.

| # | Risk | Component | Noticed by | Mitigation | Residual |
|---|---|---|---|---|---|
| R1 | E1 widens the project's hard DNS constraint; a bad install breaks household DNS | Router (CLI, dnsmasq/AdGuard) | Everyone, immediately | Read-only inspection first; the delivery shape is unresolved (see §2.3), choose the one that touches the least; pre-images + byte-exact uninstall (G4); rehearsal on empty policy; console rollback ready | A vendor firmware upgrade can rewrite DNS config; drift check refuses and alerts |
| R2 | Adults or guests get filtered by the strict default | CLI default profile | Adult hits a block | Adults and protected MACs stay off the CLI path (a shape that sends all port-53 traffic through the CLI is rejected); one-tap "map this device" for new adult devices (roadmap item 3) | Visitors on the kids' SSID are filtered until mapped; state it on the guest page |
| R3 | Child changes Private DNS / DoH to another resolver | Device → router | `dns_bypass_attempts` count (after attribution ships); blocked device "has no internet" | Router rejects listed resolvers; plain 53 redirected; NextDNS kept on the block list so profiles cannot be swapped; Family Link setting lock if verified | Unlisted DoH endpoints (browser defaults) still work → R4 |
| R4 | Browser/app secure DNS to an unlisted endpoint; hard-coded DNS; IP literals | Device | `traffic_without_dns` | Wider DoH list (roadmap item 9); managed Chrome via Family Link; detection with measured thresholds | Cannot be closed by list; detection has benign false positives |
| R5 | VPN or Tor app | Device | `long_lived_single_flow`, `traffic_without_dns` | **App-install approval** (Family Link / Ask to Buy) is the control; decided not to block by provider list | A VPN already approved, or sideloaded on an unmanaged device |
| R6 | MAC randomization or factory reset moves the device off its mapping | Device → router | `new_device`; child's MAC absent | Strict default profile (D1); per-network randomization off; re-enroll flow in the inventory UI | Couvre-feu pause/schedule rules also miss the new MAC until re-enrolled (existing known limit) |
| R7 | Cellular, hotspot, friend's network | Device | Not observable by the router | OS controls are the only layer; coverage matrix shows the gap; `child_device_absent` as a weak hint | Entirely outside network control; say so to parents |
| R8 | Content inside an allowed app (embedded video, chat links, in-game browsers) | NextDNS (domain-level) | Not observable | Block the app/service outright where the owner chooses; app limits in Family Link | DNS filtering cannot see inside HTTPS |
| R9 | Borrowed adult/sibling device, console, TV | Household | Not observable for adult devices | Per-device controls where they exist; household rules; strict default for unmapped kids-path devices | Adult devices are out of scope by design |
| R10 | HTTPS to a blocked domain just fails: child (or parent) thinks "the Wi-Fi is broken" | NextDNS, no block page | Support calls to parents | UI copy and the kids' request page state "blocked by filter, no page shown"; keep Block Page off (needs a CA) | Confusion persists for apps that show generic errors |
| R11 | Service writes a filter NextDNS did not apply (API error, 429, beta API change) | Service ↔ NextDNS API | `filter_drift` / "not confirmed" pill | Write–read-back–diff; never show "applied" without read-back; client behind an interface; snapshot tests for API shapes (hex service ids) | API changes break the client until updated |
| R12 | API key leak or theft from the service host (the key can edit or disable every profile) | Service host | Unexpected profile changes in NextDNS, `filter_drift` | Key file `0600` under the service uid (see §2.1); never in manifest/DB/logs (CI snapshot test on stderr); rotate on any suspicion (NextDNS currently has one key per account; rotation means regenerating) | One key covers the whole account, including adult profiles |
| R13 | NextDNS outage or account lapse | Cloud | Kids' DNS fails (CLI has no fallback by design) | CLI cache; decide in E1 whether a failure falls back to GL's resolver (unfiltered) or fails closed (no internet for kids); recommended **fail closed** for kids, with an alert | Fail closed means homework stops during an outage |
| R14 | Detection false positives erode trust; false negatives give false comfort | Service alerts | Parents ignore alerts, or trust silence | Thresholds from measurement (C2); alerts owner-only for two weeks; every alert lists benign causes; never `critical` for any heuristic; `traffic_without_dns` stays `warning` at most | Heuristics stay heuristics |
| R15 | Privacy regression: a domain, MAC or hostname lands in an alert, digest or log | Service | CI | Privacy gate snapshot tests (G7); Couvre-feu stores no browsing data and no domains except the parent-entered deny/allow lists (D8), which stay out of audit, logs, alerts and errors; NextDNS keeps one week of logs that only parents read; the service reads counts only (D5) | NextDNS cloud still sees the queries; that is the vendor trade-off the owner accepted |
| R16 | Flow offload makes byte counters undercount, so `traffic_without_dns` is wrong | Router | `offload: on` in activity output | Suppress the signal when offload is on; measure both states in C2 | Offload on means weaker detection |
| R17 | Two truths for time (Couvre-feu schedules vs NextDNS Recreation Time) | Design | "Why is this blocked?" has two answers | Recreation Time stays off; filter editor hides time features | A parent enabling it in NextDNS directly causes confusion; drift check reports it |
| R18 | Parent-side mistakes: accidental loosening, wrong child | Service/UI | Audit log | Step-up on loosening; audit rows; owner-only rollout first | — |
| R19 | Log review turns into surveillance or unfair accusation (prefetch, ads and accidental clicks create blocked lookups) | Parents | Child conflict, hiding behaviour | Weekly blocked-only review at most, never live; a hit starts a conversation, not a punishment; tell the children what is logged; alert on repeated reason-class counts, not single hits | Trust still depends on how it is used |
| R20 | Parent-entered deny/allow domains sit in the service database and its backups (D8) | Service database | A domain in a log, audit row, alert, push, digest or error (CI snapshot tests, G7) | Read only by the filter routes and reconciler; never copied elsewhere; 500-entry cap; loosening needs step-up; back up the database like any private data | Anyone with the database or a backup can read the lists; treat them as private |

## 4. What to tell parents (limits, plainly)

The router filters and pauses only traffic that crosses it, from devices it knows. It cannot see inside apps, cannot stop cellular data or a friend's hotspot, and cannot stop a VPN that was allowed onto the device. Family Link and Screen Time are the controls for those. Blocked sites fail without an explanation page. Alerts about bypass are hints with ordinary explanations, not proof. See also [Limits to state to users](ROADMAP.md#limits-to-state-to-users).
