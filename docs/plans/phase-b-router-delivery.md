# Phase B plan: getting each child's DNS to their NextDNS profile (PRP-006 item 12)

Status: **plan only.** I ran nothing on the router, changed nothing in the repo, pushed nothing and opened no PR.
Everything router-side below is UNVERIFIED until a separately approved live step records it.
Written 2026-11-13 from: `AGENTS.md`, `docs/prp/PRP-006-content-filtering.md`, `docs/content-filtering-stack.md`,
`docs/dns-hardening.md`, `docs/enforcement-contract.md`, `docs/router-transition-design.md`, `docs/spike-001.md`,
`docs/spike-005.md`, `docs/runbooks/router-admission-facts.md` (grep), `docs/runbooks/live-first-rehearsal.md` (head),
`docs/ROADMAP.md`, `router/lib/firewall.sh`, `router/install.sh`, `router/lib/json.awk`, `service/src/content-filter-config.ts`.
No spike-006 document exists yet; PRP-006 §7 B2 and content-filtering-stack §2.3 only name it.

---

## 0. The short version

1. **Recommended shape (O1):** keep dnsmasq, AdGuard Home, DHCP and WAN exactly as they are. Run the NextDNS CLI as a
   Couvre-feu-owned procd service listening **only** on `<LAN IP>:<high port>`. Widen the existing kids-only IPv4 DNAT in
   `cf_dns` (`router/lib/firewall.sh:72`) so it catches *all* kids' TCP/UDP port-53 traffic, including queries sent to the
   router itself. Today `! -d <LAN IP>` excludes those. Send it to that port, and add a matching kids-only INPUT accept.
   Only `cf_kids` MACs are meant to reach the CLI; this is UNVERIFIED until Q8 and the lab show that other LAN hosts cannot reach the listener (a listener on `<LAN IP>:<P>` is reachable by any LAN host if `zone_lan_input` accepts it, so B3 adds a REJECT for non-kids on `<P>` in `cf_input`, and E1 item 3 must cover it). Adults and protected MACs keep their current path byte-for-byte, because no rule
   matches them. The CLI keeps the child's source IP, because DNAT does not rewrite it, so it can find the MAC from the
   router's neighbour table and pick the per-child profile.
2. This shape **does not change dnsmasq configuration or the WAN zone**, so it fits inside the letter of `AGENTS.md:39`.
   PRP-006 still assigns the package/init/config/DNAT-port change to exception E1, so E1 is still needed. It can be much
   narrower than PRP-006 §6 feared (wording in §3).
3. Failure is **fail-closed for kids** by construction: if the CLI is down, kids' DNS goes to a closed port. That needs an
   owner decision (D9) and an alert. A local "delivery off" switch restores kids' plain DNS (note: `cfctl dns-filter off` itself needs SSH and per-invocation approval, so it is not a no-SSH path)
   to edit files.
4. Nothing live can start before Phase 0 (the first live rehearsal) passes, because the DNAT this relies on is part of
   the Couvre-feu router core, and that core is not installed live yet (ROADMAP "Phase 0 is not done").
5. Seven offline PRs (§4) can merge behind an absent-means-off policy field. They need no live router. They can be
   checked with the existing fixture harness, plus an optional network-namespace lab with the real CLI binary.

---

## 1. Open questions that need read-only router inspection

Rules for this section:
- Each command is **one approval**. The owner runs it themselves, or approves exactly this string for one run. Nothing is
  batched, retried or "fixed up" without fresh approval.
- Every command is read-only, BusyBox-ash compatible, and avoids `stat`/`od` (missing per spike-005).
- Output is filtered to drop the WAN address, neighbour MACs, lease names and secrets where possible. Raw output stays
  private (the owner's machine, mode 0600, not tmpfs, not the repo). The public spike-006 doc records only conclusions.
- In the tables, `\|` is the Markdown escape for a literal `|`. Before approval, B0 copies each command into its own
  fenced block in spike-006, so the approved string is exact and unescaped.
- Prefix for each command: send EVERY Q in the heredoc form `ssh <router-admin-alias> sh -s <<'EOF'` … `EOF`, one
  invocation per Q. The table's regex alternations contain `|` and several contain single quotes, so the wrapped form
  `ssh <alias> '<COMMAND>'` would be split by the operator's shell and the router would receive a different command than
  the one approved. In spike-006, put each Q in its own fenced block exactly as it will be run, and approve that block.
  Use the operator's existing admin path from
  `docs/runbooks/operator-ssh-agent.md`, **not** the `cfctl-ssh` forced-command key, which refuses these.

**Q0 (no router, ask first).** Does the owner still hold the private spike-001 capture (912 lines, 2026-10-10)? It
already contains full `iptables-save` for filter/nat/mangle/raw. If yes, Q6–Q9 can be answered from it for the
2026-10-10 state. Then re-run only Q6 to check for drift. That saves four approvals.

### Must-have (Phase B cannot be designed without them)

| # | Question | Proposed command (exact) | Why it is needed |
|---|---|---|---|
| Q1 | Exact firmware and OpenWrt base | `cat /etc/glversion; grep -E '^DISTRIB_(RELEASE\|REVISION\|ARCH)=' /etc/openwrt_release` | spike-001 did not confirm GL 4.8.3. CLI binary arch (aarch64 expected) and the vendor-profile pin depend on it. |
| Q2 | What listens on 53, 3053, 5353 and the candidate CLI ports, and on which address class | `netstat -lnup 2>&1 \| awk -v lan="$(uci -q get network.lan.ipaddr)" 'NR>2{n=split($4,a,":");p=a[n];ad=substr($4,1,length($4)-length(p)-1);c=(ad==lan)?"lan":(ad~/^127\./)?"lo4":(ad=="0.0.0.0")?"any4":(ad=="::"\|\|ad==":::")?"any6":(ad=="::1")?"lo6":"other";if(p~/^(53\|853\|3053\|5353\|5342\|5343\|5354\|8053)$/)print $1,p,c,$NF}'` then the same with `-lntp` | Picks a free high port. Shows whether dnsmasq or AdGuard Home owns LAN:53, and whether anything binds `any4` (a CLI on `any4` would collide). spike-001 saw 53 listeners but no process attribution. If BusyBox `netstat` lacks `-p`, the last column is blank, which is still useful. |
| Q3 | Which DNS daemons are running and with what command lines | `ps w \| grep -E '[d]nsmasq\|[A]dGuardHome\|[n]extdns\|[s]tubby\|[h]ttps-dns'` | Confirms AdGuard Home is actually running ("AGH-on" was only the init-enabled check). Rules out an existing nextdns/stubby that would conflict. |
| Q4 | dnsmasq's port and upstreams (read, not change) | `uci -q show dhcp \| grep -E '^dhcp\.@dnsmasq\[0\]\.(port\|server\|noresolv\|resolvfile\|localuse\|rebind_protection)='` | Confirms the adult path we must not disturb. If dnsmasq forwards to AdGuard Home on 3053, kids on O1 skip both, which is intended and is documented to the owner. |
| Q5 | DHCP DNS handed to LAN clients | `uci -q show dhcp.lan \| grep -E 'dhcp_option\|dns\|ra\|dhcpv6\|ignore'` | If DHCP option 6 hands out an external resolver, O1 still catches it, but the parent copy and test plan change. Also shows whether RA/DHCPv6 could hand out an IPv6 resolver (IPv6 bypass, §2.5). |
| Q6 | nat PREROUTING order: does `prerouting_rule` (our `cf_dns` hook) still come before GL's `dns_dispatcher`? | `iptables -w 5 -t nat -S PREROUTING; iptables -w 5 -t nat -S prerouting_rule` | O1 relies on our DNAT matching first, because a terminating DNAT ends nat-table traversal. spike-001 saw this order on 2026-10-10. GL's `/etc/firewall.dns_order` include exists *to reorder DNS rules* on reload (Q7). |
| Q7 | What GL's DNS-order include does | `cat /etc/firewall.dns_order` | spike-001: enabled with reload support, contents never read. If it moves `dns_dispatcher` to PREROUTING position 1 on every reload, our DNAT may be skipped (silently unfiltered) after a firewall reload. That is the most likely hidden fail-open. |
| Q8 | INPUT path to `<LAN IP>:<port>` from LAN | `iptables -w 5 -S INPUT; iptables -w 5 -S input_rule; iptables -w 5 -S zone_lan_input` | spike-001: GL leak rules DROP UDP/53 and UDP/3053 by mark in `zone_lan_input`. We need to confirm a high port from `br-lan` reaches ACCEPT, and that `cf_input` is still hooked first. |
| Q9 | Marks and conntrack zones on DNS packets | `iptables -w 5 -t mangle -S \| grep -nE 'dport (53\|3053)\|0x8/\|0x8000\|CT\|TPROXY'; iptables -w 5 -t raw -S` | spike-001: "raw/mangle DNS handling and GL routing marks also exist". A mark or CT zone applied before our DNAT could route the packet to a GL path (policy routing, VPN) or match a leak DROP. |
| Q10 | Router-originated HTTPS egress (the CLI's upstream) | `iptables -w 5 -S OUTPUT; iptables -w 5 -S output_rule; ip rule show \| sed -E 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?/<ip>/g'` | The CLI talks DoH from the router (OUTPUT, not FORWARD), so the kids' `cf_fwd` DoH rejects should not hit it. That is G3 part 2. A GL VPN kill-switch or policy routing could still block or reroute it, which means fail-closed for kids. `ip rule` exposes only rule priorities and tables, no addresses beyond what GL configured. |
| Q11 | Flash and RAM headroom | `df -k / /overlay /tmp 2>/dev/null; grep -E '^(MemTotal\|MemAvailable):' /proc/meminfo` | The CLI is a Go static binary (single-digit MB, version-dependent). It must sit on persistent overlay with margin for the recovery journal. |
| Q12 | Is the neighbour table readable the way the CLI reads it? | `head -1 /proc/net/arp; wc -l < /proc/net/arp; ip -6 neigh show dev br-lan \| wc -l` | MAC-conditional profiles need IP→MAC lookup on the router (expected via the ARP/NDP table, UNVERIFIED until the source review in PR B0). This prints only the header and counts, no MACs. |
| Q13 | Current IPv6 exposure on the LAN | `ip -6 addr show dev br-lan \| grep -c 'inet6 '; uci -q get network.lan.ip6assign; uci -q get dhcp.lan.ra; uci -q get dhcp.lan.dhcpv6` | spike-001: no LAN IPv6 *then*. If the router gains a LAN IPv6 address, kids' UDP/53 to it is accepted by `firewall.sh:67` and goes to dnsmasq unfiltered. Decides whether the v6 reject in §2.5 is urgent or preventive. |

### Nice-to-have (narrow residual unknowns; skip if the owner wants fewer approvals)

| # | Question | Proposed command (exact) | Why |
|---|---|---|---|
| Q14 | Package state, to rule out the opkg route or a conflicting install | `opkg list-installed \| grep -iE '^(nextdns\|adguardhome\|dnsmasq\|https-dns-proxy\|stubby) '` | Read-only (local status DB). **Do not run `opkg update`**: it writes and fetches. |
| Q15 | Feed URLs, to check offline whether GL's feed carries `nextdns` | `cat /etc/opkg/distfeeds.conf; cat /etc/opkg/customfeeds.conf 2>/dev/null` | Lets me fetch the feed index from my side with no router involvement. Only matters if the owner prefers opkg over a pinned binary (§2.2). |
| Q16 | Does sysupgrade keep `/etc/init.d` additions? | `grep -vE '^\s*(#\|$)' /etc/sysupgrade.conf` | `install.sh:310` appends Couvre-feu paths. A new init script and `rc.d` link must be preserved too, or a firmware upgrade leaves the DNAT in place with no CLI (fail-closed after upgrade). |
| Q17 | Router clock and NTP source (TLS needs a sane clock) | `date -u; uci -q get system.ntp.enabled; uci -q show system.ntp \| grep -c server` | The CLI's DoH fails on a bad clock, which means fail-closed for kids at boot. NTP resolves through dnsmasq, which O1 never touches, so this is a check, not a change. |

Also needed, owner reading the GL admin UI with no command: **Network → DNS** (mode, "Override DNS settings of all
clients", encrypted DNS, rebinding) and **Applications → AdGuard Home** (on/off, "handle client requests"). These GL
toggles install or remove `dns_redirect`/`adg_redirect` rules (empty on 2026-10-10). A later toggle by a parent could
change the PREROUTING picture.

**Stop conditions after inspection:** stop and re-plan, without installing anything, if any of these hold:
- Q6/Q7 show GL forces its DNS dispatcher ahead of `prerouting_rule` on reload.
- Q8/Q9 show a mark-based DROP we cannot precede from `cf_input`.
- Q2 shows no free port bindable on the LAN address only.
- Q10 shows router egress is forced through a path we cannot predict.

The fallback is "Phase A stands alone" (PRP-006 §9).

---

## 2. Design options for per-child delivery

### 2.1 What the router does today (offline-tested, unverified live)

From `router/lib/firewall.sh:53-72`, kids (`cf_kids` MACs) only:
- IPv4 TCP/UDP port 53 to **any other address** is DNATed to `<LAN IP>:53`, so it lands on dnsmasq (or AdGuard Home).
- IPv4 UDP/53 to the router is accepted in `cf_input` ahead of GL's leak DROP.
- IPv4 TCP/53 to the router is **not** DNATed and **not** in `cf_input`. It falls to GL rules, probably dnsmasq.
- IPv6 forwarded 53 is rejected. UDP/53 to the router's IPv6 addresses is accepted (dnsmasq, unfiltered).
- DoT/DoQ ports are rejected. DoH is rejected only for listed IPs, and only with `dnsHardening.dohList` on (off by default).

There is no nftables here. OpenWrt 21.02 on this router is fw3 plus iptables 1.8.7 **legacy** (spike-001), so an
"nftables redirect" means this iptables DNAT. Couvre-feu already owns the right chain (`cf_dns` → slot `cf2_<a|b>_d`).

### 2.2 Options

| | Shape | Touches | Per-child MAC visible to CLI? | Adults affected? | Verdict |
|---|---|---|---|---|---|
| **O1** | CLI on `<LAN IP>:<P>` (P high, from Q2). Kids-only DNAT of **all** TCP/UDP 53 (drop the `! -d LAN` exclusion) to `<LAN IP>:<P>`, plus kids-only `cf_input` ACCEPT tcp/udp `<P>` | Couvre-feu's own firewall rules; new owned files (binary, init, config) | Yes: DNAT keeps the source IP, and the CLI resolves IP→MAC from the neighbour table (UNVERIFIED, B0/G2) | No: no rule matches non-kid MACs | **Recommended** |
| O2 | CLI takes LAN:53 (`setup-router true`); dnsmasq moves or is disabled | dnsmasq config and process | Yes | **Yes**: every adult gets the strict default profile, and a CLI crash takes down household DNS | Rejected (PRP-006 §4.2, R2) |
| O3 | dnsmasq forwards to CLI on localhost with `add-mac` EDNS | dnsmasq config (forbidden), all household queries | Only via EDNS `add-mac` | Yes unless the CLI forwards adults elsewhere; one path for all | Rejected: needs E1 on dnsmasq, larger blast radius |
| O4 | Second LAN IP alias with CLI on alias:53; DHCP tag hands kids that DNS | network + DHCP config | Yes | Indirectly (DHCP) | Rejected: DHCP and network change, no gain over O1 |
| O5 | Per-device DoH/DoT to `<profile>.dns.nextdns.io` (Android Private DNS, iOS profile) | No router change | n/a (profile in hostname) | No | Rejected as the primary layer: collides with the kids' 853 reject and the NextDNS DoH block, child-changeable, PRP-006 §3 last bullet. Keep only as an off-network idea under D7 |
| O6 | CLI on the house service host; router DNATs kids to it | Firewall only | **No**: hairpin DNAT to a LAN host needs SNAT or replies go asymmetric, and SNAT hides the child | No | Rejected (loses per-child identity) |
| O7 | CLI with opkg package `nextdns` instead of pinned binary | opkg state (not journaled, spike-005), package postinst/init | Same as O1 | Risk: the package init may run `setup-router`/modify dnsmasq (UNVERIFIED) | Not preferred. Follow the pinned-helper precedent (live-first-rehearsal: "hash-pinned static helper ships inside the reviewed release payload; not a package-manager install") |

### 2.3 O1 in detail

**Owned files (all new, all journaled, all removed byte-exact by `uninstall.sh`):**
- `/usr/lib/couvrefeu/nextdns`: pinned upstream `linux_arm64` release binary. The SHA-256 is compiled into the release
  pin like `busybox-static`. `/usr/lib/couvrefeu` is already in the sysupgrade list (`install.sh:310`).
- `/etc/init.d/couvrefeu-nextdns`: procd script with `USE_PROCD=1`, respawn, `env -i` PATH like the cron handling.
  It runs `nextdns run -config-file /etc/couvrefeu/nextdns.conf`. It never calls `nextdns install`/`activate`.
- `/etc/rc.d/S??couvrefeu-nextdns`: enable link. It must start **before** the firewall include applies the DNAT, or
  the gap is fail-closed at boot (acceptable but noisy).
- `/etc/couvrefeu/nextdns.conf`: generated by `cfctl` from router state. Mode 0600 root. It contains MACs and profile
  ids, so it never goes in logs or RPC output.

**Rendered config (allowlisted keys only; the renderer refuses anything else):**
```
listen <LAN IP>:<P>
setup-router false
auto-activate false
detect-captive-portals false
report-client-info false
log-queries false
mdns disabled
discovery-dns
cache-size 10MB
max-ttl 5m
profile <kid MAC 1>=<child A profile>
profile <kid MAC 2>=<child A profile>
profile <kid MAC 3>=<child B profile>
profile <strict default profile>
```
Why each pinned setting matters. The exact option names and semantics are verified in the B0 source review at a pinned
tag, not assumed:
- `setup-router false`: the CLI must not touch dnsmasq. A NextDNS forum thread reports that enabling the CLI cache
  "disables dnsmasq automatically" in router mode. This is a lockout risk for the whole house if wrong.
- `auto-activate false`: the CLI must not rewrite the router's `/etc/resolv.conf`. Otherwise the router's own lookups
  (NTP, GL cloud) would go through a kids profile.
- `detect-captive-portals false`: otherwise the CLI may fall back to the system resolver, a silent fail-open.
- `mdns disabled`: do not bind 5353 next to umdns.
- `discovery-dns` empty: no PTR lookups.
- `max-ttl`: bounds how stale a cached answer can be after a profile change (G1 timing).
- `listen <LAN IP>:<P>` only: never `any4`. WAN input is DROP (spike-001), but do not rely on it.

**Where the mapping comes from.** Router state already holds person→MACs (`P` records). Add one optional policy field
so the router renders the file itself from one truth. The service never pushes files, and `cfctl-ssh` grammar stays
unchanged:
```json
"dnsFilter": {"port": 5342, "default": "<profile id>", "profiles": [{"person": "<id>", "profile": "<profile id>"}]}
```
Absent means byte-identical state, digests and rules to today, using the same pattern as `allowances`
(`router/lib/json.awk:105,119`). The service fills it from the existing `contentFilter` manifest (`profiles`,
`defaultProfile`, already validated by `PROFILE_ID_PATTERN`) only when a new manifest key
`contentFilter.delivery: true` is present. Strict keys apply: absent is off.

**Firewall change inside the slot generation (`cf_policy_plan`):**
- With `dnsFilter` present, IPv4 `cf_dns`: `-i br-lan -m set --match-set cf_kids src -p {tcp,udp} --dport 53 -j DNAT --to-destination <LAN IP>:<P>`
  (no `! -d`).
- `cf_input`: kids-only ACCEPT `-p {tcp,udp} -d <LAN IP> --dport <P>`. The old UDP/53 accept stays harmlessly, or is
  dropped (decide in B2).
- IPv6: replace the kids' UDP/53 ACCEPT to router IPv6 (`firewall.sh:67`) with REJECT tcp/udp 53 to the router, so kids
  fall back to IPv4 DNS (§2.5).
- With `dnsFilter` absent, the rules are exactly today's.

These ride the existing two-slot immutable generation switch (enforcement contract): the DNAT target changes with one
fixed-position `-R` per table, so there is no flush window.

**Ordering, so a transition never strands kids:**
- Enable: write the config, start or restart the CLI, and prove the listener is up from `/proc/net/udp` and `/proc/net/tcp`
  (port in hex, awk only, no `netstat` dependency). Only then expose the generation with the new DNAT. If the listener is
  not up, refuse with `dns_filter_listener_down`; the old generation stays dispatched.
- Mapping change (enroll, unenroll, move, profile edit): write the new config atomically, then restart the CLI. Expect a
  ~1-2 s window of kids' DNS failures (UNVERIFIED; measure). Reload semantics (SIGHUP?) come from the B0 source review.
- Disable: switch the generation back to the `:53` DNAT first, then stop the CLI.

**Status (read-only, `rpc-status`):** add `dnsFilter: {"enabled": bool, "listener": "up|down|unknown", "configDigest": "<sha256>"}`
with no MACs and no profile ids. The service raises `filter_delivery_down` (warning) and shows "delivery: not confirmed"
on the filter card.

### 2.4 Failure modes: fail-open vs fail-closed (O1)

| Failure | What kids get | What adults get | Detected by | Notes |
|---|---|---|---|---|
| CLI crashed, not respawned | **No DNS** (ICMP port-unreachable, fast fail) | Unchanged | `listener: down`, alert | procd respawn first. Parent can turn delivery off (§5 kill switch) |
| NextDNS cloud or account outage, router WAN down | No DNS (CLI SERVFAIL/timeout, UNVERIFIED which) | Unchanged | Hard; maybe a CLI health probe later | R13. Owner decision D9 |
| Bad router clock at boot (TLS fails) | No DNS until NTP syncs | Unchanged (NTP via dnsmasq) | Q17 / boot test | Self-heals |
| Firewall reload without the Couvre-feu include | **Unfiltered**: kids reach dnsmasq/AGH directly (no DNAT) | Unchanged | Existing drift check | Same residual as all Couvre-feu rules (enforcement contract) |
| GL `dns_order` puts `dns_dispatcher` ahead of `cf_dns` | **Unfiltered**, silently | Unchanged | Only if `cfctl` verifies PREROUTING order (it already calls `cf_parent_order 4 nat PREROUTING prerouting_rule`; B2 extends it to assert position vs GL dispatcher) | Q6/Q7 decide whether this is real |
| Firmware upgrade drops the init script but keeps `/etc/couvrefeu` | No DNS for kids (DNAT survives, CLI gone) | Unchanged | `listener: down` | Q16. Add the init path to sysupgrade, or have the include refuse DNAT when the binary is absent |
| Couvre-feu uninstalled | Unfiltered (back to today's path) | Unchanged | Expected | |
| Kid device not in `cf_kids` (rotated MAC, new device, guest) | Unfiltered (never redirected) | n/a | `new_device` | PRP-006 row 7; closed only by roadmap item 3 |
| `setup-router`/`auto-activate` accidentally true | Possibly household-wide DNS change | **Affected** | Renderer refuses; fixture test; G4 byte-compare | The main parent-lockout risk; §5 |

**Recommendation (D9): fail closed for kids, with alert and a one-step local off switch.** Fail-open (automatically
reverting the DNAT when the listener is down) would let a crash or OOM silently unfilter. It would also add a second
router-side state machine. If the owner chooses fail-open anyway, implement it as a minute-cron check that issues
an ordinary policy transition to "delivery off" and records it, never as a rule edit outside the slot path.

### 2.5 Bypass handling (what O1 does and does not stop)

| Bypass | O1 effect | Other layer |
|---|---|---|
| Plain DNS to any IPv4 address, including the router | Redirected to CLI, filtered | — |
| TCP DNS | Now redirected too (today TCP to the router escapes to dnsmasq) | — |
| IPv6 DNS to the router (if LAN IPv6 appears) | Rejected, so the device falls back to IPv4 | Q13 |
| IPv6 DNS forwarded out | Already rejected | — |
| DoT / DoQ | Already rejected by port | — |
| DoH to listed resolvers, **including NextDNS anycast (so a kid cannot pick another profile)** | Rejected **only if `dnsHardening.dohList` is on**. **Make the dohList enable gate a Phase B entry condition**, or a child can type `https://dns.nextdns.io/<any profile>` | NextDNS "Block Bypass Methods" on every kid profile |
| DoH to unlisted endpoints (browser defaults, CDN-hosted) | Not stopped | Managed Chrome via Family Link; Phase C `traffic_without_dns` |
| VPN / Tor | Not stopped (owner decision: no lists) | App-install approval; Block Bypass Methods; Phase C single-flow hint |
| MAC randomization / reset | Escapes DNAT entirely | Per-SSID randomization off; `new_device`; item 3 |
| Cellular / hotspot | Out of reach | Family Link / Screen Time only |

---

## 3. What E1 must cover (wording for the owner to approve or reject)

O1 changes **no** dnsmasq configuration and **no** WAN zone, so `AGENTS.md:39` is not breached as written. PRP-006 §6
and content-filtering-stack §2.3 nonetheless reserve the CLI install, its config and the DNAT port change for E1, and
the 2026-10-27 lift covered only the kids' firewall DNS rules for item 9. So the owner records E1, scoped as below.
It must be recorded *after* the Q-inspection, because it names the port and address.

> **Exception E1 (kids' DNS delivery to NextDNS), recorded by the owner on <date>.**
> For devices whose MAC is in Couvre-feu's kids set only, the owner permits:
> 1. A Couvre-feu router release that adds, as owned, journaled files removed byte-exact by `uninstall.sh`: the NextDNS
>    CLI binary version `<vX.Y.Z>` with SHA-256 `<pin>` at `/usr/lib/couvrefeu/nextdns`; the procd script
>    `/etc/init.d/couvrefeu-nextdns` and its `/etc/rc.d` enable link; the generated config
>    `/etc/couvrefeu/nextdns.conf`; and the matching `/etc/sysupgrade.conf` lines.
> 2. The CLI listening only on `<LAN IP>:<P>` TCP and UDP, with `setup-router false`, `auto-activate false`,
>    `detect-captive-portals false`, `report-client-info false`, `log-queries false`, `mdns disabled`. Couvre-feu
>    refuses any other value.
> 3. Changing the kids-only IPv4 DNAT so that kids' TCP/UDP port 53 to *any* destination, including the router, goes
>    to `<LAN IP>:<P>`; a kids-only INPUT accept for `<P>`; and rejecting kids' IPv6 port 53 to the router.
> 4. A new optional policy field `dnsFilter` controlling items 1–3. Absent means today's behaviour exactly.
>
> **Not permitted under E1:** any change to dnsmasq configuration or its process; AdGuard Home; DHCP options;
> `/etc/resolv.conf`; the WAN zone; GL DNS settings; any rule matching adult, guest, management or protected MACs;
> package-manager (`opkg`) installs; running the CLI's `install`/`activate`/`setup-router`. Every live step still needs
> the owner's per-invocation approval.
> **Failure behaviour:** fail closed for kids (D9), with an alert and a local off switch.
> **Revocation:** the owner may revoke E1 at any time. Revocation means a policy without `dnsFilter`, then uninstall.

If inspection shows O1 cannot work (§1 stop conditions), the honest answer is **not** to widen E1 to dnsmasq. Phase B
stops, and filtering stays service-side until the owner reconsiders with fresh evidence.

---

## 4. PR breakdown (all offline; none needs the live router)

Shared rules (ROADMAP): one PR per step, tests first, absent-means-off, "unverified on this router" labels,
exact-commit CI green plus independent adversarial review before merge.

**B0: docs, offline source review (spike-006a) and inspection plan.** No code.
- Pin a NextDNS CLI release. Record the upstream checksum and our own SHA-256 of the `linux_arm64` asset. Check the license
  (upstream is believed MIT; verify) for redistribution in the release payload. Read the source **at that tag** and record
  file:line for each of:
  - the MAC lookup mechanism for `profile <MAC>=` (ARP/NDP? netlink? `/proc/net/arp`?)
  - what `setup-router false`, `auto-activate false` and cache settings do and do not touch
  - `detect-captive-portals` fallback behaviour
  - behaviour when every upstream fails (SERVFAIL vs timeout vs fallback)
  - whether config reload needs a restart
  - whether `listen` binds exactly the given address
  - whether the CLI ever opens 53 or 5353 on its own
- Write `docs/spike-006.md` with §1 of this plan as the approval list (filtered commands, private-output rule).
- Tests: docs only. Rollback: revert.

**B1: policy schema `dnsFilter` (router parser + shared + state).**
- `router/lib/json.awk`: optional `dnsFilter` object, with port 1024–65535 excluding 3053/5353, and default plus profiles
  validated against `^[A-Za-z0-9]{4,32}$`. Each profile references a known person; one entry per person; at most 64.
- `state.awk` gets a new record kind. `shared/src/router-schema.ts` validates the same thing, with a cross-check test
  that the TS and awk patterns match.
- Tests (`tests/test-core.py`, shared tests): accept/reject bounds, unknown keys, duplicate person, undefined person,
  128-char string cap, total size under 65536 with 64 profiles plus 256 MACs. **Absent field gives byte-identical state,
  digest and rules** to the previous release. Same-revision replay is idempotent.
- Rollback: revert. Older router releases do NOT ignore the field: `json.awk` uses a strict key list, so an older release refuses the whole policy and pause/schedule ops would stop applying. The service must send `dnsFilter` only after confirming the router release supports it, and the field is a release-id change.

**B2: firewall rules in the slot generation.**
- `cf_policy_plan` emits the O1 DNAT, `cf_input` and IPv6 reject when the field is present, and today's rules when absent.
- Extend verification to assert `prerouting_rule` precedes any GL DNS dispatcher in nat PREROUTING. If not, report
  drift, not health.
- Tests (fixture harness, `tests/test-transition.py`, `test-core.py`): rule sets for present/absent; exact `-R` switch
  only (no flush); protected MACs never matched; failure injection at each new `iptables` call leaves the old generation
  dispatched; reachability check that no earlier ACCEPT shadows the DNAT; GL dispatcher-first order yields drift.
- Rollback: revert, or a policy without the field.

**B3: config renderer and CLI lifecycle in `cfctl`.**
- Render from state into a private temp file, check it against the allowlist, then rename atomically.
- Start, restart and stop via the init script under `env -i`, plus the listener probe from `/proc/net/{udp,tcp}`.
- Ordering as in §2.3 (enable: listener before DNAT; disable: DNAT before stop).
- New error codes: `dns_filter_listener_down`, `dns_filter_config_rejected`, `dns_filter_binary_missing`.
- Tests: extend `tests/fixtures/backend.py` with a fake `couvrefeu-nextdns` service and fake `/proc/net` files.
  - Renderer golden output; it refuses `setup-router true`, a listen address other than the LAN IP, or any unknown key.
  - Lifecycle orderings; a crash between config write and restart.
  - Listener-down refusal keeps the old generation.
  - The config file never appears in stdout, stderr or RPC output (snapshot test).
- Rollback: revert.

**B4: installer, uninstaller, journal, release id.**
- Add the binary (hash-pinned; the build fetches it via `tools/freeze-router-release.py` or vendors it like
  `busybox-static`), the init script, the `rc.d` link, the config path and sysupgrade lines to the managed inventory.
  Pre-images are recorded, with prior absence noted.
- `uninstall.sh` stops the service before removal.
- Refuse install if `<P>` is already bound (needs a `/proc/net` read in the admission gate) or if `/etc/init.d/couvrefeu-nextdns`
  exists unowned.
- Tests (`test-install.py`, `test-install-recovery*.py`, `test-permanent-install.py`): exact restoration of every new path,
  including prior absence. SIGKILL at each new journal boundary. Foreign file at the init path is refused. Rehearsal
  plan digest changes.
- Rollback: revert. Live rollback is `uninstall.sh` (proven by the rehearsal before any child).

**B5: read-only status, and a local off switch.**
- `rpc-status`/`status --json` gain `dnsFilter` (§2.3; no MAC, no profile id).
- Local-only `cfctl dns-filter off` writes a new revision without the field, like a local `pause`. It is not admitted
  by `cfctl-ssh --rpc-only`.
- Tests: status contract snapshot, `cfctl-ssh` grammar refusal, revision and receipt semantics match local pause.

**B6: service and web.**
- `contentFilter.delivery` (strict boolean, absent = off). Fill `dnsFilter` in `IntegrationPolicy.queue` in the same
  single place the DoH list merges (`service/src/doh-list.ts` pattern).
- `filter_delivery_down` alert, with count-only details.
- Filter card pill: "Delivered by router: confirmed / not confirmed / off".
- Refuse to enable delivery unless `dnsHardening.dohList === true` (§2.5), so delivery and its bypass guard ship together.
- Tests: envelope snapshots with flag on, off and absent (byte-identical when absent); no profile id or MAC in alerts,
  logs or audit (G7); Playwright on the demo router with a fake listener state.

**B7: runbook and lab.**
- Runbook `docs/runbooks/live-dns-delivery.md`: rehearsal steps for PRP-006 B4, G1–G5 checks, kill switch, console
  rollback.
- Optional `tests/lab/` script: Linux network namespaces with iptables-legacy, a "kid" netns, and the **real pinned CLI
  binary** with `log-queries true` in the lab only. It proves DNAT→CLI, MAC-based profile selection and the listener
  probe on a real kernel. It runs only on a dev machine (needs root plus netns plus outbound HTTPS), never in CI by
  default. It is labelled "lab evidence, not router evidence".

**Docs alongside B2–B6:** enforcement contract ("DNS enforcement today" gains the dnsFilter column),
content-filtering-stack §2.3 (shape chosen), PRP-006 §4.2 and §6 (E1 text), ROADMAP item 12 status.

**Live sequence after merge** (each step is a separately approved invocation; matches PRP-006 B3–B5):
Phase 0 passed → Q-inspection → E1 recorded → dohList enable gate passed → rehearsal on empty policy with `dnsFilter`
present and only a test device (G2, G4) → uninstall byte-exact → one authorized child device (G1, G3, G5) →
permanent install only after one clean pass without retry.

---

## 5. Risks, and what could lock kids or parents out

**Parent/household lockout (must never happen; each has a specific guard):**
1. The CLI modifies dnsmasq or rewrites the router resolver (`setup-router`/`auto-activate`/cache side effects).
   Guards: renderer allowlist, B0 source review, never running `nextdns install`, G4 byte-compare of
   `/etc/config/dhcp` and `/etc/resolv.conf` before and after the rehearsal.
2. The CLI binds `any4:53` or a port GL uses. Guards: listen pinned to `<LAN IP>:<P>`, the installer refuses a bound
   port, Q2.
3. A rule accidentally matches adult or management MACs. Guards: every new rule carries `-m set --match-set cf_kids src`;
   protected-MAC overlap is already refused; fixture test.
4. A firewall transition failure during enable. This is the existing two-slot risk; staging failure leaves the old
   generation. Console rollback stays ready, and router-admin password login is never disabled (ROADMAP live rules).
5. The router admin UI stays reachable throughout: O1 only redirects kids' port 53.

**Kids losing internet (expected under fail-closed; must be visible and quickly reversible):**
- CLI crash, OOM, NextDNS outage, bad clock at boot, a firmware upgrade that drops the init script, profile id deleted
  in NextDNS (UNVERIFIED behaviour: probably NXDOMAIN or a refusal for everything).
- Kill-switch limits: the service-side switch is a manifest edit plus rebind, which stops dispatch and resets the router observation (service-contract rebind), so recovery takes minutes, not seconds. A local off revision may be overwritten when the service next sends a policy with `dnsFilter`, so B5 must define an off state that persists against service syncs (a router-local override the service cannot clear, surfaced as an alert). Until that is built, this plan does not claim instant recovery.
- Mitigations: procd respawn; `listener` status plus alert; **kill switch** (service: `contentFilter.delivery` off,
  then the next op removes `dnsFilter`; router-local: `cfctl dns-filter off`; last resort: `uninstall.sh`); copy in
  the parent UI saying "no DNS means delivery down, here is the switch".
- A ~1-2 s DNS blip on every mapping change (restart). Measure in the rehearsal.

**Silent fail-open (the worst kind for this feature):**
- GL's `dns_order` reload reordering PREROUTING (Q7). Guard: B2 order assertion turns it into drift.
- dohList off, so kids use DoH to another NextDNS profile or resolver. Guard: B6 refuses delivery without dohList.
- MAC rotation (out of `cf_kids`): unfixed until roadmap item 3; stated in the coverage matrix.
- IPv6 LAN later enabled. Guard: the v6 reject in B2.

**Other honest unknowns:**
- The MAC lookup mechanism, reload semantics, failure behaviour and exact option names of the CLI. B0 resolves these
  from source; G2 proves them live.
- Whether router-originated DoH escapes the kids' DoH rejects (expected yes: OUTPUT vs FORWARD; G3).
- Cache staleness after a filter edit (`max-ttl`; G1 timing).
- GL AdGuard Home filtering no longer applies to kids on O1. Intended, but tell the owner.
- Binary size and flash wear on overlay (Q11).
- NextDNS profile-count limits (D2), and analytics retention (D5); outside Phase B but unverified.
- Phase 0 itself is not done; nothing in Phase B can go live before it, and it carries its own open gates (clock,
  IPv6, offload, packets).

**Privacy:** the rendered config holds MACs plus profile ids (root 0600, never emitted). Inspection output stays
private. Status and alerts carry counts, states and digests only (G7). `report-client-info false` and
`log-queries false` keep device names and queries out of NextDNS client info and router logs. NextDNS still sees
queries per profile with one-week logs (D4, accepted).
