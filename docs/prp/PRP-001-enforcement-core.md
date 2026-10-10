# PRP-001 — Couvre-feu enforcement core

> Working name: **Couvre-feu** (Grepon Labs / Ventouxlabs, AGPL-3.0). Drop into `docs/prp/`.
> Scope: router-side enforcement + the policy service that drives it. The Bryn-facing PWA is PRP-002.

## 1. Problem

JD and Bryn need to turn the teenagers' internet off and on (now, until a time, and on a schedule) from their phones. Enforcement must live on the router so it holds when the policy service, Atlas, or the app is down. The control surface must be simple enough for a non-technical user; that is PRP-002, but this PRP must give it an API that only reports success after the router confirms.

## 2. Target platform (verified 2026-10-09)

| Item | Value |
|---|---|
| Router | GL.iNet GL-XE3000 (Puli AX), firmware 4.8.3, OpenWrt 21.02-SNAPSHOT, kernel 5.4.211 |
| RAM / storage | 512 MB (≈230 MB available), 6.8 GB free on `/overlay` |
| Firewall | **fw3 + iptables 1.8.7**. `nft` not present. `ipset`, `conntrack` present |
| DHCP / DNS | dnsmasq on 192.168.1.1:53 (LAN 192.168.1.0/24); 24 leases → Deco is already in **AP mode** |
| Timezone | `America/New York` set in `system` |
| Ports | 1× 2.5GbE WAN, 1× GbE LAN (Deco mesh hangs off the single LAN port; homelab rides through Deco) |
| Existing rules | GL.iNet DNS-leak rules present (`wan_drop_leaked_dns`, `guest_drop_leaked_dns`, AdGuard variants) |

Still to confirm in the spike (§9): `xt_time` and `xt_mac` modules, LAN IPv6 status, whether dnsmasq's WAN-address listener is reachable from the internet, AdGuard Home enabled state.

## 3. Goals

1. **Pause / resume** a person (all their devices) immediately, optionally until a time. Existing connections drop within 5 s.
2. **Schedules** (e.g., school nights 22:00–06:30) enforced by the router with no dependency on the service.
3. **Bypass resistance** for kids' devices: forced DNS to the router, DoT/DoQ blocked, known DoH endpoints blocked.
4. **Confirmed state**: every write returns the router's actual post-apply state, not an optimistic ack.
5. **Survives** firewall reload, router reboot, and GL.iNet firmware upgrade.
6. **Least privilege**: the service's SSH key can run only the Couvre-feu control command.

## 4. Non-goals (this PRP)

Content/category filtering (stays with NextDNS or AdGuard Home), screen-time minute accounting, block page/CA, VPN, VLANs, the PWA, native apps.

## 5. Architecture

```
Bryn / JD phones ──(Tailscale)──> policy service (Atlas, podman)
                                     │  SSH, key restricted to `cfctl`
                                     ▼
                         GL-XE3000: /usr/sbin/cfctl (ash)
                           ├─ ipsets: cf_kids, cf_paused (hash:mac)
                           ├─ chain cf_fwd (jumped from forwarding_rule)
                           ├─ uci rules: schedules (src_mac + time match)
                           ├─ /etc/couvrefeu/state  (pauses + expiries)
                           └─ cron: cfctl expire (every minute)
```

### 5.1 Router side (`cfctl`, POSIX ash, no daemon)

- **Pause**: `ipset add cf_paused <mac>`; record `mac expiry_epoch` in `/etc/couvrefeu/state`; flush conntrack for the device's current IPv4/IPv6 addresses (`conntrack -D -s <ip>` and `-d <ip>`).
- **Resume**: remove from set and state file.
- **Expiry without the service**: cron runs `cfctl expire` every minute, so "pause for 1 hour" ends even if Atlas is down.
- **Firewall integration**: `uci firewall include` of type `script` with `reload=1` pointing at `cfctl apply-fw`, which (re)creates the ipsets from the state file and inserts `-j cf_fwd` at the top of `forwarding_rule`. Rules must be idempotent.
- **Schedules**: written as native fw3 `rule` sections (`src_mac`, `start_time`, `stop_time`, `weekdays`, `target REJECT`, `dest wan`), one per device per window, named `cf_sched_<person>_<n>`. Persisted by uci, enforced by the kernel, no dependency on `cfctl`.
- **Bypass rules (kids only, matched via `cf_kids`)**:
  - DNAT tcp/udp 53 from kids not destined to 192.168.1.1 → 192.168.1.1.
  - REJECT tcp/udp 853 (DoT/DoQ) and udp 784/8853 from kids.
  - REJECT to ipset `cf_doh` (known DoH resolver IPs; list pushed by the service, refreshed daily).
  - Same rules in ip6tables, or IPv6 disabled on LAN (decide in spike).
- **Persistence**: add `/etc/couvrefeu/`, `/usr/sbin/cfctl`, and the include to `/etc/sysupgrade.conf`.
- **Control surface**: `cfctl status --json`, `pause <person> [--until <epoch>]`, `resume <person>`, `sync` (reads desired-state JSON on stdin: people → MACs, schedules, DoH list; converges and prints resulting state JSON).

### 5.2 Policy service (Atlas)

- TypeScript monorepo (`service/`, `web/`, `shared/`), SQLite, runs in podman, exposed only via `tailscale serve`.
- **Data model**: person, device (MAC, label, owner), schedule, override (pause/bonus with expiry), audit_log (who, what, when, router result).
- **Reconcile loop** every 60 s and on every write: build desired state → `ssh router cfctl sync` → store returned state → diff → alert on drift or failure.
- **Source of truth** is the service; changes made in GL.iNet UI to `cf_*` objects are overwritten and logged.
- **Alerts** to JD via ntfy: router unreachable >3 min, sync failure, new unassigned MAC seen in leases.
- **API (consumed by PRP-002)**: `GET /people` (status per person), `POST /people/:id/pause {until?}`, `POST /people/:id/resume`, `POST /people/:id/bonus {minutes}`, admin endpoints for devices/schedules. Writes return 200 only with router-confirmed state.
- **Auth**: passkeys (WebAuthn); two users, admin (JD) and parent (Bryn).

### 5.3 SSH hardening

Dedicated key in `/etc/dropbear/authorized_keys` with `command="/usr/sbin/cfctl-ssh",no-port-forwarding,no-agent-forwarding,no-pty`. `cfctl-ssh` parses `$SSH_ORIGINAL_COMMAND` against an allowlist of subcommands.

## 6. Failure behavior (deliberate)

| Failure | Behavior |
|---|---|
| Policy service down | Schedules and active pauses keep enforcing; pause expiries still fire via router cron. App shows "Can't reach home network." |
| `cfctl` broken / include fails | Schedules still enforce (native uci rules). Pauses fail open; service alerts JD. |
| Router reboot | Include recreates sets from state file; schedules are native. |
| Firmware upgrade | Files preserved via `sysupgrade.conf`; post-upgrade `cfctl status` check in acceptance. |
| DNS | Never touched beyond DNAT for kids; household DNS fails open. |

## 7. Device identity

Leases show locally administered (private) MACs on most phones. Policy: every kid device uses the per-network private address in **Fixed** (iOS) / per-network randomized (Android) mode, never rotating, locked via Screen Time / Family Link. Unknown MACs are listed as "unassigned" for JD in admin; they are not shown to Bryn. Quarantine (default-deny for unknown MACs) is out of scope here; revisit after a month of lease data.

## 8. Acceptance tests

1. Pause a person while a video streams on their device → playback stops within 5 s; JD's devices unaffected.
2. Pause with `--until now+2m`, stop the service container → access returns within ~1 min of expiry.
3. Schedule window active with service stopped → device blocked.
4. `/etc/init.d/firewall reload` and full reboot → pauses and schedules still enforced; `cfctl status` matches service.
5. Kid device with manual DNS 8.8.8.8 → queries answered by the router (visible in dnsmasq log).
6. Firefox DoH on a kid device → falls back to system DNS or fails; no successful DoH resolution.
7. IPv6: kid device with a global v6 address cannot reach the internet while paused (or LAN v6 disabled).
8. SSH key cannot run anything but `cfctl` subcommands.
9. GL.iNet firmware upgrade on the same version line → state and rules survive.

## 9. Spike checklist (before implementation)

```sh
lsmod | grep -E 'xt_time|xt_mac|ip_set'
ip -6 addr show br-lan; uci show dhcp.lan | grep -E 'ra|dhcpv6'
uci show firewall | grep -E "zone|input" | head -20   # confirm WAN input REJECT
/etc/init.d/adguardhome enabled && echo AGH-on || echo AGH-off
```
From cellular (not home Wi-Fi): `dig @<WAN IP> example.com` must time out.

## 10. Devil's advocate

- **Kids bypass via cellular, hotspots, or VPN apps.** Out of network scope; pair with Screen Time / Family Link. Document for Bryn.
- **fw3/iptables is end-of-line.** GL.iNet will move to fw4/nftables. Keep `cfctl` backend functions isolated so an nft implementation is a swap, not a rewrite.
- **GL.iNet UI could clobber uci rules.** Mitigated by `cf_` naming plus reconcile; verify the UI's parental-control page isn't also in use.
- **Two control planes** (Couvre-feu and GL.iNet's own parental controls) → disable GL.iNet's.
- **Fengard** (Apache-2.0) solves a superset. Use as reference design only; attribute in NOTICE any code lifted.
