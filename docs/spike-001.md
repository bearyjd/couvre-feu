# Spike 001 — router enforcement prerequisites

Status: Step 1 inspection report complete; implementation remains blocked on the gaps below. Stop after this report. No further SSH, router changes, or enforcement implementation is authorized by this step.

## Scope and evidence

The PRP source is `/var/home/user/Downloads/PRP-001-enforcement-core.md`, read in full by the orchestrator. This spike covers router enforcement (§5.1, §5.3, §6, §8); the policy service and PWA are deferred.

Findings come from the user's successful local read-only inspection, saved as `/tmp/couvre-feu-spike-output.txt` (912 lines), read in full for this report. The firewall snapshot is dated 2026-10-10 13:31:12 in the router's clock. Raw output stays local: it contains the public WAN address and unrelated neighbor identities. This document retains only the SSH client's safety-relevant mapping.

## Platform and enforcement primitives

- Confirmed GL.iNet GL-XE3000 (`glinet,xe3000-emmc`), ARMv8/aarch64, Linux 5.4.211, OpenWrt 21.02-SNAPSHOT, target `mediatek/mt7981`. GL firmware **4.8.3 was not independently confirmed** by this output.
- `iptables v1.8.7 (legacy)` is present. Loaded modules include `xt_time`, `xt_mac`, `xt_set`, `ip_set`, `ip_set_hash_mac`, and `ip_set_hash_ip`. Time and MAC match help also succeeds, including `--kerneltz` and `--mac-source`.
- These observations support the proposed time/MAC/ipset approach, but no Couvre-feu set, rule, schedule, or packet test was created. Set creation and schedule behavior remain untested; timezone correctness is unverified.
- `command -v ipset conntrack ip6tables` printed only `/usr/sbin/ipset`. This does **not** establish whether the other two executables are absent: the shell's multi-argument behavior may explain it. `ip6tables-save` did successfully produce IPv6 tables. The `conntrack` executable required for session eviction, and the `ip6tables` executable, remain unresolved.

## fw3 chains and ordering

The snapshot confirms fw3-style rules with LAN `br-lan` and WAN `eth0`.

Filter custom chains exist for both IPv4 and IPv6:

- Global: `input_rule`, `forwarding_rule`, `output_rule`.
- Zone-specific: `input_lan_rule`, `input_wan_rule`, `input_guest_rule`; `forwarding_lan_rule`, `forwarding_wan_rule`, `forwarding_guest_rule`; `output_lan_rule`, `output_wan_rule`, `output_guest_rule`.

IPv4 NAT custom chains exist:

- Global: `prerouting_rule`, `postrouting_rule`.
- Zone-specific: `prerouting_lan_rule`, `prerouting_wan_rule`, `prerouting_guest_rule`; `postrouting_lan_rule`, `postrouting_wan_rule`, `postrouting_guest_rule`.

Global NAT `PREROUTING` enters `prerouting_rule` first, then LAN/WAN zone chains; `zone_lan_prerouting` enters `prerouting_lan_rule`. GL DNS dispatcher jumps occur later in global `PREROUTING`. IPv6 NAT has only built-in chains in this snapshot.

IPv4 filter `FORWARD` order is exactly:

1. `--match-set GL_MAC_BLOCK src -j DROP`.
2. Jump to `forwarding_rule`.
3. `RELATED,ESTABLISHED -j ACCEPT`.
4. `-i br-lan -j zone_lan_forward`.
5. `-i eth0 -j zone_wan_forward`.
6. Jump to `reject`.

IPv6 follows steps 2–6, without the GL MAC set rule. In each family, `zone_lan_forward` enters `forwarding_lan_rule` before allowing LAN-to-WAN traffic. Consequently, the global `forwarding_rule` hook is before established-session acceptance; a LAN zone hook alone is too late to stop established traffic. Existing GL parental-control use of `GL_MAC_BLOCK` is unresolved and must be respected.

No `FLOWOFFLOAD` rule appears in the saved rules, although `xt_FLOWOFFLOAD` is listed among loaded x_tables users. Hardware/vendor offload configuration was not inspected. Absence of this rule is not proof that accelerated flows cannot bypass enforcement; offload and existing-session cutoff need separate validation.

Configured includes are `/etc/firewall.user`, `/etc/firewall.nat6`, `/etc/firewall.dns_order`, `/usr/bin/rtp2.sh`, `/usr/bin/gl_block.sh`, `/etc/firewall.dmz.exclude`, and `/etc/firewall.security`. `dns_order` is enabled with reload support. Include contents and restart/reload behavior were not inspected. Hook availability does not yet prove persistence or idempotence.

## IPv6 state

`br-lan` has IPv4 `192.168.1.1/24` and no IPv6 address in the captured address listing. No usable LAN IPv6 route appears; the IPv6 route listing contains only an unreachable ULA /48 on loopback. LAN RA and DHCPv6 are both configured `disabled`, but `network.lan.ip6assign='60'` and `dhcp.lan.ra_slaac='1'` remain.

This is evidence of the current snapshot, **not permanent IPv6 disablement**. IPv6 kernel/firewall support exists. Prefix acquisition, reboot, or configuration changes could change the state; the PRP's IPv6 bypass prevention remains an implementation and validation requirement.

## DNS and WAN exposure

The AdGuard init enabled check printed `AGH-on`. Actual AdGuard process health, configuration, and DNS listener ownership were not established. TCP and UDP port 53 listeners exist on LAN `192.168.1.1`, IPv4 loopback, the WAN IPv4 address, and IPv6 loopback. The listing has no process attribution, so these listeners cannot be assigned to AdGuard or dnsmasq from this evidence.

WAN zone input is **DROP**, not the PRP's stated REJECT assumption. The saved rules lead WAN input to `zone_wan_src_DROP`, with DHCP/IGMP and DNAT exceptions; no explicit WAN port-53 accept appears. A WAN-bound listener alone does not prove external DNS exposure. The external cellular `dig @<WAN IP> example.com` timeout check is pending and must be performed separately before claiming external DNS is closed.

GL DNS integration is significant:

- `dns_dispatcher` returns for mark `0x8/0x8`, then enters `adg_redirect`, `policy_redirect`, and `dns_redirect`; these targets have no rules in the captured NAT table.
- Active `zone_lan_input` rules DROP UDP/53 with mark **not** `0x8000/0xf000`, and UDP/3053 with mark `0x0/0xf000`. In IPv4 they occur after `input_lan_rule` and before the zone's DNAT acceptance rule. IPv6 contains the same leak rules after `input_lan_rule` and before `zone_lan_src_ACCEPT`, with no DNAT acceptance rule in this snapshot.
- Raw/mangle DNS handling and GL routing marks also exist. WAN/guest leak rules are configured disabled; analogous VPN-server leak rules are configured enabled.

A new kids-only DNS DNAT rule alone is therefore not established as sufficient: redirected UDP DNS can reach a GL leak DROP before the DNAT accept. Future LAN-specific Couvre-feu integration must account for marking and rule ordering and preserve adult DNS behavior. This step made no dnsmasq, WAN DNS, AdGuard, mark, or firewall changes.

## JSON, restricted SSH, and persistence

- `/usr/bin/jsonfilter` is available; `/usr/share/libubox/jshn.sh` and `/lib/functions.sh` exist. JSON parsing against the proposed schema is untested.
- Dropbear reports v2024.86; installed package is `2024.86-1`. Binary strings contain `command="`, the malformed authorized-key command diagnostic, `SSH_ORIGINAL_COMMAND`, `no-port-forwarding`, `no-agent-forwarding`, and `no-pty`. This supports compiled restricted-key functionality, but is **not runtime confirmation** of forced-command confinement or forwarding restrictions. Password/root password authentication remains enabled; no key or auth setting was changed.
- Cron enabled check printed `cron-enabled`; no task execution, timing, or restart behavior was tested.
- `/etc/sysupgrade.conf` contains only explanatory comments and example commented paths. No active Couvre-feu preservation entry exists there; default sysupgrade preservation behavior was not inspected.
- The local capture uniquely maps the current SSH client IP to a reachable MAC. Its identifiers are intentionally omitted from this public report. This is a self-lockout safety candidate from that session, not an installed allowlist or durable identity guarantee.

## Remaining checks — separate approval required

Before implementation can be considered ready, a separately approved checklist must resolve:

1. Individual `conntrack`/`ip6tables` executable and version checks, firmware identity, router timezone, and offload configuration.
2. GL include contents, current parental controls, DNS listener/process ownership, AdGuard running state, and DNS mark/redirect interactions.
3. External cellular WAN DNS reachability; LAN IPv6 bypass assumptions across prefix acquisition and reboot.
4. Runtime forced-command and forwarding restrictions using a dedicated key and rollback plan; safety-client identity confirmation.
5. Later controlled enforcement tests: set/match behavior, established-session termination, offload behavior, adult DNS preservation, firewall reload/idempotence, cron scheduling, and sysupgrade preservation. These tests may mutate state and require approval beyond inspection.

No additional checks were run for this report. The evidence establishes useful primitives and hook ordering, but does not establish operational enforcement, safe DNS integration, durable IPv6 closure, or production readiness.

## Local attempt history

Earlier sandbox attempts failed before remote execution: first SSH configuration permissions (`20-systemd-ssh-proxy.conf`), then socket creation (`Operation not permitted`) using `ssh -F /dev/null`. The user's first local attempt failed strict host-key checking. The script was adjusted for terminal host-key/password prompts; the supplied output records the subsequent successful local inspection. A local sysroot/system-bus warning also appears, but the inspection produced router output. No passwords are retained in this report.
