# DNS hardening: static public DoH resolver list (D2)

Status: implemented, **OFF by default**, **unverified on this router**. Do not turn it on until the router has been re-measured live (see "Before turning it on (enable gate)").

## What it does

When the manifest key `dnsHardening.dohList` is `true`, every policy the service submits to the router has its `doh` arrays set to the union of:

- the `doh` entries already in the router's accepted policy (hand-added entries are never removed; only list and retired entries are), and
- the static list of well-known public DoH/DoT resolver addresses in `service/src/doh-list.ts`.

The router enforces `doh.ipv4` / `doh.ipv6` from the policy (at most 256 entries per family, canonical form, sorted, no duplicates). The service changes nothing on the router and adds no router code. The list is merged in one place (`IntegrationPolicy.queue`), so pause, resume, allowance, enroll, unenroll, move and bulk operations all carry it. Existing entries always win the cap: the list is only added up to 256 per family.

When the flag key is absent, the submitted policy is byte-identical to before: whatever `doh` the router already holds is preserved by the existing `...base` spreads and nothing is added or removed. An explicit `false` is a rollback (see below).

Not touched: dnsmasq, WAN, DHCP, adult or management traffic. The service refuses to merge any list entry equal to or inside a protected address (the router host, the service listener and its trusted proxies); it then writes the tag `doh_list_protected_conflict` to stderr, with no address in it. The tag repeats on every policy operation for as long as the conflict exists. Nothing child-specific is logged.

## What is blocked

NextDNS publishes no resolver addresses on a documentation page; its row below is vendor client source, not documentation. Exact resolver addresses (no ranges) of these providers, including their filtering variants and secondary addresses. NextDNS is blocked like the others (owner decision 2026-10-27).

| Provider | Source (official) | Verified |
|---|---|---|
| Cloudflare 1.1.1.1, 1.1.1.2, 1.1.1.3 (IPv4 + IPv6) | https://developers.cloudflare.com/1.1.1.1/ip-addresses/ | 2026-10-27 |
| Google Public DNS (IPv4 + IPv6) | https://developers.google.com/speed/public-dns/docs/using | 2026-10-27 |
| Quad9 recommended, ECS, unsecured (IPv4 + IPv6) | https://quad9.net/service/service-addresses-and-features | 2026-10-27 |
| OpenDNS / Cisco, standard and FamilyShield (IPv4 only) | https://www.opendns.com/setupguide/ | 2026-10-27 |
| AdGuard DNS default, non-filtering, family (IPv4 + IPv6) | https://adguard-dns.io/en/public-dns.html | 2026-10-27 |
| NextDNS anycast 45.90.28.0, 45.90.30.0, 2a07:a8c0::, 2a07:a8c1:: | vendor client source: https://github.com/nextdns/nextdns/blob/9b004cccbccf01b0a3a4f502cd2b4298e88870c3/run.go (lines 612, 622, 623, 626; also config/config.go:141) | 2026-10-27 |
| CleanBrowsing family, adult, security (IPv4 + IPv6) | https://cleanbrowsing.org/filters/ | 2026-10-27 |
| Mullvad DNS dns, adblock, base, extended, family, all (IPv4 + IPv6; owner decision 2026-10-28) | https://mullvad.net/en/help/dns-over-https-and-dns-over-tls (shutdown announcement: https://mullvad.net/en/blog/shutting-down-our-public-encrypted-dns-servers-and-sponsoring-quad9-instead, 2026-09-03) | 2026-10-28 |

Dropped, not included:

- OpenDNS IPv6 (2620:119:35::35 and similar): the official support article now redirects and no current official page could be read.
- NextDNS addresses seen only in forum posts (for example the `.63` addresses), and any /22 or /24 range.

## Planned retirement: Mullvad

Mullvad's page says: "Please note that the public encrypted DNS service will be discontinued on November 2, 2026." The addresses are listed anyway (owner decision 2026-10-28). After 2026-11-02, from 2026-11-03, move the twelve Mullvad addresses (194.242.2.{2,3,4,5,6,9} and 2a07:e340::{2,3,4,5,6,9}) out of `DOH_PROVIDERS` and into `DOH_RETIRED_IPV4/IPV6`, so the removal path strips them from routers: a released address that is reused by someone else would otherwise stay blocked for the kids. The removal only runs while the `dnsHardening` key is present in the manifest (`dohList:true` or `dohList:false`): with the key absent the policy is returned untouched, so a router that never had the key keeps whatever its `doh` list already holds. Mullvad's pages say nothing about what happens to the addresses after the shutdown, so the reuse risk is an assumption, not a statement from Mullvad. Add a retirement test when the move is made. Add a retirement test in that change (the retired addresses are absent from the list, present in `DOH_RETIRED_*`, and removed by `reconcileStaticDoh`).

## Turn on, turn off, rollback

On: set `"dnsHardening": {"dohList": true}` in the private manifest and restart the service. The list reaches the router with the next accepted operation (any pause, resume, allowance, device change). The key is strict: only `{dohList: boolean}`; anything else makes the manifest invalid. Absent means off.

Rollback: set `{"dohList": false}`. **Do not remove the key**: an absent key means untouched, not rollback, and leaves any list already on the router in place. With the key present, every policy operation strips the retired addresses (`DOH_RETIRED_IPV4/IPV6` in `service/src/doh-list.ts`: every address ever shipped and later removed from the code) and, when `false`, the whole current list. Entries that are in neither set (for example a hand-added resolver) are never removed. Rebind or restart the service so it re-reads the manifest (the steps are in [How to turn a flag on](service-contract.md#how-to-turn-a-flag-on) in `docs/service-contract.md`); the removal takes effect on the next policy operation (any pause, resume, allowance, device change), not immediately.

When an entry is dropped from the code, add it to the retired arrays in the same change, otherwise it stays on the router for good.

The shipped `DOH_RETIRED_IPV4` / `DOH_RETIRED_IPV6` lists are empty today. Retired-entry stripping is therefore untested end-to-end until a first address is retired (the tests inject a retired set).

Overlap with a hand-added entry: the router's `doh` list has no record of who added an entry. An address that was hand-added and is also equal to a list entry is indistinguishable from a list entry. With `dohList:false`, it is stripped like any list entry (`reconcileStaticDoh` drops every current list address, `service/src/doh-list.ts`). While the flag is on it is never removed. Do not hand-add resolver addresses that are on the static list; hand-add only addresses that are not on it, since those are the only ones the service never removes.

The pilot tool `tools/live/penn-pilot.sh` does not interact with this list in normal use. Its measurement policy (`cfp_stage_json`, line ~1306) submits `"doh":{"ipv4":[],"ipv6":[]}` straight through `cfctl rpc-sync`, not through the service, so during its stages the `doh` list is empty by construction. The tool refuses to start unless the router reports revision 0 and no people (`activation_not_fresh`), so it cannot run against a router that carries a service-merged list in its accepted policy. Every path ends in `uninstall.sh`, an exact snapshot comparison and a teardown proof, so the pilot's install and policy state are removed afterwards. After that the router is a fresh install at revision 0, and the next service operation with the flag on merges the static list from an empty base (hand-added entries are not restored).

Consequence: any router with an enrolled child already fails the supplied empty-installation witness (`shared/src/empty-witness.ts:42-43` requires `revision: 0` with no people, pauses or schedules). The list only adds to that; the witness is an operator check for a router with no policy, not part of the service runtime.

## Limits

- Provider addresses change. The list is a snapshot dated above; re-verify before relying on it.
- Only listed addresses are blocked. DoH/DoT to any unlisted resolver, or to a hostname served from a shared CDN address, still works.
- VPNs, Tor and proxies are not covered.
- NextDNS profile-specific (linked-IP and personalised IPv6) addresses are not covered; the schema takes exact addresses, not CIDR.
- Blocking is only as good as the router's enforcement of the `doh` sets, which has not been measured on this router.

## Known gaps (list on does not mean DoH is blocked)

- Browsers' default Cloudflare DoH endpoints: Firefox and Chrome use dedicated hostnames and addresses that are not on this list.
- NextDNS per-profile and other addresses beyond the four anycast ones.
- iCloud Private Relay.
- OpenDNS over IPv6 (not listed; no verifiable official page).
- Any DoH resolver that is not listed.
- VPNs and Tor.

## Collateral

Kids' devices cannot ping or open web pages at the listed addresses (for example `https://1.1.1.1`, `dns.google`). Plain DNS to 8.8.8.8 is still redirected to the router and keeps working.

## Before turning it on (enable gate)

Do NOT turn the flag on until a live check on the real router shows that a policy of about 64 `doh` entries is accepted and that the rule applies to the kids' devices only. The owner decides when. The router must be re-measured live first: confirm that a policy with a full `doh` set (256 + 256 entries) is accepted, that the entries are enforced for the kids' devices only, and that adult and management traffic, DHCP and the WAN are unaffected. Until that is recorded, this feature is unverified on this router.
