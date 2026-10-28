# DNS hardening: static public DoH resolver list (D2)

Status: implemented, **OFF by default**, **unverified on this router**. Do not turn it on until the router has been re-measured live (see "Before turning it on").

## What it does

When the manifest key `dnsHardening.dohList` is `true`, every policy the service submits to the router has its `doh` arrays set to the union of:

- the `doh` entries already in the router's accepted policy (never removed), and
- the static list of well-known public DoH/DoT resolver addresses in `service/src/doh-list.ts`.

The router enforces `doh.ipv4` / `doh.ipv6` from the policy (at most 256 entries per family, canonical form, sorted, no duplicates). The service changes nothing on the router and adds no router code. The list is merged in one place (`IntegrationPolicy.queue`), so pause, resume, allowance, enroll, unenroll, move and bulk operations all carry it. Existing entries always win the cap: the list is only added up to 256 per family.

When the flag is absent or `false`, the submitted policy is byte-identical to before: whatever `doh` the router already holds is preserved by the existing `...base` spreads and nothing is added.

Not touched: dnsmasq, WAN, DHCP, adult or management traffic. The service refuses to merge any list entry equal to or inside a protected address (the router host, the service listener and its trusted proxies); it then writes the tag `doh_list_protected_conflict` to stderr, with no address in it. Nothing child-specific is logged.

## What is blocked

Exact resolver addresses (no ranges) of these providers, including their filtering variants and secondary addresses. NextDNS is blocked like the others (owner decision 2026-10-27).

| Provider | Source (official) | Verified |
|---|---|---|
| Cloudflare 1.1.1.1, 1.1.1.2, 1.1.1.3 (IPv4 + IPv6) | https://developers.cloudflare.com/1.1.1.1/ip-addresses/ | 2026-10-27 |
| Google Public DNS (IPv4 + IPv6) | https://developers.google.com/speed/public-dns/docs/using | 2026-10-27 |
| Quad9 recommended, ECS, unsecured (IPv4 + IPv6) | https://quad9.net/service/service-addresses-and-features | 2026-10-27 |
| OpenDNS / Cisco, standard and FamilyShield (IPv4 only) | https://www.opendns.com/setupguide/ | 2026-10-27 |
| AdGuard DNS default, non-filtering, family (IPv4 + IPv6) | https://adguard-dns.io/en/public-dns.html | 2026-10-27 |
| NextDNS anycast 45.90.28.0, 45.90.30.0, 2a07:a8c0::, 2a07:a8c1:: | vendor client source: https://github.com/nextdns/nextdns/blob/9b004cccbccf01b0a3a4f502cd2b4298e88870c3/config.go | 2026-10-27 |
| CleanBrowsing family, adult, security (IPv4 + IPv6) | https://cleanbrowsing.org/filters/ | 2026-10-27 |

Dropped, not included:

- OpenDNS IPv6 (2620:119:35::35 and similar): the official support article now redirects and no current official page could be read.
- Mullvad DNS: its page says the public service ends 2026-11-02; the addresses may then be reused by someone else.
- NextDNS addresses seen only in forum posts (for example the `.63` addresses), and any /22 or /24 range.

## Turn on, turn off, rollback

On: set `"dnsHardening": {"dohList": true}` in the private manifest and restart the service. The list reaches the router with the next accepted operation (any pause, resume, allowance, device change). The key is strict: only `{dohList: boolean}`; anything else makes the manifest invalid. Absent means off.

Off: set `{"dohList": false}` or remove the key. **This stops adding the list; it does not remove entries already on the router**, because the service preserves the router's accepted `doh` (that is what keeps flag-off identical to before). A test pins this. Removing the list needs a policy submitted with the `doh` arrays cleared, and no service path for that exists yet: do not treat "flag off + resubmit" as a rollback. Until a removal path exists, treat turning the flag on as one-way.

Consequence: once the router holds the list, the supplied empty-installation witness (`tests/empty-witness.ts`, requires empty `doh`) can no longer pass on that router. It is an operator check for a router with no policy, not part of the service runtime.

## Limits

- Provider addresses change. The list is a snapshot dated above; re-verify before relying on it.
- Only listed addresses are blocked. DoH/DoT to any unlisted resolver, or to a hostname served from a shared CDN address, still works.
- VPNs, Tor and proxies are not covered.
- NextDNS profile-specific (linked-IP and personalised IPv6) addresses are not covered; the schema takes exact addresses, not CIDR.
- Blocking is only as good as the router's enforcement of the `doh` sets, which has not been measured on this router.

## Before turning it on

The router must be re-measured live first: confirm that a policy with a full `doh` set (256 + 256 entries) is accepted, that the entries are enforced for the kids' devices only, and that adult and management traffic, DHCP and the WAN are unaffected. Until that is recorded, this feature is unverified on this router.
