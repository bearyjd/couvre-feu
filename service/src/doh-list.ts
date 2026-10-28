import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { IntegrationManifest } from './integration-config.ts';

/**
 * Well-known public DoH/DoT resolver addresses the router can block for the kids' devices (flag dnsHardening.dohList).
 * Every address below was read from the provider's own published documentation on the stated date; anything that could not
 * be verified first-hand is deliberately absent. Exact addresses only: no ranges, so nothing wider than a resolver is covered.
 * Provider addresses change over time; re-verify before relying on an entry.
 */
export interface DohProvider { readonly name: string; readonly source: string; readonly verified: string; readonly ipv4: readonly string[]; readonly ipv6: readonly string[] }

export const DOH_PROVIDERS: readonly DohProvider[] = Object.freeze([
    {name: 'Cloudflare', source: 'https://developers.cloudflare.com/1.1.1.1/ip-addresses/', verified: '2026-10-27',
        ipv4: ['1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3'],
        ipv6: ['2606:4700:4700::1111', '2606:4700:4700::1001', '2606:4700:4700::1112', '2606:4700:4700::1002', '2606:4700:4700::1113', '2606:4700:4700::1003']},
    {name: 'Google Public DNS', source: 'https://developers.google.com/speed/public-dns/docs/using', verified: '2026-10-27',
        ipv4: ['8.8.8.8', '8.8.4.4'], ipv6: ['2001:4860:4860::8888', '2001:4860:4860::8844']},
    {name: 'Quad9', source: 'https://quad9.net/service/service-addresses-and-features', verified: '2026-10-27',
        ipv4: ['9.9.9.9', '149.112.112.112', '9.9.9.11', '149.112.112.11', '9.9.9.10', '149.112.112.10'],
        ipv6: ['2620:fe::fe', '2620:fe::9', '2620:fe::11', '2620:fe::fe:11', '2620:fe::10', '2620:fe::fe:10']},
    // IPv4 only: the IPv6 addresses (2620:119:35::35 etc.) could not be confirmed on a current official page, so they are left out.
    {name: 'OpenDNS (Cisco)', source: 'https://www.opendns.com/setupguide/', verified: '2026-10-27',
        ipv4: ['208.67.222.222', '208.67.220.220', '208.67.222.123', '208.67.220.123'], ipv6: []},
    {name: 'AdGuard DNS', source: 'https://adguard-dns.io/en/public-dns.html', verified: '2026-10-27',
        ipv4: ['94.140.14.14', '94.140.15.15', '94.140.14.140', '94.140.14.141', '94.140.14.15', '94.140.15.16'],
        ipv6: ['2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff', '2a10:50c0::1:ff', '2a10:50c0::2:ff', '2a10:50c0::bad1:ff', '2a10:50c0::bad2:ff']},
    // NextDNS publishes no address page; these are the anycast bootstrap addresses in the vendor's own client source
    // (github.com/nextdns/nextdns config.go at 9b004cccbccf01b0a3a4f502cd2b4298e88870c3). Profile-specific addresses are not covered.
    {name: 'NextDNS', source: 'https://github.com/nextdns/nextdns/blob/9b004cccbccf01b0a3a4f502cd2b4298e88870c3/config.go', verified: '2026-10-27',
        ipv4: ['45.90.28.0', '45.90.30.0'], ipv6: ['2a07:a8c0::', '2a07:a8c1::']},
    {name: 'CleanBrowsing', source: 'https://cleanbrowsing.org/filters/', verified: '2026-10-27',
        ipv4: ['185.228.168.168', '185.228.169.168', '185.228.168.10', '185.228.169.11', '185.228.168.9', '185.228.169.9'],
        ipv6: ['2a0d:2a00:1::', '2a0d:2a00:2::', '2a0d:2a00:1::1', '2a0d:2a00:2::1', '2a0d:2a00:1::2', '2a0d:2a00:2::2']}
    // Mullvad DNS is left out: its page announces the public service ends on 2026-11-02, after which the addresses may be reused.
].map(p => Object.freeze(p)));

const unique = (items: readonly string[]): readonly string[] => Object.freeze([...new Set(items)].sort());
export const DOH_IPV4: readonly string[] = unique(DOH_PROVIDERS.flatMap(p => p.ipv4));
export const DOH_IPV6: readonly string[] = unique(DOH_PROVIDERS.flatMap(p => p.ipv6));

const FAMILY_CAP = 256;
export const DOH_CONFLICT_TAG = 'doh_list_protected_conflict';

function words(ip: string): bigint {
    const [head, tail] = ip.split('::'), left = head ? head.split(':') : [], right = tail ? tail.split(':') : [];
    const all = ip.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
    return all.reduce((n, w) => (n << 16n) + BigInt(parseInt(w, 16)), 0n);
}
interface Net { v6: boolean; base: bigint; bits: number }
function parseNet(entry: string): Net {
    const [address, prefix, extra] = entry.split('/'), v6 = address.includes(':');
    const ok = extra === undefined && (v6 ? /^[0-9a-f:]{2,39}$/.test(address) : /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(address) && address.split('.').every(p => +p <= 255));
    const width = v6 ? 128 : 32, bits = prefix === undefined ? width : /^[0-9]{1,3}$/.test(prefix) ? +prefix : -1;
    if (!ok || bits < 0 || bits > width) throw new Error('invalid_protected_address');
    return {v6, base: v6 ? words(address) : address.split('.').reduce((n, p) => (n << 8n) + BigInt(p), 0n), bits};
}
const covers = (net: Net, v6: boolean, value: bigint): boolean => {
    if (net.v6 !== v6) return false;
    const shift = BigInt((v6 ? 128 : 32) - net.bits);
    return (net.base >> shift) === (value >> shift);
};

/** The addresses the manifest already treats as the household's own: the router, the service listener and its trusted proxies. */
export function protectedAddressesOf(config: Pick<IntegrationManifest, 'router' | 'listen' | 'trustedProxies'>): string[] {
    return [config.router.host, ...(config.listen ? [config.listen.host] : []), ...(config.trustedProxies ?? [])];
}

export interface DohMerge { doh: RouterPolicy['doh']; refused: number; tag: string }
/**
 * Union of the existing entries and the static list, sorted and capped per family. Existing entries always survive; static
 * entries equal to or inside a protected address/range are refused and only counted. `protectedAddresses` are exact addresses
 * or CIDR ranges of either family.
 */
export function mergeStaticDoh(existing: RouterPolicy['doh'], protectedAddresses: readonly string[]): DohMerge {
    const nets = protectedAddresses.map(parseNet);
    let refused = 0;
    const family = (current: readonly string[], list: readonly string[], v6: boolean): string[] => {
        const kept = new Set(current), added: string[] = [];
        for (const ip of list) {
            if (kept.has(ip)) continue;
            if (nets.some(net => covers(net, v6, parseNet(ip).base))) { refused++; continue; }
            if (kept.size + added.length < FAMILY_CAP) added.push(ip);
        }
        return [...kept, ...added].sort();
    };
    return {doh: {ipv4: family(existing.ipv4, DOH_IPV4, false), ipv6: family(existing.ipv6, DOH_IPV6, true)}, refused, tag: DOH_CONFLICT_TAG};
}
