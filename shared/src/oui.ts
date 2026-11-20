import { OUI_VENDORS } from './oui-table.ts';

/**
 * Vendor hint from the first three octets of a MAC address (OUI).
 *
 * Provenance and limits (also docs/oui-table.md): the data in oui-table.ts is a TRIMMED extract of the IEEE MA-L registry as shipped in
 * hwdata, produced offline by tools/gen-oui.py; it is vendored and never fetched at runtime. It is INCOMPLETE: only the consumer and
 * home-network brands listed in the generator are kept, so `undefined` means "not in this table", not "no maker". A registered prefix
 * names whoever bought the prefix (a module maker such as Espressif or Realtek, not the product brand), so the result is a hint only.
 * The facts (prefix -> organisation) come from the IEEE public registry; check IEEE's terms before redistributing the table outside this
 * repository.
 *
 * Locally-administered addresses (the 0x02 bit of the first octet, which is what phones use for "private" Wi-Fi addresses) are random,
 * not registered, so they never get a vendor. The one exception is the documented QEMU/KVM default 52:54:00, which is a hypervisor
 * convention rather than a registered prefix.
 */
const MAC = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;
const QEMU_DEFAULT_PREFIX = '52:54:00';
export const QEMU_VENDOR = 'QEMU/KVM (virtual)';

const table = new Map<string, string>();
for (const [vendor, prefixes] of OUI_VENDORS) for (const prefix of prefixes) table.set(prefix, vendor);
export const OUI_PREFIX_COUNT = table.size;

export function lookupVendor(mac: string): string | undefined {
    if (typeof mac !== 'string' || !MAC.test(mac)) return undefined;
    const lower = mac.toLowerCase();
    if (lower.startsWith(`${QEMU_DEFAULT_PREFIX}:`)) return QEMU_VENDOR;
    // Every table prefix is globally administered (asserted in the tests), so a randomized address can only miss.
    return table.get(lower.slice(0, 8).replaceAll(':', ''));
}
