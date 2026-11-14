import type { ClassCode } from '../../shared/src/content-filter-classes.ts';

/**
 * Maps a NextDNS reason id to a fixed class code. Pure, total, and it never echoes its input: the result is always a member of
 * CLASS_CODES, so no string built from a reason id leaves this function (a `denylist:<domain>` id can carry a domain).
 *
 * UNVERIFIED: how NextDNS spells reason ids for parental-control categories, services, Block Bypass and security features. The API doc
 * only shows `blocklist:nextdns-recommended`, `native:apple` and `disguised-trackers` (plan section 1). The exact-match entries below
 * are candidate forms; the live probe (plan C0) decides the real table. Anything not listed is `other`, which is safe.
 */
const FORMS = (id: string): readonly string[] => [id, `parentalcontrol:${id}`, `category:${id}`, `service:${id}`];
const CATEGORY_IDS: readonly (readonly [string, ClassCode])[] = [['porn', 'adult'], ['gambling', 'gambling'], ['dating', 'dating'],
    ['piracy', 'piracy'], ['social-networks', 'social'], ['gaming', 'gaming'], ['video-streaming', 'video']];
// Service ids offered by the web card (SERVICES in web/public/content-filter.js), all summed into one `apps` class (plan O3).
const SERVICE_IDS = ['tiktok', 'instagram', 'snapchat', 'discord', 'roblox', 'youtube'];
const BYPASS_IDS = ['bypass', 'block-bypass', 'blockbypass'];
// Candidate security feature ids (UNVERIFIED spellings).
const SECURITY_IDS = ['threat-intelligence-feeds', 'nrd', 'dns-rebinding', 'idn-homographs', 'typosquatting', 'dga', 'parked-domains',
    'cryptojacking', 'csam', 'google-safe-browsing', 'ai-threat-detection'];
const EXACT: ReadonlyMap<string, ClassCode> = new Map<string, ClassCode>([
    ...CATEGORY_IDS.flatMap(([id, cls]) => FORMS(id).map(f => [f, cls] as const)),
    ...SERVICE_IDS.flatMap(id => FORMS(id).map(f => [f, 'apps'] as const)),
    ...BYPASS_IDS.flatMap(id => FORMS(id).map(f => [f, 'bypass'] as const)),
    ...SECURITY_IDS.flatMap(id => [[id, 'security'] as const, [`security:${id}`, 'security'] as const]),
    ['disguised-trackers', 'ads_trackers'],
]);

export function classOf(reasonId: string): ClassCode {
    if (typeof reasonId !== 'string' || reasonId.length > 4096) return 'other';
    if (reasonId === 'denylist' || reasonId.startsWith('denylist:')) return 'denylist'; // the suffix is discarded
    if (reasonId.startsWith('blocklist:') || reasonId.startsWith('native:')) return 'ads_trackers';
    return EXACT.get(reasonId) ?? 'other';
}
