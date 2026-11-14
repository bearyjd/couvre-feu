/**
 * Closed set of class codes for NextDNS blocked-lookup counts (phase-c-digest plan 4.1). The only vocabulary that ever
 * leaves the NextDNS client or reaches a database or the web app: never a vendor reason id, name or domain.
 */
export const CLASS_CODES = Object.freeze(['adult', 'gambling', 'dating', 'piracy', 'social', 'gaming', 'video', 'apps', 'bypass',
    'denylist', 'ads_trackers', 'security', 'other'] as const);
export type ClassCode = typeof CLASS_CODES[number];

/** Classes that count toward "blocked by your filter". ads_trackers and security are background; other is shown as "other". */
export const HEADLINE_CLASSES: readonly ClassCode[] = Object.freeze(['adult', 'gambling', 'dating', 'piracy', 'social', 'gaming',
    'video', 'apps', 'bypass', 'denylist'] as const);

export const CLASS_LABELS: Readonly<Record<ClassCode, string>> = Object.freeze({
    adult: 'Adult content', gambling: 'Gambling', dating: 'Dating', piracy: 'Piracy', social: 'Social networks', gaming: 'Gaming',
    video: 'Video streaming', apps: 'Blocked apps and services', bypass: 'Ways around the filter', denylist: 'Sites you blocked by hand',
    ads_trackers: 'Ads and trackers', security: 'Security protections', other: 'Other',
});

export const isClassCode = (v: unknown): v is ClassCode => typeof v === 'string' && (CLASS_CODES as readonly string[]).includes(v);
