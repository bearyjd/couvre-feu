/** Test support for content filtering: a NextDNS client over the in-process fake (no network) and canonical desired filters. */
import { createNextDnsClient } from '../../src/nextdns-client.ts';
import type { NextDnsClient, Transport } from '../../src/nextdns-client.ts';
import { parseDesired } from '../../src/content-filter-state.ts';
import { createFakeNextDns, json, profile } from './fake-nextdns.ts';
import type { FakeProfile } from './fake-nextdns.ts';

export const API_KEY = 'test-api-key-0123456789';
export const PROFILE_ID = 'abc123';
/** A parent-chosen domain that must never leave the database except in the GET/PUT answer to an authorised parent. */
export const SECRET_DOMAIN = 'blocked-example.test';
export const SECRET_ALLOWED = 'allowed-example.test';
export const DESIRED = parseDesired({categories: ['porn', 'gambling'], services: ['tiktok'], safeSearch: true, youtubeRestrictedMode: true, blockBypass: true, denylist: [SECRET_DOMAIN], allowlist: [SECRET_ALLOWED]});
export const input = (over: Record<string, unknown> = {}) => ({...DESIRED, ...over});

export interface FakeWorld { fake: ReturnType<typeof createFakeNextDns>; client: NextDnsClient; key: {value: string}; profile: FakeProfile; reads: () => number }
/** `wrap` sees every request first, so a test can fail, throttle or mutate the fake around the real answer. */
export function fakeWorld(wrap?: (next: Transport) => Transport): FakeWorld {
    const profiles = [profile(PROFILE_ID)], fake = createFakeNextDns({apiKey: API_KEY, profiles}), key = {value: API_KEY};
    let reads = 0;
    const transport: Transport = wrap ? wrap(fake.transport) : fake.transport;
    const client = createNextDnsClient({apiKey: () => key.value, transport: req => { if (req.method === 'GET') reads++; return transport(req); }, sleep: async () => undefined, random: () => 0, baseDelayMs: 0, maxDelayMs: 0});
    return {fake, client, key, profile: profiles[0]!, reads: () => reads};
}
export { json };
