import type { Auth } from './auth.ts';
import { ContentFilterRoutes } from './content-filter-http.ts';
import { ContentFilterReconciler, contentFilterApiKey } from './content-filter-reconcile.ts';
import { ContentFilterStore } from './content-filter-state.ts';
import type { IntegrationConfig } from './integration-config.ts';
import type { IntegrationPolicy } from './integration-policy.ts';
import type { IntegrationStore } from './integration-db.ts';
import { assertSafeNextDnsEnvironment, createNextDnsClient } from './nextdns-client.ts';
import type { NextDnsClient, Transport } from './nextdns-client.ts';

/**
 * Content filtering is off (null) unless the manifest sets contentFilter.mode to owner or parents. When on, the environment is checked once,
 * here, before any client exists: a disabled-TLS or env-proxy process would expose the API key, so it refuses to start. The key file is read
 * by the client's getter on every request and never at load. `client` is injectable for tests; production uses the default HTTPS transport.
 */
export function wireContentFilter(config: IntegrationConfig, store: IntegrationStore, env: NodeJS.ProcessEnv, client?: NextDnsClient, testing: {transport?: Transport; apiKey?: () => string} = {}) {
    const settings = config.contentFilter;
    if (settings === undefined || settings.mode === 'off') return null;
    assertSafeNextDnsEnvironment(env);
    const filters = new ContentFilterStore(store, () => Math.floor(Date.now() / 1000));
    const reconciler = new ContentFilterReconciler({
        // PRP-006 A3: parent-entered denylist/allowlist entries are managed (stored in the DB, sent to NextDNS), never written to audit/logs/alerts/errors;
        // owner decision 2026-11-08 (keep client gate, PR3 opts in). This is the only place the opt-in is set. `testing` (transport, key source) is for tests; production uses the HTTPS default and the key file.
        client: client ?? createNextDnsClient({apiKey: testing.apiKey ?? contentFilterApiKey(settings.apiKeyFile!), allowDomainLists: true, ...(testing.transport ? {transport: testing.transport} : {})}), profiles: settings.profiles!, store: filters,
    });
    return {filters, reconciler, routes: (auth: Auth, policy: IntegrationPolicy) => new ContentFilterRoutes({
        auth, filters, reconciler, mode: settings.mode, ...(config.ownerAccountId !== undefined ? {ownerAccountId: config.ownerAccountId} : {}),
        authorize: (actor, person) => { policy.authorized(actor, person); },
    })};
}
