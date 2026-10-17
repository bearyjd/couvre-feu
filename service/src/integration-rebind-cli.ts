import { integrationConfig } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { rebindIntegration } from './integration-rebind.ts';

// Operator-only. Stop the service first; the digests are the sha256 of each manifest file, confirming the exact pair.
if (process.argv.length !== 6) throw new Error('usage_integration_rebind_old_manifest_new_manifest_old_digest_new_digest');
const old = integrationConfig(process.argv[2]), next = integrationConfig(process.argv[3]), store = new IntegrationStore(old);
try {
    rebindIntegration(store, next, process.argv[4], process.argv[5], Math.floor(Date.now() / 1000));
    process.stdout.write(`Rebound ${old.manifestDigest} -> ${next.manifestDigest}. Dispatch remains stopped; observe the router before enabling it.\n`);
} finally { store.close(); }
