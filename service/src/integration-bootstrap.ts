import { integrationConfig } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { issueOperatorBootstrap } from './auth.ts';

// Accounts live in the database (seeded once from the manifest, later created by admins). The operator on this host is
// trusted, so the passkey this token enrolls is active at once, also as an additional passkey of an enrolled account.
if (process.argv.length !== 4) throw new Error('usage_integration_bootstrap_manifest_account');
const config = integrationConfig(process.argv[2]), store = new IntegrationStore(config);
try {
    process.stdout.write(issueOperatorBootstrap(store, process.argv[3]) + '\n');
} finally { store.close(); }
