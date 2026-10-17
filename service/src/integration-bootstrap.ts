import { integrationConfig } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { issueOperatorBootstrap } from './auth.ts';

// Accounts live in the database (seeded once from the manifest, later created by admins). The token may cross a cleartext
// proxy hop, so the passkey it enrolls is active only for an account without an active passkey (first enrollment); for an
// enrolled account it is pending until an admin compares its pairing code and approves it. A new token rejects pending passkeys.
if (process.argv.length !== 4) throw new Error('usage_integration_bootstrap_manifest_account');
const config = integrationConfig(process.argv[2]), store = new IntegrationStore(config);
try {
    process.stdout.write(issueOperatorBootstrap(store, process.argv[3]) + '\n');
} finally { store.close(); }
