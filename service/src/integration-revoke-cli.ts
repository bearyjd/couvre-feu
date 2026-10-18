import { integrationConfig } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { revokeAccountPasskeys } from './integration-revoke.ts';

// Operator-only, on the service host. Removes every passkey of one account and ends its sessions. --allow-no-admin is the
// sole-admin recovery case; the following integration:bootstrap token then enrolls an active first passkey.
const args = process.argv.slice(2), allowNoAdmin = args[2] === '--allow-no-admin';
if (args.length !== 2 && !(args.length === 3 && allowNoAdmin)) throw new Error('usage_integration_revoke_passkeys_manifest_account_allow_no_admin');
const config = integrationConfig(args[0]), store = new IntegrationStore(config);
try {
    const removed = revokeAccountPasskeys(store, args[1], Math.floor(Date.now() / 1000), allowNoAdmin);
    process.stdout.write(`Removed ${removed} passkey(s) of ${args[1]}; its sessions ended.\n`);
} finally { store.close(); }
