import { randomBytes } from 'node:crypto';
import { integrationConfig } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { digest } from './auth.ts';

if (process.argv.length !== 4) throw new Error('usage_integration_bootstrap_manifest_account');
const config = integrationConfig(process.argv[2]), store = new IntegrationStore(config), accountId = process.argv[3];
try {
    if (!config.accounts.some(a => a.id === accountId) || !store.get('SELECT id FROM accounts WHERE id=? AND active=1', accountId)) throw new Error('unknown_private_account');
    if (store.get('SELECT id FROM credentials WHERE account_id=?', accountId)) throw new Error('account_already_enrolled');
    const token = randomBytes(32).toString('base64url');
    store.transaction(() => {
        store.run('UPDATE bootstrap_tokens SET consumed=1 WHERE account_id=?', accountId);
        store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at) VALUES(?,?,?)', digest(token), accountId, Math.floor(Date.now() / 1000) + 600);
    });
    process.stdout.write(token + '\n');
} finally { store.close(); }
