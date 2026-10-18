import { AppError } from '../../shared/src/errors.ts';
import type { IntegrationStore } from './integration-db.ts';

const adminsWithPasskey = (store: IntegrationStore) => store.get<{n: number}>("SELECT count(DISTINCT a.id) n FROM accounts a JOIN credentials c ON c.account_id=a.id WHERE a.role='admin' AND a.active=1 AND c.state='active'")!.n;

/**
 * Operator-only recovery: removes every passkey (active and pending) of one account, ends all of its sessions, voids its
 * outstanding tokens and step-ups, and audits each removal. Refuses to leave no active admin with a passkey unless
 * `allowNoAdmin` (sole-admin recovery: the next `integration:bootstrap` then enrolls an active first passkey).
 */
export function revokeAccountPasskeys(store: IntegrationStore, accountId: string, now: number, allowNoAdmin: boolean): number {
    return store.transaction(() => {
        store.assertIdentity();
        if (!store.get('SELECT id FROM accounts WHERE id=?', accountId)) throw new AppError(404, 'unknown_private_account');
        const before = adminsWithPasskey(store);
        const credentials = store.all<{id: string}>('SELECT id FROM credentials WHERE account_id=? ORDER BY id', accountId);
        for (const {id} of credentials) {
            store.run('DELETE FROM credentials WHERE id=?', id);
            store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', 'operator', 'passkey_operator_revoke', now, `${accountId}:${id}`);
        }
        if (before > 0 && adminsWithPasskey(store) === 0 && !allowNoAdmin) throw new AppError(409, 'last_admin_required', 'This would leave no active admin with a passkey; pass --allow-no-admin for sole-admin recovery.');
        store.run('UPDATE sessions SET revoked=1 WHERE account_id=?', accountId);
        store.run('UPDATE bootstrap_tokens SET consumed=1 WHERE account_id=?', accountId);
        store.run('UPDATE step_ups SET consumed=1 WHERE account_id=?', accountId);
        store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', 'operator', 'account_passkeys_revoked', now, `${accountId}:${credentials.length}${allowNoAdmin ? ':allow_no_admin' : ''}`);
        return credentials.length;
    });
}
