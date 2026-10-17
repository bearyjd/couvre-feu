import type { AuthSession } from './auth.ts';
import type { AccountAdmin, AdminAction } from './admin-accounts.ts';
import type { Routed } from './time-requests-http.ts';

const ACCOUNT = /^\/admin\/accounts\/([a-z][a-z0-9_]{0,31})\/(tokens|role|active)$/;
const PASSKEY = /^\/admin\/passkeys\/([A-Za-z0-9_-]{1,1400})\/(approve|revoke)$/;
const OWN_PASSKEY = /^\/account\/passkeys\/([A-Za-z0-9_-]{1,1400})\/revoke$/;
const ACCOUNT_ACTIONS: Record<string, AdminAction> = {tokens: 'token_issue', role: 'account_role', active: 'account_active'};

/** Session-checked reads. Returns null when the path is not an account route. */
export function accountGet(admin: AccountAdmin, session: AuthSession, path: string): Routed | null {
    if (path === '/admin/accounts') return {status: 200, body: admin.list(session.dto.actor)};
    if (path === '/account/passkeys') return {status: 200, body: admin.mine(session)};
    return null;
}

/** Session- and CSRF-checked changes; each one also verifies its own fresh step-up assertion. */
export async function accountPost(admin: AccountAdmin, session: AuthSession, path: string, payload: unknown): Promise<Routed | null> {
    if (path === '/step-up/options') return {status: 200, body: await admin.stepUpOptions(session, payload)};
    if (path === '/admin/accounts') return {status: 200, body: await admin.perform(session, 'account_create', '', payload)};
    const account = ACCOUNT.exec(path);
    if (account) return {status: 200, body: await admin.perform(session, ACCOUNT_ACTIONS[account[2]], account[1], payload)};
    const passkey = PASSKEY.exec(path);
    if (passkey) return {status: 200, body: await admin.perform(session, passkey[2] === 'approve' ? 'passkey_approve' : 'passkey_revoke', passkey[1], payload)};
    const own = OWN_PASSKEY.exec(path);
    if (own) return {status: 200, body: await admin.perform(session, 'own_passkey_revoke', own[1], payload)};
    return null;
}
