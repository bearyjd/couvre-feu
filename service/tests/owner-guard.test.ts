import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Store } from '../src/db.ts';
import { seedAccounts } from '../src/fixtures.ts';
import { Auth, issueBootstrap } from '../src/auth.ts';
import { AccountAdmin } from '../src/admin-accounts.ts';
import type { AdminAction } from '../src/admin-accounts.ts';
import type { AuthSession } from '../src/auth.ts';
import { checkOwnerAccount } from '../src/integration-wiring.ts';
import { integrationFixture } from './fixtures/integration.ts';
import { TestAuthenticator } from './authenticator.ts';

const origin = 'http://localhost:4173';
const code = (expected: string) => (error: {code?: string}) => error.code === expected;
interface Device { key: TestAuthenticator; session: () => AuthSession }

/** jd (admin, alex+blair) is the attacker; bryn is promoted to admin (alex) and is the owner account. */
async function fixture(ownerAccountId: string | undefined) {
    const store = new Store(':memory:');
    seedAccounts(store);
    store.run("UPDATE accounts SET role='admin' WHERE id='bryn'");
    let now = 1791691200;
    const auth = new Auth(store, origin, () => now);
    const setup = new AccountAdmin(auth), admin = new AccountAdmin(auth, ownerAccountId);
    const device = async (id: 'jd' | 'bryn'): Promise<Device> => {
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await auth.registrationOptions({token: issueBootstrap(store, id, now)}, browser);
        const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, session: () => auth.session(result.token, browser)};
    };
    const jd = await device('jd'), bryn = await device('bryn');
    const act = async (service: AccountAdmin, who: Device, action: AdminAction, target: string, params: Record<string, unknown> = {}) => {
        const options = await service.stepUpOptions(who.session(), {action, target, params});
        return service.perform(who.session(), action, target, {...params, stepUp: {challengeId: options.challengeId, response: who.key.login(options.options, origin)}});
    };
    const snapshot = () => JSON.stringify([store.all('SELECT id,role,active,permission_version FROM accounts ORDER BY id'), store.all('SELECT id,state FROM credentials ORDER BY id'),
        store.all('SELECT hash,consumed FROM bootstrap_tokens ORDER BY hash'), store.all('SELECT actor_id,action,outcome FROM audit ORDER BY rowid')]);
    return {store, auth, setup, admin, jd, bryn, act, snapshot, close: () => store.close()};
}
const ATTACKS: [AdminAction, Record<string, unknown>][] = [['token_issue', {label: 'x'}], ['account_role', {role: 'parent'}], ['account_active', {active: false}]];

test('owner mode: another admin cannot add a credential to, change the role of or deactivate the owner; no state changes', async () => {
    const f = await fixture('bryn');
    try {
        const before = f.snapshot();
        for (const [kind, params] of ATTACKS) await assert.rejects(f.act(f.admin, f.jd, kind, 'bryn', params), code('owner_account_protected'), kind);
        assert.equal(f.snapshot(), before);
    } finally { f.close(); }
});

test('owner mode: another admin cannot approve a pending passkey of the owner account', async () => {
    const f = await fixture('bryn');
    try {
        // The pending passkey exists (e.g. enrolled with a token issued before owner mode was switched on).
        const issued = await f.act(f.setup, f.jd, 'token_issue', 'bryn') as {token: string};
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await f.auth.registrationOptions({token: issued.token}, browser);
        await f.auth.enroll({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        const pending = f.store.get<{id: string}>("SELECT id FROM credentials WHERE state='pending'")!.id;
        const before = f.snapshot();
        await assert.rejects(f.act(f.admin, f.jd, 'passkey_approve', pending), code('owner_account_protected'));
        assert.equal(f.snapshot(), before);
        assert.equal(f.store.get<{state: string}>('SELECT state FROM credentials WHERE id=?', pending)!.state, 'pending');
    } finally { f.close(); }
});

test('owner mode: the owner may still manage their own credentials and account', async () => {
    const f = await fixture('bryn');
    try {
        const issued = await f.act(f.admin, f.bryn, 'token_issue', 'bryn', {label: 'phone'}) as {token: string};
        assert.ok(issued.token);
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await f.auth.registrationOptions({token: issued.token}, browser);
        await f.auth.enroll({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        const pending = f.store.get<{id: string}>("SELECT id FROM credentials WHERE state='pending'")!.id;
        await f.act(f.admin, f.bryn, 'passkey_approve', pending);
        await f.act(f.admin, f.bryn, 'account_role', 'bryn', {role: 'admin'});
    } finally { f.close(); }
});

test('owner mode: other accounts stay manageable by admins', async () => {
    const f = await fixture('jd');
    try {
        await f.act(f.admin, f.jd, 'token_issue', 'bryn', {label: 'x'});
        await f.act(f.admin, f.jd, 'account_role', 'bryn', {role: 'parent'});
        await f.act(f.admin, f.jd, 'account_active', 'bryn', {active: false});
    } finally { f.close(); }
});

test('without an owner account (other modes) admins keep managing every account', async () => {
    const f = await fixture(undefined);
    try {
        for (const [kind, params] of ATTACKS) await f.act(f.admin, f.jd, kind, 'bryn', params);
    } finally { f.close(); }
});

test('startup check: logs one fixed tag for an inactive or missing owner; silent when fine and outside owner mode', () => {
    const f = integrationFixture();
    try {
        const run = (config: Parameters<typeof checkOwnerAccount>[0]) => { const lines: string[] = []; checkOwnerAccount(config, f.store, line => lines.push(line)); return lines; };
        const owner = {...f.config, timeRequests: {mode: 'owner' as const}, ownerAccountId: 'parent'};
        assert.deepEqual(run(owner), []);
        assert.deepEqual(run({...f.config, timeRequests: {mode: 'parents' as const}, ownerAccountId: 'parent'}), []);
        assert.deepEqual(run(f.config), []);
        f.store.run("UPDATE accounts SET active=0 WHERE id='parent'");
        assert.deepEqual(run(owner), ['owner_account_unavailable\n']);
        assert.deepEqual(run({...f.config, timeRequests: {mode: 'parents' as const}, ownerAccountId: 'parent'}), []);
        f.store.run("UPDATE accounts SET active=1 WHERE id='parent'");
        f.store.run("DELETE FROM accounts WHERE id='parent'");
        assert.deepEqual(run(owner), ['owner_account_unavailable\n']);
    } finally { f.cleanup(); }
});
