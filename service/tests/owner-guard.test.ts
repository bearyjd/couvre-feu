import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Store } from '../src/db.ts';
import { seedAccounts } from '../src/fixtures.ts';
import { Auth, digest, issueBootstrap } from '../src/auth.ts';
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
    const device = async (id: string): Promise<Device> => {
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        // issueBootstrap knows only the fictional jd/bryn; carol gets the same first-enrollment token by direct insert.
        let token: string;
        if (id === 'carol') { token = randomBytes(32).toString('base64url'); store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at,first_enrollment) VALUES(?,?,?,1)', digest(token), id, now + 600); } else token = issueBootstrap(store, id, now);
        const options = await auth.registrationOptions({token}, browser);
        const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, session: () => auth.session(result.token, browser)};
    };
    // carol (admin, blair) is outside the scope of bryn (alex); ghost is a configured owner id with no account.
    store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('carol','Carol (fictional)','admin','[\"blair\"]',?)", randomBytes(32).toString('base64url'));
    const jd = await device('jd'), bryn = await device('bryn'), carol = await device('carol');
    const act = async (service: AccountAdmin, who: Device, action: AdminAction, target: string, params: Record<string, unknown> = {}) => {
        const options = await service.stepUpOptions(who.session(), {action, target, params});
        return service.perform(who.session(), action, target, {...params, stepUp: {challengeId: options.challengeId, response: who.key.login(options.options, origin)}});
    };
    const snapshot = () => JSON.stringify([store.all('SELECT id,role,active,permission_version FROM accounts ORDER BY id'), store.all('SELECT id,state FROM credentials ORDER BY id'), store.all('SELECT hash,revoked FROM sessions ORDER BY hash'),
        store.all('SELECT hash,consumed FROM bootstrap_tokens ORDER BY hash'), store.all('SELECT actor_id,action,outcome FROM audit ORDER BY rowid')]);
    return {store, auth, setup, admin, jd, bryn, carol, act, snapshot, close: () => store.close()};
}
const ATTACKS: [AdminAction, Record<string, unknown>][] = [['token_issue', {label: 'x'}], ['account_role', {role: 'parent'}], ['account_active', {active: false}]];
const credentialOf = (f: {store: Store}, account: string) => f.store.get<{id: string}>("SELECT id FROM credentials WHERE account_id=? AND state='active'", account)!.id;

test('owner mode: another admin cannot revoke a passkey of the owner account; the passkey stays active and no session is revoked', async () => {
    const f = await fixture('bryn');
    try {
        const credential = credentialOf(f, 'bryn'), before = f.snapshot();
        await assert.rejects(f.act(f.admin, f.jd, 'passkey_revoke', credential), code('owner_account_protected'));
        assert.equal(f.snapshot(), before);
        assert.equal(f.store.get<{state: string}>('SELECT state FROM credentials WHERE id=?', credential)!.state, 'active');
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM sessions WHERE revoked=1')!.n, 0);
    } finally { f.close(); }
});

const addCredential = (f: {store: Store}, id: string, account: string, state: 'active' | 'pending') =>
    f.store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES(?,?,?,0,'[]',?)", id, account, new Uint8Array([1]), state);

test('owner mode: the owner cannot revoke their last active passkey, by either route; they stay signed in and nothing is committed', async () => {
    for (const route of ['passkey_revoke', 'own_passkey_revoke'] as const) {
        const f = await fixture('bryn');
        try {
            const credential = credentialOf(f, 'bryn'), before = f.snapshot(), counters = () => JSON.stringify(f.store.all('SELECT id,counter,last_used_at FROM credentials ORDER BY id')), used = counters();
            await assert.rejects(f.act(f.admin, f.bryn, route, credential), code('owner_self_lockout'), route);
            assert.equal(f.snapshot(), before);
            // The step-up challenge itself is single-use at verify time (as for every refusal); the commit (counter bump) is rolled back.
            assert.equal(counters(), used);
            assert.equal(f.bryn.session().dto.actor.id, 'bryn');
        } finally { f.close(); }
    }
});

test('owner mode: the owner may revoke one of several active passkeys, or a pending one of their own, by either route', async () => {
    for (const route of ['passkey_revoke', 'own_passkey_revoke'] as const) {
        const f = await fixture('bryn');
        try {
            addCredential(f, 'bryn_second', 'bryn', 'active');
            addCredential(f, 'bryn_pending', 'bryn', 'pending');
            await f.act(f.admin, f.bryn, route, 'bryn_second');
            await f.act(f.admin, f.bryn, route, 'bryn_pending');
            assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM credentials WHERE account_id='bryn'")!.n, 1);
            await assert.rejects(f.act(f.admin, f.bryn, route, credentialOf(f, 'bryn')), code('owner_self_lockout'), route);
        } finally { f.close(); }
    }
});

test('owner mode: a pending passkey does not count as a remaining one; revoking the only active passkey is refused even beside a pending one', async () => {
    for (const route of ['passkey_revoke', 'own_passkey_revoke'] as const) {
        const f = await fixture('bryn');
        try {
            addCredential(f, 'bryn_pending', 'bryn', 'pending');
            const credential = credentialOf(f, 'bryn'), before = f.snapshot();
            await assert.rejects(f.act(f.admin, f.bryn, route, credential), code('owner_self_lockout'), route);
            assert.equal(f.snapshot(), before);
            assert.equal(f.store.get<{state: string}>('SELECT state FROM credentials WHERE id=?', credential)!.state, 'active');
        } finally { f.close(); }
    }
});

test('owner mode: with no active passkey, the owner may revoke a pending one (the rule guards active passkeys only)', async () => {
    // A step-up needs an active passkey, so no route can reach this state; exercise the rule through apply() directly.
    type Applier = {apply: (actor: AuthSession['dto']['actor'], kind: AdminAction, target: string, params: Record<string, unknown>) => unknown};
    for (const route of ['passkey_revoke', 'own_passkey_revoke'] as const) {
        const f = await fixture('bryn');
        try {
            const actor = f.bryn.session().dto.actor;
            f.store.run("DELETE FROM credentials WHERE id=?", credentialOf(f, 'bryn'));
            addCredential(f, 'bryn_pending', 'bryn', 'pending');
            (f.admin as unknown as Applier).apply(actor, route, 'bryn_pending', {});
            assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM credentials WHERE account_id='bryn'")!.n, 0, route);
        } finally { f.close(); }
    }
});

test('owner mode: other accounts may revoke their last passkey; without owner mode the owner may too', async () => {
    const f = await fixture('bryn');
    try {
        await f.act(f.admin, f.carol, 'own_passkey_revoke', credentialOf(f, 'carol'));
        await f.act(f.admin, f.jd, 'passkey_revoke', credentialOf(f, 'jd'));
    } finally { f.close(); }
    const g = await fixture(undefined);
    try { await g.act(g.admin, g.bryn, 'own_passkey_revoke', credentialOf(g, 'bryn')); } finally { g.close(); }
    const h = await fixture('jd');
    try { await h.act(h.admin, h.bryn, 'passkey_revoke', credentialOf(h, 'bryn')); } finally { h.close(); }
});

test('owner mode: an admin outside the owner scope gets the scope error, never owner_account_protected', async () => {
    const f = await fixture('bryn');
    try {
        const before = f.snapshot();
        const cases: [AdminAction, string, Record<string, unknown>][] = [['token_issue', 'bryn', {label: 'x'}], ['account_role', 'bryn', {role: 'parent'}], ['account_active', 'bryn', {active: false}], ['passkey_revoke', credentialOf(f, 'bryn'), {}]];
        for (const [kind, target, params] of cases) await assert.rejects(f.act(f.admin, f.carol, kind, target, params), code('outside_scope'), kind);
        const issued = await f.act(f.setup, f.jd, 'token_issue', 'bryn') as {token: string};
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await f.auth.registrationOptions({token: issued.token}, browser);
        await f.auth.enroll({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        await assert.rejects(f.act(f.admin, f.carol, 'passkey_approve', f.store.get<{id: string}>("SELECT id FROM credentials WHERE state='pending'")!.id), code('outside_scope'));
        assert.notEqual(f.snapshot(), before);
    } finally { f.close(); }
    const g = await fixture('ghost');
    try {
        await assert.rejects(g.act(g.admin, g.jd, 'token_issue', 'ghost', {label: 'x'}), code('account_not_found'));
    } finally { g.close(); }
});

test('owner mode: the owner cannot deactivate or demote their own account (409 owner_self_lockout); other changes stay allowed', async () => {
    const f = await fixture('bryn');
    try {
        const before = f.snapshot();
        await assert.rejects(f.act(f.admin, f.bryn, 'account_active', 'bryn', {active: false}), code('owner_self_lockout'));
        await assert.rejects(f.act(f.admin, f.bryn, 'account_role', 'bryn', {role: 'parent'}), code('owner_self_lockout'));
        assert.equal(f.snapshot(), before);
        await f.act(f.admin, f.bryn, 'account_active', 'bryn', {active: true});
    } finally { f.close(); }
    const g = await fixture(undefined);
    try { await g.act(g.admin, g.bryn, 'account_role', 'bryn', {role: 'parent'}); } finally { g.close(); }
});

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
        // Active but without any active passkey: nobody can sign in as the owner.
        assert.deepEqual(run(owner), ['owner_account_unavailable\n']);
        f.store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES('owner_pending','parent',?,0,'[]','pending')", new Uint8Array([1]));
        assert.deepEqual(run(owner), ['owner_account_unavailable\n']);
        f.store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES('owner_key','parent',?,0,'[]','active')", new Uint8Array([1]));
        assert.deepEqual(run(owner), []);
        assert.deepEqual(run({...f.config, timeRequests: {mode: 'parents' as const}, ownerAccountId: 'parent'}), []);
        assert.deepEqual(run(f.config), []);
        f.store.run("UPDATE accounts SET active=0 WHERE id='parent'");
        assert.deepEqual(run(owner), ['owner_account_unavailable\n']);
        assert.deepEqual(run({...f.config, timeRequests: {mode: 'parents' as const}, ownerAccountId: 'parent'}), []);
        f.store.run("UPDATE accounts SET active=1 WHERE id='parent'");
        f.store.run("DELETE FROM credentials WHERE account_id='parent'");
        f.store.run("DELETE FROM accounts WHERE id='parent'");
        assert.deepEqual(run(owner), ['owner_account_unavailable\n']);
    } finally { f.cleanup(); }
});
