import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Store } from '../src/db.ts';
import { seedAccounts } from '../src/fixtures.ts';
import { Auth, issueBootstrap, issueOperatorBootstrap, digest, pairingCode } from '../src/auth.ts';
import { integrationFixture } from './fixtures/integration.ts';
import type { AuthSession } from '../src/auth.ts';
import { AccountAdmin } from '../src/admin-accounts.ts';
import type { AdminAction } from '../src/admin-accounts.ts';
import { ACCOUNT_LIMIT, PASSKEYS_PER_ACCOUNT } from '../src/account-limits.ts';
import { TestAuthenticator } from './authenticator.ts';

const origin = 'http://localhost:4173';
const code = (expected: string) => (error: {code?: string}) => error.code === expected;
const newBrowser = () => randomBytes(32).toString('base64url');
interface Device { key: TestAuthenticator; browser: string; token: string; session: () => AuthSession }

function fixture() {
    const store = new Store(':memory:');
    seedAccounts(store);
    let now = 1791691200;
    const auth = new Auth(store, origin, () => now), admin = new AccountAdmin(auth);
    const count = (sql: string, ...args: string[]) => store.get<{n: number}>(sql, ...args)!.n;
    return {store, auth, admin, count, now: () => now, advance: (seconds: number) => { now += seconds; }, close: () => store.close()};
}
type F = ReturnType<typeof fixture>;
/** Operator CLI path: an active passkey and a session. */
async function bootstrap(f: F, id: 'jd' | 'bryn'): Promise<Device> {
    const key = new TestAuthenticator(), browser = newBrowser();
    const options = await f.auth.registrationOptions({token: issueBootstrap(f.store, id, f.now())}, browser);
    const result = await f.auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
    return {key, browser, token: result.token, session: () => f.auth.session(result.token, browser)};
}
async function login(f: F, key: TestAuthenticator, browser = newBrowser()): Promise<Device> {
    const options = await f.auth.loginOptions({}, browser);
    const result = await f.auth.loginVerify({challengeId: options.challengeId, response: key.login(options.options, origin)}, browser);
    return {key, browser, token: result.token, session: () => f.auth.session(result.token, browser)};
}
async function stepUp(f: F, who: Device, action: AdminAction, target: string, params: Record<string, unknown> = {}) {
    const options = await f.admin.stepUpOptions(who.session(), {action, target, params});
    return {challengeId: options.challengeId, response: who.key.login(options.options, origin)};
}
async function act(f: F, who: Device, action: AdminAction, target: string, params: Record<string, unknown> = {}) {
    return f.admin.perform(who.session(), action, target, {...params, stepUp: await stepUp(f, who, action, target, params)});
}
/** Admin UI path: a pending passkey that needs approval. */
async function addDevice(f: F, token: string, key = new TestAuthenticator(), browser = newBrowser()) {
    const options = await f.auth.registrationOptions({token}, browser);
    const result = await f.auth.enroll({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
    return {key, browser, options, result};
}

test('admin creates an account, issues a one-use add-device token; the passkey stays pending until approved with a matching pairing code', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        const created = await act(f, jd, 'account_create', '', {displayName: 'Casey (fictional)', role: 'parent', personIds: ['alex']}) as {account: {id: string}};
        assert.match(created.account.id, /^[a-z][a-z0-9_]{0,31}$/);
        const issued = await act(f, jd, 'token_issue', created.account.id, {label: 'Casey phone'}) as {token: string; expiresAt: number};
        assert.equal(issued.expiresAt, f.now() + 600);
        assert.equal(f.count('SELECT count(*) n FROM bootstrap_tokens WHERE hash=?', digest(issued.token)), 1);
        assert.equal(f.count('SELECT count(*) n FROM bootstrap_tokens WHERE hash=?', issued.token), 0);
        const device = await addDevice(f, issued.token);
        assert.ok('pending' in device.result);
        const pending = (device.result as {pending: {pairingCode: string; credentialId: string}}).pending;
        assert.match(pending.pairingCode, /^[A-Z2-7]{6}$/);
        assert.equal(pending.pairingCode, pairingCode(device.key.credentialId.toString('base64url')));
        assert.equal(f.count("SELECT count(*) n FROM sessions WHERE account_id=?", created.account.id), 0);
        await assert.rejects(login(f, device.key), /credential_not_bound/);
        // A pending passkey is not even offered to sign-in challenges.
        const offered = await f.auth.loginOptions({}, newBrowser());
        assert.ok(!Object.hasOwn(JSON.parse(f.store.get<{credential_ids: string}>('SELECT credential_ids FROM challenges WHERE id=?', offered.challengeId)!.credential_ids), pending.credentialId));
        // One use: the token cannot enroll a second device.
        await assert.rejects(f.auth.registrationOptions({token: issued.token}, newBrowser()), code('token_used_or_expired'));
        const listed = f.admin.list(jd.session().dto.actor).accounts.find(a => a.id === created.account.id)!;
        assert.deepEqual(listed.passkeys.map(p => [p.state, p.pairingCode, p.label]), [['pending', pending.pairingCode, 'Casey phone']]);
        await act(f, jd, 'passkey_approve', pending.credentialId);
        const casey = await login(f, device.key);
        assert.equal(casey.session().dto.actor.id, created.account.id);
        assert.deepEqual(casey.session().dto.actor.personIds, ['alex']);
        assert.equal(casey.session().credentialId, pending.credentialId);
        assert.equal(f.store.get<{credential_id: string}>('SELECT credential_id FROM sessions WHERE hash=?', digest(casey.token))!.credential_id, pending.credentialId);
        assert.ok(f.store.get<{last_used_at: number}>('SELECT last_used_at FROM credentials WHERE id=?', pending.credentialId)!.last_used_at);
        const actions = f.store.all<{action: string}>("SELECT action FROM audit WHERE actor_id='jd' AND action LIKE 'admin_%'").map(r => r.action);
        assert.deepEqual(actions, ['admin_account_create', 'admin_token_issue', 'admin_passkey_approve']);
    } finally { f.close(); }
});

test('a second passkey for the same account excludes the first, and either passkey signs in independently', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        const issued = await act(f, jd, 'token_issue', 'jd', {label: 'Tablet'}) as {token: string};
        const device = await addDevice(f, issued.token);
        assert.deepEqual(device.options.options.excludeCredentials?.map(c => c.id), [jd.key.credentialId.toString('base64url')]);
        const pending = (device.result as {pending: {credentialId: string}}).pending;
        await act(f, jd, 'passkey_approve', pending.credentialId);
        assert.equal(f.count("SELECT count(*) n FROM credentials WHERE account_id='jd' AND state='active'"), 2);
        const tablet = await login(f, device.key), phone = await login(f, jd.key);
        assert.equal(tablet.session().dto.actor.id, 'jd');
        assert.equal(phone.session().dto.actor.id, 'jd');
        assert.notEqual(tablet.session().credentialId, phone.session().credentialId);
        // Revoking one passkey ends only the sessions it created.
        await act(f, phone, 'passkey_revoke', pending.credentialId);
        assert.throws(() => tablet.session(), /session_expired|credential_revoked/);
        assert.equal(phone.session().dto.actor.id, 'jd');
        assert.equal(jd.session().dto.actor.id, 'jd');
        await assert.rejects(login(f, device.key), /credential_not_bound/);
        assert.equal(f.count('SELECT count(*) n FROM credentials WHERE id=?', pending.credentialId), 0);
    } finally { f.close(); }
});

test('every admin change needs a fresh step-up bound to its session, action, target and parameters; replay and expiry fail', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd'), other = await login(f, jd.key);
        const params = {displayName: 'Dana (fictional)', role: 'parent', personIds: ['alex']};
        await assert.rejects(f.admin.perform(other.session(), 'account_create', '', params), (e: {status: number; code: string}) => e.status === 403 && e.code === 'step_up_required');
        const wrongParams = await stepUp(f, other, 'account_create', '', {...params, role: 'admin'});
        await assert.rejects(f.admin.perform(other.session(), 'account_create', '', {...params, stepUp: wrongParams}), (e: {status: number; code: string}) => e.status === 403 && e.code === 'step_up_mismatch');
        const wrongAction = await stepUp(f, other, 'token_issue', 'bryn', {label: ''});
        await assert.rejects(f.admin.perform(other.session(), 'account_active', 'bryn', {active: false, stepUp: wrongAction}), /step_up_mismatch/);
        const wrongTarget = await stepUp(f, other, 'token_issue', 'bryn', {label: ''});
        await assert.rejects(f.admin.perform(other.session(), 'token_issue', 'jd', {label: '', stepUp: wrongTarget}), /step_up_mismatch/);
        // A step-up made in one session cannot authorize another session of the same admin.
        const otherSession = await stepUp(f, jd, 'token_issue', 'bryn', {label: ''});
        await assert.rejects(f.admin.perform(other.session(), 'token_issue', 'bryn', {label: '', stepUp: otherSession}), /step_up_mismatch/);
        const good = await stepUp(f, other, 'token_issue', 'bryn', {label: ''});
        await f.admin.perform(other.session(), 'token_issue', 'bryn', {label: '', stepUp: good});
        await assert.rejects(f.admin.perform(other.session(), 'token_issue', 'bryn', {label: '', stepUp: good}), (e: {status: number; code: string}) => e.status === 401 && e.code === 'invalid_challenge');
        const late = await stepUp(f, other, 'token_issue', 'bryn', {label: ''});
        f.advance(121);
        await assert.rejects(f.admin.perform(other.session(), 'token_issue', 'bryn', {label: '', stepUp: late}), /invalid_challenge/);
        // A signature from a passkey of another account is refused.
        const bryn = await bootstrap(f, 'bryn');
        const foreign = await f.admin.stepUpOptions(other.session(), {action: 'token_issue', target: 'bryn', params: {label: ''}});
        await assert.rejects(f.admin.perform(other.session(), 'token_issue', 'bryn', {label: '', stepUp: {challengeId: foreign.challengeId, response: bryn.key.login(foreign.options, origin)}}), /credential_not_bound|credential_account_mismatch/);
        assert.equal(f.count("SELECT count(*) n FROM audit WHERE action='admin_token_issue'"), 1);
    } finally { f.close(); }
});

test('non-admin accounts cannot list, step up for, or perform admin changes, but can manage their own passkeys', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd'), bryn = await bootstrap(f, 'bryn');
        assert.throws(() => f.admin.list(bryn.session().dto.actor), /admin_required/);
        await assert.rejects(f.admin.stepUpOptions(bryn.session(), {action: 'account_create', target: '', params: {displayName: 'X', role: 'admin', personIds: ['alex']}}), /admin_required/);
        await assert.rejects(f.admin.perform(bryn.session(), 'token_issue', 'bryn', {label: ''}), /admin_required/);
        const own = f.admin.mine(bryn.session());
        assert.equal(own.passkeys.length, 1);
        assert.equal(own.passkeys[0].current, true);
        // Another account's passkey is invisible to self-service.
        const jdCredential = jd.key.credentialId.toString('base64url');
        await assert.rejects(act(f, bryn, 'own_passkey_revoke', jdCredential), /passkey_not_found/);
        // Admins also cannot grant people outside their own scope.
        await assert.rejects(act(f, jd, 'account_create', '', {displayName: 'Eve', role: 'parent', personIds: ['nobody']}), /invalid_person_scope/);
        await act(f, bryn, 'own_passkey_revoke', bryn.key.credentialId.toString('base64url'));
        assert.throws(() => bryn.session(), /session_expired|credential_revoked/);
        assert.equal(jd.session().dto.actor.id, 'jd');
    } finally { f.close(); }
});

test('disabling an account ends all its sessions; the last admin with a passkey cannot be removed, demoted or disabled', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd'), bryn = await bootstrap(f, 'bryn'), brynElsewhere = await login(f, bryn.key);
        const jdCredential = jd.key.credentialId.toString('base64url');
        await assert.rejects(act(f, jd, 'own_passkey_revoke', jdCredential), (e: {status: number; code: string}) => e.status === 409 && e.code === 'last_admin_required');
        await assert.rejects(act(f, jd, 'passkey_revoke', jdCredential), code('last_admin_required'));
        await assert.rejects(act(f, jd, 'account_role', 'jd', {role: 'parent'}), code('last_admin_required'));
        await assert.rejects(act(f, jd, 'account_active', 'jd', {active: false}), code('last_admin_required'));
        assert.equal(jd.session().dto.actor.role, 'admin');
        await act(f, jd, 'account_active', 'bryn', {active: false});
        assert.throws(() => bryn.session(), /account_disabled|permissions_changed/);
        assert.throws(() => brynElsewhere.session(), /account_disabled|permissions_changed/);
        await assert.rejects(login(f, bryn.key), /credential_not_bound/);
        await act(f, jd, 'account_active', 'bryn', {active: true});
        await act(f, jd, 'account_role', 'bryn', {role: 'admin'});
        const brynAdmin = await login(f, bryn.key);
        assert.equal(brynAdmin.session().dto.actor.role, 'admin');
        // Another admin with a passkey now exists, so jd may step down.
        await act(f, jd, 'account_role', 'jd', {role: 'parent'});
        assert.throws(() => jd.session(), /permissions_changed/);
        assert.equal(f.count("SELECT count(*) n FROM audit WHERE action IN ('admin_account_active','admin_account_role')"), 4);
    } finally { f.close(); }
});

test('add-device tokens: reissue consumes the old one, expiry after ten minutes, two racing browsers bind exactly one passkey', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        const first = await act(f, jd, 'token_issue', 'bryn', {label: ''}) as {token: string};
        const second = await act(f, jd, 'token_issue', 'bryn', {label: ''}) as {token: string};
        await assert.rejects(f.auth.registrationOptions({token: first.token}, newBrowser()), code('token_used_or_expired'));
        const keyA = new TestAuthenticator(), keyB = new TestAuthenticator();
        const browserA = newBrowser(), browserB = newBrowser();
        const optionsA = await f.auth.registrationOptions({token: second.token}, browserA), optionsB = await f.auth.registrationOptions({token: second.token}, browserB);
        const races = await Promise.allSettled([
            f.auth.enroll({challengeId: optionsA.challengeId, response: keyA.register(optionsA.options, origin)}, browserA),
            f.auth.enroll({challengeId: optionsB.challengeId, response: keyB.register(optionsB.options, origin)}, browserB),
        ]);
        assert.equal(races.filter(r => r.status === 'fulfilled').length, 1);
        assert.equal(f.count("SELECT count(*) n FROM credentials WHERE account_id='bryn'"), 1);
        const expiring = await act(f, jd, 'token_issue', 'bryn', {label: ''}) as {token: string};
        f.advance(601);
        await assert.rejects(f.auth.registrationOptions({token: expiring.token}, newBrowser()), code('token_used_or_expired'));
    } finally { f.close(); }
});

test('defensive account and passkey limits are generous constants enforced at the boundary', async () => {
    assert.ok(ACCOUNT_LIMIT >= 256 && PASSKEYS_PER_ACCOUNT >= 32);
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        const existing = f.count('SELECT count(*) n FROM accounts');
        for (let i = existing; i < ACCOUNT_LIMIT - 1; i++) f.store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES(?,?,'parent','[\"alex\"]',?)", `filler_${i}`, `Filler ${i}`, randomBytes(32).toString('base64url'));
        await act(f, jd, 'account_create', '', {displayName: 'Last', role: 'parent', personIds: ['alex']});
        await assert.rejects(act(f, jd, 'account_create', '', {displayName: 'One too many', role: 'parent', personIds: ['alex']}), (e: {status: number; code: string}) => e.status === 409 && e.code === 'account_limit_reached');
        for (let i = 1; i < PASSKEYS_PER_ACCOUNT - 1; i++) f.store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES(?,'jd',?,0,'[]','active')", `filler_${i}`, new Uint8Array([1]));
        const last = await act(f, jd, 'token_issue', 'jd', {label: ''}) as {token: string};
        const lastDevice = await addDevice(f, last.token);
        assert.equal(f.count("SELECT count(*) n FROM credentials WHERE account_id='jd'"), PASSKEYS_PER_ACCOUNT);
        // A pending passkey would be rejected by the next token; an approved one counts against the limit.
        await act(f, jd, 'passkey_approve', (lastDevice.result as {pending: {credentialId: string}}).pending.credentialId);
        await assert.rejects(act(f, jd, 'token_issue', 'jd', {label: ''}), code('passkey_limit_reached'));
    } finally { f.close(); }
});

test('reissuing a token first rejects pending passkeys, then counts against the passkey limit', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        for (let i = 1; i < PASSKEYS_PER_ACCOUNT; i++) f.store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES(?,'jd',?,0,'[]','pending')", `filler_${i}`, new Uint8Array([1]));
        assert.equal(f.count("SELECT count(*) n FROM credentials WHERE account_id='jd'"), PASSKEYS_PER_ACCOUNT);
        await act(f, jd, 'token_issue', 'jd', {label: ''});
        assert.equal(f.count("SELECT count(*) n FROM credentials WHERE account_id='jd'"), 1);
        for (let i = 1; i < PASSKEYS_PER_ACCOUNT; i++) f.store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES(?,'jd',?,0,'[]','pending')", `filler_${i}`, new Uint8Array([1]));
        issueOperatorBootstrap(f.store, 'jd', f.now());
        assert.equal(f.count("SELECT count(*) n FROM credentials WHERE account_id='jd'"), 1);
    } finally { f.close(); }
});

test('operator CLI bootstrap: the first passkey of an account is active; once it has an active passkey, an operator token only yields a pending one', async () => {
    const f = integrationFixture(), intOrigin = 'http://localhost:4273';
    try {
        const auth = new Auth(f.store, intOrigin, f.now, {provenance: f.config.provenance});
        const enrollWith = async (accountId: string) => {
            const browser = newBrowser(), options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, accountId, f.now())}, browser);
            return auth.enroll({challengeId: options.challengeId, response: new TestAuthenticator().register(options.options, intOrigin)}, browser);
        };
        assert.throws(() => issueOperatorBootstrap(f.store, 'nobody', f.now()), /unknown_private_account/);
        // The manifest's only admin, not yet enrolled, can always bootstrap: there is no lockout path.
        const admin = await enrollWith('operator');
        assert.ok('token' in admin && admin.dto.actor.id === 'operator' && admin.dto.actor.role === 'admin');
        // An account created through the admin UI exists only in the database, never in the manifest.
        f.store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('parent_db','DB parent','parent','[\"pilot\"]','u_db')");
        const first = await enrollWith('parent_db');
        assert.ok('token' in first && first.dto.actor.id === 'parent_db');
        // A token seen on the cleartext proxy hop must not take over an enrolled account: the new passkey waits for approval.
        const later = await enrollWith('parent_db');
        assert.ok('pending' in later);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM credentials WHERE account_id='parent_db' AND state='active'")!.n, 1);
        assert.equal(f.store.get<{state: string}>('SELECT state FROM credentials WHERE id=?', later.pending.credentialId)!.state, 'pending');
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM sessions WHERE account_id='parent_db'")!.n, 1);
        const offered = await auth.loginOptions({}, newBrowser());
        assert.ok(!Object.hasOwn(JSON.parse(f.store.get<{credential_ids: string}>('SELECT credential_ids FROM challenges WHERE id=?', offered.challengeId)!.credential_ids), later.pending.credentialId));
        f.store.run("UPDATE accounts SET active=0 WHERE id='parent_db'");
        assert.throws(() => issueOperatorBootstrap(f.store, 'parent_db', f.now()), /unknown_private_account/);
    } finally { f.cleanup(); }
});

test('operator token: the active-passkey check runs at enrollment, and two racing browsers bind exactly one active passkey', async () => {
    const f = fixture();
    try {
        // Issued while bryn had no passkey; an active passkey appears before the token is used.
        const browser = newBrowser(), options = await f.auth.registrationOptions({token: issueOperatorBootstrap(f.store, 'bryn', f.now())}, browser);
        f.store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES('bryn_phone','bryn',?,0,'[]','active')", new Uint8Array([1]));
        const late = await f.auth.enroll({challengeId: options.challengeId, response: new TestAuthenticator().register(options.options, origin)}, browser);
        assert.ok('pending' in late);
        // Unenrolled account, one operator token, two browsers: one active passkey, the other gets a clear refusal.
        const token = issueOperatorBootstrap(f.store, 'jd', f.now());
        const keyA = new TestAuthenticator(), keyB = new TestAuthenticator(), browserA = newBrowser(), browserB = newBrowser();
        const optionsA = await f.auth.registrationOptions({token}, browserA), optionsB = await f.auth.registrationOptions({token}, browserB);
        const races = await Promise.allSettled([
            f.auth.enroll({challengeId: optionsA.challengeId, response: keyA.register(optionsA.options, origin)}, browserA),
            f.auth.enroll({challengeId: optionsB.challengeId, response: keyB.register(optionsB.options, origin)}, browserB),
        ]);
        const won = races.filter(r => r.status === 'fulfilled') as PromiseFulfilledResult<unknown>[], lost = races.filter(r => r.status === 'rejected') as PromiseRejectedResult[];
        assert.equal(won.length, 1);
        assert.ok(won[0].value && typeof won[0].value === 'object' && 'token' in won[0].value);
        assert.equal(lost[0].reason.code, 'token_used_or_expired');
        assert.deepEqual(f.store.all<{state: string}>("SELECT state FROM credentials WHERE account_id='jd'").map(r => r.state), ['active']);
    } finally { f.close(); }
});

test('a stale operator token issued for an enrolled account never yields an active passkey, even after that passkey is removed', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        await act(f, jd, 'account_role', 'bryn', {role: 'admin'});
        const bryn = await bootstrap(f, 'bryn');
        // Issued while bryn is enrolled: not a first enrollment, recorded at issuance.
        const stale = issueOperatorBootstrap(f.store, 'bryn', f.now());
        assert.equal(f.store.get<{first_enrollment: number}>('SELECT first_enrollment FROM bootstrap_tokens WHERE hash=?', digest(stale))!.first_enrollment, 0);
        const options = await f.auth.registrationOptions({token: stale}, newBrowser());
        assert.ok(options.challengeId);
        // Removing a passkey voids the account's outstanding tokens.
        await act(f, bryn, 'own_passkey_revoke', bryn.key.credentialId.toString('base64url'));
        await assert.rejects(f.auth.registrationOptions({token: stale}, newBrowser()), code('token_used_or_expired'));
        // Even if the token survived the removal (belt and braces), its passkey stays pending.
        const survived = issueOperatorBootstrap(f.store, 'jd', f.now());
        f.store.run("UPDATE bootstrap_tokens SET account_id='bryn',first_enrollment=0 WHERE hash=?", digest(survived));
        assert.equal(f.count("SELECT count(*) n FROM credentials WHERE account_id='bryn' AND state='active'"), 0);
        const device = await addDevice(f, survived);
        assert.ok('pending' in device.result);
        assert.equal(f.count("SELECT count(*) n FROM sessions WHERE account_id='bryn' AND revoked=0"), 0);
        // An admin's passkey_revoke voids outstanding tokens too.
        const deviceId = (device.result as {pending: {credentialId: string}}).pending.credentialId;
        await act(f, jd, 'passkey_approve', deviceId);
        const other = issueOperatorBootstrap(f.store, 'bryn', f.now());
        await act(f, jd, 'passkey_revoke', deviceId);
        await assert.rejects(f.auth.registrationOptions({token: other}, newBrowser()), code('token_used_or_expired'));
        // A fresh operator token for the now unenrolled account is a first enrollment again.
        const fresh = issueOperatorBootstrap(f.store, 'bryn', f.now());
        assert.equal(f.store.get<{first_enrollment: number}>('SELECT first_enrollment FROM bootstrap_tokens WHERE hash=?', digest(fresh))!.first_enrollment, 1);
        assert.ok('token' in (await addDevice(f, fresh)).result);
    } finally { f.close(); }
});

test('a new add-device or operator token rejects the account\'s pending passkeys, and the rejection is audited', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        const before = await addDevice(f, (await act(f, jd, 'token_issue', 'bryn', {label: 'Unknown'}) as {token: string}).token);
        const stale = (before.result as {pending: {credentialId: string}}).pending.credentialId;
        await act(f, jd, 'token_issue', 'bryn', {label: 'Bryn phone'});
        assert.equal(f.count('SELECT count(*) n FROM credentials WHERE id=?', stale), 0);
        assert.deepEqual(f.store.all<{actor_id: string; outcome: string}>("SELECT actor_id,outcome FROM audit WHERE action='passkey_pending_rejected'").map(r => ({...r})), [{actor_id: 'jd', outcome: `bryn:${stale}`}]);
        const listed = f.admin.list(jd.session().dto.actor).accounts.find(a => a.id === 'bryn')!;
        assert.deepEqual(listed.passkeys, []);
        const again = await addDevice(f, (await act(f, jd, 'token_issue', 'bryn', {label: ''}) as {token: string}).token);
        const pending = (again.result as {pending: {credentialId: string}}).pending.credentialId;
        assert.equal(f.admin.list(jd.session().dto.actor).accounts.find(a => a.id === 'bryn')!.passkeys[0].createdAt, f.now());
        issueOperatorBootstrap(f.store, 'bryn', f.now());
        assert.equal(f.count('SELECT count(*) n FROM credentials WHERE id=?', pending), 0);
        assert.equal(f.count("SELECT count(*) n FROM audit WHERE action='passkey_pending_rejected' AND actor_id='operator' AND outcome=?", `bryn:${pending}`), 1);
        // Active passkeys are never touched by a reissue.
        await act(f, jd, 'token_issue', 'jd', {label: ''});
        assert.equal(f.count("SELECT count(*) n FROM credentials WHERE account_id='jd' AND state='active'"), 1);
    } finally { f.close(); }
});

test('an unknown, used, expired or replaced token gets one non-revealing refusal that tells the user to check pending devices', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        const used = code('token_used_or_expired');
        const message = (e: {code?: string; message?: string}) => used(e) && /already been used/.test(e.message ?? '') && /approve/.test(e.message ?? '');
        await assert.rejects(f.auth.registrationOptions({token: newBrowser()}, newBrowser()), message);
        const issued = await act(f, jd, 'token_issue', 'bryn', {label: ''}) as {token: string};
        await addDevice(f, issued.token);
        await assert.rejects(f.auth.registrationOptions({token: issued.token}, newBrowser()), message);
        const expiring = await act(f, jd, 'token_issue', 'bryn', {label: ''}) as {token: string};
        f.advance(601);
        await assert.rejects(f.auth.registrationOptions({token: expiring.token}, newBrowser()), message);
        // Replaced between options and verify: refused at enrollment with the same code.
        const replaced = await act(f, jd, 'token_issue', 'bryn', {label: ''}) as {token: string}, browser = newBrowser();
        const options = await f.auth.registrationOptions({token: replaced.token}, browser);
        await act(f, jd, 'token_issue', 'bryn', {label: ''});
        await assert.rejects(f.auth.enroll({challengeId: options.challengeId, response: new TestAuthenticator().register(options.options, origin)}, browser), message);
    } finally { f.close(); }
});

test('step-up has its own per-account limiter, so one account cannot exhaust sign-in for everyone', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd'), bryn = await bootstrap(f, 'bryn');
        const own = {action: 'own_passkey_revoke' as const, target: bryn.key.credentialId.toString('base64url'), params: {}};
        for (let i = 0; i < 10; i++) await f.admin.stepUpOptions(bryn.session(), own);
        await assert.rejects(f.admin.stepUpOptions(bryn.session(), own), (e: {status: number; code: string}) => e.status === 429 && e.code === 'step_up_rate_limited');
        await f.auth.loginOptions({}, newBrowser());
        await f.admin.stepUpOptions(jd.session(), {action: 'account_active', target: 'bryn', params: {active: false}});
        f.advance(61);
        await f.admin.stepUpOptions(bryn.session(), own);
    } finally { f.close(); }
});

test('an admin can act only on accounts whose people are all inside the admin scope', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        await act(f, jd, 'account_role', 'bryn', {role: 'admin'});
        const bryn = await bootstrap(f, 'bryn');
        // bryn is an admin for alex only; jd also covers blair.
        assert.deepEqual(f.admin.list(bryn.session().dto.actor).accounts.map(a => a.id), ['bryn']);
        for (const [kind, params] of [['token_issue', {label: ''}], ['account_role', {role: 'parent'}], ['account_active', {active: false}]] as const) {
            await assert.rejects(act(f, bryn, kind, 'jd', params), code('outside_scope'));
        }
        await assert.rejects(act(f, bryn, 'passkey_revoke', jd.key.credentialId.toString('base64url')), code('outside_scope'));
        // A pending passkey of an account outside bryn's scope cannot be approved by bryn.
        const tablet = await addDevice(f, (await act(f, jd, 'token_issue', 'jd', {label: 'Tablet'}) as {token: string}).token);
        const pending = (tablet.result as {pending: {credentialId: string}}).pending.credentialId;
        await assert.rejects(act(f, bryn, 'passkey_approve', pending), code('outside_scope'));
        assert.equal(f.store.get<{state: string}>('SELECT state FROM credentials WHERE id=?', pending)!.state, 'pending');
        assert.equal(jd.session().dto.actor.role, 'admin');
    } finally { f.close(); }
});

test('an empty person scope is refused at creation and never covered by any admin scope', async () => {
    const f = fixture();
    try {
        const jd = await bootstrap(f, 'jd');
        await assert.rejects(act(f, jd, 'account_create', '', {displayName: 'Nobody', role: 'parent', personIds: []}), code('invalid_person_scope'));
        f.store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('scopeless','Scopeless','parent','[]','u_scopeless')");
        assert.ok(!f.admin.list(jd.session().dto.actor).accounts.some(a => a.id === 'scopeless'));
        for (const [kind, params] of [['token_issue', {label: ''}], ['account_role', {role: 'admin'}], ['account_active', {active: false}]] as const) {
            await assert.rejects(act(f, jd, kind, 'scopeless', params), code('outside_scope'));
        }
    } finally { f.close(); }
});
