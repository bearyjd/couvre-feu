import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { revokeAccountPasskeys } from '../src/integration-revoke.ts';
import { TestAuthenticator } from './authenticator.ts';

const origin = 'http://localhost:4273';
const code = (expected: string) => (error: {code?: string}) => error.code === expected;
const newBrowser = () => randomBytes(32).toString('base64url');

function setup() {
    const f = integrationFixture(), auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance});
    const n = (sql: string, ...args: string[]) => f.store.get<{n: number}>(sql, ...args)!.n;
    const enroll = async (accountId: string) => {
        const key = new TestAuthenticator(), browser = newBrowser(), options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, accountId, f.now())}, browser);
        const result = await auth.enroll({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, browser, result};
    };
    return {f, auth, n, enroll};
}

test('sole-admin recovery: revoking every passkey needs --allow-no-admin, fences sessions, is audited, and the next bootstrap is active', async () => {
    const {f, auth, n, enroll} = setup();
    try {
        const lost = await enroll('operator');
        assert.ok('token' in lost.result);
        const lostToken = lost.result.token;
        // A second device of the same admin, still pending, and an outstanding token are swept as well.
        const pending = await enroll('operator');
        assert.ok('pending' in pending.result);
        const outstanding = issueOperatorBootstrap(f.store, 'operator', f.now());
        f.store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES('operator_tablet','operator',?,0,'[]','pending')", new Uint8Array([1]));
        // Without the flag the only admin with a passkey is never stripped of it.
        assert.throws(() => revokeAccountPasskeys(f.store, 'operator', f.now(), false), code('last_admin_required'));
        assert.equal(n("SELECT count(*) n FROM credentials WHERE account_id='operator'"), 2);
        assert.equal(auth.session(lostToken, lost.browser).dto.actor.id, 'operator');
        assert.equal(revokeAccountPasskeys(f.store, 'operator', f.now(), true), 2);
        assert.equal(n("SELECT count(*) n FROM credentials WHERE account_id='operator'"), 0);
        assert.throws(() => auth.session(lostToken, lost.browser));
        assert.equal(n("SELECT count(*) n FROM sessions WHERE account_id='operator' AND revoked=0"), 0);
        await assert.rejects(auth.registrationOptions({token: outstanding}, newBrowser()), code('token_used_or_expired'));
        assert.equal(n("SELECT count(*) n FROM audit WHERE actor_id='operator' AND action='passkey_operator_revoke' AND outcome=?", `operator:${lost.key.credentialId.toString('base64url')}`), 1);
        assert.equal(n("SELECT count(*) n FROM audit WHERE actor_id='operator' AND action='account_passkeys_revoked' AND outcome='operator:2:allow_no_admin'"), 1);
        // The account now has no active passkey, so the next operator token enrolls an active first passkey.
        const recovered = await enroll('operator');
        assert.ok('token' in recovered.result && recovered.result.dto.actor.role === 'admin');
    } finally { f.cleanup(); }
});

test('revoking a parent or a second admin needs no flag; unknown accounts are refused', async () => {
    const {f, n, enroll} = setup();
    try {
        assert.throws(() => revokeAccountPasskeys(f.store, 'nobody', f.now(), false), code('unknown_private_account'));
        // No admin has a passkey yet: revoking cannot make that worse.
        assert.equal(revokeAccountPasskeys(f.store, 'parent', f.now(), false), 0);
        await enroll('operator');
        const parent = await enroll('parent');
        assert.ok('token' in parent.result);
        assert.equal(revokeAccountPasskeys(f.store, 'parent', f.now(), false), 1);
        assert.equal(n("SELECT count(*) n FROM sessions WHERE account_id='parent' AND revoked=0"), 0);
        f.store.run("UPDATE accounts SET role='admin' WHERE id='parent'");
        await enroll('parent');
        assert.equal(revokeAccountPasskeys(f.store, 'operator', f.now(), false), 1);
        assert.equal(n("SELECT count(*) n FROM credentials WHERE account_id='parent' AND state='active'"), 1);
    } finally { f.cleanup(); }
});
