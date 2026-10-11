import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { seedAccounts } from '../src/fixtures.ts';
import { Auth, issueBootstrap, digest } from '../src/auth.ts';
import { TestAuthenticator } from './authenticator.ts';
const origin = 'http://localhost:4173', browser = randomBytes(32).toString('base64url');
function fixture() {
    const store = new Store(':memory:');
    seedAccounts(store);
    let now = 1791691200;
    const auth = new Auth(store, origin, () => now);
    return {
        store, auth, now: () => now, advance: (seconds: number) => {
            now += seconds;
        }, close: () => store.close()
    };
}
test('genuine signed passkey enrollment/login binds seeded account; rotates and revokes sessions', async () => {
    const f = fixture();
    try {
        const token = issueBootstrap(f.store, 'bryn', f.now()), options = await f.auth.registrationOptions({
            token
        }, browser), key = new TestAuthenticator();
        const enrolled = await f.auth.registrationVerify({
            challengeId: options.challengeId, response: key.register(options.options, origin)
        }, browser);
        assert.equal(enrolled.dto.actor.role, 'parent');
        assert.deepEqual(enrolled.dto.actor.personIds, ['alex']);
        assert.equal(enrolled.dto.actor.permissionVersion, '1');
        const login = await f.auth.loginOptions({}, browser), signed = key.login(login.options, origin);
        const session = await f.auth.loginVerify({
            challengeId: login.challengeId, response: signed
        }, browser, enrolled.token);
        assert.equal(session.dto.actor.id, 'bryn');
        assert.throws(() => f.auth.session(enrolled.token, browser), /session_expired/);
        await assert.rejects(f.auth.loginVerify({
            challengeId: login.challengeId, response: signed
        }, browser), /invalid_challenge/);
        const different = await f.auth.loginOptions({}, browser);
        await assert.rejects(f.auth.loginVerify({
            challengeId: different.challengeId, response: signed
        }, browser), /passkey_verification_failed/);
        f.auth.logout(f.auth.session(session.token, browser));
        assert.throws(() => f.auth.session(session.token, browser), /session_expired/);
        assert.equal(f.store.get<{
            n: number;
        }>('SELECT count(*) n FROM credentials')!.n, 1);
    }
    finally {
        f.close();
    }
});
for (const [name, change] of [
    ['wrong origin', {
            origin: 'https://evil.example'
        }], ['wrong RP ID', {
            rpID: 'evil.example'
        }], ['missing UV', {
            uv: false
        }], ['wrong challenge', {
            challenge: 'bogus_challenge'
        }],
] as const) {
    test(`registration rejects ${name} and consumes challenge`, async () => {
        const f = fixture();
        try {
            const options = await f.auth.registrationOptions({
                token: issueBootstrap(f.store, 'jd', f.now())
            }, browser), key = new TestAuthenticator(), response = key.register(options.options, 'origin' in change ? change.origin : origin, 'origin' in change ? {} : change);
            await assert.rejects(f.auth.registrationVerify({
                challengeId: options.challengeId, response
            }, browser), /passkey_verification_failed/);
            await assert.rejects(f.auth.registrationVerify({
                challengeId: options.challengeId, response: key.register(options.options, origin)
            }, browser), /invalid_challenge/);
            assert.equal(f.store.get<{
                n: number;
            }>('SELECT count(*) n FROM sessions')!.n, 0);
        }
        finally {
            f.close();
        }
    });
}
test('bootstrap cannot select account/role/people; challenge browser and expiration bindings', async () => {
    const f = fixture();
    try {
        const token = issueBootstrap(f.store, 'bryn', f.now());
        for (const field of ['account', 'role', 'personIds']) {
            await assert.rejects(f.auth.registrationOptions({
                token, [field]: 'jd'
            }, browser), /invalid_fields/);
        }
        const options = await f.auth.registrationOptions({
            token
        }, browser), key = new TestAuthenticator(), response = key.register(options.options, origin);
        await assert.rejects(f.auth.registrationVerify({
            challengeId: options.challengeId, response
        }, randomBytes(32).toString('base64url')), /invalid_challenge/);
        f.advance(121);
        await assert.rejects(f.auth.registrationVerify({
            challengeId: options.challengeId, response
        }, browser), /invalid_challenge/);
        f.advance(480);
        await assert.rejects(f.auth.registrationOptions({
            token
        }, browser), /invalid_bootstrap/);
    }
    finally {
        f.close();
    }
});
test('simultaneous enrollment challenges allow one credential; reissue invalidates old challenge', async () => {
    const f = fixture();
    try {
        const token = issueBootstrap(f.store, 'jd', f.now()), first = await f.auth.registrationOptions({
            token
        }, browser), second = await f.auth.registrationOptions({
            token
        }, browser), a = new TestAuthenticator(), b = new TestAuthenticator();
        await f.auth.registrationVerify({
            challengeId: first.challengeId, response: a.register(first.options, origin)
        }, browser);
        await assert.rejects(f.auth.registrationVerify({
            challengeId: second.challengeId, response: b.register(second.options, origin)
        }, browser), /invalid_challenge/);
        assert.throws(() => issueBootstrap(f.store, 'jd', f.now()), /account_already_enrolled/);
        const old = issueBootstrap(f.store, 'bryn', f.now()), pending = await f.auth.registrationOptions({
            token: old
        }, browser);
        issueBootstrap(f.store, 'bryn', f.now());
        await assert.rejects(f.auth.registrationVerify({
            challengeId: pending.challengeId, response: b.register(pending.options, origin)
        }, browser), /invalid_bootstrap/);
    }
    finally {
        f.close();
    }
});
test('cross-account user handle, permission epoch changes, expiry, and missing CSRF reject', async () => {
    const f = fixture();
    try {
        const options = await f.auth.registrationOptions({
            token: issueBootstrap(f.store, 'bryn', f.now())
        }, browser), key = new TestAuthenticator();
        const enrolled = await f.auth.registrationVerify({
            challengeId: options.challengeId, response: key.register(options.options, origin)
        }, browser);
        const login = await f.auth.loginOptions({}, browser);
        await assert.rejects(f.auth.loginVerify({
            challengeId: login.challengeId, response: key.login(login.options, origin, {
                userHandle: randomBytes(32).toString('base64url')
            })
        }, browser), /credential_account_mismatch/);
        const next = await f.auth.loginOptions({}, browser);
        f.store.run('UPDATE accounts SET permission_version=2 WHERE id=\'bryn\'');
        await assert.rejects(f.auth.loginVerify({
            challengeId: next.challengeId, response: key.login(next.options, origin)
        }, browser), /credential_account_mismatch/);
        assert.throws(() => f.auth.session(enrolled.token, browser), /permissions_changed/);
        const adminOptions = await f.auth.registrationOptions({
            token: issueBootstrap(f.store, 'jd', f.now())
        }, browser);
        f.store.run('UPDATE accounts SET permission_version=2 WHERE id=\'jd\'');
        await assert.rejects(f.auth.registrationVerify({
            challengeId: adminOptions.challengeId, response: new TestAuthenticator().register(adminOptions.options, origin)
        }, browser), /permissions_changed/);
    }
    finally {
        f.close();
    }
});
test('two SQLite connections racing signed bootstrap enrollment commit exactly one credential/account binding', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-auth-race-'));
    const first = new Store(join(dir, 'service.sqlite'));
    seedAccounts(first);
    const second = new Store(join(dir, 'service.sqlite'));
    const now = 1791691200, token = issueBootstrap(first, 'bryn', now);
    const a = new Auth(first, origin, () => now), b = new Auth(second, origin, () => now);
    try {
        const firstOptions = await a.registrationOptions({ token }, browser);
        const secondOptions = await b.registrationOptions({ token }, browser);
        const results = await Promise.allSettled([
            a.registrationVerify({ challengeId: firstOptions.challengeId, response: new TestAuthenticator().register(firstOptions.options, origin) }, browser),
            b.registrationVerify({ challengeId: secondOptions.challengeId, response: new TestAuthenticator().register(secondOptions.options, origin) }, browser),
        ]);
        assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
        assert.equal(first.get<{ n: number }>('SELECT count(*) n FROM credentials')!.n, 1);
        assert.equal(first.get<{ n: number }>('SELECT count(*) n FROM sessions')!.n, 1);
    } finally {
        second.close(); first.close(); rmSync(dir, { recursive: true });
    }
});
test('logout cancels a genuine in-flight login verification and late response cookies cannot resurrect a session', async () => {
    const f = fixture();
    try {
        const options = await f.auth.registrationOptions({ token: issueBootstrap(f.store, 'bryn', f.now()) }, browser);
        const key = new TestAuthenticator();
        const enrolled = await f.auth.registrationVerify({ challengeId: options.challengeId, response: key.register(options.options, origin) }, browser);
        const login = await f.auth.loginOptions({}, browser);
        const pending = f.auth.loginVerify({ challengeId: login.challengeId, response: key.login(login.options, origin) }, browser, enrolled.token);
        f.auth.logout(f.auth.session(enrolled.token, browser));
        await assert.rejects(pending, /authentication_context_cancelled/);
        assert.throws(() => f.auth.session(enrolled.token, browser), /session_expired/);
        const nextOptions = await f.auth.loginOptions({}, browser);
        const next = await f.auth.loginVerify({ challengeId: nextOptions.challengeId, response: key.login(nextOptions.options, origin) }, browser);
        const rotatedOptions = await f.auth.loginOptions({}, browser);
        const rotated = await f.auth.loginVerify({ challengeId: rotatedOptions.challengeId, response: key.login(rotatedOptions.options, origin) }, browser, next.token);
        f.auth.logoutRequest(next.token, browser, next.dto.csrfToken);
        assert.throws(() => f.auth.session(rotated.token, browser), /session_expired/);
        // A delayed prior-epoch logout cannot cancel a later deliberate sign-in.
        const deliberateOptions = await f.auth.loginOptions({}, browser);
        const deliberate = await f.auth.loginVerify({ challengeId: deliberateOptions.challengeId, response: key.login(deliberateOptions.options, origin) }, browser);
        f.auth.logoutRequest(next.token, browser, next.dto.csrfToken);
        assert.equal(f.auth.session(deliberate.token, browser).dto.actor.id, 'bryn');
        assert.throws(() => f.auth.session(deliberate.token, randomBytes(32).toString('base64url')), /session_browser_mismatch/);
        assert.throws(() => f.auth.logoutRequest(deliberate.token, browser, 'wrong'), /csrf_rejected/);
    } finally { f.close(); }
});
test('simultaneous same-browser cross-account and same-account genuine verifications issue one authoritative session', async () => {
    const f = fixture();
    try {
        const a = new TestAuthenticator(), b = new TestAuthenticator(), otherBrowser = randomBytes(32).toString('base64url');
        const parentOptions = await f.auth.registrationOptions({ token: issueBootstrap(f.store, 'bryn', f.now()) }, browser);
        const parentSession = await f.auth.registrationVerify({ challengeId: parentOptions.challengeId, response: a.register(parentOptions.options, origin) }, browser);
        const adminOptions = await f.auth.registrationOptions({ token: issueBootstrap(f.store, 'jd', f.now()) }, otherBrowser);
        await f.auth.registrationVerify({ challengeId: adminOptions.challengeId, response: b.register(adminOptions.options, origin) }, otherBrowser);
        const options = await f.auth.loginOptions({}, browser), competing = await f.auth.loginOptions({}, browser);
        const races = await Promise.allSettled([
            f.auth.loginVerify({ challengeId: options.challengeId, response: a.login(options.options, origin) }, browser, parentSession.token),
            f.auth.loginVerify({ challengeId: competing.challengeId, response: b.login(competing.options, origin) }, browser, parentSession.token),
        ]);
        assert.equal(races.filter(result => result.status === 'fulfilled').length, 1);
        const winner = races.find(result => result.status === 'fulfilled') as PromiseFulfilledResult<{ token: string }>;
        assert.equal(f.store.get<{ n: number }>('SELECT count(*) n FROM sessions WHERE browser_hash=? AND revoked=0', digest(browser))!.n, 1);
        assert.throws(() => f.auth.session(parentSession.token, browser), /session_expired/);
        const first = await f.auth.loginOptions({}, browser), second = await f.auth.loginOptions({}, browser);
        const sameAccount = await Promise.allSettled([
            f.auth.loginVerify({ challengeId: first.challengeId, response: a.login(first.options, origin) }, browser, winner.value.token),
            f.auth.loginVerify({ challengeId: second.challengeId, response: a.login(second.options, origin) }, browser, winner.value.token),
        ]);
        assert.equal(sameAccount.filter(result => result.status === 'fulfilled').length, 1);
        assert.throws(() => f.auth.session(winner.value.token, browser), /session_expired/);
        // An admin verification already in progress cannot finish after the parent logs this browser out.
        const active = (sameAccount.find(result => result.status === 'fulfilled') as PromiseFulfilledResult<{ token: string }>).value;
        const adminLogin = await f.auth.loginOptions({}, browser);
        const pending = f.auth.loginVerify({ challengeId: adminLogin.challengeId, response: b.login(adminLogin.options, origin) }, browser, active.token);
        f.auth.logout(f.auth.session(active.token, browser));
        await assert.rejects(pending, /authentication_context_cancelled/);
    } finally { f.close(); }
});
test('logout during asynchronous options generation cancels the captured context instead of issuing a later challenge', async () => {
    const f = fixture();
    try {
        const key = new TestAuthenticator();
        const options = await f.auth.registrationOptions({ token: issueBootstrap(f.store, 'bryn', f.now()) }, browser);
        const session = await f.auth.registrationVerify({ challengeId: options.challengeId, response: key.register(options.options, origin) }, browser);
        const pending = f.auth.loginOptions({}, browser);
        f.auth.logout(f.auth.session(session.token, browser));
        await assert.rejects(pending, /authentication_context_cancelled/);
    } finally { f.close(); }
});
