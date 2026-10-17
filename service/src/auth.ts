import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { RegistrationResponseJSON, AuthenticationResponseJSON, AuthenticatorTransportFuture } from '@simplewebauthn/server';
import type { Actor, SessionDTO, Provenance } from '../../shared/src/contracts.ts';
import { provenance } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import type { Store } from './db.ts';
import { PASSKEYS_PER_ACCOUNT } from './account-limits.ts';
export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('base64url');
const equal = (a: string, b: string) => {
    const left = Buffer.from(a), right = Buffer.from(b);
    return left.length === right.length && timingSafeEqual(left, right);
};
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_UPS_PER_MINUTE = 10;
/** One answer for unknown, used, expired and replaced tokens, so the endpoint is no token oracle. */
const tokenUnusable = () => new AppError(401, 'token_used_or_expired', 'This enrollment token is unknown, expired or has already been used. Ask your admin for a new token, and to check the pending devices and not approve any they do not recognise.');
/** A new token for an account rejects that account's pending passkeys: only the newest token's device can be approved. */
export function rejectPendingPasskeys(store: Store, accountId: string, actorId: string, now: number): void {
    const pending = store.all<{id: string}>("SELECT id FROM credentials WHERE account_id=? AND state='pending' ORDER BY id", accountId);
    for (const {id} of pending) {
        store.run('DELETE FROM credentials WHERE id=?', id);
        store.run('UPDATE sessions SET revoked=1 WHERE credential_id=?', id);
        store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', actorId, 'passkey_pending_rejected', now, `${accountId}:${id}`);
    }
}
/** Short code an enrolling device shows and an approving admin compares: first 6 base32 characters of sha256(credential id). */
export function pairingCode(credentialId: string): string {
    let bits = 0, value = 0, code = '';
    for (const byte of createHash('sha256').update(credentialId).digest()) {
        value = (value << 8) | byte; bits += 8;
        while (bits >= 5 && code.length < 6) { code += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; value &= (1 << bits) - 1; }
        if (code.length === 6) return code;
    }
    return code;
}
interface AccountRow {
    id: string;
    display_name: string;
    role: Actor['role'];
    person_ids: string;
    permission_version: number;
    active: number;
    webauthn_user_id: string;
}
interface ChallengeRow {
    id: string;
    challenge: string;
    kind: 'register' | 'login';
    account_id: string | null;
    account_version: number | null;
    bootstrap_hash: string | null;
    credential_ids: string;
    browser_hash: string;
    browser_epoch: number;
    browser_generation: number;
    expires_at: number;
    consumed: number;
}
interface CredentialRow {
    id: string;
    account_id: string;
    public_key: Uint8Array;
    counter: number;
    transports: string;
    state: 'active' | 'pending';
}
interface StepUpRow {
    id: string;
    challenge: string;
    session_hash: string;
    account_id: string;
    binding: string;
    credential_ids: string;
    expires_at: number;
    consumed: number;
}
/** A verified fresh passkey assertion, committed only inside the caller's write transaction. */
export interface StepUpProof {
    credentialId: string;
    counter: number;
    newCounter: number;
}
interface SessionRow {
    hash: string;
    account_id: string;
    csrf: string;
    permission_version: number;
    expires_at: number;
    revoked: number;
    browser_hash: string;
    browser_epoch: number;
    credential_id: string | null;
}
export interface AuthSession {
    dto: SessionDTO;
    hash: string;
    browserHash: string;
    browserEpoch: number;
    credentialId: string | null;
}
export type EnrollmentResult = {token: string; dto: SessionDTO} | {pending: {pairingCode: string; credentialId: string}};
export function tokenText(value: unknown): string {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{32,1024}$/.test(value)) {
        throw new AppError(400, 'invalid_token');
    }
    return value;
}
/** CLI-only issuance. HTTP registration cannot select the account or its permissions. */
export function issueBootstrap(store: Store, accountId: string, now = Math.floor(Date.now() / 1000)): string {
    if (!['jd', 'bryn'].includes(accountId)) {
        throw new AppError(400, 'unknown_fictional_account');
    }
    if (store.get('SELECT id FROM credentials WHERE account_id=?', accountId)) {
        throw new AppError(409, 'account_already_enrolled');
    }
    const token = secret();
    store.transaction(() => {
        store.run('UPDATE bootstrap_tokens SET consumed=1 WHERE account_id=?', accountId);
        store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at) VALUES(?,?,?)', digest(token), accountId, now + 600);
    });
    return token;
}
/**
 * Operator CLI issuance for the private integration: any active database account. The passkey it enrolls is active only
 * while the account has no active passkey (first enrollment); otherwise it is pending and needs an admin's approval.
 */
export function issueOperatorBootstrap(store: Store, accountId: string, now = Math.floor(Date.now() / 1000)): string {
    if (!store.get('SELECT id FROM accounts WHERE id=? AND active=1', accountId)) throw new AppError(404, 'unknown_private_account');
    if (store.get<{n: number}>('SELECT count(*) n FROM credentials WHERE account_id=?', accountId)!.n >= PASSKEYS_PER_ACCOUNT) throw new AppError(409, 'passkey_limit_reached');
    const token = secret();
    store.transaction(() => {
        rejectPendingPasskeys(store, accountId, 'operator', now);
        store.run('UPDATE bootstrap_tokens SET consumed=1 WHERE account_id=?', accountId);
        store.run("INSERT INTO bootstrap_tokens(hash,account_id,expires_at,purpose,created_by) VALUES(?,?,?,'bootstrap','operator')", digest(token), accountId, now + 600);
    });
    return token;
}
export class Auth {
    readonly store: Store;
    readonly origin: string;
    readonly rpID: string;
    readonly now: () => number;
    private attempts: number[] = [];
    /** Per-account, so one signed-in account cannot exhaust the shared sign-in limiter. Bounded by ACCOUNT_LIMIT keys. */
    private stepUpAttempts = new Map<string, number[]>();
    readonly provenance: Provenance;
    readonly rpName: string;
    constructor(store: Store, origin: string, now = () => Math.floor(Date.now() / 1000), context: {provenance?: Provenance; rpName?: string} = {}) {
        this.store = store;
        this.origin = origin;
        this.rpID = new URL(origin).hostname;
        this.now = now;
        this.provenance = context.provenance ?? provenance;
        this.rpName = context.rpName ?? 'Couvre-feu fictional demo';
    }
    private account(id: string): AccountRow {
        const row = this.store.get<AccountRow>('SELECT * FROM accounts WHERE id=? AND active=1', id);
        if (!row) {
            throw new AppError(401, 'account_disabled');
        }
        return row;
    }
    private actor(row: AccountRow): Actor {
        return {
            id: row.id, displayName: row.display_name, role: row.role, personIds: JSON.parse(row.person_ids), permissionVersion: String(row.permission_version)
        };
    }
    private rateLimit() {
        const now = this.now();
        this.attempts = this.attempts.filter(timestamp => timestamp > now - 60);
        if (this.attempts.length >= 60) {
            throw new AppError(429, 'auth_rate_limited');
        }
        this.attempts.push(now);
        this.store.run('DELETE FROM challenges WHERE expires_at<? OR consumed=1', now);
        this.store.run('DELETE FROM step_ups WHERE expires_at<? OR consumed=1', now);
        this.store.run('DELETE FROM bootstrap_tokens WHERE expires_at<? AND hash NOT IN (SELECT bootstrap_hash FROM challenges WHERE bootstrap_hash IS NOT NULL)', now);
    }
    private context(browserToken: string): { browserHash: string; epoch: number; generation: number } {
        const browserHash = digest(tokenText(browserToken));
        this.store.run('INSERT OR IGNORE INTO auth_contexts(browser_hash,epoch) VALUES(?,0)', browserHash);
        return { browserHash, ...this.store.get<{ epoch: number; generation: number }>('SELECT epoch,generation FROM auth_contexts WHERE browser_hash=?', browserHash)! };
    }
    private currentContext(browserHash: string, epoch: number, generation?: number): void {
        const context = this.store.get<{ epoch: number; generation: number }>('SELECT epoch,generation FROM auth_contexts WHERE browser_hash=?', browserHash);
        if (!context || context.epoch !== epoch || (generation !== undefined && context.generation !== generation)) throw new AppError(401, 'authentication_context_cancelled');
    }
    private liveChallenge(challenge: ChallengeRow): void {
        this.currentContext(challenge.browser_hash, challenge.browser_epoch, challenge.browser_generation);
        if (challenge.expires_at <= this.now()) throw new AppError(401, 'invalid_challenge');
    }
    private challenge(kind: ChallengeRow['kind'], challenge: string, context: { browserHash: string; epoch: number; generation: number }, accountId: string | null, bootstrapHash: string | null, credentials: Record<string, {
        accountId: string;
        version: number;
    }>) {
        const id = secret();
        this.store.transaction(() => {
            this.currentContext(context.browserHash, context.epoch, context.generation);
            this.store.run('INSERT INTO challenges(id,challenge,kind,account_id,account_version,bootstrap_hash,credential_ids,browser_hash,browser_epoch,browser_generation,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)', id, challenge, kind, accountId, accountId ? this.account(accountId).permission_version : null, bootstrapHash, JSON.stringify(credentials), context.browserHash, context.epoch, context.generation, this.now() + 120);
        });
        return id;
    }
    private consumeChallenge(id: unknown, browserToken: string, kind: ChallengeRow['kind']): ChallengeRow {
        tokenText(id);
        return this.store.transaction(() => {
            const row = this.store.get<ChallengeRow>('SELECT * FROM challenges WHERE id=?', id as string);
            if (!row || row.kind !== kind || row.consumed || row.expires_at <= this.now() || !equal(row.browser_hash, digest(browserToken))) {
                throw new AppError(401, 'invalid_challenge');
            }
            this.currentContext(row.browser_hash, row.browser_epoch, row.browser_generation);
            this.store.run('UPDATE challenges SET consumed=1 WHERE id=?', row.id);
            return row;
        });
    }
    async registrationOptions(input: unknown, browserToken: string) {
        this.rateLimit();
        const context = this.context(browserToken);
        const body = object(input, ['token']), token = tokenText(body.token), hash = digest(token);
        const bootstrap = this.store.get<{
            account_id: string;
            expires_at: number;
            consumed: number;
        }>('SELECT * FROM bootstrap_tokens WHERE hash=?', hash);
        if (!bootstrap || bootstrap.consumed || bootstrap.expires_at <= this.now()) {
            throw tokenUnusable();
        }
        const account = this.account(bootstrap.account_id);
        const existing = this.store.all<{id: string; transports: string}>('SELECT id,transports FROM credentials WHERE account_id=?', account.id);
        if (existing.length >= PASSKEYS_PER_ACCOUNT) throw new AppError(409, 'passkey_limit_reached');
        const options = await generateRegistrationOptions({
            excludeCredentials: existing.map(c => ({id: c.id, transports: JSON.parse(c.transports) as AuthenticatorTransportFuture[]})),
            rpName: this.rpName, rpID: this.rpID,
            userName: account.display_name, userDisplayName: account.display_name, userID: Buffer.from(account.webauthn_user_id, 'base64url'),
            attestationType: 'none', authenticatorSelection: {
                residentKey: 'required', userVerification: 'required'
            }, supportedAlgorithmIDs: [-7, -257], timeout: 120000
        });
        return {
            challengeId: this.challenge('register', options.challenge, context, account.id, hash, {}), options
        };
    }
    /** First enrollment of an account only; a pending passkey (add-device token or an already enrolled account) is reported as an error here. */
    async registrationVerify(input: unknown, browserToken: string, oldSessionToken?: string): Promise<{token: string; dto: SessionDTO}> {
        const result = await this.enroll(input, browserToken, oldSessionToken);
        if ('pending' in result) throw new AppError(409, 'enrollment_pending_approval');
        return result;
    }
    async enroll(input: unknown, browserToken: string, oldSessionToken?: string): Promise<EnrollmentResult> {
        const body = object(input, ['challengeId', 'response']), challenge = this.consumeChallenge(body.challengeId, browserToken, 'register');
        const response = body.response as RegistrationResponseJSON;
        let result;
        try {
            result = await verifyRegistrationResponse({
                response, expectedChallenge: challenge.challenge, expectedOrigin: this.origin, expectedRPID: this.rpID, requireUserVerification: true, requireUserPresence: true, supportedAlgorithmIDs: [-7, -257]
            });
        }
        catch {
            throw new AppError(401, 'passkey_verification_failed');
        }
        if (!result.verified || !result.registrationInfo.userVerified) {
            throw new AppError(401, 'passkey_verification_failed');
        }
        const credential = result.registrationInfo.credential;
        return this.store.transaction(() => {
            this.liveChallenge(challenge);
            const bootstrap = this.store.get<{
                account_id: string;
                expires_at: number;
                consumed: number;
                purpose: 'bootstrap' | 'add_device';
                label: string;
            }>('SELECT * FROM bootstrap_tokens WHERE hash=?', challenge.bootstrap_hash);
            if (!bootstrap || bootstrap.account_id !== challenge.account_id || bootstrap.consumed || bootstrap.expires_at <= this.now()) {
                throw tokenUnusable();
            }
            const account = this.account(bootstrap.account_id);
            if (account.permission_version !== challenge.account_version) {
                throw new AppError(401, 'permissions_changed');
            }
            if (this.store.get('SELECT id FROM credentials WHERE id=?', credential.id)) {
                throw new AppError(409, 'credential_already_bound');
            }
            if (this.store.get<{n: number}>('SELECT count(*) n FROM credentials WHERE account_id=?', account.id)!.n >= PASSKEYS_PER_ACCOUNT) throw new AppError(409, 'passkey_limit_reached');
            // Every token may cross a cleartext proxy hop. Only the first passkey of an account (no active one yet, checked in
            // this transaction) is active at once; any later passkey, and every add-device passkey, waits for admin approval.
            const enrolled = Boolean(this.store.get("SELECT 1 FROM credentials WHERE account_id=? AND state='active'", account.id));
            const state = bootstrap.purpose === 'add_device' || enrolled ? 'pending' : 'active';
            this.store.run('INSERT INTO credentials(id,account_id,public_key,counter,transports,label,state,created_at) VALUES(?,?,?,?,?,?,?,?)', credential.id, account.id, credential.publicKey, credential.counter, JSON.stringify(credential.transports ?? []), bootstrap.label, state, this.now());
            this.store.run('UPDATE bootstrap_tokens SET consumed=1 WHERE account_id=?', account.id);
            this.store.run('UPDATE challenges SET consumed=1 WHERE account_id=?', account.id);
            if (state === 'pending') {
                this.store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', account.id, 'passkey_enrolled', this.now(), 'pending_approval');
                return {pending: {pairingCode: pairingCode(credential.id), credentialId: credential.id}};
            }
            return this.createSession(account, challenge, oldSessionToken, credential.id);
        });
    }
    async loginOptions(input: unknown, browserToken: string) {
        object(input, []);
        this.rateLimit();
        const context = this.context(browserToken);
        const credentials = this.store.all<{
            id: string;
            account_id: string;
            permission_version: number;
        }>("SELECT credentials.id,credentials.account_id,accounts.permission_version FROM credentials JOIN accounts ON accounts.id=credentials.account_id WHERE accounts.active=1 AND credentials.state='active'");
        const options = await generateAuthenticationOptions({
            rpID: this.rpID, userVerification: 'required', timeout: 120000
        });
        return {
            challengeId: this.challenge('login', options.challenge, context, null, null, Object.fromEntries(credentials.map(c => [c.id, {
                    accountId: c.account_id, version: c.permission_version
                }]))), options
        };
    }
    async loginVerify(input: unknown, browserToken: string, oldSessionToken?: string) {
        const body = object(input, ['challengeId', 'response']), challenge = this.consumeChallenge(body.challengeId, browserToken, 'login');
        const response = body.response as AuthenticationResponseJSON;
        const bindings = JSON.parse(challenge.credential_ids) as Record<string, {
            accountId: string;
            version: number;
        }>;
        if (!response || typeof response.id !== 'string' || !Object.hasOwn(bindings, response.id)) {
            throw new AppError(401, 'credential_not_bound');
        }
        const credential = this.store.get<CredentialRow>('SELECT * FROM credentials WHERE id=?', response.id);
        if (!credential || credential.state !== 'active') {
            throw new AppError(401, 'credential_not_bound');
        }
        const account = this.account(credential.account_id);
        if (bindings[response.id].accountId !== account.id || bindings[response.id].version !== account.permission_version) {
            throw new AppError(401, 'credential_account_mismatch');
        }
        // Discoverable assertions must identify the server-owned credential account.
        if (!response.response?.userHandle || !equal(response.response.userHandle, account.webauthn_user_id)) {
            throw new AppError(401, 'credential_account_mismatch');
        }
        let result;
        try {
            result = await verifyAuthenticationResponse({
                response, expectedChallenge: challenge.challenge, expectedOrigin: this.origin, expectedRPID: this.rpID, requireUserVerification: true,
                credential: {
                    id: credential.id, publicKey: Uint8Array.from(credential.public_key), counter: credential.counter, transports: JSON.parse(credential.transports) as AuthenticatorTransportFuture[]
                }
            });
        }
        catch {
            throw new AppError(401, 'passkey_verification_failed');
        }
        if (!result.verified || !result.authenticationInfo.userVerified) {
            throw new AppError(401, 'passkey_verification_failed');
        }
        return this.store.transaction(() => {
            this.liveChallenge(challenge);
            const current = this.store.get<CredentialRow>('SELECT * FROM credentials WHERE id=?', credential.id);
            if (!current || current.account_id !== account.id || current.state !== 'active' || current.counter !== credential.counter) {
                throw new AppError(401, 'credential_changed');
            }
            const freshAccount = this.account(account.id);
            if (freshAccount.permission_version !== account.permission_version) {
                throw new AppError(401, 'permissions_changed');
            }
            this.store.run('UPDATE credentials SET counter=?,last_used_at=? WHERE id=?', result.authenticationInfo.newCounter, this.now(), credential.id);
            return this.createSession(freshAccount, challenge, oldSessionToken, credential.id);
        });
    }
    private createSession(account: AccountRow, challenge: ChallengeRow, oldToken: string | undefined, credentialId: string) {
        // Exactly one authoritative session is issued per browser authentication generation.
        this.store.run('UPDATE auth_contexts SET generation=generation+1 WHERE browser_hash=? AND epoch=? AND generation=?', challenge.browser_hash, challenge.browser_epoch, challenge.browser_generation);
        this.store.run('UPDATE sessions SET revoked=1 WHERE browser_hash=? AND browser_epoch=?', challenge.browser_hash, challenge.browser_epoch);
        const token = secret(), csrf = secret(), expiresAt = this.now() + 3600;
        this.store.run('INSERT INTO sessions(hash,account_id,csrf,permission_version,expires_at,browser_hash,browser_epoch,credential_id) VALUES(?,?,?,?,?,?,?,?)', digest(token), account.id, csrf, account.permission_version, expiresAt, challenge.browser_hash, challenge.browser_epoch, credentialId);
        this.store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', account.id, 'session_created', this.now(), 'authenticated');
        return {
            token, dto: {
                ...this.provenance, actor: this.actor(account), csrfToken: csrf, expiresAt
            } as SessionDTO
        };
    }
    session(token: string | undefined, browserToken: string | undefined): AuthSession {
        if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
            throw new AppError(401, 'authentication_required');
        }
        const hash = digest(token), row = this.store.get<SessionRow>('SELECT * FROM sessions WHERE hash=?', hash);
        if (!row || row.revoked || row.expires_at <= this.now()) {
            throw new AppError(401, 'session_expired');
        }
        if (!browserToken || !equal(row.browser_hash, digest(browserToken))) throw new AppError(401, 'session_browser_mismatch');
        this.currentContext(row.browser_hash, row.browser_epoch);
        const account = this.account(row.account_id);
        if (row.permission_version !== account.permission_version) {
            throw new AppError(401, 'permissions_changed');
        }
        // Belt and braces for revocation: a session never outlives the passkey that created it.
        if (row.credential_id !== null && !this.store.get("SELECT id FROM credentials WHERE id=? AND account_id=? AND state='active'", row.credential_id, row.account_id)) {
            throw new AppError(401, 'credential_revoked');
        }
        return {
            hash, browserHash: row.browser_hash, browserEpoch: row.browser_epoch, credentialId: row.credential_id, dto: {
                ...this.provenance, actor: this.actor(account), csrfToken: row.csrf, expiresAt: row.expires_at
            }
        };
    }
    /** Re-reads the session inside a transaction: still live, account active and permissions unchanged. */
    liveSession(session: AuthSession): Actor {
        const row = this.store.get<SessionRow>('SELECT * FROM sessions WHERE hash=?', session.hash);
        if (!row || row.revoked || row.expires_at <= this.now()) throw new AppError(401, 'session_expired');
        const account = this.account(row.account_id);
        if (row.permission_version !== account.permission_version || String(account.permission_version) !== session.dto.actor.permissionVersion) throw new AppError(401, 'permissions_changed');
        return this.actor(account);
    }
    /** A fresh assertion challenge limited to the session account's own active passkeys and bound to one exact change. */
    async stepUpChallenge(session: AuthSession, binding: string) {
        const now = this.now(), recent = (this.stepUpAttempts.get(session.dto.actor.id) ?? []).filter(timestamp => timestamp > now - 60);
        if (recent.length >= STEP_UPS_PER_MINUTE) throw new AppError(429, 'step_up_rate_limited');
        this.stepUpAttempts.set(session.dto.actor.id, [...recent, now]);
        this.store.run('DELETE FROM step_ups WHERE expires_at<? OR consumed=1', now);
        const credentials = this.store.all<{id: string; transports: string}>("SELECT id,transports FROM credentials WHERE account_id=? AND state='active'", session.dto.actor.id);
        if (!credentials.length) throw new AppError(403, 'step_up_unavailable');
        const options = await generateAuthenticationOptions({
            rpID: this.rpID, userVerification: 'required', timeout: 120000,
            allowCredentials: credentials.map(c => ({id: c.id, transports: JSON.parse(c.transports) as AuthenticatorTransportFuture[]}))
        });
        const id = secret();
        this.store.transaction(() => {
            this.liveSession(session);
            this.store.run('INSERT INTO step_ups(id,challenge,session_hash,account_id,binding,credential_ids,expires_at) VALUES(?,?,?,?,?,?,?)', id, options.challenge, session.hash, session.dto.actor.id, binding, JSON.stringify(credentials.map(c => c.id)), this.now() + 120);
        });
        return {challengeId: id, options};
    }
    /** Consumes the step-up challenge once, then checks its binding and the signature. Nothing is written until commitStepUp. */
    async stepUpVerify(session: AuthSession, input: unknown, binding: string): Promise<StepUpProof> {
        if (input === undefined) throw new AppError(403, 'step_up_required');
        const body = object(input, ['challengeId', 'response']);
        tokenText(body.challengeId);
        const row = this.store.transaction(() => {
            const found = this.store.get<StepUpRow>('SELECT * FROM step_ups WHERE id=?', body.challengeId as string);
            if (!found || found.consumed || found.expires_at <= this.now()) throw new AppError(401, 'invalid_challenge');
            this.store.run('UPDATE step_ups SET consumed=1 WHERE id=?', found.id);
            return found;
        });
        if (!equal(row.session_hash, session.hash) || row.account_id !== session.dto.actor.id || !equal(row.binding, binding)) throw new AppError(403, 'step_up_mismatch');
        const response = body.response as AuthenticationResponseJSON;
        if (!response || typeof response.id !== 'string' || !(JSON.parse(row.credential_ids) as string[]).includes(response.id)) throw new AppError(401, 'credential_not_bound');
        const credential = this.store.get<CredentialRow>('SELECT * FROM credentials WHERE id=?', response.id);
        if (!credential || credential.state !== 'active' || credential.account_id !== row.account_id) throw new AppError(401, 'credential_not_bound');
        const account = this.account(row.account_id);
        if (!response.response?.userHandle || !equal(response.response.userHandle, account.webauthn_user_id)) throw new AppError(401, 'credential_account_mismatch');
        let result;
        try {
            result = await verifyAuthenticationResponse({
                response, expectedChallenge: row.challenge, expectedOrigin: this.origin, expectedRPID: this.rpID, requireUserVerification: true,
                credential: {id: credential.id, publicKey: Uint8Array.from(credential.public_key), counter: credential.counter, transports: JSON.parse(credential.transports) as AuthenticatorTransportFuture[]}
            });
        } catch { throw new AppError(401, 'passkey_verification_failed'); }
        if (!result.verified || !result.authenticationInfo.userVerified) throw new AppError(401, 'passkey_verification_failed');
        return {credentialId: credential.id, counter: credential.counter, newCounter: result.authenticationInfo.newCounter};
    }
    /** Inside the caller's write transaction: the session and the confirming passkey are still current. Returns the fresh actor. */
    commitStepUp(session: AuthSession, proof: StepUpProof): Actor {
        if (!this.store.db.isTransaction) throw new Error('step_up_requires_transaction');
        const actor = this.liveSession(session);
        const current = this.store.get<CredentialRow>('SELECT * FROM credentials WHERE id=?', proof.credentialId);
        if (!current || current.state !== 'active' || current.account_id !== actor.id || current.counter !== proof.counter) throw new AppError(401, 'credential_changed');
        this.store.run('UPDATE credentials SET counter=?,last_used_at=? WHERE id=?', proof.newCounter, this.now(), proof.credentialId);
        return actor;
    }
    csrf(session: AuthSession, token: unknown) {
        if (typeof token !== 'string' || !equal(session.dto.csrfToken, token)) {
            throw new AppError(403, 'csrf_rejected');
        }
    }
    logout(session: Pick<AuthSession, 'hash' | 'browserHash' | 'browserEpoch'>) {
        this.store.transaction(() => {
            this.store.run('UPDATE auth_contexts SET epoch=epoch+1 WHERE browser_hash=? AND epoch=?', session.browserHash, session.browserEpoch);
            this.store.run('UPDATE sessions SET revoked=1 WHERE browser_hash=? AND browser_epoch<=?', session.browserHash, session.browserEpoch);
        });
    }
    /** This logout-only allowance revokes a just-rotated browser episode; it never grants API access. */
    logoutRequest(token: string | undefined, browserToken: string | undefined, csrf: unknown) {
        if (!token || !browserToken || typeof csrf !== 'string') throw new AppError(401, 'authentication_required');
        const row = this.store.get<SessionRow>('SELECT * FROM sessions WHERE hash=?', digest(token));
        if (!row || !row.browser_hash || row.expires_at <= this.now() || !equal(row.browser_hash, digest(browserToken))) throw new AppError(401, 'session_expired');
        const episodeSessions = this.store.all<SessionRow>('SELECT * FROM sessions WHERE browser_hash=? AND browser_epoch=? AND expires_at>?', row.browser_hash, row.browser_epoch, this.now());
        if (!episodeSessions.some(session => equal(session.csrf, csrf))) throw new AppError(403, 'csrf_rejected');
        this.logout({ hash: row.hash, browserHash: row.browser_hash, browserEpoch: row.browser_epoch });
    }
}
