import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { RegistrationResponseJSON, AuthenticationResponseJSON, AuthenticatorTransportFuture } from '@simplewebauthn/server';
import type { Actor, SessionDTO, Provenance } from '../../shared/src/contracts.ts';
import { provenance } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import type { Store } from './db.ts';
export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('base64url');
const equal = (a: string, b: string) => {
    const left = Buffer.from(a), right = Buffer.from(b);
    return left.length === right.length && timingSafeEqual(left, right);
};
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
}
export interface AuthSession {
    dto: SessionDTO;
    hash: string;
    browserHash: string;
    browserEpoch: number;
}
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
export class Auth {
    readonly store: Store;
    readonly origin: string;
    readonly rpID = 'localhost';
    readonly now: () => number;
    private attempts: number[] = [];
    readonly provenance: Provenance;
    readonly rpName: string;
    constructor(store: Store, origin: string, now = () => Math.floor(Date.now() / 1000), context: {provenance?: Provenance; rpName?: string} = {}) {
        this.store = store;
        this.origin = origin;
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
            throw new AppError(401, 'invalid_bootstrap');
        }
        const account = this.account(bootstrap.account_id);
        if (this.store.get('SELECT id FROM credentials WHERE account_id=?', account.id)) {
            throw new AppError(409, 'account_already_enrolled');
        }
        const options = await generateRegistrationOptions({
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
    async registrationVerify(input: unknown, browserToken: string, oldSessionToken?: string) {
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
            }>('SELECT * FROM bootstrap_tokens WHERE hash=?', challenge.bootstrap_hash);
            if (!bootstrap || bootstrap.account_id !== challenge.account_id || bootstrap.consumed || bootstrap.expires_at <= this.now()) {
                throw new AppError(401, 'invalid_bootstrap');
            }
            const account = this.account(bootstrap.account_id);
            if (account.permission_version !== challenge.account_version) {
                throw new AppError(401, 'permissions_changed');
            }
            if (this.store.get('SELECT id FROM credentials WHERE account_id=? OR id=?', account.id, credential.id)) {
                throw new AppError(409, 'credential_already_bound');
            }
            this.store.run('INSERT INTO credentials(id,account_id,public_key,counter,transports) VALUES(?,?,?,?,?)', credential.id, account.id, credential.publicKey, credential.counter, JSON.stringify(credential.transports ?? []));
            this.store.run('UPDATE bootstrap_tokens SET consumed=1 WHERE account_id=?', account.id);
            this.store.run('UPDATE challenges SET consumed=1 WHERE account_id=?', account.id);
            return this.createSession(account, challenge, oldSessionToken);
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
        }>('SELECT credentials.id,credentials.account_id,accounts.permission_version FROM credentials JOIN accounts ON accounts.id=credentials.account_id WHERE accounts.active=1');
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
        if (!credential) {
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
            if (!current || current.account_id !== account.id || current.counter !== credential.counter) {
                throw new AppError(401, 'credential_changed');
            }
            const freshAccount = this.account(account.id);
            if (freshAccount.permission_version !== account.permission_version) {
                throw new AppError(401, 'permissions_changed');
            }
            this.store.run('UPDATE credentials SET counter=? WHERE id=?', result.authenticationInfo.newCounter, credential.id);
            return this.createSession(freshAccount, challenge, oldSessionToken);
        });
    }
    private createSession(account: AccountRow, challenge: ChallengeRow, oldToken?: string) {
        // Exactly one authoritative session is issued per browser authentication generation.
        this.store.run('UPDATE auth_contexts SET generation=generation+1 WHERE browser_hash=? AND epoch=? AND generation=?', challenge.browser_hash, challenge.browser_epoch, challenge.browser_generation);
        this.store.run('UPDATE sessions SET revoked=1 WHERE browser_hash=? AND browser_epoch=?', challenge.browser_hash, challenge.browser_epoch);
        const token = secret(), csrf = secret(), expiresAt = this.now() + 3600;
        this.store.run('INSERT INTO sessions(hash,account_id,csrf,permission_version,expires_at,browser_hash,browser_epoch) VALUES(?,?,?,?,?,?,?)', digest(token), account.id, csrf, account.permission_version, expiresAt, challenge.browser_hash, challenge.browser_epoch);
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
        return {
            hash, browserHash: row.browser_hash, browserEpoch: row.browser_epoch, dto: {
                ...this.provenance, actor: this.actor(account), csrfToken: row.csrf, expiresAt: row.expires_at
            }
        };
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
