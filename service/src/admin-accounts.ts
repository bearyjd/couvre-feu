import { randomBytes } from 'node:crypto';
import type { Actor, Role } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { object } from '../../shared/src/json.ts';
import { digest, pairingCode, rejectPendingPasskeys } from './auth.ts';
import type { Auth, AuthSession } from './auth.ts';
import { auditFor } from './parent-audit.ts';
import { ACCOUNT_LIMIT, PASSKEYS_PER_ACCOUNT } from './account-limits.ts';

/** Every account/passkey change. All need a fresh step-up; only own_passkey_revoke is open to non-admins. */
export type AdminAction = 'account_create' | 'token_issue' | 'account_role' | 'account_active' | 'passkey_approve' | 'passkey_revoke' | 'own_passkey_revoke';
const ACTIONS: readonly AdminAction[] = ['account_create', 'token_issue', 'account_role', 'account_active', 'passkey_approve', 'passkey_revoke', 'own_passkey_revoke'];
const ACCOUNT_ID = /^[a-z][a-z0-9_]{0,31}$/;
export const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,1400}$/;
const OWNER_GUARD_CODES = ['owner_account_protected', 'owner_self_lockout'];
const TOKEN_SECONDS = 600;
interface AccountRow {id: string; display_name: string; role: Role; person_ids: string; active: number; scope_all: number}
interface CredentialRow {id: string; account_id: string; label: string; state: 'active' | 'pending'; created_at: number; last_used_at: number | null}
export interface PasskeyDTO {id: string; label: string; state: 'active' | 'pending'; createdAt: number; lastUsedAt: number | null; pairingCode: string}
export interface AccountDTO {id: string; displayName: string; role: Role; personIds: string[]; scopeAll: boolean; active: boolean; passkeys: PasskeyDTO[]; token: {expiresAt: number; label: string} | null}

function text(value: unknown, code: string, min: number): string {
    if (typeof value !== 'string') throw new AppError(400, code);
    const trimmed = value.trim();
    if (trimmed.length < min || trimmed.length > 64 || /[\x00-\x1f\x7f]/.test(trimmed)) throw new AppError(400, code);
    return trimmed;
}
function role(value: unknown): Role {
    if (value !== 'admin' && value !== 'parent') throw new AppError(400, 'invalid_role');
    return value;
}
function action(value: unknown): AdminAction {
    if (!ACTIONS.includes(value as AdminAction)) throw new AppError(400, 'invalid_action');
    return value as AdminAction;
}
/** Validates one change into canonical parameters. The same result feeds the step-up binding and the mutation itself. */
function normalize(kind: AdminAction, target: unknown, params: unknown, actor: Actor): {target: string; params: Record<string, unknown>} {
    if (typeof target !== 'string') throw new AppError(400, 'invalid_target');
    if (kind === 'account_create') {
        if (target !== '') throw new AppError(400, 'invalid_target');
        const body = object(params, ['displayName', 'role', 'personIds'], ['scopeAll']);
        if (body.scopeAll !== undefined && typeof body.scopeAll !== 'boolean') throw new AppError(400, 'invalid_person_scope');
        const people = body.personIds;
        if (!Array.isArray(people) || people.length < 1 || people.length > 64 || new Set(people).size !== people.length) throw new AppError(400, 'invalid_person_scope');
        // An admin can grant only people inside the admin's own scope.
        if (people.some(person => typeof person !== 'string' || !ACCOUNT_ID.test(person) || !actor.personIds.includes(person))) throw new AppError(403, 'invalid_person_scope');
        return {target, params: {displayName: text(body.displayName, 'invalid_display_name', 1), role: role(body.role), personIds: [...people as string[]].sort(), ...(body.scopeAll ? {scopeAll: true} : {})}};
    }
    if (kind === 'passkey_approve' || kind === 'passkey_revoke' || kind === 'own_passkey_revoke') {
        if (!CREDENTIAL_ID.test(target)) throw new AppError(404, 'passkey_not_found');
        object(params, []);
        return {target, params: {}};
    }
    if (!ACCOUNT_ID.test(target)) throw new AppError(404, 'account_not_found');
    if (kind === 'token_issue') return {target, params: {label: text(object(params, [], ['label']).label ?? '', 'invalid_label', 0)}};
    if (kind === 'account_role') return {target, params: {role: role(object(params, ['role']).role)}};
    const active = object(params, ['active']).active;
    if (typeof active !== 'boolean') throw new AppError(400, 'invalid_active');
    return {target, params: {active}};
}
const bindingOf = (kind: AdminAction, target: string, params: Record<string, unknown>) => digest(JSON.stringify([kind, target, params]));

export class AccountAdmin {
    readonly auth: Auth;
    /** In time-request owner mode, the one account other admins may not take over (credentials, role, active state). */
    readonly ownerAccountId: string | undefined;
    constructor(auth: Auth, ownerAccountId?: string) { this.auth = auth; this.ownerAccountId = ownerAccountId; }
    /** Owner mode: no other admin may issue a token for, approve or revoke a passkey of, re-role or deactivate the owner account. Runs after the scope check. */
    private assertNotOwnerTakeover(actor: Actor, target: string): void {
        if (this.ownerAccountId !== undefined && target === this.ownerAccountId && actor.id !== target) throw new AppError(403, 'owner_account_protected');
    }
    /** Owner mode: the owner may not deactivate, demote or strip themselves of their last active passkey; no one else could undo it (token_issue is guarded for others). */
    private assertNotOwnerSelfLockout(actor: Actor, target: string, locksOut: boolean): void {
        if (locksOut && this.ownerAccountId !== undefined && target === this.ownerAccountId && actor.id === target) throw new AppError(409, 'owner_self_lockout');
    }
    private get store() { return this.auth.store; }
    private allowed(actor: Actor, kind: AdminAction): void {
        if (kind !== 'own_passkey_revoke' && actor.role !== 'admin') throw new AppError(403, 'admin_required');
    }
    private passkeys(accountId: string): PasskeyDTO[] {
        return this.store.all<CredentialRow>('SELECT id,account_id,label,state,created_at,last_used_at FROM credentials WHERE account_id=? ORDER BY created_at,id', accountId)
            .map(c => ({id: c.id, label: c.label, state: c.state, createdAt: c.created_at, lastUsedAt: c.last_used_at, pairingCode: pairingCode(c.id)}));
    }
    private dto(row: AccountRow): AccountDTO {
        const token = this.store.get<{expires_at: number; label: string}>("SELECT expires_at,label FROM bootstrap_tokens WHERE account_id=? AND consumed=0 AND expires_at>? ORDER BY expires_at DESC LIMIT 1", row.id, this.auth.now());
        return {id: row.id, displayName: row.display_name, role: row.role, personIds: JSON.parse(row.person_ids), scopeAll: row.scope_all === 1, active: row.active === 1, passkeys: this.passkeys(row.id), token: token ? {expiresAt: token.expires_at, label: token.label} : null};
    }
    list(actor: Actor): {accounts: AccountDTO[]} {
        this.allowed(actor, 'account_create');
        return {accounts: this.store.all<AccountRow>('SELECT * FROM accounts ORDER BY id').filter(row => this.covers(actor, row)).map(row => this.dto(row))};
    }
    mine(session: AuthSession): {passkeys: (PasskeyDTO & {current: boolean})[]} {
        return {passkeys: this.passkeys(session.dto.actor.id).map(p => ({...p, current: p.id === session.credentialId}))};
    }
    async stepUpOptions(session: AuthSession, input: unknown) {
        const body = object(input, ['action', 'target', 'params']), kind = action(body.action);
        this.allowed(session.dto.actor, kind);
        const change = normalize(kind, body.target, body.params, session.dto.actor);
        return this.auth.stepUpChallenge(session, bindingOf(kind, change.target, change.params));
    }
    /** Verifies the fresh step-up, then applies the change, the last-admin guard and the audit row in one transaction. */
    async perform(session: AuthSession, kind: AdminAction, target: string, input: unknown): Promise<unknown> {
        this.allowed(session.dto.actor, kind);
        if (!input || typeof input !== 'object' || Array.isArray(input)) throw new AppError(400, 'invalid_object');
        const {stepUp, ...rest} = input as Record<string, unknown>;
        const change = normalize(kind, target, rest, session.dto.actor);
        const proof = await this.auth.stepUpVerify(session, stepUp, bindingOf(kind, change.target, change.params));
        try {
            return this.transact(session, kind, change, proof);
        } catch (error) {
            this.auditOwnerGuardRefusal(session.dto.actor.id, error);
            throw error;
        }
    }
    /** The guard refusals throw inside this transaction, so they roll back; the audit row is written by the caller afterwards. */
    private transact(session: AuthSession, kind: AdminAction, change: {target: string; params: Record<string, unknown>}, proof: Awaited<ReturnType<Auth['stepUpVerify']>>): unknown {
        return this.store.transaction(() => {
            const actor = this.auth.commitStepUp(session, proof);
            this.allowed(actor, kind);
            const before = this.adminsWithPasskey();
            const result = this.apply(actor, kind, change.target, change.params);
            if (before > 0 && this.adminsWithPasskey() === 0) throw new AppError(409, 'last_admin_required', 'At least one active admin must keep a working passkey.');
            this.store.run('INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES(?,?,?,?)', actor.id, kind === 'own_passkey_revoke' ? 'passkey_self_revoke' : `admin_${kind}`, this.auth.now(), result.audit);
            return result.body;
        });
    }
    /** Records a refused owner-guard attempt (actor and enums only: the target is the owner account, never stored). Fail-safe: the 403/409 response is never changed. */
    private auditOwnerGuardRefusal(actorId: string, error: unknown): void {
        if (!(error instanceof AppError) || !OWNER_GUARD_CODES.includes(error.code)) return;
        auditFor(this.store).record({actor: actorId, action: 'owner_guard_refused', people: [], result: 'refused', at: this.auth.now()});
    }
    /** At least one active admin account must keep at least one active passkey. */
    private adminsWithPasskey(): number {
        return this.store.get<{n: number}>("SELECT count(DISTINCT a.id) n FROM accounts a JOIN credentials c ON c.account_id=a.id WHERE a.role='admin' AND a.active=1 AND c.state='active'")!.n;
    }
    /** An admin may manage only accounts whose people all lie inside the admin's own scope. */
    private covers(actor: Actor, row: AccountRow): boolean {
        const people = JSON.parse(row.person_ids) as string[];
        // An empty scope would be vacuously covered by every admin; it is covered by none.
        return people.length > 0 && people.every(person => actor.personIds.includes(person));
    }
    private managed(actor: Actor, id: string): AccountRow {
        const row = this.account(id);
        if (!this.covers(actor, row)) throw new AppError(403, 'outside_scope');
        return row;
    }
    private account(id: string): AccountRow {
        const row = this.store.get<AccountRow>('SELECT * FROM accounts WHERE id=?', id);
        if (!row) throw new AppError(404, 'account_not_found');
        return row;
    }
    private credential(id: string, owner?: string): CredentialRow {
        const row = this.store.get<CredentialRow>('SELECT id,account_id,label,state,created_at,last_used_at FROM credentials WHERE id=?', id);
        if (!row || (owner !== undefined && row.account_id !== owner)) throw new AppError(404, 'passkey_not_found');
        return row;
    }
    private apply(actor: Actor, kind: AdminAction, target: string, params: Record<string, unknown>): {body: unknown; audit: string} {
        const now = this.auth.now();
        switch (kind) {
        case 'account_create': {
            if (this.store.get<{n: number}>('SELECT count(*) n FROM accounts')!.n >= ACCOUNT_LIMIT) throw new AppError(409, 'account_limit_reached', `The defensive limit of ${ACCOUNT_LIMIT} accounts is reached.`);
            // scope_all (every child, including later ones) can only be granted by an admin who holds it.
            if (params.scopeAll && this.store.get<{scope_all: number}>('SELECT scope_all FROM accounts WHERE id=?', actor.id)?.scope_all !== 1) throw new AppError(403, 'scope_all_required');
            const id = `parent_${randomBytes(6).toString('hex')}`;
            this.store.run('INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id,scope_all) VALUES(?,?,?,?,?,?)', id, params.displayName as string, params.role as string, JSON.stringify(params.personIds), randomBytes(32).toString('base64url'), params.scopeAll ? 1 : 0);
            return {body: {account: this.dto(this.account(id))}, audit: id};
        }
        case 'token_issue': {
            const issueFor = this.managed(actor, target);
            // Order matters: the scope check comes first so an out-of-scope admin never learns which account is the owner.
            this.assertNotOwnerTakeover(actor, target);
            if (!issueFor.active) throw new AppError(409, 'account_disabled');
            // Pending passkeys go first, so they never block a new token against the limit (the transaction rolls back on refusal).
            rejectPendingPasskeys(this.store, target, actor.id, now);
            if (this.store.get<{n: number}>('SELECT count(*) n FROM credentials WHERE account_id=?', target)!.n >= PASSKEYS_PER_ACCOUNT) throw new AppError(409, 'passkey_limit_reached', `This account already has ${PASSKEYS_PER_ACCOUNT} passkeys; remove one first.`);
            // One outstanding token per account: a new one consumes the old.
            const token = randomBytes(32).toString('base64url');
            this.store.run('UPDATE bootstrap_tokens SET consumed=1 WHERE account_id=?', target);
            this.store.run("INSERT INTO bootstrap_tokens(hash,account_id,expires_at,purpose,created_by,label) VALUES(?,?,?,'add_device',?,?)", digest(token), target, now + TOKEN_SECONDS, actor.id, params.label as string);
            return {body: {token, accountId: target, expiresAt: now + TOKEN_SECONDS}, audit: target};
        }
        case 'account_role':
        case 'account_active': {
            this.managed(actor, target);
            this.assertNotOwnerTakeover(actor, target);
            this.assertNotOwnerSelfLockout(actor, target, kind === 'account_role' ? params.role !== 'admin' : params.active === false);
            // Bumping the permission version ends every session of that account at its next request.
            if (kind === 'account_role') this.store.run('UPDATE accounts SET role=?,permission_version=permission_version+1 WHERE id=?', params.role as string, target);
            else this.store.run('UPDATE accounts SET active=?,permission_version=permission_version+1 WHERE id=?', params.active ? 1 : 0, target);
            return {body: {account: this.dto(this.account(target))}, audit: kind === 'account_role' ? `${target}:${params.role}` : `${target}:${params.active ? 'enabled' : 'disabled'}`};
        }
        case 'passkey_approve': {
            const pending = this.credential(target);
            this.managed(actor, pending.account_id);
            this.assertNotOwnerTakeover(actor, pending.account_id);
            if (pending.state !== 'pending') throw new AppError(409, 'passkey_not_pending');
            this.store.run("UPDATE credentials SET state='active' WHERE id=?", target);
            return {body: {passkey: this.passkeys(this.credential(target).account_id).find(p => p.id === target)}, audit: target};
        }
        case 'passkey_revoke':
        case 'own_passkey_revoke': {
            const revoked = this.credential(target, kind === 'own_passkey_revoke' ? actor.id : undefined);
            if (kind === 'passkey_revoke') {
                this.managed(actor, revoked.account_id);
                this.assertNotOwnerTakeover(actor, revoked.account_id);
            }
            // Owner mode: the owner's last active passkey stays (the thrown error rolls back the whole transaction).
            if (revoked.state === 'active' && actor.id === revoked.account_id) {
                const remaining = this.store.get<{n: number}>("SELECT count(*) n FROM credentials WHERE account_id=? AND state='active' AND id<>?", revoked.account_id, target)!.n;
                this.assertNotOwnerSelfLockout(actor, revoked.account_id, remaining === 0);
            }
            this.store.run('DELETE FROM credentials WHERE id=?', target);
            this.store.run('UPDATE sessions SET revoked=1 WHERE credential_id=?', target);
            // A token issued before the removal must not outlive it (it might otherwise meet an account left without passkeys).
            this.store.run('UPDATE bootstrap_tokens SET consumed=1 WHERE account_id=? AND consumed=0', revoked.account_id);
            this.store.run('UPDATE step_ups SET consumed=1 WHERE account_id=? AND consumed=0', revoked.account_id);
            return {body: {revoked: target}, audit: target};
        }
        }
    }
}
