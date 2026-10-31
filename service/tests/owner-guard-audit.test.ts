import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../src/db.ts';
import { seedAccounts } from '../src/fixtures.ts';
import { Auth, digest, issueBootstrap } from '../src/auth.ts';
import { AccountAdmin } from '../src/admin-accounts.ts';
import type { AdminAction } from '../src/admin-accounts.ts';
import type { AuthSession } from '../src/auth.ts';
import { auditFor } from '../src/parent-audit.ts';
import { TestAuthenticator } from './authenticator.ts';

const origin = 'http://localhost:4173';
const code = (expected: string) => (error: {code?: string}) => error.code === expected;
interface Device { key: TestAuthenticator; session: () => AuthSession }

/** jd (admin, alex+blair) is the attacker; bryn is promoted to admin (alex) and is the owner account. */
async function fixture(ownerAccountId: string | undefined, audit = true) {
    const store = new Store(':memory:');
    seedAccounts(store);
    // The demo store has no manifest: attach the one key the audit log reads.
    if (audit) (store as unknown as {config: {auditLog: {enabled: boolean}}}).config = {auditLog: {enabled: true}};
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
const rows = (f: {store: Store}) => f.store.all<Record<string, unknown>>('SELECT actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id').map(r => ({...r}));
const REFUSED = (actor: string) => ({actor_id: actor, action: 'owner_guard_refused', person_id: null, operation_id: null, result: 'refused'});
const credentialOf = (f: {store: Store}, account: string) => f.store.get<{id: string}>("SELECT id FROM credentials WHERE account_id=? AND state='active'", account)!.id;

async function pendingPasskey(f: Awaited<ReturnType<typeof fixture>>): Promise<string> {
    const issued = await f.act(f.setup, f.jd, 'token_issue', 'bryn') as {token: string};
    const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
    const options = await f.auth.registrationOptions({token: issued.token}, browser);
    await f.auth.enroll({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
    return f.store.get<{id: string}>("SELECT id FROM credentials WHERE state='pending'")!.id;
}

test('owner guard audit: another admin refused on each of the five guarded kinds writes exactly one owner_guard_refused row for that admin', async () => {
    const f = await fixture('bryn');
    try {
        const pending = await pendingPasskey(f);
        const cases: [AdminAction, string, Record<string, unknown>][] = [['token_issue', 'bryn', {label: 'x'}], ['account_role', 'bryn', {role: 'parent'}], ['account_active', 'bryn', {active: false}], ['passkey_approve', pending, {}], ['passkey_revoke', credentialOf(f, 'bryn'), {}]];
        let expected = 0;
        for (const [kind, target, params] of cases) {
            await assert.rejects(f.act(f.admin, f.jd, kind, target, params), (e: {code?: string; status?: number}) => e.code === 'owner_account_protected' && e.status === 403, kind);
            expected += 1;
            assert.equal(rows(f).length, expected, kind);
        }
        assert.deepEqual(rows(f), cases.map(() => REFUSED('jd')));
    } finally { f.close(); }
});

test('owner guard audit: owner self-lockout refusals write one row each, with the response unchanged', async () => {
    const f = await fixture('bryn');
    try {
        await assert.rejects(f.act(f.admin, f.bryn, 'account_active', 'bryn', {active: false}), (e: {code?: string; status?: number}) => e.code === 'owner_self_lockout' && e.status === 409);
        await assert.rejects(f.act(f.admin, f.bryn, 'account_role', 'bryn', {role: 'parent'}), (e: {code?: string; status?: number}) => e.code === 'owner_self_lockout' && e.status === 409);
        await assert.rejects(f.act(f.admin, f.bryn, 'passkey_revoke', credentialOf(f, 'bryn')), (e: {code?: string; status?: number}) => e.code === 'owner_self_lockout' && e.status === 409);
        await assert.rejects(f.act(f.admin, f.bryn, 'own_passkey_revoke', credentialOf(f, 'bryn')), (e: {code?: string; status?: number}) => e.code === 'owner_self_lockout' && e.status === 409);
        assert.deepEqual(rows(f), [REFUSED('bryn'), REFUSED('bryn'), REFUSED('bryn'), REFUSED('bryn')]);
    } finally { f.close(); }
});

test('owner guard audit: flag off or absent writes nothing and does no audit reads', async () => {
    const f = await fixture('bryn', false);
    try {
        const sql: string[] = [];
        const get = f.store.get.bind(f.store), run = f.store.run.bind(f.store), all = f.store.all.bind(f.store);
        const watch = (text: string) => { if (/parent_audit/.test(text)) sql.push(text); };
        f.store.get = ((q: string, ...a: never[]) => { watch(q); return get(q, ...a); }) as typeof f.store.get;
        f.store.run = ((q: string, ...a: never[]) => { watch(q); return run(q, ...a); }) as typeof f.store.run;
        f.store.all = ((q: string, ...a: never[]) => { watch(q); return all(q, ...a); }) as typeof f.store.all;
        await assert.rejects(f.act(f.admin, f.jd, 'token_issue', 'bryn', {label: 'x'}), (e: {code?: string}) => e.code === 'owner_account_protected');
        await assert.rejects(f.act(f.admin, f.bryn, 'account_active', 'bryn', {active: false}), (e: {code?: string}) => e.code === 'owner_self_lockout');
        assert.deepEqual(sql, []);
        assert.deepEqual(rows(f), []);
    } finally { f.close(); }
});

test('owner guard audit: a failing audit write never changes the response and logs only the fixed tag', async () => {
    const f = await fixture('bryn');
    const written: string[] = [], original = process.stderr.write;
    try {
        f.store.db.exec('DROP TABLE parent_audit');
        process.stderr.write = ((chunk: string | Uint8Array) => { written.push(String(chunk)); return true; }) as typeof process.stderr.write;
        await assert.rejects(f.act(f.admin, f.jd, 'token_issue', 'bryn', {label: 'x'}), (e: {code?: string; status?: number}) => e.code === 'owner_account_protected' && e.status === 403);
        await assert.rejects(f.act(f.admin, f.bryn, 'account_active', 'bryn', {active: false}), (e: {code?: string; status?: number}) => e.code === 'owner_self_lockout' && e.status === 409);
    } finally { process.stderr.write = original; f.close(); }
    assert.deepEqual(written, ['parent_audit_write_failed\n', 'parent_audit_write_failed\n']);
});

test('owner guard audit: the refused-row cap applies (20 per actor per 60 s)', async () => {
    const f = await fixture('bryn');
    try {
        // The fixture clock is frozen at 1791691200, so 20 rows at that instant fill the window.
        for (let i = 0; i < 20; i++) f.store.run("INSERT INTO parent_audit(at,actor_id,action,result) VALUES(1791691200,'jd','owner_guard_refused','refused')");
        await assert.rejects(f.act(f.admin, f.jd, 'account_active', 'bryn', {active: false}), (e: {code?: string}) => e.code === 'owner_account_protected');
        assert.equal(rows(f).length, 20, 'a 21st refusal in the window is not stored');
        await assert.rejects(f.act(f.admin, f.bryn, 'account_active', 'bryn', {active: false}), (e: {code?: string}) => e.code === 'owner_self_lockout');
        assert.deepEqual(rows(f).slice(-1), [REFUSED('bryn')], 'the cap is per actor');
    } finally { f.close(); }
});

test('owner guard audit: an out-of-scope admin gets the scope error and writes no row; unguarded refusals write none either', async () => {
    const f = await fixture('bryn');
    try {
        for (const [kind, params] of [['token_issue', {label: 'x'}], ['account_role', {role: 'parent'}], ['account_active', {active: false}]] as [AdminAction, Record<string, unknown>][])
            await assert.rejects(f.act(f.admin, f.carol, kind, 'bryn', params), (e: {code?: string}) => e.code === 'outside_scope', kind);
        await assert.rejects(f.act(f.admin, f.carol, 'passkey_revoke', credentialOf(f, 'bryn')), (e: {code?: string}) => e.code === 'outside_scope');
        await assert.rejects(f.act(f.admin, f.jd, 'token_issue', 'nobody', {label: 'x'}), (e: {code?: string}) => e.code === 'account_not_found');
        assert.deepEqual(rows(f), []);
    } finally { f.close(); }
});

test('owner guard audit: rows are visible to admins only (NULL person), never to parents', async () => {
    const f = await fixture('bryn');
    try {
        await assert.rejects(f.act(f.admin, f.jd, 'token_issue', 'bryn', {label: 'x'}), (e: {code?: string}) => e.code === 'owner_account_protected');
        const actor = (role: 'admin' | 'parent', personIds: string[]) => ({id: 'x', displayName: 'X', role, personIds, permissionVersion: '1'});
        const audit = auditFor(f.store);
        assert.deepEqual(audit.list(actor('admin', ['alex'])).entries.map(e => [e.action, e.actorId, e.personId, e.operationId, e.result]), [['owner_guard_refused', 'jd', null, null, 'refused']]);
        assert.deepEqual(audit.list(actor('parent', ['alex', 'blair'])).entries, []);
        assert.deepEqual(audit.list(actor('parent', [])).entries, []);
    } finally { f.close(); }
});

/** A demo database exactly as the code before 013 left it (migrations 001-012, user_version 12), seeded by `seed`, then opened by the current Store. */
function preThirteen(seed: (db: DatabaseSync) => void) {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m013-')), path = join(dir, 'service.sqlite'), db = new DatabaseSync(path);
    for (let n = 1; n <= 12; n++) db.exec(readFileSync(new URL(`../migrations/${String(n).padStart(3, '0')}.sql`, import.meta.url), 'utf8'));
    db.exec('PRAGMA user_version=12'); seed(db); db.close();
    const store = new Store(path);
    return {store, cleanup: () => { store.close(); rmSync(dir, {recursive: true, force: true}); }};
}
const AUDIT = 'SELECT id,at,actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id';
const insertAudit = (db: DatabaseSync, at: number, action: string, op: string | null) => db.prepare('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,?,?,?,?)').run(at, 'parent', action, 'pilot', op, 'applied');

test('migration 013 keeps rows and ids, the three indexes, STRICT and the CHECKs, and admits owner_guard_refused', () => {
    const m = preThirteen(db => { insertAudit(db, 1, 'pause', 'op_one'); insertAudit(db, 2, 'focus_start', null); insertAudit(db, 3, 'resume', 'op_three'); });
    try {
        assert.equal(m.store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 13);
        assert.deepEqual(m.store.all<Record<string, unknown>>(AUDIT).map(r => ({...r})), [
            {id: 1, at: 1, actor_id: 'parent', action: 'pause', person_id: 'pilot', operation_id: 'op_one', result: 'applied'},
            {id: 2, at: 2, actor_id: 'parent', action: 'focus_start', person_id: 'pilot', operation_id: null, result: 'applied'},
            {id: 3, at: 3, actor_id: 'parent', action: 'resume', person_id: 'pilot', operation_id: 'op_three', result: 'applied'}]);
        const indexes = m.store.all<{name: string; sql: string}>("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='parent_audit' AND sql IS NOT NULL ORDER BY name").map(r => ({...r}));
        assert.deepEqual(indexes.map(i => i.name), ['parent_audit_at', 'parent_audit_once', 'parent_audit_person']);
        assert.match(indexes.find(i => i.name === 'parent_audit_once')!.sql, /^CREATE UNIQUE INDEX .* WHERE operation_id IS NOT NULL AND person_id IS NOT NULL$/);
        assert.equal(m.store.get<{strict: number}>("SELECT strict FROM pragma_table_list WHERE name='parent_audit'")!.strict, 1, 'STRICT survives');
        const insert = (action: string, person: string | null, op: string | null = null, result = 'applied') => m.store.run('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(9,?,?,?,?,?)', 'parent', action, person, op, result);
        assert.throws(() => insert('pause', 'pilot', 'op_one'), /UNIQUE/, 'the partial unique index still de-duplicates a replay');
        assert.throws(() => insert('owner_guard_unknown', null), /CHECK/);
        assert.throws(() => insert('pause', null, null, 'maybe'), /CHECK/);
        insert('owner_guard_refused', null, null, 'refused'); insert('focus_start', 'pilot', 'op_focus');
    } finally { m.cleanup(); }
});

test('migration 013 carries the AUTOINCREMENT counter: ids freed by pruning are never reused (seq > max(id))', () => {
    const m = preThirteen(db => { for (const at of [1, 2, 3]) insertAudit(db, at, 'pause', null); db.exec('DELETE FROM parent_audit WHERE id>1'); });
    try {
        m.store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'jd', 'owner_guard_refused', 'refused');
        assert.deepEqual(m.store.all<{id: number}>(AUDIT).map(r => r.id), [1, 4], 'the counter was 3 before the rebuild, so the next id is 4, not 2');
        assert.equal(m.store.get<{n: number}>("SELECT count(*) n FROM sqlite_sequence WHERE name LIKE 'parent_audit%'")!.n, 1);
    } finally { m.cleanup(); }
});

test('migration 013 on an empty pre-013 audit table leaves a working table', () => {
    const m = preThirteen(() => {});
    try {
        m.store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'jd', 'owner_guard_refused', 'refused');
        assert.deepEqual(m.store.all<{id: number}>(AUDIT).map(r => r.id), [1]);
    } finally { m.cleanup(); }
});
