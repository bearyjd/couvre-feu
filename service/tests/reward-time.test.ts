import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { actor, integrationFixture } from './fixtures/integration.ts';
import { world } from './fixtures/grant-world.ts';
import { TestAuthenticator } from './authenticator.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { AUDIT_ACTIONS } from '../src/parent-audit.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';

const KEY = 'reward_key_1234567890';
type W = Awaited<ReturnType<typeof world>>;
type AuditRow = {actor_id: string; action: string; person_id: string | null; operation_id: string | null; result: string};

/** Flags on by default: audit log and reward time. */
async function rewardWorld(over: Partial<RouterPolicy> = {}, flags = {reward: true, audit: true}) {
    const w = await world(over);
    if (flags.reward) w.f.config.rewardTime = {enabled: true};
    if (flags.audit) w.f.config.auditLog = {enabled: true};
    const token = () => w.f.policy.people(actor).revisionToken!;
    const reward = (minutes: unknown, key = KEY, who: Actor = actor, person = 'pilot') => w.grants.reward(who, person, minutes, token(), key);
    const routerTime = () => w.f.store.observation().value!.routerTime;
    /** A grant that is queued, dispatched and observed, so the router reports it in force. */
    const grantInForce = async (minutes: number, key = 'tr-seed') => {
        const receipt = w.grants.grant(actor, 'pilot', minutes, token(), key);
        await w.dispatch(receipt.operationId);
        return receipt;
    };
    const untilOf = (operationId: string) => (JSON.parse(w.f.store.get<{payload_json: string}>('SELECT payload_json FROM operations WHERE id=?', operationId)!.payload_json) as RouterPolicy).allowances?.find(a => a.person === 'pilot')?.until;
    const audit = () => w.f.store.all<AuditRow>('SELECT actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id').map(r => ({...r}));
    const ops = () => w.f.store.get<{n: number}>("SELECT count(*) n FROM operations WHERE action='allow'")!.n;
    return {w, token, reward, routerTime, grantInForce, untilOf, audit, ops};
}
const code = (c: string) => (e: unknown) => e instanceof AppError && e.code === c;

test('reward alone is a new allowance of exactly 15 or 30 minutes from router time', async () => {
    for (const minutes of [15, 30]) {
        const r = await rewardWorld();
        try {
            const out = r.reward(minutes), t = r.routerTime();
            assert.equal(out.status, 202);
            assert.equal(r.untilOf(out.result.operation.id), t + minutes * 60);
            assert.equal(out.result.operation.action, 'allow');
        } finally { r.w.f.cleanup(); }
    }
});

test('cap boundary: grant 45 + reward 15 = 60 is accepted, extending the grant to exactly 60 minutes from now', async () => {
    const r = await rewardWorld();
    try {
        await r.grantInForce(45);
        const t = r.routerTime(), out = r.reward(15);
        assert.equal(r.untilOf(out.result.operation.id), t + 3600, 'remaining grant + reward, from router time');
    } finally { r.w.f.cleanup(); }
});

test('cap boundary: grant 45 + reward 30 is refused with reward_cap_exceeded, nothing queued, audited as refused', async () => {
    const r = await rewardWorld();
    try {
        await r.grantInForce(45);
        const before = r.ops();
        assert.throws(() => r.reward(30), (e: unknown) => e instanceof AppError && e.status === 409 && e.code === 'reward_cap_exceeded');
        assert.equal(r.ops(), before, 'no silent clamp: no operation is queued');
        assert.deepEqual(r.audit(), [{actor_id: 'operator', action: 'reward_add', person_id: 'pilot', operation_id: null, result: 'refused'}]);
    } finally { r.w.f.cleanup(); }
});

test('the remaining grant is measured at router time: elapsed minutes make room', async () => {
    const r = await rewardWorld();
    try {
        await r.grantInForce(45);
        r.w.f.advance(600); await r.w.f.observe();
        assert.throws(() => r.reward(30), code('reward_cap_exceeded'), '35 min left + 30 > 60');
        const t = r.routerTime(), out = r.reward(15);
        assert.equal(r.untilOf(out.result.operation.id), t + 35 * 60 + 15 * 60, '35 min left + 15, still within the cap');
    } finally { r.w.f.cleanup(); }
});

test('an expired allowance counts as no grant: the reward alone is the new allowance', async () => {
    const r = await rewardWorld();
    try {
        await r.grantInForce(15);
        r.w.f.advance(1200); await r.w.f.observe();
        const t = r.routerTime(), out = r.reward(30);
        assert.equal(r.untilOf(out.result.operation.id), t + 1800);
    } finally { r.w.f.cleanup(); }
});

test('an allowance already beyond the cap (or the 4 h router horizon) is never lengthened', async () => {
    const r = await rewardWorld({allowances: [{person: 'pilot', until: 1791691200 + 20000}]});
    try {
        assert.throws(() => r.reward(15), code('reward_cap_exceeded'));
        assert.equal(r.ops(), 0);
    } finally { r.w.f.cleanup(); }
});

test('only 15 and 30 minutes are accepted', async () => {
    const r = await rewardWorld();
    try {
        for (const bad of [0, 1, 10, 20, 45, 60, -15, 15.5, '15', null, undefined, NaN]) assert.throws(() => r.reward(bad), code('invalid_minutes'), String(bad));
        assert.equal(r.ops(), 0);
        assert.equal(r.audit().every(row => row.result === 'refused'), true);
    } finally { r.w.f.cleanup(); }
});

test('a paused child with no active allowance is not rewarded: the pause wins', async () => {
    const r = await rewardWorld({pauses: [{person: 'pilot', until: 0}]});
    try {
        assert.throws(() => r.reward(15), (e: unknown) => e instanceof AppError && e.status === 409 && e.code === 'child_paused');
        assert.equal(r.ops(), 0);
    } finally { r.w.f.cleanup(); }
});

test('a paused child whose approved grant is in force: the reward extends it', async () => {
    const r = await rewardWorld({pauses: [{person: 'pilot', until: 0}], allowances: [{person: 'pilot', until: 1791691200 + 30 * 60}]});
    try {
        const t = r.routerTime(), out = r.reward(15);
        assert.equal(r.untilOf(out.result.operation.id), t + 45 * 60, '30 min left + 15, from router time');
    } finally { r.w.f.cleanup(); }
});

test('a paused child whose allowance is in force and would exceed the cap is refused with reward_cap_exceeded', async () => {
    const r = await rewardWorld({pauses: [{person: 'pilot', until: 0}], allowances: [{person: 'pilot', until: 1791691200 + 45 * 60}]});
    try {
        assert.throws(() => r.reward(30), code('reward_cap_exceeded'));
        assert.equal(r.ops(), 0);
    } finally { r.w.f.cleanup(); }
});

test('a paused child whose allowance has already expired at router time is refused with child_paused', async () => {
    const r = await rewardWorld({pauses: [{person: 'pilot', until: 0}], allowances: [{person: 'pilot', until: 1791691200 - 60}]});
    try { assert.throws(() => r.reward(15), code('child_paused')); } finally { r.w.f.cleanup(); }
});

test('cap arithmetic uses the router observation, not the client clock (router 25 s behind: 45 min grant + 15 is over the cap)', async () => {
    // The worker only admits observations within [-30 s, +1 s] of the client clock, so the skew available is "router behind".
    for (const skew of [0, -25]) {
        const r = await rewardWorld();
        try {
            await r.grantInForce(45);
            const grantUntil = r.routerTime() + 45 * 60;
            r.w.f.router.transform = o => ({...o, routerTime: o.routerTime + skew});
            r.w.f.advance(20); await r.w.f.observe();
            const t = r.routerTime();
            assert.equal(t, r.w.f.now() + skew, 'precondition: the observation is skewed from the client clock by the given amount');
            if (skew === 0) assert.equal(r.untilOf(r.reward(15).result.operation.id), grantUntil + 900, 'client clock = router clock: 44m40s left + 15 fits');
            else { assert.throws(() => r.reward(15), code('reward_cap_exceeded'), '45m05s left by the router + 15 > 60'); assert.equal(r.ops(), 1, 'only the seed grant is queued'); }
        } finally { r.w.f.cleanup(); }
    }
});

test('pause ends reward and grant together', async () => {
    const r = await rewardWorld();
    try {
        await r.grantInForce(30);
        const out = r.reward(15);
        await r.w.dispatch(out.result.operation.id);
        assert.ok(r.w.f.router.policy.allowances?.some(a => a.person === 'pilot'), 'precondition: the extended allowance is on the router');
        const paused = r.w.f.policy.mutate(actor, 'pilot', 'pause', {until: 0}, r.token(), 'pause_key_1234567890');
        const next = JSON.parse(r.w.f.store.get<{payload_json: string}>('SELECT payload_json FROM operations WHERE id=?', paused.result.operation.id)!.payload_json) as RouterPolicy;
        assert.equal((next.allowances ?? []).some(a => a.person === 'pilot'), false, 'no allowance survives a pause');
        assert.deepEqual(next.pauses.filter(p => p.person === 'pilot'), [{person: 'pilot', until: 0}]);
    } finally { r.w.f.cleanup(); }
});

test('replay of the same key returns the same operation, queues once and audits once; a different payload under the key conflicts', async () => {
    const r = await rewardWorld();
    try {
        const pre = r.token(), first = r.w.grants.reward(actor, 'pilot', 15, pre, KEY), second = r.w.grants.reward(actor, 'pilot', 15, pre, KEY);
        assert.equal(second.result.operation.id, first.result.operation.id);
        assert.equal(r.ops(), 1);
        assert.throws(() => r.w.grants.reward(actor, 'pilot', 30, pre, KEY), code('idempotency_payload_conflict'));
        assert.deepEqual(r.audit().filter(a => a.result === 'applied'), [{actor_id: 'operator', action: 'reward_add', person_id: 'pilot', operation_id: first.result.operation.id, result: 'applied'}]);
    } finally { r.w.f.cleanup(); }
});

test('the audit row is written once with reward_add, the acting parent, the child and the operation; ids and enums only', async () => {
    const r = await rewardWorld();
    try {
        const out = r.reward(30);
        assert.deepEqual(r.audit(), [{actor_id: 'operator', action: 'reward_add', person_id: 'pilot', operation_id: out.result.operation.id, result: 'applied'}]);
        assert.ok((AUDIT_ACTIONS as readonly string[]).includes('reward_add'));
        assert.doesNotMatch(JSON.stringify(r.w.f.store.all('SELECT * FROM parent_audit')), /minutes|homework/i);
    } finally { r.w.f.cleanup(); }
});

test('audit off: the reward still works and writes no audit row', async () => {
    const r = await rewardWorld({}, {reward: true, audit: false});
    try { r.reward(15); assert.equal(r.audit().length, 0); assert.equal(r.ops(), 1); } finally { r.w.f.cleanup(); }
});

test('flag off (absent or false): 404 route_not_found, nothing queued, nothing audited', async () => {
    for (const flag of [undefined, {enabled: false}]) {
        const r = await rewardWorld({}, {reward: false, audit: true});
        try {
            if (flag) r.w.f.config.rewardTime = flag;
            assert.throws(() => r.reward(15), (e: unknown) => e instanceof AppError && e.status === 404 && e.code === 'route_not_found');
            assert.equal(r.ops(), 0); assert.equal(r.audit().length, 0);
        } finally { r.w.f.cleanup(); }
    }
});

test('out-of-scope parent: 404 person_not_found and no audit row', async () => {
    const r = await rewardWorld();
    try {
        const outsider: Actor = {...actor, id: 'parent', role: 'parent', personIds: []};
        assert.throws(() => r.reward(15, KEY, outsider), (e: unknown) => e instanceof AppError && e.status === 404 && e.code === 'person_not_found');
        assert.equal(r.ops(), 0); assert.equal(r.audit().length, 0);
    } finally { r.w.f.cleanup(); }
});

test('a reward needs the caller\'s revision precondition and a client idempotency key', async () => {
    const r = await rewardWorld();
    try {
        assert.throws(() => r.w.grants.reward(actor, 'pilot', 15, undefined, KEY), code('revision_precondition_required'));
        assert.throws(() => r.w.grants.reward(actor, 'pilot', 15, r.token(), 'short'), code('idempotency_key_required'));
        assert.throws(() => r.w.grants.reward(actor, 'pilot', 15, r.token(), 'tr-' + 'a'.repeat(20)), code('idempotency_key_required'), 'the grant key namespace is not shared');
        assert.equal(r.ops(), 0);
    } finally { r.w.f.cleanup(); }
});

/** A demo database exactly as the code before 011 left it (migrations 001-010, user_version 10), seeded by `seed`, then opened by the current Store. */
function preEleven(seed: (db: DatabaseSync) => void) {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m011-')), path = join(dir, 'service.sqlite'), db = new DatabaseSync(path);
    for (const n of ['001', '002', '003', '004', '005', '006', '007', '008', '009', '010']) db.exec(readFileSync(new URL(`../migrations/${n}.sql`, import.meta.url), 'utf8'));
    db.exec('PRAGMA user_version=10'); seed(db); db.close();
    const store = new Store(path);
    return {store, cleanup: () => { store.close(); rmSync(dir, {recursive: true, force: true}); }};
}
const AUDIT = 'SELECT id,at,actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id';
const insertAudit = (db: DatabaseSync, at: number, action: string, op: string | null) => db.prepare('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,?,?,?,?)').run(at, 'parent', action, 'pilot', op, 'applied');

test('migration 011 on a seeded pre-011 database keeps rows and ids, the three indexes, STRICT and the CHECKs, and admits reward_add', () => {
    const m = preEleven(db => { insertAudit(db, 1, 'pause', 'op_one'); insertAudit(db, 2, 'grant_approve', null); insertAudit(db, 3, 'resume', 'op_three'); });
    try {
        assert.equal(m.store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 12, 'opened by the current Store, so 012 has run too');
        assert.deepEqual(m.store.all<Record<string, unknown>>(AUDIT).map(r => ({...r})), [
            {id: 1, at: 1, actor_id: 'parent', action: 'pause', person_id: 'pilot', operation_id: 'op_one', result: 'applied'},
            {id: 2, at: 2, actor_id: 'parent', action: 'grant_approve', person_id: 'pilot', operation_id: null, result: 'applied'},
            {id: 3, at: 3, actor_id: 'parent', action: 'resume', person_id: 'pilot', operation_id: 'op_three', result: 'applied'}]);
        const indexes = m.store.all<{name: string; sql: string}>("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='parent_audit' AND sql IS NOT NULL ORDER BY name").map(r => ({...r}));
        assert.deepEqual(indexes.map(i => i.name), ['parent_audit_at', 'parent_audit_once', 'parent_audit_person']);
        assert.match(indexes.find(i => i.name === 'parent_audit_once')!.sql, /^CREATE UNIQUE INDEX .* WHERE operation_id IS NOT NULL AND person_id IS NOT NULL$/);
        assert.equal(m.store.get<{strict: number}>("SELECT strict FROM pragma_table_list WHERE name='parent_audit'")!.strict, 1, 'STRICT survives');
        const insert = (action: string, op: string | null = null, result = 'applied') => m.store.run('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(9,?,?,?,?,?)', 'parent', action, 'pilot', op, result);
        assert.throws(() => insert('pause', 'op_one'), /UNIQUE/, 'the partial unique index still de-duplicates a replay');
        insert('pause', null); insert('pause', null);
        assert.throws(() => insert('reward_remove'), /CHECK/);
        assert.throws(() => insert('pause', null, 'maybe'), /CHECK/);
        assert.throws(() => m.store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', '', 'pause', 'applied'), /CHECK/);
        assert.throws(() => m.store.run("INSERT INTO parent_audit(at,actor_id,action,result) VALUES('x','parent','pause','applied')"), /datatype|STRICT|cannot store/i);
        insert('reward_add', 'op_reward');
    } finally { m.cleanup(); }
});

test('migration 011 carries the AUTOINCREMENT counter: ids freed by pruning are never reused', () => {
    const m = preEleven(db => { for (const at of [1, 2, 3]) insertAudit(db, at, 'pause', null); db.exec('DELETE FROM parent_audit WHERE id>1'); });
    try {
        assert.deepEqual(m.store.all<{id: number}>(AUDIT).map(r => r.id), [1]);
        m.store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'parent', 'reward_add', 'applied');
        assert.deepEqual(m.store.all<{id: number}>(AUDIT).map(r => r.id), [1, 4], 'the counter was 3 before the rebuild, so the next id is 4, not 2');
        assert.equal(m.store.get<{n: number}>("SELECT count(*) n FROM sqlite_sequence WHERE name LIKE 'parent_audit%'")!.n, 1, 'one counter row, under the final table name');
    } finally { m.cleanup(); }
});

test('migration 011 on an empty pre-011 audit table leaves a working table (no counter to carry)', () => {
    const m = preEleven(() => {});
    try {
        m.store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'parent', 'reward_add', 'applied');
        assert.deepEqual(m.store.all<{id: number}>(AUDIT).map(r => r.id), [1]);
    } finally { m.cleanup(); }
});

// ---- HTTP: CSRF, scope, gate, path-only ----
async function session(f: W['f'], o: string, account: string) {
    const cookies = new Map<string, string>(); let csrf = '';
    const send = async (method: string, path: string, input?: unknown, headers: Record<string, string> = {}) => {
        const response = await fetch(o + path, {method, headers: {Origin: o, 'Content-Type': 'application/json', ...(method === 'POST' ? {'X-CSRF-Token': csrf} : {}), ...headers, Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; ')}, ...(input === undefined ? {} : {body: JSON.stringify(input)})});
        for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); cookies.set(k, v); }
        return {status: response.status, body: await response.json() as Record<string, any>, location: response.headers.get('location')};
    };
    const key = new TestAuthenticator(), options = await send('POST', '/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
    const verified = await send('POST', '/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, o)});
    assert.equal(verified.status, 200); csrf = verified.body.csrfToken;
    const token = async () => (await send('GET', '/people')).body.revisionToken as string;
    const post = async (path: string, input: unknown, idem = KEY, ifMatch?: string) => send('POST', path, input, {'If-Match': ifMatch ?? await token(), 'Idempotency-Key': idem});
    return {send, post, token, setCsrf: (v: string) => { csrf = v; }};
}
/** Serves the app with the config as it is now (the gate is read from it at startup). */
async function serve(r: Awaited<ReturnType<typeof rewardWorld>>, port: number) {
    const o = `http://localhost:${port}`, f = r.w.f;
    const auth = new Auth(f.store, o, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: o, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    return {o, close: async () => { server.close(); await once(server, 'close'); }};
}
let ports = 28000 + process.pid % 5000;

test('HTTP: POST /people/:id/reward queues one allowance (202 + Location), is idempotent and audited once; GET, query strings, extra fields and bad CSRF are refused', async () => {
    const r = await rewardWorld(); r.w.f.config.timeRequests = {mode: 'parents'};
    const s = await serve(r, ports++);
    try {
        const who = await session(r.w.f, s.o, 'operator'), pre = await who.token();
        const first = await who.post('/people/pilot/reward', {minutes: 15}, KEY, pre);
        assert.equal(first.status, 202);
        assert.match(first.location ?? '', /^\/operations\//);
        const replay = await who.post('/people/pilot/reward', {minutes: 15}, KEY, pre);
        assert.equal(replay.body.operation.id, first.body.operation.id);
        assert.equal(r.ops(), 1); assert.equal(r.audit().length, 1);
        assert.equal((await who.send('GET', '/people/pilot/reward')).status, 404);
        assert.equal((await who.post('/people/pilot/reward?minutes=30', {minutes: 30}, 'another_key_1234567')).status >= 400, true, 'the server rejects query strings');
        assert.equal((await who.post('/people/pilot/reward', {minutes: 15, note: 'x'}, 'another_key_1234567')).status, 400, 'no extra fields, no free text');
        who.setCsrf('wrong');
        assert.equal((await who.post('/people/pilot/reward', {minutes: 15}, 'third_key_12345678')).status, 403, 'CSRF is enforced');
        assert.equal(r.ops(), 1);
    } finally { await s.close(); r.w.f.cleanup(); }
});

test('HTTP: flag off, time requests off, out-of-scope child and the owner-mode gate are all 404 before any audit row', async () => {
    const cases: {name: string; reward: boolean; mode?: 'off' | 'owner' | 'parents'; account: string; person: string; status: number}[] = [
        {name: 'flag off', reward: false, mode: 'parents', account: 'operator', person: 'pilot', status: 404},
        {name: 'time requests off (F1 gate)', reward: true, mode: 'off', account: 'operator', person: 'pilot', status: 404},
        {name: 'time requests absent (default off)', reward: true, account: 'operator', person: 'pilot', status: 404},
        {name: 'out-of-scope child', reward: true, mode: 'parents', account: 'parent', person: 'nobody', status: 404},
        {name: 'owner mode, non-owner parent', reward: true, mode: 'owner', account: 'parent', person: 'pilot', status: 404},
        {name: 'owner mode, the owner', reward: true, mode: 'owner', account: 'operator', person: 'pilot', status: 202},
        {name: 'parents mode, a scoped parent', reward: true, mode: 'parents', account: 'parent', person: 'pilot', status: 202}];
    for (const c of cases) {
        const r = await rewardWorld({}, {reward: c.reward, audit: true});
        if (c.mode) r.w.f.config.timeRequests = {mode: c.mode};
        if (c.mode === 'owner') r.w.f.config.ownerAccountId = 'operator';
        const s = await serve(r, ports++);
        try {
            const who = await session(r.w.f, s.o, c.account);
            const out = await who.post(`/people/${c.person}/reward`, {minutes: 15});
            assert.equal(out.status, c.status, c.name);
            if (c.status === 404) { assert.equal(r.audit().length, 0, `${c.name}: no audit row`); assert.equal(r.ops(), 0, c.name); }
            else assert.equal(r.audit().length, 1, c.name);
        } finally { await s.close(); r.w.f.cleanup(); }
    }
});
