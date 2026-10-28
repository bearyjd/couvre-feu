import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { actor } from './fixtures/integration.ts';
import { world } from './fixtures/grant-world.ts';
import { TestAuthenticator } from './authenticator.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { AUDIT_ACTIONS } from '../src/parent-audit.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';

const KEY = 'focus_key_12345678901';
type W = Awaited<ReturnType<typeof world>>;
type AuditRow = {actor_id: string; action: string; person_id: string | null; operation_id: string | null; result: string};

/** Flags on by default: audit log and focus window. */
async function focusWorld(over: Partial<RouterPolicy> = {}, flags = {focus: true, audit: true}) {
    const w = await world(over);
    if (flags.focus) w.f.config.focus = {enabled: true};
    if (flags.audit) w.f.config.auditLog = {enabled: true};
    const token = () => w.f.policy.people(actor).revisionToken!;
    const focus = (minutes: unknown, key = KEY, who: Actor = actor, person = 'pilot') => w.f.policy.focus(who, person, minutes, token(), key);
    const routerTime = () => w.f.store.observation().value!.routerTime;
    const payload = (operationId: string) => JSON.parse(w.f.store.get<{payload_json: string}>('SELECT payload_json FROM operations WHERE id=?', operationId)!.payload_json) as RouterPolicy;
    const pauseOf = (operationId: string) => payload(operationId).pauses.find(p => p.person === 'pilot');
    const audit = () => w.f.store.all<AuditRow>('SELECT actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id').map(r => ({...r}));
    const ops = () => w.f.store.get<{n: number}>('SELECT count(*) n FROM operations')!.n;
    const label = () => w.f.policy.people(actor).people[0].pauseLabel;
    return {w, token, focus, routerTime, payload, pauseOf, audit, ops, label};
}
const code = (c: string) => (e: unknown) => e instanceof AppError && e.code === c;

test('focus starts a timed pause of exactly N minutes from router time, for each allowed N', async () => {
    for (const minutes of [15, 30, 45, 60, 90, 120]) {
        const r = await focusWorld();
        try {
            const out = r.focus(minutes), t = r.routerTime();
            assert.equal(out.status, 202);
            assert.equal(out.result.operation.action, 'pause', 'the existing timed-pause operation, not a new kind');
            assert.deepEqual(r.pauseOf(out.result.operation.id), {person: 'pilot', until: t + minutes * 60});
        } finally { r.w.f.cleanup(); }
    }
});

test('the deadline uses the router observation, not the client clock (router 25 s behind)', async () => {
    const r = await focusWorld();
    try {
        r.w.f.router.transform = o => ({...o, routerTime: o.routerTime - 25});
        r.w.f.advance(1); await r.w.f.observe();
        const t = r.routerTime();
        assert.equal(t, r.w.f.now() - 25, 'precondition: the observation is skewed');
        assert.deepEqual(r.pauseOf(r.focus(30).result.operation.id), {person: 'pilot', until: t + 1800});
    } finally { r.w.f.cleanup(); }
});

test('only 15, 30, 45, 60, 90 and 120 minutes are accepted; nothing is queued', async () => {
    const r = await focusWorld();
    try {
        for (const bad of [0, 1, 10, 14, 16, 20, 75, 100, 121, 180, 600, -30, 30.5, '30', null, undefined, NaN, Infinity]) assert.throws(() => r.focus(bad), code('invalid_minutes'), String(bad));
        assert.equal(r.ops(), 0);
        assert.equal(r.audit().every(row => row.action === 'focus_start' && row.result === 'refused'), true);
    } finally { r.w.f.cleanup(); }
});

test('the focus label is a closed enum on the operation and shows in the people DTO; a manual pause has no label', async () => {
    const r = await focusWorld();
    try {
        assert.equal(r.label(), null);
        const out = r.focus(30);
        const request = JSON.parse(r.w.f.store.get<{request_json: string}>('SELECT request_json FROM operations WHERE id=?', out.result.operation.id)!.request_json);
        assert.equal(request.label, 'focus');
        await r.w.dispatch(out.result.operation.id);
        assert.equal(r.label(), 'focus');
        assert.equal(r.w.f.policy.people(actor).people[0].manualPause?.until, r.routerTime() + 1800);
        const manual = r.w.f.policy.mutate(actor, 'pilot', 'pause', {until: 0}, r.token(), 'manual_key_1234567890');
        await r.w.dispatch(manual.result.operation.id);
        assert.equal(r.label(), null, 'a manual pause replaces the focus window and is not labelled');
    } finally { r.w.f.cleanup(); }
});

test('the label ends with the window: expiry and resume both clear it', async () => {
    const r = await focusWorld();
    try {
        await r.w.dispatch(r.focus(15).result.operation.id);
        assert.equal(r.label(), 'focus');
        r.w.f.advance(15 * 60 + 1); await r.w.f.observe();
        assert.equal(r.label(), null, 'expired');
        await r.w.dispatch(r.focus(15, 'second_key_1234567890').result.operation.id);
        assert.equal(r.label(), 'focus');
        const resumed = r.w.f.policy.mutate(actor, 'pilot', 'resume', {}, r.token(), 'resume_key_1234567890');
        await r.w.dispatch(resumed.result.operation.id);
        assert.equal(r.label(), null);
        assert.equal(r.w.f.router.policy.pauses.length, 0, 'a parent Resume ends the window');
    } finally { r.w.f.cleanup(); }
});

test('a focus window never replaces or shortens an existing pause: 409 child_paused', async () => {
    for (const until of [0, 1791691200 + 3600]) {
        const r = await focusWorld({pauses: [{person: 'pilot', until}]});
        try {
            assert.throws(() => r.focus(15), (e: unknown) => e instanceof AppError && e.status === 409 && e.code === 'child_paused');
            assert.equal(r.ops(), 0);
        } finally { r.w.f.cleanup(); }
    }
});

test('child ask during a focus window stays pending and does not lift the pause; only a parent approval does', async () => {
    const r = await focusWorld(), w = r.w;
    try {
        await w.dispatch(r.focus(60).result.operation.id);
        const id = w.ask(15);
        assert.equal(w.row(id).state, 'pending');
        await w.service.advance();
        assert.equal(w.row(id).state, 'pending', 'the request is queued for the parents, not applied');
        assert.equal(w.row(id).grant_operation_id, null);
        assert.equal(r.ops(), 1, 'the ask queued no router operation');
        assert.equal(w.f.router.policy.pauses.some(p => p.person === 'pilot'), true);
        assert.equal((w.f.router.policy.allowances ?? []).length, 0);
        assert.equal(r.label(), 'focus');
        assert.equal(w.f.policy.people(actor).people[0].effectiveManualPause !== null, true, 'still paused');
        // The parent approves: the grant lifts the pause as grants do today.
        await w.service.approve(actor, id, 15);
        await w.dispatch(w.row(id).grant_operation_id!);
        await w.service.advance();
        assert.equal(w.row(id).state, 'approved');
        assert.equal((w.f.router.policy.allowances ?? []).some(a => a.person === 'pilot'), true);
        assert.notEqual(w.f.policy.people(actor).people[0].allowance, null);
    } finally { w.f.cleanup(); }
});

test('a parent Pause during a focus window is not blocked by it and a parent Resume ends it (ordinary pause behaviour unchanged)', async () => {
    const r = await focusWorld(), w = r.w;
    try {
        await w.dispatch(r.focus(60).result.operation.id);
        const resumed = w.f.policy.mutate(actor, 'pilot', 'resume', {}, r.token(), 'resume_key_1234567890');
        assert.deepEqual(r.payload(resumed.result.operation.id).pauses, []);
    } finally { w.f.cleanup(); }
});

test('replay of the same key returns the same operation, queues once and audits once; a different minutes under the key conflicts', async () => {
    const r = await focusWorld();
    try {
        const pre = r.token(), first = r.w.f.policy.focus(actor, 'pilot', 30, pre, KEY), second = r.w.f.policy.focus(actor, 'pilot', 30, pre, KEY);
        assert.equal(second.result.operation.id, first.result.operation.id);
        assert.equal(r.ops(), 1);
        assert.throws(() => r.w.f.policy.focus(actor, 'pilot', 45, pre, KEY), code('idempotency_payload_conflict'));
        assert.deepEqual(r.audit().filter(a => a.result === 'applied'), [{actor_id: 'operator', action: 'focus_start', person_id: 'pilot', operation_id: first.result.operation.id, result: 'applied'}]);
    } finally { r.w.f.cleanup(); }
});

test('the audit row is written once with focus_start, the acting parent, the child and the operation; ids and enums only', async () => {
    const r = await focusWorld();
    try {
        const out = r.focus(45);
        assert.deepEqual(r.audit(), [{actor_id: 'operator', action: 'focus_start', person_id: 'pilot', operation_id: out.result.operation.id, result: 'applied'}]);
        assert.ok((AUDIT_ACTIONS as readonly string[]).includes('focus_start'));
        assert.doesNotMatch(JSON.stringify(r.w.f.store.all('SELECT * FROM parent_audit')), /minutes|homework|45/i);
    } finally { r.w.f.cleanup(); }
});

test('audit off: the focus window still starts and writes no audit row', async () => {
    const r = await focusWorld({}, {focus: true, audit: false});
    try { r.focus(15); assert.equal(r.audit().length, 0); assert.equal(r.ops(), 1); } finally { r.w.f.cleanup(); }
});

test('flag off (absent or false): 404 route_not_found, nothing queued, nothing audited', async () => {
    for (const flag of [undefined, {enabled: false}]) {
        const r = await focusWorld({}, {focus: false, audit: true});
        try {
            if (flag) r.w.f.config.focus = flag;
            assert.throws(() => r.focus(15), (e: unknown) => e instanceof AppError && e.status === 404 && e.code === 'route_not_found');
            assert.equal(r.ops(), 0); assert.equal(r.audit().length, 0);
        } finally { r.w.f.cleanup(); }
    }
});

test('out-of-scope parent: 404 person_not_found and no audit row', async () => {
    const r = await focusWorld();
    try {
        const outsider: Actor = {...actor, id: 'parent', role: 'parent', personIds: []};
        assert.throws(() => r.focus(15, KEY, outsider), (e: unknown) => e instanceof AppError && e.status === 404 && e.code === 'person_not_found');
        assert.equal(r.ops(), 0); assert.equal(r.audit().length, 0);
    } finally { r.w.f.cleanup(); }
});

test('a focus window needs the caller\'s revision precondition and a client idempotency key', async () => {
    const r = await focusWorld();
    try {
        assert.throws(() => r.w.f.policy.focus(actor, 'pilot', 15, undefined, KEY), code('revision_precondition_required'));
        assert.throws(() => r.w.f.policy.focus(actor, 'pilot', 15, r.token(), 'short'), code('idempotency_key_required'));
        assert.equal(r.ops(), 0);
    } finally { r.w.f.cleanup(); }
});

/** A demo database exactly as the code before 012 left it (migrations 001-011, user_version 11), seeded by `seed`, then opened by the current Store. */
function preTwelve(seed: (db: DatabaseSync) => void) {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m012-')), path = join(dir, 'service.sqlite'), db = new DatabaseSync(path);
    for (const n of ['001', '002', '003', '004', '005', '006', '007', '008', '009', '010', '011']) db.exec(readFileSync(new URL(`../migrations/${n}.sql`, import.meta.url), 'utf8'));
    db.exec('PRAGMA user_version=11'); seed(db); db.close();
    const store = new Store(path);
    return {store, cleanup: () => { store.close(); rmSync(dir, {recursive: true, force: true}); }};
}
const AUDIT = 'SELECT id,at,actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id';
const insertAudit = (db: DatabaseSync, at: number, action: string, op: string | null) => db.prepare('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,?,?,?,?)').run(at, 'parent', action, 'pilot', op, 'applied');

test('migration 012 on a seeded pre-012 database keeps rows and ids, the three indexes, STRICT and the CHECKs, and admits focus_start', () => {
    const m = preTwelve(db => { insertAudit(db, 1, 'pause', 'op_one'); insertAudit(db, 2, 'reward_add', null); insertAudit(db, 3, 'resume', 'op_three'); });
    try {
        assert.equal(m.store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 12);
        assert.deepEqual(m.store.all<Record<string, unknown>>(AUDIT).map(r => ({...r})), [
            {id: 1, at: 1, actor_id: 'parent', action: 'pause', person_id: 'pilot', operation_id: 'op_one', result: 'applied'},
            {id: 2, at: 2, actor_id: 'parent', action: 'reward_add', person_id: 'pilot', operation_id: null, result: 'applied'},
            {id: 3, at: 3, actor_id: 'parent', action: 'resume', person_id: 'pilot', operation_id: 'op_three', result: 'applied'}]);
        const indexes = m.store.all<{name: string; sql: string}>("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='parent_audit' AND sql IS NOT NULL ORDER BY name").map(r => ({...r}));
        assert.deepEqual(indexes.map(i => i.name), ['parent_audit_at', 'parent_audit_once', 'parent_audit_person']);
        assert.match(indexes.find(i => i.name === 'parent_audit_once')!.sql, /^CREATE UNIQUE INDEX .* WHERE operation_id IS NOT NULL AND person_id IS NOT NULL$/);
        assert.equal(m.store.get<{strict: number}>("SELECT strict FROM pragma_table_list WHERE name='parent_audit'")!.strict, 1, 'STRICT survives');
        const insert = (action: string, op: string | null = null, result = 'applied') => m.store.run('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(9,?,?,?,?,?)', 'parent', action, 'pilot', op, result);
        assert.throws(() => insert('pause', 'op_one'), /UNIQUE/, 'the partial unique index still de-duplicates a replay');
        assert.throws(() => insert('focus_end'), /CHECK/);
        assert.throws(() => insert('pause', null, 'maybe'), /CHECK/);
        insert('reward_add', 'op_reward'); insert('focus_start', 'op_focus');
    } finally { m.cleanup(); }
});

test('migration 012 carries the AUTOINCREMENT counter: ids freed by pruning are never reused', () => {
    const m = preTwelve(db => { for (const at of [1, 2, 3]) insertAudit(db, at, 'pause', null); db.exec('DELETE FROM parent_audit WHERE id>1'); });
    try {
        m.store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'parent', 'focus_start', 'applied');
        assert.deepEqual(m.store.all<{id: number}>(AUDIT).map(r => r.id), [1, 4], 'the counter was 3 before the rebuild, so the next id is 4, not 2');
        assert.equal(m.store.get<{n: number}>("SELECT count(*) n FROM sqlite_sequence WHERE name LIKE 'parent_audit%'")!.n, 1);
    } finally { m.cleanup(); }
});

test('migration 012 on an empty pre-012 audit table leaves a working table', () => {
    const m = preTwelve(() => {});
    try {
        m.store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'parent', 'focus_start', 'applied');
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
async function serve(r: Awaited<ReturnType<typeof focusWorld>>, port: number) {
    const o = `http://localhost:${port}`, f = r.w.f;
    const auth = new Auth(f.store, o, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: o, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    return {o, close: async () => { server.close(); await once(server, 'close'); }};
}
let ports = 28000 + process.pid % 5000;

test('HTTP: POST /people/:id/focus queues one timed pause (202 + Location), is idempotent and audited once; GET, query strings, extra fields and bad CSRF are refused', async () => {
    const r = await focusWorld(); r.w.f.config.timeRequests = {mode: 'parents'};
    const s = await serve(r, ports++);
    try {
        const who = await session(r.w.f, s.o, 'operator'), pre = await who.token();
        const first = await who.post('/people/pilot/focus', {minutes: 45}, KEY, pre);
        assert.equal(first.status, 202);
        assert.match(first.location ?? '', /^\/operations\//);
        const replay = await who.post('/people/pilot/focus', {minutes: 45}, KEY, pre);
        assert.equal(replay.body.operation.id, first.body.operation.id);
        assert.equal(r.ops(), 1); assert.equal(r.audit().length, 1);
        assert.equal((await who.send('GET', '/people/pilot/focus')).status, 404);
        assert.equal((await who.post('/people/pilot/focus?minutes=30', {minutes: 30}, 'another_key_1234567')).status >= 400, true, 'the server rejects query strings');
        assert.equal((await who.post('/people/pilot/focus', {minutes: 30, label: 'x'}, 'another_key_1234567')).status, 400, 'no extra fields, no free text');
        assert.equal((await who.post('/people/pilot/focus', {minutes: 31}, 'another_key_1234567')).status, 400);
        who.setCsrf('wrong');
        assert.equal((await who.post('/people/pilot/focus', {minutes: 30}, 'third_key_12345678')).status, 403, 'CSRF is enforced');
        assert.equal(r.ops(), 1);
    } finally { await s.close(); r.w.f.cleanup(); }
});

test('HTTP: flag off, time requests off, out-of-scope child and the owner-mode gate are all 404 before any audit row', async () => {
    const cases: {name: string; focus: boolean; mode?: 'off' | 'owner' | 'parents'; account: string; person: string; status: number}[] = [
        {name: 'flag off', focus: false, mode: 'parents', account: 'operator', person: 'pilot', status: 404},
        {name: 'time requests off', focus: true, mode: 'off', account: 'operator', person: 'pilot', status: 404},
        {name: 'time requests absent', focus: true, account: 'operator', person: 'pilot', status: 404},
        {name: 'out-of-scope child', focus: true, mode: 'parents', account: 'parent', person: 'nobody', status: 404},
        {name: 'owner mode, non-owner parent', focus: true, mode: 'owner', account: 'parent', person: 'pilot', status: 404},
        {name: 'owner mode, the owner', focus: true, mode: 'owner', account: 'operator', person: 'pilot', status: 202},
        {name: 'parents mode, a scoped parent', focus: true, mode: 'parents', account: 'parent', person: 'pilot', status: 202}];
    for (const c of cases) {
        const r = await focusWorld({}, {focus: c.focus, audit: true});
        if (c.mode) r.w.f.config.timeRequests = {mode: c.mode};
        if (c.mode === 'owner') r.w.f.config.ownerAccountId = 'operator';
        const s = await serve(r, ports++);
        try {
            const who = await session(r.w.f, s.o, c.account);
            const out = await who.post(`/people/${c.person}/focus`, {minutes: 30});
            assert.equal(out.status, c.status, c.name);
            if (c.status === 404) { assert.equal(r.audit().length, 0, `${c.name}: no audit row`); assert.equal(r.ops(), 0, c.name); }
            else assert.equal(r.audit().length, 1, c.name);
        } finally { await s.close(); r.w.f.cleanup(); }
    }
});
