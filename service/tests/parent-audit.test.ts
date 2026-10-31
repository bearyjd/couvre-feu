import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { world as grantWorld, bedtime } from './fixtures/grant-world.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { ChildAdmin } from '../src/admin-children.ts';
import type { ChildAction } from '../src/admin-children.ts';
import { BulkOps } from '../src/integration-bulk.ts';
import type { BulkAction } from '../src/integration-bulk.ts';
import { appServer } from '../src/http.ts';
import { wireIntegration } from '../src/integration-wiring.ts';
import { TestAuthenticator } from './authenticator.ts';
import { auditFor, AUDIT_PAGE_MAX, AUDIT_PAGE_DEFAULT, AUDIT_RETENTION_SECONDS } from '../src/parent-audit.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import { AppError } from '../../shared/src/errors.ts';
import { TimeRequestService } from '../src/time-requests.ts';

const SEED = '02:10:20:30:40:50', K2 = '02:10:20:30:40:62', NEW = '02:10:20:30:40:77';
const origin = 'http://localhost:4273';
const ALL = ['kid2', 'pilot'];
type Row = {actor_id: string; action: string; person_id: string | null; operation_id: string | null; result: string};

/** Two children on the router (pilot, kid2); operator manages both, parent only pilot, parent2 only kid2. The audit flag is ON. */
function world(flag = true) {
    const f = integrationFixture();
    if (flag) f.config.auditLog = {enabled: true};
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const admin = new ChildAdmin(auth, f.policy), bulk = new BulkOps(auth, f.policy);
    f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES('kid2','Kid 2','child',1,?)", f.now());
    f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d_kid2','kid2','Device 2','mac',?,'active',?)", K2, f.now());
    f.store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('parent2','Test parent two','parent','[\"kid2\"]','u9')");
    const setScope = (account: string, ids: string[]) => f.store.run('UPDATE accounts SET person_ids=? WHERE id=?', JSON.stringify(ids), account);
    setScope('operator', ALL); setScope('parent', ['pilot']);
    f.router.policy = normalizePolicy({version: 1, revision: 1, people: [{id: 'pilot', macs: [SEED]}, {id: 'kid2', macs: [K2]}], pauses: [], schedules: []}, f.config.protectedMacs);
    const wide: Actor = {...actor, personIds: ALL};
    const token = () => f.policy.people(wide).revisionToken!;
    async function signIn(account: string) {
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, account, f.now())}, browser);
        const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, session: () => auth.session(result.token, browser)};
    }
    type Who = Awaited<ReturnType<typeof signIn>>;
    async function bulkRun(who: Who, action: BulkAction, precondition = token()) {
        const params = {...(action === 'pause_all' ? {until: 0} : {}), precondition};
        const options = await bulk.stepUpOptions(who.session(), {action, params});
        return bulk.perform(who.session(), action, `bulk_${randomBytes(8).toString('hex')}`, {...params, stepUp: {challengeId: options.challengeId, response: who.key.login(options.options, origin)}});
    }
    async function child(who: Who, kind: ChildAction, target: string, params: Record<string, unknown>) {
        const p = {precondition: token(), ...params};
        const options = await admin.stepUpOptions(who.session(), {action: kind, target, params: p});
        return admin.perform(who.session(), kind, target, {...p, stepUp: {challengeId: options.challengeId, response: who.key.login(options.options, origin)}});
    }
    const rows = () => f.store.all<Row>('SELECT actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id').map(r => ({...r}));
    const dispatch = async (id: string) => { const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256); };
    return {...f, auth, wide, token, signIn, bulkRun, child, rows, dispatch, setScope};
}
const rowsFor = (rows: Row[], action: string) => rows.filter(r => r.action === action);

test('migration 010 adds an ids-and-enums-only parent_audit table to fresh stores', () => {
    const f = world();
    try {
        assert.equal(f.store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 11);
        assert.deepEqual(f.store.all<{name: string}>("SELECT name FROM pragma_table_info('parent_audit')").map(c => c.name), ['id', 'at', 'actor_id', 'action', 'person_id', 'operation_id', 'result']);
        const insert = (action: string, result: string) => f.store.run('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(1,?,?,?,NULL,?)', 'parent', action, 'pilot', result);
        insert('pause', 'applied');
        assert.throws(() => insert('delete_everything', 'applied'), /CHECK/, 'the action enum is closed');
        assert.throws(() => insert('pause', 'maybe'), /CHECK/, 'the result enum is closed');
    } finally { f.cleanup(); }
});

test('manifest auditLog follows the strict optional-key pattern; absent means OFF', () => {
    const f = integrationFixture();
    try { assert.equal(f.config.auditLog, undefined); assert.equal(auditFor(f.store).enabled, false); f.config.auditLog = {enabled: true}; assert.equal(auditFor(f.store).enabled, true); f.config.auditLog = {enabled: false}; assert.equal(auditFor(f.store).enabled, false); }
    finally { f.cleanup(); }
});

test('pause and resume are recorded as applied with the operation id; replays do not duplicate', async () => {
    const f = world();
    try {
        await f.observe();
        const token = f.token(), paused = f.policy.mutate(f.wide, 'pilot', 'pause', {until: 0}, token, 'pause_key_1234567890');
        f.policy.mutate(f.wide, 'pilot', 'pause', {until: 0}, token, 'pause_key_1234567890');
        assert.deepEqual(f.rows(), [{actor_id: 'operator', action: 'pause', person_id: 'pilot', operation_id: paused.result.operation.id, result: 'applied'}], 'the replay returns the first operation and writes nothing new');
    } finally { f.cleanup(); }
});

test('a refused mutation is recorded refused; an unavailable router is recorded failed; an out-of-scope child is not recorded', async () => {
    const f = world();
    try {
        await f.observe();
        assert.throws(() => f.policy.mutate(f.wide, 'pilot', 'pause', {until: 0}, '"s0-r1-' + 'a'.repeat(64) + '"', 'stale_key_12345678901'), (e: AppError) => e.code === 'revision_conflict');
        assert.throws(() => f.policy.mutate(f.wide, 'pilot', 'resume', {}, undefined, 'nopre_key_12345678901'), (e: AppError) => e.code === 'revision_precondition_required');
        assert.throws(() => f.policy.mutate({...f.wide, personIds: ['kid2']}, 'pilot', 'pause', {until: 0}, f.token(), 'scope_key_1234567890'), (e: AppError) => e.status === 404);
        const token = f.token();
        f.advance(120);
        assert.throws(() => f.policy.mutate(f.wide, 'pilot', 'pause', {until: 0}, token, 'stale_obs_1234567890'), (e: AppError) => e.status === 503);
        assert.deepEqual(f.rows().map(r => [r.action, r.person_id, r.operation_id, r.result]), [['pause', 'pilot', null, 'refused'], ['resume', 'pilot', null, 'refused'], ['pause', 'pilot', null, 'failed']]);
    } finally { f.cleanup(); }
});

test('bulk pause and resume record one row per affected child with the shared operation id; a refused bulk is recorded', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const r = await f.bulkRun(op, 'pause_all'), id = (r.body as {operation: {id: string}}).operation.id;
        assert.deepEqual(f.rows().map(x => [x.actor_id, x.action, x.person_id, x.operation_id, x.result]), ALL.map(p => ['operator', 'pause_all', p, id, 'applied']));
        await f.dispatch(id); f.advance(1); await f.observe();
        await assert.rejects(f.bulkRun(op, 'resume_all', '"s0-r1-' + 'b'.repeat(64) + '"'), (e: AppError) => e.code === 'revision_conflict');
        const refused = rowsFor(f.rows(), 'resume_all');
        assert.deepEqual(refused.map(x => [x.person_id, x.operation_id, x.result]), ALL.map(p => [p, null, 'refused']));
        const ok = await f.bulkRun(op, 'resume_all');
        assert.equal(rowsFor(f.rows(), 'resume_all').filter(x => x.result === 'applied').length, 2);
        assert.equal(ok.status, 202);
    } finally { f.cleanup(); }
});

test('device move records both children; a refused move is recorded for the source child', async () => {
    const f = world();
    try {
        const op = await f.signIn('operator'); await f.observe();
        await assert.rejects(f.child(op, 'device_move', 'd_kid2', {to: 'kid2'}), (e: AppError) => e.code === 'device_move_same_child');
        const moved = await f.child(op, 'device_move', 'd_kid2', {to: 'pilot'}), id = (moved.body as {operation: {id: string}}).operation.id;
        assert.deepEqual(f.rows().map(x => [x.action, x.person_id, x.operation_id, x.result]), [['device_move', 'kid2', null, 'refused'], ['device_move', 'kid2', id, 'applied'], ['device_move', 'pilot', id, 'applied']]);
    } finally { f.cleanup(); }
});

test('device assign: pending router scope is recorded refused; an in-scope assign is recorded applied', async () => {
    const f = world();
    try {
        f.config.routerScope = [SEED, K2, NEW];
        const op = await f.signIn('operator'); await f.observe();
        const added = await f.child(op, 'device_add', 'pilot', {label: 'Tablet', mac: NEW}), id = (added.body as {operation: {id: string}}).operation.id;
        assert.deepEqual(f.rows().map(x => [x.action, x.person_id, x.operation_id, x.result]), [['device_assign', 'pilot', id, 'applied']]);
        await f.dispatch(id); f.advance(1); await f.observe();
        f.config.routerScope = [SEED, K2];
        const pending = await f.child(op, 'device_add', 'kid2', {label: 'Other', mac: '02:10:20:30:40:78'});
        assert.equal(pending.status, 409);
        assert.deepEqual(f.rows().slice(1).map(x => [x.action, x.person_id, x.operation_id, x.result]), [['device_assign', 'kid2', null, 'refused']]);
    } finally { f.cleanup(); }
});

test('grants: approve, decline and an ended grant are recorded; approve is recorded refused when the CAS path refuses', async () => {
    const w = await grantWorld(bedtime), f = w.f;
    try {
        f.config.auditLog = {enabled: true};
        const declined = w.ask(15);
        w.service.decline(actor, declined);
        f.advance(301);
        await f.observe();
        const id = w.ask(30);
        await w.service.approve(actor, id, 30);
        const op = w.row(id).grant_operation_id!;
        await w.dispatch(op); await w.service.advance();
        const paused = f.pause(0, 'pause_key_12345678');
        await w.dispatch(paused.result.operation.id);
        f.advance(1); await f.observe(); await w.service.advance();
        assert.deepEqual(f.store.all<Row>('SELECT actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id').map(r => [r.actor_id, r.action, r.person_id, r.operation_id, r.result]), [
            ['operator', 'grant_decline', 'pilot', null, 'applied'], ['operator', 'grant_approve', 'pilot', op, 'applied'],
            ['operator', 'pause', 'pilot', paused.result.operation.id, 'applied'], ['system', 'grant_end', 'pilot', op, 'applied']]);
        f.advance(301); await f.observe();
        const refusing = w.ask(15);
        const failing = new TimeRequestService(f.store, f.policy, f.now, undefined, {grant: () => { throw new AppError(409, 'revision_conflict'); }, outcome: w.grants.outcome.bind(w.grants)});
        await assert.rejects(failing.approve(actor, refusing, 15), (e: AppError) => e.code === 'revision_conflict');
        assert.deepEqual(f.store.all<Row>("SELECT actor_id,action,person_id,operation_id,result FROM parent_audit WHERE result<>'applied'").map(r => [r.actor_id, r.action, r.person_id, r.operation_id, r.result]), [['operator', 'grant_approve', 'pilot', null, 'refused']]);
    } finally { f.cleanup(); }
});

test('nothing but ids and enums is stored: no reason text, MAC, address, hostname or URL ever reaches the table', async () => {
    const w = await grantWorld(bedtime), f = w.f;
    try {
        f.config.auditLog = {enabled: true};
        w.service.submit(w.link.token, 30, 'SECRET homework reason example.com 192.168.1.9', 'client-a');
        const id = f.store.get<{id: string}>("SELECT id FROM time_requests WHERE state='pending' ORDER BY created_at DESC")!.id;
        await w.service.approve(actor, id, 30);
        await w.dispatch(w.row(id).grant_operation_id!); await w.service.advance();
        f.pause(0, 'pause_key_12345678');
        const dump = JSON.stringify(f.store.all('SELECT * FROM parent_audit'));
        assert.ok(f.store.get<{n: number}>('SELECT count(*) n FROM parent_audit')!.n >= 2);
        assert.doesNotMatch(dump, /SECRET|homework|example\.com|192\.168|[0-9a-f]{2}(?::[0-9a-f]{2}){5}|https?:/i);
        for (const r of f.store.all<Record<string, unknown>>('SELECT * FROM parent_audit')) for (const v of Object.values(r)) assert.ok(v === null || typeof v === 'number' || /^[a-z0-9_:-]{1,64}$/i.test(String(v)) || /^[0-9a-f-]{36}$/.test(String(v)), `unexpected value ${String(v)}`);
    } finally { f.cleanup(); }
});

test('flag off (absent): nothing is written and GET /audit is 404', async () => {
    const f = world(false), port = 26000 + process.pid % 10000, o = `http://localhost:${port}`;
    const auth = new Auth(f.store, o, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: o, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        await f.observe();
        f.policy.mutate(f.wide, 'pilot', 'pause', {until: 0}, f.token(), 'pause_key_1234567890');
        assert.throws(() => f.policy.mutate(f.wide, 'pilot', 'resume', {}, undefined, 'nopre_key_12345678901'));
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM parent_audit')!.n, 0);
        const call = await http(f, auth, o, 'operator');
        assert.equal((await call('/audit')).status, 404);
        assert.equal((await call('/audit/limit/10')).status, 404);
    } finally { server.close(); await once(server, 'close'); f.cleanup(); }
});

async function http(f: ReturnType<typeof world>, _auth: Auth, o: string, account: string) {
    const cookies = new Map<string, string>(); let csrf = '';
    const call = async (path: string) => {
        const response = await fetch(o + path, {headers: {Origin: o, Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; ')}});
        return {status: response.status, body: await response.json() as Record<string, any>};
    };
    const post = async (path: string, input: unknown) => {
        const response = await fetch(o + path, {method: 'POST', headers: {Origin: o, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; ')}, body: JSON.stringify(input)});
        for (const entry of response.headers.getSetCookie()) { const [k, v] = entry.split(';')[0].split('='); cookies.set(k, v); }
        return {status: response.status, body: await response.json() as Record<string, any>};
    };
    const key = new TestAuthenticator(), options = await post('/auth/register/options', {token: issueOperatorBootstrap(f.store, account, f.now())});
    const verified = await post('/auth/register/verify', {challengeId: options.body.challengeId, response: key.register(options.body.options, o)});
    assert.equal(verified.status, 200); csrf = verified.body.csrfToken;
    return call;
}

test('GET /audit admins see every row (incl. no-child rows); non-admin parents only their own children; no children is an empty list', async () => {
    const f = world(), port = 27000 + process.pid % 10000, o = `http://localhost:${port}`;
    const auth = new Auth(f.store, o, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: o, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        const audit = auditFor(f.store);
        audit.record({actor: 'parent', action: 'pause', people: ['pilot'], operationId: 'op-a', result: 'applied'});
        audit.record({actor: 'parent2', action: 'resume', people: ['kid2'], operationId: 'op-b', result: 'applied'});
        audit.record({actor: 'operator', action: 'pause_all', people: [], result: 'refused'});
        const ids = async (account: string) => { const r = await (await http(f, auth, o, account))('/audit'); assert.equal(r.status, 200); return r.body.entries.map((e: {actorId: string; personId: string | null}) => `${e.actorId}:${e.personId}`); };
        assert.deepEqual(await ids('parent'), ['parent:pilot']);
        assert.deepEqual(await ids('parent2'), ['parent2:kid2']);
        assert.deepEqual(await ids('operator'), ['operator:null', 'parent2:kid2', 'parent:pilot'], 'an admin sees every row: other parents\' children and rows with no child; a non-admin parent sees neither (asserted above)');
        f.store.run("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('parent3','Parent with no children','parent','[]','u10')");
        const none = await (await http(f, auth, o, 'parent3'))('/audit');
        assert.equal(none.status, 200); assert.deepEqual(none.body.entries, []);
    } finally { server.close(); await once(server, 'close'); f.cleanup(); }
});

test('an audit write failure never turns a successful operation into an error; it is logged server side', async () => {
    const f = world(), written: string[] = [], real = process.stderr.write.bind(process.stderr);
    try {
        await f.observe();
        f.store.db.exec('DROP TABLE parent_audit');
        process.stderr.write = ((chunk: string) => { written.push(String(chunk)); return true; }) as never;
        const paused = f.policy.mutate(f.wide, 'pilot', 'pause', {until: 0}, f.token(), 'pause_key_1234567890');
        process.stderr.write = real;
        assert.equal(paused.status, 202);
        assert.equal(f.store.get<{state: string}>('SELECT state FROM operations WHERE id=?', paused.result.operation.id)!.state, 'pending');
        assert.ok(written.some(line => line.includes('parent_audit_write_failed')), 'logged');
        assert.doesNotMatch(written.join(''), /pilot|operator/, 'the log line names no child or account');
    } finally { process.stderr.write = real; f.cleanup(); }
});

test('retention: rows older than 90 days are pruned in bounded batches on startup (wireIntegration prune) and by prune()', () => {
    const f = world(), audit = auditFor(f.store), now = f.now();
    try {
        assert.equal(AUDIT_RETENTION_SECONDS, 90 * 86400);
        for (let i = 0; i < 1200; i++) f.store.run("INSERT INTO parent_audit(at,actor_id,action,person_id,result) VALUES(?,'parent','pause','pilot','applied')", now - AUDIT_RETENTION_SECONDS - 1 - i);
        f.store.run("INSERT INTO parent_audit(at,actor_id,action,person_id,result) VALUES(?,'parent','pause','pilot','applied')", now - AUDIT_RETENTION_SECONDS + 5);
        f.store.run("INSERT INTO parent_audit(at,actor_id,action,person_id,result) VALUES(?,'parent','resume','pilot','applied')", now);
        const first = audit.prune(now);
        assert.ok(first > 0 && first <= 1200, 'one call deletes at most a bounded number of rows');
        while (audit.prune(now) > 0);
        assert.deepEqual(f.store.all<{action: string}>('SELECT action FROM parent_audit ORDER BY id').map(r => r.action), ['pause', 'resume'], 'only expired rows went');
        f.store.run("INSERT INTO parent_audit(at,actor_id,action,person_id,result) VALUES(?,'parent','pause','pilot','applied')", Math.floor(Date.now() / 1000) - AUDIT_RETENTION_SECONDS - 100);
        wireIntegration(f.config, f.store, f.router).prune();
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM parent_audit WHERE at < ' + (Math.floor(Date.now() / 1000) - AUDIT_RETENTION_SECONDS))!.n, 0, 'the service prune hook removes rows past 90 days of the real clock');
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM parent_audit WHERE action='resume'")!.n, 1, 'newer rows stay');
    } finally { f.cleanup(); }
});

test('pagination: newest first, default page, hard cap, cursor, and no unbounded query', async () => {
    const f = world(), port = 28000 + process.pid % 10000, o = `http://localhost:${port}`;
    const auth = new Auth(f.store, o, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: o, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        for (let i = 0; i < 150; i++) f.store.run("INSERT INTO parent_audit(at,actor_id,action,person_id,result) VALUES(?,'operator','pause','pilot','applied')", f.now() + i);
        assert.equal(AUDIT_PAGE_MAX, 100);
        const call = await http(f, auth, o, 'operator');
        const first = await call('/audit');
        assert.equal(first.body.entries.length, AUDIT_PAGE_DEFAULT);
        assert.ok(first.body.entries[0].id > first.body.entries[1].id, 'newest first');
        assert.equal(first.body.nextBefore, first.body.entries[AUDIT_PAGE_DEFAULT - 1].id);
        assert.equal((await call('/audit/limit/100')).body.entries.length, 100);
        assert.equal((await call('/audit/limit/999')).body.entries.length, 100, 'a larger limit is clamped to the hard cap');
        assert.equal((await call('/audit/limit/0')).status, 400);
        const next = await call(`/audit/limit/100/before/${first.body.nextBefore}`);
        assert.equal(next.body.entries.length, 100); assert.equal(next.body.nextBefore, null);
        assert.ok(next.body.entries.every((e: {id: number}) => e.id < first.body.nextBefore));
        assert.deepEqual(Object.keys(first.body.entries[0]).sort(), ['action', 'actorId', 'actorName', 'at', 'id', 'operationId', 'personId', 'result']);
    } finally { server.close(); await once(server, 'close'); f.cleanup(); }
});

const auditRows = (f: {store: {all<T>(sql: string): T[]}}): Row[] => f.store.all<Row>('SELECT actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id').map(r => ({...r}));
/** A pause the router has confirmed, so approving a request has something to lift. `before` is how many audit rows exist already. */
async function pausedWorld() {
    const w = await grantWorld({}), f = w.f;
    f.config.auditLog = {enabled: true};
    const paused = f.pause(0, 'pause_key_12345678');
    await w.dispatch(paused.result.operation.id); f.advance(1); await f.observe();
    return {...w, legacy: new TimeRequestService(f.store, f.policy, f.now), before: auditRows(f).length};
}

test('approve writes exactly one grant_approve row and no resume row, on the legacy path', async () => {
    const w = await pausedWorld(), f = w.f;
    try {
        const id = w.ask(30);
        await w.legacy.approve(actor, id, 30);
        assert.ok(f.store.get("SELECT 1 FROM operations WHERE action='resume'"), 'the legacy path did queue a resume');
        assert.deepEqual(auditRows(f).slice(w.before).map(r => [r.actor_id, r.action, r.person_id, r.result]), [['operator', 'grant_approve', 'pilot', 'applied']]);
    } finally { f.cleanup(); }
});

test('approve writes exactly one grant_approve row and no resume row, on the grants path', async () => {
    const w = await pausedWorld(), f = w.f;
    try {
        const id = w.ask(30);
        await w.service.approve(actor, id, 30);
        assert.deepEqual(auditRows(f).slice(w.before).map(r => [r.actor_id, r.action, r.person_id, r.result]), [['operator', 'grant_approve', 'pilot', 'applied']]);
    } finally { f.cleanup(); }
});

test('the background re-pause is recorded as system/pause and never under a parent', async () => {
    const w = await pausedWorld(), f = w.f;
    try {
        const id = w.ask(30);
        await w.legacy.approve(actor, id, 30);
        const resume = f.store.get<{id: string}>("SELECT id FROM operations WHERE action='resume'")!.id;
        await w.dispatch(resume); f.advance(1); await f.observe();
        f.advance(30 * 60 + 5); await f.observe();
        await w.legacy.advance();
        assert.notEqual(w.row(id).repause_state, 'none', 'a re-pause was owed');
        const later = auditRows(f).slice(w.before + 1);
        assert.deepEqual(later.map(r => [r.actor_id, r.action, r.person_id, r.result]), [['system', 'pause', 'pilot', 'applied']]);
    } finally { f.cleanup(); }
});

test('refused rows are capped at 20 per actor per 60 s; other actors are unaffected; the window slides with the clock', () => {
    const f = world();
    try {
        const audit = auditFor(f.store), count = (actorId: string) => f.store.get<{n: number}>("SELECT count(*) n FROM parent_audit WHERE actor_id=? AND result='refused'", actorId)!.n;
        for (let i = 0; i < 21; i++) audit.record({actor: 'operator', action: 'pause', people: ['pilot'], result: 'refused', at: 1000 + i});
        assert.equal(count('operator'), 20, 'the 21st within a minute is not stored');
        audit.record({actor: 'parent', action: 'pause', people: ['pilot'], result: 'refused', at: 1021});
        assert.equal(count('parent'), 1, 'another actor is unaffected');
        audit.record({actor: 'operator', action: 'pause', people: ['pilot'], operationId: 'op-1', result: 'applied', at: 1022});
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM parent_audit WHERE operation_id='op-1'")!.n, 1, 'applied rows are not capped');
        audit.record({actor: 'operator', action: 'pause', people: ['pilot'], result: 'refused', at: 1000 + 61});
        assert.equal(count('operator'), 21, 'stored again once the oldest refusals are over a minute old');
    } finally { f.cleanup(); }
});

test('flag off: the audit wrapper and its callbacks do no extra database work', async () => {
    const w = await grantWorld(bedtime), f = w.f, seen: string[] = [];
    try {
        for (const method of ['get', 'all', 'run'] as const) {
            const real = f.store[method].bind(f.store) as (sql: string, ...args: never[]) => unknown;
            (f.store as unknown as Record<string, unknown>)[method] = (sql: string, ...args: never[]) => { seen.push(sql); return real(sql, ...args); };
        }
        const declined = w.ask(15);
        w.service.decline(actor, declined);
        f.advance(301); await f.observe();
        const approved = w.ask(30);
        await w.service.approve(actor, approved, 30);
        assert.deepEqual(seen.filter(sql => /parent_audit|COALESCE\(grant_operation_id|SELECT person_id FROM time_requests WHERE id=\?/.test(sql)), []);
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM parent_audit')!.n, 0);
    } finally { f.cleanup(); }
});

test('flag off: a child-admin action does not read the device owner for the audit', async () => {
    const f = world(false);
    try {
        const op = await f.signIn('operator'); await f.observe();
        const seen: string[] = [], real = f.store.get.bind(f.store) as (sql: string, ...args: never[]) => unknown;
        (f.store as unknown as Record<string, unknown>).get = (sql: string, ...args: never[]) => { seen.push(sql); return real(sql, ...args); };
        await f.child(op, 'device_move', 'd_kid2', {to: 'pilot'});
        assert.deepEqual(seen.filter(sql => sql.includes('SELECT person_id FROM devices WHERE id=?')), []);
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM parent_audit')!.n, 0);
    } finally { f.cleanup(); }
});

test('the before cursor is at most 15 digits; limit takes 1 to 4 digits (clamped to 100), longer segments are 404', async () => {
    const f = world(), port = 29000 + process.pid % 10000, o = `http://localhost:${port}`;
    const auth = new Auth(f.store, o, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: o, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        const call = await http(f, auth, o, 'operator');
        assert.equal((await call('/audit/before/999999999999999')).status, 200);
        assert.equal((await call('/audit/before/1000000000000000')).status, 404);
        assert.equal((await call('/audit/limit/9999')).status, 200);
        assert.equal((await call('/audit/limit/10000')).status, 404);
    } finally { server.close(); await once(server, 'close'); f.cleanup(); }
});
