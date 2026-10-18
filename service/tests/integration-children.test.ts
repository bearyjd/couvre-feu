import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { integrationFixture, actor, testConfig } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import type { AuthSession } from '../src/auth.ts';
import { ChildAdmin } from '../src/admin-children.ts';
import { AccountAdmin } from '../src/admin-accounts.ts';
import type { ChildAction } from '../src/admin-children.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { CHILD_LIMIT, DEVICES_PER_CHILD, DEVICE_LIMIT } from '../src/integration-children.ts';
import { TestAuthenticator } from './authenticator.ts';
import { appServer } from '../src/http.ts';
import { once } from 'node:events';
import { normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';

// Placeholder, locally administered unicast MACs only.
const SEED = '02:10:20:30:40:50', PROTECTED = '02:10:20:30:40:51', TABLET = '02:10:20:30:40:52', LAPTOP = '02:10:20:30:40:53', OUTSIDE = '02:10:20:30:40:5e';
const origin = 'http://localhost:4273';
const code = (expected: string) => (error: {code?: string}) => error.code === expected;

function fixture(scope: string[] = [SEED, TABLET, LAPTOP]) {
    const f = integrationFixture();
    // The router's install-time --rpc-allow set; tests bind it explicitly (the manifest default is the seed MAC alone).
    (f.config as {routerScope?: string[]}).routerScope = scope;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const admin = new ChildAdmin(auth, f.policy);
    async function signIn(account: string) {
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, account, f.now())}, browser);
        const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, cookie: `cf_session=${result.token}; cf_browser=${browser}`, session: () => auth.session(result.token, browser)};
    }
    type Who = Awaited<ReturnType<typeof signIn>>;
    async function stepUp(who: Who, action: ChildAction, target: string, params: Record<string, unknown>) {
        const options = await admin.stepUpOptions(who.session(), {action, target, params});
        return {challengeId: options.challengeId, response: who.key.login(options.options, origin)};
    }
    async function act(who: Who, action: ChildAction, target: string, params: Record<string, unknown> = {}) {
        return admin.perform(who.session(), action, target, {...params, stepUp: await stepUp(who, action, target, params)}) as Promise<{status: number; body: Record<string, any>}>;
    }
    const token = () => f.policy.people(actor).revisionToken!;
    async function dispatch(id: string) { const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256); }
    return {...f, auth, admin, signIn, stepUp, act, token, dispatch};
}
const fresh = (who: {session: () => AuthSession}): Actor => who.session().dto.actor;

test('migration 008 seeds the manifest child and device once; admins get scope_all, parents keep explicit scopes', () => {
    const f = fixture();
    try {
        assert.deepEqual(f.store.all('SELECT id,name,kind,active FROM people').map(r => ({...r as object})), [{id: 'pilot', name: 'Explicit test person', kind: 'child', active: 1}]);
        assert.deepEqual(f.store.all('SELECT id,person_id,label,identifier_kind,identifier,state FROM devices').map(r => ({...r as object})),
            [{id: 'phone', person_id: 'pilot', label: 'Explicit test device', identifier_kind: 'mac', identifier: SEED, state: 'active'}]);
        assert.deepEqual(f.store.all('SELECT id,scope_all FROM accounts ORDER BY id').map(r => ({...r as object})), [{id: 'operator', scope_all: 1}, {id: 'parent', scope_all: 0}]);
        // Reopening never reseeds or duplicates.
        f.store.run("UPDATE people SET name='Renamed' WHERE id='pilot'"); f.store.close();
        const reopened = new IntegrationStore(f.config);
        try { assert.equal(reopened.get<{name: string}>("SELECT name FROM people WHERE id='pilot'")!.name, 'Renamed'); assert.equal(reopened.get<{n: number}>('SELECT count(*) n FROM devices')!.n, 1); }
        finally { reopened.close(); }
    } finally { rmSync(f.dir, {recursive: true, force: true}); }
});

test('an existing integration database with a live operation migrates in place: FKs, operations and the single-child flow keep working', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m008-')), config = testConfig(dir), path = join(dir, 'integration.sqlite');
    const sql = (name: string) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
    try {
        const db = new DatabaseSync(path);
        for (const name of ['001.sql', '002.sql', '005.sql', '006.sql', '007.sql']) db.exec(name === '001.sql' ? sql(name).replace('revision INTEGER NOT NULL UNIQUE', 'revision INTEGER NOT NULL') : sql(name));
        db.exec('PRAGMA user_version=5'); db.exec(sql('integration-001.sql')); db.exec(sql('integration-002.sql'));
        db.prepare("INSERT INTO integration_state(singleton,mode,schema_version,target_digest,manifest_digest,generation) VALUES(1,'integration',1,?,?,?)").run(config.targetDigest, config.manifestDigest, config.router.generation);
        db.prepare('INSERT INTO service_state(singleton,desired_json,highwater) VALUES(1,?,0)').run(policyJSON(config.enrollment));
        db.exec("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('operator','Op','admin','[\"pilot\"]','u1'),('parent','Pa','parent','[\"pilot\"]','u2')");
        db.exec(`INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES('op1','operator','pilot','pause',1,'unknown','{}','{}','{}','k1',1,1)`);
        db.exec("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase) VALUES('op1','g','b','r','{}','uncertain')");
        db.exec("UPDATE integration_state SET active_operation_id='op1'");
        db.close(); chmodSync(path, 0o600);
        const store = new IntegrationStore(config);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 6);
            assert.equal(store.integrationState().active_operation_id, 'op1');
            assert.equal(store.all('PRAGMA foreign_key_check').length, 0);
            assert.equal(store.get<{n: number}>('PRAGMA foreign_keys' as string) !== undefined, true);
            assert.equal(store.get<{state: string}>("SELECT state FROM operations WHERE id='op1'")!.state, 'unknown');
            assert.match(store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='operations'")!.sql, /'enroll','unenroll'/);
            assert.doesNotMatch(store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='operations'")!.sql, /revision INTEGER NOT NULL UNIQUE/);
            assert.throws(() => store.run("DELETE FROM operations WHERE id='op1'"), /FOREIGN KEY/);
            assert.equal(store.get<{identifier: string}>("SELECT identifier FROM devices WHERE person_id='pilot'")!.identifier, SEED);
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('an admin adds a second device to a child through the CAS rpc-sync path; confirmation activates it', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const before = f.token();
        const added = await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: TABLET.toUpperCase().replaceAll(':', '-'), precondition: before});
        assert.equal(added.status, 202); const id = added.body.operation.id;
        assert.equal(added.body.operation.action, 'enroll');
        assert.equal(f.store.get<{state: string}>('SELECT state FROM devices WHERE identifier=?', TABLET)!.state, 'enrolling');
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM audit WHERE action='admin_device_add' AND actor_id='operator'")!.n, 1);
        // One change at a time, like pause/resume.
        await assert.rejects(f.act(op, 'device_add', 'pilot', {label: 'Laptop', mac: LAPTOP, precondition: before}), (e: {code?: string}) => ['operation_in_progress', 'revision_conflict'].includes(e.code!));
        await f.dispatch(id);
        assert.deepEqual(f.router.policy.people, [{id: 'pilot', macs: [SEED, TABLET]}]);
        assert.equal(f.policy.operation(actor, id).state, 'confirmed');
        assert.equal(f.store.get<{state: string}>('SELECT state FROM devices WHERE identifier=?', TABLET)!.state, 'active');
        f.advance(1); await f.observe();
        const people = f.policy.people(actor);
        assert.deepEqual(people.people[0].devices.map(d => [d.label, d.evidence?.enrollment]), [['Explicit test device', 'included'], ['Tablet', 'included']]);
        assert.ok(!JSON.stringify(people).includes(TABLET), 'the people view never carries MACs');
        assert.notEqual(people.revisionToken, null);
        // Pause/resume still work on a multi-device child.
        const paused = f.pause(0, 'pause_after_enroll_1'); await f.dispatch(paused.result.operation.id);
        assert.deepEqual(f.router.policy.pauses, [{person: 'pilot', until: 0}]);
    } finally { f.cleanup(); }
});

test('device add refuses protected, duplicate, out-of-scope, multicast and unlisted MACs, non-admins and unbound step-ups', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'), parent = await f.signIn('parent'); await f.observe();
        const add = (mac: string) => f.act(op, 'device_add', 'pilot', {label: 'Extra', mac, precondition: f.token()});
        await assert.rejects(add(PROTECTED), code('device_mac_protected'));
        await assert.rejects(add(SEED), code('device_already_enrolled'));
        await assert.rejects(add(OUTSIDE), code('device_outside_router_scope'));
        await assert.rejects(add('03:10:20:30:40:52'), code('invalid_mac'));
        await assert.rejects(add('not-a-mac'), code('invalid_mac'));
        await assert.rejects(f.act(op, 'device_add', 'pilot', {label: '', mac: TABLET, precondition: f.token()}), code('invalid_label'));
        await assert.rejects(f.act(op, 'device_add', 'pilot', {label: 'x'.repeat(65), mac: TABLET, precondition: f.token()}), code('invalid_label'));
        await assert.rejects(f.act(op, 'device_add', 'nobody', {label: 'Tablet', mac: TABLET, precondition: f.token()}), code('person_not_found'));
        await assert.rejects(f.admin.stepUpOptions(parent.session(), {action: 'device_add', target: 'pilot', params: {label: 'T', mac: TABLET, precondition: f.token()}}), code('admin_required'));
        assert.throws(() => f.admin.list(fresh(parent)), code('admin_required'));
        await assert.rejects(f.admin.perform(op.session(), 'device_add', 'pilot', {label: 'Tablet', mac: TABLET, precondition: f.token()}), code('step_up_required'));
        const proof = await f.stepUp(op, 'device_add', 'pilot', {label: 'Tablet', mac: TABLET, precondition: f.token()});
        await assert.rejects(f.admin.perform(op.session(), 'device_add', 'pilot', {label: 'Tablet', mac: LAPTOP, precondition: f.token(), stepUp: proof}), code('step_up_mismatch'));
        await assert.rejects(f.admin.perform(op.session(), 'device_add', 'pilot', {label: 'Tablet', mac: TABLET, precondition: f.token(), stepUp: proof}), code('invalid_challenge'));
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM devices')!.n, 1);
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM operations')!.n, 0);
    } finally { f.cleanup(); }
});

test('admins manage only children in their own scope, and duplicates in another scope are refused without naming it', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'), restricted = await f.signIn('parent'); await f.observe();
        const other = (await f.act(op, 'child_create', '', {name: 'Second child'})).body.child.id as string;
        assert.match(other, /^[a-z][a-z0-9_]{0,31}$/);
        // scope_all accounts gain the new child; explicit scopes do not.
        assert.deepEqual(JSON.parse(f.store.get<{person_ids: string}>("SELECT person_ids FROM accounts WHERE id='operator'")!.person_ids), ['pilot', other]);
        assert.deepEqual(JSON.parse(f.store.get<{person_ids: string}>("SELECT person_ids FROM accounts WHERE id='parent'")!.person_ids), ['pilot']);
        f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d_other',?,'Other tablet','mac',?,'active',1)", other, TABLET);
        // A restricted admin (explicit scope 'pilot' only).
        f.store.run("UPDATE accounts SET role='admin' WHERE id='parent'");
        assert.deepEqual(f.admin.list(fresh(restricted)).children.map(c => c.id), ['pilot']);
        assert.ok(!JSON.stringify(f.admin.list(fresh(restricted))).includes(TABLET));
        await assert.rejects(f.act(restricted, 'device_add', other, {label: 'X', mac: LAPTOP, precondition: f.token()}), code('person_not_found'));
        await assert.rejects(f.act(restricted, 'device_remove', 'd_other', {precondition: f.token()}), code('device_not_found'));
        await assert.rejects(f.act(restricted, 'device_add', 'pilot', {label: 'X', mac: TABLET, precondition: f.token()}), (e: {code?: string; message?: string}) => e.code === 'device_already_enrolled' && !/Second child|Other tablet/.test(e.message ?? ''));
        await assert.rejects(f.act(restricted, 'child_create', '', {name: 'Nope'}), code('scope_all_required'));
        await assert.rejects(f.act(restricted, 'child_remove', other, {}), code('person_not_found'));
    } finally { f.cleanup(); }
});

test('router limits: 32 devices per child, 256 devices, 64 children', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observe();
        const mac = (i: number) => `02:aa:00:00:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`;
        (f.config as {routerScope?: string[]}).routerScope = [SEED, ...Array.from({length: 300}, (_, i) => mac(i))];
        for (let i = 0; i < DEVICES_PER_CHILD - 1; i++) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,'pilot','D','mac',?,'active',1)", `d${i}`, mac(i));
        await assert.rejects(f.act(op, 'device_add', 'pilot', {label: 'One too many', mac: mac(299), precondition: f.token()}), code('child_device_limit_reached'));
        for (let c = 0; c < CHILD_LIMIT - 1; c++) f.store.run("INSERT INTO people(id,name,active,created_at) VALUES(?,'C',1,1)", `c${c}`);
        await assert.rejects(f.act(op, 'child_create', '', {name: 'Sixty-fifth'}), code('child_limit_reached'));
        f.store.run("UPDATE accounts SET person_ids=? WHERE id='operator'", JSON.stringify(['pilot', ...Array.from({length: CHILD_LIMIT - 1}, (_, c) => `c${c}`)]));
        for (let i = DEVICES_PER_CHILD; i < DEVICE_LIMIT; i++) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,'D','mac',?,'active',1)", `d${i}`, `c${i % 60}`, mac(i));
        await assert.rejects(f.act(op, 'device_add', 'c1', {label: 'Over', mac: mac(299), precondition: f.token()}), code('device_limit_reached'));
    } finally { f.cleanup(); }
});

test('removing devices: confirmed unenroll deletes the row, the last device takes the child (and its pause) off the router, unknown-to-router rows go DB-only', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observe();
        await f.dispatch((await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: TABLET, precondition: f.token()})).body.operation.id);
        f.advance(1); await f.observe();
        await f.dispatch(f.pause(0, 'pause_before_remove_1').result.operation.id); f.advance(1); await f.observe();
        const tablet = f.store.get<{id: string}>('SELECT id FROM devices WHERE identifier=?', TABLET)!.id;
        const removed = await f.act(op, 'device_remove', tablet, {precondition: f.token()});
        assert.equal(removed.body.operation.action, 'unenroll');
        assert.equal(f.store.get<{state: string}>('SELECT state FROM devices WHERE id=?', tablet)!.state, 'removing');
        await f.dispatch(removed.body.operation.id);
        assert.equal(f.store.get('SELECT id FROM devices WHERE id=?', tablet), undefined);
        assert.deepEqual(f.router.policy.people, [{id: 'pilot', macs: [SEED]}]);
        assert.deepEqual(f.router.policy.pauses, [{person: 'pilot', until: 0}]);
        f.advance(1); await f.observe();
        const last = await f.act(op, 'device_remove', 'phone', {precondition: f.token()}); await f.dispatch(last.body.operation.id);
        assert.deepEqual(f.router.policy.people, []); assert.deepEqual(f.router.policy.pauses, []);
        f.advance(1); await f.observe();
        // A row the router never accepted needs no router change.
        f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d_stale','pilot','Stale','mac',?,'active',1)", LAPTOP);
        const dbOnly = await f.act(op, 'device_remove', 'd_stale', {precondition: null});
        assert.deepEqual(dbOnly.body, {removed: 'd_stale', routerChange: false});
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM audit WHERE action='admin_device_remove'")!.n, 3);
        // An empty child can be removed; one with devices cannot.
        const child = (await f.act(op, 'child_create', '', {name: 'Temp'})).body.child.id as string;
        f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d_tmp',?,'T','mac',?,'active',1)", child, OUTSIDE);
        await assert.rejects(f.act(op, 'child_remove', child, {}), code('child_has_devices'));
        f.store.run("DELETE FROM devices WHERE id='d_tmp'");
        assert.deepEqual((await f.act(op, 'child_remove', child, {})).body, {removed: child});
        assert.ok(!f.admin.list(fresh(op)).children.some(c => c.id === child));
    } finally { f.cleanup(); }
});

test('an offline device makes the router refuse the sync: the change fails cleanly, the row reverts and admins see which devices to check', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'), parent = await f.signIn('parent'); await f.observe();
        f.router.reject = 'incomplete_transition_address_coverage';
        const added = await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: TABLET, precondition: f.token()});
        await f.dispatch(added.body.operation.id);
        const failed = f.policy.operation(actor, added.body.operation.id);
        assert.equal(failed.state, 'failed'); assert.equal(failed.error, 'incomplete_transition_address_coverage');
        assert.equal(f.store.integrationState().active_operation_id, null);
        assert.equal(f.store.get('SELECT id FROM devices WHERE identifier=?', TABLET), undefined);
        const rejection = f.admin.list(fresh(op)).lastRejection!;
        assert.equal(rejection.code, 'incomplete_transition_address_coverage');
        assert.deepEqual(rejection.devices, [{child: 'Explicit test person', device: 'Explicit test device'}, {child: 'Explicit test person', device: 'Tablet'}]);
        assert.equal(rejection.otherDevices, 0);
        assert.ok(!JSON.stringify(rejection).includes(SEED));
        // Parents see the failed change but never device identifiers.
        const view = JSON.stringify(f.policy.people(fresh(parent)));
        assert.ok(!view.includes(SEED) && !view.includes(TABLET));
        // The router still reports the recorded apply error until it reconfirms; then removal works again.
        f.advance(1); await f.observe(); assert.equal(f.policy.people(actor).revisionToken, null);
        f.router.reject = null; f.router.runtimeError = null; f.advance(1); await f.observe();
        assert.notEqual(f.policy.people(actor).revisionToken, null);
    } finally { f.cleanup(); }
});

test('a router policy naming a MAC that no child owns is foreign and fails closed', async () => {
    const f = fixture();
    try {
        f.router.policy = normalizePolicy({...f.router.policy, people: [{id: 'pilot', macs: [SEED, LAPTOP]}]});
        await f.observe();
        assert.equal(f.store.integrationState().observation_error, 'router_policy_foreign');
        assert.equal(f.policy.people(actor).revisionToken, null);
    } finally { f.cleanup(); }
});

test('without routerScope the v1 dispatch script and target digest are unchanged; with it the header lists the scope', () => {
    const f = fixture();
    try {
        delete (f.config as {routerScope?: string[]}).routerScope;
        assert.match(f.worker.prepare('observe').script, new RegExp(`# Allowed MAC: ${SEED}\\n`));
        (f.config as {routerScope?: string[]}).routerScope = [SEED, TABLET];
        assert.match(f.worker.prepare('observe').script, new RegExp(`# Allowed MACs: ${SEED},${TABLET}\\n`));
    } finally { f.cleanup(); }
});

test('a device group (e.g. a shared TV) is a non-child entry paused through the same path; kind round-trips', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observe();
        await assert.rejects(f.act(op, 'child_create', '', {name: 'X', kind: 'adult'}), code('invalid_kind'));
        const group = (await f.act(op, 'child_create', '', {name: 'Living-room TV', kind: 'device_group'})).body.child;
        assert.equal(group.kind, 'device_group'); assert.match(group.id, /^group_[0-9a-f]{10}$/);
        assert.equal(f.store.get<{kind: string}>('SELECT kind FROM people WHERE id=?', group.id)!.kind, 'device_group');
        await assert.rejects(f.act(op, 'device_add', group.id, {label: 'TV', mac: PROTECTED, precondition: f.token()}), code('device_mac_protected'));
        const groupActor = {...actor, personIds: ['pilot', group.id]};
        await f.dispatch((await f.act(op, 'device_add', group.id, {label: 'TV', mac: LAPTOP, precondition: f.token()})).body.operation.id);
        f.advance(1); await f.observe();
        const view = f.policy.people(groupActor);
        assert.deepEqual(view.people.map(p => [p.name, p.kind]), [['Explicit test person', 'child'], ['Living-room TV', 'device_group']]);
        const paused = f.policy.mutate(groupActor, group.id, 'pause', {until: 0}, view.revisionToken!, 'pause_group_1234567');
        await f.dispatch(paused.result.operation.id);
        assert.deepEqual(f.router.policy.pauses, [{person: group.id, until: 0}]);
        assert.deepEqual(f.admin.list(fresh(op)).children.map(c => c.kind), ['child', 'device_group']);
    } finally { f.cleanup(); }
});

test('account scope_all: only a scope_all admin grants it, and the account then sees entries added later', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'), parent = await f.signIn('parent'), accounts = new AccountAdmin(f.auth);
        const create = async (who: typeof op, params: Record<string, unknown>) => {
            const options = await accounts.stepUpOptions(who.session(), {action: 'account_create', target: '', params});
            return accounts.perform(who.session(), 'account_create', '', {...params, stepUp: {challengeId: options.challengeId, response: who.key.login(options.options, origin)}}) as Promise<{account: {id: string; scopeAll: boolean}}>;
        };
        const wide = (await create(op, {displayName: 'Other parent', role: 'parent', personIds: ['pilot'], scopeAll: true})).account;
        assert.equal(wide.scopeAll, true);
        f.store.run("UPDATE accounts SET role='admin' WHERE id='parent'");
        await assert.rejects(create(parent, {displayName: 'Nope', role: 'parent', personIds: ['pilot'], scopeAll: true}), code('scope_all_required'));
        const added = (await f.act(op, 'child_create', '', {name: 'Later child'})).body.child.id as string;
        assert.deepEqual(JSON.parse(f.store.get<{person_ids: string}>('SELECT person_ids FROM accounts WHERE id=?', wide.id)!.person_ids), ['pilot', added]);
    } finally { f.cleanup(); }
});

test('HTTP: child admin routes are admin-only, CSRF/Origin-checked, and step-up options route by action', async () => {
    const f = fixture(), port = 36000 + process.pid % 9000, base = `http://localhost:${port}`;
    const auth = new Auth(f.store, base, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin: base, host: `localhost:${port}`});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        const sign = async (account: string) => {
            const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
            const options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, account, f.now())}, browser);
            const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, base)}, browser);
            return {cookie: `cf_session=${result.token}; cf_browser=${browser}`, csrf: result.dto.csrfToken};
        };
        const op = await sign('operator'), parent = await sign('parent');
        const call = (who: {cookie: string; csrf: string}, path: string, body?: unknown, headers: Record<string, string> = {}) => fetch(base + path, {method: body === undefined ? 'GET' : 'POST',
            headers: {Cookie: who.cookie, Origin: base, ...(body === undefined ? {} : {'Content-Type': 'application/json', 'X-CSRF-Token': who.csrf}), ...headers}, body: body === undefined ? undefined : JSON.stringify(body)});
        assert.equal((await call(parent, '/admin/children')).status, 403);
        const listed = await (await call(op, '/admin/children')).json();
        assert.deepEqual(listed.children.map((c: {id: string; kind: string}) => [c.id, c.kind]), [['pilot', 'child']]);
        assert.equal((await call(parent, '/step-up/options', {action: 'device_add', target: 'pilot', params: {label: 'T', mac: TABLET, precondition: null}})).status, 403);
        assert.equal((await call(op, '/admin/children', {name: 'X'}, {'X-CSRF-Token': 'wrong'})).status, 403);
        assert.equal((await call(op, '/admin/children', {name: 'X'}, {Origin: 'http://evil.example.test'})).status, 403);
        const stepUp = await call(op, '/step-up/options', {action: 'child_create', target: '', params: {name: 'X'}});
        assert.equal(stepUp.status, 200); assert.ok((await stepUp.json()).challengeId);
        // Without the step-up proof nothing changes.
        assert.equal((await call(op, '/admin/children', {name: 'X'})).status, 403);
        assert.equal(f.store.get<{n: number}>('SELECT count(*) n FROM people')!.n, 1);
        // Account step-ups still route to the account module.
        assert.equal((await call(op, '/step-up/options', {action: 'token_issue', target: 'parent', params: {label: ''}})).status, 200);
    } finally { server.close(); server.closeAllConnections(); f.cleanup(); }
});
