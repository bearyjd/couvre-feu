import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { integrationFixture, actor as operatorActor } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { ChildAdmin } from '../src/admin-children.ts';
import type { ChildAction } from '../src/admin-children.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import { ScopeTracker, SCOPE_REQUEST_TTL, PENDING_PER_CHILD } from '../src/integration-scope.ts';
import { TestAuthenticator } from './authenticator.ts';
import { rebindIntegration } from '../src/integration-rebind.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { IntegrationWorker } from '../src/integration-worker.ts';
import { TestRouter } from './fixtures/integration.ts';
import { sha256 } from '../../shared/src/router-rpc.ts';
import type { Actor } from '../../shared/src/contracts.ts';
import type { IntegrationConfig } from '../src/integration-config.ts';

// Placeholder, locally administered unicast MACs only.
const SEED = '02:10:20:30:40:50', TABLET = '02:10:20:30:40:52', LAPTOP = '02:10:20:30:40:53', OUTSIDE = '02:10:20:30:40:5e';
const origin = 'http://localhost:4273';
const code = (expected: string) => (error: {code?: string}) => error.code === expected;
const shaOf = (scope: string[]) => sha256(scope.join('\n') + '\n');
const extra = (n: number) => `02:10:20:30:41:${n.toString(16).padStart(2, '0')}`;
const admin1: Actor = operatorActor, admin2: Actor = {...operatorActor, id: 'bryn', personIds: []};
const parentActor: Actor = {...operatorActor, id: 'parent', role: 'parent'};

function fixture(scope: string[] = [SEED]) {
    const f = integrationFixture();
    (f.config as {routerScope?: string[]}).routerScope = scope;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const admin = new ChildAdmin(auth, f.policy);
    const alerts = new ParentAlerts(f.store, null, f.now), tracker = new ScopeTracker(f.store, alerts, f.now);
    async function signIn(account: string) {
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, account, f.now())}, browser);
        const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, session: () => auth.session(result.token, browser)};
    }
    type Who = Awaited<ReturnType<typeof signIn>>;
    async function act(who: Who, action: ChildAction, target: string, params: Record<string, unknown> = {}) {
        const options = await admin.stepUpOptions(who.session(), {action, target, params});
        const stepUp = {challengeId: options.challengeId, response: who.key.login(options.options, origin)};
        return admin.perform(who.session(), action, target, {...params, stepUp}) as Promise<{status: number; body: Record<string, any>}>;
    }
    /** Observe with a router that reports `scope`, or none (an old router). */
    async function observeScope(scopeList: string[] | undefined, over: Record<string, unknown> = {}) {
        f.advance(1);
        f.router.transform = o => scopeList ? {...o, scope: scopeList, scopeSha: shaOf(scopeList), ...over} : o;
        await f.observe();
    }
    const token = () => f.policy.people(operatorActor).revisionToken!;
    const changes = () => f.store.all<{id: number; sha_before: string | null; sha_after: string; added_json: string; removed_json: string; matched_request_id: string | null}>('SELECT * FROM scope_changes ORDER BY id').map(r => ({...r}));
    const requests = () => f.store.all<Record<string, any>>('SELECT * FROM scope_requests ORDER BY created_at,id').map(r => ({...r}));
    return {...f, auth, admin, alerts, tracker, signIn, act, observeScope, token, changes, requests};
}
const scopeAlerts = (f: ReturnType<typeof fixture>, who: Actor) => f.alerts.list(who).alerts.filter(a => a.kind === 'router_scope_change' && a.state !== 'resolved');

test('first scope observation is a silent baseline against the floor; an identical digest later changes nothing', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED]);
        assert.deepEqual({...f.store.get('SELECT scope_sha FROM router_scope_observed')!}, {scope_sha: shaOf([SEED])});
        assert.deepEqual(f.changes(), []);
        assert.deepEqual(scopeAlerts(f, admin1), []);
        await f.observeScope([SEED]);
        assert.deepEqual(f.changes(), []);
    } finally { f.cleanup(); }
});

test('growth that matches a pending request is recorded as matched and resolves the request; no alert', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED]);
        const {id} = f.tracker.request(operatorActor, 'pilot', TABLET);
        await f.observeScope([SEED, TABLET]);
        const [change] = f.changes();
        assert.equal(f.changes().length, 1);
        assert.equal(change.matched_request_id, id);
        assert.equal(change.sha_before, shaOf([SEED])); assert.equal(change.sha_after, shaOf([SEED, TABLET]));
        assert.deepEqual(JSON.parse(change.added_json), [TABLET]); assert.deepEqual(JSON.parse(change.removed_json), []);
        const [row] = f.requests();
        assert.equal(row.state, 'observed'); assert.equal(row.scope_sha_after, shaOf([SEED, TABLET])); assert.equal(row.scope_sha_before, shaOf([SEED]));
        assert.equal(row.requested_by, 'operator'); assert.equal(row.mac, TABLET); assert.equal(typeof row.resolved_at, 'number');
        // S2: matched growth is still told to the admins, as information.
        const found = scopeAlerts(f, admin1);
        assert.equal(found.length, 1); assert.equal(found[0].severity, 'info'); assert.equal(found[0].details.matched, true);
        assert.deepEqual(scopeAlerts(f, parentActor), []);
    } finally { f.cleanup(); }
});

test('unmatched growth is recorded with NULL match and alerts every admin, never a parent; details carry no MAC', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED]);
        await f.observeScope([SEED, LAPTOP]);
        const [change] = f.changes();
        assert.equal(change.matched_request_id, null);
        assert.deepEqual(JSON.parse(change.added_json), [LAPTOP]);
        for (const who of [admin1, admin2]) {
            const found = scopeAlerts(f, who);
            assert.equal(found.length, 1); assert.equal(found[0].state, 'open'); assert.equal(found[0].severity, 'critical'); assert.equal(found[0].personId, null); assert.equal(found[0].details.matched, false);
            assert.doesNotMatch(JSON.stringify(found[0]), /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/);
        }
        assert.deepEqual(scopeAlerts(f, parentActor), []);
        // A second unmatched change after an acknowledgement re-opens the alert rather than hiding behind it.
        f.alerts.acknowledge(admin1, scopeAlerts(f, admin1)[0].id);
        await f.observeScope([SEED, TABLET, LAPTOP]);
        assert.equal(scopeAlerts(f, admin1)[0].state, 'open');
        assert.equal(f.changes().length, 2);
    } finally { f.cleanup(); }
});

test('removal is recorded as unmatched and alerts', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED, TABLET]);
        // Baseline against the floor [SEED] saw TABLET appear unrequested.
        assert.equal(f.changes().length, 1);
        f.store.run('UPDATE parent_alerts SET state=\'resolved\',resolved_at=1');
        await f.observeScope([SEED]);
        const removal = f.changes()[1];
        assert.deepEqual(JSON.parse(removal.removed_json), [TABLET]); assert.deepEqual(JSON.parse(removal.added_json), []);
        assert.equal(removal.matched_request_id, null);
        assert.equal(scopeAlerts(f, admin2).length, 1);
        assert.equal(scopeAlerts(f, admin2)[0].severity, 'warning');
    } finally { f.cleanup(); }
});

test('a reply without scope, or with errors, is unknown: it never reads as shrinkage and never overwrites the baseline', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED, TABLET]);
        const before = f.changes().length, sha = f.store.get<{scope_sha: string}>('SELECT scope_sha FROM router_scope_observed')!.scope_sha;
        await f.observeScope(undefined);
        f.advance(1); f.router.transform = o => ({...o, scope: [SEED], scopeSha: shaOf([SEED]), errors: ['busy']}); await f.observe();
        assert.equal(f.changes().length, before);
        assert.equal(f.store.get<{scope_sha: string}>('SELECT scope_sha FROM router_scope_observed')!.scope_sha, sha);
    } finally { f.cleanup(); }
});

test('mixed change: the matching request resolves, but the change is unmatched and alerts', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED]);
        f.tracker.request(operatorActor, 'pilot', TABLET);
        await f.observeScope([SEED, TABLET, LAPTOP]);
        assert.equal(f.changes()[0].matched_request_id, null);
        assert.equal(f.requests()[0].state, 'observed');
        assert.equal(scopeAlerts(f, admin1).length, 1);
    } finally { f.cleanup(); }
});

test('scope requests: pending dedupe by MAC, cap per child, other child conflicts, 7-day expiry, resolved rows kept', () => {
    const f = fixture();
    try {
        const first = f.tracker.request(operatorActor, 'pilot', TABLET);
        assert.equal(first.created, true);
        assert.deepEqual(f.tracker.request(operatorActor, 'pilot', TABLET), {id: first.id, created: false});
        assert.equal(f.requests().length, 1);
        assert.equal(PENDING_PER_CHILD, 4);
        for (let i = 1; i < PENDING_PER_CHILD; i++) f.tracker.request(operatorActor, 'pilot', extra(i));
        assert.throws(() => f.tracker.request(operatorActor, 'pilot', extra(99)), code('scope_request_limit'));
        assert.equal(f.requests().length, PENDING_PER_CHILD);
        f.store.run("INSERT INTO people(id,name,active,created_at) VALUES('second','Second',1,0)");
        assert.throws(() => f.tracker.request(operatorActor, 'second', TABLET), code('scope_request_conflict'));
        assert.equal(f.requests()[0].expires_at - f.requests()[0].created_at, SCOPE_REQUEST_TTL);
        assert.equal(SCOPE_REQUEST_TTL, 7 * 86400);
        // Expiry frees the cap and the MAC; the old row stays as 'expired'.
        f.advance(SCOPE_REQUEST_TTL);
        const again = f.tracker.request(operatorActor, 'pilot', TABLET);
        assert.equal(again.created, true); assert.notEqual(again.id, first.id);
        assert.equal(f.requests().filter(r => r.state === 'expired').length, PENDING_PER_CHILD);
        assert.equal(f.requests().filter(r => r.state === 'pending').length, 1);
    } finally { f.cleanup(); }
});

test('an expired request does not count as a match for later growth', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED]);
        f.tracker.request(operatorActor, 'pilot', TABLET);
        f.advance(SCOPE_REQUEST_TTL);
        await f.observeScope([SEED, TABLET]);
        assert.equal(f.changes()[0].matched_request_id, null);
        assert.equal(f.requests()[0].state, 'expired');
        assert.equal(scopeAlerts(f, admin1).length, 1);
    } finally { f.cleanup(); }
});

test('device add outside the floor and the observed scope answers 409 device_pending_router_scope with no command, and records the request and audit', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observeScope(undefined);
        const result = await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: OUTSIDE, precondition: f.token()});
        assert.equal(result.status, 409);
        assert.equal(result.body.error.code, 'device_pending_router_scope');
        assert.equal(result.body.error.mac, OUTSIDE);
        const {mac: _mac, requestId: _id, ...rest} = result.body.error;
        assert.match(rest.message, /cfctl scope-add <ADDRESS FROM DEVICE SETTINGS> --base <router-read>/);
        // No paste-ready command: the canonical MAC appears only in its own field, and no concrete --base value exists.
        assert.doesNotMatch(JSON.stringify(rest), /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/);
        assert.doesNotMatch(JSON.stringify(result.body), /--base [0-9a-f]{8}/);
        const [row] = f.requests();
        assert.equal(row.mac, OUTSIDE); assert.equal(row.person_id, 'pilot'); assert.equal(row.requested_by, 'operator'); assert.equal(row.state, 'pending');
        assert.equal(result.body.error.requestId, row.id);
        assert.equal(f.store.all('SELECT * FROM audit WHERE action=\'admin_device_add\'').length, 1);
        assert.equal(f.store.all('SELECT * FROM devices WHERE identifier=?', OUTSIDE).length, 0);
        // The same MAC again dedupes onto the same pending row.
        const second = await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: OUTSIDE, precondition: f.token()});
        assert.equal(second.status, 409); assert.equal(second.body.error.requestId, row.id); assert.equal(f.requests().length, 1);
        // The cap per child shows as a refusal, not another row.
        for (let i = 1; i < PENDING_PER_CHILD; i++) await f.act(op, 'device_add', 'pilot', {label: 'T', mac: extra(i), precondition: f.token()});
        await assert.rejects(f.act(op, 'device_add', 'pilot', {label: 'T', mac: extra(99), precondition: f.token()}), code('scope_request_limit'));
        assert.equal(f.requests().length, PENDING_PER_CHILD);
    } finally { f.cleanup(); }
});

test('the device becomes enrollable once a fresh observation includes its MAC; a stale one does not', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observeScope([SEED]);
        assert.equal((await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: OUTSIDE, precondition: f.token()})).status, 409);
        await f.observeScope([SEED, OUTSIDE]);
        assert.equal(f.requests()[0].state, 'observed');
        const added = await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: OUTSIDE, precondition: f.token()});
        assert.notEqual(added.status, 409);
        assert.equal(f.store.get<{state: string}>('SELECT state FROM devices WHERE identifier=?', OUTSIDE)!.state, 'enrolling');
        // A stale observation no longer vouches for the scope.
        const f2 = fixture();
        try {
            const op2 = await f2.signIn('operator'); await f2.observeScope([SEED, OUTSIDE]); const tok2 = f2.token();
            f2.advance(40);
            const stale = await f2.act(op2, 'device_add', 'pilot', {label: 'Tablet', mac: OUTSIDE, precondition: tok2});
            assert.equal(stale.status, 409); assert.equal(stale.body.error.code, 'device_pending_router_scope');
        } finally { f2.cleanup(); }
    } finally { f.cleanup(); }
});

test('an old router (no scope) keeps today\'s floor behaviour: floor MACs enroll, everything else pends', async () => {
    const f = fixture([SEED, TABLET]);
    try {
        const op = await f.signIn('operator'); await f.observeScope(undefined); const tok = f.token();
        const added = await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: TABLET, precondition: tok});
        assert.notEqual(added.status, 409);
        // The queued enrollment hides the live token; the scope check comes after the (syntactic) precondition check.
        assert.equal((await f.act(op, 'device_add', 'pilot', {label: 'Other', mac: LAPTOP, precondition: tok})).status, 409);
    } finally { f.cleanup(); }
});

test('rebind validates stored devices against the NEW manifest floor, never the old observed scope, and resets the scope baseline', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED, OUTSIDE]);
        f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('d_out','pilot','Scoped','mac',?, 'active',1)", OUTSIDE);
        f.store.run('UPDATE integration_state SET dispatch_stopped=1');
        const next = (change: Partial<IntegrationConfig>): IntegrationConfig => ({...f.config, router: {...f.config.router, generation: 'e'.repeat(64)}, manifestDigest: 'f'.repeat(64), targetDigest: '9'.repeat(64), ...change});
        const run = (config: IntegrationConfig) => rebindIntegration(f.store, config, f.config.manifestDigest, config.manifestDigest, f.now());
        // The old generation observed OUTSIDE in scope; the new manifest floor does not list it, so the rebind refuses.
        assert.throws(() => run(next({routerScope: [SEED]})), /rebind_device_outside_scope/);
        assert.equal(f.store.all('SELECT * FROM router_scope_observed').length, 1);
        run(next({routerScope: [SEED, OUTSIDE]}));
        assert.deepEqual(f.store.all('SELECT * FROM router_scope_observed'), []);
        assert.equal(f.store.observation().value, null);
    } finally { f.cleanup(); }
});

test('S2: a request created after the router change but before the observation still alerts (info)', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED]);
        f.advance(1);
        f.router.transform = o => { f.tracker.request(admin1, 'pilot', OUTSIDE); return {...o, scope: [SEED, OUTSIDE], scopeSha: shaOf([SEED, OUTSIDE])}; };
        await f.observe();
        const found = scopeAlerts(f, admin1);
        assert.equal(found.length, 1); assert.equal(found[0].severity, 'info');
    } finally { f.cleanup(); }
});

test('S4/C4: scope-change audit rows carry the MACs, the requesters, the digests and every matched request id; requests audit the MAC and requester', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observeScope([SEED]);
        const a = f.tracker.request(operatorActor, 'pilot', TABLET), b = f.tracker.request(operatorActor, 'pilot', LAPTOP);
        await f.observeScope([SEED, TABLET, LAPTOP]);
        const rows = f.store.all<{outcome: string; actor_id: string}>("SELECT actor_id,outcome FROM audit WHERE action='router_scope_change'");
        assert.equal(rows.length, 1);
        const outcome = JSON.parse(rows[0].outcome);
        assert.equal(outcome.result, 'matched'); assert.equal(outcome.before, shaOf([SEED])); assert.equal(outcome.after, shaOf([SEED, TABLET, LAPTOP]));
        assert.deepEqual(outcome.added, [TABLET, LAPTOP]); assert.deepEqual(outcome.removed, []);
        assert.deepEqual(outcome.requests.map((r: {id: string}) => r.id).sort(), [a.id, b.id].sort());
        assert.ok(outcome.requests.every((r: {requestedBy: string}) => r.requestedBy === 'operator'));
        // Unmatched removal records what left.
        await f.observeScope([SEED]);
        const last = JSON.parse(f.store.all<{outcome: string}>("SELECT outcome FROM audit WHERE action='router_scope_change' ORDER BY id DESC LIMIT 1")[0].outcome);
        assert.equal(last.result, 'unmatched'); assert.deepEqual(last.removed, [TABLET, LAPTOP]);
        // The alert still carries counts only.
        assert.doesNotMatch(JSON.stringify(scopeAlerts(f, admin1)), /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/);
        // A device_add that becomes a request audits MAC and requester.
        await f.act(op, 'device_add', 'pilot', {label: 'T', mac: OUTSIDE, precondition: f.token()});
        const audit = f.store.get<{outcome: string}>("SELECT outcome FROM audit WHERE action='admin_device_add' ORDER BY id DESC LIMIT 1")!.outcome;
        assert.match(audit, /scope_request:/); assert.ok(audit.includes(OUTSIDE)); assert.ok(audit.includes('operator'));
    } finally { f.cleanup(); }
});

test('S5: a rebind cancels pending requests; a stale-generation pending row neither swallows a new request nor matches growth', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED]);
        const pending = f.tracker.request(admin1, 'pilot', TABLET);
        f.store.run('UPDATE integration_state SET dispatch_stopped=1');
        const config: IntegrationConfig = {...f.config, router: {...f.config.router, generation: 'e'.repeat(64)}, manifestDigest: 'f'.repeat(64), targetDigest: '9'.repeat(64)};
        rebindIntegration(f.store, config, f.config.manifestDigest, config.manifestDigest, f.now());
        const cancelled = f.requests().find(r => r.id === pending.id)!;
        assert.equal(cancelled.state, 'cancelled'); assert.equal(typeof cancelled.resolved_at, 'number');
    } finally { f.cleanup(); }
    // PROBE2: a stale pending row (as left by a rebind that predates this fix).
    const g = fixture();
    try {
        await g.observeScope([SEED]);
        g.store.run("INSERT INTO scope_requests(id,person_id,mac,requested_by,state,generation,created_at,expires_at) VALUES('scope_old','pilot',?,'operator','pending',?,?,?)", OUTSIDE, 'e'.repeat(64), g.now(), g.now() + 86400);
        const again = g.tracker.request(admin1, 'pilot', OUTSIDE);
        assert.equal(again.created, true); assert.notEqual(again.id, 'scope_old');
        // The stale row does not count toward the per-child cap either.
        for (let i = 1; i < PENDING_PER_CHILD; i++) g.tracker.request(admin1, 'pilot', extra(i));
        await g.observeScope([SEED, OUTSIDE]);
        assert.equal(g.changes()[0].matched_request_id, again.id);
        assert.equal(g.requests().find(r => r.id === 'scope_old')!.state, 'pending');
    } finally { g.cleanup(); }
});

test('S6: scope from a reply that carries errors never authorizes device_add', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observeScope([SEED]); const tok = f.token();
        f.advance(1); f.router.transform = o => ({...o, scope: [SEED, OUTSIDE], scopeSha: shaOf([SEED, OUTSIDE]), errors: ['busy']}); await f.observe();
        const r = await f.act(op, 'device_add', 'pilot', {label: 'Tablet', mac: OUTSIDE, precondition: tok});
        assert.equal(r.status, 409); assert.equal(r.body.error.code, 'device_pending_router_scope');
    } finally { f.cleanup(); }
});

test('S7: the device limit and a missing precondition are refused before any scope request is created', async () => {
    const f = fixture();
    try {
        const op = await f.signIn('operator'); await f.observeScope([SEED]);
        await assert.rejects(f.act(op, 'device_add', 'pilot', {label: 'T', mac: OUTSIDE, precondition: null}), code('revision_precondition_required'));
        assert.equal(f.requests().length, 0);
        for (let i = 0; i < 32; i++) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,'pilot','d','mac',?,'active',1)", `d_fill${i}`, extra(100 + i));
        await assert.rejects(f.act(op, 'device_add', 'pilot', {label: 'T', mac: OUTSIDE, precondition: f.token()}), code('child_device_limit_reached'));
        assert.equal(f.requests().length, 0);
    } finally { f.cleanup(); }
});

test('C3a: a rebind onto a router whose live scope is larger raises exactly one critical unmatched alert on the first observation', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED]);
        f.store.run('UPDATE integration_state SET dispatch_stopped=1');
        const config: IntegrationConfig = {...f.config, router: {...f.config.router, generation: 'e'.repeat(64)}, manifestDigest: 'f'.repeat(64), targetDigest: '9'.repeat(64)};
        rebindIntegration(f.store, config, f.config.manifestDigest, config.manifestDigest, f.now());
        // A restart under the new manifest: the router now reports a larger live scope than the new floor.
        const store2 = new IntegrationStore(config), router2 = new TestRouter(store2, f.now), worker2 = new IntegrationWorker(store2, router2, f.now);
        try {
            f.advance(1); router2.transform = o => ({...o, scope: [SEED, LAPTOP], scopeSha: shaOf([SEED, LAPTOP])});
            const plan = worker2.prepare('observe'); await worker2.execute(plan, plan.scriptSha256);
            const found = new ParentAlerts(store2, null, f.now).list(admin1).alerts.filter(a => a.kind === 'router_scope_change');
            assert.equal(found.length, 1); assert.equal(found[0].severity, 'critical'); assert.equal(found[0].count, 1);
            assert.equal(store2.all('SELECT * FROM scope_changes').length, 1);
        } finally { store2.close(); }
    } finally { f.cleanup(); }
});

test('C3b: an observation without scope, or with errors, leaves the stored scope row byte-identical', async () => {
    const f = fixture();
    try {
        await f.observeScope([SEED, TABLET]);
        const row = () => JSON.stringify(f.store.get('SELECT * FROM router_scope_observed'));
        const before = row();
        await f.observeScope(undefined); assert.equal(row(), before);
        f.advance(1); f.router.transform = o => ({...o, scope: [SEED], scopeSha: shaOf([SEED]), errors: ['busy']}); await f.observe(); assert.equal(row(), before);
    } finally { f.cleanup(); }
});
