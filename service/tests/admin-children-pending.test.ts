import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor as operatorActor } from './fixtures/integration.ts';
import { Auth } from '../src/auth.ts';
import { ChildAdmin } from '../src/admin-children.ts';
import { ScopeTracker, SCOPE_REQUEST_TTL } from '../src/integration-scope.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import type { Actor } from '../../shared/src/contracts.ts';

// Placeholder, locally administered unicast MACs only. GET /admin/children lists the requests still waiting for the router (UI plan H).
const ASKED = '02:10:20:30:40:5e', SECOND = '02:10:20:30:40:5f';
const origin = 'http://localhost:4273';
const extra = (n: number) => `02:10:20:30:41:${n.toString(16).padStart(2, '0')}`;
const parent: Actor = {...operatorActor, id: 'parent', role: 'parent'};

function fixture() {
    const f = integrationFixture();
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const admin = new ChildAdmin(auth, f.policy), tracker = new ScopeTracker(f.store, new ParentAlerts(f.store, null, f.now), f.now);
    const hostname = (mac: string, name: string) => f.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',?,'both',?,?)", f.config.router.generation, mac, name, f.now(), f.now());
    return {...f, admin, tracker, hostname};
}

test('pendingScope lists a waiting request by id, child, device name and age, with no address and no request internals', () => {
    const f = fixture();
    try {
        f.hostname(ASKED, 'jacks-pixel');
        const {id} = f.tracker.request(operatorActor, 'pilot', ASKED);
        f.advance(125);
        const {pendingScope, children} = f.admin.list(operatorActor) as unknown as {pendingScope: Record<string, unknown>[]; children: unknown[]};
        assert.deepEqual(pendingScope, [{id, childId: 'pilot', name: 'jacks-pixel', status: 'pending', ageSeconds: 125}]);
        const text = JSON.stringify(pendingScope);
        assert.ok(!text.includes(ASKED) && !/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i.test(text), 'no address in pendingScope');
        for (const secret of ['requested_by', 'operator', 'scope_sha', 'generation', 'expires']) assert.ok(!text.includes(secret), `no ${secret}`);
        assert.equal(children.length, 1);
    } finally { f.cleanup(); }
});

test('a request whose address the inventory has never seen has a null name', () => {
    const f = fixture();
    try {
        f.tracker.request(operatorActor, 'pilot', ASKED);
        const [row] = (f.admin.list(operatorActor) as unknown as {pendingScope: {name: string | null}[]}).pendingScope;
        assert.equal(row.name, null);
    } finally { f.cleanup(); }
});

test('only pending, unexpired requests of this generation inside the admin scope are listed', () => {
    const f = fixture();
    try {
        const pending = f.tracker.request(operatorActor, 'pilot', ASKED).id;
        const seen = f.tracker.request(operatorActor, 'pilot', SECOND).id;
        f.store.run("UPDATE scope_requests SET state='observed',resolved_at=? WHERE id=?", f.now(), seen);
        const stale = f.tracker.request(operatorActor, 'pilot', extra(1)).id;
        f.store.run("UPDATE scope_requests SET generation=? WHERE id=?", 'f'.repeat(64), stale);
        const ids = () => (f.admin.list(operatorActor) as unknown as {pendingScope: {id: string}[]}).pendingScope.map(r => r.id);
        assert.deepEqual(ids(), [pending]);
        f.advance(SCOPE_REQUEST_TTL + 1);
        assert.deepEqual(ids(), [], 'an expired request is not waiting any more');
    } finally { f.cleanup(); }
});

test('an admin who manages no child sees no waiting request, and a parent is refused exactly as before', () => {
    const f = fixture();
    try {
        f.tracker.request(operatorActor, 'pilot', ASKED);
        const other: Actor = {...operatorActor, id: 'bryn', personIds: []};
        assert.deepEqual((f.admin.list(other) as unknown as {pendingScope: unknown[]}).pendingScope, []);
        assert.throws(() => f.admin.list(parent), (error: {status?: number; code?: string}) => error.status === 403 && error.code === 'admin_required');
    } finally { f.cleanup(); }
});

test('a removed child does not list its waiting requests', () => {
    const f = fixture();
    try {
        f.tracker.request(operatorActor, 'pilot', ASKED);
        f.store.run("UPDATE people SET active=0 WHERE id='pilot'");
        assert.deepEqual((f.admin.list(operatorActor) as unknown as {pendingScope: unknown[]}).pendingScope, []);
    } finally { f.cleanup(); }
});

test('pendingScope is bounded however many rows exist', () => {
    const f = fixture();
    try {
        for (let n = 0; n < 150; n++) {
            f.store.run("INSERT INTO scope_requests(id,person_id,mac,requested_by,state,generation,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
                `scope_bulk${n}`, 'pilot', extra(n), 'operator', 'pending', f.config.router.generation, f.now(), f.now() + 3600);
        }
        const {pendingScope} = f.admin.list(operatorActor) as unknown as {pendingScope: unknown[]};
        assert.ok(pendingScope.length > 0 && pendingScope.length <= 64);
    } finally { f.cleanup(); }
});
