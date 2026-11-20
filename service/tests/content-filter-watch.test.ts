import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture } from './fixtures/integration.ts';
import { ParentAlerts } from '../src/parent-alerts.ts';
import { ContentFilterReconciler } from '../src/content-filter-reconcile.ts';
import { ContentFilterStore } from '../src/content-filter-state.ts';
import { ContentFilterWatch, UNREACHABLE_AFTER, UNREACHABLE_REPEAT, startContentFilterWatch } from '../src/content-filter-watch.ts';
import type { Transport } from '../src/nextdns-client.ts';
import { DESIRED, PROFILE_ID, SECRET_ALLOWED, SECRET_DOMAIN, fakeWorld } from './fixtures/content-filter.ts';

function world(wrap?: (next: Transport) => Transport) {
    const f = integrationFixture(), w = fakeWorld(wrap), filters = new ContentFilterStore(f.store, f.now);
    const reconciler = new ContentFilterReconciler({client: w.client, profiles: {pilot: PROFILE_ID}, store: filters});
    const alerts = new ParentAlerts(f.store, null, f.now), watch = new ContentFilterWatch(reconciler, alerts);
    const rows = () => f.store.all<{person_id: string; kind: string; severity: string; count: number; state: string; details: string}>("SELECT person_id,kind,severity,count,state,details FROM parent_alerts WHERE kind='filter_drift'");
    const applied = async () => { filters.put('pilot', DESIRED, 'operator'); await reconciler.reconcile('pilot'); };
    return {...f, ...w, filters, reconciler, alerts, watch, rows, applied};
}

test('a filter that still matches NextDNS raises nothing and writes nothing', async () => {
    const s = world();
    await s.applied();
    const before = s.fake.requests.length;
    await s.watch.tick();
    assert.equal(s.rows().length, 0);
    assert.ok(s.fake.requests.slice(before).every(r => r.method === 'GET'), 'the check is read-only');
});

test('a change made in NextDNS raises one counts-free alert, then the filter is put back', async () => {
    const s = world();
    await s.applied();
    s.profile.parentalControl.safeSearch = false; s.profile.denylist.length = 0;
    await s.watch.tick();
    const [alert] = s.rows();
    assert.equal(s.rows().length, 1);
    assert.deepEqual({person: alert!.person_id, severity: alert!.severity, details: JSON.parse(alert!.details)}, {person: 'pilot', severity: 'warning', details: {cause: 'changed'}});
    assert.doesNotMatch(alert!.details, new RegExp(`${SECRET_DOMAIN}|${SECRET_ALLOWED}|porn|safeSearch`));
    assert.equal(s.filters.get('pilot')!.state, 'applied');
    assert.equal(s.profile.parentalControl.safeSearch, true, 'put back');
    assert.deepEqual(s.profile.denylist.filter(e => e.active).map(e => e.id), [SECRET_DOMAIN]);
    await s.watch.tick();
    assert.equal(s.rows()[0]!.count, 1, 'no second alert once it matches again');
});

test('a second change re-opens an acknowledged alert and counts it', async () => {
    const s = world();
    await s.applied();
    s.profile.parentalControl.blockBypass = false; await s.watch.tick();
    s.store.run("UPDATE parent_alerts SET state='acknowledged' WHERE kind='filter_drift'");
    s.profile.parentalControl.blockBypass = false; await s.watch.tick();
    assert.deepEqual([s.rows()[0]!.state, s.rows()[0]!.count], ['open', 2]);
});

test('unreachable NextDNS raises an info alert only after repeated failed reads, then rarely', async () => {
    let down = false;
    const s = world(next => async req => { if (down) throw new Error('offline'); return next(req); });
    await s.applied();
    down = true;
    for (let i = 1; i < UNREACHABLE_AFTER; i++) { await s.watch.tick(); assert.equal(s.rows().length, 0); }
    await s.watch.tick();
    assert.deepEqual(s.rows().map(r => [r.severity, JSON.parse(r.details), r.count]), [['info', {cause: 'unreachable'}, 1]]);
    for (let i = 0; i < UNREACHABLE_REPEAT - 1; i++) await s.watch.tick();
    assert.equal(s.rows()[0]!.count, 1, 'not on every check');
    await s.watch.tick();
    assert.equal(s.rows()[0]!.count, 2);
    down = false; await s.watch.tick();
    down = true; for (let i = 0; i < UNREACHABLE_AFTER - 1; i++) await s.watch.tick();
    assert.equal(s.rows()[0]!.count, 2, 'a successful read restarts the failure count');
});

test('a save in flight is never mistaken for drift', async () => {
    let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
    const s = world(next => async req => { if (req.method === 'PUT') await gate; return next(req); });
    s.filters.put('pilot', DESIRED, 'operator');
    const running = s.reconciler.reconcile('pilot');
    await s.watch.tick();
    assert.equal(s.rows().length, 0);
    assert.equal(await s.reconciler.check('pilot'), 'skipped');
    release(); await running;
    assert.equal(await s.reconciler.check('pilot'), 'match');
});

test('a child with no stored filter is not checked', async () => {
    const s = world();
    await s.watch.tick();
    assert.equal(s.fake.requests.length, 0);
    assert.equal(await s.reconciler.check('pilot'), 'none');
});

test('migration integration-008: filter_drift is admitted, older kinds and ids are kept', () => {
    const s = world();
    const sql = s.store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='parent_alerts'")!.sql;
    assert.match(sql, /'filter_drift'/);
    s.alerts.raise({kind: 'new_device', personId: null, severity: 'info', details: {count: 1}});
    s.alerts.raise({kind: 'filter_drift', personId: 'pilot', severity: 'warning', details: {cause: 'changed'}});
    assert.equal(s.store.all("SELECT id FROM parent_alerts").length, 2);
    assert.throws(() => s.store.run("INSERT INTO parent_alerts(person_id,kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES('x','nope','info',1,1,1,1,'open','{}')"));
});

test('an unrelated reconcile pass never resolves a filter_drift alert; only an admin acknowledgement ends it', async () => {
    const s = world();
    s.alerts.raise({kind: 'filter_drift', personId: 'pilot', severity: 'warning', details: {cause: 'changed'}});
    s.alerts.reconcile({now: s.now() + 100000, timeRequests: [], activity: []});
    assert.equal(s.rows()[0]!.state, 'open');
});

test('a filter that was never applied is retried quietly: no alert, and it becomes applied', async () => {
    const s = world();
    s.filters.put('pilot', DESIRED, 'operator'); // pending: a save whose write never reached NextDNS
    await s.watch.tick();
    assert.equal(s.rows().length, 0);
    assert.equal(s.filters.get('pilot')!.state, 'applied');
});

test('a match whose stored state is not applied is brought to applied without an alert', async () => {
    const s = world();
    await s.applied();
    s.store.run("UPDATE content_filter_desired SET state='not_confirmed'");
    await s.watch.tick();
    assert.equal(s.rows().length, 0);
    assert.equal(s.filters.get('pilot')!.state, 'applied');
});

test('a filter that cannot converge never re-raises: drift already seen is retried quietly', async () => {
    const s = world(next => async req => { const res = await next(req); if (req.method === 'PUT' && req.path.endsWith('/denylist')) s.profile.denylist.length = 0; return res; });
    await s.applied();
    assert.equal(s.filters.get('pilot')!.state, 'drift');
    for (let i = 0; i < 3; i++) await s.watch.tick();
    assert.equal(s.rows().length, 0, 'the filter never reached applied, so nothing "changed"');
});

test('a store failure ends one pass without rejecting; the timer helper survives it', async () => {
    const s = world();
    await s.applied();
    s.store.run("UPDATE content_filter_desired SET desired_json='not json'");
    await assert.doesNotReject(s.watch.tick());
    const stop = startContentFilterWatch(s.watch, 5, 1);
    await new Promise(resolve => setTimeout(resolve, 40));
    stop();
});

test('a read that overlaps a save is discarded even when the save finishes inside it', async () => {
    let slow!: () => void; const gate = new Promise<void>(resolve => { slow = resolve; });
    let held = false;
    const s = world(next => async req => { if (req.method === 'GET' && held) { held = false; await gate; } return next(req); });
    await s.applied();
    held = true;
    const check = s.reconciler.check('pilot');
    await new Promise(resolve => setTimeout(resolve, 5));
    s.profile.parentalControl.safeSearch = false; // half-written state a concurrent save would leave
    await s.reconciler.reconcile('pilot');
    slow();
    assert.equal(await check, 'skipped');
});

test('a revision change during the read skips the result', async () => {
    let slow!: () => void; const gate = new Promise<void>(resolve => { slow = resolve; });
    let held = false;
    const s = world(next => async req => { if (req.method === 'GET' && held) { held = false; await gate; } return next(req); });
    await s.applied();
    held = true;
    const check = s.reconciler.check('pilot');
    await new Promise(resolve => setTimeout(resolve, 5));
    s.filters.put('pilot', DESIRED, 'operator');
    slow();
    assert.equal(await check, 'skipped');
});
