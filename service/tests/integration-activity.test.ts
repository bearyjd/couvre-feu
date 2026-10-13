import test from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { integrationFixture, testConfig, actor } from './fixtures/integration.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { SSHRouter } from '../src/ssh-router.ts';
import { RouterTransportError } from '../src/router-transport.ts';

const PILOT = '02:10:20:30:40:50', STRANGER = '02:10:20:30:40:99';
const poll = (devices: {person: string; mac: string; tx: number}[], over: Record<string, unknown> = {}) => ({version: 1, router_epoch: 1, counter_epoch: 1, offload: 'off', errors: [], ...over,
    devices: devices.map(d => ({person: d.person, mac: d.mac, ip: '192.168.1.50', neighbor: 'REACHABLE', tx_bytes: d.tx, rx_bytes: 0, tx_packets: 1, rx_packets: 1, blocked_packets: 0}))});
const samples = (f: ReturnType<typeof integrationFixture>) => f.store.all<{mac: string; delta_state: string; delta_bytes: number | null}>('SELECT mac,delta_state,delta_bytes FROM activity_samples ORDER BY sampled_at,mac').map(r => ({...r}));
async function permit(f: ReturnType<typeof integrationFixture>) { const plan = f.worker.prepare('activity'); await f.worker.execute(plan, plan.scriptSha256); return plan; }

test('activity is a separate fixed, read-only SSH invocation that cannot cross-parse', async () => {
    const c = testConfig('/tmp/cf-no-agent-test'), router = new SSHRouter(c), a = router.invocation('activity'), o = router.invocation('observe');
    assert.equal(a.argv.at(-1), 'cfctl rpc-activity --json'); assert.equal(a.stdin, ''); assert.equal(a.kind, 'activity'); assert.equal(a.operationId, null);
    assert.notEqual(a.requestDigest, o.requestDigest);
    assert.deepEqual(a.argv.slice(0, -1), o.argv.slice(0, -1));
    assert.throws(() => router.invocation('activity', undefined, 'op_1'));
    await assert.rejects(router.invoke(a), /invalid_dispatch_kind/);
    await assert.rejects(router.invokeActivity(o), /invalid_dispatch_kind/);
    await assert.rejects(router.invokeActivity({...a, argv: [...a.argv, ';reboot']}), /invocation_changed|invalid_dispatch_kind/);
});
test('an exact operator permit ingests enrolled-device counters once and leaves policy observation state untouched', async () => {
    const f = integrationFixture();
    try {
        await f.observe();
        const before = f.store.observation(), sequence = f.store.integrationState().observation_sequence, calls = f.router.calls.length;
        f.router.activity = poll([{person: 'pilot', mac: PILOT, tx: 1000}, {person: 'pilot', mac: STRANGER, tx: 5}, {person: 'other', mac: '02:10:20:30:40:98', tx: 5}]);
        const plan = await permit(f);
        assert.equal(f.router.calls.length, calls + 1); assert.equal(f.router.calls.at(-1)!.argv.at(-1), 'cfctl rpc-activity --json');
        assert.deepEqual(samples(f), [{mac: PILOT, delta_state: 'baseline', delta_bytes: null}]);
        await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /dispatch_permit_already_consumed/);
        f.advance(30);
        f.router.activity = poll([{person: 'pilot', mac: PILOT, tx: 6000}]);
        await permit(f);
        assert.deepEqual(samples(f).map(s => [s.delta_state, s.delta_bytes]), [['baseline', null], ['valid', 5000]]);
        assert.deepEqual(f.store.observation(), before); assert.equal(f.store.integrationState().observation_sequence, sequence);
        assert.equal(f.store.integrationState().dispatch_stopped, 1);
        assert.equal(f.store.get<{state: string}>("SELECT state FROM dispatch_steps WHERE kind='activity' ORDER BY rowid DESC LIMIT 1")!.state, 'resolved');
        assert.equal(f.store.get<{n: number}>("SELECT COUNT(*) AS n FROM audit WHERE action='activity_poll'")!.n, 2);
        assert.equal(f.worker.activity.report(actor, 'pilot').days.at(-1)!.totalBytes, 5000);
    } finally { f.cleanup(); }
});
test('transport failure, invalid output and router-reported errors store nothing and never pass the automatic path', async () => {
    const f = integrationFixture();
    try {
        f.router.failure = new RouterTransportError('ssh_timeout');
        await permit(f);
        assert.equal(f.store.get<{state: string}>("SELECT state FROM dispatch_steps WHERE kind='activity'")!.state, 'uncertain');
        f.router.failure = null; f.advance(1);
        f.router.activity = {...poll([{person: 'pilot', mac: PILOT, tx: 1}]), extra: 1};
        await permit(f);
        f.advance(1);
        f.router.activity = poll([{person: 'pilot', mac: PILOT, tx: 1}], {errors: ['conntrack_unavailable']});
        await permit(f);
        assert.deepEqual(samples(f), []);
        assert.deepEqual(f.store.all<{outcome: string}>("SELECT outcome FROM audit WHERE action='activity_poll' ORDER BY id").map(r => r.outcome), ['ssh_timeout', 'router_activity_invalid', 'router_reported_errors']);
        await assert.rejects(f.worker.executeAutomatic('activity', {token: 'x', epoch: 0}), /activity_requires_operator_permit/);
    } finally { f.cleanup(); }
});
// Frozen literal copy of the dispatch_steps DDL and index shipped in integration-001.sql before the activity kind existed.
const LEGACY_DISPATCH_STEPS = `CREATE TABLE dispatch_steps (
 batch_id TEXT NOT NULL REFERENCES dispatch_batches(id), ordinal INTEGER NOT NULL CHECK(ordinal=1),
 operation_id TEXT REFERENCES operations(id), kind TEXT NOT NULL CHECK(kind IN ('observe','apply','receipt')),
 request_digest TEXT NOT NULL, argv_json TEXT NOT NULL, stdin_text TEXT NOT NULL,
 deadline_ms INTEGER NOT NULL CHECK(deadline_ms BETWEEN 1000 AND 30000),
 state TEXT NOT NULL CHECK(state IN ('consumed','resolved','uncertain','revoked')),
 claim_token TEXT NOT NULL, lease_until INTEGER NOT NULL,
 PRIMARY KEY(batch_id,ordinal)
) STRICT;
CREATE INDEX dispatch_live_claims ON dispatch_steps(state,lease_until);`;
const schema = (store: IntegrationStore) => store.all<{type: string; name: string; tbl_name: string; sql: string | null}>("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").map(r => ({...r}));
test('integration-002 upgrades a legacy database to exactly the schema of a fresh one, keeping rows', async () => {
    const fresh = integrationFixture(), old = integrationFixture();
    try {
        await old.observe();
        const rows = old.store.all<object>('SELECT * FROM dispatch_steps').map(r => ({...r}));
        assert.equal(rows.length, 1);
        old.store.db.exec(`DROP INDEX dispatch_live_claims; ALTER TABLE dispatch_steps RENAME TO dispatch_steps_tmp; ${LEGACY_DISPATCH_STEPS} INSERT INTO dispatch_steps(batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until) SELECT batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until FROM dispatch_steps_tmp; DROP TABLE dispatch_steps_tmp`);
        assert.ok(!old.store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='dispatch_steps'")!.sql.includes("'activity'"));
        assert.notDeepEqual(schema(old.store), schema(fresh.store));
        old.store.close();
        const upgraded = new IntegrationStore(old.config);
        try {
            assert.deepEqual(schema(upgraded), schema(fresh.store));
            assert.deepEqual(upgraded.all<object>('SELECT * FROM dispatch_steps').map(r => ({...r})), rows);
            upgraded.run("INSERT INTO dispatch_batches(id,script_sha256,target_digest,generation,dispatch_epoch,approved_at,expires_at,state) VALUES('b2','s2',?,?,0,1,2,'spent')", old.config.targetDigest, old.config.router.generation);
            upgraded.run("INSERT INTO dispatch_steps(batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until) VALUES('b2',1,NULL,'activity','d','[]','',1000,'resolved','t',1)");
        } finally { upgraded.close(); }
        const again = new IntegrationStore(old.config);
        try { assert.deepEqual(schema(again), schema(fresh.store)); } finally { again.close(); }
    } finally { fresh.cleanup(); rmSync(old.dir, {recursive: true, force: true}); }
});
