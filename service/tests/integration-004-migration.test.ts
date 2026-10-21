import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { IntegrationStore } from '../src/integration-db.ts';
import { testConfig } from './fixtures/integration.ts';
import { policyJSON } from '../../shared/src/router-schema.ts';

const sql = (name: string) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
const MAC = '02:10:20:30:40:52', SHA = 'a'.repeat(64);

/** A database exactly as integration-001..003 left it (main chain through 008 is applied by the store), with live rows in every table 004 rebuilds or references. */
function legacy(path: string, config: ReturnType<typeof testConfig>): void {
    const db = new DatabaseSync(path);
    for (const name of ['001.sql', '002.sql', '005.sql', '006.sql', '007.sql', '008.sql']) db.exec(name === '001.sql' ? sql(name).replace('revision INTEGER NOT NULL UNIQUE', 'revision INTEGER NOT NULL') : sql(name));
    db.exec('PRAGMA user_version=6');
    db.exec(sql('integration-001.sql'));
    db.prepare("INSERT INTO integration_state(singleton,mode,schema_version,target_digest,manifest_digest,generation) VALUES(1,'integration',1,?,?,?)").run(config.targetDigest, config.manifestDigest, config.router.generation);
    db.prepare('INSERT INTO service_state(singleton,desired_json,highwater) VALUES(1,?,?)').run(policyJSON(config.enrollment), 0);
    db.exec(sql('integration-002.sql'));
    db.exec('PRAGMA foreign_keys=OFF');
    db.exec(sql('integration-003.sql'));
    db.exec('PRAGMA foreign_keys=ON');
    db.exec("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('operator','Operator','admin','[\"pilot\"]','u1')");
    db.exec("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES('op1','operator','pilot','enroll',1,'pending','{}','{}','{}','k1',5,5),('op2','operator','pilot','pause',2,'confirmed','{}','{}','{}','k2',6,6)");
    db.exec("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase) VALUES('op1','" + config.router.generation + "','b','r','{}','queued')");
    db.exec("INSERT INTO dispatch_batches(id,script_sha256,target_digest,generation,dispatch_epoch,approved_at,expires_at,state) VALUES('b1','s1','t','g',0,1,2,'spent')");
    db.exec("INSERT INTO dispatch_steps(batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until) VALUES('b1',1,'op1','activity','r','[]','',5000,'resolved','c',9)");
    db.exec("UPDATE integration_state SET active_operation_id='op1'");
    db.close();
    chmodSync(path, 0o600);
}
const tables = (store: IntegrationStore) => store.all<{name: string}>("SELECT name FROM sqlite_master WHERE type='table'").map(t => t.name);

function assertMigrated(store: IntegrationStore): void {
    for (const name of ['scope_requests', 'router_scope_observed', 'scope_changes', 'operation_people', 'parent_alerts']) assert.ok(tables(store).includes(name), name);
    assert.deepEqual(store.all('PRAGMA foreign_key_check'), []);
    assert.equal(store.get<{foreign_keys: number}>('PRAGMA foreign_keys')!.foreign_keys, 1);
    const opsSql = store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='operations'")!.sql;
    for (const action of ['pause_all', 'resume_all', 'move', 'enroll', 'unenroll']) assert.match(opsSql, new RegExp(`'${action}'`));
    // Children still point at the rebuilt parent.
    assert.match(store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='operation_rpc'")!.sql, /REFERENCES operations\(id\)/);
    assert.doesNotMatch(tables(store).join(','), /operations_next|_v1/);
}

test('integration-004 upgrades a database created by 001-003 in place and keeps every row', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-i004-up-')), config = testConfig(dir);
    try {
        legacy(join(dir, 'integration.sqlite'), config);
        const store = new IntegrationStore(config);
        try {
            assertMigrated(store);
            assert.deepEqual(store.all<{id: string}>('SELECT id FROM operations ORDER BY id').map(r => r.id), ['op1', 'op2']);
            assert.deepEqual({...store.get('SELECT action,state,created_at,idempotency_key FROM operations WHERE id=\'op1\'')!}, {action: 'enroll', state: 'pending', created_at: 5, idempotency_key: 'k1'});
            assert.equal(store.get<{n: number}>('SELECT count(*) n FROM operation_rpc')!.n, 1);
            assert.equal(store.get<{n: number}>('SELECT count(*) n FROM dispatch_steps')!.n, 1);
            assert.equal(store.integrationState().active_operation_id, 'op1');
            // The idempotency uniqueness survives the rebuild.
            assert.throws(() => store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES('op3','operator','pilot','pause',3,'pending','{}','{}','{}','k1',7,7)"), /UNIQUE/);
            store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES('op4','operator','pilot','pause_all',3,'pending','{}','{}','{}','k4',7,7)");
            store.run("INSERT INTO operation_people(operation_id,person_id) VALUES('op4','pilot')");
        } finally { store.close(); }
        // Reopening is a no-op: the marker says 004 already ran.
        const again = new IntegrationStore(config);
        try { assertMigrated(again); assert.equal(again.get<{n: number}>('SELECT count(*) n FROM operations')!.n, 3); } finally { again.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('integration-004 on a fresh database yields the same schema', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-i004-fresh-')), config = testConfig(dir), store = new IntegrationStore(config);
    try {
        assertMigrated(store);
        assert.equal(store.get<{n: number}>('SELECT count(*) n FROM scope_requests')!.n, 0);
    } finally { store.close(); rmSync(dir, {recursive: true, force: true}); }
});

test('integration-004 constraints: request MAC and digest shape, 7-day expiry, one pending request per MAC, bounded alert kind', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-i004-ck-')), config = testConfig(dir), store = new IntegrationStore(config);
    try {
        const insert = (id: string, mac: string, state: string, expires: number, before: string | null = null) =>
            store.run('INSERT INTO scope_requests(id,person_id,mac,requested_by,state,scope_sha_before,generation,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)', id, 'pilot', mac, 'operator', state, before, 'g', 100, expires);
        insert('r1', MAC, 'pending', 100 + 604800, SHA);
        assert.throws(() => insert('r2', MAC, 'pending', 200), /UNIQUE/);
        insert('r3', MAC, 'expired', 200);
        assert.throws(() => insert('r4', '02:10:20:30:40:5E', 'pending', 200), /CHECK/);
        assert.throws(() => insert('r5', '02:10:20:30:40:53', 'pending', 100 + 604801), /CHECK/);
        assert.throws(() => insert('r6', '02:10:20:30:40:53', 'pending', 200, 'A'.repeat(64)), /CHECK/);
        assert.throws(() => insert('r7', '02:10:20:30:40:53', 'bogus', 200), /CHECK/);
        assert.throws(() => store.run("INSERT INTO parent_alerts(kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES('nonsense','info',1,1,1,1,'open','{}')"), /CHECK/);
        store.run("INSERT INTO parent_alerts(kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES('router_scope_change','critical',1,1,1,1,'open','{}')");
    } finally { store.close(); rmSync(dir, {recursive: true, force: true}); }
});
