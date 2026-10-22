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
const GEN = 'a'.repeat(64);
const mac = (n: number) => `00:00:5e:${(n >> 16 & 255).toString(16).padStart(2, '0')}:${(n >> 8 & 255).toString(16).padStart(2, '0')}:${(n & 255).toString(16).padStart(2, '0')}`;

/** A database exactly as integration-001..005 left it, with live rows in the two tables 006 rebuilds. */
function at005(path: string, config: ReturnType<typeof testConfig>): void {
    const db = new DatabaseSync(path);
    for (const name of ['001.sql', '002.sql', '005.sql', '006.sql', '007.sql', '008.sql']) db.exec(name === '001.sql' ? sql(name).replace('revision INTEGER NOT NULL UNIQUE', 'revision INTEGER NOT NULL') : sql(name));
    db.exec('PRAGMA user_version=6');
    db.exec(sql('integration-001.sql'));
    db.prepare("INSERT INTO integration_state(singleton,mode,schema_version,target_digest,manifest_digest,generation) VALUES(1,'integration',1,?,?,?)").run(config.targetDigest, config.manifestDigest, config.router.generation);
    db.prepare('INSERT INTO service_state(singleton,desired_json,highwater) VALUES(1,?,?)').run(policyJSON(config.enrollment), 0);
    db.exec(sql('integration-002.sql'));
    db.exec('PRAGMA foreign_keys=OFF');
    for (const name of ['integration-003.sql', 'integration-004.sql', 'integration-005.sql']) db.exec(sql(name));
    db.exec('PRAGMA foreign_keys=ON');
    db.exec("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('operator','Operator','admin','[\"pilot\"]','u1')");
    db.exec("INSERT INTO dispatch_batches(id,script_sha256,target_digest,generation,dispatch_epoch,approved_at,expires_at,state) VALUES('b1','s1','t','g',0,1,2,'spent')");
    db.exec("INSERT INTO dispatch_steps(batch_id,ordinal,operation_id,kind,request_digest,argv_json,stdin_text,deadline_ms,state,claim_token,lease_until) VALUES('b1',1,NULL,'activity','r','[]','',5000,'resolved','c',9)");
    db.exec("INSERT INTO parent_alerts(id,kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES(41,'router_scope_change','critical',5,5,5,1,'open','{}'),(42,'sync_failed','warning',6,6,6,1,'resolved','{}')");
    db.exec("DELETE FROM parent_alerts WHERE id=42");
    db.close();
    chmodSync(path, 0o600);
}
const names = (s: IntegrationStore, type = 'table') => s.all<{name: string}>("SELECT name FROM sqlite_master WHERE type=?", type).map(t => t.name);
function assertMigrated(s: IntegrationStore): void {
    for (const t of ['inventory_devices', 'inventory_state']) assert.ok(names(s).includes(t), t);
    assert.doesNotMatch(names(s).join(','), /_v1|_next/);
    assert.deepEqual(s.all('PRAGMA foreign_key_check'), []);
    assert.equal(s.get<{foreign_keys: number}>('PRAGMA foreign_keys')!.foreign_keys, 1);
    assert.match(s.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='dispatch_steps'")!.sql, /'inventory'/);
    assert.match(s.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='parent_alerts'")!.sql, /'new_device'/);
    assert.ok(names(s, 'index').includes('parent_alerts_unresolved') && names(s, 'index').includes('dispatch_live_claims'));
}

test('integration-006 on a fresh database creates the inventory tables and admits the new kinds', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-i006-new-')), config = testConfig(dir);
    try {
        const store = new IntegrationStore(config);
        try { assertMigrated(store); } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
test('integration-006 upgrades a 005-level database in place, keeps rows, ids and the unresolved-alert uniqueness, and reopening is a no-op', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-i006-up-')), config = testConfig(dir);
    try {
        at005(join(dir, 'integration.sqlite'), config);
        let store = new IntegrationStore(config);
        try {
            assertMigrated(store);
            assert.equal(store.get<{n: number}>('SELECT count(*) n FROM dispatch_steps')!.n, 1);
            assert.equal(store.get<{kind: string}>('SELECT kind FROM dispatch_steps')!.kind, 'activity');
            assert.deepEqual(store.all<{id: number}>('SELECT id FROM parent_alerts').map(r => r.id), [41]);
            // AUTOINCREMENT high-water survives: the deleted id 42 is never reused.
            store.run("INSERT INTO parent_alerts(kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES('new_device','warning',7,7,7,1,'open','{}')");
            assert.equal(store.get<{id: number}>("SELECT id FROM parent_alerts WHERE kind='new_device'")!.id, 43);
            assert.throws(() => store.run("INSERT INTO parent_alerts(kind,severity,created_at,first_seen,last_seen,count,state,details) VALUES('new_device','warning',8,8,8,1,'open','{}')"), /UNIQUE/);
        } finally { store.close(); }
        store = new IntegrationStore(config);
        try { assertMigrated(store); assert.equal(store.get<{n: number}>('SELECT count(*) n FROM parent_alerts')!.n, 2); } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
test('inventory_devices CHECKs: mac shape, hostname charset/length/first character, ipv4 list size, source, foreign key and the 1024-row cap', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-i006-chk-')), config = testConfig(dir);
    try {
        const store = new IntegrationStore(config);
        try {
            const insert = (m: string, over: {host?: string | null; ips?: string; source?: string; by?: string | null; gen?: string} = {}) =>
                store.run('INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen,acknowledged_at,acknowledged_by) VALUES(?,?,?,?,?,1,1,?,?)',
                    over.gen ?? GEN, m, over.ips ?? '[]', over.host === undefined ? null : over.host, over.source ?? 'both', over.by ? 5 : null, over.by ?? null);
            insert(mac(1)); insert(mac(2), {host: 'host-a.local', ips: '["192.0.2.1","192.0.2.2","192.0.2.3","192.0.2.4"]'}); insert(mac(3), {by: 'operator'});
            for (const bad of [() => insert('00:00:5e:00:00'), () => insert('zz:00:5e:00:00:01'), () => insert(mac(4), {host: 'a b'}), () => insert(mac(4), {host: '<b>'}), () => insert(mac(4), {host: '-x'}),
                () => insert(mac(4), {host: 'a'.repeat(64)}), () => insert(mac(4), {host: ''}), () => insert(mac(4), {ips: '["1.1.1.1","1.1.1.2","1.1.1.3","1.1.1.4","1.1.1.5"]'}), () => insert(mac(4), {ips: '{}'}),
                () => insert(mac(4), {ips: 'nope'}), () => insert(mac(4), {source: 'static'}), () => insert(mac(4), {by: 'nobody'}), () => insert(mac(1)), () => insert(mac(4), {gen: 'short'})]) assert.throws(bad);
            for (let i = 10; i < 10 + 1021; i++) insert(mac(i));
            assert.equal(store.get<{n: number}>('SELECT count(*) n FROM inventory_devices')!.n, 1024);
            assert.throws(() => insert(mac(5000)), /inventory_row_cap/);
            insert(mac(5000), {gen: 'b'.repeat(64)}); // the cap is per generation
            store.run('INSERT INTO inventory_state(singleton) VALUES(1)');
            assert.throws(() => store.run('INSERT INTO inventory_state(singleton) VALUES(2)'));
            assert.equal(store.get<{alert_day_count: number}>('SELECT alert_day_count FROM inventory_state')!.alert_day_count, 0);
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
