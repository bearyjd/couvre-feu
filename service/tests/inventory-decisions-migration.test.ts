import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { testConfig } from './fixtures/integration.ts';

const sql = (name: string) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
const AUDIT = 'SELECT id,at,actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id';
const NEW_ACTIONS = ['inventory_classify', 'inventory_undo', 'inventory_link', 'inventory_unlink', 'inventory_stable'];
const COLUMNS = ['generation', 'mac', 'role', 'label', 'previous_role', 'linked_from_mac', 'stable_confirmed', 'stable_at', 'decided_by', 'decided_at'];
const G = 'a'.repeat(64), MAC = '00:00:5e:00:00:07', OTHER = '00:00:5e:00:00:08';
const seed = (db: DatabaseSync) => {
    const insert = db.prepare('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,?,?,?,?)');
    insert.run(1, 'parent', 'pause', 'pilot', 'op_one', 'applied'); insert.run(2, 'parent', 'content_filter_set', 'pilot', null, 'applied'); insert.run(3, 'parent', 'focus_start', null, null, 'refused');
    db.exec("DELETE FROM parent_audit WHERE action='focus_start'");
};
const decision = (store: Store, over: Record<string, string | number | null> = {}) => {
    const v = {generation: G, mac: MAC, role: 'adult', label: null, previous_role: null, linked_from_mac: null, stable_confirmed: 0, stable_at: null, decided_by: 'operator', decided_at: 5, ...over};
    store.run(`INSERT OR REPLACE INTO inventory_decisions(${COLUMNS.join(',')}) VALUES(${COLUMNS.map(() => '?').join(',')})`, ...COLUMNS.map(c => v[c as keyof typeof v]));
};

/** `rows`: an integration database, where inventory_devices exists, so the CHECKs and the foreign key can be exercised with real rows. */
function assertMigrated(store: Store, rows: boolean): void {
    assert.equal(store.get<{strict: number}>("SELECT strict FROM pragma_table_list WHERE name='inventory_decisions'")!.strict, 1);
    assert.deepEqual(store.all<{name: string}>("SELECT name FROM pragma_table_info('inventory_decisions')").map(c => c.name), COLUMNS);
    assert.doesNotMatch(store.all<{name: string}>("SELECT name FROM sqlite_master WHERE type='table'").map(t => t.name).join(','), /_next/);
    assert.deepEqual(store.all('PRAGMA foreign_key_check'), []);
    assert.deepEqual(store.all<{name: string}>("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='parent_audit' AND sql IS NOT NULL ORDER BY name").map(i => i.name), ['parent_audit_at', 'parent_audit_once', 'parent_audit_person']);
    for (const action of NEW_ACTIONS) store.run('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(9,?,?,NULL,?,?)', 'operator', action, 'inventory_row:7', 'applied');
    assert.throws(() => store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'operator', 'inventory_label', 'applied'), /CHECK/);
    assert.deepEqual(store.all('PRAGMA foreign_key_check'), []);
    store.run('DELETE FROM parent_audit WHERE id>2');
    if (!rows) return;
    for (const mac of [MAC, OTHER]) store.run("INSERT OR IGNORE INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'both',1,1)", G, mac);
    assert.throws(() => decision(store, {mac: '00:00:5e:00:00:99'}), /FOREIGN KEY/, 'a decision needs its row');
    for (const role of ['new', 'kid', 'adult', 'infrastructure', 'home', 'guest', 'ignored']) decision(store, {role});
    assert.throws(() => decision(store, {role: 'hidden'}), /CHECK/);
    assert.throws(() => decision(store, {role: 'protected'}), /CHECK/);
    assert.throws(() => decision(store, {previous_role: 'bogus'}), /CHECK/);
    decision(store, {label: 'x'.repeat(40)});
    assert.throws(() => decision(store, {label: 'x'.repeat(41)}), /CHECK/);
    assert.throws(() => decision(store, {label: ''}), /CHECK/);
    assert.throws(() => decision(store, {linked_from_mac: MAC}), /CHECK/, 'a row is never linked to itself');
    assert.throws(() => decision(store, {linked_from_mac: 'short'}), /CHECK/);
    decision(store, {linked_from_mac: OTHER});
    assert.throws(() => decision(store, {stable_confirmed: 2}), /CHECK/);
    assert.throws(() => decision(store, {stable_confirmed: 1, stable_at: null}), /CHECK/);
    decision(store, {stable_confirmed: 1, stable_at: 6});
    assert.throws(() => decision(store, {decided_by: ''}), /CHECK/);
    assert.throws(() => decision(store, {decided_by: 'a'.repeat(65)}), /CHECK/);
    decision(store);
    store.run('DELETE FROM inventory_devices WHERE mac=?', MAC);
    assert.equal(store.get<{n: number}>('SELECT count(*) n FROM inventory_decisions')!.n, 0, 'deleting a row cascades its decision');
    store.run('DELETE FROM inventory_decisions'); store.run('DELETE FROM inventory_devices');
}

test('migration 015 on a fresh demo database creates inventory_decisions and admits the five inventory audit actions', () => {
    const store = new Store(':memory:');
    try { assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 15); assertMigrated(store, false); } finally { store.close(); }
});

test('migration 015 upgrades a demo database at 014 in place and keeps audit rows, ids and the AUTOINCREMENT counter', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m015-')), path = join(dir, 'service.sqlite');
    try {
        const db = new DatabaseSync(path);
        for (let n = 1; n <= 14; n++) db.exec(sql(`${String(n).padStart(3, '0')}.sql`));
        db.exec('PRAGMA user_version=14'); seed(db);
        assert.throws(() => db.exec("INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,'parent','inventory_classify','applied')"), /CHECK/, 'precondition: the old audit table refuses the new action');
        db.close();
        const store = new Store(path);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 15);
            assert.deepEqual(store.all<Record<string, unknown>>(AUDIT).map(r => ({...r})), [
                {id: 1, at: 1, actor_id: 'parent', action: 'pause', person_id: 'pilot', operation_id: 'op_one', result: 'applied'},
                {id: 2, at: 2, actor_id: 'parent', action: 'content_filter_set', person_id: 'pilot', operation_id: null, result: 'applied'}]);
            store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'jd', 'inventory_classify', 'applied');
            assert.deepEqual(store.all<{id: number}>(AUDIT).map(r => r.id), [1, 2, 4], 'the id freed before the rebuild (3) is never reused');
            assert.throws(() => store.run("INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(9,'parent','pause','pilot','op_one','applied')"), /UNIQUE/);
            store.run('DELETE FROM parent_audit WHERE id=4');
            assertMigrated(store, false);
        } finally { store.close(); }
        const again = new Store(path);
        try { assert.equal(again.get<{n: number}>('SELECT count(*) n FROM parent_audit')!.n, 2); } finally { again.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('migration 015 on an integration database: fresh, and an existing database at the previous version', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m015-int-')), config = testConfig(dir), path = join(dir, 'integration.sqlite');
    try {
        let store = new IntegrationStore(config);
        try { assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 13); assertMigrated(store, true); } finally { store.close(); }
        // Put the database back exactly where 014 left it: no inventory_decisions, the 014 audit table with live rows, user_version 12.
        const db = new DatabaseSync(path);
        db.exec('DROP TABLE inventory_decisions'); db.exec('DELETE FROM parent_audit'); seed(db); db.exec(sql('014.sql').split('\n-- The parent-configured')[0]); db.exec('PRAGMA user_version=12');
        assert.throws(() => db.exec("INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,'parent','inventory_classify','applied')"), /CHECK/, 'precondition: the old audit table refuses the new action');
        db.close(); chmodSync(path, 0o600);
        store = new IntegrationStore(config);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 13);
            assert.deepEqual(store.all<{action: string}>('SELECT action FROM parent_audit ORDER BY id').map(r => r.action), ['pause', 'content_filter_set']);
            assertMigrated(store, true);
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
