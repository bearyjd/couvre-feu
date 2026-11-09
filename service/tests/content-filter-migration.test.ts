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
const NEW_ACTIONS = ['content_filter_set', 'content_filter_loosened'];
const seed = (db: DatabaseSync) => {
    const insert = db.prepare('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,?,?,?,?)');
    insert.run(1, 'parent', 'pause', 'pilot', 'op_one', 'applied'); insert.run(2, 'parent', 'focus_start', 'pilot', null, 'applied'); insert.run(3, 'parent', 'owner_guard_refused', null, null, 'refused');
    db.exec("DELETE FROM parent_audit WHERE action='owner_guard_refused'");
};

function assertMigrated(store: Store): void {
    const tables = store.all<{name: string}>("SELECT name FROM sqlite_master WHERE type='table'").map(t => t.name);
    assert.ok(tables.includes('content_filter_desired'));
    assert.doesNotMatch(tables.join(','), /_next/);
    assert.equal(store.get<{strict: number}>("SELECT strict FROM pragma_table_list WHERE name='content_filter_desired'")!.strict, 1);
    assert.deepEqual(store.all<{name: string}>("SELECT name FROM pragma_table_info('content_filter_desired')").map(c => c.name),
        ['person_id', 'revision', 'desired_json', 'desired_sha256', 'state', 'applied_sha256', 'state_at', 'updated_at', 'updated_by']);
    assert.deepEqual(store.all('PRAGMA foreign_key_check'), []);
    assert.equal(store.get<{strict: number}>("SELECT strict FROM pragma_table_list WHERE name='parent_audit'")!.strict, 1);
    const indexes = store.all<{name: string}>("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='parent_audit' AND sql IS NOT NULL ORDER BY name").map(i => i.name);
    assert.deepEqual(indexes, ['parent_audit_at', 'parent_audit_once', 'parent_audit_person']);
    for (const action of NEW_ACTIONS) store.run('INSERT INTO parent_audit(at,actor_id,action,person_id,result) VALUES(9,?,?,?,?)', 'parent', action, 'pilot', 'applied');
    assert.throws(() => store.run('INSERT INTO parent_audit(at,actor_id,action,person_id,result) VALUES(9,?,?,?,?)', 'parent', 'content_filter_domain', 'pilot', 'applied'), /CHECK/);
    const row = (state: string, applied: string | null, desired = 'a'.repeat(64)) => store.run('INSERT OR REPLACE INTO content_filter_desired(person_id,revision,desired_json,desired_sha256,state,applied_sha256,state_at,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?,?)', 'pilot', 1, '{}', desired, state, applied, 1, 1, 'operator');
    row('pending', null); row('drift', 'b'.repeat(64)); row('applied', 'a'.repeat(64));
    assert.throws(() => row('applied', null), /CHECK/); assert.throws(() => row('applied', 'b'.repeat(64)), /CHECK/); assert.throws(() => row('bogus', null), /CHECK/);
    assert.throws(() => store.run('INSERT INTO content_filter_desired(person_id,revision,desired_json,desired_sha256,state,state_at,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?)', 'other', 0, '{}', 'a'.repeat(64), 'pending', 1, 1, 'operator'), /CHECK/);
    store.run('DELETE FROM content_filter_desired'); store.run('DELETE FROM parent_audit WHERE id>2');
}

test('migration 014 on a fresh demo database creates the table and admits the two audit actions', () => {
    const store = new Store(':memory:');
    try { assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 14); assertMigrated(store); } finally { store.close(); }
});

test('migration 014 upgrades a demo database at 013 in place and keeps audit rows, ids and the AUTOINCREMENT counter', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m014-')), path = join(dir, 'service.sqlite');
    try {
        const db = new DatabaseSync(path);
        for (let n = 1; n <= 13; n++) db.exec(sql(`${String(n).padStart(3, '0')}.sql`));
        db.exec('PRAGMA user_version=13'); seed(db); db.close();
        const store = new Store(path);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 14);
            assert.deepEqual(store.all<Record<string, unknown>>(AUDIT).map(r => ({...r})), [
                {id: 1, at: 1, actor_id: 'parent', action: 'pause', person_id: 'pilot', operation_id: 'op_one', result: 'applied'},
                {id: 2, at: 2, actor_id: 'parent', action: 'focus_start', person_id: 'pilot', operation_id: null, result: 'applied'}]);
            store.run('INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,?,?,?)', 'jd', 'content_filter_set', 'applied');
            assert.deepEqual(store.all<{id: number}>(AUDIT).map(r => r.id), [1, 2, 4], 'the id freed before the rebuild (3) is never reused');
            assert.throws(() => store.run("INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(9,'parent','pause','pilot','op_one','applied')"), /UNIQUE/);
            store.run('DELETE FROM parent_audit WHERE id=4');
            assertMigrated(store);
        } finally { store.close(); }
        const again = new Store(path);
        try { assert.equal(again.get<{n: number}>('SELECT count(*) n FROM parent_audit')!.n, 2); } finally { again.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('migration 014 on an integration database: fresh, and an existing database at the previous version', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m014-int-')), config = testConfig(dir), path = join(dir, 'integration.sqlite');
    try {
        let store = new IntegrationStore(config);
        try { assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 12); assertMigrated(store); } finally { store.close(); }
        // Put the database back exactly where 013 left it: no content_filter_desired, the 013 audit table with live rows, user_version 11.
        const db = new DatabaseSync(path);
        db.exec('DROP TABLE content_filter_desired'); db.exec('DELETE FROM parent_audit'); seed(db); db.exec(sql('013.sql')); db.exec('PRAGMA user_version=11');
        assert.throws(() => db.exec("INSERT INTO parent_audit(at,actor_id,action,result) VALUES(9,'parent','content_filter_set','applied')"), /CHECK/, 'precondition: the old audit table refuses the new action');
        db.close(); chmodSync(path, 0o600);
        store = new IntegrationStore(config);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 12);
            assert.deepEqual(store.all<{action: string}>('SELECT action FROM parent_audit ORDER BY id').map(r => r.action), ['pause', 'focus_start']);
            assertMigrated(store);
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
