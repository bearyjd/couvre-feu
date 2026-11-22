import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { AUDIT_ACTIONS } from '../src/parent-audit.ts';
import { testConfig } from './fixtures/integration.ts';

const sql = (name: string) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
const AUDIT = 'SELECT id,at,actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id';
const NEW_ACTIONS = ['schedule_set', 'schedule_loosened', 'schedule_extra_time', 'schedule_skip_tonight'];
const INSERT = 'INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(9,?,?,?,?,?)';
/** The audit table exactly as 015 left it (the part of 015.sql before its inventory_decisions table), so the 017 upgrade really rebuilds it. */
const audit015 = () => sql('015.sql').split('\n-- Parent decisions')[0]!;
const seed = (db: DatabaseSync) => {
    const insert = db.prepare('INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,?,?,?,?)');
    insert.run(1, 'parent', 'pause', 'pilot', 'op_one', 'applied'); insert.run(2, 'parent', 'inventory_stable', null, 'inventory_row:3', 'applied'); insert.run(3, 'parent', 'owner_guard_refused', null, null, 'refused');
    db.exec("DELETE FROM parent_audit WHERE action='owner_guard_refused'");
};
const EXPECTED = [
    {id: 1, at: 1, actor_id: 'parent', action: 'pause', person_id: 'pilot', operation_id: 'op_one', result: 'applied'},
    {id: 2, at: 2, actor_id: 'parent', action: 'inventory_stable', person_id: null, operation_id: 'inventory_row:3', result: 'applied'}];

function assertMigrated(store: Store): void {
    assert.doesNotMatch(store.all<{name: string}>("SELECT name FROM sqlite_master WHERE type='table'").map(t => t.name).join(','), /_next/);
    assert.equal(store.get<{strict: number}>("SELECT strict FROM pragma_table_list WHERE name='parent_audit'")!.strict, 1);
    assert.deepEqual(store.all('PRAGMA foreign_key_check'), []);
    assert.deepEqual(store.all<{name: string}>("SELECT name FROM pragma_table_info('parent_audit')").map(c => c.name), ['id', 'at', 'actor_id', 'action', 'person_id', 'operation_id', 'result']);
    assert.deepEqual(store.all<{name: string}>("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='parent_audit' AND sql IS NOT NULL ORDER BY name").map(i => i.name), ['parent_audit_at', 'parent_audit_once', 'parent_audit_person']);
    for (const action of NEW_ACTIONS) store.run(INSERT, 'operator', action, 'pilot', 'sched_op_1', 'applied');
    assert.throws(() => store.run(INSERT, 'operator', 'schedule_edit', 'pilot', null, 'applied'), /CHECK/, 'unknown action still refused');
    assert.throws(() => store.run(INSERT, 'operator', 'schedule_set', 'pilot', null, 'maybe'), /CHECK/, 'result enum still closed');
    assert.throws(() => store.run(INSERT, 'operator', 'schedule_set', 'pilot', 'sched_op_1', 'applied'), /UNIQUE/, 'the once index survives');
    store.run("DELETE FROM parent_audit WHERE operation_id='sched_op_1'");
}

test('AUDIT_ACTIONS lists exactly the actions the 018 CHECK admits', () => {
    for (const action of NEW_ACTIONS) assert.ok((AUDIT_ACTIONS as readonly string[]).includes(action));
    const listed = /action IN \(([^)]*)\)/.exec(sql('018.sql'))![1]!.split(',').map(c => c.trim().slice(1, -1));
    assert.deepEqual(listed, [...AUDIT_ACTIONS]);
});

test('migration 017 on a demo database at 016: rows and ids preserved, new actions insertable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m017-')), path = join(dir, 'demo.sqlite');
    try {
        const first = new Store(path);
        try { assert.equal(first.get<{user_version: number}>('PRAGMA user_version')!.user_version, 18); assertMigrated(first); } finally { first.close(); }
        const db = new DatabaseSync(path);
        db.exec("DELETE FROM parent_audit; DELETE FROM sqlite_sequence WHERE name='parent_audit'"); seed(db); db.exec(audit015()); db.exec('PRAGMA user_version=16');
        assert.throws(() => db.prepare(INSERT).run('operator', 'schedule_set', 'pilot', null, 'applied'), /CHECK/, 'precondition: the old table refuses the new action');
        db.close(); chmodSync(path, 0o600);
        const store = new Store(path);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 18);
            assert.deepEqual(store.all<Record<string, unknown>>(AUDIT).map(r => ({...r})), EXPECTED);
            store.run(INSERT, 'operator', 'schedule_set', 'pilot', null, 'applied');
            assert.deepEqual(store.all<{id: number}>(AUDIT).map(r => r.id), [1, 2, 4], 'the id freed before the rebuild (3) is never reused');
            store.run('DELETE FROM parent_audit WHERE id=4');
            assertMigrated(store);
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('migration 017 on an integration database at the previous version', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m017-int-')), config = testConfig(dir), path = join(dir, 'integration.sqlite');
    try {
        let store = new IntegrationStore(config);
        try { assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 16); assertMigrated(store); } finally { store.close(); }
        const db = new DatabaseSync(path);
        db.exec("DELETE FROM parent_audit; DELETE FROM sqlite_sequence WHERE name='parent_audit'"); seed(db); db.exec(audit015()); db.exec('PRAGMA user_version=14');
        db.close(); chmodSync(path, 0o600);
        store = new IntegrationStore(config);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 16);
            assert.deepEqual(store.all<Record<string, unknown>>(AUDIT).map(r => ({...r})), EXPECTED);
            assertMigrated(store);
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('migration 018 preserves an existing schedule audit row and a pruned id from 017', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m018-')), path = join(dir, 'demo.sqlite');
    try {
        new Store(path).close();
        const db = new DatabaseSync(path);
        db.exec("DELETE FROM parent_audit; DELETE FROM sqlite_sequence WHERE name='parent_audit'"); seed(db); db.exec(audit015()); db.exec(sql('017.sql'));
        db.prepare(INSERT).run('operator', 'schedule_set', 'pilot', 'edit_1', 'applied');
        db.prepare(INSERT).run('operator', 'schedule_loosened', 'pilot', 'edit_2', 'applied');
        db.exec("DELETE FROM parent_audit WHERE operation_id='edit_2'; PRAGMA user_version=17");
        assert.throws(() => db.prepare(INSERT).run('operator', 'schedule_extra_time', 'pilot', null, 'refused'), /CHECK/);
        db.close();
        const store = new Store(path);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 18);
            store.run(INSERT, 'operator', 'schedule_extra_time', 'pilot', 'extra_1', 'applied');
            assert.deepEqual(store.all<{id: number; action: string}>('SELECT id,action FROM parent_audit WHERE id>=4 ORDER BY id').map(r => ({...r})),
                [{id: 4, action: 'schedule_set'}, {id: 6, action: 'schedule_extra_time'}]);
            assertMigrated(store);
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
