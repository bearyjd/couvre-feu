import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { CLASS_CODES } from '../../shared/src/content-filter-classes.ts';
import { testConfig } from './fixtures/integration.ts';

const sql = (name: string) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
const DAY = ['person_id', 'day', 'state', 'total', 'blocked', 'attempts', 'fetched_at'], CLASS = ['person_id', 'day', 'class', 'queries'];
const day = (store: Store, over: Record<string, string | number | null> = {}) => {
    const v = {person_id: 'pilot', day: '2026-11-10', state: 'ok', total: 10, blocked: 2, attempts: 0, fetched_at: 1, ...over};
    store.run('INSERT OR REPLACE INTO content_filter_day(person_id,day,state,total,blocked,attempts,fetched_at) VALUES(?,?,?,?,?,?,?)', v.person_id!, v.day!, v.state!, v.total!, v.blocked!, v.attempts!, v.fetched_at!);
};
const cls = (store: Store, over: Record<string, string | number> = {}) => {
    const v = {person_id: 'pilot', day: '2026-11-10', class: 'adult', queries: 1, ...over};
    store.run('INSERT OR REPLACE INTO content_filter_day_class(person_id,day,class,queries) VALUES(?,?,?,?)', v.person_id!, v.day!, v.class!, v.queries!);
};

function assertMigrated(store: Store): void {
    for (const [table, columns] of [['content_filter_day', DAY], ['content_filter_day_class', CLASS]] as const) {
        assert.equal(store.get<{strict: number}>(`SELECT strict FROM pragma_table_list WHERE name='${table}'`)!.strict, 1, table);
        assert.deepEqual(store.all<{name: string}>(`SELECT name FROM pragma_table_info('${table}')`).map(c => c.name), columns);
    }
    assert.deepEqual(store.all('PRAGMA foreign_key_check'), []);
    for (const state of ['ok', 'suspect_zero']) day(store, {state, total: 0, blocked: 0});
    day(store, {state: 'unavailable', total: null, blocked: null}); day(store, {state: 'logs_off', total: null, blocked: null});
    assert.throws(() => day(store, {state: 'bogus', total: null, blocked: null}), /CHECK/);
    assert.throws(() => day(store, {state: 'ok', total: null, blocked: null}), /CHECK/, 'an ok day has its totals');
    assert.throws(() => day(store, {state: 'unavailable', total: 1, blocked: 1}), /CHECK/, 'a gap has none');
    assert.throws(() => day(store, {total: -1}), /CHECK/); assert.throws(() => day(store, {blocked: -1}), /CHECK/); assert.throws(() => day(store, {attempts: -1}), /CHECK/);
    assert.throws(() => day(store, {total: 1.5}), /datatype|CHECK|cannot store/, 'integers only');
    assert.throws(() => day(store, {total: 'many'}), /datatype|CHECK|cannot store/);
    for (const bad of ['2026-1-10', '2026-11-10T01:00', 'yesterday', '']) assert.throws(() => day(store, {day: bad}), /CHECK/, bad);
    assert.throws(() => day(store, {person_id: ''}), /CHECK/); assert.throws(() => day(store, {person_id: 'x'.repeat(65)}), /CHECK/);
    day(store);
    for (const code of CLASS_CODES) cls(store, {class: code});
    for (const bad of ['porn', 'denylist:secret.test', 'ADULT', '']) assert.throws(() => cls(store, {class: bad}), /CHECK/, bad);
    assert.throws(() => cls(store, {queries: -1}), /CHECK/); assert.throws(() => cls(store, {queries: 0.5}), /datatype|CHECK|cannot store/);
    for (const bad of ['2026-1-10', '2026-11-10T01:00', 'yesterday', '']) assert.throws(() => cls(store, {day: bad}), /CHECK/, `class day ${bad}`);
    assert.throws(() => cls(store, {person_id: ''}), /CHECK/); assert.throws(() => cls(store, {person_id: 'x'.repeat(65)}), /CHECK/);
    assert.throws(() => cls(store, {day: '2026-11-11'}), /FOREIGN KEY/, 'a class row needs its day');
    assert.equal(store.get<{n: number}>('SELECT count(*) n FROM content_filter_day_class')!.n, CLASS_CODES.length);
    store.run("DELETE FROM content_filter_day WHERE day='2026-11-10'");
    assert.equal(store.get<{n: number}>('SELECT count(*) n FROM content_filter_day_class')!.n, 0, 'classes go with their day');
    store.run('DELETE FROM content_filter_day');
    assert.ok(store.all<{name: string}>("SELECT name FROM sqlite_master WHERE type='index'").some(i => i.name === 'content_filter_day_day'));
}

test('migration 016 on a fresh demo database creates both tables, empty, with their constraints', () => {
    const store = new Store(':memory:');
    try {
        assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 18);
        assert.equal(store.get<{n: number}>('SELECT count(*) n FROM content_filter_day')!.n, 0);
        assertMigrated(store);
    } finally { store.close(); }
});

test('migration 016 upgrades a demo database at 015 in place and touches nothing else', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m016-')), path = join(dir, 'service.sqlite');
    try {
        const db = new DatabaseSync(path);
        for (let n = 1; n <= 15; n++) db.exec(sql(`${String(n).padStart(3, '0')}.sql`));
        db.exec('PRAGMA user_version=15');
        db.exec("INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(1,'parent','pause','pilot','op_one','applied')");
        db.exec("INSERT INTO content_filter_desired(person_id,revision,desired_json,desired_sha256,state,state_at,updated_at,updated_by) VALUES('pilot',1,'{}','" + 'a'.repeat(64) + "','pending',1,1,'operator')");
        db.close();
        const store = new Store(path);
        try {
            assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 18);
            assert.equal(store.get<{n: number}>('SELECT count(*) n FROM parent_audit')!.n, 1);
            assert.equal(store.get<{n: number}>('SELECT count(*) n FROM content_filter_desired')!.n, 1);
            assertMigrated(store);
        } finally { store.close(); }
        const again = new Store(path);
        try { assert.equal(again.get<{user_version: number}>('PRAGMA user_version')!.user_version, 18); } finally { again.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('migration 016 on an integration database: fresh, and an existing database at the previous version', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m016-int-')), config = testConfig(dir), path = join(dir, 'integration.sqlite');
    try {
        let store = new IntegrationStore(config);
        try { assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 17); assertMigrated(store); } finally { store.close(); }
        const db = new DatabaseSync(path);
        db.exec('DROP TABLE content_filter_day_class'); db.exec('DROP TABLE content_filter_day'); db.exec('PRAGMA user_version=13');
        db.close(); chmodSync(path, 0o600);
        store = new IntegrationStore(config);
        try { assert.equal(store.get<{user_version: number}>('PRAGMA user_version')!.user_version, 17); assertMigrated(store); } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('the class list in the migration is exactly the shared closed set', () => {
    const listed = /class TEXT NOT NULL CHECK\(class IN \(([^)]*)\)\)/.exec(sql('016.sql'))![1]!.split(',').map(c => c.trim().slice(1, -1));
    assert.deepEqual(listed, [...CLASS_CODES]);
});
