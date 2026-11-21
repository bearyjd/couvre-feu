import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { IntegrationStore } from '../src/integration-db.ts';
import { testConfig } from './fixtures/integration.ts';

const INSERT = "INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at) VALUES(?,'operator','pilot',?,1,'pending','{}','{}','{}',?,1,1)";
const actionSql = (store: IntegrationStore) => store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='operations'")!.sql;

test('integration-010 admits schedule actions, keeps rows, and reopening is a no-op (schedules.editable, unverified on this router)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-i010-')), config = testConfig(dir);
    try {
        const first = new IntegrationStore(config);
        try {
            for (const a of ['schedule_create', 'schedule_update', 'schedule_delete']) { assert.match(actionSql(first), new RegExp(`'${a}'`)); first.run(INSERT, 'op_' + a, a, 'k_' + a); }
            assert.throws(() => first.run(INSERT, 'op_bad', 'schedule_other', 'k_bad'), /CHECK/);
            assert.deepEqual(first.all('PRAGMA foreign_key_check'), []);
        } finally { first.close(); }
        const again = new IntegrationStore(config);
        try { assert.equal(again.get<{n: number}>('SELECT count(*) n FROM operations')!.n, 3); assert.match(actionSql(again), /'allow'/); } finally { again.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
test('integration-010 upgrades a database that stops at 007..009 in place and keeps operation rows and children', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-i010-up-')), config = testConfig(dir), path = join(dir, 'integration.sqlite');
    try {
        const fresh = new IntegrationStore(config);
        fresh.run(INSERT, 'op1', 'pause', 'k1');
        fresh.run("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase) VALUES('op1',?,'b','r','{}','queued')", config.router.generation);
        fresh.close();
        // Put operations back to its 007 shape (no schedule actions) so the store must run 010 on open.
        const db = new DatabaseSync(path);
        db.exec('PRAGMA foreign_keys=OFF');
        const sql = (db.prepare("SELECT sql FROM sqlite_master WHERE name='operations'").get() as {sql: string}).sql;
        const old = sql.replace(",'schedule_create','schedule_update','schedule_delete'", '').replace(/CREATE TABLE "?operations"?/, 'CREATE TABLE operations_x');
        db.exec(`${old}; INSERT INTO operations_x SELECT * FROM operations; DROP TABLE operations; ALTER TABLE operations_x RENAME TO operations`);
        db.close(); chmodSync(path, 0o600);
        const store = new IntegrationStore(config);
        try {
            assert.match(actionSql(store), /'schedule_delete'/);
            assert.deepEqual(store.all<{id: string}>('SELECT id FROM operations').map(r => r.id), ['op1']);
            assert.equal(store.get<{n: number}>('SELECT count(*) n FROM operation_rpc')!.n, 1);
            assert.deepEqual(store.all('PRAGMA foreign_key_check'), []);
            assert.equal(store.get<{foreign_keys: number}>('PRAGMA foreign_keys')!.foreign_keys, 1);
            assert.match(store.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE name='operation_rpc'")!.sql, /REFERENCES operations\(id\)/);
            store.run(INSERT, 'op2', 'schedule_create', 'k2');
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
