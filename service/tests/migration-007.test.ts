import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { testConfig } from './fixtures/integration.ts';
import { policyJSON } from '../../shared/src/router-schema.ts';

const sql = (name: string) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
/** Builds a database exactly as the pre-007 code left it, with one enrolled account and a live session. */
function legacy(path: string, names: string[], integration: boolean) {
    const db = new DatabaseSync(path);
    for (const name of names) db.exec(integration && name === '001.sql' ? sql(name).replace('revision INTEGER NOT NULL UNIQUE', 'revision INTEGER NOT NULL') : sql(name));
    db.exec(`PRAGMA user_version=${names.length}`);
    db.exec("INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES('owner','Owner','admin','[\"pilot\"]','u1'),('other','Other','parent','[\"pilot\"]','u2')");
    db.exec("INSERT INTO credentials(id,account_id,public_key,counter,transports) VALUES('cred_owner','owner',x'01',7,'[\"internal\"]')");
    db.exec("INSERT INTO auth_contexts(browser_hash,epoch,generation) VALUES('b',0,1)");
    db.exec("INSERT INTO sessions(hash,account_id,csrf,permission_version,expires_at,browser_hash,browser_epoch) VALUES('s1','owner','c',1,9999999999,'b',0)");
    db.exec("INSERT INTO bootstrap_tokens(hash,account_id,expires_at) VALUES('t1','other',9999999999)");
    return db;
}
function assertMigrated(store: Store, version: number) {
    assert.equal((store.db.prepare('PRAGMA user_version').get() as {user_version: number}).user_version, version);
    assert.deepEqual({...store.get('SELECT id,account_id,counter,transports,label,state,created_at,last_used_at FROM credentials')!},
        {id: 'cred_owner', account_id: 'owner', counter: 7, transports: '["internal"]', label: '', state: 'active', created_at: 0, last_used_at: null});
    assert.equal(store.get<{credential_id: string}>("SELECT credential_id FROM sessions WHERE hash='s1'")!.credential_id, 'cred_owner');
    assert.deepEqual({...store.get('SELECT purpose,created_by,label,first_enrollment FROM bootstrap_tokens')!}, {purpose: 'bootstrap', created_by: null, label: '', first_enrollment: 0});
    // UNIQUE(account_id) is gone: a second passkey for the same account is now admissible.
    store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state,created_at) VALUES('cred_two','owner',x'02',0,'[]','pending',1)");
    assert.throws(() => store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports,state) VALUES('cred_bad','owner',x'03',0,'[]','revoked')"), /CHECK/);
    assert.throws(() => store.run("INSERT INTO bootstrap_tokens(hash,account_id,expires_at,purpose) VALUES('t2','owner',1,'login')"), /CHECK/);
}

test('migration 007 upgrades a populated demo database in place and keeps every passkey and session', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m007-demo-')), path = join(dir, 'service.sqlite');
    try {
        legacy(path, ['001.sql', '002.sql', '003.sql', '004.sql', '005.sql', '006.sql'], false).close();
        const store = new Store(path);
        try { assertMigrated(store, 9); } finally { store.close(); }
        const again = new Store(path);
        try { assert.equal(again.get<{n: number}>('SELECT count(*) n FROM credentials')!.n, 2); } finally { again.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('migration 007 upgrades a populated manifest-bound integration database without touching its identity marker', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-m007-int-')), config = testConfig(dir);
    try {
        const db = legacy(join(dir, 'integration.sqlite'), ['001.sql', '002.sql', '005.sql', '006.sql'], true);
        db.exec(sql('integration-001.sql'));
        db.prepare("INSERT INTO integration_state(singleton,mode,schema_version,target_digest,manifest_digest,generation) VALUES(1,'integration',1,?,?,?)").run(config.targetDigest, config.manifestDigest, config.router.generation);
        db.prepare('INSERT INTO service_state(singleton,desired_json,highwater) VALUES(1,?,?)').run(policyJSON(config.enrollment), 0);
        db.close();
        chmodSync(join(dir, 'integration.sqlite'), 0o600);
        const store = new IntegrationStore(config);
        try {
            // 008 follows in the same open: the manifest child and device are seeded, the manifest admin gets scope_all.
            assertMigrated(store, 7);
            assert.deepEqual(store.all<{id: string; scope_all: number}>('SELECT id,scope_all FROM accounts ORDER BY id').map(r => [r.id, r.scope_all]), [['other', 0], ['owner', 1]]);
            assert.deepEqual(store.all<{id: string; kind: string}>('SELECT id,kind FROM people').map(r => [r.id, r.kind]), [['pilot', 'child']]);
            assert.deepEqual({...store.get('SELECT target_digest,manifest_digest,generation FROM integration_state')!}, {target_digest: config.targetDigest, manifest_digest: config.manifestDigest, generation: config.router.generation});
            assert.equal(store.get<{n: number}>('SELECT count(*) n FROM accounts')!.n, 2);
        } finally { store.close(); }
    } finally { rmSync(dir, {recursive: true, force: true}); }
});
