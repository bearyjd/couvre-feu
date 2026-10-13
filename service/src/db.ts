import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync, existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
export class Store {
    readonly db: DatabaseSync;
    constructor(path: string, migrationSQL?: string, internalMode?: 'integration') {
        const migrations = migrationSQL === undefined
            ? (internalMode === 'integration' ? ['001.sql', '002.sql', '005.sql'] : ['001.sql', '002.sql', '003.sql', '004.sql', '005.sql']).map(name => {
                const sql = readFileSync(fileURLToPath(new URL(`../migrations/${name}`, import.meta.url)), 'utf8');
                // CAS allocates base+1. An explicitly never-delivered intent cannot reserve that router revision.
                return internalMode === 'integration' && name === '001.sql' ? sql.replace('revision INTEGER NOT NULL UNIQUE', 'revision INTEGER NOT NULL') : sql;
            })
            : [migrationSQL];
        if (path !== ':memory:') {
            mkdirSync(dirname(resolve(path)), {
                recursive: true, mode: 0o700
            });
        }
        this.db = new DatabaseSync(path, {
            timeout: 1000, enableForeignKeyConstraints: true, allowExtension: false, defensive: true
        });
        if (path !== ':memory:' && existsSync(path)) {
            chmodSync(path, 0o600);
        }
        try {
            const marker = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='integration_state'").get();
            if (marker && internalMode !== 'integration') throw new Error('integration_database_forbidden');
            if (internalMode === 'integration' && !marker && this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'").get()) throw new Error('demo_database_forbidden');
            this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;');
            const version = this.db.prepare('PRAGMA user_version').get()!.user_version;
            if (typeof version !== 'number' || version < 0 || version > migrations.length) {
                throw new Error('unsupported_database_version');
            }
            for (let index = version; index < migrations.length; index++) {
                this.transaction(() => {
                    this.db.exec(migrations[index]);
                    this.db.exec(`PRAGMA user_version=${index + 1}`);
                });
            }
            if (migrationSQL === undefined) {
                const required: Record<string, string> = {
                    accounts: 'id,display_name,role,person_ids,permission_version,active,webauthn_user_id',
                    credentials: 'id,account_id,public_key,counter,transports',
                    bootstrap_tokens: 'hash,account_id,expires_at,consumed',
                    auth_contexts: 'browser_hash,epoch,generation',
                    challenges: 'id,challenge,kind,account_id,account_version,bootstrap_hash,credential_ids,browser_hash,browser_epoch,browser_generation,expires_at,consumed',
                    sessions: 'hash,account_id,csrf,permission_version,expires_at,revoked,browser_hash,browser_epoch',
                    service_state: 'singleton,desired_json,highwater,observation_json,observed_at,last_confirmation_at',
                    operations: 'id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error,confirmed_at',
                    audit: 'id,actor_id,operation_id,action,revision,timestamp,outcome',
                };
                if (internalMode !== 'integration') required.parent_alerts = 'id,person_id,kind,severity,created_at,first_seen,last_seen,count,state,acknowledged_at,acknowledged_by,resolved_at,details'; // demo-only table; integration migrations stop at 002
                try {
                    for (const [table, columns] of Object.entries(required)) this.db.prepare(`SELECT ${columns} FROM ${table} LIMIT 0`).all();
                } catch { throw new Error('unsupported_database_schema'); }
            }
        }
        catch (error) {
            this.db.close();
            throw error;
        }
    }
    transaction<T>(work: () => T): T {
        this.db.exec('BEGIN IMMEDIATE');
        try {
            const result = work();
            this.db.exec('COMMIT');
            return result;
        }
        catch (error) {
            this.db.exec('ROLLBACK');
            throw error;
        }
    }
    get<T>(sql: string, ...args: (string | number | null | Uint8Array)[]): T | undefined {
        return this.db.prepare(sql).get(...args) as T | undefined;
    }
    all<T>(sql: string, ...args: (string | number | null | Uint8Array)[]): T[] {
        return this.db.prepare(sql).all(...args) as T[];
    }
    run(sql: string, ...args: (string | number | null | Uint8Array)[]) {
        return this.db.prepare(sql).run(...args);
    }
    close() {
        this.db.close();
    }
}
