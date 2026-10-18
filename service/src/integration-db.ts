import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Store } from './db.ts';
import { requirePrivatePath } from './integration-config.ts';
import type { IntegrationConfig } from './integration-config.ts';
import { policyJSON } from '../../shared/src/router-schema.ts';
import { AppError } from '../../shared/src/errors.ts';
import type { RPCObservation } from '../../shared/src/router-rpc.ts';
import { seedChildren } from './integration-children.ts';

export interface IntegrationState {
    generation: string; dispatch_epoch: number; dispatch_stopped: number; active_operation_id: string | null;
    observation_sequence: number; observation_error: string | null;
}
export const AUTOMATIC_READ_RETENTION = 64;
export class IntegrationStore extends Store {
    readonly config: IntegrationConfig;
    constructor(config: IntegrationConfig) {
        requirePrivatePath(config.dataDir, 'directory');
        const path = join(config.dataDir, 'integration.sqlite');
        for (const name of [path, path + '-wal', path + '-shm', path + '-journal']) {
            try { lstatSync(name); }
            catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
            // lstat sees dangling links as existing. Never let SQLite follow one into another directory.
            requirePrivatePath(name, 'file');
        }
        super(path, undefined, 'integration');
        this.config = config;
        try {
            this.transaction(() => {
                const marker = this.get<{target_digest: string; manifest_digest: string; generation: string; schema_version: number; mode: string}>("SELECT * FROM integration_state WHERE singleton=1");
                if (marker) {
                    if (marker.target_digest !== config.targetDigest || marker.manifest_digest !== config.manifestDigest || marker.generation !== config.router.generation || marker.schema_version !== 1 || marker.mode !== 'integration') throw new Error('integration_database_identity_mismatch');
                    return;
                }
                throw new Error('integration_database_uninitialized');
            });
        } catch (error) {
            // A new DB has no marker table. Initialize only that exact fresh schema, never a foreign/demo DB.
            if (!(error instanceof Error) || !/no such table: integration_state/.test(error.message)) { this.close(); throw error; }
            try {
                this.transaction(() => {
                    this.db.exec(readFileSync(new URL('../migrations/integration-001.sql', import.meta.url), 'utf8'));
                    this.run("INSERT INTO integration_state(singleton,mode,schema_version,target_digest,manifest_digest,generation) VALUES(1,'integration',1,?,?,?)", config.targetDigest, config.manifestDigest, config.router.generation);
                    this.run('INSERT INTO service_state(singleton,desired_json,highwater) VALUES(1,?,?)', policyJSON(config.enrollment), config.enrollment.revision);
                    for (const a of config.accounts) this.run('INSERT INTO accounts(id,display_name,role,person_ids,webauthn_user_id) VALUES(?,?,?,?,?)', a.id, a.displayName, a.role, JSON.stringify(a.personIds), randomBytes(32).toString('base64url'));
                });
            } catch (initializationError) { this.close(); throw initializationError; }
        }
        // integration-002 admits the read-only `activity` step kind. Fresh and existing databases both pass through it exactly once.
        if (!this.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE type='table' AND name='dispatch_steps'")!.sql.includes("'activity'")) {
            this.transaction(() => this.db.exec(readFileSync(new URL('../migrations/integration-002.sql', import.meta.url), 'utf8')));
        }
        // integration-003 widens operations.action for device enrollment. operations is a parent table, so the rebuild runs with
        // foreign keys off (a no-op inside a transaction) and must leave no dangling reference behind before it commits.
        if (!this.get<{sql: string}>("SELECT sql FROM sqlite_master WHERE type='table' AND name='operations'")!.sql.includes("'enroll'")) {
            this.db.exec('PRAGMA foreign_keys=OFF');
            try {
                this.transaction(() => {
                    this.db.exec(readFileSync(new URL('../migrations/integration-003.sql', import.meta.url), 'utf8'));
                    if (this.all('PRAGMA foreign_key_check').length) throw new Error('integration_migration_foreign_key_violation');
                });
            } catch (error) { this.close(); throw error; }
            finally { if (this.db.isOpen) this.db.exec('PRAGMA foreign_keys=ON'); }
        }
        // Migration 008 data: the manifest's single child and device seed the database exactly once. Time 0 keeps the seed
        // deterministic and ordered before anything an admin adds later.
        this.transaction(() => seedChildren(this, config, 0));
        // Separate additive state keeps existing manifest-bound databases readable.
        this.db.exec(`CREATE TABLE IF NOT EXISTS automatic_dispatch (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL,
            owner_token TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
        ) STRICT`);
        this.db.exec(`CREATE TABLE IF NOT EXISTS automatic_read_polls (
            sequence INTEGER PRIMARY KEY, batch_id TEXT NOT NULL UNIQUE REFERENCES dispatch_batches(id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS automatic_read_summary (
            kind TEXT PRIMARY KEY CHECK(kind IN ('observe','receipt')), dispatch_count INTEGER NOT NULL,
            dispatched_at INTEGER NOT NULL, completed_at INTEGER, outcome TEXT NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS dispatch_live_claims ON dispatch_steps(state,lease_until)`);
        // Startup never releases an uncertain claim or starts dispatch.
    }
    /** A rebind can rewrite the marker under a running process. Mutate and dispatch transactions re-check it and fail closed. */
    assertIdentity(): void {
        const m = this.get<{target_digest: string; manifest_digest: string; generation: string}>('SELECT target_digest,manifest_digest,generation FROM integration_state WHERE singleton=1');
        if (!m || m.target_digest !== this.config.targetDigest || m.manifest_digest !== this.config.manifestDigest || m.generation !== this.config.router.generation) throw new AppError(503, 'integration_database_identity_mismatch');
    }
    integrationState(): IntegrationState { return this.get<IntegrationState>('SELECT * FROM integration_state WHERE singleton=1')!; }
    observation(): {value: RPCObservation | null; observedAt: number | null} {
        const s = this.get<{observation_json: string | null; observed_at: number | null}>('SELECT observation_json,observed_at FROM service_state WHERE singleton=1')!;
        return {value: s.observation_json ? JSON.parse(s.observation_json) as RPCObservation : null, observedAt: s.observed_at};
    }
    /** Local fence only. It revokes future invocations; it cannot prove remote drain. */
    stopDispatch(now = Math.floor(Date.now() / 1000)): void {
        this.transaction(() => {
            this.run('UPDATE integration_state SET dispatch_stopped=1,dispatch_epoch=dispatch_epoch+1 WHERE singleton=1');
            this.run('UPDATE automatic_dispatch SET enabled=0 WHERE singleton=1');
            this.run("INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES('operator','dispatch_revoked',?,'local_fence_only')", now);
            this.run("UPDATE dispatch_batches SET state='revoked' WHERE state='running'");
            this.run("UPDATE dispatch_steps SET state='uncertain' WHERE state='consumed'");
            this.run("UPDATE operations SET state='unknown',error='dispatch_stopped_remote_outcome_unknown',updated_at=? WHERE id=(SELECT active_operation_id FROM integration_state WHERE singleton=1) AND state IN ('pending','unknown') AND id IN (SELECT operation_id FROM operation_rpc WHERE attempt_count>0)", now);
            this.run("UPDATE operation_rpc SET phase='uncertain' WHERE phase='claimed'");
            this.pruneAutomaticReads();
        });
    }
    /** Only marked automatic reads can be compacted; maintenance and every write remain. */
    pruneAutomaticReads(): void {
        if (!this.db.isTransaction) throw new Error('read_retention_requires_transaction');
        const old = this.all<{batch_id: string}>(`SELECT p.batch_id FROM automatic_read_polls p
            JOIN dispatch_steps s ON s.batch_id=p.batch_id AND s.ordinal=1
            WHERE s.kind IN ('observe','receipt') AND s.state<>'consumed'
            ORDER BY p.sequence DESC LIMIT -1 OFFSET ?`, AUTOMATIC_READ_RETENTION);
        for (const row of old) {
            // No consumed callback survives this selection; do not remove its fence witness.
            this.run('DELETE FROM dispatch_steps WHERE batch_id=?', row.batch_id);
            this.run('DELETE FROM automatic_read_polls WHERE batch_id=?', row.batch_id);
            this.run('DELETE FROM dispatch_batches WHERE id=?', row.batch_id);
        }
    }
}
