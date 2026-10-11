import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Store } from './db.ts';
import { requirePrivatePath } from './integration-config.ts';
import type { IntegrationConfig } from './integration-config.ts';
import { policyJSON } from '../../shared/src/router-schema.ts';
import type { RPCObservation } from '../../shared/src/router-rpc.ts';

export interface IntegrationState {
    generation: string; dispatch_epoch: number; dispatch_stopped: number; active_operation_id: string | null;
    observation_sequence: number; observation_error: string | null;
}
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
        // Startup never releases an uncertain claim or starts dispatch.
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
            this.run("UPDATE dispatch_batches SET state='revoked' WHERE state='running'");
            this.run("UPDATE dispatch_steps SET state='uncertain' WHERE state='consumed'");
            this.run("UPDATE operations SET state='unknown',error='dispatch_stopped_remote_outcome_unknown',updated_at=? WHERE id=(SELECT active_operation_id FROM integration_state WHERE singleton=1) AND state IN ('pending','unknown') AND id IN (SELECT operation_id FROM operation_rpc WHERE attempt_count>0)", now);
            this.run("UPDATE operation_rpc SET phase='uncertain' WHERE phase='claimed'");
        });
    }
}
