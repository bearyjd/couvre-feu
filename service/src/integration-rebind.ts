import { AppError } from '../../shared/src/errors.ts';
import { policyJSON } from '../../shared/src/router-schema.ts';
import type { IntegrationConfig } from './integration-config.ts';
import type { IntegrationStore } from './integration-db.ts';

const refuse = (code: string): never => { throw new AppError(409, code); };
/**
 * Moves a manifest-bound database to a later manifest of the same installation (new router generation, protected MAC
 * change, ...) while keeping accounts, passkeys and request links. Router-facing state is reset from the new enrollment
 * and dispatch stays fenced. `store` must be open with the old manifest, so its marker already matched that manifest.
 * The service cannot prove it is stopped; a still-running process fails closed on its next mutate/dispatch transaction.
 */
export function rebindIntegration(store: IntegrationStore, next: IntegrationConfig, oldDigest: string, newDigest: string, now: number): void {
    const old = store.config;
    if (oldDigest !== old.manifestDigest || newDigest !== next.manifestDigest) refuse('rebind_digest_mismatch');
    if (old.manifestDigest === next.manifestDigest) refuse('rebind_unchanged');
    // The origin fixes the WebAuthn RP ID: every passkey would stop working.
    if (old.origin !== next.origin) refuse('rebind_origin_changed');
    // Accounts are scoped to this person id; a different person would silently orphan every parent.
    if (old.person.id !== next.person.id) refuse('rebind_person_changed');
    if (old.dataDir !== next.dataDir) refuse('rebind_data_dir_changed');
    store.transaction(() => {
        store.assertIdentity();
        const state = store.integrationState();
        if (state.dispatch_stopped !== 1 || store.get("SELECT enabled FROM automatic_dispatch WHERE singleton=1 AND enabled=1")) refuse('rebind_requires_dispatch_stopped');
        if (state.active_operation_id !== null || store.get("SELECT id FROM operations WHERE state IN ('pending','unknown') LIMIT 1")) refuse('rebind_operation_in_progress');
        if (store.get("SELECT operation_id FROM operation_rpc WHERE phase IN ('queued','claimed','uncertain') LIMIT 1") || store.get("SELECT batch_id FROM dispatch_steps WHERE state IN ('consumed','uncertain') LIMIT 1")) refuse('rebind_uncertain_claim');
        if (store.get("SELECT id FROM time_requests WHERE state='approving' OR repause_state IN ('waiting','applying') LIMIT 1")) refuse('rebind_time_request_obligation');
        store.run('UPDATE integration_state SET target_digest=?,manifest_digest=?,generation=?,dispatch_stopped=1,dispatch_epoch=dispatch_epoch+1,observation_error=NULL WHERE singleton=1', next.targetDigest, next.manifestDigest, next.router.generation);
        store.run('UPDATE automatic_dispatch SET enabled=0 WHERE singleton=1');
        store.run("UPDATE dispatch_batches SET state='revoked' WHERE state='running'");
        // Revision tokens embed highwater, so it only ever moves forward.
        store.run('UPDATE service_state SET desired_json=?,highwater=max(highwater+1,?),observation_json=NULL,observed_at=NULL WHERE singleton=1', policyJSON(next.enrollment), next.enrollment.revision);
        store.run("INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES('operator','integration_rebind',?,?)", now, `${old.manifestDigest}->${next.manifestDigest}`);
    });
}
