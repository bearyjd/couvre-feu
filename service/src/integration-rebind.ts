import { AppError } from '../../shared/src/errors.ts';
import { normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import { routerScopeOf } from './integration-config.ts';
import type { IntegrationConfig } from './integration-config.ts';
import type { IntegrationStore } from './integration-db.ts';
import { canonicalSchedules, scheduleWindows, schedulesInDatabase, seedScheduleWindows } from './integration-schedule-store.ts';
import { hasObligation } from './time-request-obligations.ts';

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
        if (hasObligation(store)) refuse('rebind_time_request_obligation');
        // A stored device the new router installation protects or does not allow would invalidate every observation and
        // block every change, including its own removal. Remove the device first, or list it in the new routerScope.
        const macs = store.all<{identifier: string}>("SELECT identifier FROM devices WHERE identifier_kind='mac'").map(d => d.identifier), scope = routerScopeOf(next);
        if (macs.some(m => next.protectedMacs.includes(m))) refuse('rebind_device_protected');
        if (macs.some(m => !scope.includes(m))) refuse('rebind_device_outside_scope');
        // schedules.editable (unverified on this router); every flag flip changes the manifest digest, so it always passes through here.
        // off->off reads nothing. on->on: the committed rows stay the truth and must stay enforceable (without scheduleClock every router
        // policy holding them, even an exact match, would be refused). on->off: the manifest becomes the owner again, so it must own exactly
        // the committed rows. off->on: forget any earlier rows and the seed marker, so the next open seeds once from this manifest.
        // The rebind CLI opens without seeding. With the flag on and no seed yet (right after an off->on rebind), the rows the next open
        // would seed from the old manifest are seeded here: the guards judge them, and they commit only if this transaction does.
        seedScheduleWindows(store, old);
        const was = schedulesInDatabase(old), will = schedulesInDatabase(next);
        if (was && will && scheduleWindows(store).length > 0 && !next.scheduleClock) refuse('rebind_schedule_clock_required');
        if (was && !will && canonicalSchedules(scheduleWindows(store)) !== canonicalSchedules(normalizePolicy(next.enrollment).schedules)) refuse('rebind_schedules_diverge');
        if (!was && will) { store.run('DELETE FROM schedule_windows'); store.run('DELETE FROM schedule_seed'); }
        // Scope observed under the old generation says nothing about the new router: forget it, so the next observation re-baselines on the new floor.
        store.run('DELETE FROM router_scope_observed');
        // A request made against the old router can never be observed by the new one.
        store.run("UPDATE scope_requests SET state='cancelled',resolved_at=? WHERE state='pending'", now);
        store.run('UPDATE integration_state SET target_digest=?,manifest_digest=?,generation=?,dispatch_stopped=1,dispatch_epoch=dispatch_epoch+1,observation_error=NULL WHERE singleton=1', next.targetDigest, next.manifestDigest, next.router.generation);
        store.run('UPDATE automatic_dispatch SET enabled=0 WHERE singleton=1');
        store.run("UPDATE dispatch_batches SET state='revoked' WHERE state='running'");
        // Revision tokens embed highwater, so it only ever moves forward.
        store.run('UPDATE service_state SET desired_json=?,highwater=max(highwater+1,?),observation_json=NULL,observed_at=NULL WHERE singleton=1', policyJSON(next.enrollment), next.enrollment.revision);
        store.run("INSERT INTO audit(actor_id,action,timestamp,outcome) VALUES('operator','integration_rebind',?,?)", now, `${old.manifestDigest}->${next.manifestDigest}`);
    });
}
