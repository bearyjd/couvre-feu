import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { IntegrationPolicy } from '../src/integration-policy.ts';
import { rebindIntegration } from '../src/integration-rebind.ts';
import type { IntegrationConfig } from '../src/integration-config.ts';
import { policyJSON } from '../../shared/src/router-schema.ts';
import { rmSync } from 'node:fs';

/** A later manifest for the same installation: new router generation, so new digests. */
function next(config: IntegrationConfig, change: Partial<IntegrationConfig> = {}): IntegrationConfig {
    return {...config, router: {...config.router, generation: 'e'.repeat(64)}, manifestDigest: 'f'.repeat(64), targetDigest: '9'.repeat(64), ...change};
}
function seedPasskey(store: IntegrationStore) {
    store.run("INSERT INTO credentials(id,account_id,public_key,counter,transports) VALUES('cred_operator','operator',x'01',3,'[]')");
    store.run("INSERT INTO request_links(id,person_id,token_hash,created_by,created_at) VALUES('link1','pilot','h','operator',1)");
}

test('rebind refuses while any dispatch, operation, claim or time-request obligation is live, or when identity inputs change', async () => {
    const f = integrationFixture();
    try {
        seedPasskey(f.store);
        const target = next(f.config), run = (config = target, oldDigest = f.config.manifestDigest, newDigest = config.manifestDigest) => rebindIntegration(f.store, config, oldDigest, newDigest, f.now());
        assert.throws(() => run(target, 'a'.repeat(64)), /rebind_digest_mismatch/);
        assert.throws(() => run(target, f.config.manifestDigest, 'a'.repeat(64)), /rebind_digest_mismatch/);
        assert.throws(() => run(next(f.config, {manifestDigest: f.config.manifestDigest})), /rebind_unchanged/);
        assert.throws(() => run(next(f.config, {origin: 'https://other.example.test', host: 'other.example.test'})), /rebind_origin_changed/);
        assert.throws(() => run(next(f.config, {person: {...f.config.person, id: 'someone'}})), /rebind_person_changed/);
        assert.throws(() => run(next(f.config, {dataDir: '/elsewhere'})), /rebind_data_dir_changed/);
        await f.observe();
        // A live automatic-dispatch owner, or a dispatch whose step is still in flight, both refuse.
        f.store.run("INSERT INTO automatic_dispatch(singleton,epoch,owner_token,enabled) VALUES(1,0,'owner',1)");
        assert.throws(() => run(), /rebind_requires_dispatch_stopped/);
        f.store.run('UPDATE automatic_dispatch SET enabled=0'); f.store.run('UPDATE integration_state SET dispatch_stopped=0');
        assert.throws(() => run(), /rebind_requires_dispatch_stopped/);
        f.store.stopDispatch(f.now());
        f.pause();
        assert.throws(() => run(), /rebind_operation_in_progress/);
        f.store.run("UPDATE operations SET state='failed'"); f.store.run('UPDATE integration_state SET active_operation_id=NULL');
        f.store.run("UPDATE operation_rpc SET phase='uncertain'");
        assert.throws(() => run(), /rebind_uncertain_claim/);
        f.store.run("UPDATE operation_rpc SET phase='resolved'");
        f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at,repause_state) VALUES('r1','link1','pilot',15,'','approved',1,2,'waiting')");
        assert.throws(() => run(), /rebind_time_request_obligation/);
        f.store.run("UPDATE time_requests SET repause_state='done'");
        // The marker is untouched by every refusal.
        assert.equal(f.store.get<{manifest_digest: string}>('SELECT manifest_digest FROM integration_state')!.manifest_digest, f.config.manifestDigest);
        run();
    } finally { f.cleanup(); }
});

test('rebind keeps accounts, passkeys and links, resets router observation, fences dispatch, and stale processes fail closed', async () => {
    const f = integrationFixture();
    let closed = false;
    try {
        seedPasskey(f.store);
        await f.observe();
        f.store.stopDispatch(f.now());
        const epoch = f.store.integrationState().dispatch_epoch, highwater = f.store.get<{highwater: number}>('SELECT highwater FROM service_state')!.highwater;
        const target = next(f.config);
        rebindIntegration(f.store, target, f.config.manifestDigest, target.manifestDigest, f.now());
        assert.deepEqual({...f.store.get('SELECT target_digest,manifest_digest,generation,dispatch_stopped,active_operation_id FROM integration_state')!},
            {target_digest: target.targetDigest, manifest_digest: target.manifestDigest, generation: target.router.generation, dispatch_stopped: 1, active_operation_id: null});
        assert.equal(f.store.integrationState().dispatch_epoch, epoch + 1);
        const state = f.store.get<{desired_json: string; highwater: number; observation_json: string | null; observed_at: number | null}>('SELECT * FROM service_state')!;
        assert.equal(state.observation_json, null); assert.equal(state.observed_at, null);
        assert.equal(state.desired_json, policyJSON(target.enrollment));
        assert.ok(state.highwater > highwater);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM credentials WHERE id='cred_operator'")!.n, 1);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM request_links")!.n, 1);
        const audit = f.store.get<{outcome: string}>("SELECT outcome FROM audit WHERE action='integration_rebind'")!;
        assert.equal(audit.outcome, `${f.config.manifestDigest}->${target.manifestDigest}`);
        // The running process still holds the old manifest: every mutate and dispatch transaction re-reads the marker.
        f.store.run('UPDATE service_state SET observation_json=NULL');
        assert.throws(() => new IntegrationPolicy(f.store, f.now).mutate(actor, 'pilot', 'pause', {until: 0}, '"s0-r0-' + 'a'.repeat(64) + '"', 'stale_process_1234567'), /integration_database_identity_mismatch/);
        await assert.rejects(f.observe(), /integration_database_identity_mismatch/);
        await assert.rejects(f.worker.executeAutomatic('observe', {token: 'x', epoch: 0}), /integration_database_identity_mismatch/);
        assert.equal(f.router.calls.length, 1);
        // The old manifest can no longer open the database; the new one can.
        f.store.close(); closed = true;
        assert.throws(() => new IntegrationStore(f.config), /integration_database_identity_mismatch/);
        const reopened = new IntegrationStore(target);
        try { assert.equal(reopened.get<{n: number}>("SELECT count(*) n FROM accounts")!.n, 2); } finally { reopened.close(); }
    } finally { if (closed) rmSync(f.dir, {recursive: true, force: true}); else f.cleanup(); }
});
