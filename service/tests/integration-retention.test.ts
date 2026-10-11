import test from 'node:test';
import assert from 'node:assert/strict';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { AUTOMATIC_READ_RETENTION, IntegrationStore } from '../src/integration-db.ts';
import { IntegrationWorker } from '../src/integration-worker.ts';
import { IntegrationPolicy } from '../src/integration-policy.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { actor, integrationFixture } from './fixtures/integration.ts';

function count(store: IntegrationStore, table: string): number {
    return store.get<{n: number}>(`SELECT count(*) n FROM ${table}`)!.n;
}
test('thousands of automatic observations retain bounded history, indexed live claims and exact maintenance permits', async () => {
    const f = integrationFixture(); let automatic: AutomaticDispatch | null = null;
    try {
        const manual = f.worker.prepare('observe'); await f.worker.execute(manual, manual.scriptSha256);
        await assert.rejects(f.worker.execute(manual, manual.scriptSha256), /dispatch_permit_already_consumed/);
        f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
        automatic = new AutomaticDispatch(f.worker);
        const auditBefore = count(f.store, 'audit');
        for (let i = 0; i < 1000; i++) { f.advance(2); await automatic.tick(); }
        const pages = f.store.get<{page_count: number}>('PRAGMA page_count')!.page_count;
        for (let i = 0; i < 1000; i++) { f.advance(2); await automatic.tick(); }
        assert.equal(count(f.store, 'automatic_read_polls'), AUTOMATIC_READ_RETENTION);
        assert.equal(count(f.store, 'dispatch_batches'), AUTOMATIC_READ_RETENTION + 1);
        assert.equal(count(f.store, 'dispatch_steps'), AUTOMATIC_READ_RETENTION + 1);
        assert.equal(count(f.store, 'audit'), auditBefore);
        assert.equal(count(f.store, 'automatic_read_summary'), 1);
        assert.equal(f.store.get<{dispatch_count: number}>("SELECT dispatch_count FROM automatic_read_summary WHERE kind='observe'")!.dispatch_count, 2000);
        assert.ok(f.store.get('SELECT id FROM dispatch_batches WHERE script_sha256=?', manual.scriptSha256));
        assert.ok(f.store.get<{page_count: number}>('PRAGMA page_count')!.page_count <= pages + 4, 'SQLite allocation stays bounded after warmup');
        for (const sql of ["SELECT batch_id FROM dispatch_steps WHERE state='consumed' AND lease_until>0 LIMIT 1", "UPDATE dispatch_steps SET state='uncertain' WHERE state='consumed' AND lease_until<=0"]) {
            const plan = f.store.all<{detail: string}>('EXPLAIN QUERY PLAN ' + sql).map(row => row.detail).join(' ');
            assert.match(plan, /SEARCH dispatch_steps USING (?:COVERING )?INDEX dispatch_live_claims/);
            assert.doesNotMatch(plan, /SCAN dispatch_steps/);
        }
        assert.deepEqual(f.store.all('PRAGMA foreign_key_check'), []);
        assert.equal(f.policy.people(actor).observedAt, f.now());
    } finally { await automatic?.stop(); f.cleanup(); }
});
test('thousands of unknown receipt polls coalesce audit without deleting a write claim, envelope or expiry across restart', async () => {
    const f = integrationFixture(); let automatic: AutomaticDispatch | null = null, restarted: AutomaticDispatch | null = null;
    let second: IntegrationStore | null = null;
    try {
        f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
        automatic = new AutomaticDispatch(f.worker); await automatic.tick();
        const until = f.now() + 60, op = f.pause(until).result.operation;
        const original = f.router.invoke.bind(f.router);
        f.router.invoke = async invocation => {
            if (invocation.kind === 'apply') { f.router.calls.push(invocation); throw new RouterTransportError('ssh_timeout'); }
            return original(invocation);
        };
        await automatic.tick();
        const envelope = f.policy.envelope(op.id);
        const claim = f.store.get<{claim_token: string; claim_epoch: number}>('SELECT claim_token,claim_epoch FROM operation_rpc WHERE operation_id=?', op.id)!;
        f.advance(30); await automatic.tick();
        const auditBefore = count(f.store, 'audit');
        for (let i = 0; i < 1000; i++) { f.advance(2); await automatic.tick(); }
        assert.equal(count(f.store, 'audit'), auditBefore);
        assert.equal(count(f.store, 'dispatch_batches'), AUTOMATIC_READ_RETENTION + 1);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM dispatch_steps WHERE kind='apply' AND state='uncertain'")!.n, 1);
        const rpc = f.store.get<{attempt_count: number; claim_token: string; claim_epoch: number}>('SELECT * FROM operation_rpc WHERE operation_id=?', op.id)!;
        assert.equal(rpc.attempt_count, 1); assert.equal(rpc.claim_token, claim.claim_token); assert.equal(rpc.claim_epoch, claim.claim_epoch);
        assert.deepEqual(f.policy.envelope(op.id), envelope); assert.equal(envelope.policy.pauses[0].until, until);
        assert.equal(f.policy.operation(actor, op.id).state, 'unknown');
        assert.equal(f.policy.people(actor).observedAt, f.now());
        assert.equal(f.policy.people(actor).revisionToken, null);
        await automatic.stop();
        second = new IntegrationStore(f.config);
        restarted = new AutomaticDispatch(new IntegrationWorker(second, f.router, f.now));
        for (let i = 0; i < 1000; i++) { f.advance(2); await restarted.tick(); }
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
        assert.equal(count(second, 'dispatch_batches'), AUTOMATIC_READ_RETENTION + 1);
        assert.equal(new IntegrationPolicy(second, f.now).operation(actor, op.id).state, 'unknown');
        assert.equal(second.get<{attempt_count: number}>('SELECT attempt_count FROM operation_rpc WHERE operation_id=?', op.id)!.attempt_count, 1);
        assert.deepEqual(f.policy.envelope(op.id), envelope);
        assert.deepEqual(second.all('PRAGMA foreign_key_check'), []);
    } finally { await restarted?.stop(); await automatic?.stop(); second?.close(); f.cleanup(); }
});
test('retention preserves an active read callback and canonical accepted receipt evidence', async () => {
    const f = integrationFixture(); let automatic: AutomaticDispatch | null = null, release!: () => void;
    try {
        f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
        automatic = new AutomaticDispatch(f.worker); await automatic.tick();
        const op = f.pause(f.now() + 60).result.operation;
        f.router.afterApplyFailure = new RouterTransportError('ssh_timeout'); await automatic.tick();
        await automatic.tick(); assert.equal(f.policy.operation(actor, op.id).state, 'confirmed');
        const receipt = f.store.get<{receipt_json: string}>('SELECT receipt_json FROM operation_rpc WHERE operation_id=?', op.id)!.receipt_json;
        for (let i = 0; i < 1000; i++) { f.advance(2); await automatic.tick(); }
        assert.equal(f.store.get<{receipt_json: string}>('SELECT receipt_json FROM operation_rpc WHERE operation_id=?', op.id)!.receipt_json, receipt);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM dispatch_steps WHERE kind='apply'")!.n, 1);
        f.router.defer = new Promise<void>(resolve => {release = resolve;});
        const flight = automatic.tick();
        const active = f.store.get<{batch_id: string}>("SELECT batch_id FROM dispatch_steps WHERE state='consumed'")!;
        f.store.transaction(() => f.store.pruneAutomaticReads());
        assert.ok(f.store.get('SELECT batch_id FROM dispatch_steps WHERE batch_id=?', active.batch_id));
        release(); await flight;
        assert.equal(f.store.get<{state: string}>('SELECT state FROM dispatch_steps WHERE batch_id=?', active.batch_id)!.state, 'resolved');
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
    } finally { release?.(); await automatic?.stop(); f.cleanup(); }
});
