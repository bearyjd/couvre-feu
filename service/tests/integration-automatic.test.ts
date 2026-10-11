import test from 'node:test';
import assert from 'node:assert/strict';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { IntegrationWorker } from '../src/integration-worker.ts';
import { actor, integrationFixture } from './fixtures/integration.ts';
import { RouterTransportError } from '../src/router-transport.ts';

function enabled() {
    const f = integrationFixture();
    f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
    return {...f, automatic: new AutomaticDispatch(f.worker)};
}
test('automatic dispatch is denied by default, and enabled queued pause/resume confirm without an operator permit', async () => {
    const disabled = integrationFixture();
    try { assert.throws(() => new AutomaticDispatch(disabled.worker), /automatic_dispatch_disabled/); assert.equal(disabled.router.calls.length, 0); }
    finally { disabled.cleanup(); }
    const f = enabled();
    try {
        await f.automatic.tick();
        const until = f.now() + 60, queued = f.pause(until).result.operation;
        assert.equal(queued.dispatch, 'awaiting_automatic_dispatch');
        await f.automatic.tick();
        assert.equal(f.policy.operation(actor, queued.id).state, 'confirmed');
        assert.equal(f.router.policy.pauses[0].until, until);
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
        const resumed = f.policy.mutate(actor, 'pilot', 'resume', {}, f.policy.people(actor).revisionToken!, 'auto_resume_1234567');
        await f.automatic.tick(); assert.equal(f.policy.operation(actor, resumed.result.operation.id).state, 'confirmed');
        assert.deepEqual(f.router.policy.pauses, []);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM audit WHERE action='automatic_apply' AND outcome='claimed_once'")!.n, 2);
        const maintenance = f.worker.prepare('observe');
        await assert.rejects(f.worker.execute(maintenance, maintenance.scriptSha256), /automatic_dispatch_authority_required/);
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('concurrent ticks serialize and another owner fences late callbacks without repeating an apply', async () => {
    const f = enabled(); let release!: () => void;
    const otherStore = new IntegrationStore(f.config);
    let other: AutomaticDispatch | null = null;
    try {
        await f.automatic.tick(); const queued = f.pause().result.operation;
        // Delay the apply after its observation and durable claim.
        const original = f.router.invoke.bind(f.router);
        f.router.invoke = async i => { if (i.kind === 'apply') await new Promise<void>(r => {release = r;}); return original(i); };
        const flight = f.automatic.tick(); assert.equal(f.automatic.tick(), flight);
        await new Promise(resolve => setImmediate(resolve));
        other = new AutomaticDispatch(new IntegrationWorker(otherStore, f.router, f.now));
        release(); await flight;
        assert.equal(f.policy.operation(actor, queued.id).state, 'unknown');
        await other.tick();
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
        assert.equal(f.policy.operation(actor, queued.id).state, 'confirmed');
        await f.automatic.tick(); assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
    } finally { await other?.stop(); await f.automatic.stop(); otherStore.close(); f.cleanup(); }
});
test('possible delivery and missing receipt remain unknown across restart and lease expiry with no blind apply retry', async () => {
    const f = enabled(); let restarted: AutomaticDispatch | null = null;
    try {
        await f.automatic.tick(); const queued = f.pause().result.operation;
        f.router.failure = new RouterTransportError('ssh_timeout');
        await f.automatic.tick();
        // The preceding observation failed, so the intent has not yet dispatched.
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 0);
        f.router.failure = null;
        const original = f.router.invoke.bind(f.router);
        f.router.invoke = async i => { if (i.kind === 'apply') { f.router.calls.push(i); throw new RouterTransportError('ssh_timeout'); } return original(i); };
        await f.automatic.tick(); assert.equal(f.policy.operation(actor, queued.id).state, 'unknown');
        f.advance(900);
        restarted = new AutomaticDispatch(f.worker);
        await restarted.tick(); await restarted.tick();
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
        assert.equal(f.policy.operation(actor, queued.id).state, 'unknown');
        assert.equal(f.policy.people(actor).revisionToken, null);
    } finally { await restarted?.stop(); await f.automatic.stop(); f.cleanup(); }
});
test('lost accepted response reconciles receipt without extending a timed pause', async () => {
    const f = enabled();
    try {
        await f.automatic.tick(); const until = f.now() + 10, queued = f.pause(until).result.operation;
        f.router.afterApplyFailure = new RouterTransportError('ssh_timeout');
        await f.automatic.tick(); assert.equal(f.policy.operation(actor, queued.id).state, 'unknown');
        f.advance(20); await f.automatic.tick();
        assert.equal(f.policy.operation(actor, queued.id).state, 'confirmed');
        assert.equal(f.router.policy.pauses[0].until, until);
        assert.equal(f.policy.people(actor).people[0].effectiveManualPause, null);
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 1);
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('revocation fences further reads and writes; actor permission revocation fails a queued intent before SSH apply', async () => {
    const f = enabled();
    try {
        await f.automatic.tick(); const queued = f.pause().result.operation;
        f.store.run("UPDATE accounts SET permission_version=permission_version+1 WHERE id='operator'");
        await f.automatic.tick(); assert.equal(f.policy.operation(actor, queued.id).state, 'failed');
        assert.equal(f.router.calls.filter(c => c.kind === 'apply').length, 0);
        f.store.stopDispatch(f.now()); const calls = f.router.calls.length;
        await f.automatic.tick(); assert.equal(f.router.calls.length, calls);
        await assert.rejects(f.worker.executeAutomatic('observe', f.automatic.owner), /automatic_dispatch_authority_required/);
    } finally { await f.automatic.stop(); f.cleanup(); }
});
