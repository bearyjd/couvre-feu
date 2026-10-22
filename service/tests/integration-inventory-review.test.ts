import test from 'node:test';
import assert from 'node:assert/strict';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { actor, integrationFixture } from './fixtures/integration.ts';

const m = (n: number) => `00:00:5e:00:00:${n.toString(16).padStart(2, '0')}`;
function enabled(pollSeconds = 2) {
    const f = integrationFixture();
    f.config.dispatch = {enabled: true, pollSeconds, maxBackoffSeconds: 8};
    const automatic = new AutomaticDispatch(f.worker);
    const reply = (ns: number[]) => JSON.stringify({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(),
        devices: ns.map(n => ({mac: m(n), ipv4: [`192.0.2.${n}`], hostname: `host-${n}`, source: 'both'})), truncated: false, errors: []});
    const steps = () => f.store.all<{state: string}>('SELECT state FROM dispatch_steps').map(r => r.state);
    const state = () => f.store.get<{last_error: string | null; last_ok_at: number | null}>('SELECT last_error,last_ok_at FROM inventory_state')!;
    const clean = () => {
        assert.deepEqual(steps().filter(s => s === 'consumed' || s === 'uncertain'), [], 'no step is left to block a rebind or the next claim');
        assert.equal(f.store.integrationState().observation_error, null);
    };
    return {...f, automatic, reply, steps, state, clean};
}

test('CM-1: a reply later than the lease settles the step resolved, ingests nothing and records lease_expired', async () => {
    const f = enabled();
    try {
        f.router.inventoryText = f.reply([1]); f.router.spend = {inventory: 11};
        await f.automatic.worker.executeAutomatic('observe', f.automatic.owner);
        await f.worker.pollInventory(f.automatic.owner);
        assert.equal(f.state().last_error, 'inventory_unavailable:lease_expired');
        assert.equal(f.worker.inventory.list(actor).devices.length, 0, 'a late reply is not applied');
        f.clean();
        assert.deepEqual(f.steps().filter(s => s !== 'resolved'), []);
        f.router.spend = {}; f.router.calls.length = 0;
        await f.automatic.worker.executeAutomatic('observe', f.automatic.owner);
        f.clean();
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('CM-1/SL-3: bookkeeping that throws still settles the step; observation_error stays NULL and the next observe is not blocked', async () => {
    const cases: [string, (f: ReturnType<typeof enabled>) => () => void][] = [
        ['pruneAutomaticReads throws', f => { const keep = f.store.pruneAutomaticReads; f.store.pruneAutomaticReads = () => { throw new Error('boom'); }; return () => { f.store.pruneAutomaticReads = keep; }; }],
        ['ingest and recordFailure throw', f => { const a = f.worker.inventory.ingest, b = f.worker.inventory.recordFailure; f.worker.inventory.ingest = () => { throw new Error('boom'); }; f.worker.inventory.recordFailure = () => { throw new Error('boom'); };
            return () => { f.worker.inventory.ingest = a; f.worker.inventory.recordFailure = b; }; }],
    ];
    for (const [name, arrange] of cases) {
        const f = enabled();
        try {
            f.router.inventoryText = f.reply([1]);
            await f.automatic.worker.executeAutomatic('observe', f.automatic.owner);
            const restore = arrange(f);
            await assert.doesNotReject(f.worker.pollInventory(f.automatic.owner), name);
            restore();
            assert.deepEqual(f.steps().filter(s => s !== 'resolved' && s !== 'spent'), [], name);
            f.clean();
            await assert.doesNotReject(f.automatic.worker.executeAutomatic('observe', f.automatic.owner), name);
            f.clean();
        } finally { await f.automatic.stop(); f.cleanup(); }
    }
});
test('CM-1: a step another claim already marked uncertain (expired lease) is still settled resolved by its own token', async () => {
    const f = enabled();
    try {
        f.router.inventoryText = f.reply([1]);
        f.router.onReturn = kind => { if (kind === 'inventory') f.store.run("UPDATE dispatch_steps SET state='uncertain' WHERE state='consumed'"); };
        await f.worker.pollInventory(f.automatic.owner);
        f.clean();
        assert.deepEqual(f.steps(), ['resolved']);
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('M14: a reply inside the lease IS applied, one past it is not (the lease decides, not the clock at claim)', async () => {
    const f = enabled();
    try {
        f.router.inventoryText = f.reply([1, 2]); f.router.spend = {inventory: 9};
        await f.worker.pollInventory(f.automatic.owner);
        assert.equal(f.worker.inventory.list(actor).devices.length, 2); assert.equal(f.state().last_error, null);
        f.advance(61); f.router.spend = {inventory: 11}; f.router.inventoryText = f.reply([1, 2, 3]);
        await f.worker.pollInventory(f.automatic.owner);
        assert.equal(f.worker.inventory.list(actor).devices.length, 2);
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('SM-2: a slow inventory poll cannot stretch the gap between observations past the freshness window', async () => {
    const f = enabled(15);
    try {
        f.router.inventoryText = f.reply([1]); f.router.spend = {inventory: 8, observe: 7};
        await f.automatic.tick();
        assert.equal(f.policy.fresh(), true);
        f.worker.inventory.requestRefresh(actor, f.now());
        const next = (f.automatic as unknown as {nextDelaySeconds?: () => number}).nextDelaySeconds?.() ?? 15;
        f.advance(next);
        let outcome = 'not_attempted';
        f.router.onReturn = kind => {
            if (kind !== 'observe') return;
            f.router.onReturn = null;
            try { f.pause(); outcome = 'queued'; } catch (error) { outcome = (error as {code?: string}).code ?? String(error); }
        };
        await f.automatic.tick();
        assert.equal(outcome, 'queued', 'the previous observation was still fresh when the pause was asked for');
    } finally { await f.automatic.stop(); f.cleanup(); }
});
