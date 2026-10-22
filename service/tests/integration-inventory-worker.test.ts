import test from 'node:test';
import assert from 'node:assert/strict';
import { AutomaticDispatch } from '../src/integration-automatic.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { AppError } from '../../shared/src/errors.ts';
import { actor, integrationFixture } from './fixtures/integration.ts';

const m = (n: number) => `00:00:5e:00:00:${n.toString(16).padStart(2, '0')}`;
function enabled() {
    const f = integrationFixture();
    f.config.dispatch = {enabled: true, pollSeconds: 2, maxBackoffSeconds: 8};
    const automatic = new AutomaticDispatch(f.worker);
    const reply = (ns: number[], over: Record<string, unknown> = {}) => JSON.stringify({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(),
        devices: ns.map(n => ({mac: m(n), ipv4: [`192.0.2.${n}`], hostname: `host-${n}`, source: 'both'})), truncated: false, errors: [], ...over});
    const kinds = () => f.router.calls.map(c => c.kind);
    const state = () => f.store.get<{last_error: string | null; last_ok_at: number | null; baseline_at: number | null}>('SELECT last_error,last_ok_at,baseline_at FROM inventory_state')!;
    const alerts = () => f.store.get<{n: number}>("SELECT count(*) n FROM parent_alerts WHERE kind='new_device'")!.n;
    return {...f, automatic, reply, kinds, state, alerts};
}
const isolated = (f: ReturnType<typeof enabled>) => {
    assert.equal(f.store.integrationState().observation_error, null, 'inventory never writes observation_error');
    assert.equal(f.policy.fresh(), true, 'the policy observation is fresh');
    assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM dispatch_steps WHERE state='consumed'")!.n, 0, 'every step is settled');
};

test('a cycle polls inventory FIRST when no operation is active, then observes; the baseline is silent', async () => {
    const f = enabled();
    try {
        f.router.inventoryText = f.reply([1, 2]);
        await f.automatic.tick();
        assert.deepEqual(f.kinds(), ['inventory', 'observe']);
        assert.equal(f.worker.inventory.list(actor).devices.length, 2); assert.equal(f.alerts(), 0); isolated(f);
        assert.equal(f.router.calls[0].argv.at(-1), 'cfctl rpc-inventory --json');
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('cadence: not again within 60 s, again after; a new MAC after the baseline raises one alert', async () => {
    const f = enabled();
    try {
        f.router.inventoryText = f.reply([1]);
        await f.automatic.tick(); f.advance(2); await f.automatic.tick(); f.advance(30); await f.automatic.tick();
        assert.equal(f.kinds().filter(k => k === 'inventory').length, 1);
        f.advance(40); f.router.inventoryText = f.reply([1, 2]); await f.automatic.tick();
        assert.equal(f.kinds().filter(k => k === 'inventory').length, 2); assert.equal(f.alerts(), 1); isolated(f);
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('an active operation suppresses the inventory poll', async () => {
    const f = enabled();
    try {
        f.router.inventoryText = f.reply([1]);
        await f.automatic.tick();
        const queued = f.pause().result.operation; f.advance(61); f.router.calls.length = 0;
        await f.automatic.tick();
        assert.ok(!f.kinds().includes('inventory'));
        assert.equal(f.policy.operation(actor, queued.id).state, 'confirmed');
        f.advance(1); await f.automatic.tick(); assert.ok(f.kinds().includes('inventory'), 'due again once nothing is active');
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('ISOLATION: every inventory failure leaves observation_error NULL, the observation fresh, and the tick succeeding', async () => {
    const cases: [string, (f: ReturnType<typeof enabled>) => void, string][] = [
        ['old router, empty exit 2', f => { f.router.inventoryText = null; }, 'inventory_unavailable:old_router'],
        ['old router, invalid_command body', f => { f.router.inventoryText = '{"ok":false,"errors":["invalid_command"]}'; }, 'inventory_unavailable:invalid_command'],
        ['unknown version', f => { f.router.inventoryText = f.reply([1], {inventory_version: 2}); }, 'inventory_unavailable:unknown_inventory_version'],
        ['garbage', f => { f.router.inventoryText = 'not json'; }, 'inventory_unavailable:invalid_router_inventory'],
        ['unknown field', f => { f.router.inventoryText = f.reply([1], {extra: 1}); }, 'inventory_unavailable:invalid_router_inventory'],
        ['protected MAC listed', f => { f.router.inventoryText = f.reply([1]).replace(m(1), f.config.protectedMacs[0]); }, 'inventory_unavailable:protected_mac_listed'],
        ['timeout', f => { f.router.inventoryFailure = new RouterTransportError('ssh_timeout'); }, 'inventory_unavailable:ssh_timeout'],
        ['ssh 255 stays distinct', f => { f.router.inventoryFailure = new RouterTransportError('ssh_exit_255', 'possible', 255); }, 'inventory_transport_error:ssh_exit_255'],
        ['non-transport throw', f => { f.router.invokeInventory = async () => { throw new Error('boom'); }; }, 'inventory_unavailable:invalid_router_inventory'],
        ['claim refused (409)', f => { const run = f.worker.executeAutomatic.bind(f.worker); f.worker.executeAutomatic = async (kind, owner, op) => { if (kind === 'inventory') throw new AppError(409, 'dispatch_in_progress'); return run(kind, owner, op); }; }, 'inventory_not_run:dispatch_in_progress'],
    ];
    for (const [name, arrange, label] of cases) {
        const f = enabled();
        try {
            arrange(f);
            // The poll alone, after a fresh observation: a later successful observe would otherwise overwrite a leaked observation_error.
            const {worker, owner} = f.automatic;
            await worker.executeAutomatic('observe', owner);
            await assert.doesNotReject(worker.pollInventory(owner), name);
            assert.equal(f.state().last_error, label, name); isolated(f);
            f.advance(61); f.router.calls.length = 0;
            await assert.doesNotReject(f.automatic.tick(), name);
            assert.equal(f.state().last_error, label, name); isolated(f);
            assert.ok(f.kinds().includes('observe'), `${name}: observe still ran`);
            assert.equal(f.state().baseline_at, null);
        } finally { await f.automatic.stop(); f.cleanup(); }
    }
});
test('a failing router is re-polled on the 60 s cadence, not every cycle, and a later good reply clears the error', async () => {
    const f = enabled();
    try {
        await f.automatic.tick(); f.advance(2); await f.automatic.tick(); f.advance(2); await f.automatic.tick();
        assert.equal(f.kinds().filter(k => k === 'inventory').length, 1);
        f.advance(60); f.router.inventoryText = f.reply([1]); await f.automatic.tick();
        assert.equal(f.state().last_error, null); assert.ok(f.state().last_ok_at !== null);
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('inventory never sets or depends on dispatch_stopped, and ignores a stale value', async () => {
    const f = enabled();
    try {
        f.router.inventoryText = f.reply([1]);
        for (const value of [0, 1]) {
            f.store.run('UPDATE integration_state SET dispatch_stopped=?', value); f.store.run('DELETE FROM inventory_devices');
            await f.automatic.worker.pollInventory(f.automatic.owner);
            assert.equal(f.store.integrationState().dispatch_stopped, value, 'unchanged');
            assert.equal(f.worker.inventory.list(actor).devices.length, 1, `ingested with dispatch_stopped=${value}`);
            f.advance(61);
        }
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('a restart/fence during the flight discards the late reply and the tick ends cleanly', async () => {
    const f = enabled(); let release!: () => void;
    try {
        f.router.inventoryText = f.reply([1]); f.router.inventoryDefer = new Promise<void>(r => { release = r; });
        const flight = f.automatic.tick();
        await new Promise(resolve => setImmediate(resolve));
        f.store.stopDispatch(f.now()); release();
        await assert.doesNotReject(flight);
        assert.equal(f.worker.inventory.list(actor).devices.length, 0); assert.deepEqual(f.kinds(), ['inventory']);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM dispatch_steps WHERE state='consumed'")!.n, 0);
    } finally { await f.automatic.stop(); f.cleanup(); }
});
test('inventory permits exist only for the automatic owner; activity stays operator-only', async () => {
    const f = enabled();
    try {
        await assert.rejects(f.automatic.worker.executeAutomatic('activity', f.automatic.owner), /activity_requires_operator_permit/);
        await f.automatic.stop();
        const plan = f.worker.prepare('inventory');
        await assert.rejects(f.worker.execute(plan, plan.scriptSha256), /inventory_requires_automatic_permit/);
        assert.equal(f.router.calls.length, 0);
        assert.match(plan.script, /cfctl rpc-inventory --json/);
    } finally { f.cleanup(); }
});
test('inventory steps are pruned like other automatic reads', async () => {
    const f = enabled();
    try {
        f.router.inventoryText = f.reply([1]);
        for (let i = 0; i < 80; i++) { await f.automatic.tick(); f.advance(61); }
        const n = f.store.get<{n: number}>("SELECT count(*) n FROM dispatch_steps WHERE kind='inventory'")!.n;
        assert.ok(n > 0 && n <= 64, String(n));
    } finally { await f.automatic.stop(); f.cleanup(); }
});
