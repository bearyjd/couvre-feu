import test from 'node:test';
import assert from 'node:assert/strict';
import { boundedChild, inventoryFailure, inventoryFromReply, SSHRouter } from '../src/ssh-router.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { testConfig } from './fixtures/integration.ts';

const c = testConfig('/tmp/cf-m2c-no-agent');
const good = {inventory_version: 1, generation: c.router.generation, routerTime: 1791691200, devices: [{mac: '00:00:5e:00:53:01', ipv4: ['192.0.2.10'], hostname: 'host-a', source: 'both'}], truncated: false, errors: []};
const child = (mode: string) => boundedChild(process.execPath, ['service/tests/fixtures/transport-child.ts', mode], '', 1000, {}, true);
const code = (expected: string) => (e: unknown) => e instanceof RouterTransportError && e.code === expected;

test('the inventory invocation is the exact fixed argv with its own 8 s deadline and no stdin', () => {
    const r = new SSHRouter(c), i = r.invocation('inventory');
    assert.equal(i.argv.at(-1), 'cfctl rpc-inventory --json'); assert.equal(i.kind, 'inventory'); assert.equal(i.stdin, ''); assert.equal(i.deadlineMs, 8000); assert.equal(i.operationId, null);
    assert.equal(i.argv.at(-2), 'root@192.168.1.1');
    assert.throws(() => r.invocation('inventory', undefined, 'a1b2c3d4'), code('invalid_dispatch_kind'));
    assert.throws(() => r.invocation('inventory', c.enrollment as never), code('invalid_dispatch_kind'));
});
test('only invokeInventory accepts an inventory invocation', async () => {
    const r = new SSHRouter(c), i = r.invocation('inventory');
    await assert.rejects(r.invoke(i), code('invalid_dispatch_kind'));
    await assert.rejects(r.invokeActivity(i), code('invalid_dispatch_kind'));
    await assert.rejects(r.invokeInventory(r.invocation('observe')), code('invalid_dispatch_kind'));
    await assert.rejects(r.invokeInventory({...i, argv: [...i.argv, ';reboot']}), code('invocation_changed'));
});
test('boundedChild surfaces the remote exit code on a silent nonzero exit; the code string stays ssh_exit_failed', async () => {
    await assert.rejects(child('exit2'), e => e instanceof RouterTransportError && e.code === 'ssh_exit_failed' && e.exitCode === 2);
    await assert.rejects(child('exit255'), e => e instanceof RouterTransportError && e.code === 'ssh_exit_failed' && e.exitCode === 255);
    assert.equal((await child('invalid-command')).trim(), '{"ok":false,"errors":["invalid_command"]}');
});
test('old router, shape 1: new cfctl-ssh in front of an old cfctl replies invalid_command with exit 2', async () => {
    const text = await child('invalid-command');
    assert.throws(() => inventoryFromReply(text, c), code('inventory_unavailable:invalid_command'));
});
test('old router, shape 2: an old cfctl-ssh exits 2 silently', async () => {
    await assert.rejects(child('exit2').catch(e => { throw inventoryFailure(e); }), code('inventory_unavailable:old_router'));
});
test('ssh exit 255 (host-key mismatch, auth failure) is NOT mapped to inventory_unavailable', async () => {
    await assert.rejects(child('exit255').catch(e => { throw inventoryFailure(e); }), e => e instanceof RouterTransportError && e.code === 'ssh_exit_255' && !e.code.startsWith('inventory_unavailable'));
    // Any other transport failure keeps its own code.
    assert.equal(inventoryFailure(new RouterTransportError('ssh_timeout')).code, 'ssh_timeout');
    assert.equal(inventoryFailure(new RouterTransportError('ssh_exit_failed', 'possible', 1)).code, 'ssh_exit_failed');
    assert.equal(inventoryFailure(new Error('boom')).code, 'inventory_unavailable:invalid_router_inventory');
});
test('a valid v1 reply parses; unknown version, bad shape, wrong generation and empty output become inventory_unavailable codes', () => {
    assert.equal(inventoryFromReply(JSON.stringify(good), c).devices.length, 1);
    assert.throws(() => inventoryFromReply(JSON.stringify({...good, inventory_version: 2}), c), code('inventory_unavailable:unknown_inventory_version'));
    assert.throws(() => inventoryFromReply(JSON.stringify({...good, extra: 1}), c), code('inventory_unavailable:invalid_router_inventory'));
    assert.throws(() => inventoryFromReply(JSON.stringify({...good, generation: 'b'.repeat(64)}), c), code('inventory_unavailable:invalid_router_inventory'));
    assert.throws(() => inventoryFromReply('', c), code('inventory_unavailable:empty_reply'));
    assert.throws(() => inventoryFromReply(JSON.stringify({...good, devices: [{...good.devices[0], mac: c.protectedMacs[0]}]}), c), code('inventory_unavailable:protected_mac_listed'));
});
test('invokeInventory composes the transport and the classifier (255 and exit 2 stay distinguishable)', async () => {
    const r = new SSHRouter(c), i = r.invocation('inventory'), patch = r as unknown as {run: () => Promise<string>};
    patch.run = async () => JSON.stringify(good); assert.equal((await r.invokeInventory(i)).routerTime, 1791691200);
    patch.run = () => child('exit2'); await assert.rejects(r.invokeInventory(i), code('inventory_unavailable:old_router'));
    patch.run = () => child('exit255'); await assert.rejects(r.invokeInventory(i), code('ssh_exit_255'));
    patch.run = () => child('invalid-command'); await assert.rejects(r.invokeInventory(i), code('inventory_unavailable:invalid_command'));
});
