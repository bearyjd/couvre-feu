import test from 'node:test';
import assert from 'node:assert/strict';
import { boundedChild, SSHRouter } from '../src/ssh-router.ts';
import { testConfig, observation } from './fixtures/integration.ts';
import { parseObservation, policyDigest } from '../../shared/src/router-rpc.ts';

test('SSH invocation uses fixed public-key-only pinned argv, no forwarding, shell interpolation or environment fallback', async () => {
    const c = testConfig('/tmp/cf-no-agent-test'), router = new SSHRouter(c), i = router.invocation('observe');
    assert.equal(i.executable, '/usr/bin/ssh'); assert.equal(i.argv.at(-1), 'cfctl rpc-status --json');
    assert.deepEqual(i.argv.slice(0, 4), ['-F', '/dev/null', '-T', '-p']);
    for (const required of ['BatchMode=yes', 'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no', 'PreferredAuthentications=publickey', 'IdentitiesOnly=yes', 'StrictHostKeyChecking=yes', 'ForwardAgent=no', 'ForwardX11=no', 'ClearAllForwardings=yes', 'PermitLocalCommand=no', 'ConnectionAttempts=1', 'ProxyCommand=none', 'ProxyJump=none']) assert.ok(i.argv.includes(required), required);
    assert.ok(i.argv.includes(`IdentityAgent=${c.router.agentSocket}`)); assert.ok(i.argv.includes(`UserKnownHostsFile=${c.router.knownHosts}`));
    assert.equal(i.argv.at(-2), 'root@192.168.1.1'); assert.equal(i.stdin, '');
    assert.throws(() => router.invocation('receipt', undefined, 'a;reboot'));
    assert.throws(() => router.invocation('apply', {rpc_version: 1, generation: c.router.generation, operation_id: 'bad\ncommand', expected_revision: 0, expected_digest: policyDigest(c.enrollment), policy: {...c.enrollment, revision: 1}}));
    await assert.rejects(router.invoke({...i, argv: [...i.argv, ';reboot']}), /invocation_changed/);
    await assert.rejects(router.invoke(i), e => e instanceof Error && e.message === 'private_transport_configuration_unavailable' && 'delivery' in e && e.delivery === 'not_delivered');
});
test('bounded real child distinguishes spawn failure from possibly delivered exit and truncation', async () => {
    await assert.rejects(boundedChild('/definitely/missing/cf-test-child', [], '', 1000, {}), e => e instanceof Error && e.message === 'ssh_spawn_failed' && 'delivery' in e && e.delivery === 'not_delivered');
    await assert.rejects(boundedChild(process.execPath, ['service/tests/fixtures/transport-child.ts', 'exit'], '', 1000, {}), /ssh_exit_failed/);
    const text = await boundedChild(process.execPath, ['service/tests/fixtures/transport-child.ts', 'truncated'], '', 1000, {});
    assert.throws(() => parseObservation(text));
});
test('real children enforce output, diagnostic and deadline bounds without returning diagnostics', async () => {
    for (const [mode, expected] of [['oversize', 'ssh_output_limit'], ['diagnostics', 'ssh_diagnostic_limit'], ['delay', 'ssh_timeout']] as const) {
        const start = Date.now(); await assert.rejects(boundedChild(process.execPath, ['service/tests/fixtures/transport-child.ts', mode], '', mode === 'delay' ? 100 : 1000, {}), e => e instanceof Error && e.message === expected && !e.message.includes('PRIVATE_DIAGNOSTIC') && 'delivery' in e && e.delivery === 'possible');
        assert.ok(Date.now() - start < 2500);
    }
});
test('child stdin is literal and nonzero accepted output remains subject to full RPC validation', async () => {
    const c = testConfig('/tmp/unused'), o = observation(c, c.enrollment, 1791691200), input = JSON.stringify(o);
    const text = await boundedChild(process.execPath, ['service/tests/fixtures/transport-child.ts', 'echo-nonzero'], input, 1000, {}, true);
    assert.deepEqual(parseObservation(text), o);
    const literal = '$(echo PRIVATE_COMMAND); `id`\n';
    assert.equal(await boundedChild(process.execPath, ['service/tests/fixtures/transport-child.ts', 'echo'], literal, 1000, {}), literal);
    assert.equal(await boundedChild(process.execPath, ['service/tests/fixtures/transport-child.ts', 'environment'], '', 1000, {CF_TEST_PUBLIC: 'explicit'}), 'explicit:absent');
});
