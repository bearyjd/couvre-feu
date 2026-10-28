import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { PassThrough, Readable } from 'node:stream';
import { once } from 'node:events';
import { emptyRuntimeWitness } from '../src/empty-witness.ts';
import { normalizePolicy, MAX_INTEGER } from '../src/router-schema.ts';
import { policyDigest } from '../src/router-rpc.ts';
import type { RPCObservation } from '../src/router-rpc.ts';
import { readWitnessInput } from '../../tests/empty-witness.ts';

const generation = 'a'.repeat(64), clock = 1736204400;
const context = {expectedGeneration: generation, minRouterTime: clock - 1, maxRouterTime: clock + 1};
function sample(): RPCObservation {
    const policy = normalizePolicy({version: 1, revision: 0, people: [], pauses: [], schedules: [], doh: {ipv4: [], ipv6: []}});
    return {rpc_version: 1, generation, acceptedPolicy: policy, policyDigest: policyDigest(policy), currentOperationId: null, receipt: null, routerTime: clock, errors: [],
        status: {ok: true, desiredRevision: 0, confirmedRevision: 0, desiredPauses: [], effectivePauses: [], observed: {kids: [], paused: []}, drift: false, errors: [],
            capabilities: {ipv6: true, conntrack: true, nativeKernelConfirmed: true, addressCoverageComplete: true, routerCompatibilityVerified: false}}};
}
const gate = (o: RPCObservation, c: unknown = context) => emptyRuntimeWitness(JSON.stringify(o), c);
function replacePolicy(o: RPCObservation, input: unknown): RPCObservation {
    const p = normalizePolicy(input);
    return {...o, acceptedPolicy: p, policyDigest: policyDigest(p), status: {...o.status, desiredRevision: p.revision, confirmedRevision: p.revision, desiredPauses: p.pauses}};
}
test('empty witness pass labels only supplied runtime evidence, with explicit generation and inclusive time bounds', () => {
    assert.deepEqual(gate(sample()), {source: 'supplied-empty-runtime-witness', verdict: 'PASS_EMPTY_WITNESS', reason: null, routerCompatibilityVerified: false, packetAcceptance: 'unmeasured', restoration: 'unverified'});
    for (const time of [context.minRouterTime, context.maxRouterTime]) assert.equal(gate({...sample(), routerTime: time}).verdict, 'PASS_EMPTY_WITNESS');
    assert.equal(gate(sample(), {...context, minRouterTime: clock, maxRouterTime: clock}).verdict, 'PASS_EMPTY_WITNESS');
});
test('strict witness context rejects missing, extra, guessed, noncanonical, zero, backwards and out-of-range values', () => {
    for (const c of [null, {}, {...context, extra: true}, {...context, expectedGeneration: undefined}, {...context, expectedGeneration: 'A'.repeat(64)}, {...context, expectedGeneration: generation + '\n'}, {...context, expectedGeneration: 'generated_from_response'},
        {...context, minRouterTime: 0}, {...context, maxRouterTime: 0}, {...context, minRouterTime: clock + 2}, {...context, minRouterTime: -1}, {...context, maxRouterTime: MAX_INTEGER + 1}, {...context, minRouterTime: 1.5}, {...context, maxRouterTime: '1736204401'}, {...context, maxRouterTime: NaN}]) {
        assert.deepEqual(gate(sample(), c), {...gate(sample()), verdict: 'UNAVAILABLE', reason: 'invalid_context'});
    }
    assert.equal(gate({...sample(), generation: 'b'.repeat(64)}).reason, 'generation_mismatch');
    assert.equal(gate({...sample(), routerTime: 0}).reason, 'clock_unavailable');
    for (const routerTime of [context.minRouterTime - 1, context.maxRouterTime + 1]) assert.equal(gate({...sample(), routerTime}).reason, 'clock_out_of_bounds');
});
test('any policy content or nonzero revision fails, including placeholder people and DoH-only policy', () => {
    const o = sample(), p = o.acceptedPolicy;
    const variants = [{...p, revision: 1}, {...p, people: [{id: 'placeholder', macs: []}]}, {...p, people: [{id: 'pilot', macs: ['02:11:22:33:44:55']}]},
        {...p, doh: {ipv4: ['1.1.1.1'], ipv6: []}}, {...p, doh: {ipv4: [], ipv6: ['2001:db8::1']}},
        {...p, people: [{id: 'pilot', macs: []}], pauses: [{person: 'pilot', until: clock + 20}]},
        {...p, people: [{id: 'pilot', macs: []}], schedules: [{person: 'pilot', id: 'school', weekdays: ['Mon'], start: '21:00', stop: '07:00'}]}];
    for (const policy of variants) assert.notEqual(gate(replacePolicy(o, policy)).verdict, 'PASS_EMPTY_WITNESS');
    assert.equal(gate({...o, policyDigest: '0'.repeat(64)}).reason, 'invalid_rpc');
});
test('operation identities and historical receipts cannot pass the empty activation gate', () => {
    const o = sample();
    assert.equal(gate({...o, currentOperationId: 'old_operation'}).reason, 'operation_present');
    const r = {operationId: 'old_operation', requestDigest: 'b'.repeat(64), baseRevision: 0, baseDigest: o.policyDigest, acceptedRevision: 1, acceptedDigest: 'c'.repeat(64), outcome: 'accepted' as const, current: false};
    assert.equal(gate({...o, receipt: r}).reason, 'operation_present');
    assert.equal(gate({...o, errors: ['installation_in_progress']}).reason, 'rpc_errors');
});
test('unhealthy runtime, missing confirmation, capabilities, sets and pause metadata never grant a pass', () => {
    const o = sample();
    const statuses = [{...o.status, ok: false}, {...o.status, drift: true}, {...o.status, errors: ['previous_apply_failed']}, {...o.status, confirmedRevision: null}, {...o.status, confirmedRevision: 1}, {...o.status, desiredRevision: 1},
        {...o.status, observed: {kids: ['02:11:22:33:44:55'], paused: []}}, {...o.status, observed: {kids: [], paused: ['02:11:22:33:44:55']}},
        {...o.status, desiredPauses: [{person: 'pilot', until: 0}]}, {...o.status, effectivePauses: [{person: 'pilot', until: 0}]}];
    for (const status of statuses) assert.notEqual(gate({...o, status}).verdict, 'PASS_EMPTY_WITNESS');
    for (const capability of ['ipv6', 'conntrack', 'nativeKernelConfirmed', 'addressCoverageComplete'] as const) assert.equal(gate({...o, status: {...o.status, capabilities: {...o.status.capabilities, [capability]: false}}}).reason, 'runtime_unhealthy');
    assert.equal(gate({...o, status: {...o.status, capabilities: {...o.status.capabilities, routerCompatibilityVerified: true as false}}}).reason, 'invalid_rpc');
});
test('production parser remains authoritative for malformed, duplicate, truncated, extra and oversized RPC input', () => {
    const raw = JSON.stringify(sample());
    for (const input of ['', '{}', raw.slice(0, -1), raw + '{}', raw.replace('"rpc_version":1', '"rpc_version":1,"rpc_version":1'), JSON.stringify(sample().status)]) assert.equal(emptyRuntimeWitness(input, context).reason, 'invalid_rpc');
    assert.equal(emptyRuntimeWitness(' '.repeat(131073), context).reason, 'input_limit');
    assert.equal(emptyRuntimeWitness(raw + '\u0000', context).reason, 'input_not_ascii');
    assert.equal(emptyRuntimeWitness(raw + '\u00a0', context).reason, 'input_not_ascii');
});
test('bounded input reader requires EOF and rejects total bytes, non-ASCII, abrupt close and deadline', async () => {
    const open = new PassThrough(); let complete = false;
    const pending = readWitnessInput(open, 500).then(v => {complete = true; return v;});
    open.write(JSON.stringify(sample())); await new Promise(resolve => setImmediate(resolve)); assert.equal(complete, false);
    open.end(); assert.equal(await pending, JSON.stringify(sample()));
    assert.equal((await readWitnessInput(Readable.from([Buffer.alloc(131072, 32)]))).length, 131072);
    await assert.rejects(readWitnessInput(Readable.from([Buffer.alloc(131072, 32), Buffer.from('x')])), /input_limit/);
    await assert.rejects(readWitnessInput(Readable.from([Buffer.from([0xff])])), /input_not_ascii/);
    const abrupt = new PassThrough(), a = readWitnessInput(abrupt, 500); abrupt.destroy(); await assert.rejects(a, /input_unavailable/);
    const failure = new PassThrough(), f = readWitnessInput(failure, 500); failure.destroy(new Error('PRIVATE_ERROR_MUST_NOT_ESCAPE')); await assert.rejects(f, /^Error: input_unavailable$/);
    const timed = new PassThrough(); await assert.rejects(readWitnessInput(timed, 25), /input_deadline/); assert.equal(timed.destroyed, true);
    for (const deadline of [0, 10001, NaN]) await assert.rejects(readWitnessInput(new PassThrough(), deadline), /input_unavailable/);
});
test('actual CLI has bounded generic output, exact positional context, ASCII/size limits and no metadata echo', () => {
    const argv = ['tests/empty-witness.ts', generation, String(context.minRouterTime), String(context.maxRouterTime)];
    const run = (input: string | Buffer, args = argv) => spawnSync(process.execPath, args, {input, encoding: 'utf8', timeout: 15000});
    const pass = run(JSON.stringify(sample())); assert.equal(pass.status, 0, pass.stderr); assert.equal(JSON.parse(pass.stdout).verdict, 'PASS_EMPTY_WITNESS');
    for (const failed of [run('{PRIVATE_RPC'), run(Buffer.alloc(131073, 32)), run(Buffer.from([0xff])), run(JSON.stringify({...sample(), generation: 'b'.repeat(64)})), run('', argv.slice(0, -1)), run('', [...argv, 'EXTRA_PRIVATE_ARG']), run('', [argv[0], generation, '01', argv[3]]), run('', [argv[0], generation + '\n', argv[2], argv[3]]), run('', [argv[0], generation, argv[2] + '\n', argv[3]])]) {
        assert.equal(failed.status, 1, failed.stderr); assert.ok(failed.stdout.length < 512); assert.equal(failed.stderr, ''); assert.doesNotMatch(failed.stdout, /PRIVATE|a{64}|b{64}|173620/); assert.notEqual(JSON.parse(failed.stdout).verdict, 'PASS_EMPTY_WITNESS');
    }
});
test('actual CLI waits for EOF instead of passing a complete JSON document while stdin stays open', async () => {
    const child = spawn(process.execPath, ['tests/empty-witness.ts', generation, String(context.minRouterTime), String(context.maxRouterTime)], {stdio: ['pipe', 'pipe', 'pipe']});
    let output = '', diagnostics = ''; child.stdout.on('data', chunk => {output += chunk;}); child.stderr.on('data', chunk => {diagnostics += chunk;});
    const closed = once(child, 'close');
    child.stdin.write(JSON.stringify(sample())); await new Promise(resolve => setTimeout(resolve, 100)); assert.equal(output, '');
    child.stdin.end(); const [code] = await closed; assert.equal(code, 0); assert.equal(diagnostics, ''); assert.equal(JSON.parse(output).verdict, 'PASS_EMPTY_WITNESS');
});
// router/install.sh takes ~51 s on a quiet host and over 60 s under load (CI, parallel agents). The inner install
// limit is 180 s and the outer spawnSync limit (240 s) must stay above it so the Python side reports first.
test('actual marked fresh scoped install output passes only as supplied fixture runtime evidence', () => {
    const script = `import json, os, subprocess, sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path('tests/fixtures').resolve()))\nfrom harness import RouterFixture, REPO, KID, PROTECTED\nf = RouterFixture()\ntry:\n r = subprocess.run(f.shell + [str(REPO / 'router/install.sh'), '--activate', '--protect', PROTECTED, '--rpc-allow', KID], env=dict(f.env, CF_TEST_INSTALL_KERNEL='1'), capture_output=True, text=True, timeout=180)\n if r.returncode: raise RuntimeError('marked_fixture_activation_failed')\n g = next(line.split('\\t')[1] for line in (f.root / 'etc/couvrefeu/state').read_text().splitlines() if line.startswith('G\\t'))\n r = f.run('rpc-status', '--json')\n if r.returncode: raise RuntimeError('marked_fixture_rpc_status_failed')\n t = int(f.env['CF_NOW'])\n print(json.dumps({'raw': r.stdout, 'context': {'expectedGeneration': g, 'minRouterTime': t-1, 'maxRouterTime': t+1}}))\nfinally:\n f.close()\n`;
    const child = spawnSync('python3', ['-B', '-c', script], {encoding: 'utf8', timeout: 240000}); assert.equal(child.status, 0, child.stderr);
    const supplied = JSON.parse(child.stdout) as {raw: string; context: unknown};
    const result = emptyRuntimeWitness(supplied.raw, supplied.context);
    assert.equal(result.verdict, 'PASS_EMPTY_WITNESS'); assert.equal(result.source, 'supplied-empty-runtime-witness'); assert.equal(result.restoration, 'unverified');
});
