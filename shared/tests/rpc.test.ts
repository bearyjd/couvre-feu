import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { canonicalPolicyRecords, normalizeEnvelope, normalizeObservation, parseObservation, policyDigest, requestDigest, exactHealthy } from '../src/router-rpc.ts';
import { normalizePolicy } from '../src/router-schema.ts';
import { testConfig, observation } from '../../service/tests/fixtures/integration.ts';

test('RPC digests match actual router awk records, C sorting, weekdays and canonical IPv6', () => {
    const input = {version: 1, revision: 13, people: [{id: 'z', macs: []}, {id: 'a', macs: ['02:11:22:33:44:55']}], pauses: [{person: 'a', until: 0}], schedules: [{person: 'a', id: 'school', weekdays: ['Fri', 'Mon', 'Sun'], start: '21:00', stop: '07:00'}], doh: {ipv4: ['9.9.9.9', '1.1.1.1'], ipv6: ['2001:0db8:0000:0000:0001:0000:0000:0001']}};
    const p = normalizePolicy(input), child = spawnSync('awk', ['-f', 'router/lib/json.awk'], {input: JSON.stringify(input), encoding: 'utf8', env: {PATH: '/usr/bin:/bin', LC_ALL: 'C'}});
    assert.equal(child.status, 0, child.stderr);
    const rows = child.stdout.trimEnd().split('\n'), canonical = ['V\t1', 'R\t13', ...rows.filter(row => !/^[VR]\t/.test(row)).sort()].join('\n') + '\n';
    assert.equal(canonicalPolicyRecords(p), canonical);
    const hash = spawnSync('sha256sum', [], {input: canonical, encoding: 'utf8'});
    assert.equal(policyDigest(p), hash.stdout.split(' ')[0]);
    const e = normalizeEnvelope({rpc_version: 1, generation: 'a'.repeat(64), operation_id: 'op_1', expected_revision: 12, expected_digest: 'b'.repeat(64), policy: p});
    const request = spawnSync('sha256sum', [], {input: `rpc1\n${e.generation}\nop_1\n12\n${e.expected_digest}\n${policyDigest(p)}\n`, encoding: 'utf8'});
    assert.equal(requestDigest(e), request.stdout.split(' ')[0]);
});
test('RPC envelope rejects shell-like identities, unknown fields, missing next revision and input overflow', () => {
    const c = testConfig('/tmp/unused'), p = {...c.enrollment, revision: 1};
    const e = {rpc_version: 1, generation: c.router.generation, operation_id: 'op', expected_revision: 0, expected_digest: policyDigest(c.enrollment), policy: p};
    assert.equal(normalizeEnvelope(e).operation_id, 'op');
    for (const operation_id of ['-', 'OP', 'a;reboot', 'a\n', 'a'.repeat(65)]) assert.throws(() => normalizeEnvelope({...e, operation_id}));
    assert.throws(() => normalizeEnvelope({...e, policy: c.enrollment}));
    assert.throws(() => normalizeEnvelope({...e, extra: true}));
    assert.throws(() => normalizeEnvelope({...e, generation: 'A'.repeat(64)}));
});
test('RPC observation rejects missing, contradicted, duplicate, truncated and fabricated witnesses', () => {
    const c = testConfig('/tmp/unused'), o = observation(c, c.enrollment, 1791691200);
    assert.equal(parseObservation(JSON.stringify(o)).policyDigest, o.policyDigest);
    assert.throws(() => normalizeObservation({...o, policyDigest: '0'.repeat(64)}));
    assert.throws(() => normalizeObservation({...o, rpc_version: 2}));
    assert.throws(() => normalizeObservation({...o, status: {...o.status, capabilities: {...o.status.capabilities, nativeKernelConfirmed: undefined}}}));
    assert.throws(() => parseObservation(JSON.stringify(o).slice(0, -1)));
    assert.throws(() => parseObservation(JSON.stringify(o) + '{}'));
    assert.throws(() => parseObservation('{"rpc_version":1,"rpc_version":1}'));
    assert.throws(() => parseObservation(' '.repeat(131073)));
    const e = normalizeEnvelope({rpc_version: 1, generation: c.router.generation, operation_id: 'op', expected_revision: 0, expected_digest: o.policyDigest, policy: {...c.enrollment, revision: 1}});
    assert.equal(exactHealthy(o, e), false);
});
