import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseJSON } from '../src/json.ts';
import { parsePolicy, normalizePolicy, canonicalIPv6, policyJSON } from '../src/router-schema.ts';
import { INITIAL_POLICY } from '../../service/src/fixtures.ts';
test('strict router subset rejects duplicate/unknown keys, escapes, Unicode, exponents, overflow and depth', () => {
    for (const value of [policyJSON(INITIAL_POLICY).replace('"version":1', '"version":1,"version":1'), policyJSON(INITIAL_POLICY).replace('"revision":0', '"revision":1e2'), policyJSON(INITIAL_POLICY).replace('"revision":0', '"revision":-0'), policyJSON(INITIAL_POLICY).replace('"revision":0', '"revision":2147483648'), policyJSON(INITIAL_POLICY).replace('"alex"', '"al\\u0065x"'), policyJSON(INITIAL_POLICY).replace('"alex"', '"aléx"'), policyJSON(INITIAL_POLICY).replace('"version":1', '"bonus":1,"version":1')]) {
        assert.throws(() => parsePolicy(value));
    }
    assert.throws(() => parseJSON('['.repeat(14) + '0' + ']'.repeat(14)));
    assert.throws(() => parseJSON(' '.repeat(65537)));
    assert.throws(() => parseJSON('{"a":1,"a":2}'));
});
test('ownership/protected identities, schedule expansion and address canonical duplicates rejected', () => {
    assert.throws(() => normalizePolicy({
        ...INITIAL_POLICY, people: [...INITIAL_POLICY.people, {
                id: 'other', macs: INITIAL_POLICY.people[0].macs
            }]
    }), /duplicate_value/);
    assert.throws(() => normalizePolicy(INITIAL_POLICY, INITIAL_POLICY.people[0].macs), /protected_mac_overlap/);
    assert.throws(() => normalizePolicy({
        ...INITIAL_POLICY, people: [{
                id: 'alex', macs: Array.from({
                    length: 32
                }, (_, i) => `02:00:00:00:03:${i.toString(16).padStart(2, '0')}`)
            }], schedules: Array.from({
            length: 5
        }, (_, i) => ({
            person: 'alex', id: `s${i}`, weekdays: ['Mon'], start: '22:00', stop: '06:30'
        }))
    }), /expanded_schedule_limit/);
    assert.equal(canonicalIPv6('2001:0db8:0:0:0:0:0:1'), '2001:db8::1');
    assert.throws(() => normalizePolicy({
        ...INITIAL_POLICY, doh: {
            ipv4: [], ipv6: ['2001:db8::1', '2001:0db8:0:0:0:0:0:1']
        }
    }), /duplicate_value/);
});
test('shared serialization passes actual cfctl awk parser with canonical record/weekday/address agreement', () => {
    const input = normalizePolicy({
        ...INITIAL_POLICY, pauses: [{
                person: 'alex', until: 1791691201
            }], doh: {
            ipv4: ['203.0.113.1'], ipv6: ['2001:0db8:0:0:0:0:0:1']
        }
    }), serialized = policyJSON(input);
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-schema-')), path = join(dir, 'policy.json');
    writeFileSync(path, serialized + '\n');
    try {
        const result = spawnSync('awk', ['-f', fileURLToPath(new URL('../../router/lib/json.awk', import.meta.url)), path], {
            encoding: 'utf8', timeout: 3000 // timeout-ok: awk parse of a tiny file measured 0.01 s (300x headroom)
        });
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /A\talex\t1791691201/);
        assert.match(result.stdout, /S\talex\tschool_nights\tMon,Tue,Wed,Thu,Fri,Sat,Sun/);
        assert.match(result.stdout, /D6\t2001:db8::1/);
        assert.deepEqual(parsePolicy(serialized), input);
    }
    finally {
        rmSync(dir, {
            recursive: true
        });
    }
});
