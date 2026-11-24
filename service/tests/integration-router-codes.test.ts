import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { KNOWN_ROUTER_CODES, PRE_WRITE_ROUTER_CODES, ROUTER_ERROR_UNRECOGNIZED, withFixedErrorCodes } from '../src/integration-router-codes.ts';
import { ADDRESS_COVERAGE_REJECTIONS, PRE_WRITE_REJECTIONS } from '../src/integration-children.ts';
import { observation, testConfig } from './fixtures/integration.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';

// Roadmap item 2, S2a (schedules.editable, off; unverified on this router): the closed set of router codes the service may store or serve.
const ROUTER = new URL('../../router/', import.meta.url).pathname;
function files(dir: string): string[] {
    return readdirSync(dir).flatMap(name => { const p = join(dir, name); return statSync(p).isDirectory() ? files(p) : [p]; });
}
test('every known router code is a literal failure code in router/ (cf_fail, platform_fail or a CF_ERROR default)', () => {
    const text = files(ROUTER).map(p => readFileSync(p, 'utf8')).join('\n');
    for (const code of KNOWN_ROUTER_CODES) {
        assert.match(text, new RegExp(`(?:cf_fail|platform_fail) ${code}\\b|CF_ERROR=(?:\\$\\{CF_ERROR:-)?${code}\\b`), code);
    }
    for (const code of [...PRE_WRITE_REJECTIONS, ...ADDRESS_COVERAGE_REJECTIONS, ...PRE_WRITE_ROUTER_CODES]) assert.ok(KNOWN_ROUTER_CODES.has(code), code);
});
test('withFixedErrorCodes maps entry for entry: counts (and so health) are kept, unknown text becomes one fixed code', () => {
    const config = testConfig('/nonexistent'), o = observation(config, normalizePolicy(config.enrollment), 1791691200);
    const mapped = withFixedErrorCodes({...o, errors: ['policy_conflict', 'some text'], status: {...o.status, errors: ['x y z', 'previous_apply_failed', 'x y z']}});
    assert.deepEqual(mapped.errors, ['policy_conflict', ROUTER_ERROR_UNRECOGNIZED]);
    assert.deepEqual(mapped.status.errors, [ROUTER_ERROR_UNRECOGNIZED, 'previous_apply_failed', ROUTER_ERROR_UNRECOGNIZED]);
    assert.deepEqual({...mapped, errors: o.errors, status: o.status}, o);
});
