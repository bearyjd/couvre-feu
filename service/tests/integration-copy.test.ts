import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { applyRewrites, integrationHTMLRewrites, integrationManifestRewrites } from '../src/integration-copy.ts';

const publicFile = (name: string) => readFileSync(new URL(`../../web/public/${name}`, import.meta.url), 'utf8');
const scope = 'a'.repeat(64);

for (const automatic of [false, true]) {
    test(`every integration needle applies to the shipped files (automatic=${automatic})`, () => {
        const cases = [
            ['index.html', integrationHTMLRewrites(scope, automatic)],
            ['manifest.webmanifest', integrationManifestRewrites(automatic)],
        ] as const;
        for (const [name, rewrites] of cases) {
            const source = publicFile(name);
            const out = applyRewrites(source, rewrites, name);
            for (const [needle, replacement] of rewrites) {
                assert.ok(source.includes(needle), `${name}: needle present: ${needle}`);
                assert.ok(out.includes(replacement), `${name}: replacement applied: ${needle}`);
            }
            assert.notEqual(out, source);
        }
    });
}

test('a needle missing from the source throws instead of serving demo copy', () => {
    assert.throws(() => applyRewrites('edited copy', [['old copy', 'new copy']], 'index.html'), /integration_copy_needle_missing:index\.html:old copy/);
});

test('replacement text containing $ patterns is inserted literally', () => {
    assert.equal(applyRewrites('a', [['a', '$&$1']], 'x'), '$&$1');
});
