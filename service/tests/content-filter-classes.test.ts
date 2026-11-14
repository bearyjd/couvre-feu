import test from 'node:test';
import assert from 'node:assert/strict';
import { CLASS_CODES, HEADLINE_CLASSES, isClassCode } from '../../shared/src/content-filter-classes.ts';
import { classOf } from '../src/content-filter-classes.ts';

const inEnum = (v: string) => (CLASS_CODES as readonly string[]).includes(v);

test('the shared class enum is the closed list of the plan, headline classes are a subset without background ones', () => {
    assert.deepEqual([...CLASS_CODES], ['adult', 'gambling', 'dating', 'piracy', 'social', 'gaming', 'video', 'apps', 'bypass', 'denylist', 'ads_trackers', 'security', 'other']);
    assert.ok(Object.isFrozen(CLASS_CODES) && Object.isFrozen(HEADLINE_CLASSES));
    assert.ok(HEADLINE_CLASSES.every(inEnum));
    for (const c of ['ads_trackers', 'security', 'other']) assert.ok(!(HEADLINE_CLASSES as readonly string[]).includes(c), c);
    assert.equal(HEADLINE_CLASSES.length, 10);
    assert.ok(isClassCode('adult') && !isClassCode('porn') && !isClassCode('') && !isClassCode(7) && !isClassCode('toString'));
});

test('prefix families map to background classes', () => {
    assert.equal(classOf('blocklist:nextdns-recommended'), 'ads_trackers');
    assert.equal(classOf('native:apple'), 'ads_trackers');
    assert.equal(classOf('disguised-trackers'), 'ads_trackers');
});

test('denylist ids map to denylist and the suffix is discarded', () => {
    assert.equal(classOf('denylist'), 'denylist');
    assert.equal(classOf('denylist:secret-domain.test'), 'denylist');
    assert.equal(classOf('denylistx'), 'other');
});

test('candidate parental-control forms map to their classes (UNVERIFIED forms, closed table)', () => {
    assert.equal(classOf('porn'), 'adult');
    assert.equal(classOf('parentalcontrol:porn'), 'adult');
    assert.equal(classOf('category:gambling'), 'gambling');
    assert.equal(classOf('tiktok'), 'apps');
    assert.equal(classOf('service:discord'), 'apps');
});

test('unknown, empty and near-miss ids are other', () => {
    for (const id of ['', 'unknown-thing', 'porn2', 'PORN-x', 'parentalcontrol:', 'blocklist', 'native', 'xblocklist:a']) assert.equal(classOf(id), 'other', id);
});

test('totality and no echo: any input, including hostile and non-string values, yields a class code only', () => {
    const hostile = ['denylist:secret-domain.test', 'blocklist:secret-domain.test', 'native:\u0000', 'é'.repeat(300), 'a'.repeat(256), '__proto__', 'constructor', 'toString',
        '<script>alert(1)</script>', 'x'.repeat(100_000), '\n', 'denylist:' + 'a'.repeat(1000)];
    for (const id of hostile) { const out = classOf(id); assert.ok(inEnum(out), id.slice(0, 20)); assert.ok(!out.includes('secret-domain')); }
    let seed = 12345;
    const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    for (let i = 0; i < 2000; i++) {
        const id = Array.from({ length: Math.floor(rnd() * 40) }, () => String.fromCharCode(Math.floor(rnd() * 0x250))).join('');
        assert.ok(inEnum(classOf(id)));
    }
    for (const bad of [undefined, null, 5, {}, []]) assert.equal(classOf(bad as never), 'other');
});
