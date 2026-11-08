import test from 'node:test';
import assert from 'node:assert/strict';
import { parseContentFilter, MAX_FILTER_PROFILES } from '../src/content-filter-config.ts';

const good = {mode: 'owner', apiKeyFile: '/etc/couvrefeu/private/nextdns.key', defaultProfile: 'abc123', profiles: {jack: 'def456', penn: 'ghi789'}};
const code = (value: unknown, ...rest: [string?]) => { try { parseContentFilter(value, rest.length ? rest[0] : 'parent'); } catch (e) { return (e as Error).message; } return 'ok'; };

test('content filter manifest: valid shapes and mode requirements', () => {
    assert.deepEqual(parseContentFilter(good, 'parent'), good);
    assert.equal(parseContentFilter({...good, mode: 'parents'}, undefined).mode, 'parents');
    assert.equal(parseContentFilter({...good, mode: 'off', profiles: {}}, undefined).mode, 'off');
    assert.equal(code(good, undefined), 'owner_account_required');
});

test('content filter manifest: strict keys and values, codes only', () => {
    assert.equal(code({...good, extra: 1}), 'invalid_content_filter');
    assert.equal(code({...good, mode: 'on'}), 'invalid_content_filter');
    assert.equal(code({mode: 'off'}), 'invalid_content_filter');
    for (const apiKeyFile of ['relative/key', '/etc/../key', '/etc/a b', '/etc/k;rm', '', '/' + 'a'.repeat(4097), 7]) assert.equal(code({...good, apiKeyFile}), 'invalid_content_filter_key_file');
    for (const defaultProfile of ['AB1234', 'abc', 'a'.repeat(13), '../x', 5]) assert.equal(code({...good, defaultProfile}), 'invalid_content_filter_profile');
    for (const profiles of [[], null, 'x', {Jack: 'def456'}, {jack: 'abc123'}, {jack: 'def456', penn: 'def456'}, {jack: 'DEF456'}, {jack: 7}]) assert.equal(code({...good, profiles}), 'invalid_content_filter_profiles');
    const many = Object.fromEntries(Array.from({length: MAX_FILTER_PROFILES + 1}, (_, i) => [`p${i}`, `x${String(i).padStart(5, '0')}`]));
    assert.equal(code({...good, profiles: many}), 'invalid_content_filter_profiles');
});

test('content filter manifest: prototype-ish person ids are plain own keys, bad ones rejected', () => {
    const out = parseContentFilter({...good, profiles: {constructor: 'def456', tostring: 'ghi789'}}, 'parent');
    assert.equal(Object.getPrototypeOf(out.profiles), null); assert.equal(Object.hasOwn(out.profiles, 'constructor'), true); assert.equal(out.profiles['hasownproperty'], undefined);
    for (const person of ['__proto__', 'Constructor', '1jack', 'a-b', '']) assert.equal(code({...good, profiles: {[person]: 'def456'}}), 'invalid_content_filter_profiles');
});

test('content filter manifest: errors never echo values', () => {
    for (const bad of [{...good, apiKeyFile: '/etc/secret key'}, {...good, defaultProfile: 'SECRETID'}]) {
        try { parseContentFilter(bad, 'parent'); assert.fail('should throw'); } catch (e) { assert.match((e as Error).message, /^invalid_content_filter(_key_file|_profile)?$/); }
    }
});
