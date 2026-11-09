import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db.ts';
import { AppError } from '../../shared/src/errors.ts';
import { ContentFilterStore, FILTER_LIMITS, canonicalJSON, desiredSha256, hostname, isLoosening, parseDesired } from '../src/content-filter-state.ts';
import type { ContentFilterDesired } from '../src/content-filter-state.ts';
import { PROFILE_ID_PATTERN } from '../src/content-filter-config.ts';
import { PROFILE_ID } from '../src/nextdns-client.ts';
import { DESIRED, SECRET_DOMAIN, input } from './fixtures/content-filter.ts';

const BASE: ContentFilterDesired = parseDesired({categories: ['gambling', 'porn'], services: ['tiktok', 'youtube'], safeSearch: true, youtubeRestrictedMode: true, blockBypass: true, denylist: ['a-bad.test', 'b-bad.test'], allowlist: ['ok.test']});
const with_ = (over: Record<string, unknown>) => parseDesired({...BASE, ...over});
const invalid = (value: unknown) => assert.throws(() => parseDesired(value), (e: unknown) => e instanceof AppError && e.status === 400 && e.code === 'invalid_filter' && e.message === 'invalid_filter');

test('the manifest profile-id rule equals the NextDNS client rule', () => {
    assert.equal(PROFILE_ID_PATTERN.source, PROFILE_ID.source);
});

test('parseDesired canonicalises: sorted, de-duplicated, lowercase domains, identical hash for equal filters', () => {
    const a = parseDesired(input({categories: ['porn', 'gambling', 'porn'], denylist: ['B.example', 'a.example', 'b.example']}));
    assert.deepEqual(a.categories, ['gambling', 'porn']);
    assert.deepEqual(a.denylist, ['a.example', 'b.example']);
    const b = parseDesired(input({categories: ['gambling', 'porn'], denylist: ['a.example', 'b.example']}));
    assert.equal(desiredSha256(a), desiredSha256(b));
    assert.equal(canonicalJSON(a), canonicalJSON(b));
    assert.notEqual(desiredSha256(a), desiredSha256(parseDesired(input({safeSearch: false}))));
    assert.match(desiredSha256(a), /^[0-9a-f]{64}$/);
});

test('parseDesired is strict: shape, unknown and missing keys, types, ids and bounds', () => {
    const base = {categories: [], services: [], safeSearch: false, youtubeRestrictedMode: false, blockBypass: false, denylist: [], allowlist: []};
    parseDesired(base);
    for (const bad of [null, [], 'x', 1, {}, {...base, extra: 1}, {...base, safeSearch: 'yes'}, {...base, blockBypass: 1}, {...base, categories: 'porn'},
        {...base, categories: [1]}, {...base, categories: ['Porn']}, {...base, categories: ['a b']}, {...base, services: ['']}, {...base, services: ['../x']},
        {...base, categories: Array.from({length: FILTER_LIMITS.categories + 1}, (_, n) => `c${n}`)},
        {...base, services: Array.from({length: FILTER_LIMITS.services + 1}, (_, n) => `s${n}`)},
        {...base, denylist: Array.from({length: FILTER_LIMITS.denylist + 1}, (_, n) => `d${n}.test`)},
        {...base, allowlist: Array.from({length: FILTER_LIMITS.allowlist + 1}, (_, n) => `a${n}.test`)},
        {...base, denylist: [5]}, {...base, allowlist: [null]}]) invalid(bad);
    const {safeSearch: _drop, ...missing} = base; invalid(missing);
    parseDesired({...base, categories: Array.from({length: FILTER_LIMITS.categories}, (_, n) => `c${n}`)});
});

test('hostname: strict lowercase hostnames only', () => {
    for (const ok of ['example.com', 'Example.COM', 'a-b.example.org', 'x1.y2.z3', 'xn--bcher-kva.example']) assert.equal(hostname(ok), ok.toLowerCase());
    const long = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`;
    assert.equal(long.length, 253); hostname(long);
    for (const bad of ['', 'localhost', 'a', '.example.com', 'example.com.', 'a..b.com', '-a.example.com', 'a-.example.com', '*.example.com', 'a_b.example.com', 'exa mple.com',
        'example.com/path', 'example.com:80', 'http://example.com', '192.168.1.1', '1.2.3.4', 'example.123', 'bücher.example', `${'a'.repeat(64)}.example.com`, `${long}x`, 'a.b\n', 5, null, undefined]) {
        assert.throws(() => hostname(bad), (e: unknown) => e instanceof AppError && e.code === 'invalid_filter' && !e.message.includes('example'), String(bad));
    }
});

test('an invalid-filter error never echoes the input', () => {
    for (const value of [input({denylist: [`${SECRET_DOMAIN}/path`]}), input({allowlist: [`*.${SECRET_DOMAIN}`]}), {[SECRET_DOMAIN]: 1}, input({categories: [SECRET_DOMAIN]})]) {
        try { parseDesired(value); assert.fail('accepted'); } catch (e) { assert.ok(!JSON.stringify(e, Object.getOwnPropertyNames(e)).includes('blocked-example')); }
    }
});

// Each row: [name, previous, next, loosening]. Pure and exhaustive over the seven rules plus their tightening mirror images.
const rows: [string, ContentFilterDesired | null, ContentFilterDesired, boolean][] = [
    ['no previous state is loosening (fail closed)', null, BASE, true],
    ['identical', BASE, BASE, false],
    ['category removed', BASE, with_({categories: ['porn']}), true],
    ['category added', BASE, with_({categories: ['gambling', 'porn', 'social']}), false],
    ['category swapped', BASE, with_({categories: ['gambling', 'social']}), true],
    ['service removed', BASE, with_({services: ['tiktok']}), true],
    ['service added', BASE, with_({services: ['tiktok', 'youtube', 'twitch']}), false],
    ['denylist entry removed', BASE, with_({denylist: ['a-bad.test']}), true],
    ['denylist entry added', BASE, with_({denylist: ['a-bad.test', 'b-bad.test', 'c-bad.test']}), false],
    ['allowlist entry added', BASE, with_({allowlist: ['ok.test', 'new.test']}), true],
    ['allowlist entry removed', BASE, with_({allowlist: []}), false],
    ['allowlist replaced', BASE, with_({allowlist: ['other.test']}), true],
    ['safeSearch off', BASE, with_({safeSearch: false}), true],
    ['safeSearch on', with_({safeSearch: false}), BASE, false],
    ['youtubeRestrictedMode off', BASE, with_({youtubeRestrictedMode: false}), true],
    ['youtubeRestrictedMode on', with_({youtubeRestrictedMode: false}), BASE, false],
    ['blockBypass off', BASE, with_({blockBypass: false}), true],
    ['blockBypass on', with_({blockBypass: false}), BASE, false],
    ['flag stays off', with_({safeSearch: false}), with_({safeSearch: false}), false],
    ['tighten one thing and loosen another is loosening', BASE, with_({categories: ['gambling', 'porn', 'social'], safeSearch: false}), true],
    ['everything off from empty is not loosening', with_({categories: [], services: [], safeSearch: false, youtubeRestrictedMode: false, blockBypass: false, denylist: [], allowlist: []}),
        with_({categories: [], services: [], safeSearch: false, youtubeRestrictedMode: false, blockBypass: false, denylist: [], allowlist: []}), false],
    ['empty to full is not loosening', with_({categories: [], services: [], safeSearch: false, youtubeRestrictedMode: false, blockBypass: false, denylist: [], allowlist: []}),
        with_({allowlist: []}), false],
];
for (const [name, previous, next, expected] of rows) test(`isLoosening: ${name}`, () => assert.equal(isLoosening(previous, next), expected));

function memory() {
    let clock = 1000;
    const db = new Store(':memory:'), filters = new ContentFilterStore(db, () => clock);
    return {db, filters, tick: (n = 1) => { clock += n; }, close: () => db.close()};
}

test('store: put creates revision 1 pending, each put bumps the revision and resets to pending', () => {
    const m = memory();
    try {
        assert.equal(m.filters.get('pilot'), undefined);
        const first = m.filters.put('pilot', DESIRED, 'operator');
        assert.deepEqual({revision: first.revision, state: first.state, stateAt: first.stateAt}, {revision: 1, state: 'pending', stateAt: 1000});
        assert.equal(first.desiredSha256, desiredSha256(DESIRED));
        assert.deepEqual(first.desired, DESIRED);
        m.tick();
        assert.ok(m.filters.recordOutcome('pilot', 1, {state: 'applied', readBackSha256: first.desiredSha256}));
        assert.equal(m.filters.get('pilot')!.state, 'applied');
        m.tick();
        const second = m.filters.put('pilot', parseDesired(input({safeSearch: false})), 'parent');
        assert.deepEqual({revision: second.revision, state: second.state}, {revision: 2, state: 'pending'});
        const row = m.db.get<Record<string, unknown>>('SELECT * FROM content_filter_desired')!;
        assert.equal(row.updated_by, 'parent'); assert.equal(row.updated_at, 1002);
        assert.equal(row.applied_sha256, first.desiredSha256, 'the last confirmed hash is kept, but the state is no longer applied');
        assert.equal(m.db.get<{n: number}>('SELECT count(*) n FROM content_filter_desired')!.n, 1);
    } finally { m.close(); }
});

test('store: state transitions record state_at; stale revisions are ignored', () => {
    const m = memory();
    try {
        const r1 = m.filters.put('pilot', DESIRED, 'operator');
        for (const state of ['not_confirmed', 'drift', 'pending'] as const) {
            m.tick(); assert.ok(m.filters.recordOutcome('pilot', 1, {state}));
            assert.deepEqual({state: m.filters.get('pilot')!.state, at: m.filters.get('pilot')!.stateAt}, {state, at: m.filters.get('pilot')!.stateAt});
        }
        const lastAt = m.filters.get('pilot')!.stateAt;
        m.tick(); const r2 = m.filters.put('pilot', parseDesired(input({safeSearch: false})), 'operator');
        assert.equal(m.filters.recordOutcome('pilot', r1.revision, {state: 'drift'}), false, 'a late outcome of revision 1 cannot touch revision 2');
        assert.equal(m.filters.recordOutcome('pilot', 9, {state: 'drift'}), false);
        assert.equal(m.filters.get('pilot')!.state, 'pending');
        assert.ok(m.filters.get('pilot')!.stateAt > lastAt);
        assert.equal(m.filters.recordOutcome('ghost', 1, {state: 'drift'}), false);
        assert.equal(r2.revision, 2);
    } finally { m.close(); }
});

test('store: applied is refused unless the read-back hash equals the desired hash, in code and in the database', () => {
    const m = memory();
    try {
        m.filters.put('pilot', DESIRED, 'operator');
        assert.throws(() => m.filters.recordOutcome('pilot', 1, {state: 'applied', readBackSha256: 'f'.repeat(64)}), /applied_requires_matching_read_back/);
        assert.equal(m.filters.get('pilot')!.state, 'pending');
        assert.throws(() => m.db.run("UPDATE content_filter_desired SET state='applied' WHERE person_id='pilot'"), /CHECK/);
        assert.throws(() => m.db.run("UPDATE content_filter_desired SET state='applied',applied_sha256=? WHERE person_id='pilot'", 'f'.repeat(64)), /CHECK/);
        assert.throws(() => m.db.run("UPDATE content_filter_desired SET state='maybe' WHERE person_id='pilot'"), /CHECK/);
    } finally { m.close(); }
});

test('store: put inside the caller transaction joins it and rolls back with it', () => {
    const m = memory();
    try {
        assert.throws(() => m.db.transaction(() => { m.filters.put('pilot', DESIRED, 'operator'); throw new Error('rollback'); }), /rollback/);
        assert.equal(m.filters.get('pilot'), undefined);
        m.db.transaction(() => { m.filters.put('pilot', DESIRED, 'operator'); });
        assert.equal(m.filters.get('pilot')!.revision, 1);
    } finally { m.close(); }
});
