import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db.ts';
import { ContentFilterReconciler, contentFilterApiKey } from '../src/content-filter-reconcile.ts';
import { ContentFilterStore, desiredSha256, parseDesired } from '../src/content-filter-state.ts';
import { NextDnsError } from '../src/nextdns-client.ts';
import type { NextDnsClient, Transport } from '../src/nextdns-client.ts';
import { API_KEY, DESIRED, PROFILE_ID, SECRET_DOMAIN, fakeWorld, input, json } from './fixtures/content-filter.ts';

function setup(wrap?: (next: Transport) => Transport, profiles: Record<string, string> = {pilot: PROFILE_ID}) {
    const w = fakeWorld(wrap), db = new Store(':memory:'), filters = new ContentFilterStore(db, () => 1000);
    const reconciler = new ContentFilterReconciler({client: w.client, profiles, store: filters});
    return {...w, db, filters, reconciler, put: (desired = DESIRED) => filters.put('pilot', desired, 'operator'), close: () => db.close()};
}
const active = (list: {id: string; active: boolean}[]) => list.filter(e => e.active).map(e => e.id).sort();

test('applied: writes all five parts to NextDNS, reads them back and only then says applied', async () => {
    const s = setup();
    try {
        const record = s.put(), done = await s.reconciler.reconcile('pilot');
        assert.equal(done!.state, 'applied');
        assert.equal(s.db.get<{applied_sha256: string}>('SELECT applied_sha256 FROM content_filter_desired')!.applied_sha256, record.desiredSha256);
        const p = s.profile.parentalControl;
        assert.deepEqual(active(p.categories), ['gambling', 'porn']); assert.deepEqual(active(p.services), ['tiktok']);
        assert.deepEqual([p.safeSearch, p.youtubeRestrictedMode, p.blockBypass], [true, true, true]);
        assert.deepEqual(active(s.profile.denylist), [SECRET_DOMAIN]); assert.deepEqual(active(s.profile.allowlist), ['allowed-example.test']);
        const methods = s.fake.requests.map(r => r.method), firstRead = methods.indexOf('GET');
        assert.ok(firstRead > 0 && methods.slice(0, firstRead).every(m => m !== 'GET') && methods.slice(firstRead).every(m => m === 'GET'), 'every write precedes the read-back');
        assert.ok(s.fake.requests.every(r => r.keyOk));
    } finally { s.close(); }
});

test('applied again on a changed desired state, and a stale entry NextDNS held before is removed', async () => {
    const s = setup();
    try {
        s.put(); await s.reconciler.reconcile('pilot');
        s.filters.put('pilot', parseDesired(input({denylist: [], categories: ['porn']})), 'operator');
        assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'applied');
        assert.deepEqual(active(s.profile.denylist), []); assert.deepEqual(active(s.profile.parentalControl.categories), ['porn']);
    } finally { s.close(); }
});

test('drift: NextDNS answers a different filter on read-back', async () => {
    const s = setup(next => async req => {
        const res = await next(req);
        if (req.method === 'PUT' && req.path.endsWith('/denylist')) s.profile.denylist.pop();
        return res;
    });
    try {
        s.put();
        const done = await s.reconciler.reconcile('pilot');
        assert.equal(done!.state, 'drift');
        assert.equal(s.db.get<{applied_sha256: string | null}>('SELECT applied_sha256 FROM content_filter_desired')!.applied_sha256, null, 'a drifting filter was never confirmed');
    } finally { s.close(); }
});

for (const [name, mutate] of [
    ['a flag flipped', () => { s_profile().parentalControl.safeSearch = false; }],
    ['an extra active allowlist entry', () => { s_profile().allowlist.push({id: 'extra.example', active: true}); }],
    ['a missing category', () => { s_profile().parentalControl.categories.pop(); }],
] as const) test(`drift: ${name}`, async () => {
    const s = setup(next => async req => { const res = await next(req); if (req.method === 'PUT' && req.path.endsWith('/allowlist')) mutate(); return res; });
    current = s.profile;
    try { s.put(); assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'drift'); } finally { s.close(); }
});
let current: ReturnType<typeof fakeWorld>['profile'];
const s_profile = () => current;

test('an inactive entry on read-back filters nothing and does not count as drift', async () => {
    const s = setup(next => async req => { const res = await next(req); if (req.method === 'PUT' && req.path.endsWith('/allowlist')) s.profile.denylist.push({id: 'dormant.example', active: false}); return res; });
    try { s.put(); assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'applied'); } finally { s.close(); }
});

test('not_confirmed: a read-back error never yields applied (and the writes did happen)', async () => {
    const s = setup(next => async req => req.method === 'GET' ? json(500, {errors: [{code: 'boom', detail: SECRET_DOMAIN}]}) : next(req));
    try {
        s.put();
        assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'not_confirmed');
        assert.equal(s.db.get<{applied_sha256: string | null}>('SELECT applied_sha256 FROM content_filter_desired')!.applied_sha256, null);
        assert.deepEqual(active(s.profile.denylist), [SECRET_DOMAIN]);
    } finally { s.close(); }
});

test('not_confirmed: an unparseable read-back (bad shape) is not applied', async () => {
    const s = setup(next => async req => req.method === 'GET' && req.path.endsWith('/parentalControl') ? json(200, {data: {unexpected: true}}) : next(req));
    try { s.put(); assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'not_confirmed'); } finally { s.close(); }
});

test('pending: a write that is rate limited forever stays pending and never reads back', async () => {
    let writes = 0;
    const s = setup(next => async req => { if (req.method === 'GET') return next(req); writes++; return json(429, {errors: [{code: 'rate'}]}); });
    try {
        s.put();
        assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'pending');
        assert.equal(s.reads(), 0, 'no read-back after a write that did not happen');
        assert.equal(writes, 4, 'the client retried 429 up to its attempt cap');
    } finally { s.close(); }
});

for (const [name, step] of [['a server error', json(503, {errors: [{code: 'x'}]})], ['a network failure', {throw: 'network'} as const], ['a timeout', {throw: 'timeout'} as const]] as const) {
    test(`pending: ${name} on the first write is retryable`, async () => {
        const s = setup();
        try { s.fake.enqueue(step); s.put(); assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'pending'); assert.equal(s.reads(), 0); } finally { s.close(); }
    });
}

test('not_confirmed: an unknown profile (404) and a rejected key (401)', async () => {
    const unknown = setup(undefined, {pilot: 'zzzz9'});
    try { unknown.put(); assert.equal((await unknown.reconciler.reconcile('pilot'))!.state, 'not_confirmed'); } finally { unknown.close(); }
    const wrong = setup();
    try { wrong.key.value = 'wrong-key-0123456789'; wrong.put(); assert.equal((await wrong.reconciler.reconcile('pilot'))!.state, 'not_confirmed'); assert.equal(wrong.fake.requests.every(r => !r.keyOk), true); } finally { wrong.close(); }
});

test('not_confirmed: a bad request (400) and a malformed write answer', async () => {
    const s = setup(next => async req => req.method === 'PUT' ? json(400, {errors: [{code: 'invalid', detail: SECRET_DOMAIN}]}) : next(req));
    try { s.put(); assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'not_confirmed'); } finally { s.close(); }
});

test('a person without a profile in the manifest map: no NextDNS call, record untouched', async () => {
    const s = setup(undefined, {other: PROFILE_ID});
    try {
        const record = s.put();
        assert.equal(s.reconciler.configured('pilot'), false); assert.equal(s.reconciler.configured('other'), true);
        assert.equal(s.reconciler.configured('constructor'), false, 'prototype names are not people');
        assert.deepEqual(await s.reconciler.reconcile('pilot'), record);
        assert.equal(s.fake.requests.length, 0);
        assert.equal(await s.reconciler.reconcile('ghost'), undefined);
    } finally { s.close(); }
});

test('a client that throws something unexpected degrades to not_confirmed; the reconcile never rejects', async () => {
    const w = fakeWorld(), db = new Store(':memory:'), filters = new ContentFilterStore(db, () => 1);
    const boom = new Proxy(w.client, {get: () => () => { throw new Error(`secret ${SECRET_DOMAIN}`); }}) as NextDnsClient;
    try {
        filters.put('pilot', DESIRED, 'operator');
        const done = await new ContentFilterReconciler({client: boom, profiles: {pilot: PROFILE_ID}, store: filters}).reconcile('pilot');
        assert.equal(done!.state, 'not_confirmed');
    } finally { db.close(); }
});

test('a store that throws never rejects the reconcile, and the next reconcile of that child still runs', async () => {
    const s = setup();
    try {
        s.put();
        let failures = 1;
        const realGet = s.filters.get.bind(s.filters);
        s.filters.get = (person: string) => { if (failures-- > 0) throw new Error(`database ${SECRET_DOMAIN}`); return realGet(person); };
        assert.equal(await s.reconciler.reconcile('pilot'), undefined);
        const [a, b] = await Promise.all([s.reconciler.reconcile('pilot'), s.reconciler.reconcile('pilot')]);
        assert.equal(a!.state, 'applied'); assert.equal(b!.state, 'applied');
    } finally { s.close(); }
});

test('a burst of reconciles is coalesced: one running, one waiting, later callers share the waiting run', async () => {
    let gate!: () => void, patches = 0;
    const open = new Promise<void>(resolve => { gate = resolve; });
    const s = setup(next => async req => { if (req.method === 'PATCH') { patches++; if (patches === 1) await open; } return next(req); });
    try {
        s.put();
        const first = s.reconciler.reconcile('pilot');
        await new Promise(r => setImmediate(r));
        s.filters.put('pilot', parseDesired(input({categories: ['porn']})), 'operator');
        const burst = Array.from({length: 5}, () => s.reconciler.reconcile('pilot'));
        assert.ok(burst.every(p => p === burst[0]), 'one shared waiting run');
        gate();
        const [, ...rest] = await Promise.all([first, ...burst]);
        assert.equal(patches, 2, 'two round trips for six callers');
        assert.ok(rest.every(r => r!.revision === 2 && r!.state === 'applied'), 'the waiting run reads the newest revision');
        assert.deepEqual(active(s.profile.parentalControl.categories), ['porn']);
        assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'applied', 'the slot is free again');
    } finally { s.close(); }
});

test('reconcileWithin gives up waiting at the budget and answers the stored pending state; the run carries on', async () => {
    let release!: () => void;
    const hold = new Promise<void>(resolve => { release = resolve; });
    const w = fakeWorld(next => async req => { await hold; return next(req); });
    const db = new Store(':memory:'), filters = new ContentFilterStore(db, () => 1);
    const reconciler = new ContentFilterReconciler({client: w.client, profiles: {pilot: PROFILE_ID}, store: filters, waitMs: 40});
    try {
        filters.put('pilot', DESIRED, 'operator');
        const started = Date.now(), answer = await reconciler.reconcileWithin('pilot');
        assert.ok(Date.now() - started < 1500); assert.equal(answer!.state, 'pending');
        release();
        assert.equal((await reconciler.reconcile('pilot'))!.state, 'applied', 'the abandoned run finished and the next one is not stuck');
    } finally { release(); db.close(); }
});

test('a newer revision wins: the outcome of a reconcile that raced a newer PUT is dropped', async () => {
    let raced = false;
    const s = setup(next => async req => {
        if (!raced && req.method === 'PATCH') { raced = true; s.filters.put('pilot', parseDesired(input({categories: ['porn']})), 'operator'); }
        return next(req);
    });
    try {
        s.put();
        const done = await s.reconciler.reconcile('pilot');
        assert.equal(done!.revision, 2); assert.equal(done!.state, 'pending', 'revision 2 has not been reconciled yet');
        assert.equal((await s.reconciler.reconcile('pilot'))!.state, 'applied');
        assert.deepEqual(active(s.profile.parentalControl.categories), ['porn']);
    } finally { s.close(); }
});

test('reconciles of one child never overlap', async () => {
    let inFlight = 0, peak = 0;
    const s = setup(next => async req => { peak = Math.max(peak, ++inFlight); try { await new Promise(r => setImmediate(r)); return await next(req); } finally { inFlight--; } });
    try {
        s.put();
        const all = await Promise.all([s.reconciler.reconcile('pilot'), s.reconciler.reconcile('pilot'), s.reconciler.reconcile('pilot')]);
        assert.equal(peak, 1); assert.ok(all.every(r => r!.state === 'applied'));
    } finally { s.close(); }
});

test('the inline budget bounds one reconcile: an unresponsive NextDNS leaves pending', async () => {
    const w = fakeWorld(() => req => new Promise((_, reject) => req.signal?.addEventListener('abort', () => reject(new Error('aborted')))));
    const db = new Store(':memory:'), filters = new ContentFilterStore(db, () => 1), keepAlive = setInterval(() => undefined, 10); // AbortSignal.timeout is unref'd
    try {
        filters.put('pilot', DESIRED, 'operator');
        const started = Date.now();
        const done = await new ContentFilterReconciler({client: w.client, profiles: {pilot: PROFILE_ID}, store: filters, budgetMs: 50}).reconcile('pilot');
        assert.ok(Date.now() - started < 2000); assert.equal(done!.state, 'pending');
    } finally { clearInterval(keepAlive); db.close(); }
});

test('the key is read at use time, on every request, and never at load', async () => {
    let reads = 0, key = API_KEY, failing = false;
    const getter = contentFilterApiKey('/nonexistent/key', () => { reads++; if (failing) throw new Error(`/nonexistent/key ${SECRET_DOMAIN}`); return key; });
    assert.equal(reads, 0, 'building the getter reads nothing');
    const s = setup();
    const { createNextDnsClient } = await import('../src/nextdns-client.ts');
    const client = createNextDnsClient({apiKey: getter, transport: s.fake.transport, sleep: async () => undefined, random: () => 0, baseDelayMs: 0});
    const reconciler = new ContentFilterReconciler({client, profiles: {pilot: PROFILE_ID}, store: s.filters});
    try {
        assert.equal(reads, 0, 'building the client and reconciler reads nothing');
        s.put();
        assert.equal((await reconciler.reconcile('pilot'))!.state, 'applied');
        const afterFirst = reads;
        assert.ok(afterFirst >= 6, 'once per request');
        key = 'rotated-key-0123456789'; s.filters.put('pilot', DESIRED, 'operator');
        assert.equal((await reconciler.reconcile('pilot'))!.state, 'not_confirmed', 'the rotated key is used immediately (the fake rejects it)');
        assert.ok(reads > afterFirst);
        key = API_KEY; failing = true; s.filters.put('pilot', DESIRED, 'operator');
        assert.equal((await reconciler.reconcile('pilot'))!.state, 'not_confirmed', 'an unreadable key file is not_confirmed');
        assert.throws(getter, (e: unknown) => e instanceof NextDnsError && e.code === 'unauthorized' && e.message === 'unauthorized');
    } finally { s.close(); }
});

test('the desired hash used for the comparison is of the canonical form', () => {
    assert.equal(desiredSha256(parseDesired(input({categories: ['porn', 'gambling']}))), desiredSha256(DESIRED));
});
