import test from 'node:test';
import assert from 'node:assert/strict';
const modulePath = '../../web/public/operational-alerts.js';
const {createAlertJournal, cacheAlertEvidence, ALERT_PREFIX} = await import(modulePath);

class MemoryStorage {
    values = new Map<string, string>();
    get length() { return this.values.size; }
    key(index: number) { return [...this.values.keys()][index] ?? null; }
    getItem(key: string) { return this.values.get(key) ?? null; }
    setItem(key: string, value: string) { this.values.set(key, value); }
    removeItem(key: string) { this.values.delete(key); }
}
const t = 1791691200, id = '00000000-0000-4000-8000-000000000001', otherId = '00000000-0000-4000-8000-000000000002';
const actor = {id: 'parent', permissionVersion: '1', role: 'parent', personIds: ['pilot']};
const session = {source: 'real-router-integration', integrationScope: 'a'.repeat(64), actor, expiresAt: t + 3600};
function evidence(at = t, change: Record<string, unknown> = {}) {
    return {source: 'router-policy', evaluatedAt: at, sourceObservedAt: at, serviceReceivedAt: at, freshUntil: at + 31, freshness: 'fresh',
        healthy: true, confirmedOperationId: null, expiryVerifiedThrough: at, conditions: [], ...change};
}
function status(value = evidence(), person = 'pilot') { return {...session, people: [{id: person, operationalAlerts: value}]}; }
function fixture() {
    const storage = new MemoryStorage(), journal = createAlertJournal(storage);
    journal.bind(session, status(), t); return {storage, journal};
}
const unavailable = (at: number) => evidence(at, {healthy: false, freshness: 'unknown', confirmedOperationId: null, expiryVerifiedThrough: null, conditions: [{code: 'observation-unavailable'}]});

test('repeated failure, witnessed recovery and recurrence produce one bounded episode each', () => {
    const {journal} = fixture();
    journal.ingest(status(unavailable(t)), t, true);
    journal.ingest(status(unavailable(t)), t + 1, true);
    assert.equal(journal.view(t + 1).records.length, 1); assert.equal(journal.view(t + 1).records[0].firstNoticedAt, t);
    journal.ingest(status(evidence(t)), t + 1, true); // Same witness cannot recover a changed condition.
    assert.equal(journal.view(t + 1).records[0].recoveredAt, null);
    journal.ingest(status(evidence(t + 2)), t + 2, false); // Cached/offline must never recover.
    assert.equal(journal.view(t + 2).records[0].recoveredAt, null);
    journal.ingest(status(evidence(t + 2)), t + 2, true);
    journal.ingest(status(evidence(t + 2)), t + 2, true);
    assert.equal(journal.view(t + 2).records.length, 1); assert.equal(journal.view(t + 2).records[0].recoveredAt, t + 2);
    journal.ingest(status(unavailable(t + 2)), t + 2, true); // Equal second has no ordering proof after recovery.
    assert.equal(journal.view(t + 2).records.length, 1);
    journal.ingest(status(unavailable(t + 3)), t + 3, true);
    assert.equal(journal.view(t + 3).records.length, 2); assert.equal(journal.view(t + 3).records.filter((record: any) => record.recoveredAt === null).length, 1);
});

test('stale tab and offline replay cannot reopen recovered episodes; later read errors with the same source can recur', () => {
    const {journal: first, storage} = fixture(), staleTab = createAlertJournal(storage);
    staleTab.bind(session, status(), t);
    first.ingest(status(unavailable(t)), t, true); staleTab.ingest(status(unavailable(t)), t, true);
    first.ingest(status(evidence(t + 2)), t + 2, true);
    staleTab.ingest(status(unavailable(t)), t + 3, false);
    assert.equal(staleTab.view(t + 3).records.length, 1);
    assert.equal(staleTab.view(t + 3).records[0].recoveredAt, t + 2);
    first.ingest(status(evidence(t + 2)), t + 3, false); // Healthy replay negative control.
    assert.equal(first.view(t + 3).records.length, 1);
    const reload = createAlertJournal(storage); reload.bind(session, status(), t + 4);
    reload.ingest(status(unavailable(t)), t + 4, false);
    reload.ingest(status(unavailable(t + 2)), t + 4, true); // Equal evaluation time is also ambiguous.
    assert.equal(reload.view(t + 4).records.length, 1);
    const laterReadError = unavailable(t + 5);
    Object.assign(laterReadError, {sourceObservedAt: t + 2, serviceReceivedAt: t + 2, freshUntil: t + 33});
    reload.ingest(status(laterReadError), t + 5, true);
    assert.equal(reload.view(t + 5).records.length, 2);
    assert.equal(reload.view(t + 5).records.filter((record: any) => record.recoveredAt === null).length, 1);
    reload.ingest(status(evidence(t + 2, {evaluatedAt: t + 6})), t + 6, true);
    assert.equal(reload.view(t + 6).records.filter((record: any) => record.recoveredAt === null).length, 1);
    reload.ingest(status(evidence(t + 7)), t + 7, true);
    assert.equal(reload.view(t + 7).records.length, 2);
    assert.equal(reload.view(t + 7).records.filter((record: any) => record.recoveredAt === null).length, 0);
});

test('only exact fresh confirmation can recover a historical request, never latest-operation change', () => {
    const {journal} = fixture();
    const warning = evidence(t, {healthy: false, conditions: [{code: 'control-verification-unavailable', operationId: id}]});
    journal.ingest(status(warning), t, true);
    journal.ingest(status(evidence(t + 1, {confirmedOperationId: otherId})), t + 1, true);
    assert.equal(journal.view(t + 1).records[0].recoveredAt, null);
    journal.ingest(status(evidence(t + 2, {confirmedOperationId: id, sourceObservedAt: t + 3})), t + 2, true); // Future clock.
    journal.ingest(status(evidence(t + 2, {confirmedOperationId: id, sourceObservedAt: null})), t + 2, true);
    journal.ingest(status(evidence(t - 10, {confirmedOperationId: id})), t + 2, true); // Old read or backwards evaluation clock.
    journal.ingest(status(evidence(t + 3, {confirmedOperationId: id, freshness: 'unknown', healthy: false})), t + 3, true);
    assert.equal(journal.view(t + 3).records[0].recoveredAt, null);
    journal.ingest(status(evidence(t + 4, {confirmedOperationId: id})), t + 4, true);
    assert.equal(journal.view(t + 4).records[0].recoveredAt, t + 4);
});

test('freshness expires exactly at 31 seconds and expiry needs a verified post-deadline router clock', () => {
    const {journal} = fixture();
    journal.ingest(status(evidence(t)), t + 30, false); assert.equal(journal.view(t + 30).records.length, 0);
    journal.ingest(status(evidence(t)), t + 31, false); assert.equal(journal.view(t + 31).records[0].code, 'observation-stale');
    journal.ingest(status(evidence(t)), t + 30, true); // Clock rewind cannot use same witness to recover.
    assert.equal(journal.view(t + 31).records[0].recoveredAt, null);
    journal.ingest(status(evidence(t + 32)), t + 32, true);
    assert.equal(journal.view(t + 32).records[0].recoveredAt, t + 32);
    journal.ingest(status(evidence(t)), t + 63, false); // Old tab expiry is not a new failure.
    assert.equal(journal.view(t + 63).records.length, 1);
    journal.ingest(status(evidence(t + 32)), t + 63, false); // Latest witness really expires at its exclusive deadline.
    assert.equal(journal.view(t + 63).records.length, 2);
    assert.equal(journal.view(t + 63).records.filter((record: any) => record.recoveredAt === null).length, 1);
    const second = fixture().journal;
    second.ingest(status(evidence(t, {conditions: [{code: 'pause-expiry-unverified', pauseUntil: t + 1}]})), t + 1, true);
    second.ingest(status(evidence(t + 2, {expiryVerifiedThrough: t})), t + 2, true);
    assert.equal(second.view(t + 2).records[0].recoveredAt, null);
    second.ingest(status(evidence(t + 3)), t + 3, true); assert.equal(second.view(t + 3).records[0].recoveredAt, t + 3);
});

test('assignment, permissions, account, source, installation and session lifecycle isolate and clear journal/preferences', () => {
    for (const changed of [{actor: {...actor, permissionVersion: '2'}}, {actor: {...actor, id: 'other'}},
        {actor: {...actor, personIds: []}}, {integrationScope: 'b'.repeat(64)}, {source: 'synthetic-fake-router'}, {expiresAt: t + 4000}]) {
        const {journal, storage} = fixture();
        journal.ingest(status(unavailable(t)), t, true); journal.setHideRecovery(true, t);
        journal.ingest(status(unavailable(t), 'adult'), t, true);
        assert.equal(journal.view(t).records.length, 1);
        const next = {...session, ...changed}; assert.equal(journal.bind(next, {...status(), ...changed}, t), true);
        assert.deepEqual(journal.view(t), {records: [], hideRecovery: false});
        assert.equal([...storage.values.keys()].filter(key => key.startsWith(ALERT_PREFIX)).length, 1);
        journal.clear(); assert.equal(storage.length, 0);
    }
    assert.equal(cacheAlertEvidence({...unavailable(t), mac: 'PRIVATE', rawStderr: 'PRIVATE', domain: 'PRIVATE'}, session.source).mac, undefined);
    assert.equal(cacheAlertEvidence(unavailable(t), 'synthetic-fake-router'), undefined);
    assert.equal(cacheAlertEvidence({...unavailable(t), conditions: [{code: 'activity-observed', raw: 'PRIVATE'}]}, session.source), undefined);
});

test('shared storage and reload reconcile the same episode, with scoped recovery preference', () => {
    const {journal: first, storage} = fixture(), second = createAlertJournal(storage);
    second.bind(session, status(), t);
    first.ingest(status(unavailable(t)), t, true); second.ingest(status(unavailable(t)), t + 1, true);
    first.ingest(status(evidence(t + 2)), t + 2, true); second.ingest(status(evidence(t + 2)), t + 2, true);
    assert.equal(second.view(t + 2).records.length, 1); assert.equal(second.view(t + 2).records[0].firstNoticedAt, t);
    const reload = createAlertJournal(storage); reload.bind(session, status(), t + 2);
    assert.equal(reload.view(t + 2).records[0].recoveredAt, t + 2);
    reload.setHideRecovery(true, t + 2); assert.equal(first.view(t + 2).records.length, 0);
    second.ingest(status(unavailable(t + 3)), t + 3, true);
    assert.equal(first.view(t + 3).records.length, 1); assert.equal(first.view(t + 3).records[0].recoveredAt, null);
    storage.removeItem('cf-alerts-active:v1'); // A delayed storage event must not resurrect cleared data.
    assert.deepEqual(first.view(t + 3), {records: [], hideRecovery: false});
    assert.equal(storage.getItem('cf-alerts-active:v1'), null);
    second.storageChanged('cf-alerts-active:v1', null); second.ingest(status(unavailable(t + 4)), t + 4, true);
    assert.deepEqual(second.view(t + 4), {records: [], hideRecovery: false});
    assert.equal(storage.getItem('cf-alerts-active:v1'), null);
});

test('journal bounds 50 records, 64 KiB, 24 hours and session expiry while denied/malformed storage is safe', () => {
    const {journal, storage} = fixture();
    for (let index = 0; index < 60; index++) {
        const operationId = '00000000-0000-4000-8000-' + String(index).padStart(12, '0');
        journal.ingest(status(evidence(t + index, {conditions: [{code: 'control-verification-unavailable', operationId}]})), t + index, false);
    }
    assert.equal(journal.view(t + 60).records.length, 50);
    for (const [key, value] of storage.values) if (key.startsWith(ALERT_PREFIX)) assert.ok(Buffer.byteLength(value) <= 65536);
    const longSession = {...session, expiresAt: t + 200000}; journal.bind(longSession, status(), t);
    journal.ingest(status(unavailable(t)), t, true); assert.equal(journal.view(t + 86400).records.length, 0);
    journal.ingest(status(unavailable(t + 90000)), t + 90000, false);
    assert.deepEqual(journal.view(longSession.expiresAt), {records: [], hideRecovery: false}); assert.equal(storage.length, 0);
    const denied = new Proxy({}, {get() { throw new Error('Storage denied'); }}), memory = createAlertJournal(denied);
    assert.equal(memory.bind(session, status(), t), true); memory.ingest(status(unavailable(t)), t, true); assert.equal(memory.view(t).records.length, 1); memory.clear();
    const malformed = fixture();
    for (const key of malformed.storage.values.keys()) if (key.startsWith(ALERT_PREFIX)) malformed.storage.setItem(key, '{broken');
    const fresh = createAlertJournal(malformed.storage); fresh.bind(session, status(), t); assert.deepEqual(fresh.view(t).records, []);
});
