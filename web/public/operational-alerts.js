import { actorScope } from './status-cache.js';

export const ALERT_PREFIX = 'cf-alerts:v1:';
export const ALERT_ACTIVE = 'cf-alerts-active:v1';
const ACTIVE = ALERT_ACTIVE;
const DAY = 86400, MAX_RECORDS = 50, MAX_BYTES = 65536;
const CODES = ['observation-unavailable', 'observation-stale', 'control-verification-unavailable', 'observed-drift', 'pause-expiry-unverified'];
const epoch = value => Number.isSafeInteger(value) && value >= 1577836800;
const operationId = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const personId = value => typeof value === 'string' && /^[a-z][a-z0-9_]{0,31}$/.test(value);
const nullableEpoch = value => value === null || epoch(value);
const baseKey = record => JSON.stringify([record.personId, record.code, record.operationId ?? null, record.pauseUntil ?? null]);

export function alertText(code) {
  return ({'observation-unavailable': 'Unable to verify router status.', 'observation-stale': 'Router status observation is stale.',
    'control-verification-unavailable': 'Unable to verify this control request; it may be historical.',
    'observed-drift': 'The fresh router observation reports policy drift.',
    'pause-expiry-unverified': 'Pause expiry time reached; router expiry is not yet verified. A schedule may still block access.'})[code] ?? '';
}

function signal(value) {
  if (!value || !CODES.includes(value.code)) return null;
  if (value.code === 'control-verification-unavailable') return operationId(value.operationId) ? {code: value.code, operationId: value.operationId} : null;
  if (value.code === 'pause-expiry-unverified') return epoch(value.pauseUntil) ? {code: value.code, pauseUntil: value.pauseUntil} : null;
  return {code: value.code};
}

/** Allowlist selection is shared with status caching; raw payloads never enter this journal. */
export function cacheAlertEvidence(value, source) {
  const expected = source === 'real-router-integration' ? 'router-policy' : source === 'synthetic-fake-router' ? 'synthetic-policy' : null;
  if (!value || !expected || value.source !== expected || !epoch(value.evaluatedAt) || !nullableEpoch(value.sourceObservedAt) ||
      !nullableEpoch(value.serviceReceivedAt) || !nullableEpoch(value.freshUntil) || !['fresh', 'stale', 'unknown'].includes(value.freshness) ||
      typeof value.healthy !== 'boolean' || !(value.confirmedOperationId === null || operationId(value.confirmedOperationId)) ||
      !nullableEpoch(value.expiryVerifiedThrough) || !Array.isArray(value.conditions) || value.conditions.length > 5) return undefined;
  const conditions = value.conditions.map(signal);
  if (conditions.some(condition => !condition)) return undefined;
  return {source: expected, evaluatedAt: value.evaluatedAt, sourceObservedAt: value.sourceObservedAt, serviceReceivedAt: value.serviceReceivedAt,
    freshUntil: value.freshUntil, freshness: value.freshness, healthy: value.healthy,
    confirmedOperationId: value.confirmedOperationId, expiryVerifiedThrough: value.expiryVerifiedThrough, conditions};
}

function scoped(session, status) {
  if (!session || !status || !['synthetic-fake-router', 'real-router-integration'].includes(status.source) || session.source !== status.source || (session.integrationScope ?? null) !== (status.integrationScope ?? null) ||
      !epoch(session.expiresAt) || typeof session.actor?.permissionVersion !== 'string') return null;
  const scope = JSON.stringify([status.source, status.integrationScope ?? null, actorScope(session.actor), session.expiresAt]);
  return scope.length <= 2048 ? scope : null;
}

function sanitizeRecord(value) {
  const condition = signal(value);
  if (!condition || !personId(value.personId) || !epoch(value.firstNoticedAt) || !epoch(value.lastNoticedAt) ||
      !Number.isSafeInteger(value.occurrence) || value.occurrence < 1 || value.occurrence > 2147483647 ||
      value.lastNoticedAt < value.firstNoticedAt || !nullableEpoch(value.sourceObservedAt) || !nullableEpoch(value.serviceReceivedAt) ||
      !epoch(value.failureEvaluatedAt) || !nullableEpoch(value.recoveryEvaluatedAt) || !nullableEpoch(value.witnessObservedAt) || !nullableEpoch(value.witnessReceivedAt) ||
      !nullableEpoch(value.recoveredAt) || value.recoveredAt !== null && value.recoveredAt < value.firstNoticedAt) return null;
  const clockCeiling = Math.max(value.lastNoticedAt, value.recoveredAt ?? 0);
  return {personId: value.personId, ...condition, occurrence: value.occurrence, firstNoticedAt: value.firstNoticedAt, lastNoticedAt: value.lastNoticedAt,
    sourceObservedAt: value.sourceObservedAt, serviceReceivedAt: value.serviceReceivedAt, failureEvaluatedAt: value.failureEvaluatedAt,
    recoveryEvaluatedAt: value.recoveryEvaluatedAt, witnessObservedAt: value.witnessObservedAt <= clockCeiling ? value.witnessObservedAt : null,
    witnessReceivedAt: value.witnessReceivedAt <= clockCeiling ? value.witnessReceivedAt : null, recoveredAt: value.recoveredAt};
}

function bounded(records, now, permitted) {
  const selected = records.map(sanitizeRecord).filter(record => record && permitted.has(record.personId) &&
    record.firstNoticedAt <= now && record.firstNoticedAt > now - DAY && (record.recoveredAt === null || record.recoveredAt <= now));
  const episodes = new Map();
  for (const record of selected) {
    const key = baseKey(record) + ':' + record.occurrence;
    const previous = episodes.get(key);
    if (!previous) episodes.set(key, record);
    else episodes.set(key, {...previous, firstNoticedAt: Math.min(previous.firstNoticedAt, record.firstNoticedAt), lastNoticedAt: Math.max(previous.lastNoticedAt, record.lastNoticedAt),
      sourceObservedAt: Math.max(previous.sourceObservedAt ?? 0, record.sourceObservedAt ?? 0) || null,
      serviceReceivedAt: Math.max(previous.serviceReceivedAt ?? 0, record.serviceReceivedAt ?? 0) || null,
      failureEvaluatedAt: Math.max(previous.failureEvaluatedAt, record.failureEvaluatedAt),
      recoveryEvaluatedAt: Math.max(previous.recoveryEvaluatedAt ?? 0, record.recoveryEvaluatedAt ?? 0) || null,
      witnessObservedAt: Math.max(previous.witnessObservedAt ?? 0, record.witnessObservedAt ?? 0) || null,
      witnessReceivedAt: Math.max(previous.witnessReceivedAt ?? 0, record.witnessReceivedAt ?? 0) || null,
      recoveredAt: previous.recoveredAt ?? record.recoveredAt});
  }
  const result = [...episodes.values()].sort((a, b) => b.firstNoticedAt - a.firstNoticedAt || baseKey(a).localeCompare(baseKey(b)) || b.occurrence - a.occurrence).slice(0, MAX_RECORDS);
  while (new TextEncoder().encode(JSON.stringify(result)).byteLength > MAX_BYTES - 4096) result.pop();
  return result;
}

/** Clock barriers only: never used to establish current health or recover an episode. */
function boundedWitnesses(values, now, permitted, source) {
  const floors = new Map();
  for (const value of values) {
    if (!value || !personId(value.personId) || !permitted.has(value.personId) || !epoch(value.sourceObservedAt) || !epoch(value.evaluatedAt) ||
        value.evaluatedAt > now || value.evaluatedAt <= now - DAY || value.sourceObservedAt > value.evaluatedAt ||
        (source === 'real-router-integration' ? !epoch(value.serviceReceivedAt) || value.serviceReceivedAt > value.evaluatedAt : value.serviceReceivedAt !== null) ||
        !nullableEpoch(value.healthyEvaluatedAt) || value.healthyEvaluatedAt !== null && value.healthyEvaluatedAt > value.evaluatedAt) continue;
    const previous = floors.get(value.personId);
    floors.set(value.personId, {personId: value.personId, sourceObservedAt: Math.max(previous?.sourceObservedAt ?? 0, value.sourceObservedAt),
      serviceReceivedAt: Math.max(previous?.serviceReceivedAt ?? 0, value.serviceReceivedAt ?? 0) || null,
      evaluatedAt: Math.max(previous?.evaluatedAt ?? 0, value.evaluatedAt),
      healthyEvaluatedAt: Math.max(previous?.healthyEvaluatedAt ?? 0, value.healthyEvaluatedAt !== null && value.healthyEvaluatedAt > now - DAY ? value.healthyEvaluatedAt : 0) || null});
  }
  return [...floors.values()].sort((a, b) => b.evaluatedAt - a.evaluatedAt || a.personId.localeCompare(b.personId)).slice(0, MAX_RECORDS);
}

/** State is bound to an authenticated scope and expiry, never CSRF or cookie values. */
export function createAlertJournal(storage = globalThis.localStorage) {
  let scope = null, source = null, installation = null, permitted = new Set(), expiresAt = null, records = [], witnesses = [], hideRecovery = false, lastClock = 0;
  const dropMemory = () => { scope = null; source = null; installation = null; records = []; witnesses = []; permitted = new Set(); expiresAt = null; hideRecovery = false; lastClock = 0; };
  const read = (binding = false) => {
    try {
      const active = storage.getItem(ACTIVE);
      if (active !== scope) { if (!binding) dropMemory(); return; }
      const raw = storage.getItem(ALERT_PREFIX + scope);
      if (!raw || new TextEncoder().encode(raw).byteLength > MAX_BYTES) return;
      const value = JSON.parse(raw);
      if (value.scope === scope && value.expiresAt === expiresAt && Array.isArray(value.records) && value.records.length <= MAX_RECORDS) {
        records = [...records, ...value.records]; hideRecovery = value.hideRecovery === true;
        if (Array.isArray(value.witnesses) && value.witnesses.length <= MAX_RECORDS) witnesses = [...witnesses, ...value.witnesses];
      }
    } catch { /* Denied or malformed storage leaves the bounded in-memory journal usable. */ }
  };
  const write = now => {
    if (!scope) return;
    records = bounded(records, now, permitted);
    witnesses = boundedWitnesses(witnesses, now, permitted, source);
    let payload = JSON.stringify({scope, expiresAt, hideRecovery, records, witnesses});
    while (records.length && new TextEncoder().encode(payload).byteLength > MAX_BYTES) { records.pop(); payload = JSON.stringify({scope, expiresAt, hideRecovery, records, witnesses}); }
    try { storage.setItem(ALERT_PREFIX + scope, payload); storage.setItem(ACTIVE, scope); } catch { /* Memory only when storage is unavailable. */ }
  };
  const clear = () => {
    dropMemory();
    try {
      for (let index = storage.length - 1; index >= 0; index--) { const key = storage.key(index); if (key?.startsWith(ALERT_PREFIX)) storage.removeItem(key); }
      storage.removeItem(ACTIVE);
    } catch { /* Clearing memory and DOM remains mandatory even when storage is denied. */ }
  };
  return {
    clear,
    isBound() { return scope !== null; },
    latestWitness(person) { const witness = witnesses.find(value => value.personId === person); return witness ? {...witness} : null; },
    storageChanged(key, value) {
      if (scope && (key === ACTIVE && value !== scope || key === ALERT_PREFIX + scope && value === null)) {
        dropMemory();
      }
    },
    bind(session, status, now) {
      const next = scoped(session, status);
      if (!next || session.expiresAt <= now) { clear(); return false; }
      if (scope !== next) {
        if (scope !== null) clear();
        try { if (storage.getItem(ACTIVE) !== next) clear(); } catch { /* Memory only. */ }
        scope = next; source = status.source; installation = status.integrationScope ?? null; expiresAt = session.expiresAt; permitted = new Set(session.actor.personIds); read(true);
      }
      lastClock = Math.max(lastClock, now); write(lastClock); return true;
    },
    ingest(status, now, canRecover = false) {
      if (!scope || status.source !== source || (status.integrationScope ?? null) !== installation) return;
      if (now < lastClock) { read(); write(lastClock); return; }
      lastClock = now;
      if (expiresAt <= now) { clear(); return; }
      read(); records = bounded(records, now, permitted);
      witnesses = boundedWitnesses(witnesses, now, permitted, source);
      for (const person of status.people ?? []) {
        if (!permitted.has(person.id)) continue;
        const evidence = cacheAlertEvidence(person.operationalAlerts, status.source);
        if (!evidence) continue;
        const {sourceObservedAt: observed, serviceReceivedAt: received} = evidence;
        const validObserved = epoch(observed) && observed <= now && observed <= evidence.evaluatedAt ? observed : 0;
        const validReceived = epoch(received) && received <= now && received <= evidence.evaluatedAt ? received : 0;
        const clocks = epoch(observed) && observed <= now && (evidence.source === 'synthetic-policy' ? received === null : epoch(received) && received <= now);
        const deadline = clocks ? Math.min(observed, received ?? observed) + 31 : null;
        const fresh = clocks && evidence.freshUntil === deadline && evidence.freshness === 'fresh' && now < deadline && evidence.evaluatedAt <= now && evidence.evaluatedAt >= observed && evidence.evaluatedAt >= (received ?? 0);
        const latest = witnesses.find(value => value.personId === person.id);
        const acceptedLive = canRecover && fresh && (!latest || observed >= latest.sourceObservedAt &&
          (evidence.source === 'synthetic-policy' || received >= latest.serviceReceivedAt) && evidence.evaluatedAt >= latest.evaluatedAt);
        if (acceptedLive) {
          witnesses.push({personId: person.id, sourceObservedAt: observed, serviceReceivedAt: received, evaluatedAt: evidence.evaluatedAt,
            healthyEvaluatedAt: evidence.healthy ? evidence.evaluatedAt : null});
          witnesses = boundedWitnesses(witnesses, now, permitted, source);
        }
        const floor = witnesses.find(value => value.personId === person.id);
        const conditions = evidence.conditions.filter(condition => condition.code !== 'observed-drift' || fresh);
        const localStale = deadline !== null && now >= deadline && !conditions.some(value => value.code.startsWith('observation-'));
        if (localStale) conditions.push({code: 'observation-stale'});
        for (const condition of conditions) {
          const key = baseKey({...condition, personId: person.id});
          const related = records.filter(record => baseKey(record) === key);
          const personRecords = records.filter(record => record.personId === person.id);
          const recoveryEvaluation = Math.max(0, ...personRecords.map(record => record.recoveryEvaluatedAt ?? 0),
            condition.code.startsWith('observation-') || condition.code === 'observed-drift' ? floor?.healthyEvaluatedAt ?? 0 : 0);
          const witnessObservedAt = Math.max(validObserved, floor?.sourceObservedAt ?? 0, ...personRecords.map(record => record.witnessObservedAt ?? 0)) || null;
          const witnessReceivedAt = Math.max(validReceived, floor?.serviceReceivedAt ?? 0, ...personRecords.map(record => record.witnessReceivedAt ?? 0)) || null;
          const failureEvaluation = localStale && condition.code === 'observation-stale' ? now : evidence.evaluatedAt;
          // Cached/ticking failure copy cannot start another episode after a newer recovery.
          // Expiry of the latest witness can; expiry of an older tab's witness cannot.
          if (failureEvaluation > now || failureEvaluation <= recoveryEvaluation ||
              (condition.code === 'observation-stale' || condition.code === 'observed-drift') &&
              (observed < (witnessObservedAt ?? 0) || evidence.source === 'router-policy' && received < (witnessReceivedAt ?? 0))) continue;
          const open = records.find(record => record.recoveredAt === null && baseKey(record) === key);
          if (open) {
            open.lastNoticedAt = Math.max(open.lastNoticedAt, now);
            open.failureEvaluatedAt = Math.max(open.failureEvaluatedAt, failureEvaluation);
            open.witnessObservedAt = witnessObservedAt; open.witnessReceivedAt = witnessReceivedAt;
            open.sourceObservedAt = Math.max(open.sourceObservedAt ?? 0, validObserved) || null;
            open.serviceReceivedAt = Math.max(open.serviceReceivedAt ?? 0, validReceived) || null;
          } else {
            const occurrence = Math.max(0, ...related.map(record => record.occurrence)) + 1;
            records.push({personId: person.id, ...condition, occurrence, firstNoticedAt: now, lastNoticedAt: now, sourceObservedAt: validObserved || null, serviceReceivedAt: validReceived || null,
              failureEvaluatedAt: failureEvaluation, recoveryEvaluatedAt: null, witnessObservedAt, witnessReceivedAt, recoveredAt: null});
          }
        }
        if (!acceptedLive || !evidence.healthy) continue;
        for (const record of records) {
          if (record.personId !== person.id || record.recoveredAt !== null || conditions.some(condition => baseKey({...condition, personId: person.id}) === baseKey(record)) ||
              evidence.evaluatedAt < record.failureEvaluatedAt || observed <= (record.witnessObservedAt ?? 0) ||
              evidence.source === 'router-policy' && received <= (record.witnessReceivedAt ?? 0)) continue;
          if (record.code === 'control-verification-unavailable' && evidence.confirmedOperationId !== record.operationId) continue;
          if (record.code === 'pause-expiry-unverified' && (!epoch(evidence.expiryVerifiedThrough) || evidence.expiryVerifiedThrough > observed || evidence.expiryVerifiedThrough < record.pauseUntil)) continue;
          record.recoveredAt = now;
          record.recoveryEvaluatedAt = evidence.evaluatedAt;
          record.witnessObservedAt = observed; record.witnessReceivedAt = received;
        }
      }
      write(now);
    },
    view(now, includeRecovery = false) {
      if (!scope) return {records: [], hideRecovery: false};
      lastClock = Math.max(lastClock, now); now = lastClock;
      if (expiresAt <= now) { clear(); return {records: [], hideRecovery: false}; }
      read(); write(now);
      return {records: records.filter(record => includeRecovery || !hideRecovery || record.recoveredAt === null).map(record => ({...record})), hideRecovery};
    },
    setHideRecovery(value, now) { if (!scope) return; read(); if (!scope) return; hideRecovery = value === true; lastClock = Math.max(lastClock, now); write(lastClock); },
  };
}
