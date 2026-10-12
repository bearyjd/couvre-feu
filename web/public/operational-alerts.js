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
      !nullableEpoch(value.recoveredAt) || value.recoveredAt !== null && value.recoveredAt < value.firstNoticedAt) return null;
  return {personId: value.personId, ...condition, occurrence: value.occurrence, firstNoticedAt: value.firstNoticedAt, lastNoticedAt: value.lastNoticedAt,
    sourceObservedAt: value.sourceObservedAt, serviceReceivedAt: value.serviceReceivedAt, recoveredAt: value.recoveredAt};
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
      recoveredAt: previous.recoveredAt ?? record.recoveredAt});
  }
  const result = [...episodes.values()].sort((a, b) => b.firstNoticedAt - a.firstNoticedAt || baseKey(a).localeCompare(baseKey(b)) || b.occurrence - a.occurrence).slice(0, MAX_RECORDS);
  while (new TextEncoder().encode(JSON.stringify(result)).byteLength > MAX_BYTES - 4096) result.pop();
  return result;
}

/** State is bound to an authenticated scope and expiry, never CSRF or cookie values. */
export function createAlertJournal(storage = globalThis.localStorage) {
  let scope = null, permitted = new Set(), expiresAt = null, records = [], hideRecovery = false, lastClock = 0;
  const dropMemory = () => { scope = null; records = []; permitted = new Set(); expiresAt = null; hideRecovery = false; lastClock = 0; };
  const read = (binding = false) => {
    try {
      const active = storage.getItem(ACTIVE);
      if (active !== scope) { if (!binding) dropMemory(); return; }
      const raw = storage.getItem(ALERT_PREFIX + scope);
      if (!raw || new TextEncoder().encode(raw).byteLength > MAX_BYTES) return;
      const value = JSON.parse(raw);
      if (value.scope === scope && value.expiresAt === expiresAt && Array.isArray(value.records) && value.records.length <= MAX_RECORDS) {
        records = [...records, ...value.records]; hideRecovery = value.hideRecovery === true;
      }
    } catch { /* Denied or malformed storage leaves the bounded in-memory journal usable. */ }
  };
  const write = now => {
    if (!scope) return;
    records = bounded(records, now, permitted);
    let payload = JSON.stringify({scope, expiresAt, hideRecovery, records});
    while (records.length && new TextEncoder().encode(payload).byteLength > MAX_BYTES) { records.pop(); payload = JSON.stringify({scope, expiresAt, hideRecovery, records}); }
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
        scope = next; expiresAt = session.expiresAt; permitted = new Set(session.actor.personIds); read(true);
      }
      lastClock = Math.max(lastClock, now); write(lastClock); return true;
    },
    ingest(status, now, canRecover = false) {
      if (!scope) return;
      if (now < lastClock) { read(); write(lastClock); return; }
      lastClock = now;
      if (expiresAt <= now) { clear(); return; }
      read(); records = bounded(records, now, permitted);
      for (const person of status.people ?? []) {
        if (!permitted.has(person.id)) continue;
        const evidence = cacheAlertEvidence(person.operationalAlerts, status.source);
        if (!evidence) continue;
        const {sourceObservedAt: observed, serviceReceivedAt: received} = evidence;
        const clocks = epoch(observed) && observed <= now && (evidence.source === 'synthetic-policy' ? received === null : epoch(received) && received <= now);
        const deadline = clocks ? Math.min(observed, received ?? observed) + 31 : null;
        const fresh = clocks && evidence.freshUntil === deadline && evidence.freshness === 'fresh' && now < deadline && evidence.evaluatedAt <= now && evidence.evaluatedAt >= observed;
        const conditions = [...evidence.conditions];
        if (deadline !== null && now >= deadline && !conditions.some(value => value.code.startsWith('observation-'))) conditions.push({code: 'observation-stale'});
        for (const condition of conditions) {
          const key = baseKey({...condition, personId: person.id});
          const open = records.find(record => record.recoveredAt === null && baseKey(record) === key);
          if (open) {
            open.lastNoticedAt = Math.max(open.lastNoticedAt, now);
            open.sourceObservedAt = Math.max(open.sourceObservedAt ?? 0, observed ?? 0) || null;
            open.serviceReceivedAt = Math.max(open.serviceReceivedAt ?? 0, received ?? 0) || null;
          } else {
            const occurrence = Math.max(0, ...records.filter(record => baseKey(record) === key).map(record => record.occurrence)) + 1;
            records.push({personId: person.id, ...condition, occurrence, firstNoticedAt: now, lastNoticedAt: now, sourceObservedAt: observed, serviceReceivedAt: received, recoveredAt: null});
          }
        }
        if (!canRecover || !fresh || !evidence.healthy) continue;
        for (const record of records) {
          if (record.personId !== person.id || record.recoveredAt !== null || conditions.some(condition => baseKey({...condition, personId: person.id}) === baseKey(record)) ||
              evidence.evaluatedAt < record.lastNoticedAt || observed <= (record.sourceObservedAt ?? 0) ||
              evidence.source === 'router-policy' && received <= (record.serviceReceivedAt ?? 0)) continue;
          if (record.code === 'control-verification-unavailable' && evidence.confirmedOperationId !== record.operationId) continue;
          if (record.code === 'pause-expiry-unverified' && (!epoch(evidence.expiryVerifiedThrough) || evidence.expiryVerifiedThrough > observed || evidence.expiryVerifiedThrough < record.pauseUntil)) continue;
          record.recoveredAt = now;
        }
      }
      write(now);
    },
    view(now) {
      if (!scope) return {records: [], hideRecovery: false};
      lastClock = Math.max(lastClock, now); now = lastClock;
      if (expiresAt <= now) { clear(); return {records: [], hideRecovery: false}; }
      read(); write(now);
      return {records: records.filter(record => !hideRecovery || record.recoveredAt === null).map(record => ({...record})), hideRecovery};
    },
    setHideRecovery(value, now) { if (!scope) return; read(); if (!scope) return; hideRecovery = value === true; lastClock = Math.max(lastClock, now); write(lastClock); },
  };
}
