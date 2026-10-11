const PREFIX = 'cf-status:v1:';
const ACTIVE = 'cf-status-active:v1';
export const LOGOUT_REQUIRED = 'cf-logout-required:v1';
export const LOGOUT_EVENT = 'cf-logout-event:v1';
export const SCOPE_EVENT = 'cf-scope-event:v1';

export function actorScope(actor) {
  return JSON.stringify([actor.id, actor.permissionVersion, actor.role, [...actor.personIds].sort()]);
}
function statusScope(actor, status) {
  return status.source === 'synthetic-fake-router' && !status.integrationScope ? actorScope(actor) : JSON.stringify([status.source, status.integrationScope]) + ':' + actorScope(actor);
}
function expectedSource() {
  return { source: document.documentElement.dataset.source ?? 'synthetic-fake-router', integrationScope: document.documentElement.dataset.integrationScope ?? null };
}

export function clearStatusCache() {
  try {
    for (const key of Object.keys(localStorage)) if (key.startsWith(PREFIX)) localStorage.removeItem(key);
    localStorage.removeItem(ACTIVE);
  } catch { /* Storage can be unavailable; in-memory status is cleared by the caller. */ }
}

export function saveStatus(session, status) {
  const actor = session.actor;
  if (typeof actor.permissionVersion !== 'string') return;
  const expected = expectedSource();
  if (status.source !== expected.source || (status.integrationScope ?? null) !== expected.integrationScope || session.source !== status.source || (session.integrationScope ?? null) !== expected.integrationScope) return;
  const scope = statusScope(actor, status);
  const key = PREFIX + scope;
  try {
    if (localStorage.getItem(ACTIVE) !== key) clearStatusCache();
    // Explicit field selection keeps CSRF, session cookies and auth responses out.
    const permitted = new Set(actor.personIds);
    const people = status.people.filter((person) => permitted.has(person.id)).map((person) => ({
      id: person.id, name: person.name, devices: person.devices.map(({ id, label }) => ({ id, label })),
      manualPause: person.manualPause, effectiveManualPause: person.effectiveManualPause,
      observationHealth: person.observationHealth, scheduleBlocked: person.scheduleBlocked,
      scheduleExplanation: person.scheduleExplanation, status: person.status,
      latestOperation: person.latestOperation,
    }));
    const snapshot = {
      actor: { id: actor.id, displayName: actor.displayName, role: actor.role, personIds: [...actor.personIds], permissionVersion: actor.permissionVersion },
      sessionExpiresAt: session.expiresAt, savedAt: Math.floor(Date.now() / 1000),
      status: {
        people, serviceDesiredRevision: status.serviceDesiredRevision, revisionToken: status.revisionToken,
        routerDesiredRevision: status.routerDesiredRevision, routerConfirmedRevision: status.routerConfirmedRevision,
        observedAt: status.observedAt, statusAgeSeconds: status.statusAgeSeconds,
        lastSuccessfulConfirmationAt: status.lastSuccessfulConfirmationAt, errors: status.errors,
        source: status.source, routerCompatibilityVerified: false,
        integrationScope: status.integrationScope, packetAcceptance: status.packetAcceptance,
      },
    };
    localStorage.setItem(key, JSON.stringify(snapshot));
    localStorage.setItem(ACTIVE, key);
  } catch { /* A denied/full cache must never prevent status or control use online. */ }
}

export function readStatus() {
  try {
    if (localStorage.getItem(LOGOUT_REQUIRED)) return null;
    const key = localStorage.getItem(ACTIVE);
    if (!key?.startsWith(PREFIX)) return null;
    const snapshot = JSON.parse(localStorage.getItem(key) ?? 'null');
    if (!snapshot || key !== PREFIX + statusScope(snapshot.actor, snapshot.status) || snapshot.sessionExpiresAt <= Date.now() / 1000) {
      clearStatusCache();
      return null;
    }
    const expected = expectedSource();
    if (snapshot.status.source !== expected.source || (snapshot.status.integrationScope ?? null) !== expected.integrationScope || snapshot.status.routerCompatibilityVerified !== false) { clearStatusCache(); return null; }
    const permitted = new Set(snapshot.actor.personIds);
    if (!snapshot.status.people.every((person) => permitted.has(person.id))) return null;
    return snapshot;
  } catch {
    clearStatusCache();
    return null;
  }
}

export function needsServerLogout() {
  try { return localStorage.getItem(LOGOUT_REQUIRED) === 'true'; } catch { return false; }
}

export function setServerLogoutNeeded(needed) {
  try {
    if (needed) localStorage.setItem(LOGOUT_REQUIRED, 'true');
    else localStorage.removeItem(LOGOUT_REQUIRED);
  } catch { /* The current page also keeps this state in memory. */ }
}

export function broadcastLogout() {
  try { localStorage.setItem(LOGOUT_EVENT, crypto.randomUUID()); } catch { /* No persistent storage. */ }
}

export function broadcastScope(scope) {
  try { localStorage.setItem(SCOPE_EVENT, scope); } catch { /* No persistent storage. */ }
}
