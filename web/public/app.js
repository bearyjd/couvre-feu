import { createPasskey, getPasskey } from './auth-client.js';
import { actorScope, clearStatusCache, saveStatus, readStatus, needsServerLogout, setServerLogoutNeeded, broadcastLogout, broadcastScope, LOGOUT_EVENT, LOGOUT_REQUIRED, SCOPE_EVENT } from './status-cache.js';
import { createScheduleEditor, actionVerb } from './schedule-editor.js';
import { createParentAlerts } from './parent-alerts.js';
import { createActivityPanel } from './activity.js';
import { createTimeRequests } from './time-requests.js';
import { createAccounts } from './accounts.js';
import { createChildren, createBulk, effectText } from './children.js';
import { createAlertJournal, alertText, cacheAlertEvidence, ALERT_PREFIX, ALERT_ACTIVE } from './operational-alerts.js';

const $ = (selector) => document.querySelector(selector);
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const now = () => Math.floor(Date.now() / 1000);
const time = (value) => value ? new Date(value * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }) : 'Not yet observed';
const duration = (seconds) => seconds < 60 ? `${Math.max(0, seconds)}s` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`;
const FRESH_SECONDS = 30;
let alertStorage;
try { alertStorage = localStorage; } catch { alertStorage = null; }
const alertJournal = createAlertJournal(alertStorage);
const parentAlerts = createParentAlerts({ escape, time, csrfToken: () => state.session?.csrfToken, personName: (id) => state.people?.people.find((person) => person.id === id)?.name });
const activityPanel = createActivityPanel({ container: $('#activity-panel'), api });
const timeRequests = createTimeRequests({ session: () => state.session, people: () => state.people?.people ?? [] });
const accounts = createAccounts({ session: () => state.session, people: () => state.people?.people ?? [] });
const bulk = createBulk({ gate: () => controlBlock(), session: () => state.session, people: () => state.people?.people ?? [], revisionToken: () => state.people?.revisionToken ?? null, refresh: () => void refresh({ quiet: true }), version: () => state.people ? `${state.people.observedAt}:${state.people.serviceDesiredRevision}` : null });
const children = createChildren({ session: () => state.session, revisionToken: () => state.people?.revisionToken ?? null, refresh: () => void refresh({ quiet: true }), version: () => state.people ? `${state.people.observedAt}:${state.people.serviceDesiredRevision}` : null });
const isReal = () => document.documentElement.dataset.source === 'real-router-integration';
const state = {
  session: null, snapshotActor: null, snapshotExpiresAt: null, people: null, savedAt: null, offline: !navigator.onLine,
  busy: false, needsRefresh: true, refreshing: false, localUnknown: false, operation: null,
  generation: 0, renderKey: '', logoutRequired: needsServerLogout(), durations: new Map(),
  authController: null,
  scheduleClockBasis: null,
};

class APIError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

async function api(path, { method = 'GET', body, headers = {}, signal } = {}) {
  const response = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store', headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body), signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(12000)]) : AbortSignal.timeout(12000),
  });
  const result = await response.json();
  if (!response.ok) throw new APIError(response.status, result.error?.code ?? 'request_failed', result.error?.message ?? 'The request could not be completed.');
  return result;
}

function announce(message, error = false) {
  $('#notice').textContent = message;
  $('#notice').hidden = !message;
  $('#notice').classList.toggle('error', error);
}

function actor() { return state.session?.actor ?? state.snapshotActor; }
function age() { return state.people?.observedAt ? Math.max(0, now() - state.people.observedAt) : Infinity; }
function scheduleLabel(person) {
  const basis = state.scheduleClockBasis, wall = Date.now() / 1000;
  const elapsed = basis ? Math.max(0, performance.now() / 1000 - basis.started) : 0;
  const expected = basis ? basis.wall + elapsed : wall;
  const clockValid = basis && Number.isSafeInteger(person.scheduleCheckedAt) && Math.abs(basis.wall - person.scheduleCheckedAt) <= 1 && Math.abs(wall - expected) <= 1;
  const deadlineValid = person.scheduleWitness === 'none' || person.scheduleWitness === 'owner-reviewed-clock' && clockValid && Number.isSafeInteger(person.scheduleValidUntil) && person.scheduleValidUntil > person.scheduleCheckedAt
    && person.scheduleValidUntil <= person.scheduleCheckedAt + FRESH_SECONDS + 1
    && person.scheduleValidUntil > Math.max(wall, expected, person.scheduleCheckedAt + elapsed);
  const blocked = isReal() && (state.offline || state.localUnknown || age() > FRESH_SECONDS || person.observationHealth !== 'healthy' || !deadlineValid) ? null : person.scheduleBlocked;
  return blocked === null ? 'Schedule state unknown' : blocked ? 'Schedule currently blocks access' : 'No active schedule block';
}
function deviceEvidenceLabel(device) {
  const evidence = device.evidence, source = isReal() ? 'Router' : 'Demo';
  const expectedSource = isReal() ? 'router-policy' : 'synthetic-policy';
  const epoch = value => Number.isSafeInteger(value) && value >= 1577836800;
  const basis = state.scheduleClockBasis, wall = Date.now() / 1000;
  const elapsed = basis ? Math.max(0, performance.now() / 1000 - basis.started) : 0;
  const expected = basis ? basis.wall + elapsed : wall;
  const clockValid = !basis || Math.abs(wall - expected) <= 1;
  const timestampValid = evidence && evidence.source === expectedSource && epoch(evidence.sourceObservedAt) && evidence.sourceObservedAt <= wall &&
    (isReal() ? epoch(evidence.serviceReceivedAt) && evidence.serviceReceivedAt <= wall : evidence.serviceReceivedAt === null);
  const deadline = timestampValid ? Math.min(evidence.sourceObservedAt, evidence.serviceReceivedAt ?? evidence.sourceObservedAt) + FRESH_SECONDS + 1 : null;
  const known = timestampValid && clockValid && evidence.freshUntil === deadline && ['fresh', 'stale'].includes(evidence.freshness) && ['included', 'not-included'].includes(evidence.enrollment);
  const historical = state.offline || evidence?.freshness === 'stale' || wall >= deadline || expected >= deadline;
  const enrollment = known ? `${historical ? 'Last observed' : 'Observed'} enrollment: ${evidence.enrollment === 'included' ? 'included' : 'not included'}${historical ? ' · historical' : ''}` : 'Enrollment unknown';
  const observed = timestampValid ? ` · observed ${time(evidence.sourceObservedAt)} · ${duration(Math.max(0, Math.floor(Math.max(wall, expected) - evidence.sourceObservedAt)))} ago` : '';
  return `${source} · ${enrollment}${observed} · Activity unavailable`;
}
function unsettled() { return state.localUnknown || state.operation && ['pending', 'unknown'].includes(state.operation.state) || state.people?.people.some((person) => ['pending', 'unknown'].includes(person.status)); }
// Why mutating controls are unavailable right now (null = available). One source for per-person controls and the bulk panel.
function controlBlock() {
  if (state.offline) return 'Offline';
  if (state.busy || unsettled()) return 'A change is already in progress';
  const fresh = state.session && state.people && !state.refreshing && !state.needsRefresh && age() <= FRESH_SECONDS && typeof state.people.revisionToken === 'string' && state.people.routerDesiredRevision !== null && state.session.expiresAt > now();
  return fresh ? null : 'Status is out of date — refresh';
}
function canControl() { return controlBlock() === null; }

function resetView() {
  state.generation++;
  state.authController?.abort(); state.authController = null;
  state.session = null; state.snapshotActor = null; state.snapshotExpiresAt = null; state.people = null; state.savedAt = null; state.scheduleClockBasis = null;
  state.operation = null; state.localUnknown = false; state.needsRefresh = true; state.renderKey = '';
  state.busy = false; state.refreshing = false; state.durations.clear();
  clearStatusCache();
  alertJournal.clear();
  render();
}

function showCachedStatus() {
  const snapshot = readStatus();
  if (!snapshot) { alertJournal.clear(); return false; }
  state.snapshotActor = snapshot.actor; state.people = snapshot.status; state.savedAt = snapshot.savedAt;
  state.scheduleClockBasis = {wall: Date.now() / 1000, started: performance.now() / 1000};
  state.snapshotExpiresAt = snapshot.sessionExpiresAt;
  state.session = null; state.needsRefresh = true;
  alertJournal.bind({source: snapshot.status.source, integrationScope: snapshot.status.integrationScope, actor: snapshot.actor, expiresAt: snapshot.sessionExpiresAt}, snapshot.status, now());
  render();
  return true;
}

function acceptSession(session) {
  const previous = actor() ?? readStatus()?.actor;
  if (session.source !== (isReal() ? 'real-router-integration' : 'synthetic-fake-router') || (session.integrationScope ?? null) !== (document.documentElement.dataset.integrationScope ?? null)) throw new APIError(401, 'installation_scope_changed', 'The source or installation changed. Reload and sign in again.');
  if (previous && actorScope(previous) !== actorScope(session.actor)) {
    clearStatusCache();
    alertJournal.clear();
    state.people = null; state.operation = null; state.localUnknown = false; state.renderKey = '';
  }
  if (state.session && state.session.expiresAt !== session.expiresAt) alertJournal.clear();
  state.session = session;
  state.snapshotActor = null;
  state.snapshotExpiresAt = null;
  broadcastScope(actorScope(session.actor));
}

async function completePendingLogout() {
  if (!state.logoutRequired && !needsServerLogout()) return;
  try {
    const session = await api('/auth/session');
    await api('/auth/logout', { method: 'POST', body: {}, headers: { 'X-CSRF-Token': session.csrfToken } });
  } catch (error) { if (!(error instanceof APIError && error.status === 401)) throw error; }
  state.logoutRequired = false;
  setServerLogoutNeeded(false);
}

async function refresh({ quiet = false } = {}) {
  if (state.refreshing || state.busy || state.logoutRequired && state.offline) return false;
  if (state.offline || !navigator.onLine) { state.offline = true; state.needsRefresh = true; render(); return false; }
  const generation = state.generation;
  state.refreshing = true;
  renderConnection(); renderControlState(); renderAuthControls();
  try {
    await completePendingLogout();
    const session = await api('/auth/session');
    if (generation !== state.generation) return false;
    acceptSession(session);
    // Invalidate old permissions immediately, before receiving new status.
    render();
    const people = await api('/people');
    if (generation !== state.generation) return false;
    if (people.source !== session.source || (people.integrationScope ?? null) !== (session.integrationScope ?? null)) throw new APIError(401, 'installation_scope_changed', 'The installation changed. Reload and sign in again.');
    state.people = people; state.savedAt = now(); state.offline = false; state.needsRefresh = false;
    state.scheduleClockBasis = {wall: Date.now() / 1000, started: performance.now() / 1000};
    const latest = state.operation && people.people.find((person) => person.id === state.operation.personId)?.latestOperation;
    if (latest?.id === state.operation?.id) state.operation = latest;
    // An uncertain response is resolved only through a fresh server observation.
    state.localUnknown = people.people.some((person) => person.status === 'unknown');
    saveStatus(state.session, people);
    alertJournal.bind(state.session, people, now());
    alertJournal.ingest(people, now(), !state.offline);
    void parentAlerts.load();
    if (!quiet) announce('Status refreshed. Review the current manual pause and schedule before making a change.');
    return true;
  } catch (error) {
    state.needsRefresh = true;
    if (error instanceof APIError && [401, 403].includes(error.status)) {
      const hadStatus = Boolean(actor());
      resetView();
      if (hadStatus || !quiet) announce('Your session or permissions changed. Sign in again to see permitted status.', true);
    } else {
      state.offline = !navigator.onLine || !(error instanceof APIError);
      if (!state.people && state.offline) showCachedStatus();
      if (!quiet) announce('Status could not be refreshed. Controls are disabled; no changes are queued.', true);
    }
    return false;
  } finally {
    if (generation === state.generation) { state.refreshing = false; render(); }
  }
}

async function authenticate(kind, token) {
  if (state.busy) return;
  clearStatusCache();
  alertJournal.clear();
  state.busy = true; renderAuthControls();
  announce(kind === 'register' ? 'Create a passkey with your browser. The token fixes the account and permissions.' : 'Confirm your passkey in the browser.');
  const generation = state.generation;
  const controller = new AbortController();
  state.authController = controller;
  try {
    await completePendingLogout();
    if (generation !== state.generation || controller.signal.aborted) return;
    const start = await api(`/auth/${kind}/options`, { method: 'POST', body: kind === 'register' ? { token } : {}, signal: controller.signal });
    token = undefined;
    if (generation !== state.generation || controller.signal.aborted) return;
    const response = kind === 'register' ? await createPasskey(start.options, controller.signal) : await getPasskey(start.options, controller.signal);
    if (generation !== state.generation || controller.signal.aborted) return;
    const session = await api(`/auth/${kind}/verify`, { method: 'POST', body: { challengeId: start.challengeId, response }, signal: controller.signal });
    if (generation !== state.generation) return;
    if (session.pending) {
      // An admin-issued add-device token: the passkey exists but signs in only after an admin approves this code.
      $('#pairing-code').textContent = session.pairingCode;
      $('#pairing').hidden = false;
      announce(`Passkey created and waiting for approval. Pairing code ${session.pairingCode}: ask an admin to approve it, then sign in with your passkey.`);
      return;
    }
    $('#pairing').hidden = true;
    acceptSession(session);
    state.busy = false;
    await refresh({ quiet: true });
    if (state.people) announce(`Signed in as ${state.session.actor.displayName}. ${isReal() ? document.documentElement.dataset.automaticDispatch === 'true' ? 'Owner-enabled router dispatch is configured.' : 'Router dispatch requires an operator-approved invocation.' : 'All status is fictional.'}`);
  } catch (error) {
    if (generation !== state.generation) return;
    const message = error.name === 'NotAllowedError' ? 'Passkey sign-in was cancelled or unavailable. No control action was sent.'
      // Unknown, used and expired tokens get one answer; a used one may mean someone else enrolled with it.
      : error.code === 'token_used_or_expired' ? 'This enrollment token is unknown, expired or has already been used. Ask your admin for a new token, and to check the pending devices and not approve any they do not recognise.'
      : error.message;
    announce(message || 'Passkey sign-in could not be completed.', true);
  } finally {
    token = undefined;
    if (state.authController === controller) state.authController = null;
    if (generation === state.generation) { state.busy = false; render(); }
  }
}

async function logout() {
  const csrfToken = state.session?.csrfToken;
  const offline = state.offline || !navigator.onLine;
  state.logoutRequired = true;
  setServerLogoutNeeded(true);
  broadcastLogout();
  resetView();
  announce('Local status cleared. Signing out of the server…');
  if (offline) {
    announce('Local status cleared. You are offline; server sign-out is still required and will run when the connection returns.');
    return;
  }
  try {
    if (csrfToken) await api('/auth/logout', { method: 'POST', body: {}, headers: { 'X-CSRF-Token': csrfToken } });
    else await completePendingLogout();
    state.logoutRequired = false; setServerLogoutNeeded(false);
    announce('Signed out. Local status has been cleared.');
  } catch {
    announce('Local status cleared. Server sign-out could not be confirmed; it will be completed before the next sign-in.', true);
  }
}

async function mutate(personId, action, presetSeconds) {
  if (!canControl()) return;
  const beforeRevision = state.people.revisionToken;
  const beforeScope = actorScope(state.session.actor);
  const requestedDuration = presetSeconds ?? state.durations.get(personId) ?? '0';
  const generation = state.generation;
  // Fresh reads are part of this click, never an automatic mutation retry.
  const refreshed = await refresh({ quiet: true });
  if (!refreshed || generation !== state.generation || !canControl()) return;
  if (beforeRevision !== state.people.revisionToken || beforeScope !== actorScope(state.session.actor)) {
    announce('The revision or your permissions changed. Status has been refreshed; review it and choose the action again.', true);
    return;
  }
  state.busy = true;
  renderControlState();
  announce(`Sending ${action === 'resume' ? 'resume' : 'manual pause'} request. A request is not confirmation.`);
  try {
    const until = requestedDuration === '0' ? 0 : now() + Number(requestedDuration);
    const result = await api(`/people/${encodeURIComponent(personId)}/${action}`, {
      method: 'POST', body: action === 'pause' ? { until } : {},
      headers: { 'If-Match': beforeRevision, 'Idempotency-Key': crypto.randomUUID(), 'X-CSRF-Token': state.session.csrfToken },
    });
    if (generation !== state.generation) return;
    state.operation = result.operation;
    const person = state.people.people.find((entry) => entry.id === personId);
    if (person) { person.latestOperation = result.operation; person.status = result.operation.state; }
    announce(operationText(result.operation));
    state.busy = false;
    render();
    if (['pending', 'unknown'].includes(result.operation.state)) void followOperation(result.operation.id, generation);
    else await refresh({ quiet: true });
  } catch (error) {
    if (generation !== state.generation) return;
    state.needsRefresh = true;
    if (error instanceof APIError && error.status === 409) {
      announce('Revision conflict. No retry was sent. Refresh status, review the change, then choose the action again.', true);
    } else if (error instanceof APIError && [401, 403].includes(error.status)) {
      resetView();
      announce('This action is not authorized. Sign in again; local status has been cleared.', true);
    } else if (error instanceof APIError) {
      announce(`The request failed: ${error.message} Refresh status before another action.`, true);
    } else {
      state.localUnknown = true;
      state.offline = !navigator.onLine;
      announce(isReal() ? 'Outcome unknown. The intent may have been saved; no router invocation or retry is authorized by this response. Refresh the cached status.' : 'Outcome unknown. The response was lost; the action may have reached the fake router. No retry is queued. Reconnect and refresh status.', true);
    }
  } finally {
    if (generation === state.generation) { state.busy = false; render(); }
  }
}

const COVERAGE_REFUSALS = ['incomplete_address_coverage', 'incomplete_transition_address_coverage'];
function operationText(operation) {
  const verb = actionVerb(operation.action);
  // A bulk change says what is in force right now (its `effect`), in every mode; the generic fake-router text below never describes it.
  const effect = effectText(operation, verb);
  if (effect) return effect;
  if (isReal()) return ({
    pending: operation.dispatch === 'awaiting_automatic_dispatch' ? `${verb} pending. Waiting for automatic router confirmation.` : operation.dispatch === 'consumed' ? `${verb} pending. Waiting for the router receipt.` : `${verb} pending. Waiting for an exact operator-approved router invocation.`,
    confirmed: `${verb} confirmed by a fresh router receipt and current runtime observation. Packet behavior remains unmeasured.`,
    failed: COVERAGE_REFUSALS.includes(operation.error) ? `${verb} refused by the router: a managed device had no network address (it may be off or away). Nothing changed. An admin can see which devices to check.` : `${verb} was not delivered. Review the operation details before another deliberate action.`,
    unknown: `${verb} outcome unknown. A historical receipt or local timeout cannot establish current enforcement. No retry is authorized.`,
    conflict: `${verb} conflict. The accepted router policy changed; review a separately approved fresh observation.`,
  })[operation.state] ?? 'Operation status unavailable.';
  return ({
    pending: `${verb} pending. Waiting for healthy fake-router confirmation.`,
    confirmed: `${verb} confirmed by the fake router. ${operation.action === 'resume' ? 'An active schedule can still block access.' : 'Real packet behavior remains unverified.'}`,
    failed: `${verb} failed. The fake router reported an explicit failure. Refresh status before another action.`,
    unknown: `${verb} outcome unknown. No sufficient confirmation was observed. The action may have applied; no automatic retry will run.`,
    conflict: `${verb} conflict. Refresh status and review the current revision before another action.`,
  })[operation.state] ?? 'Operation status unavailable.';
}

async function followOperation(id, generation) {
  // Read-only polling; mutations are never replayed. Unknown can reconcile later.
  while (generation === state.generation && state.operation?.id === id && ['pending', 'unknown'].includes(state.operation.state)) {
    await new Promise((resolve) => setTimeout(resolve, 750));
    if (generation !== state.generation || state.offline || !navigator.onLine) return;
    try {
      const operation = await api(`/operations/${encodeURIComponent(id)}`);
      if (generation !== state.generation) return;
      state.operation = operation;
      const person = state.people?.people.find((entry) => entry.id === operation.personId);
      if (person) { person.latestOperation = operation; person.status = operation.state; }
      announce(operationText(operation), ['failed', 'unknown', 'conflict'].includes(operation.state));
      render();
      if (operation.state === 'unknown') { state.needsRefresh = true; renderControlState(); return; }
      if (operation.state !== 'pending') {
        state.needsRefresh = operation.state !== 'confirmed';
        await refresh({ quiet: true });
        return;
      }
    } catch (error) {
      if (generation !== state.generation) return;
      if (error instanceof APIError && [401, 403, 404].includes(error.status)) {
        resetView(); announce('Operation access changed. Sign in again to refresh permitted status.', true);
      } else {
        state.needsRefresh = true; state.localUnknown = true; state.offline = !navigator.onLine || !(error instanceof APIError);
        announce('Operation observation is unavailable. Outcome is unknown; refresh before another action.', true); render();
      }
      return;
    }
  }
}

function renderAuthControls() {
  for (const selector of ['#sign-in', '#enroll', '#enrollment-token']) $(selector).disabled = state.busy || state.refreshing || state.offline;
}

function renderControlState() {
  const enabled = canControl();
  for (const button of document.querySelectorAll('[data-control], [data-quick-pause]')) button.disabled = !enabled;
  for (const field of document.querySelectorAll('[data-duration]')) field.disabled = !enabled;
  bulk.update();
  $('#refresh').disabled = state.busy || state.refreshing || state.offline;
  scheduleEditor.render();
}

function renderConnection() {
  if (!state.people) return;
  const stale = age() > FRESH_SECONDS || state.needsRefresh;
  const diagnosticsOpen = $('#connection details')?.open;
  const status = state.offline ? 'Offline · read-only snapshot' : state.refreshing ? 'Refreshing session and status…' : stale ? 'Status needs refresh · controls disabled' : isReal() ? 'Connected · cached router observation' : 'Connected · current synthetic observation';
  $('#connection').className = `connection${state.offline ? ' offline' : stale ? ' stale' : ''}`;
  $('#connection').innerHTML = `<strong>${escape(status)}</strong>Observed ${escape(time(state.people.observedAt))} · <span data-age>${Number.isFinite(age()) ? escape(duration(age())) + ' ago' : 'age unavailable'}</span>${state.savedAt ? ` · cached ${escape(time(state.savedAt))}` : ''}<details class="diagnostics" ${diagnosticsOpen ? 'open' : ''}><summary>${isReal() ? 'Router observation details' : 'Advanced demo status'}</summary><p>Service desired ${escape(state.people.serviceDesiredRevision)} · router desired ${escape(state.people.routerDesiredRevision ?? 'unknown')} · router confirmed ${escape(state.people.routerConfirmedRevision ?? 'unconfirmed')}${state.people.errors.length ? `<br>Observation errors: ${escape(state.people.errors.join(', '))}` : ''}<br>Source: ${isReal() ? 'real router integration · packet acceptance unmeasured' : 'synthetic fake router · target compatibility unverified'}</p></details>`;
}

function renderPeople() {
  const renderKey = JSON.stringify([state.people, state.offline, state.localUnknown]);
  if (renderKey === state.renderKey) return;
  const focused = document.activeElement?.dataset?.focusKey;
  const openDetails = new Set([...document.querySelectorAll('[data-details-key][open]')].map((element) => element.dataset.detailsKey));
  state.renderKey = renderKey;
  $('#people').innerHTML = state.people.people.map((person) => {
    const id = escape(person.id);
    const label = escape(person.name);
    const manual = person.manualPause;
    const effectiveManual = person.effectiveManualPause;
    const operation = person.latestOperation;
    const personStatus = state.localUnknown || person.observationHealth !== 'healthy' && person.status === 'confirmed' ? 'unknown' : person.status;
    const choices = [['0', 'Until I resume'], ['60', isReal() ? '1 minute' : '1 minute · demo'], ['900', '15 minutes'], ['1800', '30 minutes'], ['3600', '1 hour']];
    const timedPause = effectiveManual && effectiveManual.until > 0;
    return `<article class="person" data-person="${id}" aria-labelledby="name-${id}">
      <div class="person-top"><div class="person-name"><span class="avatar" aria-hidden="true">${escape(person.name.slice(0, 1))}</span><div><h3 id="name-${id}">${label}</h3><p class="person-id">${person.kind === 'device_group' ? 'Device group' : isReal() ? 'Private pilot person' : 'Fictional person'} · ${person.devices.length} assigned ${person.devices.length === 1 ? 'device' : 'devices'}</p></div></div><span class="badge ${escape(personStatus)}">${escape(personStatus === 'confirmed' ? isReal() ? 'Router confirmed' : 'Fake confirmed' : personStatus[0].toUpperCase() + personStatus.slice(1))}</span></div>
      <dl class="reasons"><div><dt>Manual pause</dt><dd>${effectiveManual ? effectiveManual.until === 0 ? 'Paused until you resume' : `Paused until ${escape(time(effectiveManual.until))}<span class="reason-detail" data-until="${effectiveManual.until}"></span>` : manual ? 'Expired in the latest observation' : 'No manual pause'}<span class="reason-detail">${effectiveManual ? 'Manual pause is separate from the schedule.' : 'A schedule may still block access.'}</span></dd></div><div><dt>Schedule</dt><dd><span data-schedule-state="${id}">${escape(scheduleLabel(person))}</span><span class="reason-detail">${escape(person.scheduleExplanation)}</span></dd></div></dl>
      <p class="devices-label">Assigned devices</p><ul class="devices" aria-label="${label} assigned devices">${person.devices.length ? person.devices.map((device) => `<li>${escape(device.label)}${device.change ? ` · ${device.change === 'adding' ? 'being added' : device.change === 'moving' ? 'being moved' : 'being removed'}` : ''}<span class="reason-detail" data-device-evidence="${escape(device.id)}">${escape(deviceEvidenceLabel(device))}</span></li>`).join('') : '<li>No assigned devices</li>'}</ul>
      <div class="quick-pauses" role="group" aria-label="Quick pause for ${label}">${[[900, '15'], [1800, '30'], [3600, '60']].map(([seconds, minutes]) => `<button class="button primary" type="button" data-quick-pause="${seconds}" data-person-id="${id}" data-focus-key="quick-${seconds}-${id}" aria-label="Pause ${label} for ${minutes} minutes">Pause ${minutes} min</button>`).join('')}</div>
      ${timedPause ? `<p class="remaining" role="timer" aria-label="Time remaining on ${label} timed pause">Time left: <strong data-remaining="${effectiveManual.until}"></strong></p>` : ''}
      <p class="extra-time" data-extra-time="${id}"><button class="button secondary" type="button" disabled aria-describedby="extra-note-${id}">Extra time 15 / 30 / 60 min</button><span class="reason-detail" id="extra-note-${id}">Unavailable: the router policy has no allowance concept yet, so a schedule block cannot be lifted temporarily. Pausing and ending a pause work as shown.</span></p>
      <div class="person-controls"><div class="duration-field"><label for="duration-${id}">Pause duration for ${label}</label><select id="duration-${id}" data-duration="${id}" data-focus-key="duration-${id}">${choices.map(([value, text]) => `<option value="${value}" ${value === (state.durations.get(person.id) ?? '0') ? 'selected' : ''}>${text}</option>`).join('')}</select></div><button class="button primary" type="button" data-control="pause" data-person-id="${id}" data-focus-key="pause-${id}" aria-label="Pause ${label}">Pause</button><button class="button secondary" type="button" data-control="resume" data-person-id="${id}" data-focus-key="resume-${id}" aria-label="${timedPause ? `End ${label} timed pause now` : `Resume ${label} manual pause`}">${timedPause ? 'End now' : 'Resume'}</button></div>
      ${operation ? `<div class="operation ${escape(operation.state)}" role="status"><strong>${escape(operationText(operation))}</strong><details class="diagnostics" data-details-key="${id}" ${openDetails.has(person.id) ? 'open' : ''}><summary>Operation details</summary><p>Operation ${escape(operation.id)} · revision ${escape(operation.revision)} · updated ${escape(time(operation.updatedAt))}${operation.error ? `<br>Detail: ${escape(operation.error)}` : ''}</p></details></div>` : ''}
      <p class="confirmation">Current observation: ${escape(person.observationHealth)}. Last healthy ${isReal() ? 'router' : 'synthetic'} confirmation: ${escape(time(state.people.lastSuccessfulConfirmationAt))}. Resume clears only manual pause.</p>
    </article>`;
  }).join('') || '<p>No people are assigned to this account.</p>';
  if (focused) document.querySelector(`[data-focus-key="${CSS.escape(focused)}"]`)?.focus();
  renderControlState();
  tick();
}

function renderAlerts() {
  const panel = $('#operational-alerts'), feed = $('#alert-feed');
  if (!state.people || !actor()) { feed.replaceChildren(); panel.hidden = true; $('#hide-recovery').checked = false; return; }
  const all = alertJournal.view(now(), true);
  const view = {...all, records: all.records.filter(record => !all.hideRecovery || record.recoveredAt === null)};
  const sameCondition = (record, condition) => record.code === condition.code && (record.operationId ?? null) === (condition.operationId ?? null) && (record.pauseUntil ?? null) === (condition.pauseUntil ?? null);
  const currentRows = state.offline || !alertJournal.isBound() ? '' : state.people.people.filter(person => actor().personIds.includes(person.id)).flatMap(person => {
    const evidence = cacheAlertEvidence(person.operationalAlerts, state.people.source);
    const witness = alertJournal.latestWitness(person.id);
    const recoveredEvaluation = Math.max(0, ...all.records.filter(record => record.personId === person.id).map(record => record.recoveryEvaluatedAt ?? 0));
    if (!evidence || evidence.evaluatedAt > now() || evidence.evaluatedAt < recoveredEvaluation) return [];
    return evidence.conditions.filter(condition => !(condition.code.startsWith('observation-') || condition.code === 'observed-drift') || evidence.evaluatedAt >= (witness?.healthyEvaluatedAt ?? 0))
      .filter(condition => condition.code !== 'observed-drift' || evidence.freshness === 'fresh' && evidence.freshUntil > now())
      .filter(condition => !['observation-stale', 'observed-drift'].includes(condition.code) || !witness || evidence.sourceObservedAt >= witness.sourceObservedAt &&
        (evidence.source === 'synthetic-policy' || evidence.serviceReceivedAt >= witness.serviceReceivedAt))
      .filter(condition => !all.records.some(record => record.personId === person.id && record.recoveredAt === null && sameCondition(record, condition)))
      .map(condition => `<li class="alert-row alert-current"><strong>${escape(person.name)} · Current response verification warning</strong><p>${escape(alertText(condition.code))}</p><small>Response evaluated ${escape(time(evidence.evaluatedAt))} · source observed ${escape(time(evidence.sourceObservedAt))}</small></li>`);
  }).join('');
  const rows = currentRows + view.records.map(record => {
    const person = state.people.people.find(person => person.id === record.personId);
    if (!person) return '';
    const current = !state.offline && (person.operationalAlerts?.conditions.some(condition => condition.code === record.code &&
      (condition.code !== 'observed-drift' || person.operationalAlerts.freshness === 'fresh' && person.operationalAlerts.freshUntil > now()) &&
      (condition.operationId ?? null) === (record.operationId ?? null) && (condition.pauseUntil ?? null) === (record.pauseUntil ?? null)) ||
      record.code === 'observation-stale' && person.operationalAlerts?.freshUntil !== null && person.operationalAlerts?.freshUntil <= now());
    const label = record.recoveredAt !== null ? 'Recovered with a newer router witness' : state.offline ? 'Historical warning · unresolved' : current ? 'Current verification warning' : 'Earlier warning · unresolved';
    return `<li class="alert-row${record.recoveredAt !== null ? ' recovered' : ''}"><strong>${escape(person.name)} · ${escape(label)}</strong><p>${escape(alertText(record.code))}</p><small>First noticed ${escape(time(record.firstNoticedAt))} · source observed ${escape(time(record.sourceObservedAt))}${record.recoveredAt !== null ? ` · recovered ${escape(time(record.recoveredAt))}` : ''}${record.operationId ? '<br>This warning concerns the earlier identified request; current controls use the latest status above.' : ''}</small></li>`;
  }).join('');
  const html = rows || '<li class="fine-print">No retained alerts for this permitted session.</li>';
  if (feed.innerHTML !== html) feed.innerHTML = html;
  $('#hide-recovery').checked = view.hideRecovery;
  panel.hidden = false;
}

function render() {
  const hasStatus = Boolean(state.people && actor());
  $('#auth-view').hidden = hasStatus;
  $('#status-view').hidden = !hasStatus;
  const account = actor();
  const accountKey = account ? `${account.id}:${account.role}` : '';
  if ($('#account-actions').dataset.accountKey !== accountKey) {
    $('#account-actions').dataset.accountKey = accountKey;
    $('#account-actions').innerHTML = account ? `<div class="account-actions"><span class="account-name">${escape(account.displayName)} · ${escape(account.role)}</span><button id="logout" class="button secondary" type="button">Sign out</button></div>` : '';
    $('#logout')?.addEventListener('click', () => void logout());
  }
  if (hasStatus) {
    $('#account-context').textContent = `${account.displayName} · ${account.role} · only your permitted ${isReal() ? 'private pilot person' : 'fictional people'}`;
    renderConnection(); renderPeople(); renderControlState();
    activityPanel.update(state.people.people, Boolean(state.session) && !state.offline);
  } else {
    activityPanel.clear();
    $('#people').replaceChildren();
    $('#connection').replaceChildren();
    $('#account-context').textContent = '';
    state.renderKey = '';
    scheduleEditor.render();
  }
  renderAuthControls();
  renderAlerts();
  parentAlerts.render(hasStatus && !state.offline, document.querySelectorAll('#alert-feed .alert-current').length);
  timeRequests.update();
  accounts.update();
  bulk.update();
  children.update();
}

function tick() {
  const currentAge = age();
  for (const label of document.querySelectorAll('[data-schedule-state]')) {
    const person = state.people?.people.find(person => person.id === label.dataset.scheduleState);
    if (person) label.textContent = scheduleLabel(person);
  }
  for (const label of document.querySelectorAll('[data-device-evidence]')) {
    const person = state.people?.people.find(person => person.id === label.closest('[data-person]')?.dataset.person);
    const device = person?.devices.find(device => device.id === label.dataset.deviceEvidence);
    if (device) label.textContent = deviceEvidenceLabel(device);
  }
  for (const label of document.querySelectorAll('[data-age]')) label.textContent = Number.isFinite(currentAge) ? `${duration(currentAge)} ago` : 'age unavailable';
  for (const label of document.querySelectorAll('[data-remaining]')) {
    const remaining = Number(label.dataset.remaining) - now();
    label.textContent = remaining > 0 ? duration(remaining) : 'expiry time reached, awaiting router observation';
  }
  for (const label of document.querySelectorAll('[data-until]')) {
    const remaining = Number(label.dataset.until) - now();
    label.textContent = remaining > 0 ? `${duration(remaining)} until the expiry time; router observation remains authoritative.` : 'Expiry time reached. Waiting for a fresh router observation; this countdown cannot confirm expiry.';
  }
  if (state.people && currentAge > FRESH_SECONDS && !state.needsRefresh) { state.needsRefresh = true; renderConnection(); }
  if (state.session && state.session.expiresAt <= now()) { resetView(); announce('Your session expired. Sign in again; local status was cleared.', true); }
  if (state.snapshotExpiresAt && state.snapshotExpiresAt <= now()) { resetView(); announce('The cached session expired. Local status was cleared; reconnect and sign in again.', true); }
  if (state.people && actor()) { alertJournal.ingest(state.people, now(), false); renderAlerts(); }
  renderControlState();
}

const scheduleEditor = createScheduleEditor({
  root: $('#schedule-editor'), state, api, announce, canControl, refresh, render, operationText, followOperation,
  setBusy: (value) => { state.busy = value; renderControlState(); },
  unauthorized: () => { resetView(); announce('This action is not authorized. Sign in again; local status has been cleared.', true); },
});

$('#sign-in').addEventListener('click', () => void authenticate('login'));
$('#enroll-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const token = $('#enrollment-token').value.trim();
  $('#enrollment-token').value = '';
  if (token) void authenticate('register', token);
});
$('#refresh').addEventListener('click', () => void refresh());
$('#hide-recovery').addEventListener('change', event => { alertJournal.setHideRecovery(event.target.checked, now()); renderAlerts(); });
$('#people').addEventListener('change', (event) => {
  if (event.target.matches('[data-duration]')) state.durations.set(event.target.dataset.duration, event.target.value);
});
$('#people').addEventListener('click', (event) => {
  const button = event.target.closest('[data-control], [data-quick-pause]');
  if (button && !button.disabled) void mutate(button.dataset.personId, button.dataset.quickPause ? 'pause' : button.dataset.control, button.dataset.quickPause);
});
window.addEventListener('offline', () => { state.offline = true; state.needsRefresh = true; render(); announce('Offline. Last observed status is read-only; no control requests will be queued.'); });
window.addEventListener('online', async () => {
  state.offline = false; state.needsRefresh = true; render();
  if (state.logoutRequired || needsServerLogout()) {
    try { await completePendingLogout(); announce('Server sign-out completed. Sign in again to refresh permitted status.'); }
    catch { announce('Server sign-out is still unconfirmed. Local status remains cleared.', true); }
  } else await refresh();
});
window.addEventListener('storage', (event) => {
  if (event.key === ALERT_ACTIVE || event.key?.startsWith(ALERT_PREFIX)) {
    alertJournal.storageChanged(event.key, event.newValue);
    renderAlerts();
  }
  if (event.key === LOGOUT_EVENT) {
    state.logoutRequired = needsServerLogout(); resetView();
    announce('Signed out in another tab. Local status has been cleared.');
  } else if (event.key === SCOPE_EVENT && actor() && event.newValue !== actorScope(actor())) {
    resetView();
    announce('Account or permissions changed in another tab. Sign in again to refresh permitted status.');
  } else if (event.key === LOGOUT_REQUIRED && event.newValue === null) {
    state.logoutRequired = false;
  }
});
document.addEventListener('visibilitychange', () => { if (!document.hidden && state.session && !state.busy) void refresh({ quiet: true }); });
setInterval(tick, 1000);
setInterval(() => { if (state.session && !state.offline && !state.busy && !state.refreshing && !state.needsRefresh) void refresh({ quiet: true }); }, 10000);

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => { /* Online UI remains usable; offline installation is not claimed. */ });
render();
if (state.offline) {
  showCachedStatus();
  announce(state.people ? 'Offline read-only snapshot. Sign-in and control requests are unavailable.' : 'Offline. No permitted status snapshot is available.');
} else void refresh({ quiet: true });
