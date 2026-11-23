import { actorScope } from './status-cache.js';
import { getPasskey } from './auth-client.js';

// Client-side bounds mirror shared/src/router-schema.ts (the service re-validates authoritatively).
export const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
export const ID_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
export const CLOCK_PATTERN = /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/;
export const MAX_SCHEDULES = 256;
export const MAX_EXPANDED_WINDOWS = 256;
// Mirrors MAX_WINDOWS_PER_CHILD in the integration schedule store.
const MAX_INTEGRATION_WINDOWS = 8;
const EXTRA_MINUTES = [15, 30, 60];
// The exclusive observation deadline is FRESH_SECONDS + 1, as in the app's schedule label.
const MAX_SCHEDULE_CLAIM_SECONDS = 31;

const crossesMidnight = (start, stop) => start > stop && stop !== '00:00';
const minutes = (clock) => Number(clock.slice(0, 2)) * 60 + Number(clock.slice(3));
const orderedDays = (weekdays) => DAYS.filter((day) => weekdays.includes(day));

/** Plain-language windows, one per selected day, e.g. "Mon 22:00 → Tue 06:30". */
export function previewWindows(weekdays, start, stop) {
  if (!CLOCK_PATTERN.test(start) || !CLOCK_PATTERN.test(stop) || start === stop) return [];
  return orderedDays(weekdays).map((day) => {
    const end = start < stop ? day : DAYS[(DAYS.indexOf(day) + 1) % 7];
    return `${day} ${start} → ${end} ${stop}`;
  });
}

function weeklyIntervals(window) {
  const length = window.start < window.stop ? minutes(window.stop) - minutes(window.start) : 1440 - minutes(window.start) + minutes(window.stop);
  return orderedDays(window.weekdays).flatMap((day) => {
    const begin = DAYS.indexOf(day) * 1440 + minutes(window.start), end = begin + length;
    return end > 10080 ? [[begin, 10080], [0, end - 10080]] : [[begin, end]];
  });
}
export function overlaps(a, b) {
  const right = weeklyIntervals(b);
  return weeklyIntervals(a).some(([from, to]) => right.some(([otherFrom, otherTo]) => from < otherTo && otherFrom < to));
}

export function expandedWindows(schedules, deviceCount) {
  return schedules.reduce((total, schedule) => total + deviceCount * (crossesMidnight(schedule.start, schedule.stop) ? 2 : 1), 0);
}

/** Returns field messages; an empty object means the draft is acceptable to submit. */
export function validateDraft(draft, { schedules, editingId = null, deviceCount, maxSchedules = MAX_SCHEDULES }) {
  const errors = {};
  if (!ID_PATTERN.test(draft.id)) errors.id = 'Use a lowercase letter first, then lowercase letters, digits or underscores (up to 32 characters).';
  else if (editingId === null && schedules.some((schedule) => schedule.id === draft.id)) errors.id = 'A schedule with this name already exists.';
  if (!Array.isArray(draft.weekdays) || draft.weekdays.length === 0 || draft.weekdays.some((day) => !DAYS.includes(day))) errors.weekdays = 'Choose at least one day.';
  if (!CLOCK_PATTERN.test(draft.start)) errors.start = 'Enter a start time (HH:MM, 24-hour).';
  if (!CLOCK_PATTERN.test(draft.stop)) errors.stop = 'Enter a stop time (HH:MM, 24-hour).';
  if (!errors.start && !errors.stop && draft.start === draft.stop) errors.form = 'Start and stop must differ; an empty window is not allowed.';
  if (!errors.start && !errors.stop && !errors.form) {
    const others = schedules.filter((schedule) => schedule.id !== editingId);
    if (others.length + 1 > maxSchedules) errors.form = `At most ${maxSchedules} schedules are allowed.`;
    else {
      const expanded = expandedWindows([...others, draft], deviceCount);
      if (expanded > MAX_EXPANDED_WINDOWS) errors.form = `This would need ${expanded} per-device router windows; the router allows at most ${MAX_EXPANDED_WINDOWS} (a window that crosses midnight counts twice per device). Remove or simplify a schedule.`;
    }
  }
  return errors;
}

export function actionVerb(action) {
  return ({ pause: 'Pause', resume: 'Resume', schedule_create: 'Schedule addition', schedule_update: 'Schedule change', schedule_delete: 'Schedule removal', enroll: 'Device addition', unenroll: 'Device removal', pause_all: 'Block all', resume_all: 'Unblock all', move: 'Move', allow: 'Extra time' })[action] ?? 'Change';
}

const SERVER_FIELD = {
  invalid_id: 'id', schedule_id_exists: 'id', invalid_weekday: 'weekdays', empty_weekdays: 'weekdays', duplicate_value: 'weekdays', array_limit: 'weekdays',
  invalid_clock: 'start', empty_schedule: 'form', expanded_schedule_limit: 'form',
};
const PASSKEY_REFUSALS = new Set(['invalid_challenge', 'step_up_required', 'step_up_mismatch', 'credential_not_bound',
  'credential_account_mismatch', 'passkey_verification_failed', 'credential_changed']);
const SESSION_REFUSALS = new Set(['authentication_required', 'session_expired', 'session_browser_mismatch', 'permissions_changed', 'credential_revoked', 'account_disabled']);
const WRITE_REFUSALS = {
  400: ['invalid_object', 'invalid_fields', 'invalid_id', 'invalid_clock', 'invalid_weekday', 'empty_weekdays', 'duplicate_value',
    'array_limit', 'empty_schedule', 'expanded_schedule_limit', 'idempotency_key_required'],
  403: ['origin_rejected', 'schedule_editing_unavailable'],
  404: ['person_not_found'],
  409: ['schedule_id_exists', 'operation_in_progress', 'schedule_payload_inadmissible', 'person_has_no_enrolled_device',
    'recurring_focus_unavailable', 'idempotency_payload_conflict', 'revision_exhausted'],
  428: ['revision_precondition_required'],
  503: ['approved_router_observation_required', 'router_runtime_unconfirmed'],
};
const REFUSAL_TEXT = {
  operation_in_progress: 'Another router change is already in progress. Refresh status before saving again.',
  schedule_payload_inadmissible: 'These windows exceed the router’s limits. Review the draft before saving again.',
  person_has_no_enrolled_device: 'This child has no enrolled device. Refresh status before saving again.',
};
const ALLOWANCE_REFUSALS = {
  400: ['invalid_minutes'],
  404: ['route_not_found'],
  409: ['child_paused', 'schedule_clock_unverified', 'schedule_not_active', 'schedule_allowance_cap_exceeded', 'allowance_beyond_horizon'],
};
const ALLOWANCE_TEXT = {
  route_not_found: 'Schedule allowances are unavailable on this installation.',
  child_paused: 'This child is paused. The pause takes precedence over schedule extra time.',
  schedule_clock_unverified: 'The service could not verify the router clock for this allowance. Refresh status before trying again.',
  schedule_not_active: 'There is no active schedule window to cover. Refresh status before trying again.',
  schedule_allowance_cap_exceeded: 'Extra time cannot exceed 60 minutes from the router’s current time. Try a shorter extension.',
  allowance_beyond_horizon: 'The router’s time limit prevented this allowance.',
};
const SCHEDULE_ACTION = { create: 'schedule_create', edit: 'schedule_update', delete: 'schedule_delete' };
const windowSnapshot = (window) => window && JSON.stringify([orderedDays(window.weekdays), window.start, window.stop, window.kind ?? null]);
const sessionKey = (session) => session && JSON.stringify([actorScope(session.actor), session.csrfToken, session.source, session.integrationScope]);
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const describe = (schedule) => `${orderedDays(schedule.weekdays).join(', ')} · ${schedule.start} → ${schedule.stop}${crossesMidnight(schedule.start, schedule.stop) ? ' (next day)' : ''}`;

/**
 * Parent-app schedule editor. All writes use the same If-Match / Idempotency-Key / CSRF protocol as pause and
 * resume. Only the server's pre-write passkey refusal permits a second POST, bound to the original change.
 */
export function createScheduleEditor(deps) {
  const { root, state } = deps;
  let view = { open: null, confirm: null, submitted: false, serverErrors: {} };
  let lastKey = '';
  let active = null;

  const editable = () => (state.people?.people ?? []).filter((person) => person.schedulesEditable === true && Array.isArray(person.schedules));
  const integration = () => state.people?.source === 'real-router-integration';
  const maxSchedules = () => integration() ? MAX_INTEGRATION_WINDOWS : MAX_SCHEDULES;
  const person = (id) => editable().find((entry) => entry.id === id);
  const reset = () => { view = { open: null, confirm: null, submitted: false, serverErrors: {} }; };
  const context = () => {
    const entry = person(view.open.person);
    return { schedules: entry.schedules, editingId: view.open.mode === 'edit' ? view.open.originalId : null, deviceCount: entry.devices.length, maxSchedules: maxSchedules() };
  };
  const errorsNow = () => ({ ...(view.submitted ? validateDraft(view.open.draft, context()) : {}), ...view.serverErrors });

  function nextId(entry) {
    for (let index = 1; index <= MAX_SCHEDULES + 1; index++) if (!entry.schedules.some((schedule) => schedule.id === `window_${index}`)) return `window_${index}`;
    return '';
  }

  function formMarkup(entry, enabled) {
    const { mode, draft } = view.open, key = escape(entry.id), title = mode === 'edit' ? `Edit ${escape(view.open.originalId)}` : `Add a schedule for ${escape(entry.name)}`;
    const locked = active ? 'disabled' : '';
    const day = (name) => `<label class="day-choice"><input type="checkbox" data-field="day" value="${name}" ${draft.weekdays.includes(name) ? 'checked' : ''} data-focus-key="day-${name}" ${locked}> ${name}</label>`;
    return `<form class="schedule-form" data-schedule-form novalidate aria-labelledby="sched-form-title-${key}">
      <h4 id="sched-form-title-${key}">${title}</h4>
      <div class="schedule-field"><label for="sched-id-${key}">Name</label><input id="sched-id-${key}" data-field="id" data-focus-key="id" value="${escape(draft.id)}" maxlength="32" autocomplete="off" autocapitalize="none" spellcheck="false" ${mode === 'edit' ? 'readonly' : ''} ${locked} aria-describedby="sched-id-help-${key} sched-id-error-${key}">
        <p class="field-help" id="sched-id-help-${key}">Lowercase letters, digits and underscores; starts with a letter.</p><p class="field-error" data-error="id" id="sched-id-error-${key}"></p></div>
      <fieldset class="schedule-days"><legend>Days</legend><div class="day-row">${DAYS.map(day).join('')}</div><p class="field-error" data-error="weekdays"></p></fieldset>
      <div class="time-row">
        <div class="schedule-field"><label for="sched-start-${key}">Start</label><input id="sched-start-${key}" type="time" step="60" data-field="start" data-focus-key="start" value="${escape(draft.start)}" ${locked} required><p class="field-error" data-error="start"></p></div>
        <div class="schedule-field"><label for="sched-stop-${key}">Stop</label><input id="sched-stop-${key}" type="time" step="60" data-field="stop" data-focus-key="stop" value="${escape(draft.stop)}" ${locked} required><p class="field-error" data-error="stop"></p></div>
      </div>
      <div class="schedule-preview" data-preview aria-live="polite"></div>
      <p class="field-error form-error" data-error="form" role="alert"></p>
      <div class="schedule-buttons"><button class="button primary" type="submit" data-sched-submit ${enabled ? '' : 'disabled'}>Save schedule</button><button class="button secondary" type="button" data-sched-action="cancel" ${active?.posting ? 'disabled' : ''}>Cancel</button></div>
    </form>`;
  }

  function allowanceStatus(entry) {
    const status = { available: false, skipAvailable: false, until: null };
    const basis = state.scheduleClockBasis, observedAt = state.people?.observedAt;
    if (!integration() || !basis || !entry.schedules.length || state.offline || state.localUnknown || state.needsRefresh ||
        entry.observationHealth !== 'healthy' || !Number.isSafeInteger(observedAt)) return status;
    const wall = Date.now() / 1000, elapsed = Math.max(0, performance.now() / 1000 - basis.started);
    const expected = basis.wall + elapsed, current = Math.max(wall, expected, observedAt + elapsed);
    if (Math.abs(wall - expected) > 1 || observedAt + MAX_SCHEDULE_CLAIM_SECONDS <= current) return status;
    const checkedAt = entry.scheduleCheckedAt, validUntil = entry.scheduleValidUntil;
    const claimNow = Math.max(current, checkedAt + elapsed);
    if (entry.scheduleWitness !== 'owner-reviewed-clock' || !Number.isSafeInteger(checkedAt) || !Number.isSafeInteger(validUntil) ||
        Math.abs(basis.wall - checkedAt) > 1 || validUntil <= claimNow ||
        validUntil > checkedAt + MAX_SCHEDULE_CLAIM_SECONDS) return status;
    const until = entry.allowance?.until;
    if (Number.isSafeInteger(until) && until > claimNow && until * 1000 <= 8.64e15) status.until = until;
    const allowanceDeadline = entry.scheduleAllowanceValidUntil;
    status.available = Number.isSafeInteger(allowanceDeadline) && allowanceDeadline > claimNow;
    status.skipAvailable = status.available && entry.scheduleSkipTonightAvailable === true;
    return status;
  }

  function allowanceAvailable(entry, mode) {
    const status = allowanceStatus(entry);
    return mode === 'skip' ? status.skipAvailable : status.available;
  }

  function allowanceMarkup(entry, { available, skipAvailable, until }, enabled) {
    if (!integration() || !entry.schedules.length) return '';
    const key = escape(entry.id);
    const disabled = enabled && !view.open && !view.confirm ? '' : 'disabled';
    const deadline = until === null ? null : new Date(until * 1000).toISOString();
    return `<div class="schedule-buttons" role="group" aria-label="Schedule allowances for ${escape(entry.name)}">
      ${EXTRA_MINUTES.map(minutes => `<button class="button secondary" type="button" data-sched-action="extra" data-person-id="${key}" data-minutes="${minutes}" data-focus-key="extra-${key}-${minutes}" ${available ? disabled : 'disabled'}>Add ${minutes} minutes of extra time</button>`).join('')}
      <button class="button secondary" type="button" data-sched-action="skip" data-person-id="${key}" data-focus-key="skip-${key}" ${skipAvailable ? disabled : 'disabled'}>Skip tonight</button>
    </div>
    <p class="fine-print">Skip tonight covers an active schedule for up to 60 minutes. It may end before the schedule does.</p>
    ${deadline ? `<p class="fine-print">Router reported extra time until <time datetime="${deadline}">${deadline.slice(11, 16)} UTC on ${deadline.slice(0, 10)}</time>.</p>` : ''}`;
  }

  function cardMarkup(entry, enabled, allowance) {
    const key = escape(entry.id), name = escape(entry.name);
    const atIntegrationLimit = integration() && entry.schedules.length >= MAX_INTEGRATION_WINDOWS;
    const clock = integration() && entry.schedules.length ? [
      entry.scheduleTimezone && `Configured router timezone: ${escape(entry.scheduleTimezone)}.`,
      entry.scheduleWitness === 'unverified' && 'Router clock unverified.',
    ].filter(Boolean).join(' ') : '';
    const open = view.open?.person === entry.id, confirming = view.confirm?.person === entry.id;
    const items = entry.schedules.map((schedule) => {
      const id = escape(schedule.id);
      return `<li class="schedule-item" data-schedule-id="${id}"><div class="schedule-summary"><strong>${id}</strong><span>${escape(describe(schedule))}</span>
        <details><summary>Each window</summary><ul class="window-list">${previewWindows(schedule.weekdays, schedule.start, schedule.stop).map((line) => `<li>${escape(line)}</li>`).join('')}</ul></details></div>
        <div class="schedule-actions"><button class="button secondary" type="button" data-sched-action="edit" data-person-id="${key}" data-schedule="${id}" aria-label="Edit schedule ${id} for ${name}" ${enabled ? '' : 'disabled'}>Edit</button>
        <button class="button secondary" type="button" data-sched-action="delete" data-person-id="${key}" data-schedule="${id}" aria-label="Delete schedule ${id} for ${name}" ${enabled ? '' : 'disabled'}>Delete</button></div></li>`;
    }).join('');
    const confirm = confirming ? `<div class="schedule-confirm" role="group" aria-label="Confirm deletion"><p>Delete schedule <strong>${escape(view.confirm.id)}</strong> for ${name}? Access stays blocked only by the windows that remain.</p>
      <div class="schedule-buttons"><button class="button primary" type="button" data-sched-action="confirm-delete" data-focus-key="confirm-delete" ${enabled ? '' : 'disabled'}>Confirm delete ${escape(view.confirm.id)}</button><button class="button secondary" type="button" data-sched-action="cancel-delete" ${active?.posting ? 'disabled' : ''}>Keep it</button></div></div>` : '';
    return `<article class="schedule-card" data-schedule-person="${key}" aria-labelledby="sched-title-${key}">
      <h3 id="sched-title-${key}">Schedules for ${name}</h3>
      ${clock ? `<p class="fine-print">${clock}</p>` : ''}
      ${entry.schedules.length ? `<ul class="schedule-list" aria-label="Schedules for ${name}">${items}</ul>` : '<p class="fine-print">No weekly schedule windows.</p>'}
      ${allowanceMarkup(entry, allowance, enabled)}
      ${confirm}
      ${open ? formMarkup(entry, enabled) : `<button class="button secondary" type="button" data-sched-action="add" data-person-id="${key}" data-focus-key="add-${key}" ${enabled && !atIntegrationLimit ? '' : 'disabled'}>Add a schedule for ${name}</button>`}
      ${atIntegrationLimit ? `<p class="fine-print">This child has the maximum of ${MAX_INTEGRATION_WINDOWS} schedule windows.</p>` : ''}
    </article>`;
  }

  function updateLive() {
    const form = root.querySelector('[data-schedule-form]');
    if (!form || !view.open) return;
    const { draft } = view.open, errors = errorsNow();
    for (const element of form.querySelectorAll('[data-error]')) element.textContent = errors[element.dataset.error] ?? '';
    for (const input of form.querySelectorAll('[data-field]')) input.toggleAttribute('aria-invalid', Boolean(errors[input.dataset.field === 'day' ? 'weekdays' : input.dataset.field]));
    const lines = previewWindows(draft.weekdays, draft.start, draft.stop), entry = person(view.open.person);
    const clash = entry && lines.length ? entry.schedules.filter((schedule) => schedule.id !== view.open.originalId && overlaps(draft, schedule)).map((schedule) => schedule.id) : [];
    form.querySelector('[data-preview]').innerHTML = lines.length
      ? `<strong>Blocks access:</strong><ul class="window-list">${lines.map((line) => `<li>${escape(line)}</li>`).join('')}</ul>${clash.length ? `<p class="fine-print">Overlaps ${escape(clash.join(', '))}. Overlaps are allowed; access is blocked whenever any window is active.</p>` : ''}`
      : '<span class="fine-print">Choose days and two different times to preview the window.</span>';
  }

  function render() {
    if (active && active.generation !== state.generation) {
      active.controller.abort();
      active = null;
    }
    const people = editable();
    if (!state.people || people.length === 0) {
      if (!root.hidden || lastKey) { root.hidden = true; root.replaceChildren(); lastKey = ''; reset(); }
      return;
    }
    if ((view.open && !person(view.open.person)) || (view.confirm && !person(view.confirm.person))) reset();
    const enabled = !active && deps.canControl();
    const allowances = people.map(allowanceStatus);
    const key = JSON.stringify([integration(), allowances, people.map((entry) => [entry.id, entry.name, entry.schedules, entry.devices.length, entry.scheduleTimezone, entry.scheduleWitness]), enabled, Boolean(active), Boolean(active?.posting), view.open && [view.open.person, view.open.mode, view.open.originalId], view.confirm, view.serverErrors]);
    if (key === lastKey) return;
    lastKey = key;
    const focused = document.activeElement?.dataset?.focusKey;
    root.hidden = false;
    root.innerHTML = `<h2 id="schedules-title">Weekly schedules</h2>
      <p class="field-help">Each window blocks access on the chosen days between start and stop. A stop earlier than the start ends the next morning (for example Mon 22:00 → Tue 06:30). Times use the router clock${integration() ? '' : ' (UTC in this demo)'}. Windows may overlap; access is blocked whenever any window is active. Changes are requests until the router confirms them.</p>
      ${people.map((entry, index) => cardMarkup(entry, enabled, allowances[index])).join('')}`;
    updateLive();
    if (focused) root.querySelector(`[data-focus-key="${CSS.escape(focused)}"]`)?.focus();
  }

  function open(personId, mode, schedule) {
    const entry = person(personId);
    if (!entry) return;
    view = { open: { person: personId, mode, originalId: schedule?.id ?? null, snapshot: windowSnapshot(schedule), draft: schedule ? { id: schedule.id, weekdays: [...schedule.weekdays], start: schedule.start, stop: schedule.stop } : { id: nextId(entry), weekdays: [], start: '', stop: '' } }, confirm: null, submitted: false, serverErrors: {} };
    lastKey = '';
    render();
    root.querySelector(mode === 'edit' ? '[data-field="day"]' : '[data-field="id"]')?.focus();
  }

  function close() {
    if (active?.posting) return;
    if (active) {
      active.controller.abort();
      deps.announce('Schedule change cancelled before it was queued.');
    }
    reset(); lastKey = ''; render();
  }

  function fail(code, message) {
    const field = SERVER_FIELD[code];
    view.serverErrors = { [field ?? 'form']: message };
    lastKey = '';
    render();
  }

  async function submit({ personId, mode, scheduleId, draft, minutes }) {
    if (active) return;
    const allowance = mode === 'extra' || mode === 'skip';
    const generation = state.generation, beforeRevision = state.people.revisionToken, beforeSession = sessionKey(state.session);
    const attempt = { generation, controller: new AbortController(), posting: false }, intentView = view;
    const originalWindow = mode === 'delete' ? view.confirm.snapshot : view.open?.snapshot;
    const scheduleAction = SCHEDULE_ACTION[mode];
    const isIntegration = integration();
    const operationAction = allowance ? 'allow' : isIntegration ? 'schedule_update' : scheduleAction;
    const sameIntent = () => active === attempt && generation === state.generation && intentView === view;
    const sameSession = () => generation === state.generation && beforeSession === sessionKey(state.session);
    const headers = { 'If-Match': beforeRevision, 'Idempotency-Key': crypto.randomUUID(), 'X-CSRF-Token': state.session.csrfToken };
    const parent = `/people/${encodeURIComponent(personId)}`, base = `${parent}/schedules`;
    const window = draft && { weekdays: [...draft.weekdays], start: draft.start, stop: draft.stop };
    const [path, body] = mode === 'extra' ? [`${parent}/schedule-extra-time`, { minutes }]
      : mode === 'skip' ? [`${parent}/schedule-skip-tonight`, {}]
        : mode === 'create' ? [base, { id: draft.id, ...window }]
          : mode === 'edit' ? [`${base}/${encodeURIComponent(scheduleId)}`, window]
            : [`${base}/${encodeURIComponent(scheduleId)}/delete`, {}];
    async function send(content) {
      attempt.posting = true;
      render();
      try {
        return await deps.api(path, { method: 'POST', body: content, headers });
      } finally {
        attempt.posting = false;
        render();
      }
    }
    const notice = (message) => {
      if (!sameIntent()) return;
      deps.announce(message, true);
      if (draft) fail(null, message);
    };
    function writeSessionCurrent() {
      if (sameSession()) return true;
      // Keep old-session operation details out of the new scope, but require observation before another write.
      if (generation === state.generation) {
        state.needsRefresh = true;
        state.localUnknown = true;
        deps.announce('Outcome unknown. The session changed while the schedule request was pending. Refresh status before another action.', true);
      }
      return false;
    }
    async function refreshIntent() {
      const refreshed = await deps.refresh({ quiet: true });
      if (!sameIntent()) return false;
      if (!refreshed) {
        notice('Could not refresh status. No schedule change was queued.');
        return false;
      }
      if (!sameSession() || beforeRevision !== state.people?.revisionToken) {
        notice('Schedules changed elsewhere or permissions changed. Review the current schedules and save again.');
        return false;
      }
      const entry = person(personId);
      if (scheduleId && originalWindow !== windowSnapshot(entry?.schedules.find((schedule) => schedule.id === scheduleId))) {
        notice('The window changed since you opened it. Close this draft or confirmation and open the current window before trying again.');
        return false;
      }
      if (!deps.canControl() || !entry) {
        notice('Schedule controls are unavailable after refreshing status. No change was queued.');
        return false;
      }
      if (allowance && !allowanceAvailable(entry, mode)) {
        const label = mode === 'skip' ? 'Skip tonight' : 'Schedule extra time';
        notice(`${label} is unavailable after refreshing status. No change was queued.`);
        return false;
      }
      return true;
    }
    active = attempt;
    render();
    let phase = 'status', busy = false;
    try {
      if (!await refreshIntent()) return;
      deps.setBusy(true); busy = true;
      const request = allowance ? 'schedule allowance' : mode === 'delete' ? 'schedule removal' : 'schedule';
      deps.announce(`Sending ${request} request. A request is not confirmation.`);
      phase = 'request';
      let result;
      try {
        result = await send(body);
      } catch (error) {
        if (allowance || !isIntegration || error?.status !== 403 || error?.code !== 'step_up_required') throw error;
        if (!writeSessionCurrent() || !sameIntent()) return;
        deps.announce('Confirm with your passkey to continue.');
        phase = 'options';
        const requestedAt = performance.now();
        const { options, challengeId } = await deps.api('/step-up/options', { method: 'POST', signal: attempt.controller.signal,
          headers: { 'X-CSRF-Token': headers['X-CSRF-Token'] },
          body: { action: 'schedule_change', person: personId, scheduleAction, precondition: beforeRevision, change: body, ...(scheduleId ? { scheduleId } : {}) } });
        if (!sameIntent() || !sameSession()) return;
        const timeout = options?.timeout;
        if (!Number.isFinite(timeout) || timeout <= 0) {
          notice('The service did not provide a valid passkey timeout. No schedule change was queued.');
          return;
        }
        if (performance.now() - requestedAt >= timeout) {
          notice('Passkey confirmation expired. Review the schedule and save again.');
          return;
        }
        phase = 'prompt';
        const response = await getPasskey(options, attempt.controller.signal);
        if (!sameIntent() || !sameSession()) return;
        // Refresh takes the app's control lock synchronously, before this turn yields to other input.
        // The editor keeps its own lock across refresh and proof submission.
        deps.setBusy(false); busy = false;
        phase = 'status';
        if (!await refreshIntent()) return;
        if (performance.now() - requestedAt >= timeout) {
          notice('Passkey confirmation expired. Review the schedule and save again.');
          return;
        }
        deps.setBusy(true); busy = true;
        phase = 'proof';
        result = await send({ ...body, stepUp: { challengeId, response } });
      }
      if (!writeSessionCurrent()) return;
      const operation = result?.operation;
      if (typeof operation?.id !== 'string' || !operation.id || operation.personId !== personId || operation.action !== operationAction ||
          !['pending', 'unknown', 'confirmed', 'failed', 'conflict'].includes(operation.state)) {
        throw new Error('Unrecognized schedule operation');
      }
      state.operation = operation;
      const entry = state.people.people.find((candidate) => candidate.id === personId);
      if (entry) { entry.latestOperation = operation; entry.status = operation.state; }
      deps.announce(deps.operationText(operation));
      reset(); lastKey = '';
      deps.setBusy(false); busy = false;
      if (['pending', 'unknown'].includes(operation.state)) void deps.followOperation(operation.id, generation);
      else await deps.refresh({ quiet: true });
    } catch (error) {
      const write = phase === 'request' || phase === 'proof';
      if (write ? !writeSessionCurrent() : !sameSession()) return;
      const status = error?.status, code = error?.code;
      // Demo routes retain their existing HTTP refusal semantics. Integration requires a known pre-write code.
      const demoRefusal = !isIntegration && write && typeof status === 'number';
      if (phase === 'prompt') {
        notice(['NotAllowedError', 'AbortError'].includes(error?.name)
          ? 'Passkey confirmation was cancelled. No schedule change was queued.'
          : 'The passkey could not be read. No schedule change was queued.');
      } else if (phase === 'proof' && [401, 403].includes(status) && PASSKEY_REFUSALS.has(code)) {
        notice('The service refused the passkey confirmation. Review the schedule and save again.');
      } else if ((demoRefusal && [401, 403].includes(status)) ||
          (status === 401 && SESSION_REFUSALS.has(code)) || (status === 403 && code === 'csrf_rejected')) {
        deps.unauthorized();
      } else if (phase === 'options' || phase === 'status') {
        notice('Could not complete schedule confirmation. No change was queued.');
      } else if ((status === 409 && (code === 'revision_conflict' || demoRefusal && code !== 'schedule_id_exists')) ||
          (status === 404 && code === 'schedule_not_found')) {
        state.needsRefresh = true;
        deps.setBusy(false); busy = false;
        const refreshed = await deps.refresh({ quiet: true });
        if (!sameSession()) return;
        const reason = status === 409 ? 'Revision conflict. Schedules changed elsewhere.' : 'That schedule no longer exists.';
        notice(`${reason} ${refreshed ? 'Review the current schedules before trying again.' : 'Refresh status before trying again.'}`);
        if (demoRefusal && (status === 404 || mode === 'delete') && sameIntent()) { reset(); lastKey = ''; }
      } else if (demoRefusal || WRITE_REFUSALS[status]?.includes(code) || (allowance && ALLOWANCE_REFUSALS[status]?.includes(code))) {
        if (demoRefusal || ['operation_in_progress', 'person_has_no_enrolled_device', 'approved_router_observation_required', 'router_runtime_unconfirmed',
          'child_paused', 'schedule_clock_unverified', 'schedule_not_active'].includes(code)) {
          state.needsRefresh = true;
        }
        const refusal = (allowance ? ALLOWANCE_TEXT[code] : undefined) ?? REFUSAL_TEXT[code];
        const message = demoRefusal ? error.message : refusal ?? error.message;
        deps.announce(demoRefusal ? `The schedule request failed: ${message} Nothing was changed.`
          : refusal ?? `The service refused the schedule change. ${message}`, true);
        if (draft) fail(code, message);
      } else {
        state.needsRefresh = true;
        state.localUnknown = true;
        state.offline = !navigator.onLine;
        notice('Outcome unknown. The change may have reached the router. No retry is queued. Refresh status before another action.');
      }
    } finally {
      if (active === attempt) {
        active = null;
        if (generation === state.generation) { if (busy) deps.setBusy(false); deps.render(); }
      }
    }
  }

  async function save() {
    if (!view.open || active) return;
    view.submitted = true; view.serverErrors = {};
    const errors = validateDraft(view.open.draft, context());
    if (Object.keys(errors).length) {
      updateLive();
      const first = ['id', 'weekdays', 'start', 'stop'].find((field) => errors[field]);
      root.querySelector(first === 'weekdays' ? '[data-field="day"]' : first ? `[data-field="${first}"]` : '[data-sched-submit]')?.focus();
      return;
    }
    if (!deps.canControl()) { view.serverErrors = { form: 'Controls are unavailable until status is refreshed. Nothing was sent.' }; lastKey = ''; render(); return; }
    const { person: personId, mode, originalId, draft } = view.open;
    await submit({ personId, mode, scheduleId: originalId, draft });
  }

  root.addEventListener('input', (event) => {
    const field = event.target.dataset?.field;
    if (!field || !view.open || active) return;
    const { draft } = view.open;
    if (field === 'day') {
      const days = new Set(draft.weekdays);
      if (event.target.checked) days.add(event.target.value); else days.delete(event.target.value);
      draft.weekdays = DAYS.filter((day) => days.has(day));
    } else draft[field] = event.target.value;
    view.serverErrors = {};
    updateLive();
  });
  root.addEventListener('submit', (event) => { event.preventDefault(); void save(); });
  root.addEventListener('click', (event) => {
    const button = event.target.closest('[data-sched-action]');
    if (!button || button.disabled) return;
    const action = button.dataset.schedAction, entry = person(button.dataset.personId ?? view.open?.person ?? view.confirm?.person);
    const window = entry?.schedules.find((schedule) => schedule.id === button.dataset.schedule);
    if (action === 'add') open(button.dataset.personId, 'create');
    else if (action === 'edit' && window) open(button.dataset.personId, 'edit', window);
    else if (action === 'cancel') close();
    else if (action === 'delete' && window) {
      view = { open: null, confirm: { person: entry.id, id: window.id, snapshot: windowSnapshot(window) }, submitted: false, serverErrors: {} };
      lastKey = ''; render(); root.querySelector('[data-focus-key="confirm-delete"]')?.focus();
    }
    else if (action === 'cancel-delete') close();
    else if (action === 'confirm-delete' && view.confirm) {
      const { person: personId, id } = view.confirm;
      if (deps.canControl()) void submit({ personId, mode: 'delete', scheduleId: id });
    } else if ((action === 'extra' || action === 'skip') && entry && !view.open && !view.confirm && deps.canControl() && allowanceAvailable(entry, action)) {
      const minutes = Number(button.dataset.minutes);
      if (action === 'skip' || EXTRA_MINUTES.includes(minutes)) void submit({ personId: entry.id, mode: action, minutes });
    }
  });

  return { render };
}
