import { actorScope } from './status-cache.js';

// Client-side bounds mirror shared/src/router-schema.ts (the service re-validates authoritatively).
export const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
export const ID_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
export const CLOCK_PATTERN = /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/;
export const MAX_SCHEDULES = 256;
export const MAX_EXPANDED_WINDOWS = 256;

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
export function validateDraft(draft, { schedules, editingId = null, deviceCount }) {
  const errors = {};
  if (!ID_PATTERN.test(draft.id)) errors.id = 'Use a lowercase letter first, then lowercase letters, digits or underscores (up to 32 characters).';
  else if (editingId === null && schedules.some((schedule) => schedule.id === draft.id)) errors.id = 'A schedule with this name already exists.';
  if (!Array.isArray(draft.weekdays) || draft.weekdays.length === 0 || draft.weekdays.some((day) => !DAYS.includes(day))) errors.weekdays = 'Choose at least one day.';
  if (!CLOCK_PATTERN.test(draft.start)) errors.start = 'Enter a start time (HH:MM, 24-hour).';
  if (!CLOCK_PATTERN.test(draft.stop)) errors.stop = 'Enter a stop time (HH:MM, 24-hour).';
  if (!errors.start && !errors.stop && draft.start === draft.stop) errors.form = 'Start and stop must differ; an empty window is not allowed.';
  if (!errors.start && !errors.stop && !errors.form) {
    const others = schedules.filter((schedule) => schedule.id !== editingId);
    if (others.length + 1 > MAX_SCHEDULES) errors.form = `At most ${MAX_SCHEDULES} schedules are allowed.`;
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
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const describe = (schedule) => `${orderedDays(schedule.weekdays).join(', ')} · ${schedule.start} → ${schedule.stop}${crossesMidnight(schedule.start, schedule.stop) ? ' (next day)' : ''}`;

/**
 * Parent-app schedule editor. All writes use the same If-Match / Idempotency-Key / CSRF protocol as pause and
 * resume; the editor never retries, queues, or applies a change locally before the service confirms it.
 */
export function createScheduleEditor(deps) {
  const { root, state } = deps;
  let view = { open: null, confirm: null, submitted: false, serverErrors: {} };
  let lastKey = '';

  const editable = () => (state.people?.people ?? []).filter((person) => person.schedulesEditable === true && Array.isArray(person.schedules));
  const person = (id) => editable().find((entry) => entry.id === id);
  const reset = () => { view = { open: null, confirm: null, submitted: false, serverErrors: {} }; };
  const context = () => {
    const entry = person(view.open.person);
    return { schedules: entry.schedules, editingId: view.open.mode === 'edit' ? view.open.originalId : null, deviceCount: entry.devices.length };
  };
  const errorsNow = () => ({ ...(view.submitted ? validateDraft(view.open.draft, context()) : {}), ...view.serverErrors });

  function nextId(entry) {
    for (let index = 1; index <= MAX_SCHEDULES + 1; index++) if (!entry.schedules.some((schedule) => schedule.id === `window_${index}`)) return `window_${index}`;
    return '';
  }

  function formMarkup(entry) {
    const { mode, draft } = view.open, key = escape(entry.id), title = mode === 'edit' ? `Edit ${escape(view.open.originalId)}` : `Add a schedule for ${escape(entry.name)}`;
    const day = (name) => `<label class="day-choice"><input type="checkbox" data-field="day" value="${name}" ${draft.weekdays.includes(name) ? 'checked' : ''} data-focus-key="day-${name}"> ${name}</label>`;
    return `<form class="schedule-form" data-schedule-form novalidate aria-labelledby="sched-form-title-${key}">
      <h4 id="sched-form-title-${key}">${title}</h4>
      <div class="schedule-field"><label for="sched-id-${key}">Name</label><input id="sched-id-${key}" data-field="id" data-focus-key="id" value="${escape(draft.id)}" maxlength="32" autocomplete="off" autocapitalize="none" spellcheck="false" ${mode === 'edit' ? 'readonly' : ''} aria-describedby="sched-id-help-${key} sched-id-error-${key}">
        <p class="field-help" id="sched-id-help-${key}">Lowercase letters, digits and underscores; starts with a letter.</p><p class="field-error" data-error="id" id="sched-id-error-${key}"></p></div>
      <fieldset class="schedule-days"><legend>Days</legend><div class="day-row">${DAYS.map(day).join('')}</div><p class="field-error" data-error="weekdays"></p></fieldset>
      <div class="time-row">
        <div class="schedule-field"><label for="sched-start-${key}">Start</label><input id="sched-start-${key}" type="time" step="60" data-field="start" data-focus-key="start" value="${escape(draft.start)}" required><p class="field-error" data-error="start"></p></div>
        <div class="schedule-field"><label for="sched-stop-${key}">Stop</label><input id="sched-stop-${key}" type="time" step="60" data-field="stop" data-focus-key="stop" value="${escape(draft.stop)}" required><p class="field-error" data-error="stop"></p></div>
      </div>
      <div class="schedule-preview" data-preview aria-live="polite"></div>
      <p class="field-error form-error" data-error="form" role="alert"></p>
      <div class="schedule-buttons"><button class="button primary" type="submit" data-sched-submit ${deps.canControl() ? '' : 'disabled'}>Save schedule</button><button class="button secondary" type="button" data-sched-action="cancel">Cancel</button></div>
    </form>`;
  }

  function cardMarkup(entry, enabled) {
    const key = escape(entry.id), name = escape(entry.name);
    const open = view.open?.person === entry.id, confirming = view.confirm?.person === entry.id;
    const items = entry.schedules.map((schedule) => {
      const id = escape(schedule.id);
      return `<li class="schedule-item" data-schedule-id="${id}"><div class="schedule-summary"><strong>${id}</strong><span>${escape(describe(schedule))}</span>
        <details><summary>Each window</summary><ul class="window-list">${previewWindows(schedule.weekdays, schedule.start, schedule.stop).map((line) => `<li>${escape(line)}</li>`).join('')}</ul></details></div>
        <div class="schedule-actions"><button class="button secondary" type="button" data-sched-action="edit" data-person-id="${key}" data-schedule="${id}" aria-label="Edit schedule ${id} for ${name}" ${enabled ? '' : 'disabled'}>Edit</button>
        <button class="button secondary" type="button" data-sched-action="delete" data-person-id="${key}" data-schedule="${id}" aria-label="Delete schedule ${id} for ${name}" ${enabled ? '' : 'disabled'}>Delete</button></div></li>`;
    }).join('');
    const confirm = confirming ? `<div class="schedule-confirm" role="group" aria-label="Confirm deletion"><p>Delete schedule <strong>${escape(view.confirm.id)}</strong> for ${name}? Access stays blocked only by the windows that remain.</p>
      <div class="schedule-buttons"><button class="button primary" type="button" data-sched-action="confirm-delete" data-focus-key="confirm-delete" ${enabled ? '' : 'disabled'}>Confirm delete ${escape(view.confirm.id)}</button><button class="button secondary" type="button" data-sched-action="cancel-delete">Keep it</button></div></div>` : '';
    return `<article class="schedule-card" data-schedule-person="${key}" aria-labelledby="sched-title-${key}">
      <h3 id="sched-title-${key}">Schedules for ${name}</h3>
      ${entry.schedules.length ? `<ul class="schedule-list" aria-label="Schedules for ${name}">${items}</ul>` : '<p class="fine-print">No weekly schedule windows.</p>'}
      ${confirm}
      ${open ? formMarkup(entry) : `<button class="button secondary" type="button" data-sched-action="add" data-person-id="${key}" data-focus-key="add-${key}" ${enabled ? '' : 'disabled'}>Add a schedule for ${name}</button>`}
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
    const people = editable();
    if (!state.people || people.length === 0) {
      if (!root.hidden || lastKey) { root.hidden = true; root.replaceChildren(); lastKey = ''; reset(); }
      return;
    }
    if (view.open && !person(view.open.person)) reset();
    const enabled = deps.canControl();
    const key = JSON.stringify([people.map((entry) => [entry.id, entry.name, entry.schedules, entry.devices.length]), enabled, view.open && [view.open.person, view.open.mode, view.open.originalId], view.confirm, view.serverErrors]);
    if (key === lastKey) return;
    lastKey = key;
    const focused = document.activeElement?.dataset?.focusKey;
    root.hidden = false;
    root.innerHTML = `<h2 id="schedules-title">Weekly schedules</h2>
      <p class="field-help">Each window blocks access on the chosen days between start and stop. A stop earlier than the start ends the next morning (for example Mon 22:00 → Tue 06:30). Times use the router clock (UTC in this demo). Windows may overlap; access is blocked whenever any window is active. Changes are requests until the router confirms them.</p>
      ${people.map((entry) => cardMarkup(entry, enabled)).join('')}`;
    updateLive();
    if (focused) root.querySelector(`[data-focus-key="${CSS.escape(focused)}"]`)?.focus();
  }

  function open(personId, mode, schedule) {
    const entry = person(personId);
    if (!entry) return;
    view = { open: { person: personId, mode, originalId: schedule?.id ?? null, draft: schedule ? { id: schedule.id, weekdays: [...schedule.weekdays], start: schedule.start, stop: schedule.stop } : { id: nextId(entry), weekdays: [], start: '', stop: '' } }, confirm: null, submitted: false, serverErrors: {} };
    lastKey = '';
    render();
    root.querySelector(mode === 'edit' ? '[data-field="day"]' : '[data-field="id"]')?.focus();
  }

  function close() { reset(); lastKey = ''; render(); }

  function fail(code, message) {
    const field = SERVER_FIELD[code];
    view.serverErrors = { [field ?? 'form']: message };
    lastKey = '';
    render();
  }

  async function submit(personId, mode, scheduleId, draft) {
    const generation = state.generation, beforeRevision = state.people.revisionToken, beforeScope = actorScope(state.session.actor);
    // The fresh read belongs to this click; the write itself is never retried automatically.
    const refreshed = await deps.refresh({ quiet: true });
    if (!refreshed || generation !== state.generation || !deps.canControl()) return;
    if (beforeRevision !== state.people.revisionToken || beforeScope !== actorScope(state.session.actor)) {
      deps.announce('Schedules or permissions changed elsewhere. They were reloaded; review them and save again.', true);
      view.serverErrors = mode === 'delete' ? {} : { form: 'Schedules changed elsewhere. The current schedules were reloaded; review and save again.' };
      lastKey = ''; render();
      return;
    }
    deps.setBusy(true);
    deps.announce(`Sending ${mode === 'delete' ? 'schedule removal' : 'schedule'} request. A request is not confirmation.`);
    const base = `/people/${encodeURIComponent(personId)}/schedules`;
    const [path, body] = mode === 'create' ? [base, { id: draft.id, weekdays: draft.weekdays, start: draft.start, stop: draft.stop }]
      : mode === 'edit' ? [`${base}/${encodeURIComponent(scheduleId)}`, { weekdays: draft.weekdays, start: draft.start, stop: draft.stop }]
        : [`${base}/${encodeURIComponent(scheduleId)}/delete`, {}];
    try {
      const result = await deps.api(path, { method: 'POST', body, headers: { 'If-Match': beforeRevision, 'Idempotency-Key': crypto.randomUUID(), 'X-CSRF-Token': state.session.csrfToken } });
      if (generation !== state.generation) return;
      state.operation = result.operation;
      const entry = state.people.people.find((candidate) => candidate.id === personId);
      if (entry) { entry.latestOperation = result.operation; entry.status = result.operation.state; }
      deps.announce(deps.operationText(result.operation));
      reset(); lastKey = '';
      deps.setBusy(false);
      if (['pending', 'unknown'].includes(result.operation.state)) void deps.followOperation(result.operation.id, generation);
      else await deps.refresh({ quiet: true });
    } catch (error) {
      if (generation !== state.generation) return;
      state.needsRefresh = true;
      const status = error?.status, code = error?.code;
      if ([401, 403].includes(status)) {
        deps.unauthorized();
      } else if (typeof status === 'number') {
        deps.setBusy(false);
        if (status === 409 && code !== 'schedule_id_exists') {
          deps.announce('Revision conflict. No retry was sent. The current schedules were reloaded; review them and save again.', true);
          view.serverErrors = mode === 'delete' ? {} : { form: 'Conflict: the schedules changed since you opened this form. The latest version was reloaded; review and save again.' };
          if (mode === 'delete') view.confirm = null;
          lastKey = '';
          await deps.refresh({ quiet: true });
        } else if (status === 404 && code === 'schedule_not_found') {
          deps.announce('That schedule no longer exists. The current schedules were reloaded.', true);
          reset(); lastKey = '';
          await deps.refresh({ quiet: true });
        } else {
          deps.announce(`The schedule request failed: ${error.message} Nothing was changed.`, true);
          if (mode !== 'delete') fail(code, error.message);
        }
      } else {
        state.localUnknown = true;
        state.offline = !navigator.onLine;
        deps.announce('Outcome unknown. The response was lost; the change may have reached the router. No retry is queued. Reconnect and refresh status before another action.', true);
      }
    } finally {
      if (generation === state.generation) { deps.setBusy(false); deps.render(); }
    }
  }

  async function save() {
    if (!view.open) return;
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
    await submit(personId, mode, originalId, draft);
  }

  root.addEventListener('input', (event) => {
    const field = event.target.dataset?.field;
    if (!field || !view.open) return;
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
    if (action === 'add') open(button.dataset.personId, 'create');
    else if (action === 'edit') open(button.dataset.personId, 'edit', entry?.schedules.find((schedule) => schedule.id === button.dataset.schedule));
    else if (action === 'cancel') close();
    else if (action === 'delete') { view = { open: null, confirm: { person: button.dataset.personId, id: button.dataset.schedule }, submitted: false, serverErrors: {} }; lastKey = ''; render(); root.querySelector('[data-focus-key="confirm-delete"]')?.focus(); }
    else if (action === 'cancel-delete') close();
    else if (action === 'confirm-delete' && view.confirm) {
      const { person: personId, id } = view.confirm;
      if (deps.canControl()) void submit(personId, 'delete', id, null);
    }
  });

  return { render };
}
