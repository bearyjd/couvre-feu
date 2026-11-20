// Parent-side Focus window buttons (a labelled timed pause of 15 to 120 minutes for a child). All dynamic text is escaped or fixed.
// Nothing is optimistic: the page says "Focus window requested" only once the service reports the operation confirmed. The "Focus" chip on the
// person card comes from person.pauseLabel === 'focus', which the service sets only while that very pause is in force.
// The controls are offered only while the service says the feature is on for this viewer (people.focusWindow === true). As a fallback, a
// route_not_found answer to a tap hides every control for the session; a person_not_found answer only retires that one child's controls.
const MINUTES = [15, 30, 45, 60, 90, 120];
// Parent-friendly text per service refusal. Unknown codes get the generic text; a raw code is never shown.
const REFUSAL_TEXT = {
  child_paused: 'This child is already paused. End the pause first, then start a focus window.',
  invalid_minutes: 'That length is not available. Choose one of the buttons.',
  revision_conflict: 'The status changed, so nothing was sent. It has been refreshed; choose again.',
  operation_in_progress: 'Another change is still being applied. Wait for it to finish, then try again.',
};
const GENERIC_REFUSAL = 'The focus window could not be started. Nothing was changed.';
const refusalText = (code) => (Object.hasOwn(REFUSAL_TEXT, code) ? REFUSAL_TEXT[code] : GENERIC_REFUSAL);
const NOT_FOR_CHILD = 'A focus window is not available for this child.';

export function createFocusWindow({ session, people, send, refresh, render, escape }) {
  let key = '', hidden = false, wantFocus = '';
  const entries = new Map(); // person id -> { minutes, starting?, opId?, text?, unavailable? }
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.csrfToken}` : ''; };
  // A different (or no) session owns nothing the previous one showed.
  const sync = () => { const next = sessionKey(); if (next !== key) { key = next; hidden = false; wantFocus = ''; entries.clear(); } return key; };

  const operationOf = (entry, person) => (entry?.opId && person.latestOperation?.id === entry.opId ? person.latestOperation : null);
  // True while the service has not yet said whether the focus window was applied.
  const inFlight = (entry, person) => Boolean(entry?.starting || (entry?.opId && operationOf(entry, person)?.state === 'pending'));
  function statusText(entry, person) {
    if (!entry) return '';
    if (entry.starting) return 'Starting… sending the request. No focus window yet.';
    if (entry.text) return entry.text;
    const operation = operationOf(entry, person);
    if (!operation) return 'A later change replaced this request. Check the current status before trying again.';
    if (operation.state === 'pending') return 'Starting… waiting for the router to confirm. No focus window yet.';
    if (operation.state === 'unknown') return 'The router did not say whether the focus window started. Refresh and check before trying again.';
    if (operation.state !== 'confirmed') return 'The focus window was not started: the router did not confirm it.';
    return person.pauseLabel === 'focus' ? '' : 'The router confirmed the change. Waiting for the status to show the focus window.';
  }

  function buttons(person, busy) {
    const id = escape(person.id), label = escape(person.name);
    const one = (minutes) => `<button class="button secondary" type="button" data-focus-minutes="${minutes}" data-person-id="${id}" data-focus-key="focus-${minutes}-${id}" aria-label="Start a ${minutes} minute focus window for ${label}" ${busy ? 'disabled data-focus-busy' : ''}>Focus ${minutes} min</button>`;
    return `<div class="person-controls" role="group" aria-label="Focus window for ${label}">${MINUTES.map(one).join('')}</div>`;
  }

  function markup(person) {
    sync();
    if (!key || hidden || people()?.focusWindow !== true || person.kind === 'device_group') return '';
    const entry = entries.get(person.id), text = statusText(entry, person);
    // A child who is already paused cannot start a focus window (the existing pause wins); offer nothing until the pause ends.
    const blocked = Boolean(entry?.unavailable) || Boolean(person.effectiveManualPause);
    if (blocked && !text) return '';
    const id = escape(person.id);
    return `<div class="focus-window" data-focus-window="${id}">${blocked ? '' : buttons(person, inFlight(entry, person))}<p class="reason-detail" data-focus-status="${id}" role="status" aria-live="polite">${escape(text)}</p>${blocked ? '' : '<p class="reason-detail">A focus window pauses internet access for the chosen time. It counts only once the router confirms it.</p>'}</div>`;
  }

  async function tap(personId, minutes) {
    const asked = sync();
    if (!MINUTES.includes(minutes) || !asked || hidden || entries.get(personId)?.starting) return;
    entries.set(personId, { minutes, starting: true });
    wantFocus = `focus-${minutes}-${personId}`;
    render();
    const outcome = await send(personId, minutes);
    if (asked !== sessionKey()) return; // the session changed in flight: show nothing for the old one
    if (outcome.sent) entries.set(personId, { minutes, opId: outcome.operationId });
    else if (outcome.status === 404 && outcome.code === 'route_not_found') { hidden = true; entries.clear(); wantFocus = ''; }
    else if (outcome.status === 404) { entries.set(personId, { minutes, unavailable: true, text: NOT_FOR_CHILD }); wantFocus = ''; }
    else {
      entries.set(personId, { minutes, text: outcome.code ? refusalText(outcome.code) : outcome.reason ?? GENERIC_REFUSAL });
      if (outcome.code === 'revision_conflict') void refresh();
    }
    render();
  }

  // After a redraw the tapped button is a new element (and was disabled while starting): put focus back once it can take it.
  function afterRender() {
    if (!wantFocus) return;
    const active = document.activeElement;
    if (active && active !== document.body && active.dataset?.focusKey !== wantFocus) { wantFocus = ''; return; }
    const target = document.querySelector(`[data-focus-key="${CSS.escape(wantFocus)}"]`);
    if (target && !target.disabled) { target.focus(); wantFocus = ''; }
  }

  return { markup, tap, afterRender, signature: () => JSON.stringify([sync(), hidden, [...entries]]) };
}
