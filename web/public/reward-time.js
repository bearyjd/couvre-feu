// Parent-side Reward Time buttons (+15 / +30 min of extra time for a child). All dynamic text is escaped or fixed.
// Nothing is optimistic: "Extra time until" appears only once the service reports the operation confirmed AND the child's allowance in force.
// The service has no feature signal for Reward Time, so the controls are shown until the first tap answers 404 (feature off, not the owner,
// or out of scope); they are then hidden for the rest of the session with no error shown.
const MINUTES = [15, 30];
// Parent-friendly text per service refusal. Unknown codes get the generic text; a raw code is never shown.
const REFUSAL_TEXT = {
  reward_cap_exceeded: 'That would go past the 60 minute limit. Try a smaller amount, or wait for some of the current extra time to run out.',
  child_paused: 'This child is paused. End the pause first, then add extra time.',
  revision_conflict: 'The status changed, so nothing was sent. It has been refreshed; choose again.',
  operation_in_progress: 'Another change is still being applied. Wait for it to finish, then try again.',
};
const GENERIC_REFUSAL = 'Extra time could not be added. Nothing was changed.';
const refusalText = (code) => (Object.hasOwn(REFUSAL_TEXT, code) ? REFUSAL_TEXT[code] : GENERIC_REFUSAL);
const UNVERIFIED = 'unverified on this router';
const clock = (epoch) => new Date(epoch * 1000).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });

export function createRewardTime({ session, send, refresh, render, escape, now }) {
  let key = '', hidden = false, wantFocus = '';
  const entries = new Map(); // person id -> { minutes, starting?, opId?, text? }
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.csrfToken}` : ''; };
  // A different (or no) session owns nothing the previous one showed.
  const sync = () => { const next = sessionKey(); if (next !== key) { key = next; hidden = false; wantFocus = ''; entries.clear(); } return key; };

  const operationOf = (entry, person) => (entry?.opId && person.latestOperation?.id === entry.opId ? person.latestOperation : null);
  // True while the service has not yet said whether the extra time was applied.
  const inFlight = (entry, person) => Boolean(entry?.starting || (entry?.opId && operationOf(entry, person)?.state === 'pending'));
  function statusText(entry, person) {
    if (!entry) return '';
    if (entry.starting) return 'Applying… sending the request. No extra time yet.';
    if (entry.text) return entry.text;
    const operation = operationOf(entry, person);
    if (!operation) return 'A later change replaced this request. Check the current status before trying again.';
    if (operation.state === 'pending') return 'Applying… waiting for the router to confirm. No extra time yet.';
    if (operation.state === 'unknown') return 'The router did not say whether the extra time was applied. Refresh and check before trying again.';
    if (operation.state !== 'confirmed') return 'Extra time was not applied: the router did not confirm it.';
    return person.allowance && person.allowance.until > now()
      ? `Extra time until ${clock(person.allowance.until)} (${UNVERIFIED}).`
      : 'The router confirmed the change. Waiting for it to report the extra time.';
  }

  function markup(person) {
    sync();
    if (!key || hidden || person.kind === 'device_group') return '';
    const entry = entries.get(person.id), text = statusText(entry, person);
    // A paused child with no allowance cannot be given extra time (the pause wins); offer nothing until the pause ends.
    const blocked = Boolean(person.effectiveManualPause) && !person.allowance;
    if (blocked && !text) return '';
    const id = escape(person.id), label = escape(person.name), busy = inFlight(entry, person);
    const buttons = blocked ? '' : `<div class="person-controls" role="group" aria-label="Extra time for ${label}">${MINUTES.map((minutes) => `<button class="button secondary" type="button" data-reward-minutes="${minutes}" data-person-id="${id}" data-focus-key="reward-${minutes}-${id}" aria-label="Add ${minutes} minutes of extra time for ${label}" ${busy ? 'disabled data-reward-busy' : ''}>Reward +${minutes} min</button>`).join('')}</div>`;
    return `<div class="reward" data-reward="${id}">${buttons}<p class="reason-detail" data-reward-status="${id}" role="status" aria-live="polite">${escape(text)}</p>${blocked ? '' : `<p class="reason-detail">Extra time is ${UNVERIFIED}: it counts only once the router confirms it. Total extra time is capped at 60 minutes.</p>`}</div>`;
  }

  async function tap(personId, minutes) {
    const asked = sync();
    if (!asked || hidden || entries.get(personId)?.starting) return;
    entries.set(personId, { minutes, starting: true });
    wantFocus = `reward-${minutes}-${personId}`;
    render();
    const outcome = await send(personId, minutes);
    if (asked !== sessionKey()) return; // the session changed in flight: show nothing for the old one
    if (outcome.sent) entries.set(personId, { minutes, opId: outcome.operationId });
    else if (outcome.status === 404) { hidden = true; entries.clear(); wantFocus = ''; }
    else {
      entries.set(personId, { minutes, text: outcome.code ? refusalText(outcome.code) : outcome.reason ?? GENERIC_REFUSAL });
      if (outcome.code === 'revision_conflict') void refresh();
    }
    render();
  }

  // After a redraw the tapped button is a new element (and was disabled while applying): put focus back once it can take it.
  function afterRender() {
    if (!wantFocus) return;
    const active = document.activeElement;
    if (active && active !== document.body && active.dataset?.focusKey !== wantFocus) { wantFocus = ''; return; }
    const target = document.querySelector(`[data-focus-key="${CSS.escape(wantFocus)}"]`);
    if (target && !target.disabled) { target.focus(); wantFocus = ''; }
  }

  return { markup, tap, afterRender, signature: () => JSON.stringify([sync(), hidden, [...entries]]) };
}
