// Parent-side Reward Time buttons (+15 / +30 min of extra time for a child). All dynamic text is escaped or fixed.
// Nothing is optimistic: "Extra time until" appears only once the service reports the operation confirmed AND the child's allowance in force.
// The controls are offered only while the service says the feature is on for this viewer (people.rewardTime === true). As a fallback, a
// route_not_found answer to a tap hides every control for the session; a person_not_found answer only retires that one child's controls.
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
const NOT_FOR_CHILD = 'Extra time is not available for this child.';
// The end time is the router-reported allowance end, shown as a time of day. Whether it is current is judged against the service's
// observation time, never this device's clock.
const clock = (epoch) => new Date(epoch * 1000).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });

export function createRewardTime({ session, people, send, refresh, render, escape }) {
  let key = '', hidden = false, wantFocus = '';
  const entries = new Map(); // person id -> { minutes, starting?, opId?, text?, unavailable?, earliestEnd? }
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.csrfToken}` : ''; };
  // A different (or no) session owns nothing the previous one showed.
  const sync = () => { const next = sessionKey(); if (next !== key) { key = next; hidden = false; wantFocus = ''; entries.clear(); } return key; };

  const operationOf = (entry, person) => (entry?.opId && person.latestOperation?.id === entry.opId ? person.latestOperation : null);
  // True while the service has not yet said whether the extra time was applied.
  const inFlight = (entry, person) => Boolean(entry?.starting || (entry?.opId && operationOf(entry, person)?.state === 'pending'));
  // True only when the polled allowance is the post-reward one: still in force at the service's observation time and at least as late as the
  // earliest end this reward could produce (router time at the tap + any allowance already running + the minutes). A stale allowance is not shown.
  function reflectsReward(entry, person) {
    const observedAt = people()?.observedAt, until = person.allowance?.until;
    return Number.isFinite(entry.earliestEnd) && Number.isFinite(observedAt) && Number.isFinite(until) && until > observedAt && until >= entry.earliestEnd;
  }
  function statusText(entry, person) {
    if (!entry) return '';
    if (entry.starting) return 'Applying… sending the request. No extra time yet.';
    if (entry.text) return entry.text;
    const operation = operationOf(entry, person);
    if (!operation) return 'A later change replaced this request. Check the current status before trying again.';
    if (operation.state === 'pending') return 'Applying… waiting for the router to confirm. No extra time yet.';
    if (operation.state === 'unknown') return 'The router did not say whether the extra time was applied. Refresh and check before trying again.';
    if (operation.state !== 'confirmed') return 'Extra time was not applied: the router did not confirm it.';
    return reflectsReward(entry, person)
      ? `Extra time until ${clock(person.allowance.until)} (${UNVERIFIED}).`
      : 'The router confirmed the change. Waiting for it to report the extra time.';
  }

  function buttons(person, busy) {
    const id = escape(person.id), label = escape(person.name);
    const one = (minutes) => `<button class="button secondary" type="button" data-reward-minutes="${minutes}" data-person-id="${id}" data-focus-key="reward-${minutes}-${id}" aria-label="Add ${minutes} minutes of extra time for ${label}" ${busy ? 'disabled data-reward-busy' : ''}>Reward +${minutes} min</button>`;
    return `<div class="person-controls" role="group" aria-label="Extra time for ${label}">${MINUTES.map(one).join('')}</div>`;
  }

  function markup(person) {
    sync();
    if (!key || hidden || people()?.rewardTime !== true || person.kind === 'device_group') return '';
    const entry = entries.get(person.id), text = statusText(entry, person);
    // A paused child with no allowance cannot be given extra time (the pause wins); offer nothing until the pause ends.
    const blocked = Boolean(entry?.unavailable) || Boolean(person.effectiveManualPause) && !person.allowance;
    if (blocked && !text) return '';
    const id = escape(person.id);
    return `<div class="reward" data-reward="${id}">${blocked ? '' : buttons(person, inFlight(entry, person))}<p class="reason-detail" data-reward-status="${id}" role="status" aria-live="polite">${escape(text)}</p>${blocked ? '' : `<p class="reason-detail">Extra time is ${UNVERIFIED}: it counts only once the router confirms it. Total extra time is capped at 60 minutes.</p>`}</div>`;
  }

  async function tap(personId, minutes) {
    const asked = sync();
    if (!MINUTES.includes(minutes) || !asked || hidden || entries.get(personId)?.starting) return;
    const before = people(), allowance = before?.people.find((entry) => entry.id === personId)?.allowance;
    // Router time is at least the last observation, so this is a lower bound on the end the reward will produce.
    const earliestEnd = Number.isFinite(before?.observedAt) ? Math.max(allowance?.until ?? 0, before.observedAt) + minutes * 60 : null;
    entries.set(personId, { minutes, starting: true, earliestEnd });
    wantFocus = `reward-${minutes}-${personId}`;
    render();
    const outcome = await send(personId, minutes);
    if (asked !== sessionKey()) return; // the session changed in flight: show nothing for the old one
    if (outcome.sent) entries.set(personId, { minutes, opId: outcome.operationId, earliestEnd });
    else if (outcome.status === 404 && outcome.code === 'route_not_found') { hidden = true; entries.clear(); wantFocus = ''; }
    else if (outcome.status === 404) { entries.set(personId, { minutes, unavailable: true, text: NOT_FOR_CHILD }); wantFocus = ''; }
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

  return { markup, tap, afterRender, offered: () => { sync(); return Boolean(key) && !hidden && people()?.rewardTime === true; }, signature: () => JSON.stringify([sync(), hidden, [...entries]]) };
}
