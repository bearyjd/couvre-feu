// Parent-side time requests and child request links. All dynamic text is rendered with textContent.
const MESSAGES = {
  schedule_override_unsupported: 'Not supported yet: schedules cannot be overridden, so the schedule still blocks access.',
  grant_ended: 'approved, but access was paused, so the extra time has ended.',
};
// Parent-friendly reasons for a grant that could not be applied. Unknown codes get the generic text; the raw code stays in data-code.
const FAILURE_TEXT = {
  approval_not_applied: 'the router change did not take effect',
  grant_not_applied: 'the router did not accept the change',
  grant_not_in_force: 'the time ran out before the router applied it',
  apply_failed: 'the router change did not complete',
};
const GENERIC_FAILURE = 'the router did not confirm it';
const LESS_MINUTES = [15, 30];
const HISTORY_CAP = 8;
const CAP_MINUTES = 60;
const POLL_MS = 5000;
const clock = (epoch) => new Date(epoch * 1000).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key.startsWith('data-') || key.startsWith('aria-')) node.setAttribute(key, value);
    else node[key] = value;
  }
  node.append(...children);
  return node;
}

export function createTimeRequests({ session, people, end = async () => ({ sent: false, reason: 'Not available.' }) }) {
  const root = document.querySelector('#time-requests');
  let disabled = false, key = '', data = null, notice = '', link = null, drawn = '', timer = null, wantFocus = '';
  const busy = new Map(); // request id or person id -> 'grant' | 'decline' | 'end'; a control is disabled while its entry exists
  const nowSeconds = () => Math.floor(Date.now() / 1000);
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.csrfToken}` : ''; };
  const clearAll = () => { data = null; link = null; notice = ''; drawn = ''; wantFocus = ''; busy.clear(); root.replaceChildren(); root.hidden = true; };

  const nameOf = (id) => people().find((person) => person.id === id)?.name ?? id;
  async function call(path, body) {
    const current = session();
    if (!current) throw new Error('You are signed out.');
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': current.csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(12000),
    });
    const result = await response.json();
    if (!response.ok) { const error = new Error(result.error?.message ?? 'The request could not be completed.'); error.status = response.status; throw error; }
    return result;
  }
  async function load() {
    if (!session() || !navigator.onLine) return;
    const asked = sessionKey(); // a response that arrives after the session changed belongs to someone else
    let result = null;
    try { result = await call('/time-requests'); }
    catch (error) {
      if (asked !== sessionKey()) return;
      // 404: this installation has time requests switched off. Stop polling and stay hidden.
      if (error.status === 404) { disabled = true; clearInterval(timer); timer = null; clearAll(); return; }
      notice = error.message;
    }
    if (asked !== sessionKey()) return;
    if (result) data = result;
    draw();
  }
  // The card's own aria-live region announces results; nothing is written to the page-level status line.
  async function act(path, body, then, busyKey, kind, focus) {
    if (busy.has(busyKey)) return; // double-tap: the first request is still in flight
    const asked = sessionKey();
    notice = ''; wantFocus = focus;
    busy.set(busyKey, kind); draw(true);
    try { then(await call(path, body)); }
    catch (error) { notice = error.message; }
    if (asked !== sessionKey()) return;
    busy.delete(busyKey);
    await load();
    draw(true);
    restoreFocus();
  }
  async function endGrant(personId) {
    if (busy.has(personId)) return;
    const asked = sessionKey(), who = nameOf(personId);
    busy.set(personId, 'end'); notice = ''; wantFocus = `end:${personId}`; draw(true);
    let result;
    try { result = await end(personId); } catch (error) { result = { sent: false, reason: error.message }; }
    if (asked !== sessionKey()) return;
    notice = result?.sent
      ? `Pause requested for ${who}. Extra time is over only once this card says it ended.`
      : `Couldn't send the pause for ${who}. ${result?.reason ?? 'No reason was given.'} The extra time is still in force until this card says it ended.`;
    busy.delete(personId);
    await load();
    draw(true);
    restoreFocus();
  }
  // After a tap redraws the card the tapped control is gone: put focus on the same request's next control, else the heading.
  function restoreFocus() {
    const wanted = wantFocus; wantFocus = '';
    const active = document.activeElement;
    if (!wanted || (active && active !== document.body && !root.contains(active))) return;
    const owner = wanted.slice(wanted.indexOf(':') + 1);
    const target = [...root.querySelectorAll('[data-focus]')].find((node) => node.dataset.focus === wanted && !node.disabled)
      ?? [...root.querySelectorAll('[data-request]')].find((node) => node.dataset.request === owner)?.querySelector('button:not(:disabled)')
      ?? root.querySelector('#time-requests-title');
    target?.focus();
  }
  function grantButton(item, who, minutes, primary, inFlight) {
    return el('button', { class: `button ${primary ? 'primary' : 'secondary'}`, type: 'button', disabled: Boolean(inFlight), 'data-focus': `grant:${item.id}`, 'aria-label': `Grant ${minutes} minutes for ${who}`,
      onclick: () => void act(`/time-requests/${item.id}/approve`, { minutes }, (result) => {
        notice = result.request.state === 'unsupported' ? MESSAGES.schedule_override_unsupported : '';
      }, item.id, 'grant', `grant:${item.id}`) }, `Grant ${minutes} min`);
  }
  function requestCard(item) {
    const who = nameOf(item.personId), minutes = Math.min(item.minutes, CAP_MINUTES), inFlight = busy.get(item.id);
    const grant = grantButton(item, who, minutes, true, inFlight);
    const decline = el('button', { class: 'button secondary', type: 'button', disabled: Boolean(inFlight), 'data-focus': `decline:${item.id}`, 'aria-label': `Decline request from ${who}`,
      onclick: () => void act(`/time-requests/${item.id}/decline`, {}, () => { notice = 'Request declined.'; }, item.id, 'decline', `decline:${item.id}`) }, 'Decline');
    const less = LESS_MINUTES.filter((value) => value < minutes);
    const lessGroup = less.length ? el('div', { class: 'person-controls', role: 'group', 'data-grant-less': item.id, 'aria-label': `Grant less time for ${who}` },
      el('span', {}, 'Grant less:'), ...less.map((value) => grantButton(item, who, value, false, inFlight))) : null;
    return el('li', { class: 'time-request', 'data-request': item.id },
      el('strong', {}, `${who} asks for ${item.minutes} minutes`),
      el('span', { class: 'reason-detail' }, item.reason ? `“${item.reason}”` : 'No reason given'),
      el('span', { class: 'reason-detail' }, `Expires at ${clock(item.expiresAt)}`),
      ...(inFlight ? [el('span', { class: 'reason-detail' }, inFlight === 'grant' ? 'Applying…' : 'Declining…')] : []),
      el('div', { class: 'person-controls' }, grant, decline),
      ...(lessGroup ? [lessGroup] : []));
  }
  const activeGrant = (item) => item.state === 'approved' && !item.code && item.allowanceUntil !== null && item.allowanceUntil > nowSeconds();
  function resolvedText(item) {
    const who = nameOf(item.personId), by = item.decidedBy ? ` by ${item.decidedBy}` : '';
    if (item.state === 'approved' && item.code === 'grant_ended') return `${who}: ${MESSAGES.grant_ended}`;
    if (activeGrant(item)) return `${who}: Granted until ${clock(item.allowanceUntil)}${by}.`;
    if (item.state === 'approved') return `${who}: extra time ended at ${clock(item.allowanceUntil)}${by}.`;
    if (item.state === 'approving') return `${who}: Applying… waiting for the router to confirm. Not granted yet.`;
    if (item.state === 'apply_failed') return `${who}: Couldn't apply (${FAILURE_TEXT[item.code] ?? GENERIC_FAILURE}). No extra time was confirmed.`;
    if (item.state === 'declined') return `${who}: declined${by}.`;
    if (item.state === 'expired') return `${who}: expired unanswered.`;
    if (item.state === 'cancelled') return `${who}: cancelled when the link was turned off.`;
    return `${who}: ${MESSAGES[item.code] ?? `could not be completed (${FAILURE_TEXT[item.code] ?? GENERIC_FAILURE})`}.`;
  }
  function historyRow(item) {
    const props = item.code ? { 'data-code': item.code } : {};
    if (!activeGrant(item)) return el('li', props, resolvedText(item));
    const who = nameOf(item.personId);
    return el('li', props, resolvedText(item), ' ', el('button', { class: 'button secondary', type: 'button', disabled: busy.has(item.personId), 'data-focus': `end:${item.personId}`, 'aria-label': `End extra time for ${who}`,
      onclick: () => void endGrant(item.personId) }, busy.get(item.personId) === 'end' ? 'Ending…' : 'End extra time'));
  }
  function linkRow(entry) {
    const id = entry.personId, key = `link:${id}`, working = busy.has(key);
    const buttons = [el('button', { class: 'button secondary', type: 'button', disabled: working, 'data-focus': `link:${id}`, 'aria-label': `${entry.active ? 'Replace' : 'Create'} request link for ${nameOf(id)}`,
      onclick: () => void act(`/people/${id}/request-link`, {}, (result) => { link = { personId: id, url: `${location.origin}${result.path}` }; }, key, 'link', `link:${id}`) }, entry.active ? 'Replace link' : 'Create link')];
    if (entry.active) buttons.push(el('button', { class: 'button secondary', type: 'button', disabled: working, 'data-focus': `link-off:${id}`, 'aria-label': `Turn off request link for ${nameOf(id)}`,
      onclick: () => void act(`/people/${id}/request-link/revoke`, {}, () => { if (link?.personId === id) link = null; notice = 'Request link turned off.'; }, key, 'link', `link-off:${id}`) }, 'Turn off'));
    const row = el('li', { class: 'request-link', 'data-link': id }, el('span', {}, `${nameOf(id)}: ${entry.active ? 'link active' : 'no link'}`), ...buttons);
    if (link?.personId === id) {
      row.append(el('label', {}, 'Share this link with the child. It is shown once.', el('input', { type: 'text', readOnly: true, value: link.url, 'aria-label': `Request link for ${nameOf(id)}` })));
    }
    return row;
  }
  function draw(force = false) {
    if (!session() || !data) { clearAll(); return; }
    // Grants still in force are pinned above the cap so newer rows can never hide their End button.
    const pending = data.requests.filter((item) => item.state === 'pending'), settled = data.requests.filter((item) => item.state !== 'pending');
    const pinned = settled.filter(activeGrant), others = settled.filter((item) => !activeGrant(item));
    const resolved = [...pinned, ...others.slice(0, Math.max(0, HISTORY_CAP - pinned.length))];
    const overdue = data.requests.filter((item) => item.repauseOverdue);
    const next = JSON.stringify([data, notice, link, [...busy], people().map((person) => [person.id, person.name])]);
    if (!force && next === drawn) return;
    drawn = next;
    root.replaceChildren(
      el('h2', { id: 'time-requests-title', tabIndex: -1 }, 'Time requests'),
      el('p', { class: 'fine-print' }, 'Children ask through a private link. Approving ends a current pause for the time you choose, then restores it (if the service is down when time runs out, the child stays unblocked until it returns). Schedules cannot be overridden yet.'),
      ...overdue.map((item) => el('p', { class: 'notice error', role: 'alert' }, `${nameOf(item.personId)}: the approved time has ended but the pause is not restored yet${item.repauseError ? ` (${item.repauseError})` : ''}. The service keeps retrying; pause manually if needed.`)),
      el('p', { class: 'notice', role: 'status', 'aria-live': 'polite', hidden: !notice }, notice),
      el('p', { class: 'fine-print' }, 'Extra time is unverified on this router: it has not been proven on live hardware yet. A grant counts only once the router confirms it.'),
      pending.length ? el('ul', { class: 'time-request-list', 'aria-label': 'Pending time requests' }, ...pending.map(requestCard)) : el('p', {}, 'No pending requests.'),
      ...(resolved.length ? [el('ul', { class: 'time-request-history', 'aria-label': 'Recent requests' }, ...resolved.map(historyRow))] : []),
      el('h3', {}, 'Request links'),
      el('ul', { class: 'request-links' }, ...data.links.map(linkRow)),
    );
    root.hidden = false;
  }
  function update() {
    const next = sessionKey();
    if (next !== key) { key = next; disabled = false; clearAll(); if (next) void load(); }
    if (next && !timer && !disabled) timer = setInterval(() => { if (!document.hidden && !root.contains(document.activeElement?.closest('input'))) void load(); }, POLL_MS);
    if (!next && timer) { clearInterval(timer); timer = null; }
  }
  return { update };
}
