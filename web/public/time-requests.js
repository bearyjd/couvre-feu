// Parent-side time requests and child request links. All dynamic text is rendered with textContent.
const MESSAGES = {
  schedule_override_unsupported: 'Not supported yet: schedules cannot be overridden, so the schedule still blocks access.',
  approval_not_applied: 'Approved, but the router change did not take effect.',
};
const POLL_MS = 5000;
const clock = (epoch) => new Date(epoch * 1000).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key.startsWith('data-') || key === 'aria-label') node.setAttribute(key, value);
    else node[key] = value;
  }
  node.append(...children);
  return node;
}

export function createTimeRequests({ session, people }) {
  const root = document.querySelector('#time-requests');
  let key = '', data = null, notice = '', link = null, drawn = '', timer = null;

  const nameOf = (id) => people().find((person) => person.id === id)?.name ?? id;
  async function call(path, body) {
    const current = session();
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': current.csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(12000),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message ?? 'The request could not be completed.');
    return result;
  }
  async function load() {
    if (!session() || !navigator.onLine) return;
    try { data = await call('/time-requests'); }
    catch (error) { notice = error.message; }
    draw();
  }
  async function act(path, body, then) {
    notice = '';
    try { then(await call(path, body)); }
    catch (error) { notice = error.message; }
    await load();
    draw(true);
  }
  function requestCard(item) {
    const approve = [15, 30, 60].map((minutes) => el('button', { class: 'button primary', type: 'button', 'aria-label': `Approve ${minutes} minutes for ${nameOf(item.personId)}`,
      onclick: () => void act(`/time-requests/${item.id}/approve`, { minutes }, (result) => {
        const state = result.request.state;
        notice = state === 'unsupported' ? MESSAGES.schedule_override_unsupported : `Approved ${minutes} minutes for ${nameOf(item.personId)}.`;
      }) }, `Approve ${minutes}`));
    const decline = el('button', { class: 'button secondary', type: 'button', onclick: () => void act(`/time-requests/${item.id}/decline`, {}, () => { notice = 'Request declined.'; }) }, 'Decline');
    return el('li', { class: 'time-request', 'data-request': item.id },
      el('strong', {}, `${nameOf(item.personId)} asks for ${item.minutes} minutes`),
      el('span', { class: 'reason-detail' }, item.reason ? `“${item.reason}”` : 'No reason given'),
      el('span', { class: 'reason-detail' }, `Expires at ${clock(item.expiresAt)}`),
      el('div', { class: 'person-controls' }, ...approve, decline));
  }
  function resolvedText(item) {
    const who = nameOf(item.personId), by = item.decidedBy ? ` by ${item.decidedBy}` : '';
    if (item.state === 'approved') return `${who}: approved ${item.grantedMinutes} minutes until ${clock(item.allowanceUntil)}${by}.`;
    if (item.state === 'approving') return `${who}: approval in progress.`;
    if (item.state === 'declined') return `${who}: declined${by}.`;
    if (item.state === 'expired') return `${who}: expired unanswered.`;
    if (item.state === 'cancelled') return `${who}: cancelled when the link was turned off.`;
    return `${who}: ${MESSAGES[item.code] ?? item.state}`;
  }
  function linkRow(entry) {
    const buttons = [el('button', { class: 'button secondary', type: 'button', 'aria-label': `${entry.active ? 'Replace' : 'Create'} request link for ${nameOf(entry.personId)}`,
      onclick: () => void act(`/people/${entry.personId}/request-link`, {}, (result) => { link = { personId: entry.personId, url: `${location.origin}${result.path}` }; }) }, entry.active ? 'Replace link' : 'Create link')];
    if (entry.active) buttons.push(el('button', { class: 'button secondary', type: 'button', 'aria-label': `Turn off request link for ${nameOf(entry.personId)}`,
      onclick: () => void act(`/people/${entry.personId}/request-link/revoke`, {}, () => { if (link?.personId === entry.personId) link = null; notice = 'Request link turned off.'; }) }, 'Turn off'));
    const row = el('li', { class: 'request-link', 'data-link': entry.personId }, el('span', {}, `${nameOf(entry.personId)}: ${entry.active ? 'link active' : 'no link'}`), ...buttons);
    if (link?.personId === entry.personId) {
      row.append(el('label', {}, 'Share this link with the child. It is shown once.', el('input', { type: 'text', readOnly: true, value: link.url, 'aria-label': `Request link for ${nameOf(entry.personId)}` })));
    }
    return row;
  }
  function draw(force = false) {
    if (!session() || !data) { root.hidden = true; return; }
    const pending = data.requests.filter((item) => item.state === 'pending'), resolved = data.requests.filter((item) => item.state !== 'pending').slice(0, 8);
    const overdue = data.requests.filter((item) => item.repauseOverdue);
    const next = JSON.stringify([data, notice, link, people().map((person) => [person.id, person.name])]);
    if (!force && next === drawn) return;
    drawn = next;
    root.replaceChildren(
      el('h2', { id: 'time-requests-title' }, 'Time requests'),
      el('p', { class: 'fine-print' }, 'Children ask through a private link. Approving ends a current pause for the time you choose, then restores it (if the service is down when time runs out, the child stays unblocked until it returns). Schedules cannot be overridden yet.'),
      ...overdue.map((item) => el('p', { class: 'notice error', role: 'alert' }, `${nameOf(item.personId)}: the approved time has ended but the pause is not restored yet${item.repauseError ? ` (${item.repauseError})` : ''}. The service keeps retrying; pause manually if needed.`)),
      el('p', { class: 'notice', role: 'status', hidden: !notice }, notice),
      pending.length ? el('ul', { class: 'time-request-list', 'aria-label': 'Pending time requests' }, ...pending.map(requestCard)) : el('p', {}, 'No pending requests.'),
      resolved.length ? el('ul', { class: 'time-request-history', 'aria-label': 'Recent requests' }, ...resolved.map((item) => el('li', {}, resolvedText(item)))) : el('span'),
      el('h3', {}, 'Request links'),
      el('ul', { class: 'request-links' }, ...data.links.map(linkRow)),
    );
    root.hidden = false;
  }
  function update() {
    const current = session(), next = current ? `${current.actor.id}:${current.csrfToken}` : '';
    if (next !== key) { key = next; data = null; link = null; notice = ''; drawn = ''; draw(); if (next) void load(); }
    if (next && !timer) timer = setInterval(() => { if (!document.hidden && !root.contains(document.activeElement?.closest('input'))) void load(); }, POLL_MS);
    if (!next && timer) { clearInterval(timer); timer = null; }
  }
  return { update };
}
