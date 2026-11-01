// Parent Activity log: who asked for what, newest first. All dynamic text is rendered with textContent (names are untrusted).
// "Requested" is honest: the service accepted the request. The router confirms separately, so nothing here says "done" or "confirmed".
// The panel exists only while the service says the log is on for this viewer (people.auditLog === true). A 404 from the log hides it for the session.
const PAGE = 50;
// Parent-friendly wording per action. An unknown action gets the generic text; a raw code is never shown.
const WHAT = {
  pause: 'Paused', resume: 'Resumed', pause_all: 'Paused everyone', resume_all: 'Resumed everyone',
  device_assign: 'Assigned a device', device_move: 'Moved a device', device_remove: 'Removed a device',
  grant_approve: 'Approved extra time', grant_decline: 'Declined a request', grant_end: 'Ended extra time',
  reward_add: 'Added reward time', focus_start: 'Started a focus window',
};
const GENERIC_WHAT = 'Changed a setting';
const EVERYONE = new Set(['pause_all', 'resume_all']);
const RESULT = {
  applied: { text: 'Requested', title: 'Accepted by the service; the router confirms separately', note: 'accepted by the service; the router confirms separately' },
  refused: { text: 'Refused', title: 'Refused before anything was sent to the router', note: 'refused before anything was sent to the router' },
  failed: { text: 'Failed', title: 'Could not be carried out', note: 'could not be carried out' },
};
const GENERIC_RESULT = { text: 'Unknown', title: 'The service gave no clear result', note: 'the service gave no clear result' };
const whatOf = (action) => (Object.hasOwn(WHAT, action) ? WHAT[action] : GENERIC_WHAT);
const resultOf = (result) => (Object.hasOwn(RESULT, result) ? RESULT[result] : GENERIC_RESULT);
const when = (epoch) => new Date(epoch * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key.startsWith('data-') || key.startsWith('aria-') || key === 'role') node.setAttribute(key, value);
    else node[key] = value;
  }
  node.append(...children);
  return node;
}

// Only rows the log contract describes are drawn; anything else in a response is dropped.
const usable = (entry) => entry && typeof entry === 'object' && Number.isSafeInteger(entry.id) && Number.isFinite(entry.at) && typeof entry.action === 'string';

export function createAuditLog({ session, people }) {
  const root = document.querySelector('#audit-panel');
  const status = el('p', { class: 'fine-print', role: 'status', 'aria-live': 'polite', 'data-audit-status': '' }); // one node for the life of the panel, so screen readers hear changes
  let drawnNames = '', key = '', epoch = 0, hidden = false, loading = false, loaded = false, failed = false, rows = [], nextBefore = null, wantFocus = '';
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.csrfToken}` : ''; };
  // A different (or no) session owns nothing the previous one showed; a response that was in flight for it is ignored.
  function sync() {
    const next = sessionKey();
    if (next !== key) { key = next; epoch++; hidden = false; loading = false; loaded = false; failed = false; rows = []; nextBefore = null; wantFocus = ''; clear(); }
    return key;
  }
  function clear() { status.textContent = ''; root.replaceChildren(); root.hidden = true; }
  const offered = () => Boolean(key) && !hidden && people()?.auditLog === true;

  const childText = (entry) => {
    if (entry.personId == null) return EVERYONE.has(entry.action) ? 'All children' : 'Not about one child';
    return people()?.people?.find((person) => person.id === entry.personId)?.name ?? 'A child you can no longer see';
  };
  function rowNode(entry) {
    const result = resultOf(entry.result);
    return el('li', { class: 'audit-row', tabIndex: -1, 'data-focus-key': `audit-row-${entry.id}` },
      el('time', { dateTime: new Date(entry.at * 1000).toISOString(), textContent: when(entry.at) }),
      el('span', { class: 'audit-who', 'data-who': '', textContent: entry.actorName || entry.actorId || 'Unknown' }),
      el('span', { class: 'audit-what', 'data-what': '', textContent: whatOf(entry.action) }),
      el('span', { class: 'audit-child', 'data-child': '', textContent: childText(entry) }),
      el('span', { class: `audit-result audit-${Object.hasOwn(RESULT, entry.result) ? entry.result : 'unknown'}`, 'data-result': '', title: result.title, textContent: result.text }),
      el('span', { class: 'audit-note', textContent: ` (${result.note})` }));
  }

  const namesKey = () => JSON.stringify(rows.map(childText));
  function statusLine() {
    if (loading) return 'Loading…';
    if (failed) return "Couldn't load the log.";
    return loaded && !rows.length ? 'No activity recorded yet.' : '';
  }
  function draw() {
    if (!offered()) { clear(); return; }
    // Rebuilding the list replaces the focused button; put focus back on whatever was focused unless a load asked for a particular row.
    const had = root.contains(document.activeElement) ? document.activeElement.dataset?.focusKey ?? '' : '';
    status.textContent = statusLine();
    const more = loaded && nextBefore !== null;
    const retry = failed && !rows.length;
    root.replaceChildren(
      el('h2', { id: 'audit-title', textContent: 'Activity log' }),
      el('p', { class: 'fine-print', textContent: 'What parents asked for, newest first. Requested means the service accepted the request; the router confirms separately, so it is not proof the router has acted. This log is unverified on this router.' }),
      status,
      ...(rows.length ? [el('ul', { 'aria-label': 'Activity log entries', role: 'list', class: 'audit-list' }, ...rows.map(rowNode))] : []),
      ...(retry ? [el('button', { class: 'button secondary', type: 'button', 'data-focus-key': 'audit-retry', textContent: 'Try again' })] : []),
      ...(more ? [el('button', { class: 'button secondary', type: 'button', 'data-focus-key': 'audit-older', 'aria-disabled': loading ? 'true' : 'false', textContent: 'Show older' })] : []));
    drawnNames = namesKey();
    root.hidden = false;
    const target = document.querySelector(`#audit-panel [data-focus-key="${CSS.escape(wantFocus || had)}"]`);
    if (target && (wantFocus || had)) { target.focus(); wantFocus = ''; }
  }

  async function fetchPage(before) {
    const response = await fetch(before === null ? `/audit/limit/${PAGE}` : `/audit/limit/${PAGE}/before/${before}`, { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(12000) });
    let body = null;
    try { body = await response.json(); } catch { /* handled as a failure below */ }
    return { status: response.status, ok: response.ok, body };
  }
  async function load(before) {
    if (loading || !sync()) return;
    const mine = epoch;
    loading = true; failed = false; draw();
    try {
      const result = await fetchPage(before);
      if (mine !== epoch) return; // the session changed in flight: show nothing for the old one
      if (result.status === 404) { hidden = true; rows = []; nextBefore = null; loading = false; clear(); return; }
      if (!result.ok || !Array.isArray(result.body?.entries)) throw new Error('bad_response');
      const added = result.body.entries.filter(usable);
      rows = [...rows, ...added];
      nextBefore = Number.isSafeInteger(result.body.nextBefore) ? result.body.nextBefore : null;
      loaded = true;
      if (before !== null && added.length) wantFocus = `audit-row-${added[0].id}`;
    } catch {
      if (mine !== epoch) return;
      failed = true; if (before !== null) wantFocus = 'audit-older';
    }
    loading = false; draw();
  }

  root.addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (!button || !sync()) return;
    if (button.dataset.focusKey === 'audit-older' && !loading && nextBefore !== null) void load(nextBefore);
    else if (button.dataset.focusKey === 'audit-retry' && !loading) void load(null);
  });

  // Called after every page render: starts the first load for a session once the service says the log is on, and clears everything otherwise.
  function update() {
    sync();
    if (!offered()) { if (!root.hidden || root.childNodes.length) clear(); return; }
    if (!loaded && !loading && !failed) void load(null);
    else if (rows.length && namesKey() !== drawnNames) draw(); // a child was renamed or removed since the rows were drawn
  }
  return { update };
}
