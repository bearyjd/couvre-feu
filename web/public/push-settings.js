// Notifications settings (admin only, read only) and a "Send test push" button. Unverified on this router and phone.
// There is no people flag for this panel, so an admin probes on first load: 404 or 403 means off (push.enabled is off), and the probe repeats after any offline period.
// Nothing is persisted: the body lives in closure variables dropped on clear(). All text is set with textContent, and only allowlisted
// fields are read, so a URL, topic or token could never be drawn even if one were sent.
const KIND_LABELS = { time_request_pending: 'Extra-time requests', repeated_blocked_attempts: 'Repeated blocked attempts' };
const OTHER_KIND = 'Another low-urgency alert type';
const ZONE = 'America/New_York';
const TAG = /^[a-z0-9_]{1,40}$/;

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
const clock = (value) => {
  const match = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(value ?? '');
  if (!match) return null;
  const hour = Number(match[1]);
  return `${hour % 12 || 12}:${match[2]} ${hour < 12 ? 'AM' : 'PM'}`;
};
const usable = (body) => {
  const push = body?.push;
  return Boolean(push) && push.provider === 'ntfy' && typeof push.configured === 'boolean'
    && clock(push.quietHours?.start) !== null && clock(push.quietHours?.end) !== null && push.quietHours.zone === ZONE && typeof push.quietHours.activeNow === 'boolean'
    && Array.isArray(push.heldKinds) && push.heldKinds.length <= 20 && push.heldKinds.every((kind) => typeof kind === 'string')
    && push.digest?.audience === 'admins' && push.digest.day === 'sunday' && clock(push.digest.time) !== null && push.digest.zone === ZONE;
};
// Only these answers are ever shown; the failure tag is a short code from the service, never free text.
function testMessage(result) {
  if (result === 'sent_to_push_service') return 'Sent to push service';
  if (result === 'not_configured') return 'No push set up';
  if (typeof result === 'string' && result.startsWith('push_failed:')) { const tag = result.slice(12); return TAG.test(tag) ? `Push failed (${tag})` : 'Push failed'; }
  return null;
}

export function createPushSettings({ session, offline }) {
  const root = document.querySelector('#push-settings-panel');
  let key = '', epoch = 0, loading = false, loaded = false, failed = false, settings = null, refocus = false, testing = false, testStatus = '', sent = false;
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.csrfToken}` : ''; };
  function sync() {
    const next = sessionKey();
    if (next !== key) { key = next; epoch++; loading = false; loaded = false; failed = false; testing = false; testStatus = ''; sent = false; clear(); }
    return key;
  }
  function clear() { settings = null; refocus = false; root.replaceChildren(); root.hidden = true; }
  // The heading, the one status node and the sent note persist across redraws; only the body is rebuilt, so a redraw never moves focus or re-announces.
  function frame() {
    if (!root.querySelector('[data-body]')) {
      root.replaceChildren(el('h2', { id: 'push-settings-title', textContent: 'Notifications' }), el('div', { 'data-body': '' }),
        el('p', { role: 'status', 'data-test-status': '', 'data-push-status': '' }), el('p', { class: 'fine-print', 'data-sent-note': '', hidden: true, textContent: 'Sent to the push service does not prove the phone got it. Check the phone.' }));
    }
    return root;
  }
  function announce() {
    const node = root.querySelector('[data-test-status]'), note = root.querySelector('[data-sent-note]'), button = root.querySelector('[data-action="test"]');
    if (node) node.textContent = settings ? testStatus : (failed ? 'Notification settings unavailable' : '');
    if (note) note.hidden = !(settings && sent);
    // aria-disabled, not disabled: a disabled button drops keyboard focus; sendTest() already ignores clicks while testing.
    if (button) button.setAttribute('aria-disabled', String(testing));
  }
  const offered = () => Boolean(key) && session()?.actor.role === 'admin';

  async function call(path, post) {
    const current = session();
    const response = await fetch(path, { method: post ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
      headers: post ? { 'X-CSRF-Token': current.csrfToken } : {}, signal: AbortSignal.timeout(post ? 12000 : 15000) });
    let result = null;
    try { result = await response.json(); } catch { /* handled below */ }
    if (!response.ok || result === null) { const error = new Error('request_failed'); error.status = response.status; throw error; }
    return result;
  }

  function draw() {
    if (!offered()) { clear(); return; }
    if (offline()) return;
    const view = [];
    if (settings) {
      const { provider, configured, quietHours, heldKinds, digest } = settings;
      const known = (kind) => Object.hasOwn(KIND_LABELS, kind) ? KIND_LABELS[kind] : OTHER_KIND;
      view.push(el('p', { class: 'fine-print', 'data-unverified': '', textContent: 'Read only. Built but unverified on this router/phone: nothing here confirms a push has ever reached a phone.' }),
        el('dl', {},
          el('div', {}, el('dt', { textContent: 'Push service' }), el('dd', { 'data-provider': '', textContent: `${provider}: ${configured ? 'set up' : 'not set up'}` })),
          el('div', {}, el('dt', { textContent: 'Quiet hours' }), el('dd', { 'data-quiet': '', textContent: `${clock(quietHours.start)} to ${clock(quietHours.end)} (New York time). ${quietHours.activeNow ? 'Quiet right now.' : 'Not quiet right now.'}` })),
          el('div', {}, el('dt', { textContent: 'Held until morning' }), el('dd', {}, el('ul', { 'data-held': '' }, ...heldKinds.map((kind) => el('li', { textContent: known(kind) }))))),
          el('div', {}, el('dt', { textContent: 'Weekly digest' }), el('dd', { 'data-digest': '', textContent: `Sundays at ${clock(digest.time)} (New York time), to admins` }))),
        el('p', { class: 'fine-print', textContent: 'Other alerts are sent at any hour.' }),
        el('button', { class: 'button secondary', type: 'button', 'data-action': 'test', textContent: 'Send test push' }));
    } else if (failed) {
      view.push(el('button', { class: 'button secondary', type: 'button', 'data-action': 'retry', textContent: 'Try again' }));
    } else { clear(); return; }
    frame().querySelector('[data-body]').replaceChildren(...view);
    announce();
    root.hidden = false;
    if (refocus) { refocus = false; const title = root.querySelector('#push-settings-title'); title.tabIndex = -1; title.focus(); }
  }

  async function load() {
    if (loading || !sync()) return;
    const mine = epoch;
    loading = true; failed = false; settings = null;
    try {
      const body = await call('/push/settings', false);
      if (mine !== epoch) return;
      if (!usable(body)) throw new Error('bad_response');
      settings = body.push; loaded = true;
    } catch (error) {
      if (mine !== epoch) return;
      if (error.status === 403 || error.status === 404) { loading = false; loaded = true; clear(); return; }
      failed = true;
    }
    loading = false; draw();
  }

  async function sendTest() {
    if (testing || !sync()) return;
    const mine = epoch;
    testing = true; sent = false; testStatus = 'Sending test push...'; announce();
    try {
      const message = testMessage((await call('/push/test', true)).result);
      if (mine !== epoch) return;
      sent = message === 'Sent to push service';
      testStatus = message ?? 'The test could not be sent';
    } catch (error) {
      if (mine !== epoch) return;
      testStatus = error.status === 429 ? 'Please wait before sending another test' : 'The test could not be sent';
    }
    testing = false; announce();
  }

  root.addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (!button || !sync() || offline()) return;
    if (button.dataset.action === 'retry') { refocus = true; void load(); }
    else if (button.dataset.action === 'test') void sendTest();
  });

  function update() {
    sync();
    if (!offered() || offline()) {
      // Hidden while offline, but forget the load so the panel is fetched again once the app is back online.
      if (!loading) { loaded = false; failed = false; }
      if (!root.hidden || root.childNodes.length) clear();
      return;
    }
    if (!loaded && !loading && !failed) void load();
  }
  return { update };
}
