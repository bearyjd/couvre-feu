// Weekly digest preview (admin only): the last closed digest period as recorded-event counts. Read only; nothing is sent from here.
// There is no people flag for this panel, so an admin probes once per session: 404 or 403 means off.
// Nothing is persisted: the body lives in a closure variable that is dropped on clear(). All text is set with textContent.
const FORMAT = new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const WEEK_DAYS = 7;
const COUNTS = [['requests', 'Extra-time requests'], ['grants', 'Requests approved'], ['pauses', 'Pauses started']];

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
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const seconds = (value) => Number.isSafeInteger(value) && value > 0;
const day = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value);
const usable = (body) => Boolean(body) && seconds(body.period?.start) && seconds(body.period?.end) && body.period.start < body.period.end
  && COUNTS.every(([name]) => count(body.counts?.[name]))
  && (body.blockedLookups === undefined || (day(body.blockedLookups.firstDay) && day(body.blockedLookups.lastDay) && count(body.blockedLookups.count)
    && Number.isSafeInteger(body.blockedLookups.daysCounted) && body.blockedLookups.daysCounted > 0 && body.blockedLookups.daysCounted <= WEEK_DAYS));

export function createDigestPreview({ session, offline }) {
  const root = document.querySelector('#digest-preview-panel');
  let key = '', epoch = 0, loading = false, loaded = false, failed = false, preview = null, refocus = false;
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.csrfToken}` : ''; };
  function sync() {
    const next = sessionKey();
    if (next !== key) { key = next; epoch++; loading = false; loaded = false; failed = false; clear(); }
    return key;
  }
  function clear() { preview = null; root.replaceChildren(); root.hidden = true; }
  const offered = () => Boolean(key) && session()?.actor.role === 'admin';

  async function call(path) {
    const response = await fetch(path, { method: 'GET', credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
    let result = null;
    try { result = await response.json(); } catch { /* handled below */ }
    if (!response.ok || result === null) { const error = new Error(result?.error?.message ?? 'The request could not be completed.'); error.status = response.status; error.code = result?.error?.code; throw error; }
    return result;
  }

  function draw() {
    if (!offered()) { clear(); return; }
    const view = [el('h2', { id: 'digest-preview-title', textContent: 'Weekly digest preview' })];
    if (preview) {
      const { period, counts, blockedLookups } = preview;
      view.push(el('p', { class: 'fine-print', 'data-period': '', textContent: `Last full week: ${FORMAT.format(period.start * 1000)} to ${FORMAT.format(period.end * 1000)} (New York time)` }));
      view.push(el('dl', {}, ...COUNTS.map(([name, label]) => el('div', {}, el('dt', { textContent: label }), el('dd', { 'data-count': name, textContent: String(counts[name]) })))));
      if (blockedLookups) {
        const partial = blockedLookups.daysCounted < WEEK_DAYS ? ` ${blockedLookups.daysCounted} of ${WEEK_DAYS} days counted` : '';
        view.push(el('p', { 'data-blocked': '', textContent: `Blocked website lookups: ${blockedLookups.count} (${blockedLookups.firstDay} to ${blockedLookups.lastDay})${partial}` }));
      }
    } else if (failed) {
      view.push(el('p', { role: 'status', 'data-digest-status': '', textContent: 'Digest preview unavailable' }),
        el('button', { class: 'button secondary', type: 'button', 'data-action': 'retry', textContent: 'Try again' }));
    } else { clear(); return; }
    root.replaceChildren(...view);
    root.hidden = false;
    if (refocus) { refocus = false; const title = root.querySelector('#digest-preview-title'); title.tabIndex = -1; title.focus(); }
  }

  async function load() {
    if (loading || !sync()) return;
    const mine = epoch;
    loading = true; failed = false; preview = null;
    try {
      const body = await call('/digest/preview');
      if (mine !== epoch) return;
      if (!usable(body)) throw new Error('bad_response');
      preview = body; loaded = true;
    } catch (error) {
      if (mine !== epoch) return;
      if (error.status === 403 || error.status === 404) { loading = false; loaded = true; clear(); return; }
      failed = true;
    }
    loading = false; draw();
  }

  root.addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (button?.dataset.action === 'retry' && sync() && !offline()) { refocus = true; void load(); }
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
