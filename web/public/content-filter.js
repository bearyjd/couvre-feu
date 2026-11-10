// Content filter card (PRP-006 A4): one block per child the service lets this parent manage. All dynamic text is textContent.
// The card exists only while the service has the feature on: a 404 route_not_found answers "off" and hides it for the session.
// Loosening needs a passkey (step-up): the save is tried plainly first, and only a 403 step_up_required starts the passkey flow,
// so the server alone decides what counts as loosening. Domains the parent types stay in this page and the service; nothing logs them.
import { getPasskey } from './auth-client.js';

const STATE = {
  applied: { text: 'Applied', note: 'NextDNS read it back and it matches.' },
  pending: { text: 'Sending…', note: 'Saved here; not sent to NextDNS yet.' },
  not_confirmed: { text: 'Not confirmed', note: 'NextDNS has not confirmed it. It may or may not be in force.' },
  drift: { text: 'Changed elsewhere', note: 'NextDNS no longer matches what you set here.' },
};
const GENERIC_STATE = { text: 'Unknown', note: 'The service gave no clear state.' };
export const CATEGORIES = [['porn', 'Adult content'], ['gambling', 'Gambling'], ['dating', 'Dating'], ['piracy', 'Piracy'], ['social-networks', 'Social networks'], ['gaming', 'Gaming'], ['video-streaming', 'Video streaming']];
export const SERVICES = [['tiktok', 'TikTok'], ['instagram', 'Instagram'], ['snapchat', 'Snapchat'], ['discord', 'Discord'], ['roblox', 'Roblox'], ['youtube', 'YouTube']];
const TOGGLES = [['safeSearch', 'Safe search'], ['youtubeRestrictedMode', 'YouTube restricted mode'], ['blockBypass', 'Block ways around the filter']];
const HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const MAX_DOMAINS = 500;
const BASELINE = { categories: ['porn', 'gambling', 'dating', 'piracy'], services: [], safeSearch: true, youtubeRestrictedMode: true, blockBypass: true, denylist: [], allowlist: [] };

const stateOf = (value) => (Object.hasOwn(STATE, value) ? STATE[value] : GENERIC_STATE);
const strings = (value) => (Array.isArray(value) ? value.filter((item) => typeof item === 'string') : []);
const desiredOf = (value) => ({
  categories: strings(value?.categories), services: strings(value?.services), denylist: strings(value?.denylist), allowlist: strings(value?.allowlist),
  safeSearch: value?.safeSearch === true, youtubeRestrictedMode: value?.youtubeRestrictedMode === true, blockBypass: value?.blockBypass === true,
});
// What the page may show of a typed domain: lowercase, no scheme or path. Anything that is not a plain hostname is refused with a fixed message.
export const normalizeDomain = (text) => {
  const host = String(text).trim().toLowerCase().replace(/\.$/, '');
  return host.length <= 253 && HOST.test(host) && !/^[0-9]+$/.test(host.split('.').pop()) ? host : null;
};

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key.startsWith('data-') || key.startsWith('aria-') || key === 'for' || key === 'role') node.setAttribute(key, value);
    else node[key] = value;
  }
  node.append(...children);
  return node;
}

export function createContentFilter({ session, people }) {
  const root = document.querySelector('#filter-panel');
  // id -> { status: 'loading'|'ready'|'unset'|'error', record, draft, notice, busy }
  const cards = new Map();
  let key = '', epoch = 0, off = false, loadingEpoch = -1;
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.actor.role}:${current.csrfToken}` : ''; };

  async function call(path, body) {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : body.method ?? 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': session().csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body.json), signal: AbortSignal.timeout(20000),
    });
    let result = null;
    try { result = await response.json(); } catch { /* not JSON: handled by status */ }
    if (!response.ok) { const error = new Error('The filter could not be changed.'); error.status = response.status; error.code = result?.error?.code; throw error; }
    return result;
  }

  function sync() {
    const next = sessionKey();
    if (next !== key) { key = next; epoch++; off = false; cards.clear(); root.replaceChildren(); root.hidden = true; }
    return key;
  }

  async function loadOne(person) {
    const mine = epoch;
    const entry = cards.get(person.id) ?? { status: 'loading', record: null, draft: null, notice: '', busy: false, dirty: false, typed: {}, fetchedAt: 0, noticeNode: el('p', { class: 'fine-print', role: 'status', 'aria-live': 'polite', 'data-filter-notice': '' }) };
    cards.set(person.id, entry);
    try {
      const record = await call(`/people/${encodeURIComponent(person.id)}/filter`);
      if (mine !== epoch) return;
      entry.status = 'ready'; entry.record = record; entry.fetchedAt = Date.now(); if (!entry.dirty || !entry.draft) { entry.draft = desiredOf(record.desired); entry.dirty = false; }
    } catch (error) {
      if (mine !== epoch) return;
      if (entry.status === 'ready' && error.status !== 404) { entry.fetchedAt = Date.now(); return; } // a failed refresh keeps what is shown
      if (error.status === 404 && error.code === 'route_not_found') { off = true; return; }
      if (error.status === 404 && error.code === 'filter_not_set') { entry.status = 'unset'; entry.draft ??= desiredOf(BASELINE); }
      else if (error.status === 404) entry.status = 'none'; // not a child this account manages, or not mapped: no card, and not asked again this session
      else entry.status = 'error';
    }
  }
  const REFRESH_MS = 10000;
  async function loadAll() {
    if (!sync() || loadingEpoch === epoch) return;
    const mine = epoch; loadingEpoch = mine;
    try {
      const due = (entry) => !entry || (entry.status === 'ready' && !entry.busy && Date.now() - entry.fetchedAt >= REFRESH_MS);
      // Errors are retried only by the person (Try again); everything else is asked once, and ready cards are refreshed at most every 10 s.
      await Promise.all((people() ?? []).filter((person) => { const entry = cards.get(person.id); return !entry || due(entry); }).map(loadOne));
    } finally { if (loadingEpoch === mine) loadingEpoch = -1; }
    if (mine === epoch) draw();
  }

  const toggleIn = (list, id, on) => (on ? [...new Set([...list, id])] : list.filter((item) => item !== id));

  function checkbox(entry, group, id, label) {
    const input = el('input', { type: 'checkbox', checked: entry.draft[group].includes(id), disabled: entry.busy, 'data-filter-field': `${group}:${id}` });
    input.addEventListener('change', () => { entry.draft[group] = toggleIn(entry.draft[group], id, input.checked); entry.dirty = true; });
    return el('label', { class: 'alert-preference' }, input, ` ${label}`);
  }
  function flag(entry, name, label) {
    const input = el('input', { type: 'checkbox', checked: entry.draft[name], disabled: entry.busy, 'data-filter-field': name });
    input.addEventListener('change', () => { entry.draft[name] = input.checked; entry.dirty = true; });
    return el('label', { class: 'alert-preference' }, input, ` ${label}`);
  }
  // Ids the service holds that this page has no label for are kept as they are (shown by id) so saving never drops them.
  function extras(entry, group, known) {
    return entry.draft[group].filter((id) => !known.some(([knownId]) => knownId === id)).map((id) => checkbox(entry, group, id, id));
  }
  function domains(person, entry, group, title) {
    const input = el('input', { type: 'text', value: entry.typed[group] ?? '', inputMode: 'url', autocapitalize: 'none', autocomplete: 'off', spellcheck: false, maxLength: 253, 'aria-label': `${title}: add a site`, disabled: entry.busy, 'data-filter-input': group });
    const add = el('button', { class: 'button secondary', type: 'button', disabled: entry.busy, textContent: 'Add' });
    const problem = el('p', { class: 'fine-print', role: 'alert', hidden: true, textContent: 'Enter just the site name, like example.com.' });
    input.addEventListener('input', () => { entry.typed[group] = input.value; });
    const submit = () => {
      problem.textContent = 'Enter just the site name, like example.com.';
      const host = normalizeDomain(input.value);
      if (!host) { problem.hidden = false; return; }
      problem.hidden = true;
      if (entry.draft[group].length >= MAX_DOMAINS) { problem.textContent = 'That list is full.'; problem.hidden = false; return; }
      entry.draft[group] = [...new Set([...entry.draft[group], host])].sort(); entry.typed[group] = ''; entry.dirty = true;
      entry.notice = ''; draw(person.id, `${group}-input`);
    };
    add.addEventListener('click', submit);
    input.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); submit(); } });
    const rows = entry.draft[group].map((host) => {
      const remove = el('button', { class: 'button secondary', type: 'button', disabled: entry.busy, 'aria-label': `Remove ${host} from ${title}`, textContent: 'Remove' });
      remove.addEventListener('click', () => { entry.draft[group] = entry.draft[group].filter((item) => item !== host); entry.dirty = true; entry.notice = ''; draw(person.id, `${group}-input`); });
      return el('li', {}, el('span', { textContent: host }), ' ', remove);
    });
    return el('fieldset', { class: 'filter-domains' }, el('legend', { textContent: title }),
      ...(rows.length ? [el('ul', { 'aria-label': title }, ...rows)] : [el('p', { class: 'fine-print', textContent: 'None.' })]),
      el('div', {}, input, ' ', add), problem);
  }

  async function save(person, entry) {
    if (entry.busy) return;
    entry.busy = true; entry.notice = ''; draw(person.id);
    const path = `/people/${encodeURIComponent(person.id)}/filter`, desired = { ...entry.draft };
    try {
      try {
        entry.record = await call(path, { method: 'PUT', json: { desired } });
      } catch (error) {
        if (error.status !== 403 || error.code !== 'step_up_required') throw error;
        entry.notice = 'Confirm with your passkey to continue.'; draw(person.id);
        let start;
        try { start = await call('/step-up/options', { json: { action: 'content_filter_set', person: person.id, desired } }); } catch (failed) { failed.beforeCommit = true; throw failed; } // nothing is stored before the challenge exists
        const response = await getPasskey(start.options);
        entry.record = await call(path, { method: 'PUT', json: { desired, stepUp: { challengeId: start.challengeId, response } } });
      }
      entry.status = 'ready'; entry.draft = desiredOf(entry.record.desired); entry.dirty = false; entry.typed = {}; entry.fetchedAt = Date.now();
      entry.notice = 'Saved here. NextDNS has not confirmed it yet.';
    } catch (error) {
      // Only outcomes that happened before anything was stored may say "Nothing changed"; a timeout or a server error may have saved.
      const before = error.name === 'NotAllowedError' || error.beforeCommit === true || [400, 401, 403, 404, 429].includes(error.status);
      entry.notice = error.name === 'NotAllowedError' ? 'Passkey confirmation was cancelled. Nothing changed.'
        : error.status === 429 ? 'Too many changes just now. Try again in a minute.'
        : error.status === 400 ? 'The service did not accept that filter. Nothing changed.'
        : before ? 'The filter could not be changed. Nothing changed.'
        : 'Could not confirm whether this saved. Checking…';
      if (!before) { entry.busy = false; draw(person.id, null, 'filterSave'); await loadOne(person); entry.notice = 'Could not confirm whether your change saved. The state above is what the service holds now.'; }
    }
    entry.busy = false; draw(person.id, null, 'filterSave');
  }

  function card(person, entry) {
    const title = `filter-${person.id}`;
    const body = [];
    if (entry.status === 'loading') body.push(el('p', { class: 'fine-print', textContent: 'Loading…' }));
    else if (entry.status === 'error') {
      const retry = el('button', { class: 'button secondary', type: 'button', textContent: 'Try again' });
      retry.addEventListener('click', () => { cards.delete(person.id); void loadAll(); });
      body.push(el('p', { class: 'fine-print', role: 'alert', textContent: "Couldn't load this filter." }), retry);
    } else {
      if (entry.status === 'unset') body.push(el('p', { class: 'fine-print', textContent: 'No filter is set for this child yet. These are suggested starting choices; nothing applies until you save.' }));
      else {
        const info = stateOf(entry.record?.state);
        body.push(el('p', { 'data-filter-state': entry.record?.state ?? '' }, el('strong', { textContent: info.text }), ` — ${info.note} This is unverified on this router.`));
      }
      body.push(
        el('fieldset', {}, el('legend', { textContent: 'Blocked categories' }), ...CATEGORIES.map(([id, label]) => checkbox(entry, 'categories', id, label)), ...extras(entry, 'categories', CATEGORIES)),
        el('fieldset', {}, el('legend', { textContent: 'Blocked apps and sites' }), ...SERVICES.map(([id, label]) => checkbox(entry, 'services', id, label)), ...extras(entry, 'services', SERVICES)),
        el('fieldset', {}, el('legend', { textContent: 'Protections' }), ...TOGGLES.map(([name, label]) => flag(entry, name, label))),
        domains(person, entry, 'denylist', 'Always block these sites'), domains(person, entry, 'allowlist', 'Always allow these sites'));
      const saveButton = el('button', { class: 'button primary', type: 'button', disabled: entry.busy, 'aria-disabled': entry.busy ? 'true' : 'false', textContent: entry.status === 'unset' ? 'Save filter' : 'Save changes', 'data-filter-save': '' });
      saveButton.addEventListener('click', () => void save(person, entry));
      body.push(saveButton, (entry.noticeNode.textContent = entry.notice, entry.noticeNode));
    }
    return el('section', { class: 'filter-card', 'aria-labelledby': title, 'data-filter-person': person.id }, el('h3', { id: title, textContent: person.name }), ...body);
  }

  function draw(focusPerson, focusField, focusKey) {
    if (!sync() || off || ![...cards.values()].some((entry) => entry.status !== 'none')) { root.replaceChildren(); root.hidden = true; return; }
    const active = root.contains(document.activeElement) ? document.activeElement : null;
    const had = !focusField && !focusKey && active?.dataset?.filterField ? active.dataset.filterField : null;
    const hadSave = !focusField && !focusKey && active?.dataset?.filterSave !== undefined ? active.closest('[data-filter-person]')?.dataset.filterPerson : null;
    const listed = (people() ?? []).filter((person) => cards.has(person.id) && cards.get(person.id).status !== 'none');
    root.replaceChildren(
      el('h2', { id: 'filter-title', textContent: 'Content filter' }),
      el('p', { class: 'fine-print', textContent: 'What each child can reach, set through NextDNS. It filters websites by name only; it cannot see apps that avoid it, and each state below says what NextDNS has and has not confirmed. Unverified on this router.' }),
      ...listed.map((person) => card(person, cards.get(person.id))));
    root.hidden = false;
    if (focusField) document.querySelector(`#filter-panel [data-filter-person="${CSS.escape(focusPerson)}"] [data-filter-input="${CSS.escape(focusField.replace(/-input$/, ''))}"]`)?.focus();
    else if (focusKey === 'filterSave' && focusPerson) document.querySelector(`#filter-panel [data-filter-person="${CSS.escape(focusPerson)}"] [data-filter-save]`)?.focus();
    else if (hadSave) document.querySelector(`#filter-panel [data-filter-person="${CSS.escape(hadSave)}"] [data-filter-save]`)?.focus();
    else if (had) document.querySelector(`#filter-panel [data-filter-field="${CSS.escape(had)}"]`)?.focus();
  }

  return {
    update() {
      if (!sync() || off) { if (off) { root.replaceChildren(); root.hidden = true; } return; }
      void loadAll();
    },
  };
}
