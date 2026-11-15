// Children, device groups and their devices (real router integration, admins only). Every change asks for a fresh
// passkey confirmation (step-up) bound to that exact change; device changes then go through the router rpc-sync path.
// All dynamic text is rendered with textContent. createBulk (same file, same helpers) is the Block all / Unblock all panel for admins and parents.
import { getPasskey } from './auth-client.js';
import { createWizard } from './inventory-wizard.js';
import { childCard } from './kids-card.js';
import { triageOn, triageView, triageStatus, groupCounts, roleWord, UNDO_SECONDS } from './inventory-triage.js';

const PENDING_COMMAND = 'cfctl scope-add <ADDRESS FROM DEVICE SETTINGS> --base <router-read>'; // a placeholder only; the address is never shown next to it

// What a bulk operation means for the household right now. The server's `effect` decides the wording, never the bare state.
const EFFECT_TEXT = { blocking: 'Blocking: the router confirmed it.', not_blocking: 'Not in force.', unblocked: 'Unblocked: the router confirmed it.', may_still_be_blocked: 'May still be blocked.', unchanged: 'Nothing changed.' };
const LEAD_TEXT = { pending: 'Sent to the router — not confirmed yet.', failed: 'The router did not apply it.', unknown: 'Outcome unknown.', conflict: 'The router policy changed first.' };
export function effectText(operation, verb) {
  const effect = EFFECT_TEXT[operation.effect];
  if (!effect) return null;
  const unhealthy = operation.state === 'confirmed' && ['not_blocking', 'may_still_be_blocked'].includes(operation.effect);
  const lead = unhealthy ? 'The router is not confirming it right now.' : LEAD_TEXT[operation.state];
  return `${verb}: ${lead ? `${lead} ` : ''}${effect}`;
}

// A body that is not JSON (a 502 page from a proxy, say) is null, never a raw parse error for the person to read.
async function readJson(response) {
  try { const body = await response.json(); return body !== null && typeof body === 'object' ? body : null; } catch { return null; }
}

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key.startsWith('data-') || key.startsWith('aria-') || key === 'for') node.setAttribute(key, value);
    else node[key] = value;
  }
  node.append(...children);
  return node;
}

export function createChildren({ session, revisionToken, refresh, version, replaced = () => new Set(), wizard = { enabled: () => false, open: () => {} } }) {
  const root = document.querySelector('#children-panel');
  // prefill = the open add form's draft: { id, label, mac, warn }. confirm = the open confirm sentence: { kind: 'remove' | 'move' | 'child_remove', id }.
  let key = '', data = null, notice = '', loadError = false, approved = [], busy = false, lastVersion = null, prefill = null, focusPrefill = false, confirm = null, focus = '', drawn = '', skipped = false;
  const moveChoice = new Map(); // device id -> chosen target child, kept across redraws
  const labels = new Map(); // scope request id -> the name typed in this session (the service holds only what the router reported)
  const enabled = () => document.documentElement.dataset.source === 'real-router-integration' && session()?.actor.role === 'admin';

  async function call(path, body) {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': session().csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(130000),
    });
    const result = await readJson(response);
    if (!response.ok || result === null) { const error = new Error(result?.error?.message ?? 'The request could not be completed.'); error.status = response.status; error.code = result?.error?.code; error.requestId = result?.error?.requestId; throw error; }
    return result;
  }
  async function load() {
    if (!enabled()) { data = null; draw(); return; }
    try {
      const next = await call('/admin/children');
      approved = settleApproved(next); data = next; loadError = false;
    } catch (error) { if (error.status === 401 || error.status === 403) data = null; else loadError = true; } // old rows stay; never the raw server message
    draw();
  }
  // A waiting request that is gone from the list was taken in by the router (or timed out): tell the person it can be added now, until they dismiss it or the child shows a new device.
  function settleApproved(next) {
    const gone = (data?.pendingScope ?? []).filter((r) => !next.pendingScope?.some((n) => n.id === r.id) && next.children.some((c) => c.id === r.childId))
      .map((r) => ({ id: r.id, childId: r.childId, name: labels.get(r.id) ?? r.name ?? 'Unnamed device', devices: next.children.find((c) => c.id === r.childId).devices.length }));
    return [...approved, ...gone].filter((a) => (next.children.find((c) => c.id === a.childId)?.devices.length ?? Infinity) <= a.devices);
  }
  async function confirmed(action, target, params, path, done) {
    if (busy) return;
    busy = true; notice = 'Confirm with your passkey to continue.'; draw();
    try {
      const start = await call('/step-up/options', { action, target, params });
      const response = await getPasskey(start.options);
      notice = done(await call(path, { ...params, stepUp: { challengeId: start.challengeId, response } })) ?? '';
    } catch (error) {
      if (error.code === 'device_pending_router_scope') {
        // Not an error: the request is recorded by the service and listed from there (it survives a reload). Only the typed name is kept here.
        if (error.requestId) labels.set(error.requestId, params.label);
        notice = '';
      } else notice = error.name === 'NotAllowedError' ? 'Passkey confirmation was cancelled. Nothing changed.' : friendly(error);
    }
    busy = false;
    await load();
    refresh();
  }
  // A busy or broken service is said in plain words; the service's own message is shown only for a refusal it chose to explain (4xx other than 429).
  const friendly = (error) => (error.status === 429 ? 'Too many changes at once. Wait a minute and try again.' : !error.status || error.status >= 500 ? "Couldn't reach Couvre-feu. Check the list before trying again." : error.message);
  const queued = (result) => result.operation ? `Sent to the router (${result.operation.state}). The device list updates once the router confirms.` : null;
  function rejection(last) {
    if (!last) return [];
    const devices = last.devices.map((d) => `${d.device} (${d.child})`).join(', ');
    return [el('div', { class: 'notice', role: 'alert', 'data-rejection': '' },
      el('strong', {}, 'The router refused the last change: a managed device had no network address (it may be off or away). Nothing changed.'),
      el('p', {}, `The router does not say which device. Check that these are on and connected, or remove one that is gone: ${devices || 'none in your scope'}${last.otherDevices ? ` and ${last.otherDevices} other device${last.otherDevices === 1 ? '' : 's'}` : ''}.`))];
  }
  function pendingNotice() {
    const count = data.pendingScope?.length ?? 0;
    if (!count) return [];
    return [el('div', { class: 'notice', role: 'status', 'data-pending-approval': '' },
      el('strong', {}, 'Waiting for router approval'),
      el('p', {}, `The router does not know ${count === 1 ? 'one device' : `${count} devices`} yet, so nothing was added and nothing is blocked. A router administrator must approve the device's address first (${PENDING_COMMAND}).`),
      el('p', {}, "Read the address from the device's own Wi-Fi settings, never from this page. Add the device here again once the router has approved it."))];
  }
  function move(entry, device, to) {
    if (!to) return;
    confirm = null;
    if (to === entry.id) { notice = `${device.label} already belongs to ${entry.name}.`; focus = `[data-row-menu][data-fk="menu-${device.id}"]`; draw(); return; }
    moveChoice.delete(device.id);
    void confirmed('device_move', device.id, { to, precondition: revisionToken() }, `/admin/devices/${device.id}/move`, queued);
  }
  function remove(device) {
    confirm = null;
    void confirmed('device_remove', device.id, { precondition: revisionToken() }, `/admin/devices/${device.id}/remove`, (result) => queued(result) ?? `Removed ${device.label}.`);
  }
  function removeChild(entry) {
    confirm = null;
    void confirmed('child_remove', entry.id, {}, `/admin/children/${entry.id}/remove`, () => `Removed ${entry.name}.`);
  }
  function openForm(id) { confirm = null; prefill = { id, label: '', mac: '', warn: false }; notice = ''; focusPrefill = true; draw(); }
  function submitAdd(entry, values) {
    prefill = null;
    void confirmed('device_add', entry.id, { ...values, precondition: revisionToken() }, `/admin/children/${entry.id}/devices`, queued);
  }
  const closeSentence = (selector) => { confirm = null; focus = selector; draw(); };
  const handlers = {
    onAdd: (entry, button) => { if (wizard.enabled()) wizard.open(entry.id, button); else openForm(entry.id); },
    onCancelAdd: (entry) => { prefill = null; focus = `[data-add-device-open="${CSS.escape(entry.id)}"]`; draw(); },
    onSubmitAdd: submitAdd,
    onChoose: (kind, subject) => { confirm = { kind, id: subject.id }; notice = ''; focus = `[data-entry] [data-confirm] [data-confirm-text]`; draw(); },
    onCancel: () => { const was = confirm; closeSentence(was?.kind === 'child_remove' ? `[data-remove-child="${CSS.escape(was.id)}"]` : `[data-fk="menu-${CSS.escape(was?.id ?? '')}"]`); },
    onMove: move, onRemove: remove, onRemoveChild: removeChild,
    onDismissApproved: (id) => { approved = approved.filter((a) => a.id !== id); draw(); },
    onMenuClosed: () => { if (skipped) { skipped = false; draw(); } },
  };
  function card(entry) {
    return childCard({ entry, h: handlers, busy, confirm, prefill, moveChoice, labels, replaced: replaced(), approved: approved.filter((a) => a.childId === entry.id),
      others: data.children.filter((c) => c.id !== entry.id), pending: (data.pendingScope ?? []).filter((request) => request.childId === entry.id) });
  }
  function createForm() {
    const form = el('form', { class: 'account-form' },
      el('label', { for: 'new-entry-name' }, 'New name'),
      el('input', { id: 'new-entry-name', name: 'name', required: true, maxLength: 64, autocomplete: 'off' }),
      el('label', { for: 'new-entry-kind' }, 'Type'),
      el('select', { id: 'new-entry-kind', name: 'kind' }, el('option', { value: 'child' }, 'Child'), el('option', { value: 'device_group' }, 'Device group (e.g. a TV)')),
      el('button', { class: 'button primary', type: 'submit', disabled: busy }, 'Add'));
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const params = { name: form.elements.name.value.trim(), kind: form.elements.kind.value };
      void confirmed('child_create', '', params, '/admin/children', (result) => `Added ${result.child.name}. Add its devices below.`);
    });
    return form;
  }
  function draw() {
    if (!enabled() || !data) { drawn = ''; root.hidden = true; root.replaceChildren(); return; }
    // Never rebuild while typing, choosing in a list, or with a ⋯ menu open: it would drop the keyboard's place. The menu's close redraws.
    const active = document.activeElement;
    if (root.contains(active) && (active.matches('input') || (active.matches('select') && !active.closest('.confirm-sentence')))) return; // a move list is redrawn from fresh data
    if (root.querySelector('.row-menu-list')) { skipped = true; return; }
    const open = prefill && root.querySelector(`[data-add-device="${CSS.escape(prefill.id)}"]`);
    if (open && !focusPrefill) prefill = { ...prefill, label: open.elements.label.value, mac: open.elements.mac.value }; // keep what the parent typed over the original prefill
    if (confirm && !(confirm.kind === 'child_remove' ? data.children.some((c) => c.id === confirm.id) : data.children.some((c) => c.devices.some((d) => d.id === confirm.id)))) confirm = null; // the row is gone: no sentence about it
    const signature = JSON.stringify([data, notice, loadError, approved, busy, confirm, prefill, [...replaced()], [...labels]]);
    if (signature === drawn && !focus && !focusPrefill) return; // nothing changed: keep focus where it is
    drawn = signature; skipped = false;
    const kept = root.contains(active) ? active.dataset?.fk : null;
    root.replaceChildren(
      el('h2', { id: 'children-title' }, 'Children and device groups'),
      el('p', { class: 'fine-print' }, `Adults' protected devices can never be added. The router holds at most ${data.limits.children} entries, ${data.limits.devicesPerChild} devices each and ${data.limits.devices} in total; every device must be in its installed allow list. Each change needs your passkey and a router confirmation.`),
      el('p', { class: 'notice', role: 'status', hidden: !notice && !loadError }, loadError ? "Couldn't refresh the list. Showing the last list. Retry." : notice),
      ...(loadError ? [el('button', { class: 'button secondary', type: 'button', onclick: () => void load() }, 'Retry')] : []),
      ...pendingNotice(),
      ...rejection(data.lastRejection),
      el('ul', { class: 'account-list', 'aria-label': 'Children and device groups' }, ...data.children.map(card)),
      ...(data.canCreate ? [el('h3', {}, 'Add a child or device group'), createForm()] : []));
    root.hidden = false;
    if (focusPrefill) {
      focusPrefill = false;
      const input = prefill && root.querySelector(`[data-add-device="${CSS.escape(prefill.id)}"] input[name="label"]`);
      input?.scrollIntoView({ block: 'center' }); input?.focus();
    } else if (focus) { root.querySelector(focus)?.focus(); focus = ''; }
    else if (kept) root.querySelector(`[data-fk="${CSS.escape(kept)}"]`)?.focus();
  }
  // Used by the network list and the wizard: open one child's add form with a name and address filled in. Nothing is sent from here.
  function startAdd(id, values) {
    if (!enabled() || !data?.children.some((c) => c.id === id)) return false;
    prefill = { id, label: String(values.label ?? '').slice(0, 64), mac: String(values.mac ?? ''), warn: true };
    confirm = null; notice = ''; focusPrefill = true;
    document.activeElement?.blur?.();
    draw();
    return true;
  }
  function clearPrefill() { if (prefill) { prefill = null; draw(); } }
  const entries = () => (data?.children ?? []).map((c) => ({ id: c.id, name: c.name }));
  function update() {
    const current = session(), next = current ? `${current.actor.id}:${current.actor.role}:${current.csrfToken}` : '';
    if (next !== key) { key = next; data = null; notice = ''; loadError = false; approved = []; labels.clear(); prefill = null; confirm = null; focus = ''; moveChoice.clear(); draw(); if (next) void load(); return; }
    // Router observations settle queued device changes; reload when the status snapshot moves.
    const seen = version();
    if (next && seen !== lastVersion) { lastVersion = seen; void load(); }
  }
  return { update, load, startAdd, clearPrefill, entries, redraw: draw };
}

// "Block all kids" / "Unblock all": one router change for every child the signed-in account manages. Admins and parents alike.
// The confirmation is in the page (never window.confirm), names the children, and comes before the passkey step-up.
const UNKNOWN_OUTCOME = 'The request may have reached the router — outcome unknown. Check the status below before trying again.';
const BULK = {
  pause_all: { path: '/bulk/pause-all', button: 'Block all kids', confirm: 'Confirm block all kids', verb: 'Block all', intro: 'Block internet for these children until you unblock them:', params: (precondition) => ({ until: 0, precondition }) },
  resume_all: { path: '/bulk/resume-all', button: 'Unblock all', confirm: 'Confirm unblock all', verb: 'Unblock all', intro: 'Lift manual blocks for these children (a schedule can still block):', params: (precondition) => ({ precondition }) },
};

export function createBulk({ gate = () => null, session, people, revisionToken, refresh, version }) {
  const root = document.querySelector('#bulk-panel');
  let key = '', confirming = null, busy = false, notice = '', operation = null, lastVersion = null, drawn = '', focus = '', retry = null;
  const enabled = () => document.documentElement.dataset.source === 'real-router-integration' && Boolean(session()) && people().length > 0;

  async function call(path, body, idempotencyKey) {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': session().csrfToken, ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(130000),
    });
    const result = await readJson(response);
    if (result === null || !response.ok && !result.operation) {
      // Only a readable answer below 500 is the service's own decision; anything else leaves the outcome open.
      const error = new Error(result?.error?.message ?? 'The request could not be completed.');
      error.definitive = result !== null && response.status < 500;
      throw error;
    }
    return result;
  }
  // One key per exact change, reused for an immediate retry after an unknown outcome so a retry cannot apply twice.
  function keyFor(action, precondition) {
    const signature = JSON.stringify([action, precondition, [...people()].map((p) => p.id).sort()]);
    if (retry?.signature !== signature) retry = { signature, key: `bulk_${crypto.randomUUID().replaceAll('-', '')}` };
    return retry.key;
  }
  async function run(action) {
    const precondition = revisionToken();
    confirming = null;
    if (busy) return;
    const blocked = gate();
    if (blocked || !precondition) { notice = `${blocked ?? 'The router status is not confirmed right now'}, so nothing was sent. Refresh the status and try again.`; draw(); return; }
    busy = true; operation = null; notice = 'Confirm with your passkey to continue.'; draw();
    const params = BULK[action].params(precondition);
    let posted = false;
    try {
      const start = await call('/step-up/options', { action, params });
      const response = await getPasskey(start.options);
      const key = keyFor(action, precondition);
      posted = true; // from here the request may have left, whatever happens next
      const result = await call(BULK[action].path, { ...params, stepUp: { challengeId: start.challengeId, response } }, key);
      operation = result.operation; notice = ''; retry = null;
    } catch (error) {
      if (!posted) notice = error.name === 'NotAllowedError' ? 'Passkey confirmation was cancelled. Nothing changed.' : `${error.message} Nothing was sent.`;
      else if (error.definitive) { retry = null; notice = `${error.message} The change was not made.`; }
      else notice = UNKNOWN_OUTCOME;
    }
    busy = false; draw(); refresh();
  }
  async function follow() {
    if (!operation) return;
    try { const next = await call(`/operations/${encodeURIComponent(operation.id)}`); if (next.id === operation.id) operation = next; } catch { /* keep the last known state; it is never upgraded */ }
    draw();
  }
  function confirmBox() {
    const spec = BULK[confirming];
    const names = [...people()].map((p) => p.name).sort((a, b) => a.localeCompare(b));
    return el('div', { class: 'bulk-confirm', role: 'group', 'aria-label': spec.confirm },
      el('p', {}, spec.intro), el('ul', {}, ...names.map((name) => el('li', {}, name))),
      el('p', { class: 'fine-print' }, 'Your passkey is asked next, then the change is sent to the router. It counts only once the router confirms it.'),
      el('div', { class: 'person-controls' },
        el('button', { class: 'button primary', type: 'button', onclick: () => void run(confirming) }, 'Confirm with passkey'),
        el('button', { class: 'button secondary', type: 'button', onclick: () => { const action = confirming; confirming = null; focus = `[data-action="${action}"]`; draw(); } }, 'Cancel')));
  }
  function draw() {
    if (!enabled()) { drawn = ''; root.hidden = true; root.replaceChildren(); return; }
    const unsettled = busy || (operation && ['pending', 'unknown'].includes(operation.state));
    const reason = (unsettled ? 'A change is already in progress' : gate()) ?? (revisionToken() === null ? 'Status is out of date — refresh' : '');
    const locked = Boolean(reason);
    const text = operation ? effectText(operation, BULK[operation.action]?.verb ?? 'Change') ?? '' : notice;
    const signature = JSON.stringify([reason, confirming, text, people().map((p) => p.name)]);
    if (signature === drawn && !focus) return; // never rebuild (and drop keyboard focus) when nothing changed
    drawn = signature;
    root.replaceChildren(
      el('h2', { id: 'bulk-title' }, 'Block or unblock everything'),
      el('p', { class: 'fine-print' }, 'Applies to every child you manage, in one change. Each change needs your passkey and the router\'s confirmation. Block all lasts until you unblock.'),
      el('p', { class: 'notice', role: 'status', 'data-bulk-status': '', hidden: !text }, text),
      el('p', { class: 'fine-print', 'data-bulk-reason': '', hidden: !reason }, reason),
      el('div', { class: 'bulk-actions' },
        ...Object.entries(BULK).map(([action, spec]) => el('button', { class: action === 'pause_all' ? 'button primary' : 'button secondary', type: 'button', disabled: locked,
          'data-action': action, onclick: () => { confirming = action; notice = ''; focus = '.bulk-confirm .button'; draw(); } }, spec.button))),
      ...(confirming ? [confirmBox()] : []));
    root.hidden = false;
    if (focus) { root.querySelector(focus)?.focus(); focus = ''; }
  }
  function update() {
    const current = session(), next = current ? `${current.actor.id}:${current.actor.role}:${current.csrfToken}` : '';
    if (next !== key) { key = next; confirming = null; busy = false; notice = ''; operation = null; lastVersion = null; retry = null; draw(); return; }
    const seen = version();
    if (next && seen !== lastVersion) { lastVersion = seen; void follow(); }
    draw();
  }
  return { update };
}

// "Devices on the network" (admins only): what the router has seen on the home network, newest first. A device name is text the DEVICE
// chose and often holds a real person's name, so it is only ever set with textContent and is labelled as such. A list from the router is a
// hint, never proof: a stalled or failed scan never reads as "all clear". Addresses (MACs) are not shown; they only travel into the add form.
const STALL_SECONDS = 1800;
const FLAGS = [['new', 'New'], ['private', 'Private address'], ['unassigned', 'Unassigned']];
const PRIVATE_HINT = 'may rotate — set a fixed Wi-Fi address on this device';
const DISPATCH_OFF = 'Inventory polling is off until router dispatch is enabled', RATE_LIMITED = 'Try again in a few seconds';
const REFRESH_FAILURES = new Map([['inventory_dispatch_disabled', DISPATCH_OFF], ['inventory_refresh_rate_limited', RATE_LIMITED]]); // a Map: a code like "constructor" finds nothing
const REFRESH_STATUS = new Map([[409, DISPATCH_OFF], [429, RATE_LIMITED]]);
const NOTE_SECONDS = 30;
// Triage wording (plain, for a parent who cannot fix the router): what to do, never router vocabulary.
const TRIAGE_REFRESH_OFF = "Refresh isn't switched on yet. Tell JD.";
const TRIAGE_FAILURES = new Map([[404, 'That device is no longer listed.'], [409, 'That device already belongs to a child.'], [429, 'Too many changes at once. Wait a minute and try again.']]);

function causeText(error) {
  if (error === 'inventory_unavailable:old_router') return 'Router too old for inventory.';
  if (error === 'inventory_warning:invalid_clock') return 'The router clock looks wrong, so times may be off.';
  if (error === 'inventory_row_cap') return 'The router lists more devices than can be kept; the oldest unseen ones were left out.';
  if (error.startsWith('inventory_incomplete:')) return 'The last scan was incomplete.';
  if (error.startsWith('inventory_transport_error:') || error.startsWith('inventory_unavailable:')) return 'Router connection problem.';
  return 'The last scan did not complete.';
}
// Plain wording for the scan state. `clear` is true only when a recent complete scan is the latest word AND nothing is wrong.
export function inventoryStatus(status, nowSeconds, time) {
  const error = status.lastError ?? '', since = status.lastOkAt ? ` Showing the last complete scan from ${time(status.lastOkAt)}.` : '';
  if (!status.lastOkAt && !error) return { kind: 'none', clear: false, text: 'No complete scan yet. The router has not reported its devices.' };
  const stalled = !status.lastOkAt || nowSeconds - status.lastOkAt > STALL_SECONDS;
  if (stalled) return { kind: 'stalled', clear: false, text: `Inventory is stalled — check the router.${error ? ` ${causeText(error)}` : ''}${since}` };
  if (error === 'inventory_unavailable:old_router') return { kind: 'old_router', clear: false, text: `${causeText(error)}${since}` };
  if (error === 'inventory_warning:invalid_clock') return { kind: 'clock_warning', clear: false, text: `Last complete scan ${time(status.lastOkAt)}. ${causeText(error)}` }; // times are doubtful, so no all-clear
  if (error) return { kind: 'degraded', clear: false, text: `${causeText(error)}${since}` };
  return { kind: 'ok', clear: status.baselineAt !== null, text: `Last complete scan ${time(status.lastOkAt)}.` };
}

export function createInventory({ session, gate, offline, time, children, version, onList = () => {} }) {
  const root = document.querySelector('#inventory-panel');
  let key = '', data = null, loadedAt = null, loadFailed = false, notice = '', refreshNote = '', busy = false, picking = null, choice = '', lastVersion = null, drawn = '', timer = null, noteTimer = null, filter = 'new', undo = null, undoTimer = null;
  let serverNow = null, loadedPerf = 0, mounted = false, fetched = false, inFlight = false, swallowed = false; // swallowed: the first version bump was dropped as a duplicate of the in-flight first load, so a failure of that load must retry itself. fetched: a list request was issued for this session key. serverNow: the service clock at the last load, advanced by this page's own elapsed time
  const title = el('h2', { id: 'inventory-title', tabindex: -1 }, 'Devices on the network');
  const live = el('p', { class: 'fine-print', role: 'status', 'aria-live': 'polite', 'data-live': '', 'data-refresh-status': '' }); // one node for the life of the panel, so screen readers hear changes
  const body = el('div');
  const enabled = () => document.documentElement.dataset.source === 'real-router-integration' && session()?.actor.role === 'admin';
  // Scan age is measured on the SERVER's clock. Unknown (an older service) counts as stalled: never an all-clear on a guess.
  const nowSeconds = () => (serverNow === null ? Number.POSITIVE_INFINITY : serverNow + Math.floor((performance.now() - loadedPerf) / 1000));
  const closed = () => busy || Boolean(gate());
  const wizard = createWizard({ data: () => data, load: (signal) => load({ signal }), now: () => nowSeconds(), children,
    refresh: (signal) => call('/admin/inventory/refresh', {}, signal), stable: (id, value) => call(`/admin/inventory/${id}/stable`, { value }) }); // hoisted: call and load are declared below
  const sorted = (list) => [...list].sort((a, b) => b.firstSeen - a.firstSeen || b.lastSeen - a.lastSeen);
  function setNote(text) {
    refreshNote = text; clearTimeout(noteTimer);
    noteTimer = setTimeout(() => { refreshNote = ''; draw(); }, NOTE_SECONDS * 1000);
  }

  async function call(path, body, abort) {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': session().csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body), signal: abort ? AbortSignal.any([AbortSignal.timeout(20000), abort]) : AbortSignal.timeout(20000),
    });
    const result = await readJson(response);
    if (!response.ok || result === null) { const error = new Error(result?.error?.message ?? 'The request could not be completed.'); error.status = response.status; error.code = result?.error?.code; throw error; }
    return result;
  }
  /** Resolves true when a fresh list arrived, false when it did not (offline, failed or aborted); `signal` lets the wizard cancel its own reads. */
  async function load({ signal } = {}) {
    if (!enabled()) { data = null; swallowed = false; draw(); return false; }
    if (offline()) { swallowed = false; draw(); return false; } // keep the saved list; it is labelled as saved
    const mine = key;
    fetched = true; inFlight = true;
    let retry = false, ok = false;
    try {
      const result = await call('/admin/inventory', undefined, signal);
      if (mine !== key) return false;
      data = result.inventory; loadFailed = false; swallowed = false;
      serverNow = Number.isFinite(result.now) ? result.now : null; loadedPerf = performance.now(); loadedAt = serverNow ?? Math.floor(Date.now() / 1000);
      refreshNote = ''; clearTimeout(noteTimer); // a request note is stale once a newer list has arrived
      ok = true;
    } catch (error) {
      if (mine !== key || signal?.aborted) return false; // an aborted wizard read is not a failed load
      if (error.status === 401 || error.status === 403) { data = null; swallowed = false; }
      else {
        loadFailed = true;
        if (swallowed) { swallowed = false; retry = true; } // the bump that would have retried this was swallowed while it was in flight
      }
    } finally { if (mine === key) inFlight = false; }
    draw();
    if (ok) onList(); // the Kids tab shows hints taken from this list
    if (retry) void load();
    return ok;
  }
  async function acknowledge(device) {
    if (closed()) { draw(); return; }
    const position = sorted(data.devices).filter((d) => d.flags.new).indexOf(device);
    busy = true; notice = ''; refreshNote = ''; draw();
    try { await call('/admin/inventory/acknowledge', { mac: device.mac }); notice = `Acknowledged ${(device.hostname ?? 'device').slice(0, 40)}.`; } catch (error) { notice = error.status === 404 ? 'That device is no longer listed.' : error.message; }
    busy = false;
    await load();
    refocus(position);
  }
  // The button that was pressed is gone after a redraw; keep keyboard and screen-reader users in the list instead of dropping them on the page.
  function refocus(position) {
    const active = document.activeElement;
    if (!mounted || (active && active !== document.body && !root.contains(active))) return;
    const buttons = Array.from(root.querySelectorAll('[data-ack]:not(:disabled)'));
    (buttons[Math.min(Math.max(position, 0), buttons.length - 1)] ?? title).focus();
  }
  async function refreshNow() {
    if (closed()) { draw(); return; }
    busy = true; refreshNote = ''; notice = ''; draw();
    try {
      await call('/admin/inventory/refresh', {});
      setNote('Refresh requested. The list updates when the router answers.');
      clearTimeout(timer); timer = setTimeout(() => void load(), 5000);
    } catch (error) { setNote(triageOn(data) && REFRESH_STATUS.get(error.status) === DISPATCH_OFF ? TRIAGE_REFRESH_OFF : REFRESH_FAILURES.get(error.code) ?? REFRESH_STATUS.get(error.status) ?? error.message); }
    busy = false;
    draw();
    if (triageOn(data)) void load(); // the list itself is re-read too, so Refresh also retries a failed load
  }
  // Triage decisions (UI plan F). Rows are addressed by id, never by address. Adult, Home, Infra and Hide apply at once and can be undone for UNDO_SECONDS.
  const patch = (device) => { const devices = data.devices.map((d) => (d.id === device.id ? device : d)); data = { ...data, devices, newCount: devices.filter((d) => d.flags.new).length }; };
  async function decide(device, action, body, done) {
    if (closed()) { draw(); return; }
    busy = true; notice = ''; refreshNote = ''; draw();
    try { done((await call(`/admin/inventory/${device.id}/${action}`, body)).device); } catch (error) { notice = TRIAGE_FAILURES.get(error.status) ?? "Couldn't save that. Nothing was changed."; }
    busy = false; draw();
  }
  function classify(device, role) {
    return decide(device, 'classify', { role }, (updated) => {
      patch(updated); clearTimeout(undoTimer);
      undo = { id: device.id, text: `${role === 'ignored' ? 'Hid' : 'Moved'} ${(device.hostname ?? 'device').slice(0, 40)}${role === 'ignored' ? '.' : ` to ${roleWord(role)}.`}` };
      undoTimer = setTimeout(() => { undo = null; draw(); }, UNDO_SECONDS * 1000);
    });
  }
  function undoLast() {
    const last = undo;
    return last ? decide({ id: last.id }, 'undo', {}, (updated) => { patch(updated); undo = null; clearTimeout(undoTimer); }) : undefined;
  }
  async function linkSame(device) {
    await decide(device, 'link', { replaces: device.suggestedReplaces }, patch);
    await load();
  }
  function startChild(device, child) {
    if (closed()) { draw(); return; }
    if (!children.startAdd(child.id, { label: device.hostname ?? '', mac: device.mac })) { notice = "Couldn't open the add form. Try Refresh."; draw(); return; }
    notice = `The add form for ${child.name} is open below.`; draw();
  }
  function startAssign(device) {
    if (closed()) { draw(); return; }
    const label = device.hostname ?? '';
    if (!choice || !children.startAdd(choice, { label, mac: device.mac })) { notice = 'Choose a child or device group first.'; draw(); return; }
    picking = null; choice = ''; notice = ''; draw();
  }
  function picker(device, name) {
    const options = children.entries();
    if (!options.length) return [el('p', { class: 'fine-print' }, 'Add a child or device group first (below), then come back.')];
    const select = el('select', { 'aria-label': `Child for ${name}`, onchange: () => { choice = select.value; } },
      el('option', { value: '' }, 'Choose…'), ...options.map((c) => el('option', { value: c.id }, c.name)));
    select.value = options.some((c) => c.id === choice) ? choice : '';
    return [el('div', { class: 'inventory-actions' }, select,
      el('button', { class: 'button primary', type: 'button', onclick: () => startAssign(device) }, 'Continue'),
      el('button', { class: 'button secondary', type: 'button', onclick: () => { picking = null; choice = ''; children.clearPrefill(); draw(); } }, 'Cancel'))];
  }
  function deviceRow(device, locked) {
    const name = device.hostname ?? 'No name reported', short = name.slice(0, 40);
    const flags = FLAGS.filter(([flag]) => device.flags[flag]);
    const hints = [device.vendor, device.kind && device.kind !== 'unknown' ? `${device.kind}?` : null].filter(Boolean); // maker from the address and a kind guess from the name: hints, never proof
    return el('li', { class: 'passkey-row inventory-row' },
      el('span', { class: 'inventory-name', 'data-name': '', dir: 'auto' }, name),
      ...(device.hostname === null ? [] : [el('span', { class: 'fine-print' }, 'name reported by device')]),
      ...(hints.length ? [el('span', { class: 'fine-print', 'data-hints': '' }, `Guess: ${hints.join(' · ')}`)] : []),
      ...(flags.length ? [el('span', { class: 'inventory-flags' }, ...flags.map(([flag, label]) => el('span', { class: `inventory-flag flag-${flag}`, 'data-flag': flag }, label)))] : []),
      ...(device.flags.private ? [el('span', { class: 'fine-print' }, `Private address: ${PRIVATE_HINT}`)] : []),
      el('span', { class: 'fine-print' }, `${device.ipv4.length ? device.ipv4.join(', ') : 'No IPv4 address'} · Last seen ${time(device.lastSeen)}`),
      el('span', { class: 'fine-print' }, `First seen ${time(device.firstSeen)}`),
      ...(device.personName ? [el('span', { class: 'fine-print' }, `Belongs to ${device.personName}`)] : []),
      el('div', { class: 'inventory-actions' },
        ...(device.flags.new ? [el('button', { class: 'button secondary', type: 'button', disabled: locked, 'data-ack': '', 'aria-label': `Acknowledge ${short}`, onclick: () => void acknowledge(device) }, 'Acknowledge')] : []),
        ...(device.flags.unassigned ? [el('button', { class: 'button secondary', type: 'button', disabled: locked, 'aria-label': `Add to a child: ${short}`,
          onclick: () => { if (closed()) { draw(); return; } picking = device.mac; choice = ''; notice = ''; draw(); } }, 'Add to a child…')] : [])),
      ...(picking === device.mac && !locked ? picker(device, short) : []));
  }
  function draw() {
    if (!enabled() || !data) { wizard.close({ restore: false }); drawn = ''; mounted = false; root.hidden = true; delete root.dataset.newCount; root.replaceChildren(); live.textContent = ''; return; }
    if (!mounted) { root.replaceChildren(title, live, body); mounted = true; }
    const liveText = refreshNote || notice;
    if (live.textContent !== liveText) live.textContent = liveText;
    const stale = offline() || loadFailed;
    const reason = gate() ?? '', locked = busy || Boolean(reason);
    const ordered = sorted(data.devices);
    const status = inventoryStatus(data.status, nowSeconds(), time);
    const newCount = ordered.filter((d) => d.flags.new).length;
    root.dataset.newCount = String(newCount); // read by the tab bar for the Devices badge
    const clear = status.clear && !stale && newCount === 0;
    const summary = clear ? 'No new devices.' : newCount ? `${newCount} new device${newCount === 1 ? '' : 's'} to review.` : '';
    const triage = triageOn(data);
    const signature = JSON.stringify([data, reason, stale, loadedAt, status.text, summary, notice, refreshNote, picking, busy, children.entries(), triage, filter, undo]);
    if (signature === drawn) return; // never rebuild (and drop keyboard focus) when nothing changed
    if (root.contains(document.activeElement) && document.activeElement.matches('select')) { drawn = ''; return; }
    drawn = signature;
    if (triage) {
      const toSort = groupCounts(data.devices).new;
      body.replaceChildren(
        el('p', { class: 'fine-print' }, 'Names come from the devices themselves and are not verified.'),
        ...triageView({ data, filter, undo, statusText: triageStatus(data.status, status, nowSeconds(), toSort), failed: loadFailed && !offline(), locked, nowSeconds: nowSeconds(), children: children.entries(),
          h: { onFilter: (next) => { filter = next; draw(); }, onRole: (d, role) => void classify(d, role), onChild: startChild, onLink: (d) => void linkSame(d), onUndo: () => void undoLast(), onRetry: () => void load(), onRefresh: () => void refreshNow() } }),
        ...(offline() ? [el('p', { class: 'fine-print', 'data-inventory-snapshot': '' }, `Showing a saved list from ${time(loadedAt)}. It updates when the connection returns.`)] : []),
        el('p', { class: 'fine-print', 'data-inventory-reason': '', hidden: !reason }, reason),
        ...(data.wizard === true ? [wizard.button()] : []));
      root.hidden = false;
      return;
    }
    body.replaceChildren(
      el('p', { class: 'fine-print' }, 'What the router has seen. Device names are chosen by the devices themselves and are not verified. Protected devices are never listed.'),
      el('p', { class: 'notice', 'data-inventory-status': status.kind }, status.text, ...(summary ? [' ', el('strong', clear ? { 'data-all-clear': '' } : {}, summary)] : [])),
      ...(stale ? [el('p', { class: 'fine-print', 'data-inventory-snapshot': '' }, offline() ? `Showing a saved list from ${time(loadedAt)}. It updates when the connection returns.` : `Showing a saved list from ${time(loadedAt)}. Couvre-feu did not answer, so it may be out of date. Use Refresh now to try again.`)] : []),
      el('p', { class: 'fine-print', 'data-inventory-reason': '', hidden: !reason }, reason),
      el('div', { class: 'inventory-actions' }, el('button', { class: 'button secondary', type: 'button', disabled: locked, onclick: () => void refreshNow() }, 'Refresh now')),
      el('ul', { class: 'account-list', 'aria-label': 'Devices on the network' }, ...ordered.map((device) => deviceRow(device, locked))));
    root.hidden = false;
  }
  function update() {
    const current = session(), next = current ? `${current.actor.id}:${current.actor.role}:${current.csrfToken}` : '';
    if (next !== key) {
      wizard.close({ restore: false });
      key = next; data = null; loadedAt = null; loadFailed = false; notice = ''; refreshNote = ''; picking = null; choice = ''; lastVersion = null; fetched = false; inFlight = false; swallowed = false; drawn = ''; serverNow = null; clearTimeout(timer); clearTimeout(noteTimer); clearTimeout(undoTimer); filter = 'new'; undo = null;
      draw(); if (next) void load(); return;
    }
    const seen = version();
    if (next && seen !== lastVersion) {
      // The first version seen after sign-in (the people list arrives ~25 ms after the session) must not repeat the load the session change already issued.
      const covered = lastVersion === null && fetched && !loadFailed; // a failed first load is not covered: this bump retries it
      lastVersion = seen;
      if (covered) swallowed = inFlight; else { void load(); return; }
    }
    draw();
  }
  return { update, load, devices: () => data?.devices ?? [], wizardEnabled: () => data?.wizard === true && triageOn(data), openWizard: (child, from) => wizard.openFor(child, from) };
}
