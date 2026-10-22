// Children, device groups and their devices (real router integration, admins only). Every change asks for a fresh
// passkey confirmation (step-up) bound to that exact change; device changes then go through the router rpc-sync path.
// All dynamic text is rendered with textContent. createBulk (same file, same helpers) is the Block all / Unblock all panel for admins and parents.
import { getPasskey } from './auth-client.js';

const KIND_LABEL = { child: 'Child', device_group: 'Device group' };
const STATE_LABEL = { enrolling: 'Adding…', removing: 'Removing…', moving: 'Moving…' };
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

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key.startsWith('data-') || key.startsWith('aria-') || key === 'for') node.setAttribute(key, value);
    else node[key] = value;
  }
  node.append(...children);
  return node;
}

export function createChildren({ session, revisionToken, refresh, version }) {
  const root = document.querySelector('#children-panel');
  let key = '', data = null, notice = '', busy = false, lastVersion = null, pending = [];
  const moveChoice = new Map(); // device id -> chosen target child, kept across redraws
  const enabled = () => document.documentElement.dataset.source === 'real-router-integration' && session()?.actor.role === 'admin';

  async function call(path, body) {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': session().csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(130000),
    });
    const result = await readJson(response);
    if (!response.ok || result === null) { const error = new Error(result?.error?.message ?? 'The request could not be completed.'); error.status = response.status; error.code = result?.error?.code; throw error; }
    return result;
  }
  async function load() {
    if (!enabled()) { data = null; draw(); return; }
    try { data = await call('/admin/children'); } catch (error) { if (error.status === 401 || error.status === 403) data = null; else notice = error.message; }
    draw();
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
        // Not an error: the request is recorded, the router administrator has a step to do. Held for this session only.
        pending = [...pending, { label: params.label, child: data?.children.find((c) => c.id === target)?.name ?? '' }].slice(-5);
        notice = '';
      } else notice = error.name === 'NotAllowedError' ? 'Passkey confirmation was cancelled. Nothing changed.' : error.message;
    }
    busy = false;
    await load();
    refresh();
  }
  const queued = (result) => result.operation ? `Sent to the router (${result.operation.state}). The device list updates once the router confirms.` : null;
  function rejection(last) {
    if (!last) return [];
    const devices = last.devices.map((d) => `${d.device} (${d.child})`).join(', ');
    return [el('div', { class: 'notice', role: 'alert', 'data-rejection': '' },
      el('strong', {}, 'The router refused the last change: a managed device had no network address (it may be off or away). Nothing changed.'),
      el('p', {}, `The router does not say which device. Check that these are on and connected, or remove one that is gone: ${devices || 'none in your scope'}${last.otherDevices ? ` and ${last.otherDevices} other device${last.otherDevices === 1 ? '' : 's'}` : ''}.`))];
  }
  function pendingNotice() {
    if (!pending.length) return [];
    const names = pending.map((p) => p.child ? `${p.label} (${p.child})` : p.label).join(', ');
    return [el('div', { class: 'notice', role: 'status', 'data-pending-approval': '' },
      el('strong', {}, 'Waiting for router approval'),
      el('p', {}, `${names}: the router does not know ${pending.length === 1 ? 'this device' : 'these devices'} yet, so nothing was added and nothing is blocked. A router administrator must approve the device's address first (${PENDING_COMMAND}).`),
      el('p', {}, "Read the address from the device's own Wi-Fi settings, never from this page. Add the device here again once the router has approved it."),
      el('button', { class: 'button secondary', type: 'button', onclick: () => { pending = []; draw(); } }, 'Dismiss'))];
  }
  function moveControls(entry, device) {
    const others = data.children.filter((c) => c.id !== entry.id);
    if (!others.length) return [];
    const select = el('select', { 'aria-label': `Move ${device.label} to`, disabled: busy || device.state !== 'active',
      onchange: () => { moveChoice.set(device.id, select.value); button.disabled = busy || !select.value; } },
      el('option', { value: '' }, 'Move to…'), ...others.map((c) => el('option', { value: c.id }, c.name)));
    select.value = others.some((c) => c.id === moveChoice.get(device.id)) ? moveChoice.get(device.id) : '';
    const button = el('button', { class: 'button secondary', type: 'button', disabled: busy || device.state !== 'active' || !select.value, 'aria-label': `Move device ${device.label}`,
      onclick: () => move(entry, device, select.value) }, 'Move');
    return [el('div', { class: 'move-controls' }, select, button)];
  }
  function move(entry, device, to) {
    if (!to) return;
    if (to === entry.id) { notice = `${device.label} already belongs to ${entry.name}.`; draw(); return; }
    moveChoice.delete(device.id);
    void confirmed('device_move', device.id, { to, precondition: revisionToken() }, `/admin/devices/${device.id}/move`, queued);
  }
  function deviceRow(entry, device) {
    const where = STATE_LABEL[device.state] ?? (device.onRouter === null ? 'router state unknown' : device.onRouter ? 'on the router' : 'not on the router');
    return el('li', { class: 'passkey-row', 'data-device': device.id },
      el('span', {}, device.label), el('span', { class: 'fine-print' }, `${device.mac} · ${where}`),
      el('button', { class: 'button secondary', type: 'button', disabled: busy || device.state !== 'active', 'aria-label': `Remove device ${device.label} from ${entry.name}`,
        onclick: () => void confirmed('device_remove', device.id, { precondition: revisionToken() }, `/admin/devices/${device.id}/remove`, (result) => queued(result) ?? `Removed ${device.label}.`) }, 'Remove'),
      ...moveControls(entry, device));
  }
  function addForm(entry) {
    const form = el('form', { class: 'account-form', 'data-add-device': entry.id },
      el('label', { for: `device-label-${entry.id}` }, `New device name for ${entry.name}`),
      el('input', { id: `device-label-${entry.id}`, name: 'label', required: true, maxLength: 64, autocomplete: 'off' }),
      el('label', { for: `device-mac-${entry.id}` }, `Wi-Fi address (MAC) for ${entry.name}`),
      el('input', { id: `device-mac-${entry.id}`, name: 'mac', required: true, maxLength: 17, autocomplete: 'off', autocapitalize: 'none', spellcheck: false, placeholder: 'aa:bb:cc:dd:ee:ff' }),
      el('button', { class: 'button primary', type: 'submit', disabled: busy }, 'Add device'));
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const params = { label: form.elements.label.value.trim(), mac: form.elements.mac.value.trim(), precondition: revisionToken() };
      void confirmed('device_add', entry.id, params, `/admin/children/${entry.id}/devices`, queued);
    });
    return form;
  }
  function card(entry) {
    const kind = KIND_LABEL[entry.kind] ?? 'Child';
    return el('li', { class: 'account-card', 'data-entry': entry.id },
      el('strong', {}, entry.name), el('span', { class: 'fine-print' }, `${kind} · ${entry.devices.length} device${entry.devices.length === 1 ? '' : 's'}`),
      el('ul', { class: 'passkey-list', 'aria-label': `Devices of ${entry.name}` }, ...entry.devices.map((device) => deviceRow(entry, device))),
      addForm(entry),
      ...(entry.devices.length ? [] : [el('button', { class: 'button secondary', type: 'button', disabled: busy, 'aria-label': `Remove ${entry.name}`,
        onclick: () => void confirmed('child_remove', entry.id, {}, `/admin/children/${entry.id}/remove`, () => `Removed ${entry.name}.`) }, `Remove ${kind.toLowerCase()}`)]));
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
    if (!enabled() || !data) { root.hidden = true; root.replaceChildren(); return; }
    if (root.contains(document.activeElement) && document.activeElement.matches('input, select')) return; // never rebuild while typing
    root.replaceChildren(
      el('h2', { id: 'children-title' }, 'Children and device groups'),
      el('p', { class: 'fine-print' }, `Adults' protected devices can never be added. The router holds at most ${data.limits.children} entries, ${data.limits.devicesPerChild} devices each and ${data.limits.devices} in total; every device must be in its installed allow list. Each change needs your passkey and a router confirmation.`),
      el('p', { class: 'notice', role: 'status', hidden: !notice }, notice),
      ...pendingNotice(),
      ...rejection(data.lastRejection),
      el('ul', { class: 'account-list', 'aria-label': 'Children and device groups' }, ...data.children.map(card)),
      ...(data.canCreate ? [el('h3', {}, 'Add a child or device group'), createForm()] : []));
    root.hidden = false;
  }
  function update() {
    const current = session(), next = current ? `${current.actor.id}:${current.actor.role}:${current.csrfToken}` : '';
    if (next !== key) { key = next; data = null; notice = ''; pending = []; moveChoice.clear(); draw(); if (next) void load(); return; }
    // Router observations settle queued device changes; reload when the status snapshot moves.
    const seen = version();
    if (next && seen !== lastVersion) { lastVersion = seen; void load(); }
  }
  return { update, load };
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
