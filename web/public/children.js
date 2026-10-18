// Children, device groups and their devices (real router integration, admins only). Every change asks for a fresh
// passkey confirmation (step-up) bound to that exact change; device changes then go through the router rpc-sync path.
// All dynamic text is rendered with textContent.
import { getPasskey } from './auth-client.js';

const KIND_LABEL = { child: 'Child', device_group: 'Device group' };
const STATE_LABEL = { enrolling: 'Adding…', removing: 'Removing…' };

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
  let key = '', data = null, notice = '', busy = false, lastVersion = null;
  const enabled = () => document.documentElement.dataset.source === 'real-router-integration' && session()?.actor.role === 'admin';

  async function call(path, body) {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': session().csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(130000),
    });
    const result = await response.json();
    if (!response.ok) { const error = new Error(result.error?.message ?? 'The request could not be completed.'); error.status = response.status; throw error; }
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
      notice = error.name === 'NotAllowedError' ? 'Passkey confirmation was cancelled. Nothing changed.' : error.message;
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
  function deviceRow(entry, device) {
    const where = STATE_LABEL[device.state] ?? (device.onRouter === null ? 'router state unknown' : device.onRouter ? 'on the router' : 'not on the router');
    return el('li', { class: 'passkey-row', 'data-device': device.id },
      el('span', {}, device.label), el('span', { class: 'fine-print' }, `${device.mac} · ${where}`),
      el('button', { class: 'button secondary', type: 'button', disabled: busy || device.state !== 'active', 'aria-label': `Remove device ${device.label} from ${entry.name}`,
        onclick: () => void confirmed('device_remove', device.id, { precondition: revisionToken() }, `/admin/devices/${device.id}/remove`, (result) => queued(result) ?? `Removed ${device.label}.`) }, 'Remove'));
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
      ...rejection(data.lastRejection),
      el('ul', { class: 'account-list', 'aria-label': 'Children and device groups' }, ...data.children.map(card)),
      ...(data.canCreate ? [el('h3', {}, 'Add a child or device group'), createForm()] : []));
    root.hidden = false;
  }
  function update() {
    const current = session(), next = current ? `${current.actor.id}:${current.actor.role}:${current.csrfToken}` : '';
    if (next !== key) { key = next; data = null; notice = ''; draw(); if (next) void load(); return; }
    // Router observations settle queued device changes; reload when the status snapshot moves.
    const seen = version();
    if (next && seen !== lastVersion) { lastVersion = seen; void load(); }
  }
  return { update, load };
}
