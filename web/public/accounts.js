// Passkeys and parent accounts. Every change asks for a fresh passkey confirmation (step-up) bound to that exact change.
// All dynamic text is rendered with textContent.
import { getPasskey } from './auth-client.js';

const when = (epoch) => epoch ? new Date(epoch * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : 'never';

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

export function createAccounts({ session, people, signedOut }) {
  const root = document.querySelector('#accounts-panel');
  let key = '', mine = null, accounts = null, notice = '', token = null, busy = false;

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
    if (!session()) return;
    try {
      mine = (await call('/account/passkeys')).passkeys;
      accounts = session().actor.role === 'admin' ? (await call('/admin/accounts')).accounts : null;
    } catch (error) {
      if (error.status === 401) { signedOut(); return; }
      notice = error.message;
    }
    draw();
  }
  /** Fresh passkey confirmation for one exact change, then the change itself. */
  async function confirmed(action, target, params, path, done) {
    if (busy) return;
    busy = true; notice = 'Confirm with your passkey to continue.'; token = null; draw();
    try {
      const start = await call('/step-up/options', { action, target, params });
      const response = await getPasskey(start.options);
      const result = await call(path, { ...params, stepUp: { challengeId: start.challengeId, response } });
      notice = done(result) ?? '';
    } catch (error) {
      notice = error.name === 'NotAllowedError' ? 'Passkey confirmation was cancelled. Nothing changed.' : error.message;
      if (error.status === 401) { busy = false; signedOut(); return; }
    }
    busy = false;
    await load();
  }
  const name = (passkey) => passkey.label || 'Passkey';
  function ownRow(passkey) {
    return el('li', { class: 'passkey-row', 'data-passkey': passkey.id },
      el('span', {}, `${name(passkey)}${passkey.current ? ' · this device' : ''}`),
      el('span', { class: 'fine-print' }, passkey.state === 'pending' ? `Waiting for approval · pairing code ${passkey.pairingCode}` : `Added ${when(passkey.createdAt)} · last used ${when(passkey.lastUsedAt)}`),
      el('button', { class: 'button secondary', type: 'button', disabled: busy, 'aria-label': `Remove my passkey ${name(passkey)}${passkey.current ? ' (this device)' : ''}`,
        onclick: () => void confirmed('own_passkey_revoke', passkey.id, {}, `/account/passkeys/${passkey.id}/revoke`, () => passkey.current ? 'This device’s passkey was removed.' : 'Passkey removed.') }, 'Remove'));
  }
  function accountCard(account) {
    const who = account.displayName;
    const passkeys = account.passkeys.map((passkey) => el('li', { class: 'passkey-row', 'data-passkey': passkey.id },
      el('span', {}, passkey.state === 'pending' ? `${name(passkey)} · pending · pairing code ` : `${name(passkey)} · last used ${when(passkey.lastUsedAt)}`,
        ...(passkey.state === 'pending' ? [el('strong', { class: 'pairing-code' }, passkey.pairingCode)] : [])),
      ...(passkey.state === 'pending' ? [el('button', { class: 'button primary', type: 'button', disabled: busy, 'aria-label': `Approve passkey with pairing code ${passkey.pairingCode} for ${who}`,
        onclick: () => void confirmed('passkey_approve', passkey.id, {}, `/admin/passkeys/${passkey.id}/approve`, () => `Approved the device for ${who}.`) }, 'Approve')] : []),
      el('button', { class: 'button secondary', type: 'button', disabled: busy, 'aria-label': `Remove passkey ${name(passkey)} of ${who}`,
        onclick: () => void confirmed('passkey_revoke', passkey.id, {}, `/admin/passkeys/${passkey.id}/revoke`, () => `Removed a passkey of ${who}; its sessions ended.`) }, passkey.state === 'pending' ? 'Reject' : 'Remove')));
    const card = el('li', { class: 'account-card', 'data-account': account.id },
      el('strong', {}, who), el('span', { class: 'fine-print' }, `${account.role}${account.active ? '' : ' · disabled'} · ${account.passkeys.length} passkey${account.passkeys.length === 1 ? '' : 's'}`),
      el('ul', { class: 'passkey-list', 'aria-label': `Passkeys of ${who}` }, ...passkeys),
      el('div', { class: 'person-controls' },
        el('button', { class: 'button secondary', type: 'button', disabled: busy || !account.active, 'aria-label': `Create add-device token for ${who}`,
          onclick: () => void confirmed('token_issue', account.id, { label: '' }, `/admin/accounts/${account.id}/tokens`, (result) => { token = { accountId: account.id, value: result.token, expiresAt: result.expiresAt }; return `Token for ${who} created.`; }) }, 'Add a device'),
        el('button', { class: 'button secondary', type: 'button', disabled: busy, 'aria-label': `Make ${who} ${account.role === 'admin' ? 'a parent' : 'an admin'}`,
          onclick: () => void confirmed('account_role', account.id, { role: account.role === 'admin' ? 'parent' : 'admin' }, `/admin/accounts/${account.id}/role`, () => `${who} is now ${account.role === 'admin' ? 'a parent' : 'an admin'}.`) }, account.role === 'admin' ? 'Make parent' : 'Make admin'),
        el('button', { class: 'button secondary', type: 'button', disabled: busy, 'aria-label': `${account.active ? 'Disable' : 'Enable'} ${who}`,
          onclick: () => void confirmed('account_active', account.id, { active: !account.active }, `/admin/accounts/${account.id}/active`, () => `${who} ${account.active ? 'disabled; every session ended' : 'enabled'}.`) }, account.active ? 'Disable' : 'Enable')));
    if (token?.accountId === account.id) {
      card.append(el('label', { class: 'token-once' }, `One-use token for ${who}. Shown once; expires at ${when(token.expiresAt)}. Enter it on the new device under “First visit”, then approve the pairing code shown there.`,
        el('input', { type: 'text', readOnly: true, value: token.value, 'aria-label': `Add-device token for ${who}` })));
    }
    return card;
  }
  function createForm() {
    const form = el('form', { class: 'account-form' },
      el('label', { for: 'new-account-name' }, 'New parent name'),
      el('input', { id: 'new-account-name', name: 'displayName', required: true, maxLength: 64, autocomplete: 'off' }),
      el('label', { for: 'new-account-role' }, 'Role'),
      el('select', { id: 'new-account-role', name: 'role' }, el('option', { value: 'parent' }, 'Parent'), el('option', { value: 'admin' }, 'Admin')),
      el('fieldset', {}, el('legend', {}, 'People this account may see'),
        ...people().map((person) => el('label', { class: 'alert-preference' }, el('input', { type: 'checkbox', name: 'person', value: person.id, checked: true }), person.name))),
      el('button', { class: 'button primary', type: 'submit', disabled: busy }, 'Create account'));
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const params = { displayName: form.elements.displayName.value.trim(), role: form.elements.role.value, personIds: [...form.querySelectorAll('input[name="person"]:checked')].map((input) => input.value).sort() };
      void confirmed('account_create', '', params, '/admin/accounts', (result) => `Created ${result.account.displayName}. Use “Add a device” to enroll their first passkey.`);
    });
    return form;
  }
  function draw() {
    if (!session() || !mine) { root.hidden = true; root.replaceChildren(); return; }
    const focused = root.contains(document.activeElement) && document.activeElement.matches('input, select');
    if (focused) return; // Never rebuild the form while someone is typing.
    root.replaceChildren(
      el('h2', { id: 'accounts-title' }, 'Devices and accounts'),
      el('button', { class: 'button secondary', type: 'button', disabled: busy, onclick: () => { notice = ''; void load(); } }, 'Refresh devices'),
      el('p', { class: 'notice', role: 'status', hidden: !notice }, notice),
      el('h3', {}, 'Your passkeys'),
      el('ul', { class: 'passkey-list', 'aria-label': 'Your passkeys' }, ...mine.map(ownRow)),
      ...(accounts ? [
        el('h3', {}, 'Parent accounts'),
        el('p', { class: 'fine-print' }, 'There is no limit on parent accounts or devices. New devices wait for your approval: compare the pairing code shown on the device before approving.'),
        el('ul', { class: 'account-list', 'aria-label': 'Parent accounts' }, ...accounts.map(accountCard)),
        el('h3', {}, 'Add a parent'), createForm(),
      ] : []));
    root.hidden = false;
  }
  function update() {
    const current = session(), next = current ? `${current.actor.id}:${current.actor.role}:${current.csrfToken}` : '';
    if (next !== key) { key = next; mine = null; accounts = null; notice = ''; token = null; draw(); if (next) void load(); }
  }
  return { update };
}
