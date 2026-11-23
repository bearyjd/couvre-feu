// One card per child or device group on the Kids tab (UI plan H): device rows with a status chip, one Add device button, and Move/Remove under a
// row's ⋯ menu with an in-page confirm sentence (never window.confirm). Pure view building: state and requests stay in createChildren (children.js).
// Every name here is text a person or a device chose, so it is only ever set with textContent. An address (MAC) appears only inside the add form.
import { el } from './children.js';
import { deviceStatus, stateWord, ageText } from './kids-model.js';

const KIND_LABEL = { child: 'Child', device_group: 'Device group' };
export const CHIP = { on_router: 'On the router', sent: 'Sent, not confirmed yet', waiting: 'Waiting for router approval', replaced: 'Replaced?', unknown: 'Router status unknown', missing: 'Not on the router' };
const chip = (status) => el('span', { class: `status-chip chip-${status}`, 'data-status': status }, CHIP[status]);
const MENU = [['move', 'Move', 'Move…'], ['remove', 'Remove', 'Remove']];

/** The ⋯ button and its menu. Opening and closing happen in place (no redraw), so keyboard focus is never dropped. `h.onChoose(kind, device)`, `h.onMenuClosed()`. */
function rowMenu(device, locked, h) {
  const wrap = el('div', { class: 'row-menu' });
  const trigger = el('button', { class: 'button secondary menu-trigger', type: 'button', disabled: locked, 'data-row-menu': '', 'data-fk': `menu-${device.id}`,
    'aria-label': `Actions for ${device.label}`, 'aria-haspopup': 'menu', 'aria-expanded': 'false' }, '⋯');
  let menu = null;
  const items = () => [...menu.querySelectorAll('[role="menuitem"]')];
  // Safari/iOS do not focus a tapped button, so focus leaving the menu says nothing about the person's intent. Only a press outside it, or Escape, closes it.
  const outside = (event) => { if (!wrap.isConnected) stop(); else if (menu && !wrap.contains(event.target)) { close(false, true); } };
  const escape = (event) => { if (event.key === 'Escape' && menu) { event.preventDefault(); close(true); } };
  function stop() { document.removeEventListener('pointerdown', outside, true); document.removeEventListener('keydown', escape, true); }
  function close(restore, later = false) {
    if (!menu) return;
    const gone = menu; menu = null; gone.remove(); stop();
    trigger.setAttribute('aria-expanded', 'false');
    if (restore) trigger.focus();
    if (later) setTimeout(h.onMenuClosed, 400); // a pending redraw must not land between a press and its click
    else h.onMenuClosed();
  }
  function open(last) {
    if (menu) return;
    menu = el('ul', { class: 'row-menu-list', role: 'menu', 'aria-label': `Actions for ${device.label}` },
      ...MENU.map(([kind, verb, text]) => el('li', { role: 'none' },
        el('button', { class: 'button secondary', type: 'button', role: 'menuitem', 'aria-label': `${verb} ${device.label}`, onclick: () => { close(false); h.onChoose(kind, device); } }, text))));
    wrap.append(menu); trigger.setAttribute('aria-expanded', 'true');
    document.addEventListener('pointerdown', outside, true); document.addEventListener('keydown', escape, true);
    const list = items(); list[last ? list.length - 1 : 0].focus();
  }
  trigger.addEventListener('click', () => (menu ? close(true) : open(false)));
  trigger.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); open(event.key === 'ArrowUp'); }
  });
  wrap.addEventListener('keydown', (event) => {
    if (!menu || !menu.contains(event.target)) return;
    const list = items(), at = list.indexOf(document.activeElement), step = { ArrowDown: 1, ArrowUp: -1 }[event.key];
    if (step) { event.preventDefault(); list[(at + step + list.length) % list.length].focus(); }
    else if (event.key === 'Home' || event.key === 'End') { event.preventDefault(); list[event.key === 'Home' ? 0 : list.length - 1].focus(); }
    else if (event.key === 'Tab') close(false); // focus then moves on naturally
  });
  wrap.append(trigger);
  return wrap;
}

/** The confirm sentence: what will happen in words, then Yes / Cancel. Move also asks where to. `h.onYes(device, to)`, `h.onCancel()`. */
function sentence({ kind, name, text, extra = [], yes, h }) {
  const group = el('div', { class: 'confirm-sentence', role: 'group', 'aria-labelledby': `confirm-text-${name}`, 'data-confirm': kind, onkeydown: (event) => { if (event.key === 'Escape') { event.preventDefault(); h.onCancel(); } } },
    el('p', { id: `confirm-text-${name}`, tabIndex: -1, 'data-confirm-text': '', dir: 'auto' }, text), ...extra);
  const yesButton = el('button', { class: 'button primary', type: 'button', 'data-fk': `yes-${name}`, disabled: yes.disabled, ...(yes.destructive ? { 'data-risk': 'destructive' } : {}), onclick: yes.onclick }, yes.label);
  group.append(el('div', { class: 'inventory-actions' }, yesButton, el('button', { class: 'button secondary', type: 'button', 'data-fk': `cancel-${name}`, onclick: () => h.onCancel() }, 'Cancel')));
  return { group, yesButton };
}
function moveSentence(ctx, device) {
  const { entry, others, moveChoice, busy, h } = ctx;
  const idle = !busy && device.state === 'active'; // the server refuses a change on a device that is mid-change; so does the button
  const select = el('select', { 'aria-label': `Move ${device.label} to`, disabled: busy, 'data-fk': `move-select-${device.id}`,
    onchange: () => { moveChoice.set(device.id, select.value); built.yesButton.disabled = !idle || !select.value; } },
    el('option', { value: '' }, 'Choose…'), ...others.map((c) => el('option', { value: c.id }, c.name)));
  select.value = others.some((c) => c.id === moveChoice.get(device.id)) ? moveChoice.get(device.id) : '';
  const built = sentence({ kind: 'move', name: device.id, h, extra: [select], text: `Move ${device.label} from ${entry.name} to another child? Your passkey is asked next.`,
    yes: { label: 'Yes, move it', disabled: !idle || !select.value, onclick: () => h.onMove(entry, device, select.value) } });
  return built.group;
}
function removeSentence(ctx, device) {
  const { entry, busy, h } = ctx;
  return sentence({ kind: 'remove', name: device.id, h, text: `Remove ${device.label} from ${entry.name}? The router stops managing it. Your passkey is asked next.`,
    yes: { label: 'Yes, remove it', disabled: busy || device.state !== 'active', destructive: true, onclick: () => h.onRemove(device) } }).group;
}

function deviceRow(ctx, device) {
  const status = deviceStatus(device), locked = ctx.busy || device.state !== 'active', word = stateWord(device.state);
  const open = ctx.confirm?.id === device.id ? ctx.confirm.kind : null;
  return el('li', { class: 'device-row', 'data-device': device.id },
    el('div', { class: 'device-line' }, el('span', { class: 'device-name', 'data-name': '', dir: 'auto' }, device.label), rowMenu(device, locked, ctx.h)),
    el('div', { class: 'device-meta' },
      ...(device.vendor ? [el('span', { class: 'fine-print', 'data-vendor': '' }, device.vendor)] : []),
      chip(status), ...(status === 'on_router' && ctx.replaced.has(device.mac) ? [chip('replaced'), el('span', { class: 'fine-print', 'data-replaced-note': '' }, 'Check the old device before removing it.')] : []),
      ...(word ? [el('span', { class: 'fine-print' }, word)] : [])),
    ...(open === 'remove' ? [removeSentence(ctx, device)] : open === 'move' ? [moveSentence(ctx, device)] : []));
}
/** A request the router's administrator has not approved yet. It comes from the service, so it is still here after a reload. */
function waitingRow(ctx, request) {
  const typed = ctx.labels.get(request.id);
  return el('li', { class: 'device-row', 'data-pending-scope': request.id },
    el('div', { class: 'device-line' }, el('span', { class: 'device-name', 'data-name': '', dir: 'auto' }, typed ?? request.name ?? 'Unnamed device')),
    el('div', { class: 'device-meta' }, chip('waiting'), el('span', { class: 'fine-print' }, `Asked ${ageText(request.ageSeconds)}`),
      ...(typed === undefined && request.name ? [el('span', { class: 'fine-print', 'data-reported': '' }, 'Name reported by the device')] : [])));
}
/** The router took the device's address in: it can be added now. Kept until dismissed or the child shows a new device. */
function approvedNote(ctx, item) {
  return el('div', { class: 'notice', role: 'status', 'data-approved': item.id },
    el('strong', { dir: 'auto' }, 'Approved: add it now'), el('p', { dir: 'auto' }, `${item.name}: the router now knows this device. Use Add device to finish.`),
    el('button', { class: 'button secondary', type: 'button', 'data-fk': `dismiss-${item.id}`, onclick: () => ctx.h.onDismissApproved(item.id) }, 'Dismiss'));
}
function addForm(ctx) {
  const { entry, prefill, h } = ctx;
  const form = el('form', { class: 'account-form', 'data-add-device': entry.id },
    ...(prefill.warn ? [el('p', { class: 'notice', role: 'note', 'data-prefill-warning': '' }, "Confirm the address in the device's own Wi-Fi settings before approving")] : []),
    el('label', { for: `device-label-${entry.id}` }, `New device name for ${entry.name}`),
    el('input', { id: `device-label-${entry.id}`, name: 'label', required: true, maxLength: 64, autocomplete: 'off', value: prefill.label }),
    el('label', { for: `device-mac-${entry.id}` }, `Wi-Fi address (MAC) for ${entry.name}`),
    el('input', { id: `device-mac-${entry.id}`, name: 'mac', required: true, maxLength: 17, autocomplete: 'off', autocapitalize: 'none', spellcheck: false, placeholder: 'aa:bb:cc:dd:ee:ff', value: prefill.mac }),
    el('div', { class: 'inventory-actions' },
      el('button', { class: 'button primary', type: 'submit', disabled: ctx.busy }, 'Add device'),
      el('button', { class: 'button secondary', type: 'button', onclick: () => h.onCancelAdd(entry) }, 'Cancel')));
  form.addEventListener('submit', (event) => { event.preventDefault(); h.onSubmitAdd(entry, { label: form.elements.label.value.trim(), mac: form.elements.mac.value.trim() }); });
  return form;
}
function removeChild(ctx) {
  const { entry, busy, h } = ctx, kind = (KIND_LABEL[entry.kind] ?? 'Child').toLowerCase();
  if (ctx.confirm?.kind === 'child_remove' && ctx.confirm.id === entry.id) {
    return sentence({ kind: 'child_remove', name: entry.id, h, text: `Remove ${entry.name}? It has no devices. Your passkey is asked next.`,
      yes: { label: 'Yes, remove it', disabled: busy, destructive: true, onclick: () => h.onRemoveChild(entry) } }).group;
  }
  return el('button', { class: 'button secondary', type: 'button', disabled: busy, 'data-remove-child': entry.id, 'data-risk': 'destructive', 'data-fk': `remove-child-${entry.id}`, 'aria-label': `Remove ${entry.name}`,
    onclick: () => h.onChoose('child_remove', entry) }, `Remove ${kind}`);
}
/** `ctx` = { entry, pending, approved, replaced:Set, labels:Map, confirm, prefill, moveChoice, others, busy, h }. */
export function childCard(ctx) {
  const { entry, h } = ctx, kind = KIND_LABEL[entry.kind] ?? 'Child';
  const adding = ctx.prefill?.id === entry.id;
  return el('li', { class: 'account-card', 'data-entry': entry.id },
    el('strong', {}, entry.name), el('span', { class: 'fine-print' }, `${kind} · ${entry.devices.length} device${entry.devices.length === 1 ? '' : 's'}`),
    ...ctx.approved.map((item) => approvedNote(ctx, item)),
    el('ul', { class: 'passkey-list device-rows', 'aria-label': `Devices of ${entry.name}` }, ...entry.devices.map((device) => deviceRow(ctx, device)), ...ctx.pending.map((request) => waitingRow(ctx, request))),
    ...(adding ? [addForm(ctx)] : [el('button', { class: 'button primary add-device', type: 'button', disabled: ctx.busy, 'data-add-device-open': entry.id, 'data-fk': `add-${entry.id}`,
      'data-restore-focus': `#children-panel [data-add-device-open="${entry.id}"]`, 'aria-label': `Add device to ${entry.name}`, onclick: (event) => h.onAdd(entry, event.currentTarget) }, 'Add device')]),
    ...(entry.devices.length ? [] : [removeChild(ctx)]));
}
