// Devices triage list (UI plan F), shown inside the existing "Devices on the network" panel only while the service says the triage flag is on
// (the list then carries newCount). Pure view building: state and requests stay in createInventory (children.js). A device name is text the
// DEVICE chose, so it is only ever set with textContent. An address (MAC) is never printed or put in an attribute: it only travels into the add form.
import { el } from './children.js';

export const FILTERS = [['new', 'To sort'], ['kid', 'Kids'], ['adult', 'Adults'], ['home', 'Home'], ['infrastructure', 'Infra'], ['ignored', 'Hidden']];
const ROLES = [['adult', 'Adult', 'Adults'], ['home', 'Home', 'Home'], ['infrastructure', 'Infra', 'Infra'], ['ignored', 'Hide', 'Hidden']];
export const UNDO_SECONDS = 10;
const STALL_SECONDS = 1800;
const ACTIVE = new Set(['online', 'lease_only']);

export const triageOn = (data) => typeof data?.newCount === 'number';
// Guests are not a chip of their own: they sit under Home.
const groupOf = (device) => (device.role === 'guest' ? 'home' : device.role && device.role !== 'new' ? device.role : 'new');
export const roleWord = (role) => (ROLES.find(([key]) => key === role) ?? [])[2] ?? role;

/** Rows a parent linked as "same device" are replaced by the newer row, so the old one is not a thing to sort. */
function visibleIn(devices) {
  const replaced = new Set(devices.flatMap((d) => (d.linkedFrom ? [d.linkedFrom] : [])));
  return devices.filter((d) => !(groupOf(d) === 'new' && replaced.has(d.id)));
}
export function groupCounts(devices) {
  const counts = Object.fromEntries(FILTERS.map(([key]) => [key, 0]));
  for (const d of visibleIn(devices)) counts[groupOf(d)] += 1;
  return counts;
}
export function agoText(nowSeconds, at) {
  const s = Math.max(0, nowSeconds - at);
  if (!Number.isFinite(s)) return 'a while ago';
  if (s < 90) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
/** The scan state in words a parent can act on. `base` is the existing wording, kept for the states that are not a stall. */
export function triageStatus(status, base, nowSeconds, toSort) {
  if (base.kind === 'stalled' || base.kind === 'none') {
    const minutes = Math.floor((nowSeconds - status.lastOkAt) / 60);
    return status.lastOkAt && Number.isFinite(minutes) && minutes * 60 >= STALL_SECONDS ? `Scan stalled ${minutes} min. Tell JD.` : 'No scan has finished yet. Tell JD.';
  }
  return base.kind === 'ok' ? `Last scan ${agoText(nowSeconds, status.lastOkAt)} · ${toSort} to sort` : base.text;
}

function chips(device, h, locked, children) {
  const short = (device.hostname ?? 'device').slice(0, 40);
  const kids = device.role === 'kid' ? [] : children.map((c) => el('button', { class: 'button secondary chip', type: 'button', disabled: locked, 'data-child': '', 'aria-label': `Add ${short} to ${c.name}`, onclick: () => h.onChild(device, c) }, c.name));
  const roles = device.role === 'kid' ? [] : ROLES.map(([role, label]) => el('button', { class: 'button secondary chip', type: 'button', disabled: locked, 'data-role': role, 'aria-pressed': String(device.role === role), 'aria-label': `${label}: ${short}`, onclick: () => h.onRole(device, role) }, label));
  return kids.length + roles.length ? [el('div', { class: 'inventory-actions', 'data-chips': '' }, ...kids, ...roles)] : [];
}
function suggestion(device, all, h, locked, nowSeconds) {
  const old = device.suggestedReplaces && !device.linkedFrom && groupOf(device) === 'new' ? all.find((d) => d.id === device.suggestedReplaces) : undefined;
  if (!old) return [];
  return [el('div', { class: 'triage-suggestion', 'data-suggestion': '' },
    el('span', { class: 'fine-print' }, `Looks like "${old.hostname ?? 'a device'}" that went quiet ${agoText(nowSeconds, old.lastSeen)}`),
    el('button', { class: 'button secondary chip', type: 'button', disabled: locked, onclick: () => h.onLink(device) }, 'Same device'))];
}
function row(device, all, h, locked, nowSeconds, children) {
  const active = ACTIVE.has(device.presence), hints = [device.vendor ?? 'Unknown maker', device.kind && device.kind !== 'unknown' ? `${device.kind}?` : null, device.ipv4[0] ?? 'No address yet'].filter(Boolean);
  return el('li', { class: 'passkey-row inventory-row triage-row' },
    el('span', { class: 'triage-line triage-head' },
      el('span', { class: 'presence-dot', 'data-presence': active ? 'active' : 'quiet', 'aria-hidden': 'true' }, active ? '●' : '○'),
      el('span', { class: 'inventory-name', 'data-name': '', dir: 'auto' }, device.hostname ?? 'Unnamed device'),
      el('span', { class: 'fine-print triage-when' }, active ? 'Active now' : agoText(nowSeconds, device.lastSeen))),
    el('span', { class: 'triage-line fine-print', 'data-hints': '' }, hints.join(' · '), ...(device.personName ? [` · ${device.personName}`] : [])),
    ...(device.flags.private ? [el('span', { class: 'triage-line fine-print' }, 'Private address: the router stops recognising it if the address changes')] : []),
    ...suggestion(device, all, h, locked, nowSeconds),
    ...chips(device, h, locked, children));
}

/**
 * The triage body: scan line, filter chips with counts, the rows for the chosen filter, the Undo bar and the plain failure line.
 * `h` = { onFilter, onRole, onChild, onLink, onUndo, onRetry, onRefresh }.
 */
export function triageView({ data, filter, undo, statusText, failed, locked, nowSeconds, children, h }) {
  const counts = groupCounts(data.devices), shown = visibleIn(data.devices).filter((d) => groupOf(d) === filter).sort((a, b) => b.firstSeen - a.firstSeen || b.lastSeen - a.lastSeen);
  return [
    el('div', { class: 'triage-head-row' },
      el('p', { class: 'notice', 'data-inventory-status': '' }, statusText),
      el('button', { class: 'button secondary', type: 'button', disabled: locked, onclick: h.onRefresh }, 'Refresh')),
    ...(failed ? [el('p', { class: 'notice', role: 'status', 'data-load-failed': '' }, "Couldn't load the device list · ", el('button', { class: 'button secondary', type: 'button', onclick: h.onRetry }, 'Retry'))] : []),
    el('div', { class: 'inventory-actions triage-filters', role: 'group', 'aria-label': 'Show devices' },
      ...FILTERS.map(([key, label]) => el('button', { class: 'button secondary chip', type: 'button', 'data-filter': key, 'aria-pressed': String(key === filter), onclick: () => h.onFilter(key) }, `${label} `, el('strong', {}, String(counts[key]))))),
    ...(undo ? [el('p', { class: 'notice', role: 'status', 'data-undo': '' }, `${undo.text} `, el('button', { class: 'button secondary', type: 'button', disabled: locked, onclick: h.onUndo }, 'Undo'))] : []),
    shown.length
      ? el('ul', { class: 'account-list', 'aria-label': 'Devices on the network' }, ...shown.map((d) => row(d, data.devices, h, locked, nowSeconds, children)))
      : el('p', { class: 'fine-print' }, filter === 'new' ? 'Nothing here. Every device is sorted.' : 'Nothing here.'),
  ];
}
