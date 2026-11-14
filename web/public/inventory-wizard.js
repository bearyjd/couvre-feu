// "Find a kid's device" wizard (UI plan G): a four-step sheet opened from the Devices tab (Who? -> How? -> Confirm -> Add).
// Everything here lives in memory only (never localStorage, never a cookie) and every timer is cleared when the sheet closes, the tab changes
// or the session changes. A device name is text the DEVICE chose, so it is only ever set with textContent. An address (MAC) is never put in
// the sheet's text or attributes: it travels only into the existing add form, which already does the passkey step-up.
import { el } from './children.js';

export const JUST_CONNECTED_SECONDS = 600;
export const POLL_SECONDS = 15;
export const WAIT_SECONDS = 180;
const LIST_CAP = 40;
const NOT_KIDS = new Set(['adult', 'infrastructure', 'home', 'ignored']);
const MODES = [['connected', 'It just connected'], ['toggle', 'Turn its Wi-Fi off and on'], ['list', 'Pick from the list']];
const STEPS = ['', 'Who is it for?', 'How do we find it?', 'Check the address setting', 'Add it'];
const SAVE_FAILED = "Couldn't save that. Nothing was changed.";

const newest = (a, b) => b.firstSeen - a.firstSeen || b.lastSeen - a.lastSeen;
/** A row a parent could still give to a child: not enrolled already and not sorted as someone else's or as infrastructure. */
const candidate = (d) => d.flags.unassigned && !NOT_KIDS.has(d.role);
export const justConnected = (devices, now) => devices.filter((d) => candidate(d) && now - d.firstSeen <= JUST_CONNECTED_SECONDS).sort(newest);
export const pickable = (devices) => devices.filter(candidate).sort(newest).slice(0, LIST_CAP);
const online = (d) => d.presence === 'online';
export const snapshotOf = (devices) => Object.fromEntries(devices.map((d) => [d.id, online(d)]));
/** The toggle test: what was on and is not any more is "quiet"; what is on now and was not (or went quiet meanwhile) is "back". */
export function diffPresence(snapshot, quietIds, devices) {
  const quiet = new Set(quietIds);
  for (const d of devices) if (snapshot[d.id] === true && !online(d)) quiet.add(d.id);
  const states = new Map();
  for (const d of devices.filter(candidate)) {
    if (online(d) && (snapshot[d.id] !== true || quiet.has(d.id))) states.set(d.id, 'back');
    else if (quiet.has(d.id)) states.set(d.id, 'quiet');
  }
  return { quiet: [...quiet], states };
}
const STATE_WORD = { quiet: 'Went quiet', back: 'Came back' };

/** OS wording for the "private address" switch, by maker; unknown maker shows both. */
function osLines(device) {
  const iphone = 'iPhone: Wi-Fi > this network > Private Wi-Fi Address: OFF.';
  const android = 'Android: Wi-Fi > this network > Use device MAC.';
  return device.vendor === undefined ? [iphone, android] : /apple/i.test(device.vendor) ? [iphone] : [android];
}

const FRESH = { step: 1, child: null, mode: null, status: 'idle', snapshot: {}, quiet: [], device: null, warned: [], checked: [], privateShown: false, busy: false, error: '' };

/**
 * `source` = { data(), load(), now(), call(path, body), children: { entries(), startAdd(id, values), showKids() } }.
 * Returns { button(), close(), isOpen() }.
 */
export function createWizard(source) {
  let s = FRESH, overlay = null, opener = null, runId = 0, pollTimer = null, waitTimer = null, painted = '';
  const devices = () => source.data()?.devices ?? [];
  const find = (id) => devices().find((d) => d.id === id);
  const childName = () => source.children.entries().find((c) => c.id === s.child)?.name ?? '';

  function stopWait() { runId += 1; clearTimeout(pollTimer); clearTimeout(waitTimer); pollTimer = null; waitTimer = null; }
  function set(patch) {
    if (patch.step !== undefined && patch.step !== s.step) stopWait();
    s = { ...s, ...patch };
    if (patch.step !== undefined && patch.step !== 2 && s.status === 'waiting') s = { ...s, status: 'idle' };
    paint();
  }

  // The toggle test: one fresh read is the snapshot, then a read every POLL_SECONDS until the answer or WAIT_SECONDS is up.
  async function start() {
    stopWait();
    const mine = runId;
    set({ status: 'waiting', quiet: [], snapshot: {}, error: '' });
    await source.load();
    if (mine !== runId) return;
    s = { ...s, snapshot: snapshotOf(devices()) };
    paint();
    waitTimer = setTimeout(() => { stopWait(); set({ status: 'timeup' }); }, WAIT_SECONDS * 1000);
    const schedule = () => {
      pollTimer = setTimeout(async () => {
        await source.load();
        if (mine !== runId) return;
        set({ quiet: diffPresence(s.snapshot, s.quiet, devices()).quiet });
        schedule();
      }, POLL_SECONDS * 1000);
    };
    schedule();
  }

  async function record(device, value) {
    set({ busy: true, error: '' });
    try {
      if (value === true || device.stableConfirmed === true) await source.call(`/admin/inventory/${device.id}/stable`, { value });
      set({ busy: false, step: 4, checked: value ? [...s.checked, device.id] : s.checked });
      void source.load();
    } catch { set({ busy: false, error: SAVE_FAILED }); }
  }
  function handOff(device) {
    const label = device.hostname ?? '';
    if (!source.children.startAdd(s.child, { label, mac: device.mac })) { set({ error: "Couldn't open the add form. Close this and try Refresh." }); return; }
    close({ restore: false });
  }
  function pick(device) {
    const first = device.flags.private && !s.warned.includes(device.id);
    set({ step: 3, device: device.id, privateShown: first, warned: first ? [...s.warned, device.id] : s.warned, error: '' });
  }

  const btn = (label, onclick, props = {}) => el('button', { class: `button ${props.primary ? 'primary' : 'secondary'}${props.chip ? ' chip' : ''}`, type: 'button', 'data-fk': label, onclick, ...props.extra }, label);
  const back = (to) => btn('Back', () => set({ step: to, error: '' }));

  function deviceRow(device, state) {
    const hints = [device.vendor ?? 'Unknown maker', device.kind && device.kind !== 'unknown' ? `${device.kind}?` : null, online(device) ? 'active now' : 'quiet'].filter(Boolean).join(' · ');
    return el('li', { class: 'wizard-device-item', 'data-wizard-device': '', ...(state ? { 'data-wiz-state': state } : {}) },
      el('button', { class: 'button secondary wizard-device', type: 'button', 'data-fk': `device-${device.id}`, onclick: () => pick(device) },
        el('span', { class: 'inventory-name', 'data-name': '', dir: 'auto' }, device.hostname ?? 'Unnamed device'),
        el('span', { class: 'fine-print' }, hints),
        ...(state ? [el('strong', { class: 'wizard-state' }, STATE_WORD[state])] : [])));
  }
  const deviceList = (rows, states = new Map()) => el('ul', { class: 'wizard-list', 'aria-label': 'Devices' }, ...rows.map((d) => deviceRow(d, states.get(d.id))));

  function stepWho() {
    const kids = source.children.entries();
    return [
      ...(kids.length ? [el('div', { class: 'inventory-actions' }, ...kids.map((c) => btn(c.name, () => set({ step: 2, child: c.id, error: '' }), { chip: true, extra: { 'aria-pressed': String(c.id === s.child) } })))] : [el('p', { class: 'fine-print' }, 'No child yet. Add one first.')]),
      el('div', { class: 'inventory-actions' }, btn('Add a child', () => { source.children.showKids(); close({ restore: false }); })),
    ];
  }
  function toggleBody() {
    if (s.status === 'idle') return [el('p', { class: 'fine-print' }, "Tap Start, switch Wi-Fi off on the phone and wait up to 3 minutes. We highlight what went quiet. Then switch it on again and we highlight what came back."), btn('Start', () => void start(), { primary: true })];
    const { states } = diffPresence(s.snapshot, s.quiet, devices());
    const rows = devices().filter((d) => states.has(d.id)).sort((a, b) => (states.get(a.id) === 'back' ? 0 : 1) - (states.get(b.id) === 'back' ? 0 : 1) || newest(a, b));
    if (s.status === 'timeup') return [el('p', { class: 'notice', 'data-wizard-timeup': '' }, rows.length ? 'Time is up. Pick the one that changed, or start again.' : 'Nothing went quiet in 3 minutes. Check the phone is on this Wi-Fi, then try again or pick from the list.'), ...(rows.length ? [deviceList(rows, states)] : []), btn('Start again', () => void start())];
    return [el('p', { class: 'notice', role: 'status', 'data-wizard-waiting': '' }, 'Waiting for a change (up to 3 minutes). Switch Wi-Fi off on the phone, then on again.'),
      ...(rows.length ? [deviceList(rows, states)] : [el('p', { class: 'fine-print' }, 'Nothing has changed yet.')]), btn('Stop', () => set({ status: 'idle' }))];
  }
  function stepHow() {
    const modes = el('div', { class: 'inventory-actions' }, ...MODES.map(([key, label]) => btn(label, () => { stopWait(); set({ mode: key, status: 'idle', error: '' }); }, { chip: true, extra: { 'aria-pressed': String(s.mode === key) } })));
    const now = source.now();
    const body = s.mode === 'connected'
      ? (() => { const rows = justConnected(devices(), now); return rows.length ? [deviceList(rows)] : [el('p', { class: 'fine-print' }, 'Nothing new connected in the last 10 minutes. Try the Wi-Fi off and on, or pick from the list.')]; })()
      : s.mode === 'toggle' ? toggleBody()
        : s.mode === 'list' ? (() => { const rows = pickable(devices()); return rows.length ? [deviceList(rows)] : [el('p', { class: 'fine-print' }, 'No devices to pick from.')]; })() : [];
    return [modes, ...body, back(1)];
  }
  function stepConfirm() {
    const device = find(s.device);
    if (!device) return [el('p', { class: 'notice' }, 'That device is no longer listed.'), back(2)];
    const summary = [device.hostname ?? 'Unnamed device', device.vendor ?? 'Unknown maker', device.kind && device.kind !== 'unknown' ? device.kind : null, online(device) ? 'active' : 'quiet', device.flags.private ? '⚠ Private address' : null].filter(Boolean).join(' · ');
    const checked = s.checked.includes(device.id) || device.stableConfirmed === true;
    return [
      el('p', { class: 'wizard-summary', dir: 'auto' }, summary),
      ...(s.privateShown && !checked ? [el('p', { class: 'notice', role: 'note', 'data-private-warning': '' }, 'This phone uses a private Wi-Fi address. If the address changes, the router stops recognising the phone.')] : []),
      el('p', {}, 'Before you add it, on the phone:'),
      el('ul', { class: 'fine-print' }, ...osLines(device).map((line) => el('li', {}, line))),
      el('p', { class: 'fine-print' }, 'If the address changes after this step, the list shows a new row and we offer "Same device".'),
      ...(checked ? [el('p', { class: 'fine-print' }, 'You already checked this one.'), btn('Next', () => set({ step: 4 }), { primary: true })]
        : [el('div', { class: 'inventory-actions' }, ...[['I turned it off', true], ['It has no such setting', !device.flags.private]].map(([label, value]) => el('button', { class: 'button primary', type: 'button', 'data-fk': label, disabled: s.busy, onclick: () => void record(device, value) }, label)))]),
      back(2),
    ];
  }
  function stepAdd() {
    const device = find(s.device);
    if (!device) return [el('p', { class: 'notice' }, 'That device is no longer listed.'), back(2)];
    const checked = s.checked.includes(device.id) || device.stableConfirmed === true;
    return [
      el('p', { dir: 'auto' }, `Add ${device.hostname ?? 'this device'} to ${childName()}.`),
      ...(checked ? [] : [el('p', { class: 'notice' }, 'The address setting was not confirmed. If the address changes, the router stops recognising the phone.')]),
      el('p', { class: 'fine-print' }, 'Your passkey confirms it on the next screen. It then shows "Sent to the router, not confirmed yet"; "On the router" appears only once the router confirms.'),
      btn('Open the add form', () => handOff(device), { primary: true }), back(3),
    ];
  }

  function content() {
    const body = [null, stepWho, stepHow, stepConfirm, stepAdd][s.step]();
    return [
      el('div', { class: 'wizard-head' },
        el('h2', { id: 'wizard-title', tabIndex: -1 }, "Find a kid's device"),
        btn('Close', () => close(), { extra: { 'aria-label': "Close Find a kid's device" } })),
      el('p', { class: 'fine-print', 'data-wizard-step': '' }, `Step ${s.step} of 4: ${STEPS[s.step]}`),
      ...(s.error ? [el('p', { class: 'notice', role: 'alert' }, s.error)] : []),
      ...body,
    ];
  }

  function paint() {
    if (!overlay) return;
    const sheet = overlay.firstElementChild, next = el('div'), previous = painted;
    next.append(...content());
    if (next.innerHTML === previous && sheet.dataset.step === String(s.step)) return;
    const active = sheet.contains(document.activeElement) ? document.activeElement?.dataset?.fk : null;
    sheet.dataset.step = String(s.step);
    sheet.replaceChildren(...next.childNodes);
    painted = next.innerHTML;
    const again = active ? [...sheet.querySelectorAll('[data-fk]')].find((n) => n.dataset.fk === active) : null;
    (again ?? sheet.querySelector('#wizard-title')).focus({ preventScroll: true });
  }

  const focusable = () => [...overlay.querySelectorAll('button:not(:disabled), [tabindex="0"]')];
  function onKey(event) {
    if (event.key === 'Escape') { event.preventDefault(); close(); return; }
    if (event.key !== 'Tab') return;
    const items = focusable(), first = items[0], last = items[items.length - 1], active = document.activeElement;
    if (!items.length) { event.preventDefault(); return; }
    if (event.shiftKey && (active === first || !overlay.contains(active) || active.id === 'wizard-title')) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && (active === last || !overlay.contains(active))) { event.preventDefault(); first.focus(); }
  }
  const keepFocus = (event) => { if (overlay && !overlay.contains(event.target)) overlay.querySelector('#wizard-title').focus({ preventScroll: true }); };
  const onHash = () => close({ restore: false });

  function open(from) {
    if (overlay) return;
    opener = from; s = { ...FRESH }; painted = '';
    overlay = el('div', { class: 'wizard-backdrop' }, el('div', { class: 'wizard-sheet', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'wizard-title' }));
    overlay.addEventListener('keydown', onKey);
    document.addEventListener('focusin', keepFocus);
    window.addEventListener('hashchange', onHash);
    document.body.append(overlay);
    paint();
  }
  function close({ restore = true } = {}) {
    if (!overlay) return;
    stopWait();
    overlay.removeEventListener('keydown', onKey); document.removeEventListener('focusin', keepFocus); window.removeEventListener('hashchange', onHash);
    overlay.remove(); overlay = null; s = FRESH; painted = '';
    const target = document.querySelector('[data-wizard-open]') ?? opener;
    opener = null;
    if (restore) target?.focus();
  }

  return {
    button: () => el('div', { class: 'wizard-open-bar' }, el('button', { class: 'button primary', type: 'button', 'data-wizard-open': '', onclick: (event) => open(event.currentTarget) }, "Find a kid's device")),
    close, isOpen: () => overlay !== null,
  };
}
