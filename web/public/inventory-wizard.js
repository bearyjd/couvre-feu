// "Find a kid's device" wizard (UI plan G): a four-step sheet opened from the Devices tab (Who? -> How? -> Confirm -> Add).
// Everything here lives in memory only (never localStorage, never a cookie) and every timer is cleared when the sheet closes, the tab changes
// or the session changes. A device name is text the DEVICE chose, so it is only ever set with textContent. An address (MAC) is never put in
// the sheet's text or attributes: it travels only into the existing add form, which already does the passkey step-up.
import { el } from './children.js';
import { JUST_CONNECTED_SECONDS, justConnected, pickable, online, snapshotOf, diffPresence, osLines, deviceName } from './inventory-wizard-model.js';

export { JUST_CONNECTED_SECONDS };
export const POLL_SECONDS = 15;
export const WAIT_SECONDS = 180;
const MODES = [['connected', 'It just connected'], ['toggle', 'Turn its Wi-Fi off and on'], ['list', 'Pick from the list']];
const STEPS = ['', 'Who is it for?', 'How do we find it?', 'Check the address setting', 'Add it'];
const SAVE_FAILED = "Couldn't save that. Nothing was changed.";
const POLL_FAILED = "Couldn't refresh the list. Check your connection.";
const PRIVATE_WARNING = 'This phone uses a private Wi-Fi address. If the address changes, the router stops recognising the phone.';
const STATE_WORD = { quiet: 'Went quiet', back: 'Came back', new: 'New device' };
const FRESH = {
  step: 1, child: null, mode: null, status: 'idle', snapshot: { scanAt: 0, rows: {} }, quiet: [], device: null, warned: [], checked: [], turnedOff: [],
  privateShown: false, pollError: false, busy: false, error: '',
};

/**
 * `source` = { data(), load(signal) -> Promise<boolean>, refresh(signal), stable(id, value), now(), children: { entries(), startAdd(id, values), showKids() } }.
 * Returns { button(), openFor(childId, opener), close(), isOpen() }.
 */
export function createWizard(source) {
  let s = FRESH, overlay = null, opener = null, runId = 0, pollTimer = null, waitTimer = null, painted = '', abort = null, loading = false, pageOverflow = null;
  const devices = () => source.data()?.devices ?? [];
  const scanTime = () => source.data()?.status?.lastOkAt;
  const find = (id) => devices().find((d) => d.id === id);
  const childName = () => source.children.entries().find((c) => c.id === s.child)?.name ?? '';

  // Stops the toggle test completely: both timers, and any read still in flight.
  function stopWait() { runId += 1; clearTimeout(pollTimer); clearTimeout(waitTimer); pollTimer = null; waitTimer = null; abort?.abort(); abort = null; loading = false; }
  function set(patch) {
    if (patch.step !== undefined && patch.step !== s.step) stopWait();
    s = { ...s, ...patch };
    if (patch.step !== undefined && patch.step !== 2 && s.status !== 'idle') s = { ...s, status: 'idle' };
    if (patch.step !== undefined && patch.step !== 3) s = { ...s, privateShown: false };
    paint();
  }

  // One read at a time. A failed read keeps the last good list, says so, and the next tick tries again.
  async function read(mine) {
    if (loading) return null;
    loading = true;
    try {
      await source.refresh(abort.signal).catch(() => undefined); // ask for a fresh scan; rate limits and "polling is off" only mean we wait for the next one
      return mine === runId ? await source.load(abort.signal) : null;
    } catch { return false; } finally { if (mine === runId) loading = false; }
  }
  async function tick(mine) {
    const ok = await read(mine);
    if (mine !== runId || ok === null) return;
    set({ pollError: !ok, quiet: ok ? diffPresence(s.snapshot, s.quiet, devices(), scanTime()).quiet : s.quiet });
  }
  // The toggle test: one fresh read is the snapshot, then a read every POLL_SECONDS until the answer or WAIT_SECONDS is up.
  async function start() {
    stopWait();
    abort = new AbortController();
    const mine = runId;
    set({ status: 'starting', quiet: [], snapshot: { scanAt: 0, rows: {} }, pollError: false, error: '' });
    const ok = await read(mine);
    if (mine !== runId) return;
    if (!ok) { stopWait(); set({ status: 'timeup', pollError: true }); return; }
    set({ status: 'waiting', snapshot: snapshotOf(devices(), scanTime()) });
    waitTimer = setTimeout(() => { stopWait(); set({ status: 'timeup' }); }, WAIT_SECONDS * 1000);
    const loop = () => {
      pollTimer = setTimeout(async () => { if (!document.hidden) await tick(mine); if (mine === runId) loop(); }, POLL_SECONDS * 1000); // hidden page: no request until it is visible again
    };
    loop();
  }

  async function record(device, value) {
    set({ busy: true, error: '' });
    try {
      if (value === true || device.stableConfirmed === true) await source.stable(device.id, value);
      set({ busy: false, step: 4, checked: value ? [...s.checked, device.id] : s.checked, turnedOff: value ? [...s.turnedOff, device.id] : s.turnedOff });
      void source.load();
    } catch { set({ busy: false, error: SAVE_FAILED }); }
  }
  // Close the sheet first: the add form takes focus, and an open sheet would pull it back.
  function handOff(device) {
    const kept = s, from = opener;
    close({ restore: false });
    const values = { label: deviceName(childNameOf(kept.child), device), mac: device.mac };
    if (source.children.startAdd(kept.child, values)) return;
    open(from); s = { ...kept, error: "Couldn't open the add form. Close this and try Refresh." }; paint();
  }
  const childNameOf = (id) => source.children.entries().find((c) => c.id === id)?.name ?? '';
  function pick(device) {
    const first = device.flags.private && !s.warned.includes(device.id);
    set({ step: 3, device: device.id, privateShown: first, warned: first ? [...s.warned, device.id] : s.warned, error: '' });
  }

  const btn = (label, onclick, props = {}) => el('button', {
    class: `button ${props.primary ? 'primary' : 'secondary'}${props.chip ? ' chip' : ''}`, type: 'button', 'data-fk': label, onclick, ...props.extra,
  }, label);
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
    const chips = kids.map((c) => btn(c.name, () => set({ step: 2, child: c.id, error: '' }), { chip: true, extra: { 'aria-pressed': String(c.id === s.child) } }));
    return [
      ...(kids.length ? [el('div', { class: 'inventory-actions' }, ...chips)] : [el('p', { class: 'fine-print' }, 'No child yet. Add one first.')]),
      el('div', { class: 'inventory-actions' }, btn('Add a child', () => { close({ restore: false }); source.children.showKids(); })),
    ];
  }
  function toggleBody() {
    const failed = s.pollError ? [el('p', { class: 'notice', role: 'status', 'data-wizard-poll-error': '' }, POLL_FAILED)] : [];
    if (s.status === 'idle') {
      const how = 'Tap Start, switch Wi-Fi off on the phone and wait. This can take 1 to 3 minutes. We highlight what went quiet. Then switch it on again and we highlight what came back.';
      return [el('p', { class: 'fine-print' }, how), ...failed, btn('Start', () => void start(), { primary: true })];
    }
    const { states } = diffPresence(s.snapshot, s.quiet, devices(), scanTime());
    const order = { back: 0, quiet: 1, new: 2 };
    const rows = devices().filter((d) => states.has(d.id)).sort((a, b) => order[states.get(a.id)] - order[states.get(b.id)] || b.firstSeen - a.firstSeen);
    if (s.status === 'timeup') {
      const text = s.pollError ? "We couldn't refresh the list, so we can't tell. Check your connection, then start again."
        : rows.length ? 'Time is up. Pick the one that changed, or start again.' : 'Nothing went quiet in 3 minutes. Check the phone is on this Wi-Fi, then try again or pick from the list.';
      return [el('p', { class: 'notice', 'data-wizard-timeup': '' }, text), ...(rows.length ? [deviceList(rows, states)] : []), btn('Start again', () => void start())];
    }
    const stop = btn('Stop', () => { stopWait(); set({ status: 'idle' }); });
    if (s.status === 'starting') return [el('p', { class: 'notice', role: 'status', 'data-wizard-starting': '' }, 'Taking a first look at the list…'), stop];
    const waiting = 'Waiting for a change. This can take 1 to 3 minutes. Switch Wi-Fi off on the phone, then on again.';
    return [el('p', { class: 'notice', role: 'status', 'data-wizard-waiting': '' }, waiting), ...failed,
      ...(rows.length ? [deviceList(rows, states)] : [el('p', { class: 'fine-print' }, 'Nothing has changed yet.')]), stop];
  }
  function stepHow() {
    const choose = (key) => { stopWait(); set({ mode: key, status: 'idle', pollError: false, error: '' }); };
    const modes = el('div', { class: 'inventory-actions' }, ...MODES.map(([key, label]) => btn(label, () => choose(key), { chip: true, extra: { 'aria-pressed': String(s.mode === key) } })));
    const none = (text) => [el('p', { class: 'fine-print' }, text)];
    const list = (rows, empty) => (rows.length ? [deviceList(rows)] : none(empty));
    const body = s.mode === 'connected' ? list(justConnected(devices(), source.now()), 'Nothing new connected in the last 10 minutes. Try the Wi-Fi off and on, or pick from the list.')
      : s.mode === 'toggle' ? toggleBody()
        : s.mode === 'list' ? list(pickable(devices()), 'No devices to pick from.') : [];
    return [modes, ...body, back(1)];
  }
  function stepConfirm() {
    const device = find(s.device);
    if (!device) return [el('p', { class: 'notice' }, 'That device is no longer listed.'), back(2)];
    const kind = device.kind && device.kind !== 'unknown' ? device.kind : null;
    const parts = [device.hostname ?? 'Unnamed device', device.vendor ?? 'Unknown maker', kind, online(device) ? 'active' : 'quiet'];
    const summary = [...parts, device.flags.private ? '⚠ Private address' : null].filter(Boolean).join(' · ');
    const checked = s.checked.includes(device.id) || device.stableConfirmed === true;
    return [
      el('p', { class: 'wizard-summary', dir: 'auto' }, summary),
      ...(s.privateShown ? [el('p', { class: 'notice', role: 'note', 'data-private-warning': '' }, PRIVATE_WARNING)] : []),
      el('p', {}, 'Before you add it, on the phone:'),
      el('ul', { class: 'fine-print' }, ...osLines(device).map((line) => el('li', {}, line))),
      el('p', { class: 'fine-print' }, 'If the address changes after this step, the list shows a new row and we offer "Same device".'),
      ...(checked ? [el('p', { class: 'fine-print' }, 'You already checked this one.'), btn('Next', () => set({ step: 4 }), { primary: true })]
        : [el('div', { class: 'inventory-actions' }, ...[['I turned it off', true], ['It has no such setting', !device.flags.private]]
          .map(([label, value]) => el('button', { class: 'button primary', type: 'button', 'data-fk': label, disabled: s.busy, onclick: () => void record(device, value) }, label)))]),
      back(2),
    ];
  }
  function stepAdd() {
    const device = find(s.device);
    if (!device) return [el('p', { class: 'notice' }, 'That device is no longer listed.'), back(2)];
    const checked = s.checked.includes(device.id) || device.stableConfirmed === true;
    // Turning the private address off makes the phone present its hardware address, so the random one listed now is stale: find it again first.
    const stale = device.flags.private && s.turnedOff.includes(device.id);
    const again = btn('Find it again', () => set({ step: 2, status: 'idle', device: null, error: '' }), { primary: stale });
    return [
      el('p', { dir: 'auto' }, `Add ${device.hostname ?? 'this device'} to ${childName()}.`),
      ...(stale ? [el('p', { class: 'notice', role: 'status', 'data-wizard-find-again': '' }, 'The phone may show up again with a new address: tap Find it again.')] : []),
      ...(checked ? [] : [el('p', { class: 'fine-print' }, 'Address setting: not confirmed.')]),
      el('p', { class: 'fine-print' }, 'Your passkey confirms it on the next screen. It then shows "Sent to the router, not confirmed yet"; "On the router" appears only once the router confirms.'),
      ...(stale ? [again, btn('Open the add form', () => handOff(device))] : [btn('Open the add form', () => handOff(device), { primary: true })]),
      back(3),
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
    const sheet = overlay.firstElementChild, next = el('div');
    next.append(...content());
    if (next.innerHTML === painted && sheet.dataset.step === String(s.step)) return;
    const active = sheet.contains(document.activeElement) ? document.activeElement?.dataset?.fk : null;
    sheet.dataset.step = String(s.step);
    sheet.replaceChildren(...next.childNodes);
    painted = next.innerHTML;
    const again = active ? [...sheet.querySelectorAll('[data-fk]')].find((n) => n.dataset.fk === active) : null;
    (again ?? sheet.querySelector('#wizard-title')).focus({ preventScroll: true });
  }

  const focusable = () => [...overlay.querySelectorAll('button:not(:disabled)')];
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

  // `child` (from the Kids tab's Add device) skips step 1: the sheet starts at "How do we find it?" with that child chosen.
  function open(from, child) {
    if (overlay) return;
    opener = from; s = child ? { ...FRESH, step: 2, child } : { ...FRESH }; painted = '';
    overlay = el('div', { class: 'wizard-backdrop' }, el('div', { class: 'wizard-sheet', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'wizard-title' }));
    overlay.addEventListener('keydown', onKey);
    document.addEventListener('focusin', keepFocus);
    window.addEventListener('hashchange', onHash);
    pageOverflow = document.documentElement.style.overflow; document.documentElement.style.overflow = 'hidden'; // the page behind does not scroll
    document.body.append(overlay);
    paint();
  }
  function close({ restore = true } = {}) {
    if (!overlay) return;
    stopWait();
    overlay.removeEventListener('keydown', onKey); document.removeEventListener('focusin', keepFocus); window.removeEventListener('hashchange', onHash);
    document.documentElement.style.overflow = pageOverflow ?? '';
    overlay.remove(); overlay = null; s = FRESH; painted = '';
    const target = opener?.dataset?.restoreFocus ? document.querySelector(opener.dataset.restoreFocus) : document.querySelector('[data-wizard-open]') ?? opener; // a redrawn opener is found again by its selector
    opener = null;
    if (restore) target?.focus();
  }

  return {
    button: () => el('div', { class: 'wizard-open-bar' },
      el('button', { class: 'button primary', type: 'button', 'data-wizard-open': '', onclick: (event) => open(event.currentTarget) }, "Find a kid's device")),
    openFor: (child, from) => open(from, child), close, isOpen: () => overlay !== null,
  };
}
