// Review for the router install (admin only): the list the permanent install will protect and allow, with warnings and a digest.
// Nothing here touches the router. The panel exists only while the service says the feature is on for this admin (people.installReadiness === true).
// All dynamic text (child names, device labels) is rendered with textContent: it is untrusted.
import { getPasskey } from './auth-client.js';

const WARNING = {
  private_address_unconfirmed: (w) => `${w.device} uses a private (changing) address that has not been confirmed as fixed.`,
  device_quiet: (w) => `${w.device} has not been seen for more than 7 days.`,
  device_unseen: (w) => `${w.device} has not been seen.`,
  child_no_device: (w) => `${w.child} has no device on the list.`,
};
const PRESENCE = { online: 'Online now', lease_only: 'Recently on the network', recent: 'Seen recently', quiet: 'Quiet', unknown: 'Not seen' };
const when = (epoch) => new Date(epoch * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });

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
const usable = (body) => body && Array.isArray(body.children) && Array.isArray(body.adults) && Array.isArray(body.warnings) && typeof body.digest === 'string';
const mark = (ok, yes, no) => el('span', { class: `inventory-flag ${ok ? '' : 'flag-new'}`, textContent: ok ? yes : no });

export function createInstallReadiness({ session, people, offline }) {
  const root = document.querySelector('#install-readiness-panel');
  const status = el('p', { class: 'fine-print', role: 'status', 'aria-live': 'polite', 'data-readiness-status': '' });
  let key = '', epoch = 0, loading = false, loaded = false, failed = false, busy = false, list = null, notice = '';
  const sessionKey = () => { const current = session(); return current ? `${current.actor.id}:${current.csrfToken}` : ''; };
  function sync() {
    const next = sessionKey();
    if (next !== key) { key = next; epoch++; loading = false; loaded = false; failed = false; busy = false; list = null; notice = ''; clear(); }
    return key;
  }
  function clear() { status.textContent = ''; root.replaceChildren(); root.hidden = true; }
  const offered = () => Boolean(key) && people()?.installReadiness === true && session()?.actor.role === 'admin';

  async function call(path, body) {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': session().csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(130000),
    });
    let result = null;
    try { result = await response.json(); } catch { /* handled below */ }
    if (!response.ok || result === null) { const error = new Error(result?.error?.message ?? 'The request could not be completed.'); error.status = response.status; error.code = result?.error?.code; throw error; }
    return result;
  }

  function deviceRow(device) {
    return el('li', { class: 'inventory-row', 'data-device': '' },
      el('strong', { 'data-name': '', textContent: device.label }),
      el('span', { class: 'fine-print', textContent: `${device.vendor ?? 'Unknown maker'} · ${PRESENCE[device.presence] ?? PRESENCE.unknown}` }),
      el('code', { 'data-mac': '', textContent: device.mac }),
      el('span', { class: 'inventory-flags' },
        mark(device.stable, 'Fixed address', 'Address may change'),
        mark(device.inScope, 'In router scope', 'Not in router scope')));
  }
  const group = (title, devices, empty) => el('section', { class: 'readiness-group' }, el('h3', { textContent: title }),
    devices.length ? el('ul', { class: 'inventory-list', role: 'list' }, ...devices.map(deviceRow)) : el('p', { class: 'fine-print', textContent: empty }));

  function draw() {
    if (!offered()) { clear(); return; }
    status.textContent = loading ? 'Loading…' : failed ? "Couldn't load the list." : '';
    const view = [el('h2', { id: 'install-readiness-title', textContent: 'Review for the router install' }),
      el('p', { class: 'fine-print', textContent: 'The devices the permanent install will allow (children) and protect (adults). Nothing here touches the router. Addresses are shown here and in the download only.' }), status];
    if (notice) view.push(el('p', { role: 'status', 'data-readiness-notice': '', textContent: notice }));
    if (list) {
      view.push(...list.children.map((child) => group(child.name, child.devices, 'No device yet.')));
      if (list.adultsAvailable !== true) view.push(el('p', { role: 'status', 'data-adults-notice': '', textContent: 'Adult devices are not included in this review yet.' }));
      view.push(el('section', { class: 'readiness-group', 'data-adults': '' }, el('h3', { textContent: 'Protected devices (existing protected set)' }),
        el('p', { 'data-adult-count': '', textContent: `${list.adults.length} protected ${list.adults.length === 1 ? 'device' : 'devices'}` }),
        el('p', { class: 'fine-print', textContent: "From the service's protected set, the baseline the router install preserves. Addresses are in the download only." })));
      view.push(el('section', { class: 'readiness-group' }, el('h3', { textContent: 'Warnings' }),
        list.warnings.length ? el('ul', { role: 'list', 'data-warnings': '' }, ...list.warnings.map((w) => el('li', { textContent: (WARNING[w.code] ?? (() => 'Check this list.'))(w) })))
          : el('p', { class: 'fine-print', textContent: 'No warnings.' })));
      view.push(el('p', { class: 'fine-print' }, 'Digest: ', el('code', { 'data-digest': '', textContent: list.digest })));
      view.push(el('p', { 'data-reviewed': '', textContent: Number.isFinite(list.reviewedAt) ? `Approved ${when(list.reviewedAt)}.` : 'Not approved yet.' }));
      view.push(el('button', { class: 'button', type: 'button', 'data-action': 'approve', 'aria-disabled': busy || list.adultsAvailable !== true ? 'true' : 'false', textContent: 'Approve this list (passkey)' }),
        el('button', { class: 'button secondary', type: 'button', 'data-action': 'download', 'aria-disabled': busy ? 'true' : 'false', textContent: 'Download' }));
    } else if (failed) view.push(el('button', { class: 'button secondary', type: 'button', 'data-action': 'retry', textContent: 'Try again' }));
    root.replaceChildren(...view);
    root.hidden = false;
  }

  async function load() {
    if (loading || !sync()) return;
    const mine = epoch;
    loading = true; failed = false; draw();
    try {
      const body = await call('/admin/install-readiness');
      if (mine !== epoch) return;
      if (!usable(body)) throw new Error('bad_response');
      list = body; loaded = true;
    } catch (error) {
      if (mine !== epoch) return;
      if (error.status === 403 || error.status === 404) { loading = false; list = null; loaded = true; clear(); return; }
      failed = true;
    }
    loading = false; draw();
  }
  const refused = (error) => {
    if (error.code === 'install_list_stale') return 'The list changed while you were reviewing it. Review it again.';
    return error.name === 'NotAllowedError' ? 'Passkey confirmation was cancelled. Nothing changed.' : error.message;
  };
  async function approve() {
    if (busy || !list || list.adultsAvailable !== true) return;
    busy = true; notice = 'Confirm with your passkey to approve this list.'; draw();
    const mine = epoch, digest = list.digest;
    try {
      const start = await call('/step-up/options', { action: 'install_list_approve', digest });
      const response = await getPasskey(start.options);
      await call('/admin/install-readiness/approve', { digest, stepUp: { challengeId: start.challengeId, response } });
      notice = 'Approved. Quote the digest when you ask for the live install step.';
    } catch (error) { notice = refused(error); }
    if (mine !== epoch) return;
    busy = false; await refreshList();
  }
  async function download() {
    if (busy || !list) return;
    busy = true; notice = ''; draw();
    const mine = epoch;
    try {
      const { export: file } = await call('/admin/install-readiness/export', { digest: list.digest });
      const url = URL.createObjectURL(new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }));
      const link = el('a', { href: url, download: `install-list-${file.digest.slice(0, 12)}.json` });
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      notice = 'Downloaded. The file lists device addresses: keep it private.';
    } catch (error) { notice = refused(error); }
    if (mine !== epoch) return;
    busy = false; await refreshList();
  }
  async function refreshList() {
    try { const body = await call('/admin/install-readiness'); if (usable(body)) list = body; } catch { /* the previous list stays; the notice explains */ }
    draw();
  }

  root.addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (!button || !sync() || button.getAttribute('aria-disabled') === 'true') return;
    if (button.dataset.action === 'approve') void approve();
    else if (button.dataset.action === 'download') void download();
    else if (button.dataset.action === 'retry') void load();
  });

  function update() {
    sync();
    if (!offered() || offline()) { if (!root.hidden || root.childNodes.length) clear(); return; }
    if (!loaded && !loading && !failed) void load();
  }
  return { update };
}
