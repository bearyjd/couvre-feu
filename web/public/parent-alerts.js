// Server-persisted parent alerts. Separate from the browser-local journal in operational-alerts.js; the badge merges both counts.
const TITLES = {
  enforcement_unhealthy: 'Enforcement may not be working',
  sync_failed: 'A change could not be applied',
  apply_pending_too_long: 'A change is taking too long',
  possible_bypass: 'Possible bypass',
  repeated_blocked_attempts: 'Repeated blocked attempts',
  time_request_pending: 'Time request waiting',
  router_scope_change: 'Router device list changed',
  new_device: 'New device on the network',
  inventory_stalled: 'Network inventory has not completed recently',
};
const SEVERITIES = ['info', 'warning', 'critical'];
const STATES = ['open', 'acknowledged', 'resolved'];
const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const kb = (bytes) => `${Math.round(count(bytes) / 1024).toLocaleString()} KB`;

export function alertSummary(alert) {
  const d = alert.details ?? {};
  switch (alert.kind) {
    case 'enforcement_unhealthy': return d.drift ? 'The router reports its rules differ from the saved policy.' : 'The router has not been observed recently, so limits cannot be confirmed.';
    case 'sync_failed': return 'The router did not confirm the latest requested change. Review the current status and try again.';
    case 'apply_pending_too_long': return 'The latest requested change is still not confirmed by the router.';
    case 'possible_bypass': return `${kb(d.totalBytes)} of traffic was counted while access was blocked. This can indicate a device that is not covered; it is not proof.`;
    case 'repeated_blocked_attempts': return `${count(d.blockedPackets).toLocaleString()} blocked connection attempts were counted in one window.`;
    case 'time_request_pending': return `${count(d.pendingRequests)} request for more time ${count(d.pendingRequests) === 1 ? 'is' : 'are'} waiting.`;
    case 'router_scope_change': {
      // Counts only: the server never puts device addresses in an alert.
      const added = count(d.added), removed = count(d.removed);
      return `${added} device${added === 1 ? '' : 's'} added and ${removed} removed from the router's allowed list. ${d.matched === true ? 'A request exists.' : 'No matching request — check with the router administrator.'}`;
    }
    case 'new_device': {
      // Counts only: names and addresses of devices are never put in an alert.
      const n = count(d.count);
      return `${n} new device${n === 1 ? '' : 's'} appeared on the network.${n > 1 ? ' Review them under Devices on the network.' : ''}`;
    }
    case 'inventory_stalled':
      return d.cause === 'row_cap' ? 'The router lists more devices than the inventory can keep, so some may be missing.'
        : `No complete device scan for about ${count(d.count).toLocaleString()} minute${count(d.count) === 1 ? '' : 's'}. New devices may go unnoticed until the router answers.`;
    default: return '';
  }
}

export function createParentAlerts({ escape, time, csrfToken, personName }) {
  const panel = document.querySelector('#parent-alerts'), feed = document.querySelector('#parent-alert-feed');
  const hint = document.querySelector('#parent-alerts-hint'), badge = document.querySelector('#alert-badge'), more = document.querySelector('#parent-alerts-more');
  let failed = false, epoch = 0, items = [], openCount = 0, nextBefore = null, localCount = 0, available = false, busy = false;

  const clear = () => { epoch++; items = []; openCount = 0; nextBefore = null; available = false; busy = false; };
  async function request(path, init = {}) {
    const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(12000), ...init });
    if (!response.ok) throw new Error(String(response.status));
    return response.json();
  }
  function accept(alert) {
    return alert && Number.isSafeInteger(alert.id) && alert.id > 0 && alert.kind in TITLES && SEVERITIES.includes(alert.severity) && STATES.includes(alert.state);
  }

  function draw() {
    panel.hidden = !available;
    const total = openCount + localCount;
    badge.hidden = total === 0; badge.textContent = String(total);
    badge.setAttribute('aria-label', `${total} alert${total === 1 ? '' : 's'} need attention`);
    const html = items.map((alert) => {
      const who = alert.personId ? escape(personName(alert.personId) ?? alert.personId) : 'Whole system';
      const when = alert.resolvedAt ? ` · resolved ${escape(time(alert.resolvedAt))}` : '';
      const action = alert.state === 'open' ? `<button class="button secondary" type="button" data-acknowledge="${alert.id}">Acknowledge</button>` : '';
      return `<li class="alert-row parent-alert severity-${alert.severity}${alert.state === 'resolved' ? ' recovered' : ''}" data-alert-id="${alert.id}" data-alert-state="${alert.state}">` +
        `<strong>${who} · ${escape(TITLES[alert.kind])}</strong><p>${escape(alertSummary(alert))}</p>` +
        `<small>${escape(alert.state)} · first seen ${escape(time(alert.firstSeen))} · last seen ${escape(time(alert.lastSeen))} · seen ${count(alert.count)}×${when}</small>${action}</li>`;
    }).join('') || '<li class="fine-print">No saved alerts for your permitted people.</li>';
    if (feed.innerHTML !== html) feed.innerHTML = html;
    more.hidden = nextBefore === null;
    hint.hidden = !failed;
  }

  async function load(older = false) {
    if (busy) return;
    const mine = epoch, path = older && nextBefore !== null ? `/alerts/before/${nextBefore}` : '/alerts';
    busy = true;
    try {
      const page = await request(path);
      if (mine !== epoch) return;
      const fresh = (Array.isArray(page.alerts) ? page.alerts : []).filter(accept);
      items = older ? [...items, ...fresh] : fresh;
      openCount = count(page.openCount); nextBefore = Number.isSafeInteger(page.nextBefore) ? page.nextBefore : null; available = true;
    } catch {
      if (mine !== epoch) return;
      if (!older) { items = []; openCount = 0; nextBefore = null; available = false; } // unavailable here: local alerts keep working
    } finally { if (mine === epoch) busy = false; }
    if (mine === epoch) draw();
  }

  async function acknowledge(id) {
    failed = false;
    const mine = epoch, token = csrfToken();
    if (!token) return;
    try {
      await request(`/alerts/${id}/acknowledge`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token }, body: '{}' });
    } catch { failed = true; }
    if (mine === epoch) { await load(); failed = failed && items.some((a) => a.id === id && a.state === 'open'); draw(); }
  }

  feed.addEventListener('click', (event) => {
    const button = event.target.closest('[data-acknowledge]');
    if (button) void acknowledge(Number(button.dataset.acknowledge));
  });
  more.addEventListener('click', () => void load(true));

  return {
    load: () => load(false),
    /** Call from the app's render(): visible=false drops all data so a different account never sees stale rows. */
    render(visible, local = 0) {
      if (!visible) { if (available || items.length) clear(); localCount = 0; panel.hidden = true; badge.hidden = true; return; }
      localCount = count(local); draw();
    },
  };
}
