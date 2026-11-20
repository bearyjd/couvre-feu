// Tab bar and hash routing. Layout only: every panel keeps its own element, id and show/hide logic; a tab panel is a plain wrapper
// that is shown or hidden around them, so the modules that fill the panels never know the tabs exist.
const TABS = [
  { id: 'home', label: 'Home', heading: '#people-title' },
  { id: 'kids', label: 'Kids', heading: '#children-title', needsInfrastructure: true },
  { id: 'devices', label: 'Devices', heading: '#inventory-title', needsInfrastructure: true },
  { id: 'alerts', label: 'Alerts', heading: '#alerts-heading' },
  { id: 'more', label: 'More', heading: '#more-heading' },
];
// #tab/sub deep links. Anything else after the slash is ignored (the tab still opens).
const SUBS = {
  home: { requests: '#time-requests', bulk: '#bulk-panel' },
  alerts: { parent: '#parent-alerts', browser: '#operational-alerts' },
  more: { schedules: '#schedule-editor', activity: '#activity-panel', audit: '#audit-panel', accounts: '#accounts-panel', install: '#install-readiness-panel', about: '#about-panel' },
};
const ROUTE = /^#(home|kids|devices|alerts|more)(?:\/([a-z-]+))?$/;
const SUB_SECONDS = 6; // a sub-hash target that loads late is scrolled to once, but only soon after the link was opened
const count = (value) => Number.isSafeInteger(value) && value > 0 ? value : 0;

export const parseRoute = (hash) => { const match = ROUTE.exec(hash); return match ? { tab: match[1], sub: match[2] ?? null } : null; };

export function createTabs({ bar = document.querySelector('#tabbar') } = {}) {
  const tabs = new Map(TABS.map((spec) => [spec.id, { ...spec, link: bar.querySelector(`#tab-${spec.id}`), panel: document.querySelector(`#panel-${spec.id}`) }]));
  const list = bar.querySelector('[role="tablist"]');
  let signedIn = false, infrastructure = false, current = null, pendingSub = null, lastHash = null, forceFocus = null;

  const available = (spec) => !spec.needsInfrastructure || infrastructure;
  const order = () => TABS.filter(available).map((spec) => spec.id);

  function setBadge(id, total, phrase) {
    const entry = tabs.get(id), badge = entry.link.querySelector('.tab-badge');
    const shown = count(total);
    setHidden(badge, shown === 0);
    badge.textContent = shown === 0 ? '' : String(shown);
    entry.link.setAttribute('aria-label', shown === 0 ? entry.label : `${entry.label}, ${phrase(shown)}`);
  }

  // Assigning an unchanged `hidden` still queues a mutation record; the observers below would then feed themselves.
  const setHidden = (element, value) => { if (element.hidden !== value) element.hidden = value; };

  function showEmptyNotes() {
    for (const { panel } of tabs.values()) {
      const note = panel.querySelector(':scope > .tab-empty');
      if (note) setHidden(note, [...panel.children].some((child) => child !== note && !child.matches('.tab-heading, .more-jump') && !child.hidden));
    }
  }

  // The jump list on More offers only the sections that are showing.
  function syncJump() {
    const jump = document.querySelector('#more-jump');
    let any = false;
    for (const link of jump.querySelectorAll('a[data-target]')) {
      const target = document.querySelector(link.dataset.target), shown = Boolean(target) && !target.hidden;
      setHidden(link, !shown); any ||= shown;
    }
    setHidden(jump, !any);
  }

  function applySub(route) {
    if (!pendingSub || Date.now() > pendingSub.until) { pendingSub = null; return; }
    const target = document.querySelector(pendingSub.selector);
    if (!target || target.hidden || route?.tab !== current) return;
    pendingSub = null;
    target.scrollIntoView({ block: 'start' });
  }

  function select(id) {
    for (const [name, entry] of tabs) {
      const on = name === id;
      entry.link.setAttribute('aria-selected', String(on));
      entry.link.tabIndex = on ? 0 : -1;
      setHidden(entry.panel, !on);
    }
    current = id;
  }

  function focusHeading(id) {
    window.scrollTo(0, 0);
    // The panel's own title when it is showing; the panel itself while that title is not (e.g. its data has not loaded).
    const title = document.querySelector(tabs.get(id).heading), target = title && !title.closest('[hidden]') ? title : tabs.get(id).panel;
    target.tabIndex = -1;
    target.focus({ preventScroll: true });
  }

  /** Reconcile the page with location.hash. Focus moves only when the viewer arrived at a tab on purpose (never on load, never for #main). */
  function sync({ moveFocus = false } = {}) {
    setHidden(bar, !signedIn);
    for (const spec of TABS) setHidden(tabs.get(spec.id).link, !available(spec));
    if (!signedIn) { current = null; pendingSub = null; lastHash = null; return; } // no stale tab survives a sign-out
    let route = parseRoute(location.hash), next = current ?? 'home';
    if (route && !available(tabs.get(route.tab))) { history.replaceState(null, '', '#home'); route = parseRoute('#home'); }
    if (route) next = route.tab;
    else if (location.hash === '' || location.hash === '#') next = 'home';
    const arrived = next !== current || (moveFocus && forceFocus === next);
    if (next !== current) select(next);
    if (location.hash !== lastHash) {
      lastHash = location.hash;
      const selector = route?.sub ? SUBS[next]?.[route.sub] : null;
      pendingSub = selector ? { selector, until: Date.now() + SUB_SECONDS * 1000 } : null;
    }
    showEmptyNotes(); syncJump();
    if (arrived && moveFocus) { forceFocus = null; focusHeading(next); }
    applySub(route);
  }

  /** A tab tap replaces the history entry (tapping around must not fill Back); linked navigation and show() push. */
  function go(id) {
    if (!tabs.has(id) || !available(tabs.get(id))) return;
    if (location.hash !== `#${id}`) history.replaceState(null, '', `#${id}`);
    forceFocus = id; // the same tab again still hands focus to its heading
    sync({ moveFocus: true });
  }

  list.addEventListener('click', (event) => {
    const link = event.target.closest('[role="tab"]');
    if (!link) return;
    event.preventDefault();
    go(link.id.slice('tab-'.length));
  });
  list.addEventListener('keydown', (event) => {
    const link = event.target.closest('[role="tab"]');
    if (!link) return;
    const ids = order(), at = ids.indexOf(link.id.slice('tab-'.length));
    if (event.key === ' ') { event.preventDefault(); go(ids[at]); return; }
    const target = { ArrowRight: (at + 1) % ids.length, ArrowLeft: (at + ids.length - 1) % ids.length, Home: 0, End: ids.length - 1 }[event.key];
    if (target === undefined) return;
    event.preventDefault();
    tabs.get(ids[target]).link.focus();
  });
  window.addEventListener('hashchange', () => sync({ moveFocus: true }));

  // Badge sources are the panels' own outputs, so the numbers can never disagree with what the panel shows.
  const inventory = document.querySelector('#inventory-panel'), alertBadge = document.querySelector('#alert-badge');
  const readDevices = () => setBadge('devices', Number(inventory.dataset.newCount), (n) => `${n} new ${n === 1 ? 'device' : 'devices'}`);
  const readAlerts = () => setBadge('alerts', alertBadge.hidden ? 0 : Number(alertBadge.textContent), (n) => `${n} ${n === 1 ? 'alert needs' : 'alerts need'} attention`);
  new MutationObserver(readDevices).observe(inventory, { attributes: true, attributeFilter: ['data-new-count', 'hidden'] });
  new MutationObserver(readAlerts).observe(alertBadge, { attributes: true, attributeFilter: ['hidden'], childList: true, characterData: true, subtree: true });
  new MutationObserver(() => { showEmptyNotes(); syncJump(); applySub(parseRoute(location.hash)); }).observe(document.querySelector('#status-view'), { attributes: true, attributeFilter: ['hidden'], subtree: true });
  // On a phone the on-screen keyboard would float the pinned bar over the field being typed in: step aside while a text field has focus.
  const typing = (element) => Boolean(element?.matches?.('input:not([type="checkbox"]):not([type="radio"]):not([type="button"]):not([type="submit"]), textarea, select'));
  const setTyping = (on) => bar.classList.toggle('is-typing', on);
  document.addEventListener('focusin', (event) => setTyping(typing(event.target)));
  document.addEventListener('focusout', () => setTyping(false));
  window.visualViewport?.addEventListener('resize', () => setTyping(window.innerHeight - window.visualViewport.height > 150 || typing(document.activeElement)));
  readDevices(); readAlerts();

  return {
    /** Open a tab from code (e.g. "Add to a child" on the Devices tab needs the Kids form). One new history entry, so Back returns; focus stays with the caller. */
    show(id) {
      if (!signedIn || !tabs.has(id) || !available(tabs.get(id))) return false;
      if (location.hash !== `#${id}`) history.pushState(null, '', `#${id}`);
      sync();
      return true;
    },
    /** signedIn: the status view is showing. infrastructure: this viewer can use the Kids and Devices panels. */
    update(options) {
      signedIn = Boolean(options.signedIn); infrastructure = Boolean(options.infrastructure);
      sync();
    },
  };
}
