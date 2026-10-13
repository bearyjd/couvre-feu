// Per-child estimated network activity. Built from DOM nodes and textContent only; nothing is cached in browser storage.
export const ACTIVITY_LABEL = 'Estimated network activity — not app use, websites or screen time';
const REFRESH_SECONDS = 60;
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
// A range that ends exactly at midnight is shown as 24:00 so a whole-day gap never reads 00:00–00:00.
const utcClock = (seconds, dayStart) => seconds === dayStart + 86400 ? '24:00' : new Date(seconds * 1000).toISOString().slice(11, 16);
const percent = (part, whole) => whole > 0 ? Math.round(part / whole * 100) : 0;
export function formatBytes(bytes) {
  if (bytes === null) return 'traffic unknown';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes, unit = 0;
  while (value >= 1000 && unit < units.length - 1) { value /= 1000; unit++; }
  return `${unit === 0 ? value : value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}
function dayName(day, index, total) {
  if (index === total - 1) return 'Today';
  return new Date(day.start * 1000).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' });
}
/** Exported for tests: the one-line, never-zero summary of a day. */
export function dayFigures(day) {
  if (day.coverage === 'none') return 'No data: activity unknown';
  const lower = day.unknownMinutes > 0 || day.possiblyUndercounted;
  return `${lower ? 'At least ' : 'About '}${day.estimatedOnlineMinutes} min online · ${formatBytes(day.totalBytes)} · ${day.blockedAttempts === null ? 'blocked attempts unknown' : `${day.blockedAttempts} blocked attempts`}`;
}
function dayRow(day, index, days, scaleMinutes) {
  const row = el('li', 'activity-day');
  row.dataset.date = day.date; row.dataset.coverage = day.coverage;
  row.append(el('span', 'activity-day-name', dayName(day, index, days.length)));
  const bars = el('div', 'activity-bars');
  bars.setAttribute('role', 'img');
  bars.setAttribute('aria-label', day.coverage === 'none' ? 'No data for this day; activity unknown' : `Estimated online minutes ${day.estimatedOnlineMinutes} on a scale of ${scaleMinutes}; ${percent(day.coveredMinutes, day.expectedMinutes)} percent of the day observed`);
  const online = el('div', 'activity-track'), fill = el('span', 'activity-online');
  if (day.estimatedOnlineMinutes !== null) fill.style.width = `${Math.min(100, day.estimatedOnlineMinutes / scaleMinutes * 100)}%`;
  online.append(fill);
  const coverage = el('div', 'activity-track activity-coverage-track'), known = el('span', 'activity-covered');
  known.style.width = `${percent(day.coveredMinutes, day.expectedMinutes)}%`;
  coverage.append(known);
  bars.append(online, coverage);
  row.append(bars, el('span', 'activity-figures', dayFigures(day)));
  const notes = el('span', 'activity-notes');
  notes.append(el('span', 'activity-coverage-note', day.expectedMinutes === 0 ? 'Nothing to observe yet.' : `Observed ${day.coveredMinutes} of ${day.expectedMinutes} min (${percent(day.coveredMinutes, day.expectedMinutes)}%); ${day.unknownMinutes} min unknown.`));
  if (day.coverage !== 'none' && day.gaps.length > 0) notes.append(el('span', 'activity-gaps', `Unknown stretches (UTC): ${day.gaps.map((gap) => `${utcClock(gap.start, day.start)}–${utcClock(gap.end, day.start)}`).join(', ')}${day.gapsTruncated ? ', and more' : ''}.`));
  if (day.possiblyUndercounted) notes.append(el('span', 'activity-offload', `Hardware offload was ${day.offload}: traffic may be undercounted.`));
  row.append(notes);
  return row;
}
function card(person, report) {
  const section = el('section', 'activity-card');
  section.dataset.activityPerson = person.id;
  section.append(el('h3', '', `${person.name}`));
  section.append(el('p', 'activity-label', ACTIVITY_LABEL));
  if (!report || report.error) {
    section.append(el('p', 'activity-state', report?.error ? 'Activity is unavailable right now. Nothing is assumed.' : 'Loading estimated activity…'));
    return section;
  }
  const scale = Math.max(60, ...report.days.map((day) => day.estimatedOnlineMinutes ?? 0));
  const list = el('ol', 'activity-days');
  list.setAttribute('aria-label', `${person.name} estimated network activity by day`);
  report.days.forEach((day, index, days) => list.append(dayRow(day, index, days, scale)));
  section.append(list);
  section.append(el('p', 'fine-print activity-method', `Bars: estimated online minutes (top) and share of the day actually observed (bottom). A minute counts as online when its devices moved more than ${formatBytes(report.thresholdBytesPerMinute)}. Router counters cannot see which app or site used the network, and hardware offload can hide traffic. Unobserved time is unknown, not zero. Days are UTC; history is kept for ${report.retentionDays} days.`));
  return section;
}
export function createActivityPanel({ container, api }) {
  let generation = 0;
  const reports = new Map(), inflight = new Set();
  const draw = (people) => container.replaceChildren(el('h2', '', 'Estimated activity'), ...people.map((person) => card(person, reports.get(person.id)?.value)));
  return {
    clear() { generation++; reports.clear(); inflight.clear(); container.replaceChildren(); container.hidden = true; },
    /** Safe to call on every render: requests are throttled per person and stale results are dropped after clear(). */
    update(people, enabled) {
      if (!enabled || people.length === 0) { if (!container.hidden || reports.size) this.clear(); return; }
      const wanted = new Set(people.map((person) => person.id));
      for (const id of [...reports.keys()]) if (!wanted.has(id)) reports.delete(id);
      const stamp = Math.floor(Date.now() / 1000), current = generation;
      let changed = container.hidden || container.querySelectorAll('.activity-card').length !== people.length;
      for (const person of people) {
        const entry = reports.get(person.id);
        if (inflight.has(person.id) || (entry && stamp - entry.at < REFRESH_SECONDS)) continue;
        inflight.add(person.id);
        void api(`/people/${encodeURIComponent(person.id)}/activity`).then((value) => ({ value }), (error) => ({ value: { error: error.code ?? 'request_failed' } })).then((result) => {
          inflight.delete(person.id);
          if (current !== generation) return;
          reports.set(person.id, { at: Math.floor(Date.now() / 1000), value: result.value });
          container.hidden = false; draw(people);
        });
      }
      if (changed) { container.hidden = false; draw(people); }
    },
  };
}
