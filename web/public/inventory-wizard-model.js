// Pure rules for the "Find a kid's device" wizard (UI plan G): which rows to offer, the toggle-test diff, OS wording and the add-form name.
// No DOM and no imports, so node tests can load it. Every function returns new values and never changes its arguments.
export const JUST_CONNECTED_SECONDS = 600;
const LIST_CAP = 40;
const NOT_KIDS = new Set(['adult', 'infrastructure', 'home', 'ignored']);
const NO_PHONE_SETTING = new Set(['computer', 'console', 'tv', 'speaker', 'appliance', 'virtual', 'network']);

const newest = (a, b) => b.firstSeen - a.firstSeen || b.lastSeen - a.lastSeen;
/** A row a parent could still give to a child: not enrolled already and not sorted as someone else's or as infrastructure. */
export const candidate = (d) => d.flags.unassigned && !NOT_KIDS.has(d.role);
export const justConnected = (devices, now) => devices.filter((d) => candidate(d) && now - d.firstSeen <= JUST_CONNECTED_SECONDS).sort(newest);
export const pickable = (devices) => devices.filter(candidate).sort(newest).slice(0, LIST_CAP);
export const online = (d) => d.presence === 'online';
/** What each row looked like at Start: on or not, and when a neighbour was last seen. `scanAt` is the service's last finished scan. */
export const snapshotOf = (devices, scanAt) => ({ scanAt: scanAt ?? 0, rows: Object.fromEntries(devices.map((d) => [d.id, { on: online(d), seen: d.lastSeen }])) });

/**
 * The toggle test. Went quiet = it was on at Start and is not any more, or a scan finished after Start and did not see it (its last-seen time
 * did not move), which shows within a minute instead of waiting for it to age out. Came back = went quiet earlier and is seen again.
 * A row that did not exist at Start and is on now is a "new" device, never "came back".
 */
export function diffPresence(snapshot, quietIds, devices, scanAt) {
  const quiet = new Set(quietIds), rows = snapshot.rows;
  const scanned = Number.isFinite(scanAt) && scanAt > snapshot.scanAt;
  for (const d of devices) {
    const was = rows[d.id];
    if (was?.on && (!online(d) || (scanned && d.lastSeen <= was.seen))) quiet.add(d.id);
  }
  const states = new Map();
  for (const d of devices.filter(candidate)) {
    const was = rows[d.id];
    if (was === undefined) { if (online(d)) states.set(d.id, 'new'); } else if (quiet.has(d.id)) states.set(d.id, online(d) && d.lastSeen > was.seen ? 'back' : 'quiet');
  }
  return { quiet: [...quiet], states };
}

/** Wording for the private-address switch: by maker for phones and tablets, a generic line for PCs, consoles and TVs. */
export function osLines(device) {
  const iphone = 'iPhone or iPad: Wi-Fi > this network > Private Wi-Fi Address: OFF.';
  const android = 'Android: Wi-Fi > this network > Use device MAC.';
  if (NO_PHONE_SETTING.has(device.kind)) return ['Turn off any private or random address option in its Wi-Fi settings.'];
  return typeof device.vendor === 'string' ? (/apple/i.test(device.vendor) ? [iphone] : [android]) : [iphone, android];
}

const MODEL = /^(?:pro|max|plus|mini|air|ultra|se|xl|fe|lite|\d+[a-z]?|[a-z]\d{1,3}[a-z]?)$/i;
const PLACEHOLDER = new Set(['localhost', 'localdomain', 'unknown', 'device', 'host', 'user', 'none', 'null', 'default', 'home', 'android', 'phone']);
function nameFrom(device) {
  const token = String(device.hostname ?? '').split(/[^A-Za-z0-9]+/).find((t) => t.length >= 3 && !MODEL.test(t) && !PLACEHOLDER.has(t.toLowerCase()) && !/^[0-9a-f]{6,}$/i.test(t));
  if (token) return token;
  if (typeof device.kind === 'string' && device.kind !== 'unknown') return device.kind;
  const maker = typeof device.vendor === 'string' ? device.vendor.trim().split(/\s+/)[0] : '';
  return maker || 'device';
}
/** The add form's starting name: "Jack's Pixel", "James' phone". The parent can edit it; 64 characters at most. */
export function deviceName(childName, device) {
  const child = String(childName ?? '').trim(), possessive = !child ? '' : /s$/i.test(child) ? `${child}'` : `${child}'s`;
  return `${possessive} ${nameFrom(device)}`.trim().slice(0, 64);
}
