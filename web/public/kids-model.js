// Pure helpers for the Kids tab (UI plan H). No DOM, no requests, so they are unit-testable.
const STATE_WORD = { enrolling: 'Adding…', removing: 'Removing…', moving: 'Moving…' };
// Names a device carries out of the box: too common to say two devices are the same one.
const GENERIC = /^(android|iphone|ipad|galaxy|unknown|localhost|espressif|wlan\d*|device|phone|tablet)$/i;

export const stateWord = (state) => STATE_WORD[state] ?? null;
/** The chip for an enrolled device. A queued change is "sent" until the router confirms it: sent and confirmed are different words. */
export function deviceStatus(device) {
  if (stateWord(device.state)) return 'sent';
  if (device.onRouter === null) return 'unknown';
  return device.onRouter ? 'on_router' : 'missing';
}
export function ageText(seconds) {
  if (!Number.isFinite(seconds) || seconds < 90) return 'just now';
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}
/**
 * Addresses of enrolled devices that may have been replaced: the router's list shows that device quiet, and exactly one active,
 * private-address, not-yet-assigned row has the same (non-generic) name and first appeared after the old one went quiet. A guess for a "Replaced?" chip, never an action.
 */
export function replacedMacs(devices) {
  const key = (d) => (d.hostname ?? '').toLowerCase();
  const fresh = devices.filter((d) => d.flags?.unassigned && d.flags?.private && ['online', 'lease_only'].includes(d.presence) && d.hostname && !GENERIC.test(d.hostname));
  const quiet = devices.filter((d) => !d.flags?.unassigned && d.personName && d.presence === 'quiet' && d.hostname);
  // The new row must first appear after the old one went quiet: a device that was there all along is not its replacement.
  const successors = (d) => fresh.filter((n) => key(n) === key(d) && Number.isFinite(n.firstSeen) && Number.isFinite(d.lastSeen) && n.firstSeen >= d.lastSeen);
  return new Set(quiet.filter((d) => successors(d).length === 1 && quiet.filter((q) => key(q) === key(d)).length === 1).map((d) => d.mac));
}
