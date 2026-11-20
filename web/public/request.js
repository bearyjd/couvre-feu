// Child request page. The capability token lives in the URL fragment, which browsers never send to servers.
const $ = (selector) => document.querySelector(selector);
const token = decodeURIComponent(location.hash.slice(1));
const POLL_MS = 5000;
let timer = null;

async function call(path, body) {
  const response = await fetch(path, {
    method: 'POST', credentials: 'omit', cache: 'no-store', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, ...body }), signal: AbortSignal.timeout(12000),
  });
  const result = await response.json();
  if (!response.ok) { const error = new Error(result.error?.message ?? 'The request could not be completed.'); error.code = result.error?.code; throw error; }
  return result;
}
const clock = (epoch) => new Date(epoch * 1000).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
const minutes = (value) => value === 60 ? '1 hour' : `${value} minutes`;
const wait = (seconds) => seconds >= 60 ? `${Math.ceil(seconds / 60)} minutes` : `${seconds} seconds`;

function describe(status) {
  switch (status.state) {
    case 'pending': return `Waiting for a parent. You asked for ${minutes(status.minutes)}. This request expires at ${clock(status.expiresAt)}.`;
    case 'approved':
      // A pause during the grant keeps the request approved but ends the extra time: never keep promising it.
      if (status.code === 'grant_ended') return 'A parent paused access, so the extra time has ended.';
      return `Approved: ${minutes(status.grantedMinutes)}, until ${clock(status.allowanceUntil)}.`;
    case 'declined': return 'Not this time. A parent said no.';
    case 'expired': return 'Nobody answered in time. You can ask again.';
    case 'cancelled': return 'This request was cancelled.';
    case 'unsupported': return 'Not supported yet: a schedule is blocking access and cannot be overridden here. Please ask a parent directly.';
    case 'apply_failed': return 'A parent approved, but the change could not be applied. Please ask a parent directly.';
    default: return 'Choose how much time you would like to ask for.';
  }
}
function render(status) {
  const form = $('#child-form');
  let text = describe(status);
  if (status.state !== 'pending' && status.retryAfter > 0) text += ` You can ask again in ${wait(status.retryAfter)}.`;
  $('#child-state').textContent = text;
  form.hidden = !status.canRequest;
  clearTimeout(timer);
  timer = setTimeout(() => void poll(), POLL_MS);
}
function invalid(message) {
  clearTimeout(timer);
  $('#child-form').hidden = true;
  $('#child-state').textContent = message;
}
async function poll() {
  if (document.hidden) { timer = setTimeout(() => void poll(), POLL_MS); return; }
  try { render(await call('/child/status', {})); }
  catch (error) {
    if (error.code === 'link_invalid') invalid('This link is not active. Ask a parent for a new one.');
    else { $('#child-state').textContent = 'Cannot reach the service. Trying again…'; timer = setTimeout(() => void poll(), POLL_MS); }
  }
}
$('#child-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.target), button = event.target.querySelector('button');
  button.disabled = true;
  try { render(await call('/child/request', { minutes: Number(form.get('minutes')), reason: String(form.get('reason') ?? '').trim() })); $('#child-reason').value = ''; }
  catch (error) { $('#child-state').textContent = error.message; }
  finally { button.disabled = false; }
});
if (!/^[A-Za-z0-9_-]{43}$/.test(token)) invalid('This link is not valid. Ask a parent for a new one.');
else void poll();
