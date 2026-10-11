export const ENDPOINT = 'wss://ws.postman-echo.com/raw';
export function randomHex() {
  return [...crypto.getRandomValues(new Uint8Array(16))].map(n => n.toString(16).padStart(2, '0')).join('');
}
export function clockBounds(sent, received, server) { return [server - received, server - sent]; }
export class Probe {
  constructor({socketFactory, now, random, log}) {
    Object.assign(this, {socketFactory, now, random, log});
    this.pending = new Map(); this.started = false; this.stopped = false; this.sequence = 0;
  }
  start() {
    if (this.started) throw Error('No reconnect or restart');
    this.started = true; this.startMs = this.now(); this.lastTick = this.startMs;
    this.run = this.random(); this.connection = this.random();
    this.socket = this.socketFactory(ENDPOINT);
    this.socket.onmessage = event => this.receive(event.data);
    this.socket.onclose = () => { this.log({event: 'closed', at: this.now()}); this.stop('socket closed'); };
    this.socket.onerror = () => { this.log({event: 'socket-error', at: this.now()}); this.stop('socket error'); };
  }
  stop(reason) {
    if (this.stopped) return;
    this.stopped = true; this.log({event: 'stopped', reason, at: this.now()});
    if (this.socket && this.socket.readyState < 2) this.socket.close();
  }
  tick() {
    if (this.stopped) return;
    const at = this.now();
    if (at - this.startMs >= 60000 || this.sequence >= 120) return this.stop('trial limit');
    if (at - this.lastTick > 750) return this.stop('timing gap: observation unavailable');
    this.lastTick = at;
    if (this.socket.readyState !== 1) return;
    const nonce = this.random();
    const payload = JSON.stringify({run: this.run, socket: this.connection, seq: ++this.sequence, nonce});
    const bytes = new TextEncoder().encode(payload).length;
    if (bytes > 256) return this.stop('payload limit');
    if (this.socket.bufferedAmount + bytes > 32768) return this.stop('buffer limit: observation unavailable');
    this.pending.set(nonce, {payload, at, replied: false});
    try { this.socket.send(payload); this.log({event: 'send', at, seq: this.sequence, nonce}); }
    catch { this.stop('send error'); }
  }
  receive(data) {
    const at = this.now(); let reply;
    try { reply = typeof data === 'string' && data.length <= 256 ? JSON.parse(data) : null; } catch { reply = null; }
    const item = reply && this.pending.get(reply.nonce);
    const valid = !this.stopped && item && data === item.payload && !item.replied && at - item.at >= 0 && at - item.at <= 500;
    if (valid) item.replied = true;
    this.log({event: valid ? 'fresh-echo' : 'rejected-echo', at, seq: valid ? reply.seq : null});
  }
}

if (typeof document !== 'undefined') {
  const cap = location.hash.slice(1); history.replaceState(null, '', location.pathname);
  const output = document.querySelector('pre'); const rows = []; let queue = [], probe, busy = false, timer, count = 0, bounds;
  const log = row => { if (rows.length < 700) { rows.push(row); queue.push(row); } else probe?.stop('log limit'); };
  const local = async (path, body) => {
    const response = await fetch(path, {method: body ? 'POST' : 'GET', headers: {'X-Probe-Cap': cap},
      body: body && JSON.stringify(body), cache: 'no-store', credentials: 'omit', signal: AbortSignal.timeout(500)});
    if (!response.ok) throw Error('Local helper unavailable');
    return response.json();
  };
  const calibrate = async () => {
    const sent = performance.now(), reply = await local('/clock'), received = performance.now();
    const next = clockBounds(sent, received, reply.serverMs);
    if (next[1] - next[0] > 250) throw Error('Clock uncertainty exceeds 250 ms');
    bounds = bounds ? [Math.max(bounds[0], next[0]), Math.min(bounds[1], next[1])] : next;
    if (bounds[0] > bounds[1]) throw Error('Clock mapping changed');
    log({event: 'clock-bounds', at: received, bounds, wallMs: Date.now(), timeOrigin: performance.timeOrigin});
  };
  document.querySelector('#start').onclick = async () => {
    if (probe) return;
    if (!/^[A-Za-z0-9_-]{43}$/.test(cap) || navigator.serviceWorker?.controller || document.hidden) {
      output.textContent = 'Unavailable: capability, foreground or service worker prerequisite failed.'; return;
    }
    try {
      await calibrate();
      probe = new Probe({socketFactory: url => new WebSocket(url), now: () => performance.now(), random: randomHex, log});
      probe.start();
      timer = setInterval(async () => {
        if (navigator.serviceWorker?.controller || document.hidden) probe.stop('page control/foreground changed');
        probe.tick();
        if (busy) return;
        busy = true;
        try {
          const nonce = randomHex(), events = queue.splice(0, 8);
          const reply = await local('/heartbeat', {clientMs: performance.now(), nonce, events});
          if (reply.nonce !== nonce) throw Error('Wrong heartbeat echo');
          if (++count % 20 === 0 || probe.stopped) await calibrate();
        } catch { probe.stop('heartbeat/clock unavailable'); }
        finally { busy = false; }
        output.textContent = `Application observation only: ${probe.sequence} sends; ${rows.filter(r => r.event === 'fresh-echo').length} fresh echoes. ${probe.stopped ? rows.findLast(r => r.event === 'stopped')?.reason : 'Running.'} Packet/route/offload gates pending.`;
        if (probe.stopped) clearInterval(timer);
      }, 500);
    } catch { output.textContent = 'Unavailable: local clock/helper baseline failed.'; }
  };
  for (const event of ['visibilitychange', 'freeze']) document.addEventListener(event, () => probe?.stop('lifecycle change: observation unavailable'));
  window.addEventListener('pagehide', () => probe?.stop('lifecycle change: observation unavailable'));
  document.querySelector('#stop').onclick = () => probe?.stop('operator stopped');
  document.querySelector('#save').onclick = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify({scope: 'application-only; packet gates pending', rows})], {type: 'application/json'}));
    const a = document.createElement('a'); a.href = url; a.download = 'client-probe-private.json'; a.click(); URL.revokeObjectURL(url);
  };
}
