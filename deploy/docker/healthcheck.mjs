// TCP-only liveness probe. It never sends an HTTP request, so it does not weaken `trustedProxies`:
// the connection comes from the host's own address, which the service destroys unread. A completed
// TCP handshake is enough to prove the listener is up.
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';

const manifestPath = process.argv[2] ?? '/etc/couvrefeu/manifest.json';
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const host = manifest.listen?.host ?? '127.0.0.1';
const port = manifest.listen?.port ?? manifest.port;
const socket = connect({ host, port, timeout: 3000 });
socket.once('connect', () => { socket.destroy(); process.exit(0); });
socket.once('timeout', () => process.exit(1));
socket.once('error', () => process.exit(1));
