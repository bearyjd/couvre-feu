// TCP-only liveness probe. It sends no HTTP request and needs no `trustedProxies` entry: the connection
// comes from the host's own address and the service drops it unread. It proves only that the listener
// accepts TCP; it does NOT prove the allowlist is in force (verify that with `ss` and an off-proxy curl).
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';

const manifestPath = process.argv[2] ?? '/etc/couvrefeu/manifest.json';
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const host = manifest.listen?.host ?? 'localhost';
const port = manifest.listen?.port ?? manifest.port;
const socket = connect({ host, port, timeout: 3000 });
socket.once('connect', () => { socket.destroy(); process.exit(0); });
socket.once('timeout', () => process.exit(1));
socket.once('error', () => process.exit(1));
