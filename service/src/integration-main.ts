import { integrationConfig } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { Auth } from './auth.ts';
import { SSHRouter } from './ssh-router.ts';
import { wireIntegration } from './integration-wiring.ts';
import { AutomaticDispatch } from './integration-automatic.ts';
import { loadTLS } from './tls.ts';
import type { Server as HTTPSServer } from 'node:https';

if (process.argv.length !== 3) throw new Error('usage_integration_start_absolute_manifest');
const config = integrationConfig(process.argv[2]), store = new IntegrationStore(config);
// SSH is disabled unless the private manifest explicitly enables a new owner epoch.
const {worker, prune, app} = wireIntegration(config, store, new SSHRouter(config));
const automatic = config.dispatch?.enabled ? new AutomaticDispatch(worker) : null;
if (!automatic) store.stopDispatch();
const auth = new Auth(store, config.origin, undefined, {provenance: config.provenance, rpName: 'Couvre-feu private integration'});
prune();
const pruneTimer = setInterval(prune, 3600000);
const server = app(auth, config.tls ? {...config, tlsMaterial: loadTLS(config.tls)} : config);
server.listen(config.port, config.listen?.host ?? '127.0.0.1', () => {
    const where = config.trustedProxies ? `private LAN proxy HTTP ${config.origin} via ${config.trustedProxies.length} trusted proxies` : config.listen ? `private LAN HTTPS ${config.origin}` : 'loopback';
    process.stdout.write(automatic ? `Private integration listening on ${where}; manifest-enabled automatic dispatch active.\n` : `Private integration listening on ${where}; dispatch requires an exact one-use operator permit.\n`);
    automatic?.start();
});
let stopping = false;
async function stop() {
    if (stopping) return; stopping = true;
    clearInterval(pruneTimer);
    const closed = new Promise<void>(resolve => server.close(() => resolve()));
    if (automatic) await automatic.stop(); else store.stopDispatch();
    await closed;
    store.close();
}
// Reload renewed certificates in place; a bad pair keeps the previous one.
process.on('SIGHUP', () => {
    try { if (config.tls) (server as HTTPSServer).setSecureContext(loadTLS(config.tls)); } catch (error) { process.stderr.write(`tls_reload_failed ${(error as Error).message}\n`); }
});
process.on('SIGINT', stop); process.on('SIGTERM', stop);
