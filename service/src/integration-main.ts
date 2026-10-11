import { integrationConfig } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { IntegrationPolicy } from './integration-policy.ts';
import { Auth } from './auth.ts';
import { appServer } from './http.ts';
import { SSHRouter } from './ssh-router.ts';
import { IntegrationWorker } from './integration-worker.ts';
import { AutomaticDispatch } from './integration-automatic.ts';

if (process.argv.length !== 3) throw new Error('usage_integration_start_absolute_manifest');
const config = integrationConfig(process.argv[2]), store = new IntegrationStore(config);
// SSH is disabled unless the private manifest explicitly enables a new owner epoch.
const automatic = config.dispatch?.enabled ? new AutomaticDispatch(new IntegrationWorker(store, new SSHRouter(config))) : null;
if (!automatic) store.stopDispatch();
const auth = new Auth(store, config.origin, undefined, {provenance: config.provenance, rpName: 'Couvre-feu private integration'});
const server = appServer(auth, new IntegrationPolicy(store), config);
server.listen(config.port, '127.0.0.1', () => {
    process.stdout.write(automatic ? 'Private integration listening on loopback; manifest-enabled automatic dispatch active.\n' : 'Private integration listening on loopback; dispatch requires an exact one-use operator permit.\n');
    automatic?.start();
});
let stopping = false;
async function stop() {
    if (stopping) return; stopping = true;
    const closed = new Promise<void>(resolve => server.close(() => resolve()));
    if (automatic) await automatic.stop(); else store.stopDispatch();
    await closed;
    store.close();
}
process.on('SIGINT', stop); process.on('SIGTERM', stop);
