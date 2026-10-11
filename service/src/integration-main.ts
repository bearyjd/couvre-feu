import { integrationConfig } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { IntegrationPolicy } from './integration-policy.ts';
import { Auth } from './auth.ts';
import { appServer } from './http.ts';

if (process.argv.length !== 3) throw new Error('usage_integration_start_absolute_manifest');
const config = integrationConfig(process.argv[2]), store = new IntegrationStore(config);
// A restart fences old local callbacks, revokes unconsumed future authorization, and never invokes SSH.
store.stopDispatch();
const auth = new Auth(store, config.origin, undefined, {provenance: config.provenance, rpName: 'Couvre-feu private integration'});
const server = appServer(auth, new IntegrationPolicy(store), config);
server.listen(config.port, '127.0.0.1', () => process.stdout.write('Private integration listening on loopback; live dispatch requires an exact one-use operator permit.\n'));
let stopping = false;
function stop() {
    if (stopping) return; stopping = true;
    store.stopDispatch();
    server.close(() => { store.close(); process.exit(0); });
}
process.on('SIGINT', stop); process.on('SIGTERM', stop);
