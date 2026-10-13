import { resolve } from 'node:path';
import { Store } from './db.ts';
import { seedAccounts } from './fixtures.ts';
import { Auth } from './auth.ts';
import { PolicyService } from './policy.ts';
import { appServer } from './http.ts';
import { ParentAlerts, systemActor } from './parent-alerts.ts';
import { demoConfig } from './config.ts';
import { ActivityStore, retentionDays } from './activity-store.ts';
import { FakeRouter } from '../../demo-router/src/router.ts';
const config = demoConfig(), store = new Store(resolve(config.dataDir, 'service.sqlite'));
seedAccounts(store);
const router = new FakeRouter(resolve(config.dataDir, 'fake-router.sqlite')), auth = new Auth(store, config.origin), policy = new PolicyService(store, router);
policy.reconcile();
const activity = new ActivityStore(store, {retentionDays: retentionDays()});
// Synthetic counters only; the store keeps enrolled children and the retention job bounds history.
const sample = () => {
    try { activity.ingest(router.activity(), Math.floor(Date.now() / 1000)); }
    catch { process.stderr.write('synthetic_activity_poll_failed\n'); }
};
const prune = () => {
    try { activity.prune(); }
    catch { process.stderr.write('synthetic_activity_prune_failed\n'); }
};
sample(); prune();
const activityTimer = setInterval(sample, 15000), pruneTimer = setInterval(prune, 3600000);
const timer = setInterval(() => {
    try {
        policy.reconcile();
    }
    catch {
        process.stderr.write('synthetic_reconciliation_failed\n');
    }
    try {
        alerts.sync();
    }
    catch {
        process.stderr.write('parent_alert_sync_failed\n');
    }
}, 250);
const alerts = new ParentAlerts(store, {people: () => policy.people(systemActor)});
const server = appServer(auth, policy, config, alerts, activity);
server.listen(config.port, '127.0.0.1', () => process.stdout.write(`Fictional authenticated demo: ${config.origin}; start demo:router independently.\n`));
function stop() {
    clearInterval(timer); clearInterval(activityTimer); clearInterval(pruneTimer);
    server.close(() => {
        router.close();
        store.close();
        process.exit(0);
    });
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
