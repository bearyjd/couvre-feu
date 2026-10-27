import type { Auth } from './auth.ts';
import { ActivityStore, retentionDays } from './activity-store.ts';
import { appServer } from './http.ts';
import type { DemoConfig } from './config.ts';
import type { IntegrationConfig } from './integration-config.ts';
import type { IntegrationStore } from './integration-db.ts';
import { IntegrationPolicy } from './integration-policy.ts';
import { IntegrationWorker } from './integration-worker.ts';
import { inventoryRetentionDays } from './inventory-store.ts';
import { ParentAlerts } from './parent-alerts.ts';
import { auditFor } from './parent-audit.ts';
import type { AsyncRouter } from './router-transport.ts';

/**
 * The integration process's components and how they are joined: the inventory store (and its retention) lives on the worker, one prune covers
 * activity and inventory retention, and the app server serves the inventory routes from that same store.
 */
export function wireIntegration(config: IntegrationConfig, store: IntegrationStore, router: AsyncRouter, env: NodeJS.ProcessEnv = process.env) {
    const worker = new IntegrationWorker(store, router, undefined, inventoryRetentionDays(env));
    const activity = new ActivityStore(store, {retentionDays: retentionDays(env), provenance: config.provenance});
    const prune = () => {
        try { activity.prune(); } catch { process.stderr.write('activity_prune_failed\n'); }
        // Inventory retention holds even while automatic dispatch is off.
        try { worker.inventory.prune(); } catch { process.stderr.write('inventory_prune_failed\n'); }
        // Audit rows age out after 90 days whether or not the log is still on; this runs at startup and hourly (a bounded delete).
        try { auditFor(store).prune(); } catch { process.stderr.write('parent_audit_prune_failed\n'); }
    };
    const app = (auth: Auth, serverConfig: DemoConfig): ReturnType<typeof appServer> => appServer(auth, new IntegrationPolicy(store), serverConfig, new ParentAlerts(store, null), activity, undefined, worker.inventory);
    return {worker, activity, prune, app};
}
