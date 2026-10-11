// Cross-process reconciliation fixture; no HTTP identity or scenario injection.
import { Store } from '../../src/db.ts';
import { FakeRouter } from '../../../demo-router/src/router.ts';
import { PolicyService } from '../../src/policy.ts';
const [dir, id] = process.argv.slice(2), now = 1791691200;
const store = new Store(`${dir}/service.sqlite`), router = new FakeRouter(`${dir}/fake.sqlite`, { now: () => now });
const policy = new PolicyService(store, router, () => now);
process.on('message', () => {
    policy.reconcile();
    const result = store.get('SELECT state,confirmed_at FROM operations WHERE id=?', id);
    store.close(); router.close(); process.send!(result, () => process.exit(0));
});
process.send!({ ready: true });
