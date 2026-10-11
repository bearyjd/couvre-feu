import { testConfig, TestRouter } from './integration.ts';
import { IntegrationStore } from '../../src/integration-db.ts';
import { IntegrationWorker } from '../../src/integration-worker.ts';
const store = new IntegrationStore(testConfig(process.argv[2])), now = () => 1791691200;
const router = new TestRouter(store, now);
router.invoke = async () => { if (store.db.isTransaction) process.exit(24); process.exit(23); };
const worker = new IntegrationWorker(store, router, now), plan = worker.prepare('apply', process.argv[3]);
await worker.execute(plan, plan.scriptSha256);
process.exit(25);
