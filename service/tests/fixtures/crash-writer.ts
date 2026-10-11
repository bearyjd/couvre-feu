// Crash-only fixture: the parent kills this process after durable operation acceptance.
import { Store } from '../../src/db.ts';
import { FakeRouter } from '../../../demo-router/src/router.ts';
import { PolicyService } from '../../src/policy.ts';
const [dir, token, key, until] = process.argv.slice(2);
const now = 1791691200;
const store = new Store(`${dir}/service.sqlite`);
const router = new FakeRouter(`${dir}/fake.sqlite`, { now: () => now });
router.apply = () => { throw new Error('fixture_interrupted_before_apply'); };
const policy = new PolicyService(store, router, () => now);
const actor = { id: 'jd', displayName: 'Crash fixture', role: 'admin' as const, personIds: ['alex', 'blair'], permissionVersion: '1' };
const reply = policy.mutate(actor, 'alex', 'pause', { until: Number(until) }, token, key);
process.send!({ id: reply.result.operation.id });
setInterval(() => {}, 1000);
