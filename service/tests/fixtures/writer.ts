// Constructor-only fixture identity; never imported by the runnable service.
import { Store } from '../../src/db.ts';
import { FakeRouter } from '../../../demo-router/src/router.ts';
import { PolicyService } from '../../src/policy.ts';
const [dir, token, key] = process.argv.slice(2), now = 1791691200;
const store = new Store(`${dir}/service.sqlite`), router = new FakeRouter(`${dir}/fake.sqlite`, {
    now: () => now
}), policy = new PolicyService(store, router, () => now);
const actor = {
    id: 'jd', displayName: 'Constructor fixture', role: 'admin' as const, personIds: ['alex', 'blair'], permissionVersion: '1'
};
process.on('message', () => {
    let result;
    try {
        const reply = policy.mutate(actor, 'alex', 'pause', {
            until: 0
        }, token, key);
        result = {
            status: reply.status, id: reply.result.operation.id
        };
    }
    catch (error) {
        result = {
            status: (error as {
                status?: number;
            }).status, code: (error as {
                code?: string;
            }).code
        };
    }
    store.close();
    router.close();
    process.send!(result, () => process.exit(0));
});
process.send!({
    ready: true
});
