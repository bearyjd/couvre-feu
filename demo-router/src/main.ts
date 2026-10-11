import { resolve } from 'node:path';
import { demoConfig } from '../../service/src/config.ts';
import { FakeRouter } from './router.ts';
const router = new FakeRouter(resolve(demoConfig().dataDir, 'fake-router.sqlite'));
router.tick();
const timer = setInterval(() => {
    try {
        router.tick();
    }
    catch {
        process.stderr.write('synthetic_router_tick_failed\n');
    }
}, 100);
process.stdout.write('Fictional fake-router engine running; no network transport or real router.\n');
function stop() {
    clearInterval(timer);
    router.close();
    process.exit(0);
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
