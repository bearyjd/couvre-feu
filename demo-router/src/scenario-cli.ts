import { resolve } from 'node:path';
import { demoConfig } from '../../service/src/config.ts';
import { FakeRouter, SCENARIOS } from './router.ts';
import type { Scenario } from './router.ts';
const command = process.argv[2];
if (process.argv.length !== 3 || (!SCENARIOS.includes(command as Scenario) && command !== 'local-advance' && command !== 'status')) {
    throw new Error('Usage: demo:scenario -- healthy|pending|drift|errors|coverage|stale|unreachable|failed|timeout|local-advance|status');
}
const router = new FakeRouter(resolve(demoConfig().dataDir, 'fake-router.sqlite'));
try {
    if (command === 'status') {
        process.stdout.write(`${JSON.stringify(router.observe())}\n`);
    }
    else if (command === 'local-advance') {
        process.stdout.write(`Fictional router-local revision: ${router.localAdvance()}\n`);
    }
    else {
        router.scenario(command as Scenario);
        process.stdout.write(`Next fictional scenario: ${command}\n`);
    }
}
finally {
    router.close();
}
