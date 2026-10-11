import { resolve } from 'node:path';
import { demoConfig } from './config.ts';
import { Store } from './db.ts';
import { seedAccounts } from './fixtures.ts';
import { issueBootstrap } from './auth.ts';
const config = demoConfig();
if (process.argv.length !== 3 || !['jd', 'bryn'].includes(process.argv[2])) {
    throw new Error('Usage: npm run demo:bootstrap -- jd|bryn');
}
const store = new Store(resolve(config.dataDir, 'service.sqlite'));
seedAccounts(store);
try {
    process.stdout.write(`${issueBootstrap(store, process.argv[2])}\n`);
}
finally {
    store.close();
}
