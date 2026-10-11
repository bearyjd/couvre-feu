import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { parseJSON } from '../../shared/src/json.ts';
import { integrationConfig, requirePrivatePath } from './integration-config.ts';
import { IntegrationStore } from './integration-db.ts';
import { IntegrationWorker } from './integration-worker.ts';
import { SSHRouter } from './ssh-router.ts';
import type { DispatchKind } from './router-transport.ts';
import type { PreparedDispatch } from './integration-worker.ts';

const [command, manifestPath, planPath, argument, operationId] = process.argv.slice(2);
if (!['prepare', 'execute', 'stop'].includes(command) || !manifestPath) throw new Error('usage_integration_dispatch_prepare_execute_stop');
const config = integrationConfig(manifestPath), store = new IntegrationStore(config);
try {
    if (command === 'stop') {
        if (process.argv.length !== 4) throw new Error('usage_stop_manifest');
        store.stopDispatch(); process.stdout.write('Dispatch revoked locally. This does not prove remote drain or authorize router rollback.\n');
    } else {
        if (!planPath || !isAbsolute(planPath) || resolve(planPath) !== planPath) throw new Error('absolute_private_permit_path_required');
        requirePrivatePath(dirname(planPath), 'directory');
        const worker = new IntegrationWorker(store, new SSHRouter(config));
        if (command === 'prepare') {
            if (!['observe', 'apply', 'receipt'].includes(argument) || process.argv.length !== (argument === 'observe' ? 6 : 7)) throw new Error('usage_prepare_manifest_permit_kind_operation');
            const plan = worker.prepare(argument as DispatchKind, operationId);
            writeFileSync(planPath, JSON.stringify(plan, null, 2) + '\n', {mode: 0o600, flag: 'wx'});
            process.stdout.write(`Prepared one invocation; no SSH executed. Review private permit script. SHA256 ${plan.scriptSha256}\n`);
        } else {
            if (process.argv.length !== 6) throw new Error('usage_execute_manifest_permit_exact_sha256');
            requirePrivatePath(planPath, 'file');
            const plan = parseJSON(readFileSync(planPath, 'utf8'), false, 262144) as PreparedDispatch;
            await worker.execute(plan, argument);
            process.stdout.write('Single-use invocation consumed. Read cached operation/status for its witnessed outcome; no retry was scheduled.\n');
        }
    }
} finally { store.close(); }
