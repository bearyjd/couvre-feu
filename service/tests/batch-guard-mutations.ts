/** Manual runner: pinned Node 26.8.1, private TMPDIR and local loopback bind permission are required. */
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

interface Edit { file: string; from: string; to: string; all?: boolean }
interface Mutation { id: string; test: string; edits: Edit[]; http?: boolean }
const batch = 'service/src/admin-children-batch.ts';
const inventory = 'service/src/inventory-store.ts';
const auth = 'service/src/auth.ts';
const edit = (file: string, from: string, to: string, all = false): Edit => ({file, from, to, all});
const b = (from: string, to: string, all = false) => edit(batch, from, to, all);
const guard = (id: string, test: string, ...edits: Edit[]): Mutation => ({id, test, edits});
const canonical = 'batch: canonical ordered items and client key are committed';
const invariants = 'batch: final staged child/device/MAC invariants';
const limits = 'batch: limits accumulate across items';
const idempotency = 'batch: idempotency returns stored success/refusal';
const mutations: Mutation[] = [
    guard('binding-prefix', canonical, b("['child_admin_batch', 1, key, precondition, items]", "['child_admin', 1, key, precondition, items]")),
    guard('binding-order', 'batch binding refuses reorder', b("['child_admin_batch', 1, key, precondition, items]", "['child_admin_batch', 1, key, precondition, [...items].sort((a,b) => a.key.localeCompare(b.key))]")),
    guard('binding-client-key', canonical, b("['child_admin_batch', 1, key, precondition, items]", "['child_admin_batch', 1, '', precondition, items]")),
    guard('challenge-derived', canonical, edit(auth, "challenge: createHash('sha256').update(binding + nonce).digest()", "challenge: createHash('sha256').update(nonce).digest()")),
    guard('max-items', 'HTTP batch: item cap', b('input.items.length > MAX_BATCH_ITEMS', 'false')),
    guard('forbidden-action', 'batch: rejects forbidden_action', b("        if (item.action !== 'child_create' && item.action !== 'child_rename' && item.action !== 'device_add') throw new AppError(400, 'invalid_action');", ''), b("        if (item.action !== 'device_add') throw new AppError(400, 'invalid_action');", '')),
    guard('reference-grammar', 'batch: reference grammar rejects', b('!ID.test(item.target) && !REFERENCE.test(item.target)', 'false')),
    guard('reference-forward', 'batch: options preflight enforces exact shapes', b("referenced >= index || batch.items[referenced]?.action !== 'child_create'", "batch.items[referenced]?.action !== 'child_create'")),
    guard('reference-created-only', 'batch: rejects wrong_ref', b('referenced >= index || !created.has(referenced)', 'referenced >= index'), b("referenced >= index || batch.items[referenced]?.action !== 'child_create'", 'referenced >= index')),
    guard('name-nfc', canonical, b("input.normalize('NFC')", 'input')),
    guard('name-invisible', 'batch: names reject invisible code point', b('/[\\p{Bidi_Control}\\p{Default_Ignorable_Code_Point}]/u.test(input)', 'false')),
    guard('fresh-actor', 'batch: parent role, stale permission', b('const actor = this.auth.commitStepUp(session, proof);', 'this.auth.commitStepUp(session, proof); const actor = session.dto.actor;')),
    guard('admin-role', 'batch: parent role, stale permission', b("if (actor.role !== 'admin') throw new AppError(403, 'admin_required');", '')),
    guard('create-scope', 'batch: parent role, stale permission', b("if (!this.store.get<{scope_all: number}>('SELECT scope_all FROM accounts WHERE id=?', actor.id)?.scope_all)", 'if (false)', true)),
    guard('ready-scope', 'batch ready-only refuses scope', b('!this.policy.fresh() || !this.scope.inRouterScope(mac, this.policy)', '!this.policy.fresh()')),
    guard('ready-observation-age', 'batch: router observation can expire after options', b('!this.policy.fresh() || !this.scope.inRouterScope(mac, this.policy)', '!this.scope.inRouterScope(mac, this.policy)')),
    guard('ready-execute-recheck', 'batch: ready state is rechecked between options', b("            if (!this.ready(item.params.mac)) throw new AppError(409, 'device_not_ready');\n            seen.add", '            seen.add')),
    guard('ready-coverage-age', 'batch ready-only refuses stale_coverage', b('c.observed_at BETWEEN ? AND ?', '(? IS NOT NULL AND ? IS NOT NULL)')),
    guard('ready-poll-age', 'batch ready-only refuses stale_poll', b('s.last_ok_at BETWEEN ? AND ?', '(? IS NOT NULL AND ? IS NOT NULL)')),
    guard('ready-generation', 'batch ready-only refuses wrong_generation', b('d.generation=c.generation AND d.mac=c.mac', 'd.mac=c.mac')),
    guard('ready-address', 'batch ready-only refuses empty_address', b('json_array_length(d.ipv4_json)>0', '1=1'), edit(inventory, 'd.ipv4.length > 0 && ', '')),
    guard('ready-latest-snapshot', 'batch: a complete lease poll refreshes coverage', edit(inventory, "this.store.run('DELETE FROM inventory_coverage');", '', true), edit(inventory, 'INSERT INTO inventory_coverage(generation,mac,observed_at)', 'INSERT OR REPLACE INTO inventory_coverage(generation,mac,observed_at)')),
    guard('ready-failed-poll', 'batch: failed inventory poll invalidates', edit(inventory, "this.state(); this.store.run('DELETE FROM inventory_coverage');", 'this.state();')),
    guard('ready-incomplete-poll', 'batch: incomplete inventory poll invalidates', edit(inventory, "            this.store.run('DELETE FROM inventory_coverage');", '')),
    guard('protected-mac', 'batch: rejects protected_mac', b('this.store.config.protectedMacs.includes(item.params.mac)', 'false', true)),
    guard('duplicate-mac', 'batch: rejects duplicate_mac', b('seen.has(item.params.mac)', 'false')),
    guard('duplicate-key', 'batch: rejects duplicate_key', b('keys.has(item.key)', 'false', true)),
    guard('duplicate-rename', 'batch: duplicate rename of one existing', b('renamed.has(person)', 'false')),
    guard('batch-key-shape', 'batch: options preflight enforces exact shapes', b("typeof key !== 'string' || !CLIENT_KEY.test(key)", 'false')),
    guard('item-key-shape', 'batch: options preflight enforces exact shapes', b("typeof item.key !== 'string' || !CLIENT_KEY.test(item.key)", 'false')),
    guard('limit-children-accumulate', limits, b('++childCount > CHILD_LIMIT', 'childCount > CHILD_LIMIT')),
    guard('limit-per-child-accumulate', limits, b('counts.set(person, (counts.get(person) ?? 0) + 1)', 'counts.set(person, counts.get(person) ?? 0)')),
    guard('limit-system-accumulate', limits, b('deviceCount++;', '')),
    guard('final-child-count', invariants, b('children > CHILD_LIMIT || activeChildren(this.store).length !== children', 'false')),
    guard('final-device-count', invariants, b("devices > DEVICE_LIMIT || this.store.get<{n: number}>('SELECT count(*) n FROM devices')!.n !== devices", 'false')),
    guard('final-per-child-count', invariants, b("count > DEVICES_PER_CHILD || this.store.get<{n: number}>('SELECT count(*) n FROM devices WHERE person_id=?', person)!.n !== count", 'false')),
    guard('final-mac-set', invariants, b('macs.length !== seen.size || new Set(macs).size !== macs.length || macs.some(mac => !seen.has(mac))', 'false')),
    guard('first-run-gate', 'batch: first-run completion refuses later setup', b("if (confirmed) throw new AppError(409, 'batch_setup_completed');", '')),
    guard('first-run-marker', 'batch: first-run completion refuses later setup', b('if (touched.size) this.store.run', 'if (false) this.store.run')),
    guard('first-run-existing-child-marker', 'batch: device-only setup for the existing seed child', b('if (touched.size) this.store.run', 'if (created.size) this.store.run')),
    guard('first-run-pending-devices', 'batch: pending removal and moving rows', b("const confirmed = o.acceptedPolicy.people.some(person => person.macs.some(mac => !(person.id === seed.id && mac === seed.device.mac)));", "const confirmed = this.store.all<{person_id:string;identifier:string}>(\"SELECT person_id,identifier FROM devices WHERE state='active'\").some(d => !(d.person_id===seed.id && d.identifier===seed.device.mac) && o.acceptedPolicy.people.some(p => p.id===d.person_id && p.macs.includes(d.identifier)));")),
    guard('options-rate', 'batch: fourth options issue is rate limited', b('recent.length >= 3', 'false')),
    guard('options-rate-before-proof', 'batch: fourth options issue is rate limited', b('const now = this.policy.now(), recent = (this.attempts.get(actor.id)', 'const earlyChallenge = await this.auth.stepUpChallenge(session, batch.binding, true);\n        const now = this.policy.now(), recent = (this.attempts.get(actor.id)'), b('const challenge = await this.auth.stepUpChallenge(session, batch.binding, true);', 'const challenge = earlyChallenge;')),
    guard('options-rate-reservation', 'batch: concurrent options reserve three actor slots', b('this.attempts.set(actor.id, [...recent, now]);', ''), b('const challenge = await this.auth.stepUpChallenge(session, batch.binding, true);', 'const challenge = await this.auth.stepUpChallenge(session, batch.binding, true); this.attempts.set(actor.id, [...recent, now]);')),
    guard('idempotency-digest', idempotency, b('prior.digest !== batch.binding', 'false', true)),
    guard('idempotency-return-stored', idempotency, b('return JSON.parse(prior.result_json) as Routed;', "return {status:200,body:{results:[]}};")),
    guard('idempotency-no-reapply', idempotency, b('return JSON.parse(prior.result_json) as Routed;', '/* mutation: continue into apply */')),
    guard('idempotency-after-proof-in-transaction', 'batch: idempotency lookup and insertion occur inside', b('            const prior = this.store.get<StoredBatch>', '            const prior = preProofPrior; /* const prior = this.store.get<StoredBatch>'), b("actor.id, batch.clientKey);\n            if (prior)", "actor.id, batch.clientKey); */\n            if (prior)"), b('        const proof = await this.auth.stepUpVerify(session, body.stepUp, batch.binding);', "        const preProofPrior = this.store.get<StoredBatch>('SELECT id,digest,result_json FROM admin_batches WHERE actor_id=? AND client_key=?', session.dto.actor.id, batch.clientKey);\n        const proof = await this.auth.stepUpVerify(session, body.stepUp, batch.binding);")),
    guard('atomic-savepoint', 'batch: item five duplicate rolls back', b("this.store.db.exec('ROLLBACK TO child_batch_work');", '')),
    guard('refusal-persisted', idempotency, b('JSON.stringify(routed), operation, this.policy.now()', "JSON.stringify(routed.status >= 400 ? {status:200,body:{results:[]}} : routed), operation, this.policy.now()")),
    guard('local-no-router-queue', 'batch: local create and rename need no router', b('if (additions.length) {', 'if (additions.length || touched.size) {')),
    guard('one-revision', 'batch: 3 creates and 6 adds', edit('service/src/integration-children.ts', 'revision: base.revision + 1, people, schedules: ownerSchedules({people}, config)}, config.protectedMacs);\n}\n/** Next policy with one MAC removed', 'revision: base.revision + additions.length, people, schedules: ownerSchedules({people}, config)}, config.protectedMacs);\n}\n/** Next policy with one MAC removed')),
    guard('operation-key-independent', 'batch: 3 creates and 6 adds', b('randomUUID(), batch.precondition', 'batch.clientKey, batch.precondition')),
    guard('audit-once-per-child', 'batch: audit stores one row per child', b("now, actor.id, person, op?.id ?? null);", "now, actor.id, person, op?.id ?? null);\n            if (change.devices > 1 && auditFor(this.store).enabled) this.store.run(\"INSERT INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,'device_assign',?,NULL,'applied')\", now, actor.id, person);")),
    guard('general-audit-once-per-child', 'batch: audit stores one row per child', b('for (const [person, change] of touched)', 'for (const [person, change] of [...touched, ...[...touched].filter(([, change]) => change.devices > 1)])')),
    guard('audit-no-local-assignment', 'batch: local creates without devices have no parent', b('change.devices > 0 && auditFor(this.store).enabled', 'auditFor(this.store).enabled')),
    guard('audit-transactional-parent-write', 'batch: audit writes are transactional', b("if (change.devices > 0 && auditFor(this.store).enabled) this.store.run(\"INSERT OR IGNORE INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,'device_assign',?,?,'applied')\", now, actor.id, person, op?.id ?? null);", "try { if (change.devices > 0 && auditFor(this.store).enabled) this.store.run(\"INSERT OR IGNORE INTO parent_audit(at,actor_id,action,person_id,operation_id,result) VALUES(?,?,'device_assign',?,?,'applied')\", now, actor.id, person, op?.id ?? null); } catch {}")),
    guard('worker-own-person', 'batch: worker conflicts settle every device', edit('service/src/integration-worker.ts', 'p.id === row.person_id && p.macs.includes(row.identifier)', 'p.id === op.person_id && p.macs.includes(row.identifier)')),
    guard('rejection-batch-fallback', 'batch: pre-write router rejection removes every', edit('service/src/admin-children.ts', ' ?? request.devices?.find(d => d.person === person && d.mac === mac)?.label', '')),
    guard('retention', 'batch: old idempotency rows expire after 90 days', b('now - BATCH_RETENTION_SECONDS', 'now - BATCH_RETENTION_SECONDS * 100')),
    guard('auth-binding', 'batch binding refuses params', edit(auth, '!equal(row.binding, binding)', 'false')),
    guard('auth-session', 'batch proof isolation: same_account_session', edit(auth, '!equal(row.session_hash, session.hash)', 'false')),
    guard('auth-account', 'batch proof isolation: other_account', edit(auth, 'row.account_id !== session.dto.actor.id', 'false'), edit(auth, '!equal(row.session_hash, session.hash)', 'false')),
    guard('auth-expiry', 'batch proof isolation: expired', edit(auth, 'found.expires_at <= this.now()', 'false')),
    guard('auth-replay', 'batch proof isolation: replay', edit(auth, 'found.consumed', 'false')),
];
for (const mutation of mutations) if (mutation.test.startsWith('HTTP')) mutation.http = true;

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const selectedIds = new Set(process.argv.slice(2));
const selected = selectedIds.size ? mutations.filter(m => selectedIds.has(m.id)) : mutations;
for (const requested of selectedIds) if (!mutations.some(m => m.id === requested)) throw new Error(`Unknown guard: ${requested}`);
const node = process.env.BATCH_NODE ?? process.execPath;
if (spawnSync(node, ['--version'], {encoding: 'utf8'}).stdout.trim() !== 'v26.8.1') throw new Error('Use pinned Node 26.8.1 (or BATCH_NODE).');
const reportDir = resolve(process.env.BATCH_REPORT_DIR ?? join(tmpdir(), 'batch-guard-report'));
mkdirSync(reportDir, {recursive: true, mode: 0o700});
const workspace = process.env.TMPDIR ?? join(repo, '.omc', 'test-tmp');
mkdirSync(workspace, {recursive: true, mode: 0o700});
const root = mkdtempSync(join(workspace, 'batch-mutations-'));
chmodSync(root, 0o700);
const tree = join(root, 'tree'), privateTmp = join(root, 'tmp');
try {
mkdirSync(tree, {mode: 0o700}); mkdirSync(privateTmp, {mode: 0o700});
for (const directory of ['service', 'shared']) cpSync(join(repo, directory), join(tree, directory), {recursive: true});
cpSync(join(repo, 'package.json'), join(tree, 'package.json'));
symlinkSync(realpathSync(join(repo, 'node_modules')), join(tree, 'node_modules'), 'dir');
const originals = new Map<string, string>();
for (const mutation of mutations) for (const change of mutation.edits) if (!originals.has(change.file)) originals.set(change.file, readFileSync(join(tree, change.file), 'utf8'));
const serviceTest = 'service/tests/admin-children-batch.test.ts', httpTest = 'service/tests/admin-children-batch-http.test.ts';
const environment = {...process.env, TMPDIR: privateTmp, NODE_COMPILE_CACHE: join(root, 'compile-cache')};
const run = (test?: string, http = false) => spawnSync(node, ['--test', '--test-isolation=none', '--test-reporter=tap', ...(test ? [`--test-name-pattern=${test}`] : []), http ? httpTest : serviceTest], {cwd: tree, env: environment, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024});
const baseline = run();
writeFileSync(join(reportDir, 'mutations-baseline.tap'), baseline.stdout + baseline.stderr);
if (baseline.status !== 0) throw new Error(`Baseline failed; see ${join(reportDir, 'mutations-baseline.tap')}`);
{
    const httpBaseline = run(undefined, true);
    writeFileSync(join(reportDir, 'mutations-http-baseline.tap'), httpBaseline.stdout + httpBaseline.stderr);
    if (httpBaseline.status !== 0) throw new Error('HTTP baseline failed (local bind requires sandbox permission).');
}
const sourceHash = createHash('sha256');
for (const [file, original] of [...originals].sort(([a], [b]) => a.localeCompare(b))) sourceHash.update(file + '\n' + original);
sourceHash.update(readFileSync(join(tree, serviceTest))).update(readFileSync(join(tree, httpTest)));
const snapshot = sourceHash.digest('hex');
type Result = {id: string; test: string; status: string; log: string; snapshot: string};
let results: Result[] = [];
if (selectedIds.size) {
    try { results = (JSON.parse(readFileSync(join(reportDir, 'mutations.json'), 'utf8')) as {results: Result[]}).results.filter(result => !selectedIds.has(result.id)); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
}
for (const mutation of selected) {
    for (const [file, original] of originals) writeFileSync(join(tree, file), original);
    let malformed: string | undefined;
    for (const change of mutation.edits) {
        const path = join(tree, change.file), before = readFileSync(path, 'utf8');
        if (!before.includes(change.from)) { malformed = `Missing mutation anchor in ${change.file}: ${change.from}`; break; }
        writeFileSync(path, change.all ? before.replaceAll(change.from, change.to) : before.replace(change.from, change.to));
    }
    let status = 'invalid_mutation', output = malformed ?? '';
    if (!malformed) {
        const result = run(mutation.test, mutation.http);
        output = result.stdout + result.stderr;
        const noTest = !/^ok \d+ /m.test(output) && !/^not ok \d+ /m.test(output);
        status = noTest ? 'missing_test' : result.status === 0 ? 'survived' : /ERR_ASSERTION|AssertionError/.test(output) && !/SyntaxError|ERR_MODULE_NOT_FOUND|ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX/.test(output) ? 'killed' : 'non_assertion_failure';
        if (result.error) output += `\nRunner error: ${result.error.message}`;
    }
    const log = `mutation-${mutation.id}.tap`;
    writeFileSync(join(reportDir, log), output);
    results.push({id: mutation.id, test: mutation.test, status, log, snapshot});
    process.stdout.write(`${mutation.id} -> ${mutation.test} -> ${status}\n`);
    // Persist after each result so an interrupted run still leaves usable evidence.
    writeFileSync(join(reportDir, 'mutations.json'), JSON.stringify({node: '26.8.1', source: repo, snapshot, baseline: 'passed', defined: mutations.length, results}, null, 2) + '\n');
}
const killed = results.filter(result => result.status === 'killed').length;
process.stdout.write(`Killed ${killed}/${results.length}; report ${join(reportDir, 'mutations.json')}\n`);
if (killed !== results.length) process.exitCode = 1;
} finally {
    // This is only the fresh generated copy; the working tree is never a mutation target.
    if (process.env.BATCH_KEEP_MUTANTS !== '1') rmSync(root, {recursive: true, force: true});
}
