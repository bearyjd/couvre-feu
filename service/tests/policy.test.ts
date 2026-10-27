import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { Store } from '../src/db.ts';
import { seedAccounts } from '../src/fixtures.ts';
import { PolicyService } from '../src/policy.ts';
import { FakeRouter } from '../../demo-router/src/router.ts';
import { healthyConfirmation, normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';
const admin: Actor = {
    id: 'jd', displayName: 'JD', role: 'admin', personIds: ['alex', 'blair'], permissionVersion: '1'
};
const parent: Actor = {
    id: 'bryn', displayName: 'Bryn', role: 'parent', personIds: ['alex'], permissionVersion: '1'
};
function fixture(Router = FakeRouter) {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-policy-')), servicePath = join(dir, 'service.sqlite'), routerPath = join(dir, 'fake.sqlite');
    let now = 1791691200;
    let store = new Store(servicePath);
    seedAccounts(store);
    const router = new Router(routerPath, {
        now: () => now
    });
    router.tick();
    let policy = new PolicyService(store, router, () => now);
    return {
        dir, router, now: () => now, get store() {
            return store;
        }, get policy() {
            return policy;
        }, token: () => policy.people(admin).revisionToken!,
        advance: (seconds: number) => {
            now += seconds;
            router.tick();
        }, restart: () => {
            store.close();
            store = new Store(servicePath);
            policy = new PolicyService(store, router, () => now);
        },
        close: () => {
            store.close();
            router.close();
            rmSync(dir, {
                recursive: true
            });
        }
    };
}
test('202 pending then exact healthy confirmation; pause/timed pause/resume and remaining schedule block', () => {
    const f = fixture();
    try {
        const pause = f.policy.mutate(parent, 'alex', 'pause', {
            until: 0
        }, f.token(), randomUUID());
        assert.equal(pause.status, 202);
        assert.equal(pause.result.operation.state, 'pending');
        f.advance(1);
        f.policy.reconcile();
        const op = f.policy.operation(parent, pause.result.operation.id);
        assert.equal(op.state, 'confirmed');
        const status = f.policy.people(parent);
        assert.deepEqual(status.people.map(p => p.id), ['alex']);
        assert.equal(status.people[0].effectiveManualPause?.until, 0);
        assert.equal(status.people[0].observationHealth, 'healthy');
        const resume = f.policy.mutate(parent, 'alex', 'resume', {}, f.token(), randomUUID());
        f.advance(1);
        f.policy.reconcile();
        assert.equal(f.policy.operation(parent, resume.result.operation.id).state, 'confirmed');
        const resumed = f.policy.people(parent).people[0];
        assert.equal(resumed.manualPause, null);
        assert.equal(resumed.scheduleBlocked, true);
        assert.match(resumed.scheduleExplanation, /Resume clears only/);
        const timed = f.policy.mutate(parent, 'alex', 'pause', {
            until: f.now() + 3
        }, f.token(), randomUUID());
        f.advance(1);
        f.policy.reconcile();
        assert.equal(f.policy.operation(parent, timed.result.operation.id).state, 'confirmed');
        f.advance(4);
        const expired = f.policy.people(parent).people[0];
        assert.equal(expired.effectiveManualPause, null);
        assert.notEqual(expired.manualPause, null);
    }
    finally {
        f.close();
    }
});
for (const fault of ['drift', 'errors', 'coverage', 'stale', 'pending'] as const) {
    test(`matching or stale revision with ${fault} cannot confirm`, () => {
        const f = fixture();
        try {
            f.router.scenario(fault);
            const write = f.policy.mutate(admin, 'alex', 'pause', {
                until: 0
            }, f.token(), randomUUID());
            f.advance(1);
            f.policy.reconcile();
            assert.notEqual(f.policy.operation(admin, write.result.operation.id).state, 'confirmed');
            assert.equal(f.policy.people(admin).people[0].observationHealth, 'unconfirmed');
            if (['drift', 'errors', 'coverage'].includes(fault)) {
                assert.equal(f.router.observe().status.confirmedRevision, write.result.operation.revision);
            }
        }
        finally {
            f.close();
        }
    });
}
test('timeout after possible apply is unknown until exact router observation confirms', () => {
    const f = fixture();
    try {
        f.router.scenario('timeout');
        const write = f.policy.mutate(admin, 'alex', 'pause', {
            until: 0
        }, f.token(), randomUUID());
        assert.equal(write.status, 202);
        assert.equal(write.result.operation.state, 'unknown');
        f.advance(1);
        f.policy.reconcile();
        assert.equal(f.policy.operation(admin, write.result.operation.id).state, 'confirmed');
        assert.equal(f.router.observe().policy.revision, 1);
    }
    finally {
        f.close();
    }
});
test('known failed apply permits a new deliberate action beyond durable and observed high-water', () => {
    const f = fixture();
    try {
        f.router.scenario('failed');
        const failed = f.policy.mutate(admin, 'alex', 'pause', {
            until: 0
        }, f.token(), randomUUID());
        assert.equal(failed.status, 502);
        assert.equal(f.router.observe().policy.revision, 0);
        const next = f.policy.mutate(admin, 'blair', 'pause', {
            until: 0
        }, f.token(), randomUUID());
        assert.equal(next.result.operation.revision, 2);
        f.advance(1);
        f.policy.reconcile();
        assert.equal(f.policy.operation(admin, next.result.operation.id).state, 'confirmed');
    }
    finally {
        f.close();
    }
});
test('idempotency survives restart and expired metadata; changed payload conflicts', () => {
    const f = fixture();
    try {
        const key = randomUUID(), token = f.token(), until = f.now() + 2, write = f.policy.mutate(parent, 'alex', 'pause', {
            until
        }, token, key);
        f.advance(1);
        f.policy.reconcile();
        f.restart();
        f.advance(4);
        const retry = f.policy.mutate(parent, 'alex', 'pause', {
            until
        }, token, key);
        assert.equal(retry.result.operation.id, write.result.operation.id);
        assert.equal(retry.status, 200);
        assert.equal(f.router.observe().policy.pauses[0].until, until);
        assert.deepEqual(f.router.observe().status.effectivePauses, []);
        assert.throws(() => f.policy.mutate(parent, 'alex', 'pause', {
            until: 0
        }, token, key), /idempotency_payload_conflict/);
        assert.equal(f.store.get<{
            n: number;
        }>('SELECT count(*) n FROM operations')!.n, 1);
        assert.throws(() => f.policy.mutate(parent, 'alex', 'pause', {
            until
        }, f.token(), randomUUID()), /pause_expiry_must_be_future/);
    }
    finally {
        f.close();
    }
});
test('historical confirmed duplicate never returns mutation 200 during drift/unreachable/superseded revision', () => {
    const f = fixture();
    try {
        const key = randomUUID(), token = f.token(), write = f.policy.mutate(admin, 'alex', 'pause', {
            until: 0
        }, token, key);
        f.advance(1);
        f.policy.reconcile();
        f.router.localAdvance();
        assert.equal(f.policy.mutate(admin, 'alex', 'pause', {
            until: 0
        }, token, key).status, 202);
        assert.equal(f.policy.operation(admin, write.result.operation.id).state, 'confirmed');
        f.router.scenario('unreachable');
        assert.equal(f.policy.mutate(admin, 'alex', 'pause', {
            until: 0
        }, token, key).status, 202);
        assert.equal(f.policy.people(admin).people[0].observationHealth, 'unreachable');
    }
    finally {
        f.close();
    }
});
test('fresh opaque precondition rejects stale service writes and router-local advances; deliberate refresh preserves router state', () => {
    const f = fixture();
    try {
        const stale = f.token();
        f.router.localAdvance();
        assert.throws(() => f.policy.mutate(parent, 'alex', 'pause', {
            until: 0
        }, stale, randomUUID()), {
            code: 'revision_conflict'
        });
        const next = f.policy.mutate(parent, 'alex', 'pause', {
            until: 0
        }, f.token(), randomUUID());
        assert.equal(next.result.operation.revision, 2);
        const otherStore = new Store(join(f.dir, 'service.sqlite'));
        const other = new PolicyService(otherStore, f.router, f.now);
        try {
            assert.throws(() => other.mutate(admin, 'blair', 'pause', {
                until: 0
            }, stale, randomUUID()), {
                code: 'revision_conflict'
            });
            assert.equal(otherStore.get<{
                n: number;
            }>('SELECT count(*) n FROM operations')!.n, 1);
        }
        finally {
            otherStore.close();
        }
    }
    finally {
        f.close();
    }
});
test('transactional fake base CAS refuses router-local write between observation and application', () => {
    class RacingRouter extends FakeRouter {
        override apply(...args: Parameters<FakeRouter['apply']>) {
            this.localAdvance();
            return super.apply(...args);
        }
    }
    const f = fixture(RacingRouter);
    try {
        const write = f.policy.mutate(admin, 'alex', 'pause', {
            until: 0
        }, f.token(), randomUUID());
        assert.equal(write.status, 409);
        assert.equal(write.result.operation.state, 'conflict');
        assert.deepEqual(f.router.observe().policy.pauses, []);
    }
    finally {
        f.close();
    }
});
test('base CAS catches same revision conflicting policy and equal-revision wrong operation identity', () => {
    const f = fixture();
    try {
        const observed = f.router.observe(), candidate = normalizePolicy({
            ...observed.policy, revision: 1, pauses: [{
                    person: 'alex', until: 0
                }]
        });
        f.router.store.run('UPDATE fake_state SET policy=? WHERE singleton=1', policyJSON(normalizePolicy({
            ...observed.policy, pauses: [{
                    person: 'blair', until: 0
                }]
        })));
        assert.throws(() => f.router.apply(candidate, 'operation_a', {
            revision: 0, policyJSON: policyJSON(observed.policy)
        }), /router_base_conflict/);
        const current = f.router.observe();
        f.router.apply(candidate, 'operation_a', {
            revision: 0, policyJSON: policyJSON(current.policy)
        });
        assert.throws(() => f.router.apply(candidate, 'operation_b', {
            revision: 0, policyJSON: policyJSON(current.policy)
        }), /router_operation_conflict/);
    }
    finally {
        f.close();
    }
});
test('restart with unknown never-applied operation observes before exact expired replay', () => {
    const f = fixture();
    try {
        const original = f.router.apply.bind(f.router);
        f.router.apply = () => {
            throw new Error('interrupted_before_apply');
        };
        const token = f.token(), until = f.now() + 2, write = f.policy.mutate(admin, 'alex', 'pause', {
            until
        }, token, randomUUID());
        assert.equal(write.result.operation.state, 'unknown');
        assert.equal(f.router.observe().policy.revision, 0);
        f.restart();
        f.advance(5);
        const events: string[] = [];
        const observe = f.router.observe.bind(f.router);
        f.router.observe = () => {
            events.push('observe');
            return observe();
        };
        f.router.apply = (...args) => {
            events.push('apply');
            return original(...args);
        };
        f.policy.reconcile();
        assert.equal(events[0], 'observe');
        assert.equal(f.router.observe().policy.pauses[0].until, until);
        f.advance(1);
        f.policy.reconcile();
        assert.equal(f.policy.operation(admin, write.result.operation.id).state, 'confirmed');
        assert.deepEqual(f.router.observe().status.effectivePauses, []);
    }
    finally {
        f.close();
    }
});
test('a delayed healthy observation cannot move the last successful confirmation backwards', () => {
    const f = fixture();
    try {
        f.policy.mutate(admin, 'alex', 'pause', { until: 0 }, f.token(), randomUUID());
        f.advance(1);
        f.policy.reconcile();
        const older = f.router.observe();
        f.advance(1);
        f.policy.reconcile();
        const confirmedAt = f.policy.people(admin).lastSuccessfulConfirmationAt;
        f.router.observe = () => older;
        assert.equal(f.policy.people(admin).lastSuccessfulConfirmationAt, confirmedAt);
    }
    finally {
        f.close();
    }
});
test('independent fake router expires while service is stopped and persisted high-water prevents backward resurrection', () => {
    const f = fixture();
    try {
        const until = f.now() + 2;
        f.policy.mutate(admin, 'alex', 'pause', {
            until
        }, f.token(), randomUUID());
        f.advance(1);
        f.policy.reconcile();
        f.store.close();
        f.advance(5);
        assert.deepEqual(f.router.observe().status.effectivePauses, []);
        const highwater = f.router.observe().routerTime;
        f.advance(-10);
        assert.equal(f.router.observe().routerTime, highwater);
        assert.deepEqual(f.router.observe().status.effectivePauses, []);
        // Reopen only for fixture cleanup; the expiry happened without any service instance.
        f.restart = () => {
        };
    }
    finally {
        f.router.close();
        rmSync(f.dir, {
            recursive: true
        });
    }
});
test('storage failure rolls back operations, desired policy and sanitized audit before router write', () => {
    const f = fixture();
    try {
        f.store.db.exec("CREATE TRIGGER fail_write BEFORE INSERT ON operations BEGIN SELECT RAISE(ABORT,'synthetic_storage_failure'); END");
        assert.throws(() => f.policy.mutate(admin, 'alex', 'pause', {
            until: 0
        }, f.token(), randomUUID()), /synthetic_storage_failure/);
        assert.equal(f.router.observe().policy.revision, 0);
        assert.equal(f.store.get<{
            highwater: number;
        }>('SELECT highwater FROM service_state')!.highwater, 0);
        assert.equal(f.store.get<{
            n: number;
        }>('SELECT count(*) n FROM audit')!.n, 0);
    }
    finally {
        f.close();
    }
});
test('failed migration is transactional and unsupported schema fails closed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-migration-')), path = join(dir, 'db.sqlite');
    try {
        assert.throws(() => new Store(path, 'CREATE TABLE partial(id INTEGER); THIS IS INVALID;'));
        let db = new DatabaseSync(path);
        assert.equal(db.prepare('PRAGMA user_version').get()!.user_version, 0);
        assert.equal(db.prepare("SELECT count(*) n FROM sqlite_master WHERE name='partial'").get()!.n, 0);
        db.exec('PRAGMA user_version=999');
        db.close();
        assert.throws(() => new Store(path), /unsupported_database_version/);
    }
    finally {
        rmSync(dir, {
            recursive: true
        });
    }
});
test('resource scope, role restrictions and malformed/oversized policy controls', () => {
    const f = fixture();
    try {
        assert.throws(() => f.policy.mutate(parent, 'blair', 'pause', {
            until: 0
        }, f.token(), randomUUID()), /person_not_found/);
        assert.throws(() => f.policy.devices(parent), /admin_required/);
        const write = f.policy.mutate(admin, 'blair', 'pause', {
            until: 0
        }, f.token(), randomUUID());
        assert.throws(() => f.policy.operation(parent, write.result.operation.id), /operation_not_found/);
        for (const body of [{
                until: -1
            }, {
                until: 2147483648
            }, {
                until: 0, role: 'admin'
            }, {
                until: '0'
            }]) {
            assert.throws(() => f.policy.mutate(parent, 'alex', 'pause', body, f.token(), randomUUID()));
        }
    }
    finally {
        f.close();
    }
});
test('stale independent engine heartbeat yields unknown and cannot fabricate fresh status', () => {
    const f = fixture();
    try {
        const old = f.policy.people(admin).observedAt;
        const engineNow = f.router.now;
        Object.defineProperty(f.router, 'now', {
            value: () => engineNow() + 10
        });
        f.router.tick();
        const status = f.policy.people(admin);
        assert.equal(status.observedAt, old);
        assert.equal(status.revisionToken, null);
        assert.equal(status.people[0].observationHealth, 'unreachable');
    }
    finally {
        f.close();
    }
});
test('false IPv6, conntrack/native witness, or mismatched observed sets cannot confirm dual-family demo', () => {
    const f = fixture();
    try {
        const { policy, status, routerTime } = f.router.observe();
        assert.equal(healthyConfirmation(status, policy, routerTime), true);
        for (const flag of ['ipv6', 'conntrack', 'nativeKernelConfirmed', 'addressCoverageComplete'] as const) {
            assert.equal(healthyConfirmation({
                ...status, capabilities: {
                    ...status.capabilities, [flag]: false
                }
            }, policy, routerTime), false);
        }
        assert.equal(healthyConfirmation({
            ...status, observed: {
                ...status.observed, kids: []
            }
        }, policy, routerTime), false);
    }
    finally {
        f.close();
    }
});
test('two concurrent service processes serialize revisions and duplicate idempotency in durable SQLite', async () => {
    for (const duplicate of [false, true]) {
        const f = fixture(), token = f.token(), key = randomUUID(), children = [0, 1].map(index => fork(fileURLToPath(new URL('./fixtures/writer.ts', import.meta.url)), [f.dir, token, duplicate ? key : randomUUID()], {
            stdio: ['ignore', 'ignore', 'pipe', 'ipc']
        }));
        try {
            await Promise.all(children.map(child => once(child, 'message')));
            const replies = children.map(child => once(child, 'message'));
            children.forEach(child => child.send({
                go: true
            }));
            const results = (await Promise.all(replies)).map(([value]) => value as {
                status: number;
                id?: string;
            });
            assert.equal(f.store.get<{
                n: number;
            }>('SELECT count(*) n FROM operations')!.n, 1);
            if (duplicate) {
                assert.deepEqual(results.map(r => r.status), [202, 202]);
                assert.equal(results[0].id, results[1].id);
            }
            else {
                assert.deepEqual(results.map(r => r.status).sort(), [202, 409]);
            }
            await Promise.all(children.map(child => child.exitCode === null ? once(child, 'exit') : Promise.resolve()));
        }
        finally {
            for (const child of children) {
                if (child.exitCode === null) {
                    child.kill();
                }
            }
            f.close();
        }
    }
});
test('SIGKILL after SQLite acceptance preserves pending operation, exact payload and idempotency without clean shutdown', async () => {
    const f = fixture();
    const token = f.token(), key = randomUUID(), until = f.now() + 2;
    const child = fork(fileURLToPath(new URL('./fixtures/crash-writer.ts', import.meta.url)), [f.dir, token, key, String(until)], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    try {
        const [message] = await once(child, 'message');
        child.kill('SIGKILL');
        await once(child, 'exit');
        f.restart();
        assert.equal(f.store.get<{ journal_mode: string }>('PRAGMA journal_mode')!.journal_mode, 'wal');
        assert.equal(f.store.get<{ synchronous: number }>('PRAGMA synchronous')!.synchronous, 2);
        assert.equal(f.store.get<{ n: number }>('SELECT count(*) n FROM operations')!.n, 1);
        assert.equal(f.router.observe().policy.revision, 0);
        f.advance(5);
        f.policy.reconcile();
        f.advance(1);
        f.policy.reconcile();
        const retry = f.policy.mutate(admin, 'alex', 'pause', { until }, token, key);
        assert.equal(retry.result.operation.id, (message as { id: string }).id);
        assert.equal(retry.status, 200);
        assert.deepEqual(f.router.observe().status.effectivePauses, []);
        assert.equal(f.router.observe().policy.pauses[0].until, until);
    } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill();
        f.close();
    }
});
test('stale reconciliation snapshot cannot demote a terminal confirmation from another SQLite connection', () => {
    const f = fixture(), secondStore = new Store(join(f.dir, 'service.sqlite'));
    const second = new PolicyService(secondStore, f.router, f.now);
    try {
        const write = f.policy.mutate(admin, 'alex', 'pause', { until: 0 }, f.token(), randomUUID());
        const original = f.store.all.bind(f.store);
        let interleaved = false;
        f.store.all = <T>(sql: string, ...args: (string | number | null | Uint8Array)[]): T[] => {
            const rows = original<T>(sql, ...args);
            if (!interleaved && sql.includes("SELECT * FROM operations WHERE state IN")) {
                interleaved = true;
                f.advance(1); second.reconcile();
                assert.equal(second.operation(admin, write.result.operation.id).state, 'confirmed');
            }
            return rows;
        };
        f.policy.reconcile();
        const historical = second.operation(admin, write.result.operation.id);
        assert.equal(interleaved, true);
        assert.equal(historical.state, 'confirmed');
        assert.equal(historical.confirmedAt, f.now());
        assert.equal(f.store.get<{ n: number }>("SELECT count(*) n FROM audit WHERE outcome='confirmed'")!.n, 1);
    } finally { secondStore.close(); f.close(); }
});
test('cross-process reconciliation cannot automatically reapply after another process commits terminal failure', async () => {
    const f = fixture(), original = f.router.apply.bind(f.router);
    f.router.apply = () => { throw new Error('fixture_not_applied_yet'); };
    const accepted = f.policy.mutate(admin, 'alex', 'pause', { until: 0 }, f.token(), randomUUID());
    f.router.apply = original; f.router.scenario('failed');
    const children = [0, 1].map(() => fork(fileURLToPath(new URL('./fixtures/reconciler.ts', import.meta.url)), [f.dir, accepted.result.operation.id], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] }));
    try {
        await Promise.all(children.map(child => once(child, 'message')));
        const replies = children.map(child => once(child, 'message'));
        children.forEach(child => child.send({ go: true }));
        const result = (await Promise.all(replies)).map(([row]) => row as { state: string });
        assert.deepEqual(result.map(row => row.state), ['failed', 'failed']);
        assert.equal(f.router.observe().policy.revision, 0);
        assert.equal(f.store.get<{ n: number }>("SELECT count(*) n FROM audit WHERE outcome='failed'")!.n, 1);
        f.policy.reconcile(); assert.equal(f.router.observe().policy.revision, 0);
        await Promise.all(children.map(child => child.exitCode === null ? once(child, 'exit') : Promise.resolve()));
    } finally { for (const child of children) if (child.exitCode === null) child.kill(); f.close(); }
});
test('migrations 002-005 preserve policy/accounts and revokes legacy sessions/challenges before listening', () => {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-upgrade-')), path = join(dir, 'service.sqlite');
    const legacy = new Store(path, readFileSync(fileURLToPath(new URL('../migrations/001.sql', import.meta.url)), 'utf8'));
    try {
        seedAccounts(legacy);
        legacy.run('INSERT INTO sessions(hash,account_id,csrf,permission_version,expires_at) VALUES(?,?,?,1,?)', 'legacy_hash', 'jd', 'legacy_csrf', 1791694800);
        legacy.run("INSERT INTO challenges(id,challenge,kind,credential_ids,browser_hash,expires_at) VALUES(?,?,'login',?,?,?)", 'legacy_challenge', 'challenge', '{}', 'legacy_browser', 1791691320);
        legacy.close();
        const upgraded = new Store(path);
        try {
            assert.equal(upgraded.get<{ user_version: number }>('PRAGMA user_version')!.user_version, 10);
            assert.equal(upgraded.get<{ n: number }>('SELECT count(*) n FROM activity_samples')!.n, 0);
            assert.equal(upgraded.get<{ revoked: number }>('SELECT revoked FROM sessions')!.revoked, 1);
            assert.equal(upgraded.get<{ n: number }>('SELECT count(*) n FROM challenges')!.n, 0);
            assert.equal(upgraded.get<{ n: number }>('SELECT count(*) n FROM accounts')!.n, 2);
            assert.equal(upgraded.get<{ highwater: number }>('SELECT highwater FROM service_state')!.highwater, 0);
        } finally { upgraded.close(); }
    } finally { rmSync(dir, { recursive: true }); }
});
test('an incompatible database shape with a current version fails closed before listening', () => {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-schema-version-')), path = join(dir, 'service.sqlite');
    try {
        const db = new DatabaseSync(path); db.exec('PRAGMA user_version=4; CREATE TABLE accounts(id TEXT);'); db.close();
        assert.throws(() => new Store(path), /unsupported_database_schema/);
    } finally { rmSync(dir, { recursive: true }); }
});
test('creating a fake client without its independent engine cannot fabricate a fresh heartbeat or confirmation', () => {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-no-engine-')), store = new Store(join(dir, 'service.sqlite'));
    seedAccounts(store); const router = new FakeRouter(join(dir, 'fake.sqlite'));
    try {
        const observation = router.observe(); assert.equal(observation.routerTime, 0); assert.equal(observation.status.confirmedRevision, null);
        const policy = new PolicyService(store, router); const people = policy.people(admin);
        assert.equal(people.revisionToken, null); assert.equal(people.people[0].observationHealth, 'unreachable');
    } finally { store.close(); router.close(); rmSync(dir, { recursive: true }); }
});


test('demo enrollment evidence stays assigned, has no receipt clock, and a failed read retains only unknown history', () => {
    const f = fixture();
    try {
        const first = f.policy.people(parent);
        assert.deepEqual(first.people.map(person => person.id), ['alex']);
        const e = first.people[0].devices[0].evidence!;
        assert.equal(e.source, 'synthetic-policy'); assert.equal(e.serviceReceivedAt, null); assert.equal(e.enrollment, 'included');
        f.router.scenario('unreachable');
        const failed = f.policy.people(parent).people[0].devices[0].evidence!;
        assert.equal(failed.enrollment, 'unknown'); assert.equal(failed.sourceObservedAt, e.sourceObservedAt);
        assert.deepEqual(f.policy.people({...parent, personIds: []}).people, []);
    } finally {f.close();}
});
for (const minutes of [15, 30, 60]) {
    test(`quick ${minutes}-minute pause preset is a bounded timed pause that End now removes, and parent scope is unchanged`, () => {
        const f = fixture();
        try {
            const until = f.now() + minutes * 60;
            const pause = f.policy.mutate(parent, 'alex', 'pause', {
                until
            }, f.token(), randomUUID());
            assert.equal(pause.status, 202);
            f.advance(1);
            f.policy.reconcile();
            assert.equal(f.policy.operation(parent, pause.result.operation.id).state, 'confirmed');
            const active = f.policy.people(parent).people[0];
            assert.equal(active.effectiveManualPause?.until, until);
            assert.equal(f.router.observe().status.effectivePauses.length, 1);
            // A parent cannot target an unassigned child with a preset.
            assert.throws(() => f.policy.mutate(parent, 'blair', 'pause', {
                until
            }, f.token(), randomUUID()));
            const end = f.policy.mutate(parent, 'alex', 'resume', {}, f.token(), randomUUID());
            f.advance(1);
            f.policy.reconcile();
            assert.equal(f.policy.operation(parent, end.result.operation.id).state, 'confirmed');
            const ended = f.policy.people(parent).people[0];
            assert.equal(ended.effectiveManualPause, null);
            assert.equal(f.router.observe().status.effectivePauses.length, 0);
            // End now clears only the manual pause; the active schedule block remains.
            assert.equal(ended.scheduleBlocked, true);
            assert.match(ended.scheduleExplanation, /Resume clears only/);
        }
        finally {
            f.close();
        }
    });
}
