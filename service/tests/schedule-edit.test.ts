import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/db.ts';
import { seedAccounts, INITIAL_POLICY } from '../src/fixtures.ts';
import { PolicyService } from '../src/policy.ts';
import { FakeRouter } from '../../demo-router/src/router.ts';
import { normalizePolicy, policyJSON } from '../../shared/src/router-schema.ts';
import type { Actor } from '../../shared/src/contracts.ts';

const admin: Actor = { id: 'jd', displayName: 'JD', role: 'admin', personIds: ['alex', 'blair'], permissionVersion: '1' };
const parent: Actor = { id: 'bryn', displayName: 'Bryn', role: 'parent', personIds: ['alex'], permissionVersion: '1' };
const bedtime = { id: 'bedtime', weekdays: ['Mon', 'Tue'], start: '22:00', stop: '06:30' };
let counter = 0;
const key = () => `schedule-key-${String(++counter).padStart(12, '0')}`;
function fixture() {
    const dir = mkdtempSync(join(tmpdir(), 'couvre-feu-schedules-')), store = new Store(join(dir, 'service.sqlite'));
    seedAccounts(store);
    let now = 1791691200;
    const router = new FakeRouter(join(dir, 'fake.sqlite'), { now: () => now });
    router.tick();
    const policy = new PolicyService(store, router, () => now);
    const confirm = () => { for (let index = 0; index < 5; index++) { now += 2; router.tick(); policy.reconcile(); } };
    const create = (actor: Actor, person: string, input: unknown = bedtime, token = policy.people(admin).revisionToken!, idempotency = key()) => policy.scheduleMutate(actor, person, 'schedule_create', input, undefined, token, idempotency);
    const seed = (schedules: unknown[]) => {
        const seeded = policyJSON(normalizePolicy({ ...INITIAL_POLICY, schedules }));
        store.run('UPDATE service_state SET desired_json=? WHERE singleton=1', seeded);
        router.store.run('UPDATE fake_state SET policy=? WHERE singleton=1', seeded);
    };
    return { router, store, policy, create, confirm, seed, schedules: (person = 'alex') => policy.people(admin).people.find(p => p.id === person)!.schedules!, close: () => { store.close(); router.close(); rmSync(dir, { recursive: true }); } };
}

test('create, edit and delete go through revision CAS, durable operations and exact router confirmation', () => {
    const f = fixture();
    try {
        assert.deepEqual(f.schedules(), [{ id: 'school_nights', weekdays: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], start: '22:00', stop: '06:30' }]);
        assert.equal(f.policy.people(admin).people[0].schedulesEditable, true);
        const created = f.create(parent, 'alex');
        assert.equal(created.status, 202);
        assert.equal(created.result.operation.action, 'schedule_create');
        assert.equal(created.result.operation.revision, 1);
        f.confirm();
        assert.equal(f.policy.operation(parent, created.result.operation.id).state, 'confirmed');
        assert.deepEqual(f.router.observe().policy.schedules.map(s => s.id), ['bedtime', 'school_nights']);
        assert.deepEqual(f.schedules().find(s => s.id === 'bedtime'), bedtime);

        const edited = f.policy.scheduleMutate(parent, 'alex', 'schedule_update', { weekdays: ['Fri'], start: '23:00', stop: '07:00' }, 'bedtime', f.policy.people(admin).revisionToken!, key());
        assert.equal(edited.result.operation.action, 'schedule_update');
        f.confirm();
        assert.deepEqual(f.schedules().find(s => s.id === 'bedtime'), { id: 'bedtime', weekdays: ['Fri'], start: '23:00', stop: '07:00' });

        const removed = f.policy.scheduleMutate(parent, 'alex', 'schedule_delete', {}, 'bedtime', f.policy.people(admin).revisionToken!, key());
        assert.equal(removed.result.operation.action, 'schedule_delete');
        f.confirm();
        assert.deepEqual(f.router.observe().policy.schedules.map(s => s.id), ['school_nights']);
        assert.equal(f.store.get<{ n: number }>("SELECT count(*) n FROM audit WHERE action LIKE 'schedule_%' AND outcome='confirmed'")!.n, 3);
        assert.equal(f.store.get<{ n: number }>("SELECT count(*) n FROM operations WHERE state='confirmed'")!.n, 3);
        assert.equal(f.policy.people(admin).people[1].schedules?.length, 0, 'other people are untouched');
    } finally { f.close(); }
});
test('invalid input is rejected before any revision is allocated or router write', () => {
    const f = fixture();
    try {
        const token = f.policy.people(admin).revisionToken!;
        for (const [input, code] of [[{ ...bedtime, id: 'Bad Id' }, 'invalid_id'], [{ ...bedtime, weekdays: [] }, 'empty_weekdays'], [{ ...bedtime, stop: '22:00' }, 'empty_schedule'], [{ ...bedtime, start: '99:00' }, 'invalid_clock'], [{ ...bedtime, bonus: true }, 'invalid_fields']] as const) {
            assert.throws(() => f.create(admin, 'alex', input, token), (error: any) => error.status === 400 && error.code === code);
        }
        assert.throws(() => f.create(admin, 'alex', { ...bedtime, id: 'school_nights' }, token), (error: any) => error.status === 409 && error.code === 'schedule_id_exists');
        assert.throws(() => f.policy.scheduleMutate(admin, 'alex', 'schedule_update', { weekdays: ['Mon'], start: '01:00', stop: '02:00' }, 'ghost', token, key()), (error: any) => error.status === 404 && error.code === 'schedule_not_found');
        assert.throws(() => f.policy.scheduleMutate(admin, 'alex', 'schedule_delete', {}, 'ghost', token, key()), (error: any) => error.status === 404);
        assert.throws(() => f.policy.scheduleMutate(admin, 'alex', 'schedule_create', bedtime, undefined, undefined, key()), (error: any) => error.status === 428);
        assert.throws(() => f.policy.scheduleMutate(admin, 'alex', 'schedule_create', bedtime, undefined, token, 'short'), (error: any) => error.status === 400 && error.code === 'idempotency_key_required');
        assert.equal(f.store.get<{ n: number }>('SELECT count(*) n FROM operations')!.n, 0);
        assert.equal(f.router.observe().policy.revision, 0);
    } finally { f.close(); }
});
test('the expanded per-device native window limit is authoritative on the server', () => {
    const f = fixture();
    try {
        f.seed(Array.from({ length: 127 }, (_, index) => ({ person: 'alex', id: `w${index}`, weekdays: ['Mon'], start: '22:00', stop: '06:30' })));
        f.router.tick(); f.confirm();
        const sameDay = f.create(admin, 'alex', { ...bedtime, id: 'daytime', start: '08:00', stop: '15:00' });
        assert.equal(sameDay.status, 202, 'a same-day window needs one native window per device (255 of 256)');
        f.confirm();
        assert.throws(() => f.create(admin, 'alex', bedtime), (error: any) => error.status === 400 && error.code === 'expanded_schedule_limit');
        assert.equal(f.router.observe().policy.schedules.length, 128);
    } finally { f.close(); }
});
test('stale revision, in-flight operation and router-local change conflict without writing', () => {
    const f = fixture();
    try {
        const stale = f.policy.people(admin).revisionToken!;
        f.router.localAdvance();
        assert.throws(() => f.create(admin, 'alex', bedtime, stale), (error: any) => error.status === 409 && error.code === 'revision_conflict');
        assert.equal(f.store.get<{ n: number }>('SELECT count(*) n FROM operations')!.n, 0);
        const first = f.create(admin, 'alex', bedtime, f.policy.people(admin).revisionToken!);
        assert.equal(first.status, 202);
        assert.throws(() => f.create(admin, 'alex', { ...bedtime, id: 'second' }, f.policy.people(admin).revisionToken ?? stale), (error: any) => error.status === 409);
    } finally { f.close(); }
});
test('only assigned people may be edited and idempotent replay returns the same operation', () => {
    const f = fixture();
    try {
        const token = f.policy.people(admin).revisionToken!;
        assert.throws(() => f.create(parent, 'blair', bedtime, token), (error: any) => error.status === 404 && error.code === 'person_not_found');
        assert.throws(() => f.policy.scheduleMutate(parent, 'blair', 'schedule_delete', {}, 'school_nights', token, key()), (error: any) => error.status === 404);
        assert.throws(() => f.create(parent, 'nobody', bedtime, token), (error: any) => error.status === 404);
        assert.equal(f.router.observe().policy.revision, 0);
        const idempotency = key(), first = f.create(parent, 'alex', bedtime, token, idempotency);
        const replay = f.create(parent, 'alex', bedtime, token, idempotency);
        assert.equal(replay.result.operation.id, first.result.operation.id);
        assert.throws(() => f.create(parent, 'alex', { ...bedtime, stop: '07:00' }, token, idempotency), (error: any) => error.status === 409 && error.code === 'idempotency_payload_conflict');
        assert.equal(f.store.get<{ n: number }>('SELECT count(*) n FROM operations')!.n, 1);
        assert.equal(f.policy.people(parent).people.length, 1);
    } finally { f.close(); }
});
