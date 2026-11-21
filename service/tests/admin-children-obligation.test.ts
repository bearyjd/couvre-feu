import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { integrationFixture } from './fixtures/integration.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { ChildAdmin } from '../src/admin-children.ts';
import type { ChildAction } from '../src/admin-children.ts';
import { TestAuthenticator } from './authenticator.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';

/**
 * Whether removing or moving a device takes a child's last router-held MAC is decided from the fresh accepted router policy,
 * never from local device rows: a stale local row the router does not hold must not let an open time request lose its device.
 */
const SEED = '02:10:20:30:40:50', K2 = '02:10:20:30:40:62', K3 = '02:10:20:30:40:63', K4 = '02:10:20:30:40:64';
const origin = 'http://localhost:4273';
const ALL = ['kid2', 'kid3', 'pilot'];
const code = (expected: string) => (error: {code?: string}) => error.code === expected;

/** kid2 holds K2 on the router; `extra` adds a second local kid2 row for K4, on the router too when `routerHoldsExtra`. */
function world(opts: {audit: boolean; extra: boolean; routerHoldsExtra: boolean}) {
    const f = integrationFixture();
    f.config.auditLog = {enabled: opts.audit};
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
    const admin = new ChildAdmin(auth, f.policy), created = f.now();
    const add = (id: string, person: string, mac: string) => f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',?)", id, person, `Device ${id}`, mac, created);
    for (const id of ['kid2', 'kid3']) f.store.run("INSERT INTO people(id,name,kind,active,created_at) VALUES(?,?,'child',1,?)", id, `Kid ${id}`, created);
    add('d_kid2', 'kid2', K2); add('d_kid3', 'kid3', K3);
    if (opts.extra) add('d_kid2b', 'kid2', K4);
    f.store.run('UPDATE accounts SET person_ids=? WHERE id=?', JSON.stringify(ALL), 'operator');
    f.router.policy = normalizePolicy({version: 1, revision: 1, pauses: [], schedules: [],
        people: [{id: 'pilot', macs: [SEED]}, {id: 'kid2', macs: opts.routerHoldsExtra ? [K2, K4] : [K2]}, {id: 'kid3', macs: [K3]}]}, f.config.protectedMacs);
    // The router's own revision token: the overview withholds it while a local row is not on the router, but an admin can still send one.
    const token = () => (f.policy as unknown as {token(): string | null}).token()!;
    async function signIn() {
        const key = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
        const options = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, 'operator', f.now())}, browser);
        const result = await auth.registrationVerify({challengeId: options.challengeId, response: key.register(options.options, origin)}, browser);
        return {key, session: () => auth.session(result.token, browser)};
    }
    type Who = Awaited<ReturnType<typeof signIn>>;
    async function change(who: Who, kind: ChildAction, device: string, params: Record<string, unknown>) {
        const p = {precondition: token(), ...params};
        const options = await admin.stepUpOptions(who.session(), {action: kind, target: device, params: p});
        return admin.perform(who.session(), kind, device, {...p, stepUp: {challengeId: options.challengeId, response: who.key.login(options.options, origin)}}) as Promise<{status: number; body: Record<string, any>}>;
    }
    const pending = () => {
        f.store.run("INSERT INTO request_links(id,person_id,token_hash,created_by,created_at) VALUES('l1','kid2',?,'operator',?)", 'h'.repeat(64), f.now());
        f.store.run("INSERT INTO time_requests(id,link_id,person_id,minutes,reason,state,created_at,expires_at) VALUES('tr1','l1','kid2',15,'homework','pending',?,?)", f.now(), f.now() + 600);
    };
    const ops = () => f.store.get<{n: number}>('SELECT count(*) n FROM operations')!.n;
    return {...f, signIn, pending, ops,
        remove: (who: Who, device: string) => change(who, 'device_remove', device, {}),
        move: (who: Who, device: string, to: string) => change(who, 'device_move', device, {to})};
}

for (const audit of [false, true]) {
    const flag = `audit log ${audit ? 'on' : 'off'}`;

    test(`${flag}: a stale local row the router does not hold does not let the last router-held MAC be removed while a request is open`, async () => {
        const f = world({audit, extra: true, routerHoldsExtra: false});
        try {
            const op = await f.signIn(); await f.observe(); f.pending();
            await assert.rejects(f.remove(op, 'd_kid2'), code('child_has_pending_requests'));
            assert.equal(f.ops(), 0);
            assert.equal(f.store.get<{state: string}>("SELECT state FROM devices WHERE id='d_kid2'")!.state, 'active');
        } finally { f.cleanup(); }
    });

    test(`${flag}: a stale local row the router does not hold does not let the last router-held MAC be moved while a request is open`, async () => {
        const f = world({audit, extra: true, routerHoldsExtra: false});
        try {
            const op = await f.signIn(); await f.observe(); f.pending();
            await assert.rejects(f.move(op, 'd_kid2', 'kid3'), code('child_has_pending_requests'));
            assert.equal(f.ops(), 0);
            assert.deepEqual({...f.store.get("SELECT person_id,state,move_to FROM devices WHERE id='d_kid2'")!}, {person_id: 'kid2', state: 'active', move_to: null});
        } finally { f.cleanup(); }
    });

    test(`${flag}: the stale row itself is still dropped locally, and rows that agree with the router keep their behaviour`, async () => {
        const stale = world({audit, extra: true, routerHoldsExtra: false});
        try {
            const op = await stale.signIn(); await stale.observe(); stale.pending();
            const r = await stale.remove(op, 'd_kid2b');
            assert.equal(r.status, 200); assert.equal(r.body.routerChange, false);
        } finally { stale.cleanup(); }
        // Two router-held MACs: either may go while a request is open, by removal or by move.
        for (const kind of ['remove', 'move'] as const) {
            const f = world({audit, extra: true, routerHoldsExtra: true});
            try {
                const op = await f.signIn(); await f.observe(); f.pending();
                const r = kind === 'remove' ? await f.remove(op, 'd_kid2') : await f.move(op, 'd_kid2', 'kid3');
                assert.equal(r.status, 202, kind);
            } finally { f.cleanup(); }
        }
        // One device on both sides: refused with an open request, allowed without one.
        for (const open of [true, false]) for (const kind of ['remove', 'move'] as const) {
            const f = world({audit, extra: false, routerHoldsExtra: false});
            try {
                const op = await f.signIn(); await f.observe(); if (open) f.pending();
                const attempt = kind === 'remove' ? f.remove(op, 'd_kid2') : f.move(op, 'd_kid2', 'kid3');
                if (open) await assert.rejects(attempt, code('child_has_pending_requests'));
                else assert.equal((await attempt).status, 202, kind);
            } finally { f.cleanup(); }
        }
    });
}
