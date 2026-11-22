import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { AppError } from '../../shared/src/errors.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { Auth, issueOperatorBootstrap } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { scheduleAllowance } from '../src/integration-schedule-allowance.ts';
import { TestAuthenticator } from './authenticator.ts';
import { freePort } from './free-port.ts';
import { actor } from './fixtures/integration.ts';
import { apply, at, edit, freshKey, op, operations, token, world } from './fixtures/schedule-settle.ts';
import type { Window, World } from './fixtures/schedule-settle.ts';

const sunday = (id: string, start: string, stop: string): Window => ({id, weekdays: ['Sun'], start, stop});
const active = sunday('bedtime', '04:00', '06:00');
const extra = 'schedule_extra_time', skip = 'schedule_skip_tonight';
const code = (expected: string) => (error: unknown) => error instanceof AppError && error.code === expected;
const policyOf = (f: World, id: string) => JSON.parse(op(f, id).payload_json) as RouterPolicy;
const untilOf = (f: World, id: string) => policyOf(f, id).allowances?.find(a => a.person === 'pilot')?.until;

function reviewedClock(f: World, timezone = 'UTC', utcOffsetMinutes = 0) {
    f.config.scheduleClock = {timezone, conformance: {utcOffsetMinutes, verifiedAt: f.now() - 120, validUntil: f.now() + 86400, evidenceSha256: 'e'.repeat(64)}};
}

async function allowanceWorld(windows = [active], base: Partial<RouterPolicy> = {}, peer = false) {
    const f = world(true, {pilotWindows: windows, peer});
    reviewedClock(f);
    f.router.policy = normalizePolicy({...f.router.policy, ...base});
    await f.observe();
    return f;
}

const request = (f: World, action: typeof extra | typeof skip, input: unknown = {}, pre = token(f), key = freshKey()) =>
    scheduleAllowance(f.policy, actor, 'pilot', action, input, pre, key);

test('Extra time uses observed router time, adds to an allowance, and changes only the requested allowance', async () => {
    const f = await allowanceWorld([active], {}, true);
    try {
        f.config.dnsHardening = {dohList: true};
        const baseline = f.router.policy, until = f.now() + 20 * 60;
        f.router.policy = normalizePolicy({...baseline, allowances: [...baseline.allowances!, {person: 'pilot', until}]});
        f.router.transform = observation => ({...observation, routerTime: observation.routerTime - 23});
        f.advance(35); await f.observe();
        const base = f.router.policy, out = request(f, extra, {minutes: 30}), id = out.result.operation.id;
        assert.equal(out.status, 202);
        assert.equal(out.result.operation.action, 'allow');
        assert.deepEqual(policyOf(f, id), normalizePolicy({...base, revision: base.revision + 1,
            allowances: [...base.allowances!.filter(a => a.person !== 'pilot'), {person: 'pilot', until: until + 1800}]}));
        assert.equal(f.writes(), 0);
    } finally { f.cleanup(); }
});

test('Extra time admits 15, 30, and 60 minutes, and computes the cap from router time', async () => {
    for (const minutes of [15, 30, 60]) {
        const f = await allowanceWorld();
        try {
            f.advance(25);
            f.router.transform = observation => ({...observation, routerTime: observation.routerTime - 25});
            await f.observe();
            const id = request(f, extra, {minutes}).result.operation.id;
            assert.equal(untilOf(f, id), f.now() - 25 + minutes * 60);
        } finally { f.cleanup(); }
    }
    const f = await allowanceWorld();
    try {
        f.advance(5);
        f.router.policy = normalizePolicy({...f.router.policy, allowances: [{person: 'pilot', until: f.now() + 45 * 60 + 1}]});
        await f.observe();
        assert.throws(() => request(f, extra, {minutes: 15}), code('schedule_allowance_cap_exceeded'));
        assert.throws(() => request(f, extra, {minutes: 45}), code('invalid_minutes'));
        assert.equal(operations(f), 0);
        f.advance(1); await f.observe();
        const result = request(f, extra, {minutes: 15});
        assert.equal(untilOf(f, result.result.operation.id), f.now() + 3600);
    } finally { f.cleanup(); }
});

test('Skip tonight ends at the last currently active window across midnight, with seconds respected', async () => {
    const cross: Window = {id: 'night', weekdays: ['Sat'], start: '23:30', stop: '00:20'};
    const f = await allowanceWorld([cross, sunday('morning', '00:00', '00:35'), sunday('later', '00:36', '02:00')]);
    try {
        at(f, Date.parse('2026-10-11T00:05:47Z') / 1000);
        reviewedClock(f); await f.observe();
        const result = request(f, skip);
        assert.equal(untilOf(f, result.result.operation.id), Date.parse('2026-10-11T00:35:00Z') / 1000);
    } finally { f.cleanup(); }
});

test('Skip tonight caps at one hour, preserves a longer allowance, and expires on the router', async () => {
    for (const existing of [0, 3000]) {
        const f = await allowanceWorld([existing ? sunday('bedtime', '04:00', '04:30') : active]);
        try {
            if (existing) {
                f.advance(5);
                f.router.policy = normalizePolicy({...f.router.policy, allowances: [{person: 'pilot', until: f.now() + existing}]});
                await f.observe();
            }
            const id = request(f, skip).result.operation.id, until = f.now() + (existing || 3600);
            assert.equal(untilOf(f, id), until);
            assert.equal(f.policy.people(actor).people[0].allowance?.until ?? null, existing ? until : null);
            await apply(f, id);
            assert.equal(f.policy.people(actor).people[0].allowance?.until, until);
            assert.equal(f.policy.people(actor).people[0].scheduleBlocked, false);
            at(f, until); await f.observe();
            assert.equal(f.policy.people(actor).people[0].allowance, null);
            assert.equal(f.policy.people(actor).people[0].scheduleBlocked, !existing);
        } finally { f.cleanup(); }
    }
});

test('Skip tonight refuses an allowance that is already beyond the cap without shortening it', async () => {
    const f = await allowanceWorld();
    try {
        f.advance(5);
        f.router.policy = normalizePolicy({...f.router.policy, allowances: [{person: 'pilot', until: f.now() + 4200}]});
        await f.observe();
        assert.throws(() => request(f, skip), code('schedule_allowance_cap_exceeded'));
        assert.equal(operations(f), 0);
        assert.equal(f.policy.people(actor).people[0].allowance?.until, f.now() + 4200);
    } finally { f.cleanup(); }
});

test('Inactive schedules, unverified clocks and a skip across an unverified offset change fail closed', async () => {
    const f = await allowanceWorld([sunday('later', '05:00', '06:00')]);
    try {
        assert.throws(() => request(f, extra, {minutes: 15}), code('schedule_not_active'));
        assert.throws(() => request(f, skip), code('schedule_not_active'));
        f.config.scheduleClock = {timezone: 'UTC'};
        assert.throws(() => request(f, skip), code('schedule_clock_unverified'));
        assert.equal(operations(f), 0);
    } finally { f.cleanup(); }
    const dst = await allowanceWorld([sunday('bedtime', '01:00', '03:00')]);
    try {
        at(dst, Date.parse('2026-11-01T05:30:00Z') / 1000);
        reviewedClock(dst, 'America/New_York', -240); await dst.observe();
        assert.throws(() => request(dst, skip), code('schedule_clock_unverified'));
        assert.equal(operations(dst), 0);
        at(dst, Date.parse('2026-11-01T01:30:00Z') / 1000);
        reviewedClock(dst);
        dst.config.scheduleClock!.conformance!.validUntil = dst.now() + 600;
        await dst.observe();
        assert.throws(() => request(dst, skip), code('schedule_clock_unverified'));
    } finally { dst.cleanup(); }
});

test('Manual Pause clears a schedule allowance and prevents another from lifting the pause', async () => {
    const f = await allowanceWorld();
    try {
        await apply(f, request(f, extra, {minutes: 15}).result.operation.id);
        await apply(f, f.pause().result.operation.id);
        assert.equal(f.policy.people(actor).people[0].allowance, null);
        assert.equal(f.policy.people(actor).people[0].effectiveManualPause?.until, 0);
        assert.throws(() => request(f, extra, {minutes: 15}), code('child_paused'));
        assert.throws(() => request(f, skip), code('child_paused'));
        assert.equal(operations(f), 2);
    } finally { f.cleanup(); }
});

test('Replays retain their original intent and deadline, and CAS or authorization refuses other writes', async () => {
    const f = await allowanceWorld([active], {}, true);
    try {
        f.config.auditLog = {enabled: true};
        const pre = token(f), key = freshKey();
        const first = request(f, extra, {minutes: 15}, pre, key).result.operation.id;
        assert.throws(() => request(f, skip, {}, pre, key), code('idempotency_payload_conflict'));
        assert.throws(() => request(f, extra, {minutes: 30}, pre, key), code('idempotency_payload_conflict'));
        assert.throws(() => request(f, skip, {}, pre), code('revision_conflict'));
        assert.throws(() => scheduleAllowance(f.policy, {...actor, permissionVersion: '2'}, 'pilot', extra, {minutes: 15}, pre, key), code('idempotency_payload_conflict'));
        assert.throws(() => scheduleAllowance(f.policy, {...actor, personIds: []}, 'pilot', extra, {minutes: 15}, pre, key), code('person_not_found'));
        assert.throws(() => scheduleAllowance(f.policy, actor, 'peer', skip, {}, pre, key), code('person_not_found'));
        await apply(f, first);
        f.advance(15 * 60); await f.observe();
        assert.equal(request(f, extra, {minutes: 15}, pre, key).result.operation.id, first);
        assert.equal(operations(f), 1);
        assert.deepEqual(f.store.all('SELECT action FROM parent_audit WHERE operation_id IS NOT NULL').map(row => ({...row as {action: string}})), [{action: extra}]);
    } finally { f.cleanup(); }
});

test('A schedule edit makes an older allowance token stale and holds the write slot against a current token', async () => {
    const f = await allowanceWorld();
    try {
        const beforeEdit = token(f);
        const queuedEdit = edit(f, [{...active, stop: '07:00'}], {precondition: beforeEdit});
        assert.equal(queuedEdit.status, 202);
        assert.equal(f.store.integrationState().active_operation_id, queuedEdit.result.operation.id);
        assert.throws(() => request(f, extra, {minutes: 15}, beforeEdit), code('revision_conflict'));

        // People reads withhold the token while a write is pending. Derive the token queue() would accept from the current state.
        const {highwater} = f.store.get<{highwater: number}>('SELECT highwater FROM service_state WHERE singleton=1')!;
        const observed = f.store.observation().value!;
        const current = `"s${highwater}-r${observed.acceptedPolicy.revision}-${observed.policyDigest}"`;
        assert.throws(() => request(f, extra, {minutes: 15}, current), code('operation_in_progress'));
        assert.equal(operations(f), 1);

        await apply(f, queuedEdit.result.operation.id);
        assert.throws(() => request(f, skip, {}, beforeEdit), code('revision_conflict'));
        assert.equal(request(f, skip).status, 202);
    } finally { f.cleanup(); }
});

test('HTTP serves the two POST routes only for a scoped editor with schedules enabled', async () => {
    for (const flag of ['absent', false, true] as const) {
        const enabled = flag === true;
        const f = world(flag, {pilotWindows: enabled ? [active] : []});
        reviewedClock(f);
        const port = await freePort(), origin = `http://localhost:${port}`;
        const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'Private integration test'});
        const server = appServer(auth, f.policy, {...f.config, port, origin, host: `localhost:${port}`});
        server.listen(port, '127.0.0.1'); await once(server, 'listening');
        try {
            await f.observe();
            const passkey = new TestAuthenticator(), browser = randomBytes(32).toString('base64url');
            const reg = await auth.registrationOptions({token: issueOperatorBootstrap(f.store, 'parent', f.now())}, browser);
            const session = await auth.registrationVerify({challengeId: reg.challengeId, response: passkey.register(reg.options, origin)}, browser);
            const post = (person: string, path: string, input: unknown) => fetch(`${origin}/people/${person}/schedule-${path}`, {method: 'POST',
                headers: {Origin: origin, 'Content-Type': 'application/json', Cookie: `cf_session=${session.token}; cf_browser=${browser}`,
                    'X-CSRF-Token': session.dto.csrfToken, 'If-Match': token(f), 'Idempotency-Key': freshKey()}, body: JSON.stringify(input)});
            assert.equal((await post('nobody', 'extra-time', {minutes: 15})).status, 404);
            const first = await post('pilot', 'extra-time', {minutes: 15});
            assert.equal(first.status, enabled ? 202 : 404);
            const location = first.headers.get('Location');
            if (enabled) {
                assert.match(location!, /^\/operations\//);
                await apply(f, location!.split('/').pop()!);
                assert.equal((await post('pilot', 'skip-tonight', {until: f.now() + 5})).status, 400);
            }
            assert.equal((await post('pilot', 'skip-tonight', {})).status, enabled ? 202 : 404);
            assert.equal(operations(f), enabled ? 2 : 0);
        } finally { server.close(); await once(server, 'close'); f.cleanup(); }
    }
});
