import test from 'node:test';
import assert from 'node:assert/strict';
import { IntegrationStore } from '../src/integration-db.ts';
import { IntegrationGrants } from '../src/integration-allowance.ts';
import { rebindIntegration } from '../src/integration-rebind.ts';
import { TimeRequestService } from '../src/time-requests.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { actor } from './fixtures/integration.ts';
import { apply, editId, freshKey, night, op, plain, receipt, rebind, study, token, world } from './fixtures/schedule-settle.ts';
import type { World } from './fixtures/schedule-settle.ts';

const create = (f: World, body: unknown) => f.policy.scheduleMutate!(actor, 'pilot', 'schedule_create', body, undefined, token(f), freshKey()).result.operation.id;
const update = (f: World, id: string, body: unknown) => f.policy.scheduleMutate!(actor, 'pilot', 'schedule_update', body, id, token(f), freshKey()).result.operation.id;
const remove = (f: World, id: string) => f.policy.scheduleMutate!(actor, 'pilot', 'schedule_delete', {}, id, token(f), freshKey()).result.operation.id;
const people = (f: World) => f.policy.people(actor).people[0].schedules;
const kinds = (f: World) => f.store.all<{person_id: string; id: string; kind: string}>('SELECT person_id,id,kind FROM schedule_windows ORDER BY person_id,id').map(row => [row.person_id, row.id, row.kind]);
const expectKind = (f: World, id: string, kind: string) => assert.equal(people(f)?.find(w => w.id === id)?.kind, kind);

test('Focus kind is promoted by a receipt, stays off the wire, and survives an old-client update', async () => {
    const f = world(true, {pilotWindows: [night], peer: true});
    f.config.focus = {enabled: true};
    f.config.auditLog = {enabled: true};
    try {
        f.store.run("UPDATE schedule_windows SET kind='focus' WHERE person_id='peer'");
        await f.observe();
        const id = create(f, {...study, kind: 'focus'});
        assert.deepEqual(people(f)?.map(w => w.id), ['night']);
        assert.equal(f.policy.envelope(id).policy.schedules.some(w => 'kind' in w), false);
        await apply(f, id);
        expectKind(f, study.id, 'focus');
        expectKind(f, night.id, 'bedtime');
        const {id: _id, ...edit} = study;
        await apply(f, update(f, study.id, {...edit, stop: '18:30'}));
        expectKind(f, study.id, 'focus');
        await apply(f, update(f, study.id, {...edit, stop: '18:30', kind: 'bedtime'}));
        expectKind(f, study.id, 'bedtime');
        await apply(f, remove(f, study.id));
        assert.deepEqual(kinds(f), [['peer', study.id, 'focus'], ['pilot', night.id, 'bedtime']]);
        const audit = f.store.all<{action: string}>('SELECT action FROM parent_audit ORDER BY id');
        assert.deepEqual(audit.map(row => row.action), ['schedule_set', 'schedule_set', 'schedule_set', 'schedule_loosened']);
        assert.doesNotMatch(JSON.stringify(f.store.all('SELECT * FROM parent_audit')), /focus|bedtime|study|18:30/);
    } finally { f.cleanup(); }
});

test('An exact unhealthy receipt promotes a label-only update and a read cannot promote it twice', async () => {
    const f = world(true, {pilotWindows: [night]});
    f.config.focus = {enabled: true};
    try {
        await f.observe();
        const {id: _id, ...edit} = night;
        const id = update(f, night.id, {...edit, kind: 'focus'});
        f.router.transform = o => ({...o, status: {...o.status, ok: false, errors: ['previous_apply_failed']}});
        await apply(f, id);
        expectKind(f, night.id, 'focus');
        const writes = f.writes();
        f.router.transform = null;
        f.advance(5); await receipt(f, id);
        assert.equal(f.writes(), writes);
        expectKind(f, night.id, 'focus');
    } finally { f.cleanup(); }
});

test('Closed kinds and both flags gate a focus creation, and focus counts against the eight-window cap', async () => {
    const f = world(true, {pilotWindows: plain(7)});
    try {
        await f.observe();
        assert.throws(() => create(f, {...night, kind: 'focus'}), /recurring_focus_unavailable/);
        assert.throws(() => create(f, {...night, kind: 'other'}), /invalid_schedule_kind/);
        assert.equal(people(f)?.every(w => !('kind' in w)), true);
        f.config.focus = {enabled: true};
        await apply(f, create(f, {...night, kind: 'focus'}));
        expectKind(f, night.id, 'focus');
        assert.throws(() => create(f, study), /schedule_payload_inadmissible/);
        f.config.focus = {enabled: false};
        assert.equal(people(f)?.every(w => !('kind' in w)), true);
        assert.equal(kinds(f).some(row => row[2] === 'focus'), true);
    } finally { f.cleanup(); }
    const off = world(false);
    off.config.focus = {enabled: true};
    try {
        assert.equal(off.policy.scheduleMutate, undefined);
        assert.equal(people(off), undefined);
    } finally { off.cleanup(); }
});

test('Kind snapshots use the same admission as the wire edit and corrupted intent is refused before dispatch', async () => {
    for (const corrupt of ['request', 'missing'] as const) {
        const f = world(true);
        f.config.focus = {enabled: true};
        try {
            await f.observe();
            const id = create(f, {...night, kind: 'focus'});
            if (corrupt === 'request') f.store.run('UPDATE operations SET request_json=? WHERE id=?', op(f, id).request_json.replaceAll('focus', 'bedtime'), id);
            else f.store.run('DELETE FROM schedule_kind_intents WHERE operation_id=?', id);
            assert.throws(() => f.worker.prepare('apply', id), /schedule_payload_inadmissible/);
            assert.deepEqual(kinds(f), []);
            assert.equal(f.router.calls.filter(call => call.kind === 'apply').length, 0);
        } finally { f.cleanup(); }
    }
});

test('A pending pre-migration edit preserves labels of retained windows and defaults new ids', async () => {
    const f = world(true, {pilotWindows: [night]});
    f.config.focus = {enabled: true};
    try {
        f.store.run("UPDATE schedule_windows SET kind='focus' WHERE id=?", night.id);
        await f.observe();
        const id = editId(f, [night, study]);
        const {windowKinds: _kinds, ...legacy} = JSON.parse(op(f, id).request_json);
        f.store.transaction(() => {
            f.store.run('DELETE FROM schedule_kind_intents WHERE operation_id=?', id);
            f.store.run('UPDATE operations SET request_json=? WHERE id=?', JSON.stringify(legacy), id);
        });
        await apply(f, id);
        expectKind(f, night.id, 'focus');
        expectKind(f, study.id, 'bedtime');
    } finally { f.cleanup(); }
});

for (const version of [16, 17]) test(`Migration 019 applies from user_version ${version} and preserves windows, seed and cap`, () => {
    const f = world(true, {pilotWindows: [night]});
    try {
        // 16 represents an old database and 17 an interrupted startup after reserving the version.
        f.store.db.exec(`DROP TABLE schedule_kind_intents; ALTER TABLE schedule_windows DROP COLUMN kind; PRAGMA user_version=${version}`);
        const reopened = new IntegrationStore(f.config);
        try {
            assert.equal(reopened.get<{user_version: number}>('PRAGMA user_version')!.user_version, 17);
            assert.ok(reopened.get("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schedule_kind_intents'"));
            assert.equal(reopened.get<{kind: string}>('SELECT kind FROM schedule_windows WHERE id=?', night.id)?.kind, 'bedtime');
            assert.ok(reopened.get('SELECT 1 FROM schedule_seed'));
            assert.throws(() => reopened.run("UPDATE schedule_windows SET kind='other'"), /CHECK/);
            assert.equal(reopened.all("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'schedule_windows_cap%'").length, 2);
        } finally { reopened.close(); }
    } finally { f.cleanup(); }
});

test('Recurring focus survives manifest rebind and an editable-off rebind cannot discard its label', async () => {
    const f = world(true);
    f.config.focus = {enabled: true};
    try {
        await f.observe();
        await apply(f, create(f, {...night, kind: 'focus'}));
        const disabled = {...f.config, schedules: {editable: false}, manifestDigest: 'e'.repeat(64),
            enrollment: normalizePolicy({...f.config.enrollment, schedules: [{person: 'pilot', ...night}]})};
        assert.throws(() => rebindIntegration(f.store, disabled, f.config.manifestDigest, disabled.manifestDigest, f.now()), /rebind_focus_schedules_present/);
        rebind(f);
        const reopened = new IntegrationStore({...f.config, manifestDigest: 'e'.repeat(64)});
        try { assert.equal(reopened.get<{kind: string}>('SELECT kind FROM schedule_windows WHERE id=?', night.id)?.kind, 'focus'); }
        finally { reopened.close(); }
    } finally { f.cleanup(); }
});

test('A child ask leaves recurring focus active; a parent-approved grant lifts it until expiry', async () => {
    const f = world(true);
    f.config.focus = {enabled: true};
    f.config.scheduleClock = {timezone: 'UTC', conformance: {utcOffsetMinutes: 0, verifiedAt: f.now() - 60, validUntil: f.now() + 86400, evidenceSha256: 'e'.repeat(64)}};
    const person = () => f.policy.people(actor).people[0];
    try {
        await f.observe();
        const recurring = {id: 'during', weekdays: ['Sun'], start: '04:00', stop: '06:00', kind: 'focus'};
        await apply(f, create(f, recurring));
        assert.equal(person().scheduleBlocked, true);
        const requests = new TimeRequestService(f.store, f.policy, f.now, undefined, new IntegrationGrants(f.policy));
        const link = await requests.issueLink(actor, 'pilot');
        assert.equal(requests.submit(link.token, 15, 'homework', 'client').state, 'pending');
        assert.equal(person().scheduleBlocked, true);
        assert.equal(person().allowance, null);
        assert.equal(f.store.get<{n: number}>("SELECT count(*) n FROM operations WHERE action='allow'")!.n, 0);
        const {id} = f.store.get<{id: string}>("SELECT id FROM time_requests WHERE state='pending'")!;
        assert.equal((await requests.approve(actor, id, 15)).state, 'approving');
        assert.equal(person().scheduleBlocked, true);
        const {grant_operation_id: grant} = f.store.get<{grant_operation_id: string}>('SELECT grant_operation_id FROM time_requests WHERE id=?', id)!;
        await apply(f, grant);
        assert.equal(person().scheduleBlocked, false);
        expectKind(f, recurring.id, 'focus');
        f.advance(900); await f.observe();
        assert.equal(person().scheduleBlocked, true);
        expectKind(f, recurring.id, 'focus');
    } finally { f.cleanup(); }
});
