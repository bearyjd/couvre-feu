import test from 'node:test';
import assert from 'node:assert/strict';
import { integrationFixture, actor } from './fixtures/integration.ts';
import { parseInventoryUi } from '../src/inventory-ui-config.ts';
import { INVENTORY_ROW_CAP, DECISION_LABEL_MAX, GUEST_HIDE_SECONDS, DECISIONS_PER_MINUTE } from '../src/inventory-store.ts';
import { AUDIT_ACTIONS } from '../src/parent-audit.ts';
import type { InventoryDevice } from '../../shared/src/router-inventory.ts';
import type { Actor } from '../../shared/src/contracts.ts';

const m = (n: number) => `00:00:5e:00:00:${n.toString(16).padStart(2, '0')}`;
const priv = (n: number) => `02:00:5e:00:00:${n.toString(16).padStart(2, '0')}`;
const dev = (mac: string, over: Partial<InventoryDevice> = {}): InventoryDevice => ({mac, ipv4: ['192.0.2.9'], hostname: 'secrethost', source: 'both', ...over});
const parent: Actor = {...actor, id: 'parent', displayName: 'Test parent', role: 'parent'};
const DAY = 86400;

function setup(triage = true) {
    const f = integrationFixture();
    f.config.inventoryUi = {triage, wizard: false, installReadiness: false};
    f.config.auditLog = {enabled: true};
    const inv = f.worker.inventory;
    const poll = (devices: InventoryDevice[]) => inv.ingest({inventory_version: 1, generation: f.config.router.generation, routerTime: f.now(), devices, truncated: false, errors: []}, f.now());
    const id = (mac: string) => f.store.get<{id: number}>('SELECT rowid id FROM inventory_devices WHERE mac=?', mac)!.id;
    // dev A is in the baseline; B and C arrive afterwards (new). Each poll is 60 s apart.
    const seed = (macs: string[] = [m(1), m(2), m(3)]) => { poll([dev(macs[0])]); for (let i = 1; i < macs.length; i++) { f.advance(60); poll(macs.slice(0, i + 1).map(x => dev(x))); } };
    const code = (fn: () => unknown): string => { try { fn(); } catch (e) { return `${(e as {status?: number}).status}:${(e as Error).message}`; } return 'no_error'; };
    return {f, inv, poll, id, seed, code, rows: (sql: string) => f.store.all<Record<string, unknown>>(sql)};
}

test('inventoryUi parses strictly; absent is all off', () => {
    assert.equal(parseInventoryUi(undefined), undefined);
    assert.deepEqual(parseInventoryUi({}), {triage: false, wizard: false, installReadiness: false});
    assert.deepEqual(parseInventoryUi({triage: true}), {triage: true, wizard: false, installReadiness: false});
    assert.deepEqual(parseInventoryUi({triage: true, wizard: true, installReadiness: true}), {triage: true, wizard: true, installReadiness: true});
    for (const bad of [null, true, [], 'x', {triage: 1}, {triage: 'true'}, {wizard: null}, {installReadiness: 0}, {triage: true, extra: true}, {Triage: true}, {'inventory.triage': true}]) {
        assert.throws(() => parseInventoryUi(bad), {message: 'invalid_inventory_ui'}, JSON.stringify(bad));
    }
});

test('classify, relabel and undo: roles, previous role, newCount, flags.new', () => {
    const t = setup();
    try {
        t.seed(); const [b, c] = [t.id(m(2)), t.id(m(3))];
        let list = t.inv.list(actor);
        assert.equal(list.newCount, 2); assert.ok(list.devices.every(d => d.role === 'new' && d.stableConfirmed === false && !('label' in d) && !('linkedFrom' in d)));
        const home = t.inv.classify(actor, b, 'home', '  Kitchen TV ');
        assert.equal(home.role, 'home'); assert.equal(home.label, 'Kitchen TV'); assert.equal(home.flags.new, false);
        assert.equal(t.inv.list(actor).newCount, 1);
        // reclassify keeps the label unless told otherwise; previous role is the one before
        assert.equal(t.inv.classify(actor, b, 'adult').label, 'Kitchen TV');
        assert.equal(t.rows('SELECT previous_role p FROM inventory_decisions')[0].p, 'home');
        assert.equal(t.inv.classify(actor, b, 'adult', null).label, undefined);
        // idempotent: same role and label writes no audit row and keeps previous role
        const before = t.rows('SELECT count(*) n FROM parent_audit')[0].n;
        t.inv.classify(actor, b, 'adult', null);
        assert.equal(t.rows('SELECT count(*) n FROM parent_audit')[0].n, before);
        assert.equal(t.rows('SELECT previous_role p FROM inventory_decisions')[0].p, 'home');
        const undone = t.inv.undo(actor, b);
        assert.equal(undone.role, 'home'); assert.equal(t.inv.undo(actor, b).role, 'home', 'one step only: the previous role was cleared');
    } finally { t.f.cleanup(); }
});

test('undo goes back one step and is a no-op when there is nothing to undo', () => {
    const t = setup();
    try {
        t.seed(); const b = t.id(m(2));
        assert.equal(t.inv.undo(actor, b).role, 'new'); // nothing recorded: not an error
        assert.equal(t.rows('SELECT count(*) n FROM inventory_decisions')[0].n, 0);
        t.inv.classify(actor, b, 'ignored', 'Neighbour');
        const back = t.inv.undo(actor, b);
        assert.equal(back.role, 'new'); assert.equal(back.label, undefined, 'a label does not outlive an undo back to new');
        assert.equal(t.rows('SELECT count(*) n FROM inventory_decisions')[0].n, 0, 'an empty decision is removed');
        assert.equal(t.inv.list(actor).newCount, 2);
        assert.equal(t.inv.undo(actor, b).role, 'new');
        assert.equal(t.rows("SELECT count(*) n FROM parent_audit WHERE action='inventory_undo'")[0].n, 1, 'only the effective undo is audited');
    } finally { t.f.cleanup(); }
});

test('classify validates role and label', () => {
    const t = setup();
    try {
        t.seed(); const b = t.id(m(2));
        for (const role of ['new', 'hidden', 'protected', 'Kid', '', 5, null, undefined, 'kid(enrolled)']) assert.equal(t.code(() => t.inv.classify(actor, b, role)), '400:invalid_role', String(role));
        for (const label of ['', '   ', 'x'.repeat(DECISION_LABEL_MAX + 1), 'a\nb', 'a\u0000b', 'a‮b', '<b>x</b>', 5, {}, []]) assert.equal(t.code(() => t.inv.classify(actor, b, 'home', label)), '400:invalid_label', JSON.stringify(label));
        assert.equal(t.inv.classify(actor, b, 'home', 'x'.repeat(DECISION_LABEL_MAX)).label?.length, DECISION_LABEL_MAX);
        for (const bad of [0, -1, 1.5, '2', null, NaN]) assert.equal(t.code(() => t.inv.classify(actor, bad as number, 'home')), '404:inventory_device_not_found');
        assert.equal(t.rows('SELECT count(*) n FROM inventory_decisions')[0].n, 1);
    } finally { t.f.cleanup(); }
});

test('unknown, other-generation, protected and purged ids all answer the same 404; enrolled rows answer 409 and keep role kid', () => {
    const t = setup();
    try {
        t.seed();
        t.f.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'both',1,1)", 'f'.repeat(64), m(9));
        const other = t.id(m(9));
        t.f.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'both',1,1)", t.f.config.router.generation, t.f.config.protectedMacs[0]);
        const prot = t.id(t.f.config.protectedMacs[0]);
        const same = '404:inventory_device_not_found';
        for (const row of [99999, other, prot]) {
            assert.equal(t.code(() => t.inv.classify(actor, row, 'home')), same, `classify ${row}`);
            assert.equal(t.code(() => t.inv.undo(actor, row)), same); assert.equal(t.code(() => t.inv.unlink(actor, row)), same);
            assert.equal(t.code(() => t.inv.confirmStable(actor, row, true)), same); assert.equal(t.code(() => t.inv.link(actor, row, t.id(m(2)))), same);
            assert.equal(t.code(() => t.inv.link(actor, t.id(m(2)), row)), same);
        }
        // the enrolled child device
        t.f.advance(60); t.poll([dev(m(1)), dev(m(2)), dev(m(3)), dev(t.f.config.person.device.mac)]);
        const kid = t.id(t.f.config.person.device.mac);
        assert.equal(t.inv.list(actor).devices.find(d => d.id === kid)!.role, 'kid');
        assert.equal(t.code(() => t.inv.classify(actor, kid, 'adult')), '409:inventory_device_enrolled');
        assert.equal(t.code(() => t.inv.undo(actor, kid)), '409:inventory_device_enrolled');
        assert.equal(t.code(() => t.inv.link(actor, kid, t.id(m(2)))), '409:inventory_device_enrolled');
        assert.equal(t.code(() => t.inv.link(actor, t.id(m(2)), kid)), '409:inventory_device_enrolled');
        assert.equal(t.inv.list(actor).devices.find(d => d.id === kid)!.role, 'kid');
        assert.equal(t.rows('SELECT count(*) n FROM inventory_decisions')[0].n, 0);
        // a stable-address check is still allowed for an enrolled kid device
        assert.equal(t.inv.confirmStable(actor, kid, true).stableConfirmed, true);
    } finally { t.f.cleanup(); }
});

test('parents are refused (403) before any lookup, and the triage flag gates the store as well', () => {
    const t = setup();
    try {
        t.seed(); const b = t.id(m(2));
        for (const call of [() => t.inv.classify(parent, b, 'home'), () => t.inv.undo(parent, b), () => t.inv.link(parent, b, t.id(m(3))), () => t.inv.unlink(parent, b), () => t.inv.confirmStable(parent, b, true), () => t.inv.classify(parent, 99999, 'home')]) {
            assert.equal(t.code(call), '403:admin_required');
        }
        assert.equal(t.rows('SELECT count(*) n FROM inventory_decisions')[0].n, 0);
        t.f.config.inventoryUi = {triage: false, wizard: false, installReadiness: false};
        assert.equal(t.code(() => t.inv.classify(actor, b, 'home')), '404:route_not_found');
        t.f.config.inventoryUi = undefined;
        assert.equal(t.code(() => t.inv.confirmStable(actor, b, true)), '404:route_not_found');
    } finally { t.f.cleanup(); }
});

test('link: validation, no self link, no cycle, unlink and idempotence', () => {
    const t = setup();
    try {
        t.seed([m(1), priv(2), priv(3)]); const [a, b, c] = [t.id(m(1)), t.id(priv(2)), t.id(priv(3))];
        assert.equal(t.code(() => t.inv.link(actor, b, b)), '400:invalid_link');
        assert.equal(t.code(() => t.inv.link(actor, b, 'x' as unknown as number)), '404:inventory_device_not_found');
        const linked = t.inv.link(actor, b, a);
        assert.equal(linked.linkedFrom, a); assert.equal(linked.flags.new, true, 'linking does not classify the new row');
        assert.equal(t.inv.link(actor, b, a).linkedFrom, a);
        assert.equal(t.rows("SELECT count(*) n FROM parent_audit WHERE action='inventory_link'")[0].n, 1, 'repeating the same link is not audited again');
        // cycles: a <- b already; linking a to b (or c->b->a->c) is refused
        assert.equal(t.code(() => t.inv.link(actor, a, b)), '409:inventory_link_cycle');
        t.inv.link(actor, c, b);
        assert.equal(t.code(() => t.inv.link(actor, a, c)), '409:inventory_link_cycle');
        // the replaced rows no longer count as new
        t.f.advance(60); t.poll([dev(m(1)), dev(priv(2)), dev(priv(3))]);
        assert.equal(t.inv.list(actor).devices.find(d => d.id === c)!.linkedFrom, b);
        assert.equal(t.inv.list(actor).newCount, 1, 'b is replaced by c; a is in the baseline; c stays new');
        // re-linking moves the link
        assert.equal(t.inv.link(actor, c, a).linkedFrom, a);
        assert.equal(t.inv.unlink(actor, c).linkedFrom, undefined);
        assert.equal(t.inv.unlink(actor, c).linkedFrom, undefined);
        assert.equal(t.rows("SELECT count(*) n FROM parent_audit WHERE action='inventory_unlink'")[0].n, 1);
    } finally { t.f.cleanup(); }
});

test('confirmStable sets and clears the flag with a timestamp and is idempotent', () => {
    const t = setup();
    try {
        t.seed(); const b = t.id(m(2));
        for (const bad of ['true', 1, null, undefined, {}]) assert.equal(t.code(() => t.inv.confirmStable(actor, b, bad as boolean)), '400:invalid_value');
        const on = t.inv.confirmStable(actor, b, true);
        assert.equal(on.stableConfirmed, true); assert.equal(on.role, 'new');
        assert.equal(t.rows('SELECT stable_at s FROM inventory_decisions')[0].s, t.f.now());
        t.inv.confirmStable(actor, b, true);
        assert.equal(t.rows("SELECT count(*) n FROM parent_audit WHERE action='inventory_stable'")[0].n, 1);
        assert.equal(t.inv.confirmStable(actor, b, false).stableConfirmed, false);
        assert.equal(t.rows('SELECT count(*) n FROM inventory_decisions')[0].n, 0, 'a decision with nothing left is removed');
        assert.equal(t.rows("SELECT count(*) n FROM parent_audit WHERE action='inventory_stable'")[0].n, 2);
    } finally { t.f.cleanup(); }
});

test('decisions respect alerts: a held-back new device that was classified never alerts', () => {
    const t = setup();
    try {
        t.seed([m(1), m(2)]); // alert for m(2) raised
        assert.equal(t.rows("SELECT count(*) n FROM parent_alerts WHERE kind='new_device'")[0].n, 1);
        t.f.advance(60); t.poll([dev(m(1)), dev(m(2)), dev(m(3))]); // within the hour: held back
        t.inv.classify(actor, t.id(m(3)), 'infrastructure');
        t.f.advance(7200); assert.deepEqual(t.poll([dev(m(1)), dev(m(2)), dev(m(3))]), {complete: true, alerted: 0});
        assert.equal(t.rows("SELECT sum(count) n FROM parent_alerts WHERE kind='new_device'")[0].n, 1);
    } finally { t.f.cleanup(); }
});

test('re-baseline and pruning keep decided rows (up to 90 days); eviction at the row cap never removes a decided row', () => {
    const t = setup();
    try {
        t.seed([m(1), m(2)]); const b = t.id(m(2));
        t.inv.classify(actor, b, 'home', 'Fridge');
        // quiet for longer than the retention window and then a re-baseline: the decided row is neither pruned nor re-flagged
        t.f.advance(40 * DAY); t.poll([dev(m(1))]);
        const row = t.inv.list(actor).devices.find(d => d.mac === m(2));
        assert.equal(row?.role, 'home'); assert.equal(row?.label, 'Fridge'); assert.equal(row?.flags.new, false);
        assert.equal(t.inv.list(actor).devices.find(d => d.mac === m(1))?.role, 'new');
        // an undecided row of the same age is pruned
        t.inv.undo(actor, b);
        t.f.advance(DAY); t.poll([dev(m(1))]);
        assert.equal(t.inv.list(actor).devices.some(d => d.mac === m(2)), false);
        // cap: fill with old unseen rows; the decided row is the longest-unseen one but must survive
        t.poll([dev(m(2))]); const b2 = t.id(m(2)); t.inv.classify(actor, b2, 'adult');
        t.f.store.run('DELETE FROM inventory_devices WHERE mac<>?', m(2));
        const g = t.f.config.router.generation, now = t.f.now();
        t.f.store.run('UPDATE inventory_devices SET last_seen=? WHERE mac=?', now - 80 * DAY, m(2));
        t.f.store.transaction(() => { for (let i = 0; i < INVENTORY_ROW_CAP - 1; i++) t.f.store.run("INSERT INTO inventory_devices(generation,mac,ipv4_json,hostname,source,first_seen,last_seen) VALUES(?,?,'[]',NULL,'lease',?,?)", g, `0a:00:00:00:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`, 2, now - 100 - i); });
        t.f.advance(60); t.poll([dev(m(5)), dev(m(6))]);
        assert.equal(t.rows('SELECT count(*) n FROM inventory_devices')[0].n, INVENTORY_ROW_CAP);
        assert.equal(t.inv.list(actor).devices.find(d => d.mac === m(2))?.role, 'adult');
    } finally { t.f.cleanup(); }
});

test('decisions follow their row: a pruned or evicted row takes its decision with it, and a reused row id never inherits one', () => {
    const t = setup();
    try {
        t.seed([m(1), m(2)]); const b = t.id(m(2));
        t.inv.classify(actor, b, 'ignored');
        t.f.store.run('DELETE FROM inventory_devices WHERE rowid=?', b);
        t.inv.prune();
        assert.equal(t.rows('SELECT count(*) n FROM inventory_decisions')[0].n, 0);
        t.f.advance(60); t.poll([dev(m(1)), dev(m(7))]);
        assert.equal(t.inv.list(actor).devices.find(d => d.mac === m(7))!.role, 'new');
    } finally { t.f.cleanup(); }
});

test('guests are hidden after 14 quiet days unless asked for; hiddenCount says how many', () => {
    const t = setup();
    try {
        t.seed(); const [b, c] = [t.id(m(2)), t.id(m(3))];
        t.inv.classify(actor, b, 'guest'); t.inv.classify(actor, c, 'home');
        t.f.advance(GUEST_HIDE_SECONDS - 120);
        t.poll([dev(m(1))]);
        let list = t.inv.list(actor);
        assert.equal(list.devices.length, 3); assert.equal(list.hiddenCount, 0);
        t.f.advance(120); t.poll([dev(m(1))]);
        list = t.inv.list(actor);
        assert.deepEqual(list.devices.map(d => d.mac).sort(), [m(1), m(3)]); assert.equal(list.hiddenCount, 1);
        assert.equal(t.inv.list(actor, {includeHidden: true}).devices.length, 3);
        assert.equal(t.inv.list(actor, {includeHidden: true}).hiddenCount, 1);
        // seen again (lease-only keeps it quiet; a neighbour sighting brings it back)
        t.poll([dev(m(1)), dev(m(2))]);
        assert.equal(t.inv.list(actor).devices.length, 3);
    } finally { t.f.cleanup(); }
});

test('flag off: the DTO is exactly today\'s (no new fields, no hiding), old acknowledge keeps working', () => {
    const t = setup(false);
    try {
        t.seed();
        const list = t.inv.list(actor) as unknown as {devices: Record<string, unknown>[]} & Record<string, unknown>;
        assert.ok(!('newCount' in list) && !('hiddenCount' in list));
        for (const d of list.devices) for (const key of ['role', 'label', 'linkedFrom', 'stableConfirmed']) assert.ok(!(key in d), key);
        assert.equal(t.inv.acknowledge(actor, m(2)).acknowledgedAt, t.f.now());
        const on = setup(true);
        try {
            on.seed(); assert.equal(on.inv.acknowledge(actor, m(2)).flags.new, false);
            assert.equal(on.inv.list(actor).newCount, 1, 'an acknowledged device is not new either');
        } finally { on.f.cleanup(); }
    } finally { t.f.cleanup(); }
});

test('audit: new action types only, actor and row id only, in both logs; the audit list knows the actions', () => {
    const t = setup();
    try {
        for (const a of ['inventory_classify', 'inventory_undo', 'inventory_link', 'inventory_unlink', 'inventory_stable']) assert.ok((AUDIT_ACTIONS as readonly string[]).includes(a), a);
        t.seed([m(1), priv(2), priv(3)]); const [b, c] = [t.id(priv(2)), t.id(priv(3))];
        t.inv.classify(actor, b, 'home', 'SecretLabel'); t.inv.undo(actor, b); t.inv.link(actor, c, b); t.inv.unlink(actor, c); t.inv.confirmStable(actor, c, true);
        assert.deepEqual(t.rows('SELECT actor_id,action,person_id,operation_id,result FROM parent_audit ORDER BY id').map(r => ({...r})), [
            ['inventory_classify', b], ['inventory_undo', b], ['inventory_link', c], ['inventory_unlink', c], ['inventory_stable', c]].map(([action, row]) => ({actor_id: 'operator', action, person_id: null, operation_id: `inventory_row:${row}`, result: 'applied'})));
        assert.deepEqual(t.rows("SELECT actor_id,action,outcome FROM audit WHERE action LIKE 'inventory_%' ORDER BY id").map(r => ({...r})), [
            ['inventory_classify', b], ['inventory_undo', b], ['inventory_link', c], ['inventory_unlink', c], ['inventory_stable', c]].map(([action, row]) => ({actor_id: 'operator', action, outcome: `inventory_row:${row}`})));
    } finally { t.f.cleanup(); }
});

test('privacy: a label, hostname, vendor or MAC never reaches audit, alerts, logs, stdout or stderr', () => {
    const writes: string[] = [], real = {out: process.stdout.write, err: process.stderr.write};
    const spy = ((chunk: unknown) => { writes.push(String(chunk)); return true; }) as typeof process.stdout.write;
    const t = setup();
    process.stdout.write = spy; process.stderr.write = spy;
    try {
        t.seed([m(1), priv(2), priv(3)]); const [b, c] = [t.id(priv(2)), t.id(priv(3))];
        t.inv.classify(actor, b, 'home', 'SecretLabel');
        assert.equal(t.rows("SELECT count(*) n FROM inventory_decisions WHERE label='SecretLabel'")[0].n, 1, 'the label is stored only in the decision row');
        t.inv.link(actor, c, b); t.inv.confirmStable(actor, c, true); t.inv.undo(actor, b); t.inv.unlink(actor, c);
        t.f.advance(7200); t.poll([dev(m(1)), dev(priv(2)), dev(priv(3)), dev(m(8), {hostname: 'secrethost2'})]);
        process.stdout.write = real.out; process.stderr.write = real.err;
        const dump = JSON.stringify([t.rows('SELECT * FROM audit'), t.rows('SELECT * FROM parent_audit'), t.rows('SELECT * FROM parent_alerts'), t.rows('SELECT * FROM inventory_state'), writes]);
        for (const secret of ['SecretLabel', 'secrethost', m(1), priv(2), priv(3), '192.0.2.9']) assert.ok(!dump.includes(secret), secret);
    } finally { process.stdout.write = real.out; process.stderr.write = real.err; t.f.cleanup(); }
});

test('a failing audit write rolls the whole decision back', () => {
    const t = setup();
    try {
        t.seed(); const b = t.id(m(2));
        t.f.store.run('DROP TABLE parent_audit');
        assert.throws(() => t.inv.classify(actor, b, 'home', 'Label'));
        assert.equal(t.rows('SELECT count(*) n FROM inventory_decisions')[0].n, 0);
        assert.equal(t.rows("SELECT count(*) n FROM audit WHERE action='inventory_classify'")[0].n, 0);
    } finally { t.f.cleanup(); }
});

test('decisions are rate limited per actor', () => {
    const t = setup();
    try {
        t.seed(); const b = t.id(m(2));
        for (let i = 0; i < DECISIONS_PER_MINUTE; i++) t.inv.classify(actor, b, i % 2 ? 'home' : 'adult');
        assert.equal(t.code(() => t.inv.classify(actor, b, 'guest')), '429:inventory_decision_rate_limited');
        t.f.advance(61);
        assert.equal(t.inv.classify(actor, b, 'guest').role, 'guest');
    } finally { t.f.cleanup(); }
});
