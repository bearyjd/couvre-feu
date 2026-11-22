import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { scheduleWindows, schedulesInDatabase } from '../../src/integration-schedule-store.ts';
import { SCHEDULE_CODES } from '../../src/integration-schedule-settle.ts';
import { rebindIntegration } from '../../src/integration-rebind.ts';
import { policyDigest, requestDigest } from '../../../shared/src/router-rpc.ts';
import { normalizePolicy, policyJSON } from '../../../shared/src/router-schema.ts';
import type { RouterPolicy, Schedule } from '../../../shared/src/router-schema.ts';
import type { Actor, OperationResult } from '../../../shared/src/contracts.ts';
import type { IntegrationOperation } from '../../src/integration-policy.ts';
import { actor } from './integration.ts';
import { applyOp, parityFixture, receiptOp } from './schedule-parity-script.ts';
import type { ParityFixture, ParityFlag } from './schedule-parity-script.ts';

// Schedule edits for integration installs (roadmap item 2, S2a; schedules.editable, off; unverified on this router). Operations come
// from IntegrationPolicy.scheduleEdit (no HTTP route in S2a) and the real worker; only corruption cases write rows directly.
export type Window = Omit<Schedule, 'person'>;
export const night: Window = {id: 'night', weekdays: ['Mon', 'Tue'], start: '20:30', stop: '07:00'};
export const study: Window = {id: 'study', weekdays: ['Wed'], start: '16:00', stop: '18:00'};
export const plain = (n: number): Window[] => Array.from({length: n}, (_, i) => ({id: `p${i}`, weekdays: ['Tue'], start: '09:00', stop: '10:00'}));
export const cross = (n: number): Window[] => Array.from({length: n}, (_, i) => ({id: `c${i}`, weekdays: ['Mon'], start: '22:00', stop: '06:00'}));
export const PILOT_MAC = '02:10:20:30:40:50', PEER_MAC = '02:10:20:30:42:01';
export const macOf = (n: number): string => '02:10:20:30:41:' + n.toString(16).padStart(2, '0');
export const sha = (text: string): string => createHash('sha256').update(text).digest('hex');

export interface WorldOptions { devices?: number; clock?: boolean; peer?: boolean; pilotWindows?: readonly Window[] }
export type World = ParityFixture & {writes: () => number};
/**
 * The flag is REQUIRED ('absent' leaves the manifest key out, asserted). `devices` addresses sit under pilot; `peer` adds a second routed
 * child with an indefinite pause, an allowance, a DoH entry and one committed window. A TEMP trigger counts schedule_windows writes.
 */
export function world(flag: ParityFlag, options: WorldOptions = {}): World {
    const f = parityFixture(flag);
    if (flag === 'absent') assert.equal(f.config.schedules, undefined);
    if (options.clock === false) delete (f.config as {scheduleClock?: unknown}).scheduleClock;
    const macs = [PILOT_MAC, ...Array.from({length: (options.devices ?? 1) - 1}, (_, i) => macOf(i))], t = f.now();
    const pilotWindows = (options.pilotWindows ?? []).map(w => ({person: 'pilot', ...w})), peerWindows = options.peer ? [{person: 'peer', ...study}] : [];
    f.store.transaction(() => {
        for (const [i, mac] of macs.slice(1).entries()) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',?)", `d${i}`, 'pilot', `Device ${i}`, mac, 1);
        if (options.peer) {
            f.store.run('INSERT INTO people(id,name,active,created_at) VALUES(?,?,1,?)', 'peer', 'Second test child', 1);
            f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES('peerphone','peer','Peer device','mac',?,'active',1)", PEER_MAC);
        }
        for (const w of [...pilotWindows, ...peerWindows]) f.store.run('INSERT INTO schedule_windows(person_id,id,weekdays,start,stop) VALUES(?,?,?,?,?)', w.person, w.id, w.weekdays.join(','), w.start, w.stop);
    });
    f.router.policy = normalizePolicy({version: 1, revision: 0, people: [{id: 'pilot', macs}, ...(options.peer ? [{id: 'peer', macs: [PEER_MAC]}] : [])],
        pauses: options.peer ? [{person: 'peer', until: 0}] : [], ...(options.peer ? {allowances: [{person: 'peer', until: t + 3600}]} : {}),
        schedules: [...pilotWindows, ...peerWindows], ...(options.peer ? {doh: {ipv4: ['9.9.9.9'], ipv6: []}} : {})});
    f.store.db.exec(`CREATE TEMP TABLE window_writes(n INTEGER NOT NULL); INSERT INTO window_writes VALUES(0);
        CREATE TEMP TRIGGER window_insert AFTER INSERT ON main.schedule_windows BEGIN UPDATE window_writes SET n=n+1; END;
        CREATE TEMP TRIGGER window_delete AFTER DELETE ON main.schedule_windows BEGIN UPDATE window_writes SET n=n+1; END;`);
    const cleanup = f.cleanup;
    return {...f, writes: () => f.store.get<{n: number}>('SELECT n FROM window_writes')!.n,
        cleanup: () => { try { assertClosedCodes(f); } finally { cleanup(); } }};
}
/** SCHEDULE_CODES is closed: every schedule operation's stored error is one of its members (or none). Checked at every world's cleanup. */
function assertClosedCodes(f: ParityFixture): void {
    if (!schedulesInDatabase(f.config)) return;
    for (const row of f.store.all<{error: string | null}>("SELECT error FROM operations WHERE action LIKE 'schedule_%'")) {
        assert.ok(row.error === null || (SCHEDULE_CODES as readonly string[]).includes(row.error), `schedule operation error outside SCHEDULE_CODES: ${row.error}`);
    }
}
export const token = (f: World): string => f.policy.people(actor).revisionToken!;
let keys = 0;
export const freshKey = (): string => `schedule_key_${String(++keys).padStart(6, '0')}`;
/** One schedule edit through the real producer. Returns the operation id. */
export function edit(f: World, windows: readonly Window[], options: {key?: string; person?: string; as?: Actor; precondition?: string} = {}): {status: number; result: OperationResult} {
    return f.policy.scheduleEdit(options.as ?? actor, options.person ?? 'pilot', windows, options.precondition ?? token(f), options.key ?? freshKey());
}
export const editId = (f: World, windows: readonly Window[]): string => edit(f, windows).result.operation.id;
export const apply = applyOp, receipt = receiptOp;
export const op = (f: World, id: string): IntegrationOperation => f.store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id)!;
export const committed = (f: World, person = 'pilot'): Window[] => scheduleWindows(f.store).filter(s => s.person === person).map(({person: _p, ...w}) => w);
export const active = (f: World): string | null => f.store.integrationState().active_operation_id;
export const audits = (f: World, id: string, outcome?: string): number => f.store.get<{n: number}>('SELECT count(*) n FROM audit WHERE operation_id=? AND (?2 IS NULL OR outcome=?2)', id, outcome ?? null)!.n;
export const applies = (f: World): number => f.router.calls.filter(c => c.kind === 'apply').length;
export const operations = (f: World): number => f.store.get<{n: number}>('SELECT count(*) n FROM operations')!.n;
export const openSteps = (f: World, id: string): number => f.store.get<{n: number}>("SELECT count(*) n FROM dispatch_steps WHERE operation_id=? AND state<>'resolved'", id)!.n;
export const rpcPhase = (f: World, id: string): string => f.store.get<{phase: string}>('SELECT phase FROM operation_rpc WHERE operation_id=?', id)!.phase;
export const sequence = (f: World): number => f.store.integrationState().observation_sequence;
export const applyLease = (f: World, id: string): number => f.store.get<{lease_until: number}>("SELECT lease_until FROM dispatch_steps WHERE operation_id=? AND kind='apply'", id)!.lease_until;
/** Advances to `time` (service and router clocks are the same fixture clock). */
export const at = (f: World, time: number): void => f.advance(time - f.now());
/** A real rebind to a changed manifest digest (dispatch is stopped after every finish; nothing may be in flight). */
export function rebind(f: World): void {
    const next = {...f.config, manifestDigest: 'e'.repeat(64)};
    rebindIntegration(f.store, next, f.config.manifestDigest, next.manifestDigest, f.now());
}
/** An out-of-band router change (revision + 1): `change` edits the router's current policy. */
export function routerChange(f: World, change: (p: RouterPolicy) => Partial<RouterPolicy>): void {
    f.router.policy = normalizePolicy({...f.router.policy, ...change(f.router.policy), revision: f.router.policy.revision + 1});
}
/**
 * Inserts a pending schedule_update directly (the flag-off parity script, where scheduleEdit refuses): request, base, payload and envelope
 * are self-consistent and built here independently of the service builder.
 */
export function insertScheduleOp(f: ParityFixture, windows: readonly Window[], person = 'pilot'): string {
    const o = f.store.observation().value!, base = o.acceptedPolicy, id = randomUUID(), planned = windows.map(w => ({person, ...w}));
    const policy = normalizePolicy({...base, revision: base.revision + 1, schedules: [...base.schedules.filter(s => s.person !== person), ...planned]});
    const envelope = {rpc_version: 1 as const, generation: o.generation, operation_id: id, expected_revision: base.revision, expected_digest: policyDigest(base), policy};
    const request = JSON.stringify({person, action: 'schedule_update', windows: planned, precondition: null, permissionVersion: '1'});
    f.store.transaction(() => {
        f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error) VALUES(?,?,?,'schedule_update',?,'pending',?,?,?,?,?,?,'awaiting_operator_dispatch')",
            id, 'operator', person, policy.revision, policyJSON(policy), policyJSON(base), request, 'raw_' + id, f.now(), f.now());
        f.store.run('INSERT INTO operation_people(operation_id,person_id) VALUES(?,?)', id, person);
        f.store.run("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase) VALUES(?,?,?,?,?,'queued')", id, o.generation, o.policyDigest, requestDigest(envelope), JSON.stringify(envelope));
        f.store.run('UPDATE integration_state SET active_operation_id=? WHERE singleton=1', id);
    });
    return id;
}
