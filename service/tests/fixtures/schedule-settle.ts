import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { scheduleWindows } from '../../src/integration-schedule-store.ts';
import { policyDigest, requestDigest } from '../../../shared/src/router-rpc.ts';
import { normalizePolicy, policyJSON } from '../../../shared/src/router-schema.ts';
import type { RouterPolicy, Schedule } from '../../../shared/src/router-schema.ts';
import type { IntegrationOperation } from '../../src/integration-policy.ts';
import { parityFixture } from './schedule-parity-script.ts';
import type { ParityFixture, ParityFlag } from './schedule-parity-script.ts';

// Helpers for the schedule settlement core (roadmap item 2, S2a; schedules.editable, off; unverified on this router). There is no
// producer yet: every test inserts the operation rows directly, as the future producer will, and drives the real worker.
export type Fixture = ParityFixture;
export type Window = Omit<Schedule, 'person'>;
export const night: Window = {id: 'night', weekdays: ['Mon', 'Tue'], start: '20:30', stop: '07:00'};
export const other: Window = {id: 'other', weekdays: ['Fri'], start: '21:00', stop: '23:00'};
export const plain = (n: number): Window[] => Array.from({length: n}, (_, i) => ({id: `p${i}`, weekdays: ['Tue'], start: '09:00', stop: '10:00'}));
export const cross = (n: number): Window[] => Array.from({length: n}, (_, i) => ({id: `c${i}`, weekdays: ['Mon'], start: '22:00', stop: '06:00'}));
export const macOf = (n: number): string => '02:10:20:30:41:' + n.toString(16).padStart(2, '0');

/** The flag is REQUIRED: 'absent' leaves the manifest key out (asserted), false/true set it. `devices` addresses sit under the one child. */
export function world(flag: ParityFlag, devices = 1): Fixture {
    const f = parityFixture(flag);
    if (flag === 'absent') assert.equal(f.config.schedules, undefined);
    const macs = ['02:10:20:30:40:50', ...Array.from({length: devices - 1}, (_, i) => macOf(i))];
    f.store.transaction(() => { for (const [i, mac] of macs.slice(1).entries()) f.store.run("INSERT INTO devices(id,person_id,label,identifier_kind,identifier,state,created_at) VALUES(?,?,?,'mac',?,'active',?)", `d${i}`, 'pilot', `Device ${i}`, mac, 1); });
    f.router.policy = normalizePolicy({version: 1, revision: 0, people: [{id: 'pilot', macs}], pauses: [], schedules: []});
    return f;
}
/** `base` with the child's windows replaced and the revision bumped (other children's windows kept). */
export const withWindows = (base: RouterPolicy, windows: readonly Window[], person = 'pilot'): RouterPolicy =>
    normalizePolicy({...base, revision: base.revision + 1, schedules: [...base.schedules.filter(s => s.person !== person), ...windows.map(w => ({person, ...w}))]});
export interface QueueOptions { action?: IntegrationOperation['action']; base?: RouterPolicy; person?: string }
/** Inserts a pending schedule operation with its envelope (against the stored observation unless `base` is given) and makes it active. */
export function queue(f: Fixture, windows: readonly Window[], options: QueueOptions = {}): string {
    const base = options.base ?? f.store.observation().value!.acceptedPolicy, person = options.person ?? 'pilot';
    const id = randomUUID(), policy = withWindows(base, windows, person), generation = f.config.router.generation;
    const envelope = {rpc_version: 1 as const, generation, operation_id: id, expected_revision: base.revision, expected_digest: policyDigest(base), policy};
    insertRaw(f, id, JSON.stringify(envelope), requestDigest(envelope), {action: options.action, person, policy: policyJSON(policy), base: policyJSON(base), revision: policy.revision});
    return id;
}
interface RawRow { action?: IntegrationOperation['action']; person?: string; policy?: string; base?: string; revision?: number; generation?: string; baseDigest?: string }
/** Inserts operation rows verbatim (an envelope no producer could build, e.g. one the router normalizer refuses). */
export function insertRaw(f: Fixture, id: string, envelopeJson: string, digest: string, row: RawRow = {}): void {
    const o = f.store.observation().value!;
    f.store.transaction(() => {
        f.store.run("INSERT INTO operations(id,actor_id,person_id,action,revision,state,payload_json,base_json,request_json,idempotency_key,created_at,updated_at,error) VALUES(?,?,?,?,?,'pending',?,?,'{}',?,?,?,'awaiting_operator_dispatch')",
            id, 'operator', row.person ?? 'pilot', row.action ?? 'schedule_update', row.revision ?? 1, row.policy ?? '{}', row.base ?? '{}', 'k_' + id, f.now(), f.now());
        f.store.run("INSERT INTO operation_rpc(operation_id,generation,base_digest,request_digest,envelope_json,phase) VALUES(?,?,?,?,?,'queued')", id, row.generation ?? o.generation, row.baseDigest ?? o.policyDigest, digest, envelopeJson);
        f.store.run('UPDATE integration_state SET active_operation_id=? WHERE singleton=1', id);
    });
}
export const op = (f: Fixture, id: string): IntegrationOperation => f.store.get<IntegrationOperation>('SELECT * FROM operations WHERE id=?', id)!;
export const committed = (f: Fixture, person = 'pilot'): Window[] => scheduleWindows(f.store).filter(s => s.person === person).map(({person: _p, ...w}) => w);
export const active = (f: Fixture): string | null => f.store.integrationState().active_operation_id;
export const audits = (f: Fixture, id: string): number => f.store.get<{n: number}>('SELECT count(*) n FROM audit WHERE operation_id=?', id)!.n;
export const applies = (f: Fixture): number => f.router.calls.filter(c => c.kind === 'apply').length;
export const sequence = (f: Fixture): number => f.store.integrationState().observation_sequence;
