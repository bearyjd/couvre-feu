import { integrationFixture, actor } from './integration.ts';
import { TimeRequestService } from '../../src/time-requests.ts';
import { IntegrationGrants } from '../../src/integration-allowance.ts';
import { normalizePolicy } from '../../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../../shared/src/router-schema.ts';

const ALL_DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] as const;
export interface Row {id: string; state: string; allowance_until: number | null; granted_minutes: number | null; decision_code: string | null; grant_operation_id: string | null; repause_state: string}

/** A real IntegrationPolicy + fake router, with the router-side allowance port wired as the real path does. */
export async function world(over: Partial<RouterPolicy> = {}) {
    const f = integrationFixture();
    const now = f.now();
    // Owner-reviewed clock in UTC so the integration schedule claim is evaluable; the fixture clock is 00:00 UTC.
    f.config.scheduleClock = {timezone: 'UTC', conformance: {utcOffsetMinutes: 0, verifiedAt: now - 3600, validUntil: now + 3 * 86400, evidenceSha256: 'e'.repeat(64)}};
    // Schedules on the router must be the manifest-owned ones (validateManagedPolicy).
    if (over.schedules) f.config.enrollment = normalizePolicy({...f.config.enrollment, schedules: over.schedules});
    f.router.policy = normalizePolicy({...f.config.enrollment, revision: 1, ...over}, f.config.protectedMacs);
    await f.observe();
    const grants = new IntegrationGrants(f.policy);
    const service = new TimeRequestService(f.store, f.policy, f.now, undefined, grants);
    const dispatch = async (id: string) => { const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256); };
    const link = await service.issueLink(actor, 'pilot');
    const ask = (minutes = 30) => { service.submit(link.token, minutes, 'homework', 'client-a'); return f.store.get<Row>("SELECT * FROM time_requests WHERE state='pending'")!.id; };
    const row = (id: string) => f.store.get<Row>('SELECT * FROM time_requests WHERE id=?', id)!;
    return {f, grants, service, dispatch, link, ask, row};
}
export const bedtime = {schedules: [{person: 'pilot', id: 'bed', weekdays: [...ALL_DAYS], start: '00:00', stop: '23:59'}]};

