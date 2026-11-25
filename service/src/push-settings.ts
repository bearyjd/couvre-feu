import { AppError } from '../../shared/src/errors.ts';
import type { AuthSession } from './auth.ts';
import { DIGEST_HOUR, DIGEST_ZONE, QUIET_END_HOUR, QUIET_START_HOUR, inQuietHours } from './digest.ts';
import { HELD_KINDS } from './push-runtime.ts';
import type { NtfyPush } from './push-sender.ts';
import type { Routed } from './time-requests-http.ts';

/** One test push per account in this window. A real send is at most one attempt of PUSH_TIMEOUT_MS, so a click cannot queue work. */
export const TEST_COOLDOWN_SECONDS = 30;
const hhmm = (hour: number) => `${String(hour).padStart(2, '0')}:00`;

/**
 * Admin-only read of the push settings and a one-click test push. Exists only when push.enabled (the caller passes nothing otherwise, so both
 * routes are absent). Reports what the service can know: accepted by the push service, a failure tag, or no ntfy settings. It never claims the
 * phone received anything, and no value from the environment or the push service's answer is read into a response.
 */
export class PushSettings {
    private readonly sender: NtfyPush | null;
    private readonly now: () => number;
    private readonly lastTest = new Map<string, number>();
    /** `sender` is null when the ntfy environment is missing or invalid; `now` is epoch seconds. */
    constructor(sender: NtfyPush | null, now: () => number = () => Math.floor(Date.now() / 1000)) { this.sender = sender; this.now = now; }
    private admin(session: AuthSession): string {
        const actor = session.dto.actor;
        if (actor.role !== 'admin') throw new AppError(403, 'admin_required');
        return actor.id;
    }
    get(session: AuthSession, path: string): Routed | null {
        if (path !== '/push/settings') return null;
        this.admin(session);
        return {status: 200, body: {push: {provider: 'ntfy', configured: this.sender !== null,
            quietHours: {start: hhmm(QUIET_START_HOUR), end: hhmm(QUIET_END_HOUR), zone: DIGEST_ZONE, activeNow: inQuietHours(this.now())}, heldKinds: [...HELD_KINDS],
            digest: {audience: 'admins', day: 'sunday', time: hhmm(DIGEST_HOUR), zone: DIGEST_ZONE}}}};
    }
    async post(session: AuthSession, path: string): Promise<Routed | null> {
        if (path !== '/push/test') return null;
        const id = this.admin(session);
        if (!this.sender) return {status: 200, body: {result: 'not_configured'}};
        const now = this.now(), last = this.lastTest.get(id);
        if (last !== undefined && now - last < TEST_COOLDOWN_SECONDS) throw new AppError(429, 'push_test_cooldown');
        this.lastTest.set(id, now);
        const result = await this.sender.send({kind: 'test'});
        return {status: 200, body: {result: result.ok ? 'sent_to_push_service' : `push_failed:${result.reason}`}};
    }
}
