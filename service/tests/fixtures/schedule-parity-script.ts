import { integrationFixture } from './integration.ts';
import { RouterTransportError } from '../../src/router-transport.ts';

// Flag-off parity script for the schedule settlement core (roadmap item 2, S2a; schedules.editable, off; unverified on this router).
// It uses only actions and fixture calls that exist on main, so the golden dump (schedule-parity-golden.json) was generated at main
// with exactly this file and must still match byte for byte with the flag absent or false.
export type ParityFlag = 'absent' | false | true;
export type ParityFixture = ReturnType<typeof integrationFixture>;
export const GOLDEN_FILE = new URL('./schedule-parity-golden.json', import.meta.url);

/** A fixture with the schedules key absent, false or true (no default: every caller names it) and a schedule clock. */
export function parityFixture(flag: ParityFlag): ParityFixture {
    const f = integrationFixture(flag === 'absent' ? {} : {schedules: {editable: flag}});
    (f.config as {scheduleClock?: unknown}).scheduleClock = {timezone: 'UTC'};
    return f;
}
export async function applyOp(f: ParityFixture, id: string): Promise<void> { const plan = f.worker.prepare('apply', id); await f.worker.execute(plan, plan.scriptSha256); }
export async function receiptOp(f: ParityFixture, id: string): Promise<void> { const plan = f.worker.prepare('receipt', id); await f.worker.execute(plan, plan.scriptSha256); }
/** Pause, apply with the reply lost after the router accepted it, then read the receipt. Returns the pause operation id. */
export async function pauseLostReplyReceipt(f: ParityFixture): Promise<string> {
    await f.observe();
    const id = f.pause(f.now() + 600).result.operation.id;
    f.router.afterApplyFailure = new RouterTransportError('test_lost_response');
    await applyOp(f, id);
    f.router.afterApplyFailure = null;
    f.advance(5);
    await receiptOp(f, id);
    return id;
}
