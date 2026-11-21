import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { storeDump } from './fixtures/integration.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { scheduleSeam } from '../src/integration-schedule-settle.ts';
import { GOLDEN_FILE, applyOp, pauseLostReplyReceipt, receiptOp } from './fixtures/schedule-parity-script.ts';
import type { ParityFlag } from './fixtures/schedule-parity-script.ts';
import { night, op, queue, world } from './fixtures/schedule-settle.ts';

// Flag-off parity for the schedule settlement core (roadmap item 2, S2a; schedules.editable, off; unverified on this router).
// Golden: the pause segment's dump was generated at main (ab561b8) and must match exactly. Then an inserted schedule_update goes
// through apply, lost reply and receipt read: absent and false must store the same rows, true (the positive control) must not.
interface Run { golden: string; dump: string; state: string; decisions: number }
async function script(flag: ParityFlag): Promise<Run> {
    const f = world(flag), spy = mock.method(scheduleSeam, 'decideSchedule');
    try {
        await pauseLostReplyReceipt(f);
        const golden = storeDump(f.store);
        f.advance(5); await f.observe();
        const id = queue(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response'); await applyOp(f, id); f.router.afterApplyFailure = null;
        f.advance(5); await receiptOp(f, id);
        return {golden, dump: storeDump(f.store), state: op(f, id).state, decisions: spy.mock.callCount()};
    } finally { spy.mock.restore(); f.cleanup(); }
}

test('flag off (key absent or false): main\'s rows exactly, the same rows for both, and the settlement core never runs', async () => {
    const golden = readFileSync(GOLDEN_FILE, 'utf8');
    const absent = await script('absent'), off = await script(false);
    assert.equal(absent.golden + '\n', golden); assert.equal(off.golden + '\n', golden);
    assert.equal(absent.dump, off.dump);
    assert.equal(absent.state, 'unknown'); assert.equal(off.state, 'unknown');
    assert.equal(absent.decisions, 0); assert.equal(off.decisions, 0);
});
test('positive control: the same script with the flag on settles the schedule operation and stores different rows', async () => {
    const off = await script(false), on = await script(true);
    assert.equal(on.state, 'confirmed'); assert.ok(on.decisions > 0);
    assert.notDeepEqual(on.dump, off.dump);
});
