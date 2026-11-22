import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { storeDump } from './fixtures/integration.ts';
import { RouterTransportError } from '../src/router-transport.ts';
import { scheduleSeam } from '../src/integration-schedule-settle.ts';
import { childrenSeam } from '../src/integration-children.ts';
import { GOLDEN_FILE, pauseLostReplyReceipt } from './fixtures/schedule-parity-script.ts';
import type { ParityFlag } from './fixtures/schedule-parity-script.ts';
import { apply, insertScheduleOp, night, op, receipt, world } from './fixtures/schedule-settle.ts';

// Flag-off parity for S2a (roadmap item 2; schedules.editable, off; unverified on this router). The pause segment's dump was generated at
// main ab561b8 and must match exactly. Then an inserted schedule_update goes through apply, lost reply and receipt read: absent and false
// must store the same rows and never run the schedule builder or settlement; true (the positive control) must differ and run both.
interface Run { golden: string; dump: string; state: string; decisions: number; builds: number }
async function script(flag: ParityFlag): Promise<Run> {
    const f = world(flag), decide = mock.method(scheduleSeam, 'decideSchedule'), build = mock.method(childrenSeam, 'withScheduleWindows');
    try {
        await pauseLostReplyReceipt(f);
        const golden = storeDump(f.store);
        f.advance(5); await f.observe();
        const id = insertScheduleOp(f, [night]);
        f.router.afterApplyFailure = new RouterTransportError('test_lost_response'); await apply(f, id); f.router.afterApplyFailure = null;
        f.advance(5); await receipt(f, id);
        return {golden, dump: storeDump(f.store), state: op(f, id).state, decisions: decide.mock.callCount(), builds: build.mock.callCount()};
    } finally { decide.mock.restore(); build.mock.restore(); f.cleanup(); }
}

test('flag off (key absent or false): main\'s rows exactly, the same rows for both, and the schedule builder and settlement never run', async () => {
    const golden = readFileSync(GOLDEN_FILE, 'utf8');
    const absent = await script('absent'), off = await script(false);
    assert.equal(absent.golden + '\n', golden); assert.equal(off.golden + '\n', golden);
    assert.equal(absent.dump, off.dump);
    assert.equal(absent.state, 'unknown'); assert.equal(off.state, 'unknown');
    assert.deepEqual([absent.decisions, absent.builds, off.decisions, off.builds], [0, 0, 0, 0]);
});
test('positive control: the same script with the flag on settles the schedule operation, stores different rows and runs both', async () => {
    const off = await script(false), on = await script(true);
    assert.equal(on.state, 'confirmed'); assert.ok(on.decisions > 0); assert.ok(on.builds > 0);
    assert.notDeepEqual(on.dump, off.dump);
});
