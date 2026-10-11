import type { Readable } from 'node:stream';
import { emptyRuntimeWitness, unavailableEmptyWitness } from '../shared/src/empty-witness.ts';
import type { EmptyWitnessReason } from '../shared/src/empty-witness.ts';

const MAX_INPUT_BYTES = 131072;
const CLI_INPUT_DEADLINE_MS = 10000;
export class WitnessInputError extends Error {
    readonly code: EmptyWitnessReason;
    constructor(code: EmptyWitnessReason) { super(code); this.code = code; }
}
/** The narrow deadline parameter permits stream fixtures; the CLI always uses the fixed ten-second limit. */
export function readWitnessInput(input: Readable, deadlineMs = CLI_INPUT_DEADLINE_MS): Promise<string> {
    if (!Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > CLI_INPUT_DEADLINE_MS) return Promise.reject(new WitnessInputError('input_unavailable'));
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = []; let length = 0, finished = false;
        const cleanup = () => {
            clearTimeout(timer); input.off('data', onData); input.off('end', onEnd); input.off('error', onError); input.off('close', onClose);
        };
        const fail = (code: EmptyWitnessReason) => {
            if (finished) return; finished = true; cleanup(); input.destroy(); reject(new WitnessInputError(code));
        };
        const onData = (part: Buffer | string) => {
            const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
            length += chunk.length;
            if (length > MAX_INPUT_BYTES) { fail('input_limit'); return; }
            for (const byte of chunk) if (!(byte === 9 || byte === 10 || byte === 13 || byte >= 32 && byte <= 126)) { fail('input_not_ascii'); return; }
            chunks.push(chunk);
        };
        const onEnd = () => { if (finished) return; finished = true; cleanup(); resolve(Buffer.concat(chunks).toString('ascii')); };
        const onError = () => fail('input_unavailable');
        const onClose = () => fail('input_unavailable');
        const timer = setTimeout(() => fail('input_deadline'), deadlineMs);
        input.on('data', onData); input.once('end', onEnd); input.once('error', onError); input.once('close', onClose);
    });
}
if (import.meta.main) {
    const [generation, min, max] = process.argv.slice(2);
    let outcome;
    if (process.argv.length !== 5 || generation?.length !== 64 || !/^[a-f0-9]{64}$/.test(generation ?? '') || !/^[1-9][0-9]{0,9}$/.test(min ?? '') || !/^[1-9][0-9]{0,9}$/.test(max ?? '') || String(Number(min)) !== min || String(Number(max)) !== max) {
        process.stdin.destroy(); outcome = unavailableEmptyWitness('invalid_context');
    } else {
        try {
            const raw = await readWitnessInput(process.stdin);
            outcome = emptyRuntimeWitness(raw, {expectedGeneration: generation, minRouterTime: Number(min), maxRouterTime: Number(max)});
        } catch (error) {
            outcome = unavailableEmptyWitness(error instanceof WitnessInputError ? error.code : 'input_unavailable');
        }
    }
    process.stdout.write(JSON.stringify(outcome) + '\n');
    process.exitCode = outcome.verdict === 'PASS_EMPTY_WITNESS' ? 0 : 1;
}
