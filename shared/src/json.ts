import { AppError } from './errors.ts';
/** Duplicate-aware bounded JSON. The router mode matches cfctl's ASCII subset. */
export function parseJSON(input: string, router = false, maxBytes = 65536): unknown {
    if (Buffer.byteLength(input) > maxBytes) {
        throw new AppError(413, 'body_too_large');
    }
    let cursor = 0, nodes = 0;
    const fail = (): never => {
        throw new AppError(400, 'invalid_json');
    };
    const whitespace = () => {
        while (/[\t\r\n ]/.test(input[cursor] ?? '!')) {
            cursor++;
        }
    };
    const string = (): string => {
        const begin = cursor++;
        if (input[begin] !== '"') {
            fail();
        }
        let escaped = false;
        while (cursor < input.length) {
            const code = input.charCodeAt(cursor), char = input[cursor++];
            if (code < 32 || (router && (code > 126 || char === '\\'))) {
                fail();
            }
            if (!escaped && char === '"') {
                try {
                    const result = JSON.parse(input.slice(begin, cursor)) as string;
                    if (result.length > (router ? 128 : 16384)) {
                        fail();
                    }
                    return result;
                }
                catch {
                    return fail();
                }
            }
            if (!escaped && char === '\\') {
                escaped = true;
            }
            else {
                escaped = false;
            }
        }
        return fail();
    };
    const value = (depth: number): unknown => {
        if (depth > 12 || ++nodes > 8192) {
            fail();
        }
        whitespace();
        const char = input[cursor];
        if (char === '"') {
            return string();
        }
        if (char === '{') {
            cursor++;
            whitespace();
            const result: Record<string, unknown> = Object.create(null);
            if (input[cursor] === '}') {
                cursor++;
                return result;
            }
            while (true) {
                whitespace();
                const key = string();
                if ((router && !/^[a-z][a-z0-9_]*$/.test(key)) || Object.hasOwn(result, key)) {
                    fail();
                }
                whitespace();
                if (input[cursor++] !== ':') {
                    fail();
                }
                result[key] = value(depth + 1);
                whitespace();
                const delimiter = input[cursor++];
                if (delimiter === '}') {
                    return result;
                }
                if (delimiter !== ',') {
                    fail();
                }
            }
        }
        if (char === '[') {
            cursor++;
            whitespace();
            const result: unknown[] = [];
            if (input[cursor] === ']') {
                cursor++;
                return result;
            }
            while (true) {
                result.push(value(depth + 1));
                whitespace();
                const delimiter = input[cursor++];
                if (delimiter === ']') {
                    return result;
                }
                if (delimiter !== ',') {
                    fail();
                }
            }
        }
        for (const [word, result] of [['true', true], ['false', false], ['null', null]] as const) {
            if (input.startsWith(word, cursor)) {
                cursor += word.length;
                return result;
            }
        }
        const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(input.slice(cursor));
        if (!number || (router && !/^(0|[1-9][0-9]*)$/.test(number[0]))) {
            return fail();
        }
        cursor += number[0].length;
        const result = Number(number[0]);
        if (!Number.isFinite(result)) {
            fail();
        }
        return result;
    };
    const result = value(0);
    whitespace();
    if (cursor !== input.length) {
        fail();
    }
    return result;
}
export function object(value: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new AppError(400, 'invalid_object');
    }
    const result = value as Record<string, unknown>;
    if (Object.keys(result).some(key => !required.includes(key) && !optional.includes(key)) || required.some(key => !Object.hasOwn(result, key))) {
        throw new AppError(400, 'invalid_fields');
    }
    return result;
}
