import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const PLACEHOLDER = "'cf-shell-dev'";

export interface BuiltServiceWorker {
    readonly name: string;
    readonly source: string;
}

/**
 * Reads sw.js plus every file its ASSETS list names, hashes them, and returns sw.js with the placeholder cache name
 * replaced by `cf-shell-<hash>[-<variant>]`. Any changed shipped byte therefore renames the cache; PRs never bump it.
 * `served` maps each file's bytes to the bytes the server actually serves, so the hash covers those. Throws (never hashes fewer files) when an asset is unreadable or sw.js has no placeholder or no ASSETS list.
 */
export function buildServiceWorker(publicDir: string, variant?: string, served: (file: string, bytes: Buffer) => Buffer = (_file, bytes) => bytes): BuiltServiceWorker {
    const source = readFileSync(join(publicDir, 'sw.js'), 'utf8');
    if (source.split(PLACEHOLDER).length !== 2) {
        throw new Error(`sw.js must contain the cache-name placeholder ${PLACEHOLDER} exactly once`);
    }
    const list = /const ASSETS = \[([^\]]*)\]/.exec(source);
    const assets = list ? [...list[1].matchAll(/'(\/[^']*)'/g)].map((match) => match[1]).sort() : [];
    if (assets.length === 0) {
        throw new Error('sw.js ASSETS list not found or empty');
    }
    const hash = createHash('sha256').update(source);
    for (const asset of assets) {
        const file = asset === '/' ? 'index.html' : asset.slice(1);
        let bytes: Buffer;
        try {
            bytes = readFileSync(join(publicDir, file));
        } catch (error) {
            throw new Error(`service worker asset ${asset} (web/public/${file}) is unreadable: ${(error as Error).message}`);
        }
        hash.update(`\0${asset}\0`).update(served(file, bytes));
    }
    const name = `cf-shell-${hash.digest('hex').slice(0, 10)}${variant ? `-${variant}` : ''}`;
    return {name, source: source.replace(PLACEHOLDER, `'${name}'`)};
}
