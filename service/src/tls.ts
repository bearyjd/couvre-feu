import { lstatSync, readFileSync } from 'node:fs';
import { createSecureContext } from 'node:tls';
import { requirePrivatePath } from './integration-config.ts';

export interface TLSFiles { certPath: string; keyPath: string }
export interface TLSMaterial { cert: Buffer; key: Buffer }

/** Read and cross-check the certificate and key; every failure has a stable, operator-readable code. */
export function loadTLS(files: TLSFiles): TLSMaterial {
    let cert: Buffer, key: Buffer;
    try {
        const c = lstatSync(files.certPath);
        if (c.isSymbolicLink() || !c.isFile()) throw new Error('not a regular file');
        cert = readFileSync(files.certPath);
    } catch { throw new Error('tls_cert_unreadable'); }
    try { requirePrivatePath(files.keyPath, 'file'); } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        throw new Error(code === 'ENOENT' || code === 'EACCES' ? 'tls_key_unreadable' : 'tls_key_permissions');
    }
    try { key = readFileSync(files.keyPath); } catch { throw new Error('tls_key_unreadable'); }
    try { createSecureContext({cert, key}); } catch { throw new Error('tls_cert_key_invalid_or_mismatched'); }
    return {cert, key};
}

/** RFC 1918 private IPv4 or Tailscale CGNAT (100.64.0.0/10); never wildcard, loopback or public. */
export function privateListenHost(value: unknown): string {
    const m = typeof value === 'string' ? /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/.exec(value) : null;
    const o = m ? m.slice(1).map(Number) : [];
    if (!m || o.some(n => n > 255)) throw new Error('invalid_listen_host');
    const [a, b] = o;
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return value as string;
    throw new Error('listen_host_not_private');
}
