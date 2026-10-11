import { lstatSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { object, parseJSON } from '../../shared/src/json.ts';
import { id, integer, mac, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { hexDigest, sha256 } from '../../shared/src/router-rpc.ts';
import type { Role, Provenance } from '../../shared/src/contracts.ts';

export interface IntegrationManifest {
    version: 1; mode: 'integration'; port: number; dataDir: string;
    router: {host: string; user: 'root'; port: 22; knownHosts: string; hostFingerprint: string; agentSocket: string; publicIdentity: string; publicKeyFingerprint: string; generation: string};
    person: {id: string; name: string; device: {id: string; label: string; mac: string}};
    protectedMacs: string[];
    accounts: {id: string; displayName: string; role: Role; personIds: string[]}[];
    enrollment: RouterPolicy;
}
export interface IntegrationConfig extends IntegrationManifest {
    origin: string; host: string; manifestDigest: string; targetDigest: string; provenance: Provenance;
}
const bad = (code = 'invalid_integration_manifest'): never => { throw new Error(code); };
function text(value: unknown): string {
    if (typeof value !== 'string' || value.length < 1 || value.length > 128 || /[\x00-\x1f\x7f]/.test(value)) bad();
    return value as string;
}
function safePath(value: unknown): string {
    if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value || !/^\/[A-Za-z0-9_./-]+$/.test(value)) bad('invalid_private_path');
    return value as string;
}
/** Do not repair unsafe private permissions or follow a substituted symlink. */
export function requirePrivatePath(path: string, kind: 'file' | 'directory' | 'socket'): void {
    const s = lstatSync(path);
    if (s.isSymbolicLink() || s.uid !== process.getuid?.() || (s.mode & 0o077) !== 0 || !(kind === 'file' ? s.isFile() : kind === 'directory' ? s.isDirectory() : s.isSocket())) bad('unsafe_private_path');
    // Every ancestor must resist symlink substitution and writes by other users.
    for (let p = dirname(path); ; p = dirname(p)) {
        const a = lstatSync(p);
        if (!a.isDirectory() || a.isSymbolicLink() || ((a.mode & 0o022) !== 0 && !(a.uid === 0 && (a.mode & 0o1000) !== 0))) bad('unsafe_private_ancestor');
        if (p === '/') break;
    }
}
function fingerprint(blob: string): string {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) bad('invalid_public_key');
    const data = Buffer.from(blob, 'base64');
    if (data.length < 32 || data.toString('base64').replace(/=+$/, '') !== blob.replace(/=+$/, '')) bad('invalid_public_key');
    return 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
}
function expectedFingerprint(value: unknown): string {
    if (typeof value !== 'string' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(value)) bad('invalid_key_fingerprint');
    return value as string;
}
export function validateTransportFiles(config: Pick<IntegrationManifest, 'router'>): void {
    const r = config.router;
    requirePrivatePath(r.knownHosts, 'file'); requirePrivatePath(r.publicIdentity, 'file'); requirePrivatePath(r.agentSocket, 'socket');
    const known = readFileSync(r.knownHosts, 'utf8');
    if (Buffer.byteLength(known) > 8192) bad('invalid_pinned_host_key');
    const match = /^(\S+) (ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ([A-Za-z0-9+/]+={0,2})\n?$/.exec(known);
    if (!match || match[1] !== r.host || fingerprint(match[3]) !== r.hostFingerprint) bad('invalid_pinned_host_key');
    const identity = readFileSync(r.publicIdentity, 'utf8');
    if (Buffer.byteLength(identity) > 8192) bad('invalid_public_identity');
    const key = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]*)?\n?$/.exec(identity);
    if (!key || fingerprint(key[2]) !== r.publicKeyFingerprint) bad('invalid_public_identity');
}
export function integrationConfig(path: string): IntegrationConfig {
    path = safePath(path);
    const sourceTree = fileURLToPath(new URL('../../', import.meta.url)).replace(/\/$/, '');
    if (path.startsWith(sourceTree + '/')) bad('private_manifest_must_be_outside_source_tree');
    requirePrivatePath(path, 'file'); requirePrivatePath(dirname(path), 'directory');
    const raw = readFileSync(path, 'utf8'), m = object(parseJSON(raw), ['version', 'mode', 'port', 'dataDir', 'router', 'person', 'protectedMacs', 'accounts', 'enrollment']);
    if (m.version !== 1 || m.mode !== 'integration' || integer(m.port) < 1024 || (m.port as number) > 65535) bad();
    const dataDir = safePath(m.dataDir); requirePrivatePath(dataDir, 'directory');
    if (dataDir === sourceTree || dataDir.startsWith(sourceTree + '/')) bad('private_database_must_be_outside_source_tree');
    const r = object(m.router, ['host', 'user', 'port', 'knownHosts', 'hostFingerprint', 'agentSocket', 'publicIdentity', 'publicKeyFingerprint', 'generation']);
    // The authorized pilot target is fixed; accepting arbitrary destinations would widen its scope.
    if (r.host !== '192.168.1.1' || r.user !== 'root' || r.port !== 22) bad('pilot_target_rejected');
    const router: IntegrationManifest['router'] = {host: '192.168.1.1', user: 'root', port: 22, knownHosts: safePath(r.knownHosts), hostFingerprint: expectedFingerprint(r.hostFingerprint), agentSocket: safePath(r.agentSocket), publicIdentity: safePath(r.publicIdentity), publicKeyFingerprint: expectedFingerprint(r.publicKeyFingerprint), generation: hexDigest(r.generation)};
    const p = object(m.person, ['id', 'name', 'device']), d = object(p.device, ['id', 'label', 'mac']);
    const person = {id: id(p.id), name: text(p.name), device: {id: id(d.id), label: text(d.label), mac: mac(d.mac)}};
    if (!Array.isArray(m.protectedMacs) || !m.protectedMacs.length || m.protectedMacs.length > 64) bad('protected_identities_required');
    const protectedMacs = (m.protectedMacs as unknown[]).map(mac);
    if (new Set(protectedMacs).size !== protectedMacs.length || protectedMacs.includes(person.device.mac)) bad('protected_mac_overlap');
    if (!Array.isArray(m.accounts) || !m.accounts.length || m.accounts.length > 16) bad();
    const accounts = (m.accounts as unknown[]).map(v => {
        const a = object(v, ['id', 'displayName', 'role', 'personIds']);
        if (!['admin', 'parent'].includes(a.role as string) || !Array.isArray(a.personIds) || a.personIds.length !== 1 || a.personIds[0] !== person.id) bad('invalid_account_scope');
        return {id: id(a.id), displayName: text(a.displayName), role: a.role as Role, personIds: [person.id]};
    });
    if (new Set(accounts.map(a => a.id)).size !== accounts.length || !accounts.some(a => a.role === 'admin')) bad('admin_account_required');
    const enrollment = normalizePolicy(m.enrollment, protectedMacs);
    const manifest: IntegrationManifest = {version: 1, mode: 'integration', port: m.port as number, dataDir, router, person, protectedMacs, accounts, enrollment};
    validatePilotPolicy(enrollment, manifest, false);
    validateTransportFiles(manifest);
    const targetDigest = sha256(JSON.stringify({host: router.host, user: router.user, port: router.port, hostFingerprint: router.hostFingerprint, publicKeyFingerprint: router.publicKeyFingerprint, generation: router.generation, allowedMac: person.device.mac, protectedMacs: [...protectedMacs].sort()}));
    return {...manifest, origin: `http://localhost:${manifest.port}`, host: `localhost:${manifest.port}`, manifestDigest: sha256(raw), targetDigest, provenance: {source: 'real-router-integration', routerCompatibilityVerified: false, integrationScope: sha256(`${targetDigest}\n${sha256(raw)}`)}};
}
export function validatePilotPolicy(policy: RouterPolicy, config: Pick<IntegrationManifest, 'person' | 'protectedMacs'>, allowEmpty = true): void {
    normalizePolicy(policy, config.protectedMacs);
    if (policy.schedules.length) bad('pilot_schedules_not_verified');
    if (allowEmpty && policy.people.length === 0 && policy.pauses.length === 0) return;
    if (policy.people.length !== 1 || policy.people[0].id !== config.person.id || policy.people[0].macs.length !== 1 || policy.people[0].macs[0] !== config.person.device.mac) bad('pilot_enrollment_mismatch');
}
