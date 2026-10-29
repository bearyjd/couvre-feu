import { lstatSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { object, parseJSON } from '../../shared/src/json.ts';
import { id, integer, mac, normalizePolicy } from '../../shared/src/router-schema.ts';
import type { RouterPolicy } from '../../shared/src/router-schema.ts';
import { hexDigest, sha256 } from '../../shared/src/router-rpc.ts';
import type { Role, Provenance } from '../../shared/src/contracts.ts';
import { scheduleClockReader } from './schedule-clock.ts';
import { loadTLS, privateIPv4, privateListenHost } from './tls.ts';
import type { TLSFiles } from './tls.ts';
import { ACCOUNT_LIMIT } from './account-limits.ts';

export type TimeRequestMode = 'off' | 'owner' | 'parents';
/** The mode of a config's timeRequests setting; absent is off, and the legacy {enabled} form maps true to 'parents'. */
export function timeRequestMode(setting: unknown): TimeRequestMode {
    const s = (setting ?? {}) as {mode?: TimeRequestMode; enabled?: boolean};
    return s.mode ?? (s.enabled === true ? 'parents' : 'off');
}
export interface IntegrationManifest {
    version: 1; mode: 'integration'; port: number; dataDir: string;
    origin?: string;
    tls?: TLSFiles; listen?: {host: string; port: number}; publicOrigin?: string;
    /** Plain-HTTP LAN listener behind a TLS-terminating proxy: only these exact source addresses may connect. */
    trustedProxies?: string[];
    dispatch?: {enabled: boolean; pollSeconds: number; maxBackoffSeconds: number};
    /** Child time requests are off unless enabled here: 'owner' lets only ownerAccountId decide them, 'parents' every parent account. Legacy {enabled} is read as parents/off. */
    timeRequests?: {mode: TimeRequestMode};
    /** Audit log of parent actions; absent is off. */
    auditLog?: {enabled: boolean};
    /** Reward time (F4): extra minutes added to a grant, capped with it at MAX_GRANT_MINUTES; absent is off. */
    rewardTime?: {enabled: boolean};
    /** Focus window (F5): a labelled timed pause a parent starts for 15 to 120 minutes; absent is off. */
    focus?: {enabled: boolean};
    /** DNS hardening for the kids' firewall DNS rules; absent is off. dohList merges the static public DoH resolver list into each submitted policy (docs/dns-hardening.md). */
    dnsHardening?: {dohList: boolean};
    /** The account that decides time requests in 'owner' mode; must be one of `accounts`. */
    ownerAccountId?: string;
    scheduleClock?: {timezone: string; conformance?: {utcOffsetMinutes: number; verifiedAt: number; validUntil: number; evidenceSha256: string}};
    router: {host: string; user: 'root'; port: number; knownHosts: string; hostFingerprint: string; agentSocket: string; publicIdentity: string; publicKeyFingerprint: string; generation: string};
    /** Seeds the first child and device of a fresh database; children and devices are managed in the database afterwards. */
    person: {id: string; name: string; device: {id: string; label: string; mac: string}};
    protectedMacs: string[];
    /**
     * The router installation's fixed `--rpc-allow` set (install.sh; the router does not report it over RPC). A device can
     * only be enrolled if its MAC is listed. Absent: exactly the seed device's MAC, i.e. a single-MAC installation.
     */
    routerScope?: string[];
    accounts: {id: string; displayName: string; role: Role; personIds: string[]}[];
    enrollment: RouterPolicy;
}
export interface IntegrationConfig extends IntegrationManifest {
    origin: string; host: string; manifestDigest: string; targetDigest: string; provenance: Provenance;
}
/** Matches the router's valid_protection cap (router/lib/install-common.sh); a drift test reads that file. */
export const PROTECTED_MAC_LIMIT = 128;
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
    // OpenSSH names non-default ports as [host]:port in known_hosts.
    if (!match || match[1] !== (r.port === 22 ? r.host : `[${r.host}]:${r.port}`) || fingerprint(match[3]) !== r.hostFingerprint) bad('invalid_pinned_host_key');
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
    const raw = readFileSync(path, 'utf8'), m = object(parseJSON(raw), ['version', 'mode', 'port', 'dataDir', 'router', 'person', 'protectedMacs', 'accounts', 'enrollment'], ['origin', 'dispatch', 'timeRequests', 'auditLog', 'rewardTime', 'focus', 'dnsHardening', 'ownerAccountId', 'scheduleClock', 'tls', 'listen', 'publicOrigin', 'trustedProxies', 'routerScope']);
    if (m.version !== 1 || m.mode !== 'integration' || integer(m.port) < 1024 || (m.port as number) > 65535) bad();
    const dataDir = safePath(m.dataDir); requirePrivatePath(dataDir, 'directory');
    if (dataDir === sourceTree || dataDir.startsWith(sourceTree + '/')) bad('private_database_must_be_outside_source_tree');
    const r = object(m.router, ['host', 'user', 'port', 'knownHosts', 'hostFingerprint', 'agentSocket', 'publicIdentity', 'publicKeyFingerprint', 'generation']);
    const router: IntegrationManifest['router'] = {...routerTarget(r), knownHosts: safePath(r.knownHosts), hostFingerprint: expectedFingerprint(r.hostFingerprint), agentSocket: safePath(r.agentSocket), publicIdentity: safePath(r.publicIdentity), publicKeyFingerprint: expectedFingerprint(r.publicKeyFingerprint), generation: hexDigest(r.generation)};
    const p = object(m.person, ['id', 'name', 'device']), d = object(p.device, ['id', 'label', 'mac']);
    const person = {id: id(p.id), name: text(p.name), device: {id: id(d.id), label: text(d.label), mac: mac(d.mac)}};
    if (!Array.isArray(m.protectedMacs) || !m.protectedMacs.length || m.protectedMacs.length > PROTECTED_MAC_LIMIT) bad('protected_identities_required');
    const protectedMacs = (m.protectedMacs as unknown[]).map(mac);
    if (new Set(protectedMacs).size !== protectedMacs.length || protectedMacs.includes(person.device.mac)) bad('protected_mac_overlap');
    // Seeds a fresh database only; the database is authoritative afterwards. ACCOUNT_LIMIT is a defensive bound, not a product cap.
    if (!Array.isArray(m.accounts) || !m.accounts.length || m.accounts.length > ACCOUNT_LIMIT) bad();
    const accounts = (m.accounts as unknown[]).map(v => {
        const a = object(v, ['id', 'displayName', 'role', 'personIds']);
        if (!['admin', 'parent'].includes(a.role as string) || !Array.isArray(a.personIds) || a.personIds.length !== 1 || a.personIds[0] !== person.id) bad('invalid_account_scope');
        return {id: id(a.id), displayName: text(a.displayName), role: a.role as Role, personIds: [person.id]};
    });
    if (new Set(accounts.map(a => a.id)).size !== accounts.length || !accounts.some(a => a.role === 'admin')) bad('admin_account_required');
    const routerScope = m.routerScope === undefined ? undefined : scopeList(m.routerScope, protectedMacs, person.device.mac);
    const enrollment = normalizePolicy(m.enrollment, protectedMacs);
    const lan = m.trustedProxies === undefined ? lanHTTPS(m, m.port as number) : lanProxy(m, m.port as number);
    const origin = lan ? lan.publicOrigin : m.origin === undefined ? `http://localhost:${m.port}` : privateHTTPSOrigin(m.origin);
    let dispatch: IntegrationManifest['dispatch'];
    if (m.dispatch !== undefined) {
        const settings = object(m.dispatch, ['enabled', 'pollSeconds', 'maxBackoffSeconds']);
        const pollSeconds = integer(settings.pollSeconds), maxBackoffSeconds = integer(settings.maxBackoffSeconds);
        if (typeof settings.enabled !== 'boolean' || pollSeconds < 2 || pollSeconds > 15 || maxBackoffSeconds < pollSeconds || maxBackoffSeconds > 300) bad('invalid_dispatch_bounds');
        dispatch = {enabled: settings.enabled as boolean, pollSeconds, maxBackoffSeconds};
    }
    let timeRequests: IntegrationManifest['timeRequests'];
    if (m.timeRequests !== undefined) {
        const legacy = typeof m.timeRequests === 'object' && m.timeRequests !== null && !Array.isArray(m.timeRequests) && 'enabled' in m.timeRequests;
        if (legacy) {
            const settings = object(m.timeRequests, ['enabled']);
            if (typeof settings.enabled !== 'boolean') bad('invalid_time_requests');
            timeRequests = {mode: settings.enabled ? 'parents' : 'off'};
        } else {
            const settings = object(m.timeRequests, ['mode']);
            if (!['off', 'owner', 'parents'].includes(settings.mode as string)) bad('invalid_time_requests');
            timeRequests = {mode: settings.mode as TimeRequestMode};
        }
    }
    let auditLog: IntegrationManifest['auditLog'];
    if (m.auditLog !== undefined) {
        const settings = object(m.auditLog, ['enabled']);
        if (typeof settings.enabled !== 'boolean') bad('invalid_audit_log');
        auditLog = {enabled: settings.enabled as boolean};
    }
    let focus: IntegrationManifest['focus'];
    if (m.focus !== undefined) {
        const settings = object(m.focus, ['enabled']);
        if (typeof settings.enabled !== 'boolean') bad('invalid_focus');
        focus = {enabled: settings.enabled as boolean};
    }
    let rewardTime: IntegrationManifest['rewardTime'];
    if (m.rewardTime !== undefined) {
        const settings = object(m.rewardTime, ['enabled']);
        if (typeof settings.enabled !== 'boolean') bad('invalid_reward_time');
        rewardTime = {enabled: settings.enabled as boolean};
    }
    let dnsHardening: IntegrationManifest['dnsHardening'];
    if (m.dnsHardening !== undefined) {
        const settings = object(m.dnsHardening, ['dohList']);
        if (typeof settings.dohList !== 'boolean') bad('invalid_dns_hardening');
        dnsHardening = {dohList: settings.dohList as boolean};
    }
    const ownerAccountId = m.ownerAccountId === undefined ? undefined : id(m.ownerAccountId);
    if (ownerAccountId !== undefined && !accounts.some(a => a.id === ownerAccountId)) bad('invalid_owner_account');
    if (timeRequests?.mode === 'owner' && ownerAccountId === undefined) bad('owner_account_required');
    const scheduleClock = m.scheduleClock === undefined ? undefined : normalizeScheduleClock(m.scheduleClock);
    const manifest: IntegrationManifest = {version: 1, mode: 'integration', port: m.port as number, dataDir, router, person, protectedMacs, accounts, enrollment, ...(dispatch ? {dispatch} : {}), ...(timeRequests ? {timeRequests} : {}), ...(auditLog ? {auditLog} : {}), ...(rewardTime ? {rewardTime} : {}), ...(focus ? {focus} : {}), ...(dnsHardening ? {dnsHardening} : {}), ...(ownerAccountId ? {ownerAccountId} : {}), ...(lan ?? {}), ...(scheduleClock ? {scheduleClock} : {}), ...(routerScope ? {routerScope} : {})};
    validatePilotPolicy(enrollment, manifest, false);
    validateTransportFiles(manifest);
    const targetDigest = sha256(JSON.stringify({host: router.host, user: router.user, port: router.port, hostFingerprint: router.hostFingerprint, publicKeyFingerprint: router.publicKeyFingerprint, generation: router.generation, allowedMac: person.device.mac, protectedMacs: [...protectedMacs].sort(), ...(routerScope ? {routerScope} : {})}));
    return {...manifest, origin, host: new URL(origin).host, manifestDigest: sha256(raw), targetDigest, provenance: {source: 'real-router-integration', routerCompatibilityVerified: false, integrationScope: sha256(`${targetDigest}\n${sha256(raw)}`)}};
}
/** Mirrors install.sh: 1-256 unique canonical unicast MACs, none protected; it must contain the seed device. Stored sorted. */
function scopeList(value: unknown, protectedMacs: string[], seed: string): string[] {
    if (!Array.isArray(value) || value.length < 1 || value.length > 256) bad('invalid_router_scope');
    const scope = (value as unknown[]).map(entry => { try { return mac(entry); } catch { return bad('invalid_router_scope'); } }).sort();
    if (new Set(scope).size !== scope.length || !scope.includes(seed)) bad('invalid_router_scope');
    if (scope.some(entry => protectedMacs.includes(entry))) bad('protected_mac_overlap');
    return scope;
}
/** MACs the router accepts for enrollment: the manifest routerScope, or the seed device alone. */
export const routerScopeOf = (config: Pick<IntegrationManifest, 'routerScope' | 'person'>): string[] => config.routerScope ?? [config.person.device.mac];
/** The router is a private IPv4 literal reached as root (Dropbear forced command) on an explicit port; names, tailnet and public addresses are refused. */
function routerTarget(r: Record<string, unknown>): {host: string; user: 'root'; port: number} {
    let host: string;
    try { host = privateIPv4(r.host, {allowTailnet: false}); } catch { return bad('router_target_rejected'); }
    if (r.user !== 'root' || typeof r.port !== 'number' || !Number.isInteger(r.port) || r.port < 1 || r.port > 65535) bad('router_target_rejected');
    return {host, user: 'root', port: r.port as number};
}
function listenOn(value: unknown, port: number): {host: string; port: number} {
    const l = object(value, ['host', 'port']);
    let host: string;
    try { host = privateListenHost(l.host); } catch (error) { return bad((error as Error).message); }
    if (integer(l.port) !== port) bad('listen_port_mismatch');
    return {host, port};
}
/**
 * Plain HTTP on a private address for a TLS-terminating proxy. listen, publicOrigin and trustedProxies are all required and
 * exclude tls and the loopback-proxy origin. The origin is portless because proxies forward Host without a port.
 */
function lanProxy(m: Record<string, unknown>, port: number): {listen: {host: string; port: number}; publicOrigin: string; trustedProxies: string[]} {
    if (m.listen === undefined || m.publicOrigin === undefined || m.tls !== undefined || m.origin !== undefined) bad('lan_proxy_requires_listen_public_origin_trusted_proxies');
    const listen = listenOn(m.listen, port), publicOrigin = privateHTTPSOrigin(m.publicOrigin);
    if (new URL(publicOrigin).port !== '') bad('lan_proxy_public_origin_must_be_portless');
    const proxies = m.trustedProxies;
    if (!Array.isArray(proxies) || proxies.length < 1 || proxies.length > 8) bad('invalid_trusted_proxies');
    const trustedProxies = (proxies as unknown[]).map(value => { try { return privateListenHost(value); } catch { return bad('invalid_trusted_proxies'); } });
    // A proxy on the app host itself must use the loopback-proxy origin mode instead.
    if (new Set(trustedProxies).size !== trustedProxies.length || trustedProxies.includes(listen.host)) bad('invalid_trusted_proxies');
    return {listen, publicOrigin, trustedProxies};
}
/** tls, listen and publicOrigin are all-or-nothing and exclude the proxy-mode origin; without them the service stays loopback HTTP. */
function lanHTTPS(m: Record<string, unknown>, port: number): {tls: TLSFiles; listen: {host: string; port: number}; publicOrigin: string} | undefined {
    if (m.tls === undefined && m.listen === undefined && m.publicOrigin === undefined) return undefined;
    if (m.tls === undefined || m.listen === undefined || m.publicOrigin === undefined || m.origin !== undefined) bad('lan_https_requires_tls_listen_public_origin');
    const t = object(m.tls, ['certPath', 'keyPath']), listen = listenOn(m.listen, port);
    const tls = {certPath: safePath(t.certPath), keyPath: safePath(t.keyPath)};
    loadTLS(tls);
    return {tls, listen, publicOrigin: privateHTTPSOrigin(m.publicOrigin)};
}
/** The TLS proxy owns the private network boundary; this service only binds loopback. */
export function privateHTTPSOrigin(value: unknown): string {
    if (typeof value !== 'string') bad('invalid_private_https_origin');
    let url: URL;
    try { url = new URL(value as string); } catch { return bad('invalid_private_https_origin'); }
    if (url.protocol !== 'https:' || url.origin !== value || url.username || url.password || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(url.hostname) || url.hostname.length > 253) bad('invalid_private_https_origin');
    return url.origin;
}
export function normalizeScheduleClock(value: unknown): NonNullable<IntegrationManifest['scheduleClock']> {
    const clock = object(value, ['timezone'], ['conformance']);
    if (typeof clock.timezone !== 'string' || clock.timezone.length > 128) bad('invalid_schedule_timezone');
    try {
        if (new Intl.DateTimeFormat('en-US', {timeZone: clock.timezone as string}).resolvedOptions().timeZone !== clock.timezone) bad('invalid_schedule_timezone');
    } catch { bad('invalid_schedule_timezone'); }
    if (clock.conformance === undefined) return {timezone: clock.timezone as string};
    const record = object(clock.conformance, ['utcOffsetMinutes', 'verifiedAt', 'validUntil', 'evidenceSha256']);
    const offset = record.utcOffsetMinutes, verifiedAt = integer(record.verifiedAt), validUntil = integer(record.validUntil);
    if (typeof offset !== 'number' || !Number.isInteger(offset) || offset < -840 || offset > 840 || validUntil <= verifiedAt || validUntil - verifiedAt > 7 * 86400) bad('invalid_schedule_conformance');
    const readClock = scheduleClockReader(clock.timezone as string);
    // Modern timezone transitions cannot be hidden by matching only the interval endpoints.
    // Bounded hourly samples plus the final second cover the entire admitted seven-day span.
    for (let time = verifiedAt; time < validUntil; time += 3600) {
        if (readClock(time).utcOffsetMinutes !== offset) bad('schedule_conformance_offset_changed');
    }
    if (readClock(validUntil - 1).utcOffsetMinutes !== offset) bad('schedule_conformance_offset_changed');
    return {timezone: clock.timezone as string, conformance: {utcOffsetMinutes: offset as number, verifiedAt, validUntil, evidenceSha256: hexDigest(record.evidenceSha256)}};
}
export function validatePilotPolicy(policy: RouterPolicy, config: Pick<IntegrationManifest, 'person' | 'protectedMacs' | 'enrollment' | 'scheduleClock'>, allowEmpty = true): void {
    normalizePolicy(policy, config.protectedMacs);
    if (allowEmpty && policy.people.length === 0 && policy.pauses.length === 0 && policy.schedules.length === 0) return;
    if (policy.people.length !== 1 || policy.people[0].id !== config.person.id || policy.people[0].macs.length !== 1 || policy.people[0].macs[0] !== config.person.device.mac) bad('pilot_enrollment_mismatch');
    if (policy.schedules.length > 8) bad('owner_schedule_limit');
    if (policy.schedules.length > 0 && !config.scheduleClock) bad('owner_schedule_clock_required');
    if (config.scheduleClock) normalizeScheduleClock(config.scheduleClock);
    if (JSON.stringify(normalizePolicy(policy).schedules) !== JSON.stringify(normalizePolicy(config.enrollment).schedules)) bad('owner_schedule_configuration_changed');
}
