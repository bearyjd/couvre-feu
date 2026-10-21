import { createHash } from 'node:crypto';
import { object, parseJSON } from './json.ts';
import { integer, id, mac, normalizePolicy, healthyConfirmation, effectivePauses, MAX_ALLOWANCE_SECONDS } from './router-schema.ts';
import type { RouterPolicy, RouterStatus, Pause, Allowance, EffectiveAllowance } from './router-schema.ts';

export const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const invalid = (): never => { throw new Error('invalid_router_rpc'); };
export function rpcId(value: unknown): string {
    if (typeof value !== 'string' || !/^[a-z0-9_-]{1,64}$/.test(value) || value === '-') invalid();
    return value as string;
}
export function hexDigest(value: unknown): string {
    if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) invalid();
    return value as string;
}
/** Matches LC_ALL=C cf_canonical, including placeholder people and one trailing LF. */
export function canonicalPolicyRecords(input: RouterPolicy): string {
    const p = normalizePolicy(input), rows: string[] = [];
    for (const person of p.people) for (const m of person.macs.length ? person.macs : ['-']) rows.push(`P\t${person.id}\t${m}`);
    for (const pause of p.pauses) rows.push(`A\t${pause.person}\t${pause.until}`);
    for (const allowance of p.allowances ?? []) rows.push(`U\t${allowance.person}\t${allowance.until}`);
    for (const s of p.schedules) rows.push(`S\t${s.person}\t${s.id}\t${s.weekdays.join(',')}\t${s.start}\t${s.stop}`);
    for (const ip of p.doh.ipv4) rows.push(`D4\t${ip}`);
    for (const ip of p.doh.ipv6) rows.push(`D6\t${ip}`);
    return [`V\t1`, `R\t${p.revision}`, ...rows.sort()].join('\n') + '\n';
}
export const policyDigest = (p: RouterPolicy) => sha256(canonicalPolicyRecords(p));
export interface RPCEnvelope {
    rpc_version: 1; generation: string; operation_id: string;
    expected_revision: number; expected_digest: string; policy: RouterPolicy;
}
export function normalizeEnvelope(value: unknown): RPCEnvelope {
    const e = object(value, ['rpc_version', 'generation', 'operation_id', 'expected_revision', 'expected_digest', 'policy']);
    if (e.rpc_version !== 1) invalid();
    const policy = normalizePolicy(e.policy), expected = integer(e.expected_revision);
    if (policy.revision !== expected + 1) invalid();
    const result: RPCEnvelope = { rpc_version: 1, generation: hexDigest(e.generation), operation_id: rpcId(e.operation_id), expected_revision: expected, expected_digest: hexDigest(e.expected_digest), policy };
    parseJSON(JSON.stringify(result), true);
    return result;
}
export function requestDigest(input: RPCEnvelope): string {
    const e = normalizeEnvelope(input);
    return sha256(`rpc1\n${e.generation}\n${e.operation_id}\n${e.expected_revision}\n${e.expected_digest}\n${policyDigest(e.policy)}\n`);
}
export interface RPCReceipt {
    operationId: string; requestDigest: string; baseRevision: number; baseDigest: string;
    acceptedRevision: number; acceptedDigest: string; outcome: 'accepted'; current: boolean;
}
export interface RPCObservation {
    rpc_version: 1; generation: string; acceptedPolicy: RouterPolicy; policyDigest: string;
    currentOperationId: string | null; routerTime: number; receipt: RPCReceipt | null;
    status: RouterStatus; errors: string[];
    /** Live router scope (rpc-allowed) and its digest. Absent from old routers, and then only the manifest floor is known. */
    scope?: string[]; scopeSha?: string;
}
export const MAX_SCOPE = 256;
/** Matches the router's snapshot digest: the LC_ALL=C ascending list, one MAC per line, one trailing LF. */
export const scopeDigest = (scope: readonly string[]) => sha256(scope.join('\n') + '\n');
/** What only the service's manifest knows: the protected MACs and the install-time scope floor. */
export interface ScopeContext { protectedMacs?: readonly string[]; floor?: readonly string[] }
/** Explicitly no manifest: the router's format is checked but the protected-disjoint and floor-superset rules are not. Only for a first pass that a manifest-aware second pass follows. */
export const FORMAT_ONLY: ScopeContext = Object.freeze({});
function scopeFields(o: Record<string, unknown>, policy: RouterPolicy, context: ScopeContext): {scope: string[]; scopeSha: string} | null {
    const hasScope = o.scope !== undefined, hasSha = o.scopeSha !== undefined;
    if (hasScope !== hasSha) invalid();
    if (!hasScope) return null;
    if (!Array.isArray(o.scope) || o.scope.length < 1 || o.scope.length > MAX_SCOPE) invalid();
    const scope = (o.scope as unknown[]).map(entry => { try { return mac(entry); } catch { return invalid(); } });
    // Strictly ascending in byte order means canonical, sorted and unique at once.
    if (scope.some((entry, i) => i > 0 && !(scope[i - 1] < entry))) invalid();
    const scopeSha = hexDigest(o.scopeSha);
    if (scopeSha !== scopeDigest(scope)) invalid();
    const members = new Set(scope);
    if ((context.protectedMacs ?? []).some(entry => members.has(entry))) invalid();
    if ((context.floor ?? []).some(entry => !members.has(entry))) invalid();
    if (policy.people.some(person => person.macs.some(entry => !members.has(entry)))) invalid();
    return {scope, scopeSha};
}
function bool(value: unknown): boolean { if (typeof value !== 'boolean') invalid(); return value as boolean; }
function strings(value: unknown, max = 256): string[] {
    if (!Array.isArray(value) || value.length > max || value.some(v => typeof v !== 'string' || v.length > 128 || !/^[\x20-\x7e]*$/.test(v))) invalid();
    return value as string[];
}
function pauses(value: unknown): Pause[] {
    if (!Array.isArray(value) || value.length > 64) invalid();
    const result = (value as unknown[]).map(v => { const p = object(v, ['person', 'until']); return {person: id(p.person), until: integer(p.until)}; });
    if (new Set(result.map(p => p.person)).size !== result.length) invalid();
    return result;
}
function allowances(value: unknown): Allowance[] {
    if (!Array.isArray(value) || value.length > 64) invalid();
    const result = (value as unknown[]).map(v => { const a = object(v, ['person', 'until']); return {person: id(a.person), until: integer(a.until)}; });
    if (new Set(result.map(a => a.person)).size !== result.length || result.some(a => a.until < 1)) invalid();
    return result;
}
function effectiveAllowanceList(value: unknown): EffectiveAllowance[] {
    if (!Array.isArray(value) || value.length > 64) invalid();
    const result = (value as unknown[]).map(v => { const a = object(v, ['person', 'until', 'remaining']); return {person: id(a.person), until: integer(a.until), remaining: integer(a.remaining)}; });
    if (new Set(result.map(a => a.person)).size !== result.length || result.some(a => a.until < 1 || a.remaining < 1 || a.remaining > MAX_ALLOWANCE_SECONDS)) invalid();
    return result;
}
export function normalizeObservation(value: unknown, context: ScopeContext): RPCObservation {
    const o = object(value, ['rpc_version', 'generation', 'acceptedPolicy', 'policyDigest', 'currentOperationId', 'routerTime', 'receipt', 'status', 'errors'], ['scope', 'scopeSha']);
    if (o.rpc_version !== 1) invalid();
    const policy = normalizePolicy(o.acceptedPolicy), digest = hexDigest(o.policyDigest), time = integer(o.routerTime);
    if (digest !== policyDigest(policy)) invalid();
    const current = o.currentOperationId === null ? null : rpcId(o.currentOperationId);
    let receipt: RPCReceipt | null = null;
    if (o.receipt !== null) {
        const r = object(o.receipt, ['operationId', 'requestDigest', 'baseRevision', 'baseDigest', 'acceptedRevision', 'acceptedDigest', 'outcome', 'current']);
        if (r.outcome !== 'accepted') invalid();
        receipt = {operationId: rpcId(r.operationId), requestDigest: hexDigest(r.requestDigest), baseRevision: integer(r.baseRevision), baseDigest: hexDigest(r.baseDigest), acceptedRevision: integer(r.acceptedRevision), acceptedDigest: hexDigest(r.acceptedDigest), outcome: 'accepted', current: bool(r.current)};
        if (receipt.acceptedRevision !== receipt.baseRevision + 1 || receipt.current !== (current === receipt.operationId && receipt.acceptedRevision === policy.revision && receipt.acceptedDigest === digest)) invalid();
    }
    const s = object(o.status, ['ok', 'desiredRevision', 'confirmedRevision', 'desiredPauses', 'effectivePauses', 'observed', 'drift', 'capabilities', 'errors'], ['desiredAllowances', 'effectiveAllowances']);
    const seen = object(s.observed, ['kids', 'paused']), caps = object(s.capabilities, ['ipv6', 'conntrack', 'nativeKernelConfirmed', 'addressCoverageComplete', 'routerCompatibilityVerified']);
    if (caps.routerCompatibilityVerified !== false) invalid();
    const kids = strings(seen.kids).map(mac), paused = strings(seen.paused).map(mac);
    if (new Set(kids).size !== kids.length || new Set(paused).size !== paused.length) invalid();
    const status: RouterStatus = {ok: bool(s.ok), desiredRevision: integer(s.desiredRevision), confirmedRevision: s.confirmedRevision === null ? null : integer(s.confirmedRevision), desiredPauses: pauses(s.desiredPauses), effectivePauses: pauses(s.effectivePauses), ...(s.desiredAllowances === undefined ? {} : {desiredAllowances: allowances(s.desiredAllowances)}), ...(s.effectiveAllowances === undefined ? {} : {effectiveAllowances: effectiveAllowanceList(s.effectiveAllowances)}), observed: {kids, paused}, drift: bool(s.drift), errors: strings(s.errors, 64), capabilities: {ipv6: bool(caps.ipv6), conntrack: bool(caps.conntrack), nativeKernelConfirmed: bool(caps.nativeKernelConfirmed), addressCoverageComplete: bool(caps.addressCoverageComplete), routerCompatibilityVerified: false}};
    if (status.desiredRevision !== policy.revision || JSON.stringify(status.desiredPauses) !== JSON.stringify(policy.pauses)) invalid();
    // Status lists follow canonical policy order; an allowance absent from the accepted policy is fabricated.
    if (s.desiredAllowances !== undefined && JSON.stringify(status.desiredAllowances) !== JSON.stringify(policy.allowances ?? [])) invalid();
    if ((status.effectiveAllowances ?? []).some(a => !(policy.allowances ?? []).some(d => d.person === a.person && d.until === a.until))) invalid();
    // A failed clock/status read may report no effective pauses; it cannot grant health.
    if (status.ok && JSON.stringify(status.effectivePauses) !== JSON.stringify(effectivePauses(policy, time))) invalid();
    const scope = scopeFields(o, policy, context);
    return {rpc_version: 1, generation: hexDigest(o.generation), acceptedPolicy: policy, policyDigest: digest, currentOperationId: current, routerTime: time, receipt, status, errors: strings(o.errors, 64), ...(scope ?? {})};
}
export function parseObservation(text: string, context: ScopeContext): RPCObservation {
    return normalizeObservation(parseJSON(text, false, 131072), context);
}
export function exactReceipt(o: RPCObservation, e: RPCEnvelope): boolean {
    const r = o.receipt;
    return o.generation === e.generation && r !== null && r.operationId === e.operation_id && r.requestDigest === requestDigest(e) && r.baseRevision === e.expected_revision && r.baseDigest === e.expected_digest && r.acceptedRevision === e.policy.revision && r.acceptedDigest === policyDigest(e.policy);
}
export function exactHealthy(o: RPCObservation, e: RPCEnvelope): boolean {
    return exactReceipt(o, e) && o.receipt!.current && o.currentOperationId === e.operation_id && o.policyDigest === policyDigest(e.policy) && o.errors.length === 0 && healthyConfirmation(o.status, e.policy, o.routerTime);
}
