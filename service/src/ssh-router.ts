import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { validateTransportFiles } from './integration-config.ts';
import type { IntegrationConfig } from './integration-config.ts';
import { FORMAT_ONLY, normalizeEnvelope, parseObservation, requestDigest, rpcId, sha256 } from '../../shared/src/router-rpc.ts';
import type { RPCEnvelope, RPCObservation } from '../../shared/src/router-rpc.ts';
import { parseRouterActivity } from '../../shared/src/router-activity.ts';
import type { RouterActivity } from '../../shared/src/router-activity.ts';
import { RouterTransportError } from './router-transport.ts';
import type { AsyncRouter, DispatchKind, FrozenInvocation } from './router-transport.ts';

export class SSHRouter implements AsyncRouter {
    readonly config: IntegrationConfig;
    constructor(config: IntegrationConfig) { this.config = config; }
    invocation(kind: DispatchKind, envelope?: RPCEnvelope, operationId?: string): FrozenInvocation {
        const r = this.config.router;
        const argv = ['-F', '/dev/null', '-T', '-p', String(r.port), '-i', r.publicIdentity,
            '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'PreferredAuthentications=publickey', '-o', 'IdentitiesOnly=yes', '-o', `IdentityAgent=${r.agentSocket}`,
            '-o', `UserKnownHostsFile=${r.knownHosts}`, '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UpdateHostKeys=no', '-o', 'VerifyHostKeyDNS=no', '-o', 'AddKeysToAgent=no',
            '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
            '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1',
            '-o', 'LogLevel=ERROR', '--', `${r.user}@${r.host}`];
        let stdin = '', op: string | null = null, digest: string;
        if (kind === 'apply') {
            const e = normalizeEnvelope(envelope);
            if (e.generation !== r.generation) throw new RouterTransportError('generation_mismatch', 'not_delivered');
            stdin = JSON.stringify(e) + '\n'; op = e.operation_id; digest = requestDigest(e); argv.push('cfctl rpc-sync');
        } else {
            if (kind === 'receipt') op = rpcId(operationId);
            else if ((kind !== 'observe' && kind !== 'activity') || envelope !== undefined || operationId !== undefined) throw new RouterTransportError('invalid_dispatch_kind', 'not_delivered');
            argv.push(kind === 'activity' ? 'cfctl rpc-activity --json' : `cfctl rpc-status --json${op ? ' ' + op : ''}`);
            digest = sha256(`${kind}\n${r.generation}\n${op ?? ''}\n`);
        }
        return {executable: '/usr/bin/ssh', argv, stdin, deadlineMs: 15000, kind, operationId: op, requestDigest: digest};
    }
    async invoke(invocation: FrozenInvocation): Promise<RPCObservation> {
        if (invocation.kind === 'activity') throw new RouterTransportError('invalid_dispatch_kind', 'not_delivered');
        const text = await this.run(invocation);
        try { return parseObservation(text, FORMAT_ONLY); } catch { throw new RouterTransportError('invalid_router_response'); }
    }
    async invokeActivity(invocation: FrozenInvocation): Promise<RouterActivity> {
        if (invocation.kind !== 'activity') throw new RouterTransportError('invalid_dispatch_kind', 'not_delivered');
        const text = await this.run(invocation);
        try { return parseRouterActivity(text); } catch { throw new RouterTransportError('invalid_router_response'); }
    }
    private async run(invocation: FrozenInvocation): Promise<string> {
        const expected = invocation.kind === 'apply'
            ? this.invocation('apply', JSON.parse(invocation.stdin))
            : this.invocation(invocation.kind, undefined, invocation.operationId ?? undefined);
        if (JSON.stringify(invocation) !== JSON.stringify(expected)) throw new RouterTransportError('invocation_changed', 'not_delivered');
        try { validateTransportFiles(this.config); } catch { throw new RouterTransportError('private_transport_configuration_unavailable', 'not_delivered'); }
        return boundedChild(invocation.executable, invocation.argv, invocation.stdin, invocation.deadlineMs,
            {PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', SSH_AUTH_SOCK: this.config.router.agentSocket}, true);
    }
}
/** No shell, secret-bearing inherited environment, unbounded capture, or remote retry. */
export async function boundedChild(executable: string, argv: readonly string[], input: string, deadlineMs: number, env: NodeJS.ProcessEnv, allowNonzeroOutput = false): Promise<string> {
    if (Buffer.byteLength(input) > 65536 || deadlineMs < 1 || deadlineMs > 30000) throw new RouterTransportError('invalid_transport_bounds', 'not_delivered');
    return new Promise((resolve, reject) => {
        let child: ChildProcessWithoutNullStreams;
        try { child = spawn(executable, [...argv], {shell: false, stdio: ['pipe', 'pipe', 'pipe'], env}); }
        catch { reject(new RouterTransportError('ssh_spawn_failed', 'not_delivered')); return; }
        let spawned = false, done = false, size = 0, errorSize = 0;
        const output: Buffer[] = [];
        let timer: ReturnType<typeof setTimeout>;
        let killTimer: ReturnType<typeof setTimeout> | undefined;
        const fail = (code: string, delivery: 'not_delivered' | 'possible' = spawned ? 'possible' : 'not_delivered') => {
            if (done) return;
            done = true; clearTimeout(timer);
            child.kill('SIGTERM');
            killTimer = setTimeout(() => child.kill('SIGKILL'), 100);
            killTimer.unref();
            reject(new RouterTransportError(code, delivery));
        };
        timer = setTimeout(() => fail('ssh_timeout'), deadlineMs);
        child.once('spawn', () => { spawned = true; });
        child.once('error', () => fail('ssh_spawn_failed'));
        child.stdin.on('error', () => fail('ssh_input_failed'));
        child.stdout.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 131072) fail('ssh_output_limit'); else if (!done) output.push(chunk); });
        // Discard diagnostic content: remote/environment values never become HTTP errors or logs.
        child.stderr.on('data', (chunk: Buffer) => { errorSize += chunk.length; if (errorSize > 16384) fail('ssh_diagnostic_limit'); });
        child.once('close', (code, signal) => {
            clearTimeout(timer); if (killTimer) clearTimeout(killTimer);
            if (done) return;
            done = true;
            // An accepted RPC may exit nonzero because firewall application failed. Its validated receipt
            // remains useful; neither a zero nor a nonzero process exit substitutes for that witness.
            if (signal || (code !== 0 && (!allowNonzeroOutput || size === 0))) { reject(new RouterTransportError('ssh_exit_failed', spawned ? 'possible' : 'not_delivered')); return; }
            const result = Buffer.concat(output).toString('utf8');
            if (result.includes('\uFFFD')) reject(new RouterTransportError('ssh_invalid_utf8'));
            else resolve(result);
        });
        child.stdin.end(input);
    });
}
