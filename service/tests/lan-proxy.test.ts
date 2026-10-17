import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { connect, createServer as netServer } from 'node:net';
import { request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { integrationConfig } from '../src/integration-config.ts';
import { privateIPv4 } from '../src/tls.ts';
import { Auth, digest } from '../src/auth.ts';
import { appServer, remoteIPv4 } from '../src/http.ts';
import { SSHRouter } from '../src/ssh-router.ts';
import { sha256 } from '../../shared/src/router-rpc.ts';
import { integrationFixture, testConfig } from './fixtures/integration.ts';

const NAME = 'cf.example.invalid';
/** targetDigest of the standard 192.168.1.1/root/22 test manifest, recorded before router targets became configurable. */
const V1_TARGET_DIGEST = 'bf5cb3dcab27c1d474d7778bd3bf10885cf4aefdb90bf8f4c71dfcbb0c3d7dc7';

async function manifestFixture() {
    const dir = mkdtempSync(join(tmpdir(), 'cf-lan-proxy-config-')), sample = testConfig(dir), socket = netServer();
    socket.listen(sample.router.agentSocket); await once(socket, 'listening'); chmodSync(sample.router.agentSocket, 0o600);
    const data = Buffer.concat([Buffer.from([0,0,0,11]), Buffer.from('ssh-ed25519'), Buffer.from([0,0,0,32]), Buffer.alloc(32, 1)]), blob = data.toString('base64'), fp = 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
    const pin = (first: string) => writeFileSync(sample.router.knownHosts, `${first} ssh-ed25519 ${blob}\n`, {mode: 0o600});
    pin('192.168.1.1');
    writeFileSync(sample.router.publicIdentity, `ssh-ed25519 ${blob} test-public-key\n`, {mode: 0o600});
    const {origin: _o, host: _h, manifestDigest: _m, targetDigest: _t, provenance: _p, ...manifest} = sample;
    manifest.router.hostFingerprint = fp; manifest.router.publicKeyFingerprint = fp;
    const path = join(dir, 'manifest.json'), save = (value: unknown) => writeFileSync(path, JSON.stringify(value), {mode: 0o600});
    const close = async () => { socket.close(); await once(socket, 'close'); rmSync(dir, {recursive: true, force: true}); };
    return {dir, manifest, path, save, pin, close};
}

test('v1 manifests keep their exact manifest and target digests (DB binding unchanged)', async () => {
    const f = await manifestFixture();
    try {
        f.save(f.manifest); const c = integrationConfig(f.path);
        assert.equal(c.manifestDigest, sha256(readFileSync(f.path, 'utf8')));
        assert.equal(c.targetDigest, V1_TARGET_DIGEST);
        assert.deepEqual(c.router.host, '192.168.1.1'); assert.equal(c.router.port, 22); assert.equal(c.trustedProxies, undefined);
    } finally { await f.close(); }
});

test('private IPv4 validator: tailnet only when allowed; never loopback, wildcard, public, CIDR, IPv6 or names', () => {
    for (const ok of ['10.0.0.5', '172.16.0.1', '172.31.255.1', '192.168.0.9']) { assert.equal(privateIPv4(ok, {allowTailnet: false}), ok); assert.equal(privateIPv4(ok, {allowTailnet: true}), ok); }
    assert.equal(privateIPv4('100.64.0.1', {allowTailnet: true}), '100.64.0.1');
    assert.throws(() => privateIPv4('100.64.0.1', {allowTailnet: false}), /listen_host_not_private/);
    for (const bad of ['0.0.0.0', '127.0.0.1', '192.0.2.10', '198.51.100.7', '169.254.1.1', '10.0.0.0/8', '10.0.0.5:22', '::ffff:10.0.0.5', 'fd00::1', 'router.example.invalid', '', 7, null]) assert.throws(() => privateIPv4(bad, {allowTailnet: true}), /invalid_listen_host|listen_host_not_private/, String(bad));
});

test('lan-proxy mode (listen + publicOrigin + trustedProxies, no tls) is strictly validated and exclusive', async () => {
    const f = await manifestFixture(), m = f.manifest;
    const proxy = {listen: {host: '10.0.0.20', port: m.port}, publicOrigin: `https://${NAME}`, trustedProxies: ['10.0.0.30']};
    const refuse = (changed: Record<string, unknown>, code: RegExp) => { f.save({...m, ...proxy, ...changed}); assert.throws(() => integrationConfig(f.path), code, JSON.stringify(changed)); };
    try {
        f.save({...m, ...proxy}); const c = integrationConfig(f.path);
        assert.equal(c.origin, `https://${NAME}`); assert.equal(c.host, NAME); assert.deepEqual(c.listen, proxy.listen);
        assert.deepEqual(c.trustedProxies, ['10.0.0.30']); assert.equal(c.tls, undefined);
        f.save({...m, ...proxy, trustedProxies: ['172.16.4.2', '100.100.1.2', '10.0.0.31']}); assert.deepEqual(integrationConfig(f.path).trustedProxies, ['172.16.4.2', '100.100.1.2', '10.0.0.31']);
        f.save({...m, ...proxy, listen: {host: '100.101.102.103', port: m.port}}); assert.equal(integrationConfig(f.path).listen?.host, '100.101.102.103');
        // trustedProxies: exact private IPv4 literals only.
        for (const trustedProxies of [[], ['192.0.2.10'], ['198.51.100.7'], ['127.0.0.1'], ['0.0.0.0'], ['10.0.0.0/24'], ['::ffff:10.0.0.30'], ['fd00::1'], ['npm.example.invalid'], ['10.0.0.30', '10.0.0.30'], ['10.0.0.20'], [10], Array.from({length: 9}, (_, i) => `10.0.1.${i + 1}`), '10.0.0.30', null, {}]) refuse({trustedProxies}, /invalid_trusted_proxies/);
        // publicOrigin must be a portless https name without credentials, path, query or fragment.
        for (const publicOrigin of [`https://${NAME}:8443`, `https://${NAME}:443`, `https://${NAME}/path`, `https://user:pw@${NAME}`, `https://${NAME}?q`, `https://${NAME}#f`, `http://${NAME}`, 'https://10.0.0.20', 'https://localhost']) refuse({publicOrigin}, /invalid_private_https_origin|lan_proxy_public_origin_must_be_portless/);
        refuse({publicOrigin: `https://${NAME}:8443`}, /lan_proxy_public_origin_must_be_portless/);
        // listen host/port rules are the same as LAN HTTPS.
        refuse({listen: {host: '192.0.2.20', port: m.port}}, /listen_host_not_private/);
        refuse({listen: {host: '127.0.0.1', port: m.port}}, /listen_host_not_private/);
        refuse({listen: {host: '10.0.0.20', port: m.port + 1}}, /listen_port_mismatch/);
        // Mode exclusivity.
        const code = /lan_proxy_requires_listen_public_origin_trusted_proxies/;
        refuse({tls: {certPath: join(f.dir, 'a.crt'), keyPath: join(f.dir, 'a.key')}}, code);
        refuse({origin: `https://${NAME}`}, code);
        refuse({listen: undefined}, code);
        refuse({publicOrigin: undefined}, code);
        f.save({...m, trustedProxies: ['10.0.0.30']}); assert.throws(() => integrationConfig(f.path), code);
        f.save({...m, origin: `https://${NAME}`, trustedProxies: ['10.0.0.30']}); assert.throws(() => integrationConfig(f.path), code);
        // Without trustedProxies, listen + publicOrigin alone remain an incomplete LAN HTTPS manifest.
        f.save({...m, listen: proxy.listen, publicOrigin: proxy.publicOrigin}); assert.throws(() => integrationConfig(f.path), /lan_https_requires_tls_listen_public_origin/);
    } finally { await f.close(); }
});

test('router target accepts private IPv4/root/1..65535 with [host]:port known_hosts and rejects everything else', async () => {
    const f = await manifestFixture(), m = f.manifest;
    const target = (router: Record<string, unknown>) => ({...m, router: {...m.router, ...router}});
    try {
        f.pin('[10.0.0.1]:2222'); f.save(target({host: '10.0.0.1', port: 2222}));
        const c = integrationConfig(f.path); assert.equal(c.router.host, '10.0.0.1'); assert.equal(c.router.port, 2222);
        f.pin('172.16.0.1'); f.save(target({host: '172.16.0.1'})); assert.equal(integrationConfig(f.path).router.host, '172.16.0.1');
        // known_hosts form must follow the port exactly.
        f.pin('10.0.0.1'); f.save(target({host: '10.0.0.1', port: 2222})); assert.throws(() => integrationConfig(f.path), /invalid_pinned_host_key/);
        f.pin('[10.0.0.1]:22'); f.save(target({host: '10.0.0.1', port: 22})); assert.throws(() => integrationConfig(f.path), /invalid_pinned_host_key/);
        f.pin('[10.0.0.1]:2223'); f.save(target({host: '10.0.0.1', port: 2222})); assert.throws(() => integrationConfig(f.path), /invalid_pinned_host_key/);
        for (const router of [{host: '192.0.2.1'}, {host: '198.51.100.1'}, {host: '100.64.0.1'}, {host: '127.0.0.1'}, {host: 'router.example.invalid'}, {host: 'fd00::1'}, {host: '10.0.0.1:22'}, {host: ''},
            {user: 'admin'}, {user: 'Root'}, {user: ''}, {port: 0}, {port: 70000}, {port: 65536}, {port: -22}, {port: 22.5}, {port: '22'}, {port: null}])
        { f.save(target(router)); assert.throws(() => integrationConfig(f.path), /router_target_rejected/, JSON.stringify(router)); }
    } finally { await f.close(); }
});

test('SSH argv takes -p and user@host from the validated manifest target', () => {
    const c = testConfig('/tmp/cf-no-agent-test');
    const standard = new SSHRouter(c).invocation('observe');
    assert.deepEqual(standard.argv.slice(3, 5), ['-p', '22']); assert.equal(standard.argv.at(-2), 'root@192.168.1.1');
    const moved = new SSHRouter({...c, router: {...c.router, host: '10.0.0.1', port: 2222}}).invocation('observe');
    assert.deepEqual(moved.argv.slice(3, 5), ['-p', '2222']); assert.equal(moved.argv.at(-2), 'root@10.0.0.1');
    assert.equal(moved.argv.filter(a => a === '-p').length, 1);
});

test('remote address normalization strips only the IPv4-mapped prefix', () => {
    assert.equal(remoteIPv4('::ffff:10.0.0.30'), '10.0.0.30');
    assert.equal(remoteIPv4('10.0.0.30'), '10.0.0.30');
    assert.equal(remoteIPv4('::1'), '::1');
    assert.equal(remoteIPv4(undefined), undefined);
});

type Reply = {status: number; headers: Record<string, string | string[] | undefined>; body: string};
function call(port: number, path: string, headers: Record<string, string>, body?: string): Promise<Reply> {
    return new Promise((resolve, reject) => {
        const req = httpRequest({host: '127.0.0.1', port, path, method: body === undefined ? 'GET' : 'POST', headers, agent: false}, res => {
            const chunks: Buffer[] = []; res.on('data', c => chunks.push(c));
            res.on('end', () => resolve({status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString('utf8')}));
        });
        req.on('error', reject); req.end(body);
    });
}
async function proxyServer(trustedProxies: string[]) {
    const f = integrationFixture(), probe = netServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const port = (probe.address() as {port: number}).port; probe.close(); await once(probe, 'close');
    const origin = `https://${NAME}`, host = NAME;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'LAN proxy test'});
    // appServer receives the already-validated config; loopback stands in for the proxy source address here.
    const server = appServer(auth, f.policy, {...f.config, port, origin, host, trustedProxies});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    const close = async () => { server.close(); server.closeAllConnections(); await once(server, 'close'); f.cleanup(); };
    return {f, port, origin, host, server, close};
}

test('lan-proxy HTTP destroys connections from any non-allowlisted source before reading a request', async () => {
    const s = await proxyServer(['10.0.0.30']);
    try {
        const socket = connect(s.port, '127.0.0.1'); let received = 0;
        socket.on('data', chunk => { received += chunk.length; });
        // A reset is expected; only the absence of response bytes matters.
        const closed = new Promise<void>(resolve => socket.on('close', () => resolve()));
        socket.on('error', () => {});
        socket.write(`GET / HTTP/1.1\r\nHost: ${s.host}\r\nConnection: close\r\n\r\n`);
        await closed;
        assert.equal(received, 0, 'no response bytes to an untrusted source');
        await assert.rejects(call(s.port, '/', {Host: s.host}));
    } finally { await s.close(); }
});

test('lan-proxy HTTP closes a silent untrusted connection at accept time, without waiting for a request', async () => {
    const s = await proxyServer(['10.0.0.30']);
    try {
        const socket = connect(s.port, '127.0.0.1'); let received = 0;
        socket.on('data', chunk => { received += chunk.length; });
        socket.on('error', () => {});
        // Writes nothing: only the pre-parse connection guard can close it (the per-request check never runs).
        const closed = new Promise<boolean>(resolve => { socket.on('close', () => resolve(true)); setTimeout(() => resolve(false), 1000).unref(); });
        assert.equal(await closed, true, 'untrusted silent socket closed within 1s');
        assert.equal(received, 0);
        socket.destroy();
    } finally { await s.close(); }
});

test('lan-proxy HTTP from the trusted proxy keeps Host, Origin, cookie and HSTS rules and ignores X-Forwarded-*', async () => {
    const s = await proxyServer(['127.0.0.1']), get = (path: string, headers: Record<string, string> = {}) => call(s.port, path, {Host: s.host, ...headers});
    try {
        const page = await get('/'); assert.equal(page.status, 200); assert.match(page.body, /real-router-integration/);
        assert.equal(page.headers['strict-transport-security'], 'max-age=31536000');
        // Host must be the public name exactly: no IP, no port, no other name; forwarded headers never substitute.
        for (const Host of [`127.0.0.1:${s.port}`, `10.0.0.20:${s.port}`, `${NAME}:443`, `${NAME}:${s.port}`, 'evil.example.invalid']) assert.equal((await get('/', {Host})).status, 403, Host);
        assert.equal((await get('/', {Host: `127.0.0.1:${s.port}`, 'X-Forwarded-Host': NAME, 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '10.0.0.30', Forwarded: `host=${NAME};proto=https`})).status, 403);
        assert.equal((await get('/people', {Origin: 'https://evil.example.invalid'})).status, 403);
        assert.equal((await get('/people', {'Sec-Fetch-Site': 'cross-site'})).status, 403);
        assert.equal((await get('/people', {'X-Forwarded-User': 'operator'})).status, 400);
        const token = randomBytes(32).toString('base64url');
        s.f.store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at) VALUES(?,?,?)', digest(token), 'parent', s.f.now() + 600);
        const post = (headers: Record<string, string>) => call(s.port, '/auth/register/options', {Host: s.host, 'Content-Type': 'application/json', ...headers}, JSON.stringify({token}));
        assert.equal((await post({Origin: 'https://evil.example.invalid'})).status, 403);
        assert.equal((await post({Origin: `http://${NAME}`})).status, 403);
        assert.equal((await post({Origin: `http://${NAME}`, 'X-Forwarded-Proto': 'https'})).status, 403);
        assert.equal((await post({})).status, 403);
        const ok = await post({Origin: s.origin}); assert.equal(ok.status, 200);
        assert.equal(ok.headers['strict-transport-security'], 'max-age=31536000');
        const cookies = [ok.headers['set-cookie']].flat().filter(Boolean) as string[];
        assert.ok(cookies.length > 0 && cookies.every(c => /; HttpOnly; SameSite=Strict; Path=\/; Max-Age=3600; Secure$/.test(c)), cookies.join('|'));
        assert.equal(JSON.parse(ok.body).options.rp.id, NAME);
        // Authenticated POST without session/CSRF still fails closed.
        assert.equal((await call(s.port, '/people/pilot/pause', {Host: s.host, Origin: s.origin, 'Content-Type': 'application/json'}, '{}')).status, 401);
    } finally { await s.close(); }
});
