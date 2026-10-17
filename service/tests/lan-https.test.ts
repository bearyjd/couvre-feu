import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { createServer as netServer } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { integrationConfig } from '../src/integration-config.ts';
import { loadTLS, privateListenHost } from '../src/tls.ts';
import { Auth, digest } from '../src/auth.ts';
import { appServer } from '../src/http.ts';
import { integrationFixture, testConfig } from './fixtures/integration.ts';

const NAME = 'parent.example.test';
/** Throwaway self-signed certificate generated per test run; nothing is committed. */
function makeCert(dir: string, stem = 'tls', mode = 0o600) {
    const certPath = join(dir, `${stem}.crt`), keyPath = join(dir, `${stem}.key`);
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2', '-subj', `/CN=${NAME}`,
        '-addext', `subjectAltName=DNS:${NAME},IP:127.0.0.1`, '-keyout', keyPath, '-out', certPath], {stdio: 'ignore'});
    chmodSync(keyPath, mode); chmodSync(certPath, 0o644);
    return {certPath, keyPath};
}

test('listen host accepts only specific RFC1918 and Tailscale IPv4 addresses', () => {
    for (const ok of ['10.0.0.5', '172.16.0.1', '172.31.255.1', '192.168.1.20', '100.64.0.1', '100.127.255.254']) assert.equal(privateListenHost(ok), ok);
    for (const bad of ['0.0.0.0', '::', '::1', '127.0.0.1', '8.8.8.8', '172.32.0.1', '172.15.0.1', '100.63.0.1', '100.128.0.1', '192.169.1.1', '169.254.1.1', '10.0.0', '10.0.0.256', '010.0.0.1', 'localhost', '', 7, null]) assert.throws(() => privateListenHost(bad), /invalid_listen_host|listen_host_not_private/, String(bad));
});

test('loadTLS loads a matched pair and refuses unreadable, loose, symlinked or mismatched files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-tls-')), other = makeCert(dir, 'other'), good = makeCert(dir);
    try {
        assert.ok(loadTLS(good).cert.length > 0);
        assert.throws(() => loadTLS({...good, certPath: join(dir, 'missing.crt')}), /tls_cert_unreadable/);
        assert.throws(() => loadTLS({...good, keyPath: join(dir, 'missing.key')}), /tls_key_unreadable/);
        assert.throws(() => loadTLS({certPath: good.certPath, keyPath: other.keyPath}), /tls_cert_key_invalid_or_mismatched/);
        for (const mode of [0o640, 0o604, 0o644, 0o660]) { chmodSync(good.keyPath, mode); assert.throws(() => loadTLS(good), /tls_key_permissions/, mode.toString(8)); }
        chmodSync(good.keyPath, 0o400); assert.ok(loadTLS(good));
        chmodSync(good.keyPath, 0o600);
        const link = join(dir, 'link.key'); symlinkSync(good.keyPath, link); assert.throws(() => loadTLS({...good, keyPath: link}), /tls_key_permissions/);
        const garbage = join(dir, 'garbage.crt'); writeFileSync(garbage, 'not a certificate'); assert.throws(() => loadTLS({...good, certPath: garbage}), /tls_cert_key_invalid_or_mismatched/);
    } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('manifest tls, listen and publicOrigin are strictly validated and all-or-nothing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-lan-config-')), sample = testConfig(dir), socket = netServer(), tls = makeCert(dir);
    socket.listen(sample.router.agentSocket); await once(socket, 'listening'); chmodSync(sample.router.agentSocket, 0o600);
    const data = Buffer.concat([Buffer.from([0,0,0,11]), Buffer.from('ssh-ed25519'), Buffer.from([0,0,0,32]), Buffer.alloc(32, 1)]), blob = data.toString('base64'), fp = 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
    writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n`, {mode: 0o600});
    writeFileSync(sample.router.publicIdentity, `ssh-ed25519 ${blob} test-public-key\n`, {mode: 0o600});
    const {origin: _o, host: _h, manifestDigest: _m, targetDigest: _t, provenance: _p, ...manifest} = sample;
    manifest.router.hostFingerprint = fp; manifest.router.publicKeyFingerprint = fp;
    const path = join(dir, 'manifest.json'), save = (value: unknown) => writeFileSync(path, JSON.stringify(value), {mode: 0o600});
    const lan = {tls, listen: {host: '192.168.1.20', port: manifest.port}, publicOrigin: `https://${NAME}:${manifest.port}`};
    try {
        save(manifest); const plain = integrationConfig(path);
        assert.equal(plain.origin, `http://localhost:${manifest.port}`); assert.equal(plain.tls, undefined); assert.equal(plain.listen, undefined);
        save({...manifest, ...lan}); const c = integrationConfig(path);
        assert.equal(c.origin, lan.publicOrigin); assert.equal(c.host, `${NAME}:${manifest.port}`); assert.deepEqual(c.listen, lan.listen); assert.deepEqual(c.tls, tls);
        save({...manifest, ...lan, listen: {host: '100.101.102.103', port: manifest.port}}); assert.equal(integrationConfig(path).listen?.host, '100.101.102.103');
        const refuse = (changed: Record<string, unknown>, code: RegExp) => { save({...manifest, ...lan, ...changed}); assert.throws(() => integrationConfig(path), code); };
        refuse({listen: {host: '0.0.0.0', port: manifest.port}}, /listen_host_not_private/);
        refuse({listen: {host: '8.8.8.8', port: manifest.port}}, /listen_host_not_private/);
        refuse({listen: {host: '127.0.0.1', port: manifest.port}}, /listen_host_not_private/);
        refuse({listen: {host: '192.168.1.20', port: manifest.port + 1}}, /listen_port_mismatch/);
        refuse({listen: {host: '192.168.1.20', port: manifest.port, extra: 1}}, /./);
        refuse({publicOrigin: `http://${NAME}`}, /invalid_private_https_origin/);
        refuse({publicOrigin: `https://${NAME}/path`}, /invalid_private_https_origin/);
        refuse({publicOrigin: 'https://203.0.113.9'}, /invalid_private_https_origin/);
        refuse({origin: `https://${NAME}`}, /lan_https_requires/);
        refuse({tls: {certPath: 'relative.crt', keyPath: tls.keyPath}}, /invalid_private_path/);
        refuse({tls: {certPath: `${dir}/../x.crt`, keyPath: tls.keyPath}}, /invalid_private_path/);
        refuse({tls: {certPath: join(dir, 'nope.crt'), keyPath: tls.keyPath}}, /tls_cert_unreadable/);
        refuse({tls: {certPath: tls.certPath, keyPath: join(dir, 'nope.key')}}, /tls_key_unreadable/);
        refuse({tls: {...tls, extra: 1}}, /./);
        for (const partial of [{tls}, {listen: lan.listen}, {publicOrigin: lan.publicOrigin}, {tls, listen: lan.listen}, {tls, publicOrigin: lan.publicOrigin}]) { save({...manifest, ...partial}); assert.throws(() => integrationConfig(path), /lan_https_requires/); }
        chmodSync(tls.keyPath, 0o640); save({...manifest, ...lan}); assert.throws(() => integrationConfig(path), /tls_key_permissions/);
        chmodSync(tls.keyPath, 0o600);
        const other = makeCert(dir, 'other'); save({...manifest, ...lan, tls: {certPath: tls.certPath, keyPath: other.keyPath}}); assert.throws(() => integrationConfig(path), /tls_cert_key_invalid_or_mismatched/);
    } finally { socket.close(); await once(socket, 'close'); rmSync(dir, {recursive: true, force: true}); }
});

type Reply = {status: number; headers: Record<string, string | string[] | undefined>; body: string};
function call(kind: 'https' | 'http', port: number, ca: Buffer | undefined, path: string, headers: Record<string, string>, body?: string): Promise<Reply> {
    return new Promise((resolve, reject) => {
        const options = {host: '127.0.0.1', port, path, method: body === undefined ? 'GET' : 'POST', headers, agent: false, ...(kind === 'https' ? {ca, servername: NAME} : {})};
        const req = (kind === 'https' ? httpsRequest : httpRequest)(options, res => {
            const chunks: Buffer[] = []; res.on('data', c => chunks.push(c));
            res.on('end', () => resolve({status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString('utf8')}));
        });
        req.on('error', reject); req.end(body);
    });
}

test('HTTPS server serves with a generated cert, sets HSTS and Secure cookies, and enforces Host and Origin', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-lan-https-')), tls = makeCert(dir), f = integrationFixture();
    const material = loadTLS(tls), probe = netServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const port = (probe.address() as {port: number}).port; probe.close(); await once(probe, 'close');
    const origin = `https://${NAME}:${port}`, host = `${NAME}:${port}`;
    const auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance, rpName: 'LAN HTTPS test'});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host, tlsMaterial: material});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    const get = (path: string, headers: Record<string, string> = {}) => call('https', port, material.cert, path, {Host: host, ...headers});
    try {
        assert.equal(auth.rpID, NAME);
        const page = await get('/'); assert.equal(page.status, 200); assert.match(page.body, /real-router-integration/);
        assert.equal(page.headers['strict-transport-security'], 'max-age=31536000');
        assert.equal((await get('/', {Host: `evil.example.test:${port}`})).status, 403);
        assert.equal((await get('/', {Host: NAME})).status, 403);
        assert.equal((await get('/people', {Origin: 'https://evil.example.test'})).status, 403);
        const token = randomBytes(32).toString('base64url');
        f.store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at,first_enrollment) VALUES(?,?,?,1)', digest(token), 'parent', f.now() + 600);
        const post = (headers: Record<string, string>) => call('https', port, material.cert, '/auth/register/options', {Host: host, 'Content-Type': 'application/json', ...headers}, JSON.stringify({token}));
        assert.equal((await post({Origin: 'https://evil.example.test'})).status, 403);
        assert.equal((await post({Origin: `http://${host}`})).status, 403);
        assert.equal((await post({})).status, 403);
        const ok = await post({Origin: origin}); assert.equal(ok.status, 200);
        const cookies = [ok.headers['set-cookie']].flat().filter(Boolean) as string[];
        assert.ok(cookies.length > 0 && cookies.every(c => /; HttpOnly; SameSite=Strict; Path=\/; Max-Age=3600; Secure$/.test(c)), cookies.join('|'));
        assert.equal(JSON.parse(ok.body).options.rp.id, NAME);
        // A client that does not trust the generated certificate cannot connect.
        await assert.rejects(call('https', port, undefined, '/', {Host: host}));
        // Plain HTTP to the TLS listener never yields an application response.
        await assert.rejects(call('http', port, undefined, '/', {Host: host}));
    } finally { server.close(); server.closeAllConnections(); await once(server, 'close'); rmSync(dir, {recursive: true, force: true}); }
});

test('demo and loopback HTTP path is unchanged: plain HTTP, no HSTS, no Secure cookie', async () => {
    const f = integrationFixture(), probe = netServer(); probe.listen(0, '127.0.0.1'); await once(probe, 'listening');
    const port = (probe.address() as {port: number}).port; probe.close(); await once(probe, 'close');
    const origin = `http://localhost:${port}`, host = `localhost:${port}`, auth = new Auth(f.store, origin, f.now, {provenance: f.config.provenance});
    const server = appServer(auth, f.policy, {...f.config, port, origin, host});
    server.listen(port, '127.0.0.1'); await once(server, 'listening');
    try {
        const token = randomBytes(32).toString('base64url');
        f.store.run('INSERT INTO bootstrap_tokens(hash,account_id,expires_at,first_enrollment) VALUES(?,?,?,1)', digest(token), 'parent', f.now() + 600);
        const page = await call('http', port, undefined, '/', {Host: host});
        assert.equal(page.status, 200); assert.equal(page.headers['strict-transport-security'], undefined);
        const ok = await call('http', port, undefined, '/auth/register/options', {Host: host, Origin: origin, 'Content-Type': 'application/json'}, JSON.stringify({token}));
        assert.equal(ok.status, 200);
        const cookies = [ok.headers['set-cookie']].flat() as string[];
        assert.ok(cookies.every(c => !c.includes('Secure')));
    } finally { server.close(); server.closeAllConnections(); await once(server, 'close'); }
});
