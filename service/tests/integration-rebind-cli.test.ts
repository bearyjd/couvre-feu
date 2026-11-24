import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as netServer } from 'node:net';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { integrationConfig } from '../src/integration-config.ts';
import { IntegrationStore } from '../src/integration-db.ts';
import { rebindIntegration } from '../src/integration-rebind.ts';
import { scheduleWindows } from '../src/integration-schedule-store.ts';
import { normalizePolicy } from '../../shared/src/router-schema.ts';
import { testConfig } from './fixtures/integration.ts';

const CLI = new URL('../src/integration-rebind-cli.ts', import.meta.url).pathname;
const night = {person: 'pilot', id: 'night', weekdays: ['Mon', 'Tue'] as ('Mon' | 'Tue')[], start: '20:30', stop: '07:00'};

test('rebind CLI: after an off->on rebind, a refused second CLI rebind commits no schedule seed', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cf-rebind-cli-')), sample = testConfig(dir), socket = netServer();
    socket.listen(sample.router.agentSocket); await once(socket, 'listening'); chmodSync(sample.router.agentSocket, 0o600);
    try {
        const data = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), Buffer.alloc(32, 1)]), blob = data.toString('base64');
        const fp = 'SHA256:' + createHash('sha256').update(data).digest('base64').replace(/=+$/, '');
        writeFileSync(sample.router.knownHosts, `192.168.1.1 ssh-ed25519 ${blob}\n`, {mode: 0o600});
        writeFileSync(sample.router.publicIdentity, `ssh-ed25519 ${blob} test-public-key\n`, {mode: 0o600});
        const {origin: _o, host: _h, manifestDigest: _m, targetDigest: _t, provenance: _p, ...base} = sample;
        const router = {...base.router, hostFingerprint: fp, publicKeyFingerprint: fp};
        const enrollment = normalizePolicy({...base.enrollment, schedules: [night]});
        const write = (name: string, value: object) => { const path = join(dir, name); writeFileSync(path, JSON.stringify(value), {mode: 0o600}); return path; };
        const offPath = write('off.json', {...base, router, enrollment, scheduleClock: {timezone: 'UTC'}});
        const onPath = write('on.json', {...base, router: {...router, generation: 'e'.repeat(64)}, enrollment, schedules: {editable: true}, scheduleClock: {timezone: 'UTC'}});
        const laterPath = write('later.json', {...base, router: {...router, generation: 'd'.repeat(64)}, enrollment, schedules: {editable: true}, scheduleClock: {timezone: 'UTC'}});
        const off = integrationConfig(offPath), on = integrationConfig(onPath), later = integrationConfig(laterPath);
        const first = new IntegrationStore(off);
        try {
            first.stopDispatch(1);
            rebindIntegration(first, on, off.manifestDigest, on.manifestDigest, 2);
        } finally { first.close(); }
        // A refused second rebind (wrong new digest) through the real CLI, before the service ever opened the flag-on store.
        const r = spawnSync(process.execPath, [CLI, onPath, laterPath, on.manifestDigest, 'a'.repeat(64)], {encoding: 'utf8', timeout: 60_000});
        assert.notEqual(r.status, 0, r.stdout);
        assert.match(r.stderr, /rebind_digest_mismatch/);
        const check = new IntegrationStore(on, {seedSchedules: false});
        try {
            assert.deepEqual(scheduleWindows(check), []);
            assert.equal(check.get('SELECT 1 FROM schedule_seed'), undefined);
        } finally { check.close(); }
        // The successful CLI rebind seeds the old (bound) manifest's windows inside its transaction.
        const ok = spawnSync(process.execPath, [CLI, onPath, laterPath, on.manifestDigest, later.manifestDigest], {encoding: 'utf8', timeout: 60_000});
        assert.equal(ok.status, 0, ok.stderr);
        const done = new IntegrationStore(later, {seedSchedules: false});
        try { assert.deepEqual(scheduleWindows(done), [night]); } finally { done.close(); }
    } finally { socket.close(); rmSync(dir, {recursive: true, force: true}); }
});
