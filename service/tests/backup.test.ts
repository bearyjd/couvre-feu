import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const SCRIPT = new URL('../../deploy/backup.mjs', import.meta.url).pathname;
const RUN_MS = 60_000;

function fixture() {
    const root = mkdtempSync(join(tmpdir(), 'cf-backup-'));
    const dest = join(root, 'backups');
    mkdirSync(dest, {mode: 0o700});
    const db = join(root, 'integration.sqlite');
    const live = new DatabaseSync(db);
    live.exec('PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA user_version=14;');
    live.exec('CREATE TABLE child (id INTEGER PRIMARY KEY, name TEXT NOT NULL); CREATE INDEX child_name ON child(name);');
    for (let i = 0; i < 200; i++) live.prepare('INSERT INTO child (name) VALUES (?)').run(`child-${i}`);
    return {root, dest, db, live, cleanup: () => { live.close(); rmSync(root, {recursive: true, force: true}); }};
}
function backup(f: {db: string, dest: string}, date: string, ...extra: string[]) {
    return spawnSync(process.execPath, [SCRIPT, '--db', f.db, '--dest', f.dest, '--date', date, ...extra],
        {encoding: 'utf8', timeout: RUN_MS});
}
function rows(path: string) {
    const db = new DatabaseSync(path, {readOnly: true});
    try { return {rows: db.prepare('SELECT id, name FROM child ORDER BY id').all(), version: db.prepare('PRAGMA user_version').get()!.user_version}; }
    finally { db.close(); }
}
const sha = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
const day = (n: number) => `2026-01-${String(n).padStart(2, '0')}`;

test('the copy of a live WAL database restores identical data with mode 0600', () => {
    const f = fixture();
    try {
        assert.ok(statSync(`${f.db}-wal`).size > 0, 'rows must still be in the WAL, not checkpointed');
        const result = backup(f, '2026-03-01');
        assert.equal(result.status, 0, result.stderr);
        const copy = join(f.dest, 'integration-2026-03-01.sqlite');
        assert.equal(statSync(copy).mode & 0o777, 0o600);
        assert.deepEqual(rows(copy), rows(f.db));
        assert.equal(rows(copy).version, 14);
        assert.deepEqual(readdirSync(f.dest), ['integration-2026-03-01.sqlite']);
    } finally { f.cleanup(); }
});

test('retention keeps the newest 14 dated copies and never touches foreign files', () => {
    const f = fixture();
    try {
        for (let i = 1; i <= 20; i++) writeFileSync(join(f.dest, `integration-${day(i)}.sqlite`), 'old');
        const foreign = ['notes.txt', 'integration-2026-01-01.sqlite.bak', 'integration-latest.sqlite', 'integration-2026-1-01.sqlite', 'xintegration-2026-01-01.sqlite'];
        for (const name of foreign) writeFileSync(join(f.dest, name), 'keep me');
        mkdirSync(join(f.dest, 'integration-2025-12-31.sqlite'));
        symlinkSync('notes.txt', join(f.dest, 'integration-2025-12-30.sqlite'));
        const result = backup(f, '2026-02-01');
        assert.equal(result.status, 0, result.stderr);
        const names = readdirSync(f.dest).sort();
        const dated = names.filter((n) => /^integration-\d{4}-\d{2}-\d{2}\.sqlite$/.test(n) && statSync(join(f.dest, n)).isFile() && !n.startsWith('integration-2025'));
        assert.deepEqual(dated, ['2026-02-01', ...Array.from({length: 13}, (_, i) => day(20 - i))].sort().map((d) => `integration-${d}.sqlite`));
        for (const name of [...foreign, 'integration-2025-12-31.sqlite', 'integration-2025-12-30.sqlite']) assert.ok(names.includes(name), name);
    } finally { f.cleanup(); }
});

test('an integrity failure exits non-zero and leaves no partial file', () => {
    const f = fixture();
    try {
        f.live.exec('PRAGMA wal_checkpoint(TRUNCATE)');
        const before = readdirSync(f.dest);
        const bytes = readFileSync(f.db);
        for (let page = 2; page * 4096 < bytes.length; page++) bytes.fill(0xab, page * 4096 + 100, page * 4096 + 3000);
        f.live.close();
        writeFileSync(f.db, bytes);
        const result = backup(f, '2026-03-01');
        assert.notEqual(result.status, 0);
        assert.deepEqual(readdirSync(f.dest), before);
    } finally { rmSync(f.root, {recursive: true, force: true}); }
});

test('a repeat run on the same day is idempotent and leaves the good copy untouched', () => {
    const f = fixture();
    try {
        assert.equal(backup(f, '2026-03-01').status, 0);
        const copy = join(f.dest, 'integration-2026-03-01.sqlite');
        const digest = sha(copy), mtime = statSync(copy).mtimeMs;
        f.live.prepare('INSERT INTO child (name) VALUES (?)').run('late');
        const again = backup(f, '2026-03-01');
        assert.equal(again.status, 0, again.stderr);
        assert.equal(sha(copy), digest);
        assert.equal(statSync(copy).mtimeMs, mtime);
        assert.deepEqual(readdirSync(f.dest), ['integration-2026-03-01.sqlite']);
    } finally { f.cleanup(); }
});

test('a bad same-day file is replaced only by a verified copy, otherwise left alone', () => {
    const f = fixture();
    try {
        const copy = join(f.dest, 'integration-2026-03-01.sqlite');
        writeFileSync(copy, 'not a database');
        assert.equal(backup(f, '2026-03-01').status, 0);
        assert.deepEqual(rows(copy), rows(f.db));
        writeFileSync(copy, 'not a database');
        const result = backup(f, '2026-03-01', '--db', join(f.root, 'absent.sqlite'));
        assert.notEqual(result.status, 0);
        assert.equal(readFileSync(copy, 'utf8'), 'not a database');
        assert.deepEqual(readdirSync(f.dest), ['integration-2026-03-01.sqlite']);
    } finally { f.cleanup(); }
});

test('the live database file is never modified and bad arguments are refused', () => {
    const f = fixture();
    try {
        f.live.exec('PRAGMA wal_checkpoint(TRUNCATE)');
        const digest = sha(f.db);
        assert.equal(backup(f, '2026-03-01').status, 0);
        assert.equal(sha(f.db), digest);
        for (const args of [['--date', '2026-3-1'], ['--date', '2026-13-45'], ['--keep', '0'], ['--keep', 'x'], ['--bogus']]) {
            const r = backup(f, '2026-03-02', ...args);
            assert.notEqual(r.status, 0, args.join(' '));
        }
        assert.deepEqual(readdirSync(f.dest), ['integration-2026-03-01.sqlite']);
        assert.throws(() => execFileSync(process.execPath, [SCRIPT, '--db', join(f.root, 'absent.sqlite'), '--dest', f.dest], {stdio: 'pipe', timeout: RUN_MS}));
    } finally { f.cleanup(); }
});

test('a source whose index pages are damaged is refused even though VACUUM could rebuild them', () => {
    const f = fixture();
    try {
        f.live.exec('PRAGMA wal_checkpoint(TRUNCATE)');
        const root = f.live.prepare("SELECT rootpage FROM sqlite_master WHERE name='child_name'").get()!.rootpage as number;
        f.live.close();
        const bytes = readFileSync(f.db);
        bytes.fill(0x7f, (root - 1) * 4096 + 200, root * 4096 - 200);
        writeFileSync(f.db, bytes);
        const result = backup(f, '2026-03-01');
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /integrity_check/);
        assert.deepEqual(readdirSync(f.dest), []);
    } finally { rmSync(f.root, {recursive: true, force: true}); }
});

test('a same-day copy with an older schema version is replaced after a migration', () => {
    const f = fixture();
    try {
        assert.equal(backup(f, '2026-03-01').status, 0);
        f.live.exec('PRAGMA user_version=15');
        const result = backup(f, '2026-03-01');
        assert.equal(result.status, 0, result.stderr);
        assert.equal(rows(join(f.dest, 'integration-2026-03-01.sqlite')).version, 15);
    } finally { f.cleanup(); }
});
