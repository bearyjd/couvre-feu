// Daily online backup of the integration database. Runs as the service user (couvrefeu-backup.service).
// Needs only node:sqlite (Node 22.13+ and 26); no sqlite3 CLI.
//   node backup.mjs [--db PATH] [--dest DIR] [--keep N] [--date YYYY-MM-DD]
// The live database is opened read-only. The copy is made with VACUUM INTO (consistent with WAL), synced, verified
// (integrity_check and user_version equal to the source) and only then renamed to integration-YYYY-MM-DD.sqlite.
// Only files with exactly that name are ever replaced or pruned.
import { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, renameSync, chmodSync, truncateSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

process.umask(0o077);

const NAME = /^integration-(\d{4})-(\d{2})-(\d{2})\.sqlite$/;
const BUSY_TIMEOUT_MS = 5000;
const DEFAULTS = {db: '/var/lib/couvrefeu/integration.sqlite', dest: '/var/backups/couvrefeu', keep: '14'};

function fail(message) {
    process.stderr.write(`couvrefeu-backup: ${message}\n`);
    process.exit(1);
}

function isRealDate(text) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return false;
    const [y, m, d] = text.split('-').map(Number);
    return new Date(Date.UTC(y, m - 1, d)).toISOString().slice(0, 10) === text;
}

function isBackupName(name) {
    const match = NAME.exec(name);
    return match !== null && isRealDate(`${match[1]}-${match[2]}-${match[3]}`);
}

function parseArgs(argv) {
    const opts = {...DEFAULTS, date: new Date().toISOString().slice(0, 10)};
    for (let i = 0; i < argv.length; i += 2) {
        const key = argv[i]?.replace(/^--/, '');
        if (!argv[i]?.startsWith('--') || !(key in opts) || argv[i + 1] === undefined) fail(`bad argument: ${argv[i]}`);
        opts[key] = argv[i + 1];
    }
    if (!isRealDate(opts.date)) fail(`bad --date: ${opts.date}`);
    if (!/^[1-9]\d{0,3}$/.test(opts.keep)) fail(`bad --keep: ${opts.keep}`);
    return {...opts, keep: Number(opts.keep)};
}

function fingerprint(path) {
    // Read-only open; returns {ok, version} and never throws for a damaged file.
    let db;
    try {
        db = new DatabaseSync(path, {readOnly: true, timeout: BUSY_TIMEOUT_MS});
        const check = db.prepare('PRAGMA integrity_check').all();
        const ok = check.length === 1 && check[0].integrity_check === 'ok';
        return {ok, version: db.prepare('PRAGMA user_version').get().user_version};
    } catch {
        return {ok: false, version: null};
    } finally {
        try { db?.close(); } catch { /* already unusable */ }
    }
}

function fsyncPath(path) {
    const fd = openSync(path, 'r');
    try { fsyncSync(fd); } finally { closeSync(fd); }
}

function removeIfExists(path) {
    try { unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}

function prune(dest, keep) {
    const dated = readdirSync(dest).filter((n) => isBackupName(n) && lstatSync(join(dest, n)).isFile()).sort().reverse();
    for (const name of dated.slice(keep)) unlinkSync(join(dest, name));
    return dated.length - Math.min(keep, dated.length);
}

function requirePrivateDirectory(path) {
    const fd = openSync(path, 'r');
    try {
        const st = fstatSync(fd);
        if (!st.isDirectory() || st.uid !== process.getuid() || (st.mode & 0o077) !== 0) {
            fail(`${path} must be a directory owned by uid ${process.getuid()} with no group/other access`);
        }
    } finally { closeSync(fd); }
}

// Test-only fault injection, honoured solely when NODE_ENV=test (never set by the systemd unit).
function injectTestFault(partial) {
    const fault = process.env.NODE_ENV === 'test' ? process.env.COUVREFEU_BACKUP_TEST_FAULT : undefined;
    if (fault === 'truncate-partial') truncateSync(partial, 4096);
    if (fault === 'change-user-version') {
        const copy = new DatabaseSync(partial);
        try { copy.exec('PRAGMA user_version=999'); } finally { copy.close(); }
    }
}

function main() {
    const {db, dest, keep, date} = parseArgs(process.argv.slice(2));
    mkdirSync(dest, {recursive: true, mode: 0o700});
    requirePrivateDirectory(dest);
    const source = fingerprint(db);
    if (!source.ok) fail(`source database failed to open or failed integrity_check: ${db}`);
    const final = join(dest, `integration-${date}.sqlite`);
    const existing = fingerprint(final);
    if (existing.ok && existing.version === source.version) {
        process.stdout.write(`couvrefeu-backup: ${final} already present and verified\n`);
        prune(dest, keep);
        return;
    }
    // Fixed name for this day's partial file; it is not an integration-YYYY-MM-DD.sqlite name and is always
    // removed on failure. A stale one from a killed run is replaced here.
    const partial = join(dest, `.integration-${date}.partial`);
    removeIfExists(partial);
    try {
        const live = new DatabaseSync(db, {readOnly: true, timeout: BUSY_TIMEOUT_MS});
        try { live.exec(`VACUUM INTO '${partial.replaceAll("'", "''")}'`); } finally { live.close(); }
        injectTestFault(partial);
        chmodSync(partial, 0o600);
        fsyncPath(partial);
        const copy = fingerprint(partial);
        if (!copy.ok || copy.version !== source.version) throw new Error('copy failed verification');
        renameSync(partial, final);
        fsyncPath(dest);
    } catch (error) {
        removeIfExists(partial);
        fail(`backup failed: ${error.message}`);
    }
    const removed = prune(dest, keep);
    process.stdout.write(`couvrefeu-backup: wrote ${final}, pruned ${removed}\n`);
}

main();
